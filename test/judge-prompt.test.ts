/**
 * judge-prompt.ts — phase 1 wiring: explanation extraction, script payload
 * detection (untrusted local scripts, trusted/binary/computed exclusion),
 * and the fail-safe behavior of getJudgeExplanation through an injected
 * `complete` seam (no real model, no network).
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it, beforeAll, afterAll, beforeEach } from "vitest";
import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import type { AssistantMessage, Context, Model } from "@earendil-works/pi-ai";
import { createStore } from "../store";
import { extractScriptPayload, getJudgeExplanation, judgeAvailable, judgeStatus } from "../judge-prompt";
import { analyzeCommand } from "../analysis/command-analysis";
import { DEFAULT_JUDGE_SETTINGS, type CompleteFn, type JudgeSettings } from "../judge";
import type { BashPromptData as BashPromptDataType } from "../decision-engine";

// ── Fakes ──

function fakeModel(): Model<any> {
  return {
    id: "qwen3-27b",
    name: "qwen3-27b",
    api: "openai-completions",
    provider: "llama-cpp",
    baseUrl: "http://localhost:8080/v1",
    reasoning: true,
    input: ["text"],
    cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
    contextWindow: 32768,
    maxTokens: 8192,
  } as unknown as Model<any>;
}

function toolCallReply(args: Record<string, unknown>): AssistantMessage {
  return {
    role: "assistant",
    content: [{ type: "toolCall", id: "1", name: "report_verdict", arguments: args }] as never,
    api: "openai-completions",
    provider: "llama-cpp",
    model: "m",
    usage: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 } },
    stopReason: "stop" as never,
    timestamp: Date.now(),
  } as unknown as AssistantMessage;
}

const VERDICT = {
  explanation: "Runs the job script.",
  risk: "low",
  approve: "approve",
  reason: "local script, inside cwd",
};

interface CapturedCall {
  context: Context;
  options: { signal?: AbortSignal; apiKey?: string; toolChoice?: string } | undefined;
}

function fixedComplete(reply: () => AssistantMessage, calls: CapturedCall[]): CompleteFn {
  return async (_model, context, options) => {
    calls.push({ context, options: options as CapturedCall["options"] });
    return reply();
  };
}

interface FakeCtx {
  ctx: ExtensionContext;
  widgets: Array<{ id: string; fn: unknown }>;
}

function makeCtx(model: Model<any> | undefined, authOk = true): FakeCtx {
  const widgets: FakeCtx["widgets"] = [];
  const ctx = {
    hasUI: true,
    model,
    modelRegistry: {
      find: () => undefined,
      getApiKeyAndHeaders: async () =>
        authOk ? { ok: true, apiKey: "k" } : { ok: false, error: "no key" },
    },
    ui: { setWidget: (id: string, fn: unknown) => widgets.push({ id, fn }) },
  };
  return { ctx: ctx as unknown as ExtensionContext, widgets };
}

function makePd(command: string, cwd: string): BashPromptDataType {
  return {
    type: "bash",
    command,
    cwd,
    outsideDirs: [],
    segments: [command],
    signatures: [command.split(/\s+/)[0]],
    relativeToolIds: [],
    nonAllowedSegmentIndices: [0],
    riskDangerous: false,
    riskSeverity: null,
    riskReasons: [],
    hasUnsafePattern: false,
    credentialRule: null,
    needsCommandApproval: true,
    needsPathApproval: false,
  } as BashPromptDataType;
}

const ON: JudgeSettings = { ...DEFAULT_JUDGE_SETTINGS, enabled: true, timeoutMs: 4000 };
const OFF: JudgeSettings = { ...DEFAULT_JUDGE_SETTINGS, enabled: false };

let tmp: string;
beforeAll(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "judge-prompt-"));
});
afterAll(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});
beforeEach(() => {
  for (const f of fs.readdirSync(tmp)) {
    fs.rmSync(path.join(tmp, f), { recursive: true, force: true });
  }
});

// ── Script payload extraction ──

describe("extractScriptPayload", () => {
  async function analyze(command: string, cwd = tmp) {
    return analyzeCommand(command, cwd);
  }

  it("includes an interpreter-run local script", async () => {
    fs.writeFileSync(path.join(tmp, "job.py"), "print('hello from job')\n");
    const s = extractScriptPayload(await analyze("python3 job.py"));
    expect(s?.path).toBe(path.join(tmp, "job.py"));
    expect(s?.content).toContain("hello from job");
  });

  it("includes a directly-executed local script", async () => {
    fs.writeFileSync(path.join(tmp, "job.sh"), "#!/bin/sh\necho hi\n");
    const s = extractScriptPayload(await analyze("./job.sh"));
    expect(s?.path).toBe(path.join(tmp, "job.sh"));
    expect(s?.content).toContain("echo hi");
  });

  it("resolves the script against the effective cwd after a cd", async () => {
    const sub = path.join(tmp, "sub");
    fs.mkdirSync(sub);
    fs.writeFileSync(path.join(sub, "job.py"), "print('nested')\n");
    const s = extractScriptPayload(await analyze(`cd ${sub} && python3 job.py`));
    expect(s?.path).toBe(path.join(sub, "job.py"));
  });

  it("returns null for bash -c (no resolvable file)", async () => {
    expect(extractScriptPayload(await analyze("bash -c 'echo hi'"))).toBeNull();
  });

  it("returns null for computed script paths", async () => {
    expect(extractScriptPayload(await analyze("python3 $SCRIPT"))).toBeNull();
  });

  it("returns null for executables without a script extension", async () => {
    fs.writeFileSync(path.join(tmp, "tool"), "not a script\n");
    expect(extractScriptPayload(await analyze("./tool"))).toBeNull();
  });

  it("returns null when the file does not exist", async () => {
    expect(extractScriptPayload(await analyze("python3 missing.py"))).toBeNull();
  });
});

// ── getJudgeExplanation ──

describe("getJudgeExplanation", () => {
  it("disabled → no model call, no widget", async () => {
    const calls: CapturedCall[] = [];
    const { ctx, widgets } = makeCtx(fakeModel());
    const r = await getJudgeExplanation(makePd("ls", tmp), ctx, createStore(), {
      complete: fixedComplete(() => toolCallReply(VERDICT), calls),
      settings: OFF,
    });
    expect(r).toBe("");
    expect(calls).toHaveLength(0);
    expect(widgets).toHaveLength(0);
  });

  it("no model resolvable → ''", async () => {
    const calls: CapturedCall[] = [];
    const { ctx } = makeCtx(undefined);
    const r = await getJudgeExplanation(makePd("ls", tmp), ctx, createStore(), {
      complete: fixedComplete(() => toolCallReply(VERDICT), calls),
      settings: ON,
    });
    expect(r).toBe("");
    expect(calls).toHaveLength(0);
  });

  it("auth failure → ''", async () => {
    const calls: CapturedCall[] = [];
    const { ctx } = makeCtx(fakeModel(), false);
    const r = await getJudgeExplanation(makePd("ls", tmp), ctx, createStore(), {
      complete: fixedComplete(() => toolCallReply(VERDICT), calls),
      settings: ON,
    });
    expect(r).toBe("");
    expect(calls).toHaveLength(0);
  });

  it("valid verdict → explanation; widget shown then cleared; toolChoice auto", async () => {
    const calls: CapturedCall[] = [];
    const { ctx, widgets } = makeCtx(fakeModel());
    const r = await getJudgeExplanation(makePd("ls -la", tmp), ctx, createStore(), {
      complete: fixedComplete(() => toolCallReply(VERDICT), calls),
      settings: ON,
    });
    expect(r).toBe(VERDICT.explanation);
    expect(calls).toHaveLength(1);
    expect(calls[0].options?.toolChoice).toBe("auto");
    expect(calls[0].options?.apiKey).toBe("k");
    const judgeWidgets = widgets.filter(w => w.id === "judge");
    expect(judgeWidgets).toHaveLength(2);
    expect(judgeWidgets[0].fn).toBeDefined();
    expect(judgeWidgets[1].fn).toBeUndefined(); // cleared in finally
  });

  it("no-tool-call reply → ''", async () => {
    const { ctx } = makeCtx(fakeModel());
    const r = await getJudgeExplanation(makePd("ls", tmp), ctx, createStore(), {
      complete: (async () =>
        assistantText("I refuse to call tools") as AssistantMessage) as CompleteFn,
      settings: ON,
    });
    expect(r).toBe("");
  });

  it("the packet includes an untrusted script payload when the command runs one", async () => {
    fs.writeFileSync(path.join(tmp, "job.py"), "import os\nprint('job')\n");
    const calls: CapturedCall[] = [];
    const { ctx } = makeCtx(fakeModel());
    const r = await getJudgeExplanation(makePd("python3 job.py", tmp), ctx, createStore(), {
      complete: fixedComplete(() => toolCallReply(VERDICT), calls),
      settings: ON,
    });
    expect(r).toBe(VERDICT.explanation);
    const packet = String(calls[0].context.messages[0].content);
    expect(packet).toContain("## Script: " + path.join(tmp, "job.py") + " (untrusted,");
    expect(packet).toContain("import os");
  });

  it("bash -c commands get no script section in the packet", async () => {
    const calls: CapturedCall[] = [];
    const { ctx } = makeCtx(fakeModel());
    await getJudgeExplanation(makePd("bash -c 'echo hi'", tmp), ctx, createStore(), {
      complete: fixedComplete(() => toolCallReply(VERDICT), calls),
      settings: ON,
    });
    const packet = String(calls[0].context.messages[0].content);
    expect(packet).not.toContain("## Script:");
  });

  it("an internal throw still resolves to '' (fail-safe)", async () => {
    const { ctx } = makeCtx(fakeModel());
    const r = await getJudgeExplanation(makePd("ls", tmp), ctx, createStore(), {
      complete: (async () => {
        throw new Error("boom");
      }) as CompleteFn,
      settings: ON,
    });
    expect(r).toBe("");
  });
});

function assistantText(text: string): AssistantMessage {
  return {
    role: "assistant",
    content: [{ type: "text", text }] as never,
    api: "openai-completions",
    provider: "llama-cpp",
    model: "m",
    usage: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 } },
    stopReason: "stop" as never,
    timestamp: Date.now(),
  } as unknown as AssistantMessage;
}

// ── judgeStatus ──

describe("judgeStatus", () => {
  it("off when disabled in settings — silent (no reason surfaced)", () => {
    const { ctx } = makeCtx(fakeModel());
    expect(judgeStatus(ctx, OFF)).toEqual({ state: "off", modelLabel: null, reason: null });
  });

  it("ok with the session model, labeled as session", () => {
    const { ctx } = makeCtx(fakeModel());
    expect(judgeStatus(ctx, ON)).toEqual({
      state: "ok",
      modelLabel: "llama-cpp/qwen3-27b (session)",
      reason: null,
    });
  });

  it("ok with an explicitly configured model, labeled as configured", () => {
    const m = fakeModel();
    const ctx = {
      hasUI: true,
      model: undefined,
      modelRegistry: {
        find: (p: string, id: string) => (p === "p" && id === "m" ? m : undefined),
        getApiKeyAndHeaders: async () => ({ ok: true, apiKey: "k" }),
      },
      ui: { setWidget: () => {} },
    } as unknown as ExtensionContext;
    expect(judgeStatus(ctx, { ...ON, provider: "p", model: "m" })).toEqual({
      state: "ok",
      modelLabel: "llama-cpp/qwen3-27b (configured)",
      reason: null,
    });
  });

  it("invalid when the session model is unresolvable", () => {
    const { ctx } = makeCtx(undefined);
    expect(judgeStatus(ctx, ON)).toEqual({
      state: "invalid",
      modelLabel: null,
      reason: "session model not resolvable",
    });
  });

  it("invalid when the configured model is not found", () => {
    const { ctx } = makeCtx(fakeModel());
    expect(judgeStatus(ctx, { ...ON, provider: "p", model: "m" })).toEqual({
      state: "invalid",
      modelLabel: null,
      reason: "configured model not found (p/m)",
    });
  });
});

// ── judgeAvailable ──

describe("judgeAvailable", () => {
  it("false when disabled, even with a session model", () => {
    const { ctx } = makeCtx(fakeModel());
    expect(judgeAvailable(ctx, OFF)).toBe(false);
  });

  it("false when no model is resolvable (no session model, nothing configured)", () => {
    const { ctx } = makeCtx(undefined);
    expect(judgeAvailable(ctx, ON)).toBe(false);
  });

  it("true when enabled and a session model exists", () => {
    const { ctx } = makeCtx(fakeModel());
    expect(judgeAvailable(ctx, ON)).toBe(true);
  });

  it("session-model path never touches the registry (no throw even if absent)", () => {
    const ctx = { model: fakeModel(), modelRegistry: undefined } as unknown as ExtensionContext;
    expect(judgeAvailable(ctx, ON)).toBe(true);
  });
});

// ── Non-bash dispatch ──

describe("getJudgeVerdict: file & mcp prompts", () => {
  it("file prompts get a file operation packet", async () => {
    const pd = {
      type: "file",
      action: "write",
      filePath: "/etc/hosts",
      resolved: "/etc/hosts",
      cwd: tmp,
      outsideDir: "/etc",
      isWriteOp: true,
      warnedRule: null,
      symlinkHint: null,
      exists: true,
    } as never;
    const calls: CapturedCall[] = [];
    const { ctx } = makeCtx(fakeModel());
    const r = await getJudgeExplanation(pd, ctx, createStore(), {
      complete: fixedComplete(() => toolCallReply(VERDICT), calls),
      settings: ON,
    });
    expect(r).toBe(VERDICT.explanation);
    const packet = String(calls[0].context.messages[0].content);
    expect(packet).toContain("file write (WRITE): /etc/hosts");
    expect(packet).toContain("OUTSIDE base");
  });

  it("mcp prompts get an mcp operation packet", async () => {
    const pd = {
      type: "mcp",
      server: "exa",
      tool: "web_search_exa",
      op: "search",
      argsPreview: '{"query":"hello"}',
    } as never;
    const calls: CapturedCall[] = [];
    const { ctx } = makeCtx(fakeModel());
    const r = await getJudgeExplanation(pd, ctx, createStore(), {
      complete: fixedComplete(() => toolCallReply(VERDICT), calls),
      settings: ON,
    });
    expect(r).toBe(VERDICT.explanation);
    const packet = String(calls[0].context.messages[0].content);
    expect(packet).toContain("mcp: exa/web_search_exa");
    expect(packet).toContain('{"query":"hello"}');
  });
});

describe("getJudgeVerdict: file content threading", () => {
  it("write content reaches the model packet", async () => {
    const pd = {
      type: "file",
      action: "write",
      filePath: "/w/out.md",
      resolved: "/w/out.md",
      cwd: tmp,
      outsideDir: null,
      isWriteOp: true,
      warnedRule: null,
      symlinkHint: null,
      exists: false,
      content: "the-secret-marker-42",
    } as never;
    const calls: CapturedCall[] = [];
    const { ctx } = makeCtx(fakeModel());
    await getJudgeExplanation(pd, ctx, createStore(), {
      complete: fixedComplete(() => toolCallReply(VERDICT), calls),
      settings: ON,
    });
    const packet = String(calls[0].context.messages[0].content);
    expect(packet).toContain("## New content (UNTRUSTED DATA)");
    expect(packet).toContain("the-secret-marker-42");
  });
});
