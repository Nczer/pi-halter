/**
 * judge-prompt.ts — judge verdict wiring: explanation extraction and the
 * fail-safe behavior of getJudgeVerdict through an injected `stream` seam
 * (no real model, no network). Script-payload identification is tested in
 * test/script-payload.test.ts (analysis layer).
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it, beforeAll, afterAll, beforeEach, afterEach } from "vitest";
import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import type { AssistantMessage, Context, Model } from "@earendil-works/pi-ai";
import { createAssistantMessageEventStream } from "@earendil-works/pi-ai";
import { createStore } from "../gate/store";
import {getJudgeVerdict, getStage2Verdict, judgeAvailable, judgeStatus, judgeVerdictBlock} from "../judge/verdict";
import { analyzeCommand } from "../analysis/command-analysis";
import {DEFAULT_JUDGE_SETTINGS, JudgeStreamFn, JudgeResult, JudgeSettings} from "../judge/judge";
import type {BashPromptData as BashPromptDataType} from "../decide/types";

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

/** Fake stream: pushes start → toolcall_start → done (or error, matching
 *  the reply's stop reason) on a microtask, and captures the call. */
function fixedStream(reply: () => AssistantMessage, calls: CapturedCall[]): JudgeStreamFn {
  return (_model, context, options) => {
    calls.push({ context, options: options as CapturedCall["options"] });
    const s = createAssistantMessageEventStream();
    queueMicrotask(() => {
      const msg = reply();
      s.push({ type: "start", partial: msg } as never);
      s.push({ type: "toolcall_start", contentIndex: 0, partial: msg } as never);
      if (msg.stopReason === "aborted" || msg.stopReason === "error") {
        s.push({ type: "error", reason: msg.stopReason, error: msg } as never);
      } else {
        s.push({ type: "done", reason: "stop", message: msg } as never);
      }
      s.end();
    });
    return s;
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

// ── getJudgeVerdict ──

describe("getJudgeVerdict", () => {
  it("disabled → no model call, no widget", async () => {
    const calls: CapturedCall[] = [];
    const { ctx, widgets } = makeCtx(fakeModel());
    const r = await getJudgeVerdict(makePd("ls", tmp), ctx, createStore(), {
      stream: fixedStream(() => toolCallReply(VERDICT), calls),
      settings: OFF,
    });
    expect(r).toBeNull();
    expect(calls).toHaveLength(0);
    expect(widgets).toHaveLength(0);
  });

  it("no model resolvable → null", async () => {
    const calls: CapturedCall[] = [];
    const { ctx } = makeCtx(undefined);
    const r = await getJudgeVerdict(makePd("ls", tmp), ctx, createStore(), {
      stream: fixedStream(() => toolCallReply(VERDICT), calls),
      settings: ON,
    });
    expect(r).toBeNull();
    expect(calls).toHaveLength(0);
  });

  it("auth failure → null", async () => {
    const calls: CapturedCall[] = [];
    const { ctx } = makeCtx(fakeModel(), false);
    const r = await getJudgeVerdict(makePd("ls", tmp), ctx, createStore(), {
      stream: fixedStream(() => toolCallReply(VERDICT), calls),
      settings: ON,
    });
    expect(r).toBeNull();
    expect(calls).toHaveLength(0);
  });

  it("valid verdict → explanation; widget shown then cleared; toolChoice auto", async () => {
    const calls: CapturedCall[] = [];
    const { ctx, widgets } = makeCtx(fakeModel());
    const r = await getJudgeVerdict(makePd("ls -la", tmp), ctx, createStore(), {
      stream: fixedStream(() => toolCallReply(VERDICT), calls),
      settings: ON,
    });
    expect(r?.explanation).toBe(VERDICT.explanation);
    expect(calls).toHaveLength(1);
    expect(calls[0].options?.toolChoice).toBe("auto");
    expect(calls[0].options?.apiKey).toBe("k");
    const judgeWidgets = widgets.filter(w => w.id === "judge");
    expect(judgeWidgets).toHaveLength(2);
    expect(judgeWidgets[0].fn).toBeDefined();
    expect(judgeWidgets[1].fn).toBeUndefined(); // cleared in finally
  });

  it("no-tool-call reply → null", async () => {
    const { ctx } = makeCtx(fakeModel());
    const r = await getJudgeVerdict(makePd("ls", tmp), ctx, createStore(), {
      stream: fixedStream(() => assistantText("I refuse to call tools"), []),
      settings: ON,
    });
    expect(r).toBeNull();
  });

  it("the packet includes an untrusted script payload when the command runs one", async () => {
    fs.writeFileSync(path.join(tmp, "job.py"), "import os\nprint('job')\n");
    const calls: CapturedCall[] = [];
    const { ctx } = makeCtx(fakeModel());
    const r = await getJudgeVerdict(makePd("python3 job.py", tmp), ctx, createStore(), {
      stream: fixedStream(() => toolCallReply(VERDICT), calls),
      settings: ON,
    });
    expect(r?.explanation).toBe(VERDICT.explanation);
    const packet = String(calls[0].context.messages[0].content);
    expect(packet).toContain("## Script: " + path.join(tmp, "job.py") + " (untrusted)");
    expect(packet).toContain("import os");
  });

  it("bash -c commands get no script section in the packet", async () => {
    const calls: CapturedCall[] = [];
    const { ctx } = makeCtx(fakeModel());
    await getJudgeVerdict(makePd("bash -c 'echo hi'", tmp), ctx, createStore(), {
      stream: fixedStream(() => toolCallReply(VERDICT), calls),
      settings: ON,
    });
    const packet = String(calls[0].context.messages[0].content);
    expect(packet).not.toContain("## Script:");
  });

  it("the packet uses the carried analysis instead of re-parsing (single analysis per decision)", async () => {
    const calls: CapturedCall[] = [];
    const { ctx } = makeCtx(fakeModel());
    const carried = await analyzeCommand("ls -la carried-marker", tmp);
    const pd = { ...makePd("f=rm; $f -rf ./build", tmp), analysis: carried };
    await getJudgeVerdict(pd, ctx, createStore(), {
      stream: fixedStream(() => toolCallReply(VERDICT), calls),
      settings: ON,
    });
    const packet = String(calls[0].context.messages[0].content);
    // The static-analysis digest reflects the carried analysis (the one the
    // decision was made from), not a re-parse of the raw command.
    expect(packet).toContain("1. ls -la carried-marker");
    expect(packet).toContain("network: none");
  });

  it("an internal throw still resolves to null (fail-safe)", async () => {
    const { ctx } = makeCtx(fakeModel());
    const r = await getJudgeVerdict(makePd("ls", tmp), ctx, createStore(), {
      stream: (() => {
        throw new Error("boom");
      }) as JudgeStreamFn,
      settings: ON,
    });
    expect(r).toBeNull();
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

// ── judgeVerdictBlock ──

describe("stage-2 first-token headroom", () => {
  it("stage 2 gets 3× the first-token deadline (STAGE2_TIMEOUT_FACTOR); stage 1 keeps the base", async () => {
    // The first token arrives at 100ms: inside stage 2's extended window
    // (3 × 40ms = 120ms), outside stage 1's (40ms). Unique command — the
    // LRU is per (model, operation bytes) and must not see earlier tests.
    const lateStream: JudgeStreamFn = (_m, _c, options) => {
      const s = createAssistantMessageEventStream();
      const t = setTimeout(() => {
        const msg = toolCallReply(VERDICT);
        s.push({ type: "start", partial: msg } as never);
        s.push({ type: "toolcall_start", contentIndex: 0, partial: msg } as never);
        s.push({ type: "done", reason: "stop", message: msg } as never);
        s.end();
      }, 100);
      options?.signal?.addEventListener(
        "abort",
        () => {
          clearTimeout(t);
          s.push({
            type: "error",
            reason: "aborted",
            error: { ...assistantText(""), stopReason: "aborted" } as never,
          } as never);
          s.end();
        },
        { once: true },
      );
      return s;
    };
    const settings: JudgeSettings = { ...ON, timeoutMs: 40 };
    const { ctx } = makeCtx(fakeModel());
    const pd = makePd("ls stage-two-headroom", tmp);
    const v2 = await getStage2Verdict(pd, ctx, createStore(), { stream: lateStream, settings });
    expect(v2?.approve).toBe("approve"); // 100ms < 3 × 40ms
    const v1 = await getJudgeVerdict(pd, ctx, createStore(), { stream: lateStream, settings });
    expect(v1).toBeNull(); // 100ms > 40ms → aborted
  });
});

describe("judgeVerdictBlock", () => {
  const v = (approve: string, risk: string) =>
    ({ approve, risk, explanation: "Ex.", reason: "", latencyMs: 1, model: "m", cached: false }) as JudgeResult;

  it("approve → APPROVE with the verdict's own risk", () => {
    expect(judgeVerdictBlock(v("approve", "low"))).toBe(
      "💭 Judge: Ex.\n   → suggests: APPROVE (low)",
    );
  });

  it("deny → REJECT", () => {
    expect(judgeVerdictBlock(v("deny", "high"))).toContain("→ suggests: REJECT (high)");
  });

  it("defer → DEFER (distinct from REJECT — 'could not verify' ≠ 'saw something bad')", () => {
    const block = judgeVerdictBlock(v("defer", "medium"));
    expect(block).toContain("→ suggests: DEFER (medium)");
    expect(block).not.toContain("REJECT");
  });

  it("risk is independent of the verdict word (defer can carry any risk)", () => {
    expect(judgeVerdictBlock(v("defer", "low"))).toContain("→ suggests: DEFER (low)");
    expect(judgeVerdictBlock(v("approve", "medium"))).toContain("→ suggests: APPROVE (medium)");
  });

  it("note appends to the suggests line (the /dspa not-auto-allowed case)", () => {
    expect(judgeVerdictBlock(v("approve", "medium"), "— not auto-allowed (risk must be low)")).toContain(
      "→ suggests: APPROVE (medium) — not auto-allowed (risk must be low)",
    );
  });
});

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

describe("getJudgeVerdict: file prompts", () => {
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
    const r = await getJudgeVerdict(pd, ctx, createStore(), {
      stream: fixedStream(() => toolCallReply(VERDICT), calls),
      settings: ON,
    });
    expect(r?.explanation).toBe(VERDICT.explanation);
    const packet = String(calls[0].context.messages[0].content);
    expect(packet).toContain("file write (WRITE): /etc/hosts");
    expect(packet).toContain("OUTSIDE base");
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
    await getJudgeVerdict(pd, ctx, createStore(), {
      stream: fixedStream(() => toolCallReply(VERDICT), calls),
      settings: ON,
    });
    const packet = String(calls[0].context.messages[0].content);
    expect(packet).toContain("## New content (UNTRUSTED DATA)");
    expect(packet).toContain("the-secret-marker-42");
  });

  it("edit after-view (contentHeading + exists) reaches the model packet", async () => {
    const pd = {
      type: "file",
      action: "edit",
      filePath: "/w/app.ts",
      resolved: "/w/app.ts",
      cwd: tmp,
      outsideDir: null,
      isWriteOp: true,
      warnedRule: null,
      symlinkHint: null,
      exists: true,
      content: "    42 > L3-new",
      contentHeading: "File after this edit",
    } as never;
    const calls: CapturedCall[] = [];
    const { ctx } = makeCtx(fakeModel());
    await getJudgeVerdict(pd, ctx, createStore(), {
      stream: fixedStream(() => toolCallReply(VERDICT), calls),
      settings: ON,
    });
    const packet = String(calls[0].context.messages[0].content);
    expect(packet).toContain("## File after this edit (UNTRUSTED DATA)");
    expect(packet).toContain("file exists: yes");
    expect(packet).toContain("modifies the existing file in place");
    expect(packet).toContain("    42 > L3-new");
  });
});

// ── D17: judge infra ledger (runJudgeStage failure sites) ──

describe("D17: infra lines in the always-on judge ledger", () => {
  const judgeLog = path.join(os.tmpdir(), `judge-infra-${process.pid}.jsonl`);
  const savedJudgeLog = process.env.HALTER_JUDGE_LOG;

  function judgeLines(): Array<Record<string, unknown>> {
    if (!fs.existsSync(judgeLog)) return [];
    return fs.readFileSync(judgeLog, "utf8").trim().split("\n").map((l) => JSON.parse(l));
  }

  beforeEach(() => {
    fs.rmSync(judgeLog, { force: true });
    process.env.HALTER_JUDGE_LOG = judgeLog;
  });
  afterEach(() => {
    if (savedJudgeLog === undefined) delete process.env.HALTER_JUDGE_LOG;
    else process.env.HALTER_JUDGE_LOG = savedJudgeLog;
    fs.rmSync(judgeLog, { force: true });
  });

  it("settings off → silent (a choice, not an infra failure)", async () => {
    const { ctx } = makeCtx(fakeModel());
    await getJudgeVerdict(makePd("infra-off-test", tmp), ctx, createStore(), {
      stream: fixedStream(() => toolCallReply(VERDICT), []),
      settings: OFF,
    });
    expect(fs.existsSync(judgeLog)).toBe(false);
  });

  it("no model resolvable → infra line (no-model)", async () => {
    const { ctx } = makeCtx(undefined);
    await getJudgeVerdict(makePd("infra-nomodel-test", tmp), ctx, createStore(), {
      stream: fixedStream(() => toolCallReply(VERDICT), []),
      settings: ON,
    });
    expect(judgeLines()).toEqual([
      expect.objectContaining({ kind: "infra", mode: "manual", stage: 1, error: "no-model" }),
    ]);
  });

  it("auth failure → infra line (no-auth, model named)", async () => {
    const { ctx } = makeCtx(fakeModel(), false);
    await getJudgeVerdict(makePd("infra-noauth-test", tmp), ctx, createStore(), {
      stream: fixedStream(() => toolCallReply(VERDICT), []),
      settings: ON,
    });
    expect(judgeLines()).toEqual([
      expect.objectContaining({ kind: "infra", error: "no-auth", model: "llama-cpp/qwen3-27b" }),
    ]);
  });

  it("reply without explanation (a thrown stream normalizes to the same) → no-explanation line", async () => {
    const { ctx } = makeCtx(fakeModel());
    await getJudgeVerdict(makePd("infra-noexpl-test", tmp), ctx, createStore(), {
      stream: (() => { throw new Error("boom"); }) as JudgeStreamFn,
      settings: ON,
    });
    await getJudgeVerdict(makePd("infra-noexpl-test-2", tmp), ctx, createStore(), {
      stream: fixedStream(() => assistantText("I refuse to call tools"), []),
      settings: ON,
    });
    expect(judgeLines().map((l) => l.error)).toEqual(["no-explanation", "no-explanation"]);
    // The sub-reason is logged (detail) so a no-explanation line is diagnosable.
    expect(judgeLines().map((l) => l.detail)).toEqual(["call-failed: boom", "no-tool-call"]);
  });
});
