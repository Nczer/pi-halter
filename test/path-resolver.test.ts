/**
 * path-resolver.ts — the LLM fallback for statically unresolved tokens.
 *
 * One judge-model call reports the runtime dirs per token (grounded in the
 * command text). Tests run through the injected `stream` seam (no real
 * model): happy path, sanitize/cap rules, fail-safes (off, auth, bad
 * reply, no tool call), and the LRU cache.
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it, beforeAll, afterAll, beforeEach, afterEach } from "vitest";
import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import type { AssistantMessage, Context, Model } from "@earendil-works/pi-ai";
import { createAssistantMessageEventStream } from "@earendil-works/pi-ai";
import { resolveUnresolvedPaths, resetPathResolverCache } from "../judge/path-resolver";
import {DEFAULT_JUDGE_SETTINGS, JudgeStreamFn, JudgeSettings} from "../judge/judge";
import type {BashPromptData} from "../decide/types";

// ── Fakes (judge-prompt.test.ts pattern) ──

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

function toolCallReply(name: string, args: Record<string, unknown>): AssistantMessage {
  return {
    role: "assistant",
    content: [{ type: "toolCall", id: "1", name, arguments: args }] as never,
    api: "openai-completions",
    provider: "llama-cpp",
    model: "m",
    usage: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 } },
    stopReason: "stop" as never,
    timestamp: Date.now(),
  } as unknown as AssistantMessage;
}

function textReply(text: string): AssistantMessage {
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

interface CapturedCall {
  model: Model<any>;
  context: Context;
  options: Record<string, unknown> | undefined;
}

/** Fake stream: pushes start → toolcall_start → done (or error, matching
 *  the reply's stop reason) on a microtask, and captures the call. */
function fixedStream(reply: () => AssistantMessage, calls: CapturedCall[] = []): JudgeStreamFn {
  return (model, context, options) => {
    calls.push({ model, context, options: options as CapturedCall["options"] });
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

function makeCtx(
  model: Model<any> | undefined,
  authOk = true,
  authExtra: Record<string, unknown> = {},
): ExtensionContext {
  return {
    hasUI: true,
    model,
    sessionManager: { getSessionId: () => "sess-42" },
    modelRegistry: {
      find: () => undefined,
      getApiKeyAndHeaders: async () =>
        authOk ? { ok: true, apiKey: "k", ...authExtra } : { ok: false, error: "no key" },
    },
    ui: { setWidget: () => {} },
  } as unknown as ExtensionContext;
}

function makePd(command: string, cwd: string, tokens: string[]): BashPromptData {
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
    needsPathApproval: true,
    unresolved: tokens.map((token) => ({ token, reason: "var" as const })),
  } as BashPromptData;
}

const ON: JudgeSettings = { ...DEFAULT_JUDGE_SETTINGS, enabled: true, timeoutMs: 4000 };
const OFF: JudgeSettings = { ...DEFAULT_JUDGE_SETTINGS, enabled: false };

const CMD = `for e in a b; do grep -rn 'x' /Users/u/ext/$e/*.ts; done`;
const TOKEN = "/Users/u/ext/$e/*.ts";

let tmp: string;
beforeAll(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "path-resolver-"));
});
afterAll(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});
beforeEach(() => {
  for (const f of fs.readdirSync(tmp)) {
    fs.rmSync(path.join(tmp, f), { recursive: true, force: true });
  }
  resetPathResolverCache();
});

describe("resolveUnresolvedPaths", () => {
  it("returns null without an LLM call when the judge is off", async () => {
    const calls: CapturedCall[] = [];
    const r = await resolveUnresolvedPaths(makePd(CMD, "/Users/u/project", [TOKEN]), makeCtx(fakeModel()), {
      stream: fixedStream(() => textReply("x"), calls),
      settings: OFF,
    });
    expect(r).toBeNull();
    expect(calls).toHaveLength(0);
  });

  it("returns null when there are no unresolved tokens", async () => {
    const calls: CapturedCall[] = [];
    const pd = makePd(CMD, "/Users/u/project", []);
    pd.unresolved = undefined;
    const r = await resolveUnresolvedPaths(pd, makeCtx(fakeModel()), {
      stream: fixedStream(() => textReply("x"), calls),
      settings: ON,
    });
    expect(r).toBeNull();
    expect(calls).toHaveLength(0);
  });

  it("returns null when no model is resolvable", async () => {
    const calls: CapturedCall[] = [];
    const r = await resolveUnresolvedPaths(makePd(CMD, "/Users/u/project", [TOKEN]), makeCtx(undefined), {
      stream: fixedStream(() => textReply("x"), calls),
      settings: ON,
    });
    expect(r).toBeNull();
    expect(calls).toHaveLength(0);
  });

  it("returns null on auth failure", async () => {
    const calls: CapturedCall[] = [];
    const r = await resolveUnresolvedPaths(makePd(CMD, "/Users/u/project", [TOKEN]), makeCtx(fakeModel(), false), {
      stream: fixedStream(() => textReply("x"), calls),
      settings: ON,
    });
    expect(r).toBeNull();
    expect(calls).toHaveLength(0);
  });

  it("maps the numbered results back to tokens", async () => {
    const calls: CapturedCall[] = [];
    const tokens = [TOKEN, "/Users/u/other/$f/*.ts"];
    const r = await resolveUnresolvedPaths(makePd(CMD, "/Users/u/project", tokens), makeCtx(fakeModel()), {
      stream: fixedStream(
        () => toolCallReply("report_paths", {
          results: [
            { index: 0, known: true, dirs: ["/Users/u/ext/a", "/Users/u/ext/b"] },
            { index: 1, known: false, dirs: [] },
          ],
        }),
        calls,
      ),
      settings: ON,
    });
    expect(calls).toHaveLength(1);
    expect(r).not.toBeNull();
    expect([...(r ?? new Map()).entries()]).toEqual([[TOKEN, ["/Users/u/ext/a", "/Users/u/ext/b"]]]);
    // The resolver forces the call the same per-wire way the verdict does.
    expect(calls[0].options?.toolChoice).toBe("required");
    // And it carries pi's session id: OpenCode 400s a request without it.
    expect(calls[0].options?.sessionId).toBe("sess-42");
  });

  it("the packet names the command, cwd, and the numbered tokens", async () => {
    const calls: CapturedCall[] = [];
    await resolveUnresolvedPaths(makePd(CMD, "/Users/u/project", [TOKEN]), makeCtx(fakeModel()), {
      stream: fixedStream(
        () => toolCallReply("report_paths", { results: [{ index: 0, known: false, dirs: [] }] }),
        calls,
      ),
      settings: ON,
    });
    const user = String((calls[0]?.context as { messages: { content: string }[] }).messages[0].content);
    expect(user).toContain(CMD);
    expect(user).toContain("Working directory: /Users/u/project");
    expect(user).toContain(`1. ${TOKEN}`);
  });

  it("drops relative dirs, sentinels, and non-strings; expands ~", async () => {
    const home = os.homedir();
    const r = await resolveUnresolvedPaths(makePd(CMD, "/Users/u/project", [TOKEN]), makeCtx(fakeModel()), {
      stream: fixedStream(
        () => toolCallReply("report_paths", {
          results: [{
            index: 0,
            known: true,
            dirs: ["rel/dir", "<unresolved-var>/x", 42, "~/.pi/agent/extensions/a", "  /Users/u/ext/trim  "],
          }],
        }),
        [],
      ),
      settings: ON,
    });
    expect([...(r ?? new Map()).values()][0]).toEqual([
      path.join(home, ".pi/agent/extensions/a"),
      "/Users/u/ext/trim",
    ]);
  });

  it("caps dirs per token at 5", async () => {
    const r = await resolveUnresolvedPaths(makePd(CMD, "/Users/u/project", [TOKEN]), makeCtx(fakeModel()), {
      stream: fixedStream(
        () => toolCallReply("report_paths", {
          results: [{
            index: 0,
            known: true,
            dirs: ["/a", "/b", "/c", "/d", "/e", "/f", "/g"],
          }],
        }),
        [],
      ),
      settings: ON,
    });
    expect([...(r ?? new Map()).values()][0]).toEqual(["/a", "/b", "/c", "/d", "/e"]);
  });

  it("skips out-of-range indices and dedupes", async () => {
    const r = await resolveUnresolvedPaths(makePd(CMD, "/Users/u/project", [TOKEN]), makeCtx(fakeModel()), {
      stream: fixedStream(
        () => toolCallReply("report_paths", {
          results: [
            { index: 9, known: true, dirs: ["/nope"] },
            { index: 0, known: true, dirs: ["/x", "/x", "/y"] },
          ],
        }),
        [],
      ),
      settings: ON,
    });
    expect([...(r ?? new Map()).values()][0]).toEqual(["/x", "/y"]);
  });

  it("returns null when nothing is known", async () => {
    const r = await resolveUnresolvedPaths(makePd(CMD, "/Users/u/project", [TOKEN]), makeCtx(fakeModel()), {
      stream: fixedStream(
        () => toolCallReply("report_paths", { results: [{ index: 0, known: false, dirs: [] }] }),
        [],
      ),
      settings: ON,
    });
    expect(r).toBeNull();
  });

  it("returns null on a reply without a tool call", async () => {
    const r = await resolveUnresolvedPaths(makePd(CMD, "/Users/u/project", [TOKEN]), makeCtx(fakeModel()), {
      stream: fixedStream(() => textReply("I cannot tell."), [], ),
      settings: ON,
    });
    expect(r).toBeNull();
  });

  it("returns null on malformed results / a throwing complete", async () => {
    const bad = await resolveUnresolvedPaths(makePd(CMD, "/Users/u/project", [TOKEN]), makeCtx(fakeModel()), {
      stream: fixedStream(() => toolCallReply("report_paths", { results: "nope" }), []),
      settings: ON,
    });
    expect(bad).toBeNull();
    const boom = await resolveUnresolvedPaths(makePd(CMD, "/Users/u/project", [TOKEN]), makeCtx(fakeModel()), {
      stream: (() => {
        throw new Error("network down");
      }) as JudgeStreamFn,
      settings: ON,
    });
    expect(boom).toBeNull();
  });

  it("LRU-caches on model + command + tokens", async () => {
    const calls: CapturedCall[] = [];
    const streamFn = fixedStream(
      () => toolCallReply("report_paths", { results: [{ index: 0, known: true, dirs: ["/a"] }] }),
      calls,
    );
    const ctx = makeCtx(fakeModel());
    const pd = makePd(CMD, "/Users/u/project", [TOKEN]);
    const r1 = await resolveUnresolvedPaths(pd, ctx, { stream: streamFn, settings: ON });
    const r2 = await resolveUnresolvedPaths(pd, ctx, { stream: streamFn, settings: ON });
    expect(calls).toHaveLength(1);
    expect(r1).not.toBeNull();
    expect(r2).toEqual(r1);
    // A changed command is a different key.
    await resolveUnresolvedPaths(makePd(CMD + " 2>/dev/null", "/Users/u/project", [TOKEN]), ctx, { stream: streamFn, settings: ON });
    expect(calls).toHaveLength(2);
  });
});

describe("resolver call faults reach the judge ledger (stage 0, D17)", () => {
  // 3.40.2: every no-map fault used to `return null` in silence. An operator
  // reading judge.jsonl saw the verdict stages failing and had no way to know
  // the resolver was failing for the same reason (the user-reported OpenCode
  // MissingSessionID outage hit BOTH calls; only one was visible).
  let ledger: string;
  let savedEnv: string | undefined;
  beforeEach(() => {
    savedEnv = process.env.HALTER_JUDGE_LOG;
    ledger = path.join(tmp, "judge.jsonl");
    process.env.HALTER_JUDGE_LOG = ledger;
  });
  afterEach(() => {
    if (savedEnv === undefined) delete process.env.HALTER_JUDGE_LOG;
    else process.env.HALTER_JUDGE_LOG = savedEnv;
  });
  const lines = (): Array<Record<string, unknown>> =>
    fs.existsSync(ledger)
      ? fs
          .readFileSync(ledger, "utf8")
          .split("\n")
          .filter((l) => l.trim() !== "")
          .map((l) => JSON.parse(l) as Record<string, unknown>)
      : [];
  const run = async (stream: JudgeStreamFn, ctx = makeCtx(fakeModel())) => {
    await resolveUnresolvedPaths(makePd(CMD, "/Users/u/project", [TOKEN]), ctx, { stream, settings: ON });
  };

  it("an error stop: one call-failed line carrying the provider's message", async () => {
    const err = '400: {"type":"MissingSessionID","message":"Request is missing x-opencode-session"}';
    await run(fixedStream(() => ({ ...textReply(""), stopReason: "error", errorMessage: err }) as never));
    const l = lines();
    expect(l).toHaveLength(1);
    expect(l[0]).toMatchObject({
      kind: "infra",
      stage: 0, // not a verdict stage — the resolver's own tally
      mode: "manual",
      error: "call-failed",
      model: "llama-cpp/qwen3-27b",
      cmd: CMD,
    });
    expect(String(l[0].detail)).toContain("MissingSessionID");
  });

  it("a text-only reply is no-tool-call; malformed arguments are bad-args", async () => {
    await run(fixedStream(() => textReply("I cannot tell.")));
    await run(fixedStream(() => toolCallReply("report_paths", { results: "nope" })));
    const l = lines();
    expect(l.map((e) => e.error)).toEqual(["no-tool-call", "bad-args"]);
    expect(l.every((e) => e.stage === 0)).toBe(true);
  });

  it("a stream that throws is a call-failed line with the message", async () => {
    await run((() => {
      throw new Error("network down");
    }) as JudgeStreamFn);
    const l = lines();
    expect(l).toHaveLength(1);
    expect(l[0]).toMatchObject({ stage: 0, error: "call-failed" });
    expect(String(l[0].detail)).toContain("network down");
  });

  it("auth failure and an unresolvable model are logged too (no call is made)", async () => {
    await run(fixedStream(() => toolCallReply("report_paths", { results: [] })), makeCtx(fakeModel(), false));
    await run(fixedStream(() => toolCallReply("report_paths", { results: [] })), makeCtx(undefined));
    const l = lines();
    expect(l.map((e) => e.error)).toEqual(["auth-failed", "model-unresolved"]);
    expect(l[0].model).toBe("llama-cpp/qwen3-27b");
    expect(l[1].model).toBeUndefined();
  });

  it("NOT faults, no lines: judge off, nothing unresolved, a clean 'I do not know'", async () => {
    const pd = makePd(CMD, "/Users/u/project", [TOKEN]);
    const ctx = makeCtx(fakeModel());
    await resolveUnresolvedPaths(pd, ctx, { stream: fixedStream(() => toolCallReply("report_paths", { results: [] })), settings: OFF });
    await resolveUnresolvedPaths(makePd(CMD, "/Users/u/project", []), ctx, { stream: fixedStream(() => toolCallReply("report_paths", { results: [] })), settings: ON });
    await resolveUnresolvedPaths(pd, ctx, {
      stream: fixedStream(() => toolCallReply("report_paths", { results: [{ index: 0, known: false, dirs: [] }] })),
      settings: ON,
    });
    expect(lines()).toEqual([]);
  });
});

describe("the auth resolution's endpoint and env reach the model call", () => {
  // resolveJudgeAuth used to keep only apiKey/headers. pi returns more
  // (coding-agent/src/core/model-registry.ts:89): a baseUrl override, which
  // belongs ON THE MODEL (agent-session.ts:524), and provider-scoped env.
  it("a resolved baseUrl overrides the model endpoint; env is forwarded", async () => {
    const calls: CapturedCall[] = [];
    const ctx = makeCtx(fakeModel(), true, {
      baseUrl: "http://proxy.internal:3000/v1",
      env: { HTTPS_PROXY: "http://proxy.internal:3000" },
    });
    await resolveUnresolvedPaths(makePd(CMD, "/Users/u/project", [TOKEN]), ctx, {
      stream: fixedStream(() => toolCallReply("report_paths", { results: [{ index: 0, known: true, dirs: ["/a"] }] }), calls),
      settings: ON,
    });
    expect(calls).toHaveLength(1);
    expect(calls[0].model.baseUrl).toBe("http://proxy.internal:3000/v1");
    expect(calls[0].model.id).toBe("qwen3-27b"); // the model itself is untouched
    expect(calls[0].options?.env).toEqual({ HTTPS_PROXY: "http://proxy.internal:3000" });
  });

  it("no override in the resolution → the model goes out as resolved", async () => {
    const calls: CapturedCall[] = [];
    await resolveUnresolvedPaths(makePd(CMD, "/Users/u/project", [TOKEN]), makeCtx(fakeModel()), {
      stream: fixedStream(() => toolCallReply("report_paths", { results: [{ index: 0, known: true, dirs: ["/a"] }] }), calls),
      settings: ON,
    });
    expect(calls[0].model.baseUrl).toBe("http://localhost:8080/v1");
    expect(calls[0].options?.env).toBeUndefined();
  });
});
