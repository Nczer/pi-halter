/**
 * path-resolver.ts — the LLM fallback for statically unresolved tokens.
 *
 * One judge-model call reports the runtime dirs per token (grounded in the
 * command text). Tests run through the injected `complete` seam (no real
 * model): happy path, sanitize/cap rules, fail-safes (off, auth, bad
 * reply, no tool call), and the LRU cache.
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it, beforeAll, afterAll, beforeEach } from "vitest";
import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import type { AssistantMessage, Context, Model } from "@earendil-works/pi-ai";
import { resolveUnresolvedPaths, resetPathResolverCache } from "../judge/path-resolver";
import {DEFAULT_JUDGE_SETTINGS, CompleteFn, JudgeSettings} from "../judge/judge";
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
  context: Context;
  options: Record<string, unknown> | undefined;
}

function fixedComplete(reply: () => AssistantMessage, calls: CapturedCall[]): CompleteFn {
  return async (_model, context, options) => {
    calls.push({ context, options: options as CapturedCall["options"] });
    return reply();
  };
}

function makeCtx(model: Model<any> | undefined, authOk = true): ExtensionContext {
  return {
    hasUI: true,
    model,
    modelRegistry: {
      find: () => undefined,
      getApiKeyAndHeaders: async () =>
        authOk ? { ok: true, apiKey: "k" } : { ok: false, error: "no key" },
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

const CMD = `for e in a b; do grep -rn 'x' /home/u/ext/$e/*.ts; done`;
const TOKEN = "/home/u/ext/$e/*.ts";

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
    const r = await resolveUnresolvedPaths(makePd(CMD, "/home/u/project", [TOKEN]), makeCtx(fakeModel()), {
      complete: fixedComplete(() => textReply("x"), calls),
      settings: OFF,
    });
    expect(r).toBeNull();
    expect(calls).toHaveLength(0);
  });

  it("returns null when there are no unresolved tokens", async () => {
    const calls: CapturedCall[] = [];
    const pd = makePd(CMD, "/home/u/project", []);
    pd.unresolved = undefined;
    const r = await resolveUnresolvedPaths(pd, makeCtx(fakeModel()), {
      complete: fixedComplete(() => textReply("x"), calls),
      settings: ON,
    });
    expect(r).toBeNull();
    expect(calls).toHaveLength(0);
  });

  it("returns null when no model is resolvable", async () => {
    const calls: CapturedCall[] = [];
    const r = await resolveUnresolvedPaths(makePd(CMD, "/home/u/project", [TOKEN]), makeCtx(undefined), {
      complete: fixedComplete(() => textReply("x"), calls),
      settings: ON,
    });
    expect(r).toBeNull();
    expect(calls).toHaveLength(0);
  });

  it("returns null on auth failure", async () => {
    const calls: CapturedCall[] = [];
    const r = await resolveUnresolvedPaths(makePd(CMD, "/home/u/project", [TOKEN]), makeCtx(fakeModel(), false), {
      complete: fixedComplete(() => textReply("x"), calls),
      settings: ON,
    });
    expect(r).toBeNull();
    expect(calls).toHaveLength(0);
  });

  it("maps the numbered results back to tokens", async () => {
    const calls: CapturedCall[] = [];
    const tokens = [TOKEN, "/home/u/other/$f/*.ts"];
    const r = await resolveUnresolvedPaths(makePd(CMD, "/home/u/project", tokens), makeCtx(fakeModel()), {
      complete: fixedComplete(
        () => toolCallReply("report_paths", {
          results: [
            { index: 0, known: true, dirs: ["/home/u/ext/a", "/home/u/ext/b"] },
            { index: 1, known: false, dirs: [] },
          ],
        }),
        calls,
      ),
      settings: ON,
    });
    expect(calls).toHaveLength(1);
    expect(r).not.toBeNull();
    expect([...(r ?? new Map()).entries()]).toEqual([[TOKEN, ["/home/u/ext/a", "/home/u/ext/b"]]]);
  });

  it("the packet names the command, cwd, and the numbered tokens", async () => {
    const calls: CapturedCall[] = [];
    await resolveUnresolvedPaths(makePd(CMD, "/home/u/project", [TOKEN]), makeCtx(fakeModel()), {
      complete: fixedComplete(
        () => toolCallReply("report_paths", { results: [{ index: 0, known: false, dirs: [] }] }),
        calls,
      ),
      settings: ON,
    });
    const user = String((calls[0]?.context as { messages: { content: string }[] }).messages[0].content);
    expect(user).toContain(CMD);
    expect(user).toContain("Working directory: /home/u/project");
    expect(user).toContain(`1. ${TOKEN}`);
  });

  it("drops relative dirs, sentinels, and non-strings; expands ~", async () => {
    const home = os.homedir();
    const r = await resolveUnresolvedPaths(makePd(CMD, "/home/u/project", [TOKEN]), makeCtx(fakeModel()), {
      complete: fixedComplete(
        () => toolCallReply("report_paths", {
          results: [{
            index: 0,
            known: true,
            dirs: ["rel/dir", "<unresolved-var>/x", 42, "~/.pi/agent/extensions/a", "  /home/u/ext/trim  "],
          }],
        }),
        [],
      ),
      settings: ON,
    });
    expect([...(r ?? new Map()).values()][0]).toEqual([
      path.join(home, ".pi/agent/extensions/a"),
      "/home/u/ext/trim",
    ]);
  });

  it("caps dirs per token at 5", async () => {
    const r = await resolveUnresolvedPaths(makePd(CMD, "/home/u/project", [TOKEN]), makeCtx(fakeModel()), {
      complete: fixedComplete(
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
    const r = await resolveUnresolvedPaths(makePd(CMD, "/home/u/project", [TOKEN]), makeCtx(fakeModel()), {
      complete: fixedComplete(
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
    const r = await resolveUnresolvedPaths(makePd(CMD, "/home/u/project", [TOKEN]), makeCtx(fakeModel()), {
      complete: fixedComplete(
        () => toolCallReply("report_paths", { results: [{ index: 0, known: false, dirs: [] }] }),
        [],
      ),
      settings: ON,
    });
    expect(r).toBeNull();
  });

  it("returns null on a reply without a tool call", async () => {
    const r = await resolveUnresolvedPaths(makePd(CMD, "/home/u/project", [TOKEN]), makeCtx(fakeModel()), {
      complete: fixedComplete(() => textReply("I cannot tell."), [], ),
      settings: ON,
    });
    expect(r).toBeNull();
  });

  it("returns null on malformed results / a throwing complete", async () => {
    const bad = await resolveUnresolvedPaths(makePd(CMD, "/home/u/project", [TOKEN]), makeCtx(fakeModel()), {
      complete: fixedComplete(() => toolCallReply("report_paths", { results: "nope" }), []),
      settings: ON,
    });
    expect(bad).toBeNull();
    const boom = await resolveUnresolvedPaths(makePd(CMD, "/home/u/project", [TOKEN]), makeCtx(fakeModel()), {
      complete: (async () => {
        throw new Error("network down");
      }) as CompleteFn,
      settings: ON,
    });
    expect(boom).toBeNull();
  });

  it("LRU-caches on model + command + tokens", async () => {
    const calls: CapturedCall[] = [];
    const complete = fixedComplete(
      () => toolCallReply("report_paths", { results: [{ index: 0, known: true, dirs: ["/a"] }] }),
      calls,
    );
    const ctx = makeCtx(fakeModel());
    const pd = makePd(CMD, "/home/u/project", [TOKEN]);
    const r1 = await resolveUnresolvedPaths(pd, ctx, { complete, settings: ON });
    const r2 = await resolveUnresolvedPaths(pd, ctx, { complete, settings: ON });
    expect(calls).toHaveLength(1);
    expect(r1).not.toBeNull();
    expect(r2).toEqual(r1);
    // A changed command is a different key.
    await resolveUnresolvedPaths(makePd(CMD + " 2>/dev/null", "/home/u/project", [TOKEN]), ctx, { complete, settings: ON });
    expect(calls).toHaveLength(2);
  });
});
