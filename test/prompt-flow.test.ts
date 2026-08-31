/**
 * prompt-flow.ts — showPrompt's judge-state wiring.
 *
 * The judge must never fail silently: an invalid judge (e.g. the session
 * model became unresolvable after a switch) is surfaced in the prompt body,
 * a failed judge call under /dspat is surfaced, and the on-demand Explain
 * option is offered only when the judge can actually run.
 */
import { describe, it, expect, beforeEach, vi } from "vitest";
import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import type { Decision, PromptDecision } from "../decision-engine";

const { judgeStatusMock, verdictMock, promptSpy, resolverMock, pathsRulesMock } = vi.hoisted(() => ({
  judgeStatusMock: vi.fn(),
  verdictMock: vi.fn(),
  promptSpy: vi.fn(),
  resolverMock: vi.fn(),
  pathsRulesMock: vi.fn(),
}));

vi.mock("../judge-prompt", async (importOriginal) => ({
  judgeStatus: judgeStatusMock,
  getJudgeVerdict: verdictMock,
  // Real renderer — the suggests-line assertions below exercise it.
  judgeVerdictBlock: (await importOriginal<typeof import("../judge-prompt")>()).judgeVerdictBlock,
}));
vi.mock("../prompts", () => ({ twoTierAlwaysPrompt: promptSpy }));
vi.mock("../path-resolver", () => ({ resolveUnresolvedPaths: resolverMock }));
vi.mock("../prompt-builder", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../prompt-builder")>()),
  // Mirrors the real builder's trust contract: trustPackages derives from
  // the decision's fetchable forms (the builder, not the flow, computes it).
  buildPrompt: (decision?: any) => ({
    title: "T",
    body: "B",
    pathGrantDirs: ["/x/a", "/x/b"],
    resolverDirs: ["/x/a", "/x/b"],
    trustPackages: decision?.promptData?.fetchableForms?.length
      ? [...new Set(decision.promptData.fetchableForms.map((f: any) => f.pkg))]
      : undefined,
  }),
}));
vi.mock("../widget", () => ({ updateWidget: () => {} }));
vi.mock("../rule-generator", () => ({
  RuleGenerator: {
    generatePrimaryRules: () => [],
    generatePathsOnlyRules: pathsRulesMock,
    generateFileOnlyRules: () => null,
    generateBroaderRules: () => null,
  },
}));

import { showPrompt, type DspaFallthrough } from "../prompt-flow";
import { createStore } from "../store";
import { setDspatActive, resetDspat } from "../dspat-mode";

beforeEach(() => {
  vi.clearAllMocks();
  resetDspat();
  judgeStatusMock.mockReturnValue({ state: "ok", modelLabel: "llama-cpp/qwen (session)", reason: null });
  verdictMock.mockResolvedValue(null);
  promptSpy.mockResolvedValue("yes");
  resolverMock.mockResolvedValue(null);
  pathsRulesMock.mockReturnValue(null);
});

function bashDecision(): Decision {
  return {
    kind: "prompt",
    promptData: {
      type: "bash",
      command: "rm -rf /tmp/test",
      cwd: "/home/user/project",
      outsideDirs: [],
      segments: ["rm -rf /tmp/test"],
      signatures: ["rm"],
      relativeToolIds: [],
      nonAllowedSegmentIndices: [0],
      riskDangerous: true,
      riskSeverity: "high",
      riskReasons: ["[System] destructive delete"],
      hasUnsafePattern: true,
      credentialRule: null,
      needsCommandApproval: true,
      needsPathApproval: false,
    },
  };
}

const ctx = {
  hasUI: false,
  model: { provider: "llama-cpp", id: "qwen" },
  modelRegistry: { find: () => undefined },
  ui: {},
} as unknown as ExtensionContext;

const store = {} as never; // callbacks only fire on "always" results

function shownPrompt() {
  return promptSpy.mock.calls[0][0] as { title: string; body: string };
}
function judgeArg() {
  return promptSpy.mock.calls[0][7];
}

describe("default mode (no dspat)", () => {
  it("invalid judge → ⚠️ line in body, no Explain option", async () => {
    judgeStatusMock.mockReturnValue({ state: "invalid", modelLabel: null, reason: "session model not resolvable" });
    await showPrompt(bashDecision(), ctx, store);
    expect(shownPrompt().body).toContain("⚠️ Judge invalid: session model not resolvable");
    expect(judgeArg()).toBeUndefined();
  });

  it("ok judge → body unchanged, Explain option offered", async () => {
    await showPrompt(bashDecision(), ctx, store);
    expect(shownPrompt().body).toBe("B");
    expect(judgeArg()).toBeDefined();
  });

  it("off judge (disabled in settings) → silent, no Explain option", async () => {
    judgeStatusMock.mockReturnValue({ state: "off", modelLabel: null, reason: null });
    await showPrompt(bashDecision(), ctx, store);
    expect(shownPrompt().body).toBe("B");
    expect(judgeArg()).toBeUndefined();
  });
});

describe("/dspat active", () => {
  beforeEach(() => setDspatActive(true));

  it("invalid judge → ⚠️ line in body, no model call", async () => {
    judgeStatusMock.mockReturnValue({ state: "invalid", modelLabel: null, reason: "session model not resolvable" });
    await showPrompt(bashDecision(), ctx, store);
    expect(shownPrompt().body).toContain("⚠️ Judge invalid: session model not resolvable");
    expect(verdictMock).not.toHaveBeenCalled();
  });

  it("judge call failed (null verdict) → ⚠️ no-verdict line", async () => {
    verdictMock.mockResolvedValue(null);
    await showPrompt(bashDecision(), ctx, store);
    expect(shownPrompt().body).toContain("⚠️ Judge: no verdict (call failed or timed out)");
    expect(judgeArg()).toBeUndefined();
  });

  it("verdict shown → 💭 Judge line with suggestion, no Explain option", async () => {
    verdictMock.mockResolvedValue({
      model: "llama-cpp/qwen",
      explanation: "Removes a temp file.",
      approve: "approve",
      risk: "low",
    });
    await showPrompt(bashDecision(), ctx, store);
    const body = shownPrompt().body;
    expect(body).toContain("💭 Judge: Removes a temp file.");
    expect(body).toContain("→ suggests: APPROVE (low)");
    expect(judgeArg()).toBeUndefined();
  });

  it("defer verdict → DEFER, not REJECT (the model could not verify — a different signal)", async () => {
    verdictMock.mockResolvedValue({
      model: "llama-cpp/qwen",
      explanation: "Truncated output hides the target list.",
      approve: "defer",
      risk: "medium",
    });
    await showPrompt(bashDecision(), ctx, store);
    const body = shownPrompt().body;
    expect(body).toContain("→ suggests: DEFER (medium)");
    expect(body).not.toContain("REJECT");
    expect(judgeArg()).toBeUndefined();
  });
});

describe("/dspa fall-through", () => {
  it("gate blocked → 🚧 gate reason line (even with invalid judge)", async () => {
    judgeStatusMock.mockReturnValue({ state: "invalid", modelLabel: null, reason: "session model not resolvable" });
    const dspa: DspaFallthrough = { gate: { ok: false, reason: "dangerous: rm" }, verdict: null, stage: null };
    await showPrompt(bashDecision(), ctx, store, dspa);
    const body = shownPrompt().body;
    expect(body).toContain("🚧 DSPA: not auto-allowed — dangerous: rm");
    expect(body).not.toContain("Judge invalid");
  });

  it("gate ok, judge unavailable → 🚧 note line", async () => {
    const dspa: DspaFallthrough = { gate: { ok: true }, verdict: null, stage: null, note: "judge invalid: session model not resolvable" };
    await showPrompt(bashDecision(), ctx, store, dspa);
    expect(shownPrompt().body).toContain("🚧 DSPA: not auto-allowed — judge invalid: session model not resolvable");
  });

  it("gate ok, verdict present → 💭 Judge line (unchanged)", async () => {
    const dspa: DspaFallthrough = {
      gate: { ok: true },
      // Stage 1: an approve/medium at stage 2 would have auto-allowed, so a
      // medium-risk fallthrough verdict can only be stage 1 (needs low there).
      verdict: { model: "llama-cpp/qwen", explanation: "E.", approve: "approve", risk: "medium", reason: "r", latencyMs: 10, cached: false },
      stage: 1,
    };
    await showPrompt(bashDecision(), ctx, store, dspa);
    expect(shownPrompt().body).toContain("APPROVE (medium) — not auto-allowed (risk must be low)");
  });

  it("gate ok, deny verdict → REJECT without the not-auto-allowed note", async () => {
    const dspa: DspaFallthrough = {
      gate: { ok: true },
      verdict: { model: "llama-cpp/qwen", explanation: "E.", approve: "deny", risk: "high", reason: "r", latencyMs: 10, cached: false },
      stage: 2,
    };
    await showPrompt(bashDecision(), ctx, store, dspa);
    const body = shownPrompt().body;
    expect(body).toContain("→ suggests: REJECT (high)");
    expect(body).not.toContain("not auto-allowed (risk must be low)");
  });

  it("gate blocked on untrusted package → 🚧 line + advisory verdict block (D10)", async () => {
    const dspa: DspaFallthrough = {
      gate: { ok: false, reason: "untrusted package (npx evil-pkg)" },
      verdict: { model: "llama-cpp/qwen", explanation: "Dev tool in use this session.", approve: "approve", risk: "low", reason: "dev tool", latencyMs: 10, cached: false },
      stage: 2,
    };
    // The decision's fetchable form (from the same analysis the gate saw)
    // is what surfaces the Trust option — not a field on the fall-through.
    const decision: PromptDecision = {
      kind: "prompt",
      promptData: {
        type: "bash",
        command: "npx evil-pkg",
        cwd: "/home/user/project",
        outsideDirs: [],
        segments: ["npx evil-pkg"],
        signatures: ["npx evil-pkg"],
        relativeToolIds: [],
        nonAllowedSegmentIndices: [0],
        riskDangerous: false,
        riskSeverity: null,
        riskReasons: [],
        hasUnsafePattern: false,
        credentialRule: null,
        needsCommandApproval: true,
        needsPathApproval: false,
        fetchableForms: [{ sig: "npx evil-pkg", pkg: "evil-pkg" }],
      },
    };
    await showPrompt(decision, ctx, store, dspa);
    const body = shownPrompt().body;
    expect(body).toContain("🚧 DSPA: not auto-allowed — untrusted package (npx evil-pkg)");
    expect(body).toContain("💭 Judge: Dev tool in use this session.");
    expect(body).toContain("→ suggests: APPROVE (low) — advisory (floor stop stands)");
    // the prompt offers the Trust option for the fetchable form
    expect((shownPrompt() as any).trustPackages).toEqual(["evil-pkg"]);
  });
});

// ── Resolution persistence (path resolver → confirmed resolutions) ──────

describe("resolution persistence", () => {
  const IN_BAR = "/home/user/project/sub"; // under the decision's cwd
  const OUT_BAR = "/elsewhere/dir";

  function unresolvedDecision(): Decision {
    return {
      kind: "prompt",
      promptData: {
        type: "bash",
        command: "cat /x/$e/f",
        cwd: "/home/user/project",
        outsideDirs: ["/x/$e"],
        segments: ["cat /x/$e/f"],
        signatures: ["cat"],
        relativeToolIds: [],
        nonAllowedSegmentIndices: [0],
        riskDangerous: false,
        riskSeverity: null,
        riskReasons: [],
        hasUnsafePattern: false,
        credentialRule: null,
        needsCommandApproval: false,
        needsPathApproval: true,
        unresolved: [
          { token: "/x/$e/f", reason: "var" },
          { token: "/y/$f/f", reason: "var" },
        ],
      },
    };
  }

  it("asks the resolver only for bash prompts with unresolved tokens", async () => {
    await showPrompt(unresolvedDecision(), ctx, createStore());
    expect(resolverMock).toHaveBeenCalledTimes(1);
    // A plain command prompt (no unresolved) never resolves.
    resolverMock.mockClear();
    await showPrompt(bashDecision(), ctx, createStore());
    expect(resolverMock).not.toHaveBeenCalled();
  });

  it("yes persists only all-in-bar resolutions", async () => {
    const store = createStore();
    resolverMock.mockResolvedValue(
      new Map([
        ["/x/$e/f", [IN_BAR]],
        ["/y/$f/f", [OUT_BAR]],
      ]),
    );
    promptSpy.mockResolvedValue("yes");
    await showPrompt(unresolvedDecision(), ctx, store);
    expect(store.getConfirmedResolution("/x/$e/f")).toEqual([IN_BAR]);
    expect(store.getConfirmedResolution("/y/$f/f")).toBeNull();
  });

  it("yes persists nothing when the resolver found nothing", async () => {
    const store = createStore();
    resolverMock.mockResolvedValue(null);
    await showPrompt(unresolvedDecision(), ctx, store);
    expect(store.getConfirmedResolution("/x/$e/f")).toBeNull();
  });

  it("always grants the resolver dirs and persists every resolution", async () => {
    const store = createStore();
    resolverMock.mockResolvedValue(
      new Map([
        ["/x/$e/f", [IN_BAR]],
        ["/y/$f/f", [OUT_BAR]],
      ]),
    );
    promptSpy.mockImplementation(async (_p: unknown, _s: unknown, _c: unknown, onAlways?: () => void) => {
      onAlways?.();
      return "always";
    });
    await showPrompt(unresolvedDecision(), ctx, store);
    // The grant covers the (mocked) resolver dirs the prompt named.
    expect([...store.listAllowedReadDirs()].sort()).toEqual(["/x/a", "/x/b"]);
    // Every resolution is confirmed — the user granted what it suggested.
    expect(store.getConfirmedResolution("/x/$e/f")).toEqual([IN_BAR]);
    expect(store.getConfirmedResolution("/y/$f/f")).toEqual([OUT_BAR]);
  });

  it("alwaysPaths grants concrete ∪ resolver dirs and persists every resolution", async () => {
    const store = createStore();
    resolverMock.mockResolvedValue(
      new Map([
        ["/x/$e/f", [IN_BAR]],
        ["/y/$f/f", [OUT_BAR]],
      ]),
    );
    pathsRulesMock.mockReturnValue({ readDirs: ["/x"] });
    promptSpy.mockImplementation(async (_p: unknown, _s: unknown, _c: unknown, onAlways?: () => void, onAlwaysPaths?: () => void) => {
      onAlwaysPaths?.();
      return "alwaysPaths";
    });
    await showPrompt(unresolvedDecision(), ctx, store);
    expect([...store.listAllowedReadDirs()].sort()).toEqual(["/x", "/x/a", "/x/b"]);
    expect(store.getConfirmedResolution("/x/$e/f")).toEqual([IN_BAR]);
    expect(store.getConfirmedResolution("/y/$f/f")).toEqual([OUT_BAR]);
  });
});
