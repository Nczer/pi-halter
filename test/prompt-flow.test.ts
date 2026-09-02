/**
 * prompt-flow.ts — showPrompt's judge-state wiring.
 *
 * The judge must never fail silently: an invalid judge (e.g. the session
 * model became unresolvable after a switch) is surfaced in the prompt body,
 * a failed judge call under /dspat is surfaced, and the on-demand Explain
 * option is offered only when the judge can actually run.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import type {Decision, PermissionRequest, PromptDecision} from "../decide/types";

const { judgeStatusMock, verdictMock, promptSpy, resolverMock, pathsRulesMock, stage2Mock } = vi.hoisted(() => ({
  judgeStatusMock: vi.fn(),
  verdictMock: vi.fn(),
  promptSpy: vi.fn(),
  resolverMock: vi.fn(),
  pathsRulesMock: vi.fn(),
  stage2Mock: vi.fn(),
}));

vi.mock("../judge/verdict", async (importOriginal) => ({
  judgeStatus: judgeStatusMock,
  getJudgeVerdict: verdictMock,
  getStage2Verdict: stage2Mock,
  // Real renderer — the suggests-line assertions below exercise it.
  judgeVerdictBlock: (await importOriginal<typeof import("../judge/verdict")>()).judgeVerdictBlock,
}));
vi.mock("../ui/prompts", () => ({ twoTierAlwaysPrompt: promptSpy }));
vi.mock("../judge/path-resolver", () => ({ resolveUnresolvedPaths: resolverMock }));
vi.mock("../ui/prompt-builder", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../ui/prompt-builder")>()),
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
vi.mock("../ui/widget", () => ({ updateWidget: () => {} }));
vi.mock("../decide/rule-generator", () => ({
  RuleGenerator: {
    generatePrimaryRules: () => [],
    generatePathsOnlyRules: pathsRulesMock,
    generateFileOnlyRules: () => null,
    generateBroaderRules: () => null,
  },
}));

import { showPrompt } from "../ui/prompt-flow";
import type { DspaFallthrough } from "../gate/fallthrough";
import { createStore } from "../gate/store";
import { setDspatActive, resetDspat } from "../modes/dspat-mode";
import { getDspaStats } from "../modes/dspa-mode";

beforeEach(() => {
  vi.clearAllMocks();
  resetDspat();
  judgeStatusMock.mockReturnValue({ state: "ok", modelLabel: "llama-cpp/qwen (session)", reason: null });
  verdictMock.mockResolvedValue(null);
  stage2Mock.mockResolvedValue(null);
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
function retryArg() {
  return promptSpy.mock.calls[0][9];
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

  it("judge call failed (both stages null) → ⚠️ no-verdict line", async () => {
    verdictMock.mockResolvedValue(null);
    stage2Mock.mockResolvedValue(null);
    await showPrompt(bashDecision(), ctx, store);
    expect(shownPrompt().body).toContain("⚠️ Judge: no verdict (both stages failed or timed out)");
    expect(judgeArg()).toBeUndefined();
  });

  it("D17: BOTH stages run (stage 2 never skipped, even on stage-1 approve+low)", async () => {
    verdictMock.mockResolvedValue({
      model: "llama-cpp/qwen",
      explanation: "Removes a temp file.",
      approve: "approve",
      risk: "low",
    });
    stage2Mock.mockResolvedValue({
      model: "llama-cpp/qwen",
      explanation: "Confirmed: scoped temp cleanup.",
      approve: "approve",
      risk: "low",
    });
    await showPrompt(bashDecision(), ctx, store);
    expect(verdictMock).toHaveBeenCalledTimes(1);
    expect(stage2Mock).toHaveBeenCalledTimes(1);
    // Final verdict = stage 2's.
    expect(shownPrompt().body).toContain("💭 Judge: Confirmed: scoped temp cleanup.");
    expect(judgeArg()).toBeUndefined();
  });

  it("D17: stage 1 approve+low, stage 2 upgrades → stage 2 shown (the blind-spot probe)", async () => {
    verdictMock.mockResolvedValue({
      model: "llama-cpp/qwen",
      explanation: "Looks like a temp cleanup.",
      approve: "approve",
      risk: "low",
    });
    stage2Mock.mockResolvedValue({
      model: "llama-cpp/qwen",
      explanation: "Target escapes the cwd — unscoped delete.",
      approve: "deny",
      risk: "high",
    });
    await showPrompt(bashDecision(), ctx, store);
    const body = shownPrompt().body;
    expect(body).toContain("💭 Judge: Target escapes the cwd — unscoped delete.");
    expect(body).toContain("→ suggests: REJECT (high)");
    expect(body).not.toContain("Looks like a temp cleanup.");
  });

  it("D17: stage 2 failed → stage 1 verdict shown", async () => {
    verdictMock.mockResolvedValue({
      model: "llama-cpp/qwen",
      explanation: "Removes a temp file.",
      approve: "approve",
      risk: "low",
    });
    stage2Mock.mockResolvedValue(null);
    await showPrompt(bashDecision(), ctx, store);
    expect(shownPrompt().body).toContain("💭 Judge: Removes a temp file.");
    expect(shownPrompt().body).toContain("→ suggests: APPROVE (low)");
  });

  it("D17: stage 1 failed → stage 2 verdict shown", async () => {
    verdictMock.mockResolvedValue(null);
    stage2Mock.mockResolvedValue({
      model: "llama-cpp/qwen",
      explanation: "Session context shows a bounded target.",
      approve: "approve",
      risk: "medium",
    });
    await showPrompt(bashDecision(), ctx, store);
    expect(shownPrompt().body).toContain("💭 Judge: Session context shows a bounded target.");
    expect(shownPrompt().body).toContain("→ suggests: APPROVE (medium)");
  });

  it("defer verdict (final stage) → DEFER, not REJECT (the model could not verify — a different signal)", async () => {
    stage2Mock.mockResolvedValue({
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

describe("D17: dspat stage disagreement → always-on judge ledger", () => {
  const judgeLog = path.join(os.tmpdir(), `pf-judge-ledger-${process.pid}.jsonl`);
  const savedJudgeLog = process.env.HALTER_JUDGE_LOG;

  function judgeLines(): Array<Record<string, unknown>> {
    if (!fs.existsSync(judgeLog)) return [];
    return fs.readFileSync(judgeLog, "utf8").trim().split("\n").map((l) => JSON.parse(l));
  }

  beforeEach(() => {
    setDspatActive(true);
    fs.rmSync(judgeLog, { force: true });
    process.env.HALTER_JUDGE_LOG = judgeLog;
  });
  afterEach(() => {
    if (savedJudgeLog === undefined) delete process.env.HALTER_JUDGE_LOG;
    else process.env.HALTER_JUDGE_LOG = savedJudgeLog;
    fs.rmSync(judgeLog, { force: true });
  });

  it("stage-1 low, stage-2 high → diff line (the blind-spot probe)", async () => {
    verdictMock.mockResolvedValue({
      model: "llama-cpp/qwen", explanation: "Looks safe.", approve: "approve", risk: "low",
    });
    stage2Mock.mockResolvedValue({
      model: "llama-cpp/qwen", explanation: "Unscoped delete.", approve: "deny", risk: "high",
    });
    await showPrompt(bashDecision(), ctx, store);
    expect(judgeLines()).toEqual([
      expect.objectContaining({
        kind: "diff", mode: "dspat", s1: "approve/low", s2: "deny/high",
        cmd: "rm -rf /tmp/test",
      }),
    ]);
  });

  it("stages agree → no line (the ledger only records signal)", async () => {
    verdictMock.mockResolvedValue({
      model: "llama-cpp/qwen", explanation: "Safe.", approve: "approve", risk: "low",
    });
    stage2Mock.mockResolvedValue({
      model: "llama-cpp/qwen", explanation: "Confirmed safe.", approve: "approve", risk: "low",
    });
    await showPrompt(bashDecision(), ctx, store);
    expect(fs.existsSync(judgeLog)).toBe(false);
  });

  it("one stage failed → no diff line (a diff needs both sides)", async () => {
    verdictMock.mockResolvedValue(null);
    stage2Mock.mockResolvedValue({
      model: "llama-cpp/qwen", explanation: "Bounded.", approve: "approve", risk: "medium",
    });
    await showPrompt(bashDecision(), ctx, store);
    expect(fs.existsSync(judgeLog)).toBe(false);
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

describe("Judge again wiring (dspa fall-through)", () => {
  const request: PermissionRequest = { type: "bash", command: "rm -rf /tmp/test", cwd: "/home/user/project" };
  const defer1 = { model: "llama-cpp/qwen", explanation: "E.", approve: "defer" as const, risk: "low" as const, reason: "r", latencyMs: 10, cached: false };
  const fallthrough = (gate: DspaFallthrough["gate"], verdict: DspaFallthrough["verdict"], stage: DspaFallthrough["stage"], note?: string): DspaFallthrough =>
    ({ gate, verdict, stage, note } as DspaFallthrough);

  it("floor passed + stage-2 call failed (stage-1 verdict carried) + request → retry hook offered", async () => {
    await showPrompt(bashDecision(), ctx, store, fallthrough({ ok: true }, defer1, 1, "stage 2 unavailable"), request);
    expect(retryArg()).toBeDefined();
  });

  it("floor passed + no verdict at all → retry hook offered", async () => {
    await showPrompt(bashDecision(), ctx, store, fallthrough({ ok: true }, null, null, "judge call failed"), request);
    expect(retryArg()).toBeDefined();
  });

  it("legitimate stage-2 DEFER → no retry (a judgment, not an infra failure)", async () => {
    await showPrompt(bashDecision(), ctx, store, fallthrough({ ok: true }, defer1, 2), request);
    expect(retryArg()).toBeUndefined();
  });

  it("legitimate stage-2 REJECT → no retry (the judgment stands)", async () => {
    await showPrompt(bashDecision(), ctx, store, fallthrough({ ok: true }, { ...defer1, approve: "deny", risk: "high" }, 2), request);
    expect(retryArg()).toBeUndefined();
  });

  it("judge off → no retry (a choice, not a transient failure)", async () => {
    judgeStatusMock.mockReturnValue({ state: "off", modelLabel: null, reason: null });
    await showPrompt(bashDecision(), ctx, store, fallthrough({ ok: true }, null, null), request);
    expect(retryArg()).toBeUndefined();
  });

  it("floor stop → no retry (the deterministic layer is not re-judged)", async () => {
    await showPrompt(bashDecision(), ctx, store, fallthrough({ ok: false, reason: "dangerous: rm" }, { ...defer1, approve: "approve", risk: "low" }, 2), request);
    expect(retryArg()).toBeUndefined();
  });

  it("no request → no retry (the auto-allow log line needs it)", async () => {
    await showPrompt(bashDecision(), ctx, store, fallthrough({ ok: true }, defer1, 1, "stage 2 unavailable"));
    expect(retryArg()).toBeUndefined();
  });

  it("retry() re-runs stage 2; approve+low → auto-allow (counter + toast)", async () => {
    stage2Mock.mockResolvedValue({ model: "llama-cpp/qwen", explanation: "E2.", approve: "approve", risk: "low", reason: "r2", latencyMs: 10, cached: false });
    const notify = vi.fn();
    const uiCtx = { ...ctx, ui: { ...ctx.ui, notify } } as never;
    await showPrompt(bashDecision(), uiCtx, store, fallthrough({ ok: true }, defer1, 1, "stage 2 unavailable"), request);
    const before = getDspaStats().autoAllowed;
    const r = await retryArg()!.retry();
    expect(stage2Mock).toHaveBeenCalledTimes(1);
    expect(r).toEqual({ autoAllowed: true, body: null });
    expect(getDspaStats().autoAllowed).toBe(before + 1);
    expect(notify).toHaveBeenCalled();
  });

  it("retry() with an over-authority verdict → replacement body, still prompting", async () => {
    stage2Mock.mockResolvedValue({ model: "llama-cpp/qwen", explanation: "E2.", approve: "approve", risk: "high", reason: "r2", latencyMs: 10, cached: false });
    await showPrompt(bashDecision(), ctx, store, fallthrough({ ok: true }, defer1, 1, "stage 2 unavailable"), request);
    const r = await retryArg()!.retry();
    expect(r.autoAllowed).toBe(false);
    expect(r.body).toContain("APPROVE (high) — not auto-allowed (risk must be low or medium)");
  });

  it("retry() with a failed stage-2 call → replacement body with the failure note", async () => {
    await showPrompt(bashDecision(), ctx, store, fallthrough({ ok: true }, defer1, 1, "stage 2 unavailable"), request);
    const r = await retryArg()!.retry();
    expect(r.autoAllowed).toBe(false);
    expect(r.body).toContain("stage 2 produced no verdict");
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
