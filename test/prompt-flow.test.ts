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

const { judgeStatusMock, verdictMock, promptSpy, resolverMock, pathsRulesMock, stage2Mock, failMock, packetMock } = vi.hoisted(() => ({
  judgeStatusMock: vi.fn(),
  verdictMock: vi.fn(),
  promptSpy: vi.fn(),
  resolverMock: vi.fn(),
  pathsRulesMock: vi.fn(),
  stage2Mock: vi.fn(),
  // The judgment packet builder — the stage-pair dedup test counts it.
  packetMock: vi.fn(async () => ({}) as never),
  // Extra outcome fields (the typed failure class judge() reports) — set by
  // the failure-identity tests, empty for every existing test.
  failMock: vi.fn(() => ({})),
}));

vi.mock("../judge/verdict", async (importOriginal) => ({
  judgeStatus: judgeStatusMock,
  buildJudgmentInput: packetMock,
  getJudgeVerdict: verdictMock,
  getStage2Verdict: stage2Mock,
  getStage1Outcome: async (...a: any[]) => ({ verdict: await verdictMock(...a), ...failMock() }),
  getStage2Outcome: async (...a: any[]) => ({ verdict: await stage2Mock(...a), ...failMock() }),
  // Real renderer — the suggests-line assertions below exercise it.
  judgeVerdictBlock: (await importOriginal<typeof import("../judge/verdict")>()).judgeVerdictBlock,
  judgeFailPhrase: (await importOriginal<typeof import("../judge/verdict")>()).judgeFailPhrase,
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
vi.mock("../ui/widget", () => ({ updateStatus: () => {} }));
vi.mock("../decide/rule-generator", () => ({
  RuleGenerator: {
    generatePrimaryRules: () => [],
    generatePathsOnlyRules: pathsRulesMock,
    generateFileOnlyRules: () => null,
    generateBroaderRules: () => null,
  },
}));

import { showPrompt } from "../ui/prompt-flow";
import * as decisionLog from "../gate/decision-log";
import type { DspaFallthrough } from "../gate/fallthrough";
import type { MissFact } from "../gate/dspa-gate";
import { createStore } from "../gate/store";
import { setDspatActive, resetDspat } from "../modes/dspat-mode";
import { getDspaStats, resetDspa } from "../modes/dspa-mode";

beforeEach(() => {
  vi.clearAllMocks();
  resetDspat();
  judgeStatusMock.mockReturnValue({ state: "ok", modelLabel: "llama-cpp/qwen (session)", reason: null });
  verdictMock.mockResolvedValue(null);
  stage2Mock.mockResolvedValue(null);
  promptSpy.mockResolvedValue("yes");
  resolverMock.mockResolvedValue(null);
  pathsRulesMock.mockReturnValue(null);
  failMock.mockReturnValue({});
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
    expect(shownPrompt().body).toContain("⚠️ Judge: no verdict — both stages failed");
    expect(judgeArg()).toBeUndefined();
  });

  it("the failure line carries judge()'s typed class and latency", async () => {
    // The user's "stage 2 fails while the server is up" report is only
    // measurable if the prompt says WHICH failure it was.
    verdictMock.mockResolvedValue(null);
    stage2Mock.mockResolvedValue(null);
    failMock.mockReturnValue({ failReason: "timeout", latencyMs: 8020 });
    await showPrompt(bashDecision(), ctx, store);
    expect(shownPrompt().body).toContain("⚠️ Judge: no verdict — both stages failed (timeout 8.0s)");
  });

  it("D17: the stage pair builds ONE judgment packet, not two", async () => {
    // The packet is stage-independent (stage 2 appends its own section in
    // judge()), and building it stats/reads the operation's reported paths.
    verdictMock.mockResolvedValue({ model: "m/x", explanation: "e", approve: "reject", risk: "high" });
    stage2Mock.mockResolvedValue({ model: "m/x", explanation: "e", approve: "reject", risk: "high" });
    packetMock.mockClear();
    await showPrompt(bashDecision(), ctx, store);
    expect(verdictMock).toHaveBeenCalledTimes(1);
    expect(stage2Mock).toHaveBeenCalledTimes(1);
    expect(packetMock).toHaveBeenCalledTimes(1);
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
    // Final verdict = stage 2's (the stage is the marker).
    expect(shownPrompt().body).toContain("\nConfirmed: scoped temp cleanup.\n→ APPROVE (low, s2)");
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
    expect(body).toContain("\nTarget escapes the cwd — unscoped delete.\n→ REJECT (high, s2)");
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
    expect(shownPrompt().body).toContain("\nRemoves a temp file.\n→ APPROVE (low, s1)");
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
    expect(shownPrompt().body).toContain("\nSession context shows a bounded target.\n→ APPROVE (medium, s2)");
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
    expect(body).toContain("\nTruncated output hides the target list.\n→ DEFER (medium, s2)");
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
  it("gate blocked → the gate reason leads as the title (even with invalid judge)", async () => {
    judgeStatusMock.mockReturnValue({ state: "invalid", modelLabel: null, reason: "session model not resolvable" });
    const dspa: DspaFallthrough = { gate: { ok: false, stopClass: "dangerous", reason: "dangerous: rm" }, verdict: null, stage: null };
    await showPrompt(bashDecision(), ctx, store, dspa);
    // The floor stop is the title now — it leads the prompt; the body scrolls.
    // The ledger's `dangerous:` bucket word and source tags are stripped for
    // the operator (2026-11-13).
    expect(shownPrompt().title).toBe("DSPA · rm");
    expect(shownPrompt().body).not.toContain("Judge invalid");
  });

  it("the title renders $HOME paths as ~/", async () => {
    const dir = path.join(os.homedir(), ".pi/agent/memories");
    const dspa: DspaFallthrough = {
      gate: { ok: false, stopClass: "dangerous", reason: `write outside base (${dir})` },
      verdict: null,
      stage: null,
    };
    await showPrompt(bashDecision(), ctx, store, dspa);
    expect(shownPrompt().title).toBe("DSPA · write outside base (~/.pi/agent/memories)");
  });

  it("gate ok, judge unavailable → `· note` line", async () => {
    const dspa: DspaFallthrough = { gate: { ok: true }, verdict: null, stage: null, note: "judge invalid: session model not resolvable" };
    await showPrompt(bashDecision(), ctx, store, dspa);
    expect(shownPrompt().body).toContain("· judge invalid: session model not resolvable");
  });

  it("gate ok, verdict present → verdict block (stage marker + why it did not auto-allow)", async () => {
    const dspa: DspaFallthrough = {
      gate: { ok: true },
      // Stage 1: an approve/medium at stage 2 would have auto-allowed, so a
      // medium-risk fallthrough verdict can only be stage 1 (needs low there).
      verdict: { model: "llama-cpp/qwen", explanation: "E.", approve: "approve", risk: "medium", reason: "r", latencyMs: 10, cached: false },
      stage: 1,
    };
    await showPrompt(bashDecision(), ctx, store, dspa);
    expect(shownPrompt().body).toContain("→ APPROVE (medium, s1) · risk > low");
  });

  it("gate ok, deny verdict → REJECT without the not-auto-allowed note", async () => {
    const dspa: DspaFallthrough = {
      gate: { ok: true },
      verdict: { model: "llama-cpp/qwen", explanation: "E.", approve: "deny", risk: "high", reason: "r", latencyMs: 10, cached: false },
      stage: 2,
    };
    await showPrompt(bashDecision(), ctx, store, dspa);
    const body = shownPrompt().body;
    expect(body).toContain("→ REJECT (high, s2)");
    expect(body).not.toContain("risk >");
  });

  it("gate blocked on untrusted package → title + advisory verdict block (D10)", async () => {
    const dspa: DspaFallthrough = {
      gate: { ok: false, stopClass: "untrusted-package", reason: "untrusted package (npx evil-pkg)" },
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
    expect(shownPrompt().title).toBe("DSPA · untrusted package (npx evil-pkg)");
    // The verdict block leads the body (the freshest word on the operation).
    expect(body).toContain("Dev tool in use this session.\n→ APPROVE (low, s2) · advisory");
    // the prompt offers the Trust option for the fetchable form
    expect((shownPrompt() as any).trustPackages).toEqual(["evil-pkg"]);
  });
});

// A write-shaped DSPA stop (the D18 base write, or the D-h write the stage-2
// judge reported): the "Always (paths)" click is the row that stops the
// repetition, so the dirs the stop named must land in the WRITE tier that click
// mints. A read-only grant leaves the write bar where it was — the identical
// command prompts again on every run.

describe("dspa write stop: the paths grant is write-shaped", () => {
  it("mints the stopped dirs as writeDirs and stores them as writes", async () => {
    const s = createStore();
    const dspa: DspaFallthrough = {
      gate: {
        ok: false,
        advisory: true,
        stopClass: "write-outside-base",
        reason: "reported write outside the write bar (/home/user/Downloads)",
        writeOutside: ["/home/user/Downloads"],
      },
      verdict: null,
      stage: null,
    };
    // The real generator splits the prompt data's two tiers; here it just
    // echoes the write tier it was handed.
    pathsRulesMock.mockImplementation((data: any) => ({ writeDirs: data.outsideWriteDirs ?? [] }));
    promptSpy.mockImplementation(async (
      _p: unknown, _s: unknown, _c: unknown, _onAlways: unknown, onAlwaysPaths?: () => void,
    ) => {
      onAlwaysPaths?.();
      return "alwaysPaths";
    });
    await showPrompt(bashDecision(), ctx, s, dspa);
    expect(pathsRulesMock.mock.calls[0][0].outsideWriteDirs).toEqual(["/home/user/Downloads"]);
    expect([...s.listAllowedWriteDirs()]).toEqual(["/home/user/Downloads"]);
  });
});

// The credential floor named one directory it could be accredited for
// (docs/dspa-credential-vouch.md). The click that accepts the offer records
// BOTH grants (V-d): the accreditation, which stands the credential floor down,
// and the read grant it presumes — without the read grant the next command under
// the dir stops on `outside base` and the accreditation looks broken. It grants
// no verdict: the judge still rules every run (G6).

describe("credential stop: the accreditation offer and its click", () => {
  const credStop = (accreditDir?: string): DspaFallthrough =>
    ({
      gate: {
        ok: false,
        advisory: true,
        reason: "credential file (/w/certs/ca.pem)",
        ...(accreditDir ? { accreditDir } : {}),
      },
      verdict: null,
      stage: null,
    }) as DspaFallthrough;

  it("carries the stopped dir to the prompt, for the option to name", async () => {
    await showPrompt(bashDecision(), ctx, createStore(), credStop("/w/certs"));
    expect((promptSpy.mock.calls[0][0] as { accreditDir?: string }).accreditDir).toBe("/w/certs");
  });

  it("the click accredits the dir and grants read for it", async () => {
    const s = createStore();
    promptSpy.mockImplementation(async (_p: unknown, _st: unknown, _c: unknown, ...rest: unknown[]) => {
      (rest[8] as () => void)(); // index 11: onAccredit
      return "always";
    });
    const r = await showPrompt(bashDecision(), ctx, s, credStop("/w/certs"));
    expect([...s.listAccreditedDirs()]).toEqual(["/w/certs"]);
    expect(s.isInsideAllowedDir("/w/certs/sub/ca.pem", "read")).toBe(true);
    expect(s.isInsideAllowedDir("/w/certs/ca.pem", "write")).toBe(false);
    expect(r.allowed).toBe(true);
  });

  it("a stop with nothing dir-shaped to accredit carries nothing", async () => {
    const s = createStore();
    await showPrompt(bashDecision(), ctx, s, credStop());
    expect((promptSpy.mock.calls[0][0] as { accreditDir?: string }).accreditDir).toBeUndefined();
    expect([...s.listAccreditedDirs()]).toEqual([]);
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
    await showPrompt(bashDecision(), ctx, store, fallthrough({ ok: false, stopClass: "dangerous", reason: "dangerous: rm" }, { ...defer1, approve: "approve", risk: "low" }, 2), request);
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
    expect(r.body).toContain("→ APPROVE (high, s2) · risk > medium");
  });

  it("retry() with a failed stage-2 call → replacement body with the failure note", async () => {
    await showPrompt(bashDecision(), ctx, store, fallthrough({ ok: true }, defer1, 1, "stage 2 unavailable"), request);
    const r = await retryArg()!.retry();
    expect(r.autoAllowed).toBe(false);
    expect(r.body).toContain("stage 2 produced no verdict");
  });

  it("retry() names the typed failure class in that note", async () => {
    failMock.mockReturnValue({ failReason: "no-tool-call", latencyMs: 1200 });
    await showPrompt(bashDecision(), ctx, store, fallthrough({ ok: true }, defer1, 1, "stage 2 unavailable"), request);
    const r = await retryArg()!.retry();
    expect(r.body).toContain("stage 2 produced no verdict (no-tool-call 1.2s)");
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

// ── Unresolved ledger: one row per token, not two ──────────────────────

describe("unresolved ledger on a dspa miss stop", () => {
  const logFile = path.join(os.tmpdir(), `halter-prompt-flow-unres-${process.pid}.jsonl`);
  const rows = (): Array<Record<string, unknown>> =>
    fs.existsSync(logFile)
      ? fs.readFileSync(logFile, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l))
      : [];
  const MISS = "/x/$e/f";
  const MISS_FACT: MissFact = { kind: "unresolved", token: MISS, prefix: "", role: "read", confirmedPrior: false };

  beforeEach(() => {
    fs.rmSync(logFile, { force: true });
    process.env.HALTER_UNRESOLVED_LOG = logFile;
  });
  afterEach(() => {
    delete process.env.HALTER_UNRESOLVED_LOG;
    fs.rmSync(logFile, { force: true });
  });

  /** A miss stop: the fall-through carries the row data prompt-flow writes
   *  AFTER the click (the intent pass no longer writes at stop time). */
  function missStop(extra: MissFact[] = []): DspaFallthrough {
    const misses = [MISS_FACT, ...extra];
    return {
      gate: { ok: false, stopClass: "outside-base", reason: `runtime location unresolvable (${MISS})`, misses },
      verdict: null,
      stage: null,
      missLedger: {
        misses,
        guard: `unanchored location unanswerable (${MISS})`,
        answered: new Map([[MISS, ["/home/user/project/notes.md"]]]),
      },
    };
  }

  function decision(): Decision {
    return {
      kind: "prompt",
      promptData: {
        type: "bash",
        command: "cat /x/$e/f /y/$f/f",
        cwd: "/home/user/project",
        outsideDirs: ["/x/$e", "/y/$f"],
        segments: ["cat /x/$e/f /y/$f/f"],
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
          { token: MISS, reason: "var" },
          { token: "/y/$f/f", reason: "var" },
        ],
      },
    };
  }

  it("writes ONE intent-declined row per miss token, carrying the click (2026-11-10)", async () => {
    // Rows 44→45 and 74→75 in the old live ledger: one decided stop read as
    // two events. Before 3.52.1 the surviving row was written at stop time,
    // so it could not name the operator's answer; now the row waits for it.
    await showPrompt(decision(), ctx, createStore(), missStop());
    const r = rows();
    expect(r.map((x) => [x.token, x.outcome, x.decision])).toEqual([
      ["/y/$f/f", "gate-stop", "yes"],
      [MISS, "intent-declined", "yes"],
    ]);
    // The deferred row carries the guard and the §4.2 match set computed at
    // stop time from the same report the guard used.
    expect(r.find((x) => x.token === MISS)).toMatchObject({
      guard: `unanchored location unanswerable (${MISS})`,
      judgePaths: ["/home/user/project/notes.md"],
      persisted: false,
    });
  });

  it("the deferred row records a resolution the click stored", async () => {
    resolverMock.mockResolvedValue(new Map([[MISS, ["/home/user/project/sub"]]]));
    await showPrompt(decision(), ctx, createStore(), missStop());
    // `yes` confirms only all-in-bar resolutions; this one is under the cwd.
    expect(rows().find((x) => x.token === MISS)).toMatchObject({ decision: "yes", persisted: true });
  });

  it("writes a row for a miss the prompt's unresolved list never names", async () => {
    // outside-path / base-write facts are not in promptData.unresolved — the
    // generic loop cannot log them, so the deferred writer must.
    const outside: MissFact = { kind: "outside-path", token: "/x/outside", prefix: "/x/outside", role: "read", confirmedPrior: false };
    await showPrompt(decision(), ctx, createStore(), missStop([outside]));
    expect(rows().filter((x) => x.outcome === "intent-declined").map((x) => x.token).sort()).toEqual(
      [MISS, "/x/outside"].sort(),
    );
  });

  it("writes nothing when the prompt fails before an answer", async () => {
    promptSpy.mockRejectedValue(new Error("ui gone"));
    await expect(showPrompt(decision(), ctx, createStore(), missStop())).rejects.toThrow("ui gone");
    expect(rows()).toEqual([]);
  });

  it("without a miss list every token still gets its prompt row", async () => {
    // A bare stop (no intent pass ran) keeps the generic rows: nothing else
    // records those tokens.
    const bare: DspaFallthrough = { gate: { ok: false, stopClass: "network-egress", reason: "network egress (https://x.y/z)" }, verdict: null, stage: null };
    await showPrompt(decision(), ctx, createStore(), bare);
    expect(rows().map((r) => r.outcome)).toEqual(["gate-stop", "gate-stop"]);
  });
});

describe("path ledger: the two prompt-flow sites pass ctx", () => {
  // judgePathLogFields splits a judge path report against the floor AND the
  // Session context the judge was shown. Without ctx that second side is
  // `undefined` and every context echo — a path the parser missed but the
  // session carried — is filed as `floorMisses`, i.e. as a parser blind spot
  // the floor does not have. Measured on the live judge ledger: 82 floorMiss
  // entries vs 29 contextMiss entries, so the omission misfiles about a
  // quarter of the misses. gate/fallthrough.ts passes ctx at all three of its
  // sites; these two (the /dspat on-demand pass, the Judge-again retry) did not.
  const approveHigh = {
    model: "llama-cpp/qwen", explanation: "E.", approve: "approve" as const, risk: "high" as const,
    reason: "r", latencyMs: 10, cached: false, paths: ["/x/outside"],
  };
  const request: PermissionRequest = { type: "bash", command: "rm -rf /tmp/test", cwd: "/home/user/project" };
  let spy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    spy = vi.spyOn(decisionLog, "logJudgePaths").mockImplementation(() => {});
  });
  afterEach(() => vi.mocked(decisionLog.logJudgePaths).mockRestore());

  it("/dspat on-demand pass", async () => {
    setDspatActive(true);
    stage2Mock.mockResolvedValue(approveHigh);
    await showPrompt(bashDecision(), ctx, store);
    expect(spy).toHaveBeenCalledWith(
      expect.objectContaining({ command: "rm -rf /tmp/test" }), store, approveHigh, "dspat", ctx,
    );
  });

  it("Judge-again retry (a non-allowing retry reports its own paths)", async () => {
    stage2Mock.mockResolvedValue(approveHigh);
    const dspa = { gate: { ok: true }, verdict: null, stage: null, note: "judge call failed" } as DspaFallthrough;
    await showPrompt(bashDecision(), ctx, store, dspa, request);
    await retryArg()!.retry();
    expect(spy).toHaveBeenCalledWith(
      expect.objectContaining({ command: "rm -rf /tmp/test" }), store, approveHigh, "dspa", ctx,
    );
  });
});

describe("Judge again: the retry's state is the row's state (one row per call)", () => {
  // The retry used to write its OWN auto-allow row and leave gate()'s prompt
  // row on the pre-prompt fields: the same tool call appeared in the auto-allow
  // tally and the prompt tally (live log: 2 pairs, identical to the
  // millisecond, and DecisionLogEntry has no per-call id to dedupe them with),
  // and neither row described the verdict that actually decided. Now: the retry
  // keeps every side effect except the decision row, and reports its state up
  // so gate()'s row — the call's only row — carries it.
  const request: PermissionRequest = { type: "bash", command: "rm -rf /tmp/test", cwd: "/home/user/project" };
  const decLog = path.join(os.tmpdir(), `pf-retry-row-${process.pid}.jsonl`);
  const rows = (): Array<Record<string, unknown>> =>
    fs.existsSync(decLog)
      ? fs.readFileSync(decLog, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l))
      : [];
  const dspa = { gate: { ok: true }, verdict: null, stage: null, note: "judge call failed" } as DspaFallthrough;

  beforeEach(() => {
    resetDspa();
    fs.rmSync(decLog, { force: true });
    process.env.HALTER_DECISION_LOG = decLog;
  });
  afterEach(() => {
    delete process.env.HALTER_DECISION_LOG;
    fs.rmSync(decLog, { force: true });
  });

  /** Click "Judge again" inside the prompt, then answer Yes to the re-shown one. */
  async function runWithRetry(v2: object | null) {
    stage2Mock.mockResolvedValue(v2 as never);
    promptSpy.mockImplementation(async (_p: unknown, _s: unknown, _c: unknown, ...rest: unknown[]) => {
      const hook = rest.find(
        (x) => !!x && typeof x === "object" && typeof (x as { retry?: unknown }).retry === "function",
      ) as { retry: () => Promise<unknown> };
      await hook.retry();
      return "yes";
    });
    return showPrompt(bashDecision(), ctx, store, dspa, request);
  }

  it("an approving retry auto-allows, still counts, and writes no row of its own", async () => {
    const res = await runWithRetry({
      model: "llama-cpp/qwen", explanation: "the user asked for exactly this",
      approve: "approve", risk: "medium", reason: "r", latencyMs: 10, cached: false,
    });
    expect(res.allowed).toBe(true);
    expect(getDspaStats().autoAllowed).toBe(1); // the judge's allow still counts
    expect(rows()).toEqual([]);                 // gate() owns the call's single row
    expect(res.judgeRefresh).toMatchObject({
      dspa: "judge: stage 2 approved on retry (llama-cpp/qwen)",
      judgeVerdict: "approve", judgeStage: 2, judgeModel: "llama-cpp/qwen",
    });
  });

  it("a rejecting retry replaces the verdict fields, and the tag says it was a retry", async () => {
    const res = await runWithRetry({
      model: "llama-cpp/qwen", explanation: "unscoped delete",
      approve: "deny", risk: "high", reason: "r", latencyMs: 10, cached: false,
    });
    expect(res.allowed).toBe(true); // the operator answered Yes anyway — the prompt's job
    expect(getDspaStats().autoAllowed).toBe(0);
    expect(rows()).toEqual([]);
    expect(res.judgeRefresh).toMatchObject({
      dspa: "judge: declined (stage 2) on retry",
      stopClass: "judge-declined",
      stopDetail: "deny (stage 2)",
      judgeVerdict: "deny", judgeStage: 2,
    });
    expect(res.judgeRefresh?.judgeExplain).toBe("unscoped delete");
  });

  it("a retry that fails again says so, as a retry", async () => {
    const res = await runWithRetry(null);
    expect(res.judgeRefresh).toMatchObject({
      dspa: "judge: stage 2 produced no verdict on retry",
      stopClass: "judge-failed",
    });
    expect(String(res.judgeRefresh?.stopDetail)).toContain("on retry");
  });
});
