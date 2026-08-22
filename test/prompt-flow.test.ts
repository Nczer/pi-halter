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
import type { Decision } from "../decision-engine";

const { judgeStatusMock, verdictMock, promptSpy } = vi.hoisted(() => ({
  judgeStatusMock: vi.fn(),
  verdictMock: vi.fn(),
  promptSpy: vi.fn(),
}));

vi.mock("../judge-prompt", async (importOriginal) => ({
  judgeStatus: judgeStatusMock,
  getJudgeVerdict: verdictMock,
  // Real renderer — the suggests-line assertions below exercise it.
  judgeVerdictBlock: (await importOriginal<typeof import("../judge-prompt")>()).judgeVerdictBlock,
}));
vi.mock("../prompts", () => ({ twoTierAlwaysPrompt: promptSpy }));
vi.mock("../prompt-builder", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../prompt-builder")>()),
  buildPrompt: () => ({ title: "T", body: "B" }),
}));
vi.mock("../widget", () => ({ updateWidget: () => {} }));
vi.mock("../rule-generator", () => ({
  RuleGenerator: {
    generatePrimaryRules: () => [],
    generatePathsOnlyRules: () => null,
    generateFileOnlyRules: () => null,
    generateBroaderRules: () => null,
  },
}));

import { showPrompt, type DspaFallthrough } from "../prompt-flow";
import { setDspatActive, resetDspat } from "../dspat-mode";

beforeEach(() => {
  vi.clearAllMocks();
  resetDspat();
  judgeStatusMock.mockReturnValue({ state: "ok", modelLabel: "llama-cpp/qwen (session)", reason: null });
  verdictMock.mockResolvedValue(null);
  promptSpy.mockResolvedValue("yes");
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
      nonAllowedSegmentIndices: [0],
      riskDangerous: true,
      riskSeverity: "high",
      riskReasons: ["[System] destructive delete"],
      hasUnsafePattern: true,
      credentialRule: null,
      needsCommandApproval: true,
      needsPathApproval: false,
    },
  } as Decision;
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
    const dspa: DspaFallthrough = { gate: { ok: false, reason: "dangerous: rm" }, verdict: null };
    await showPrompt(bashDecision(), ctx, store, dspa);
    const body = shownPrompt().body;
    expect(body).toContain("🚧 dspa: not auto-allowed — dangerous: rm");
    expect(body).not.toContain("Judge invalid");
  });

  it("gate ok, judge unavailable → 🚧 note line", async () => {
    const dspa: DspaFallthrough = { gate: { ok: true }, verdict: null, note: "judge invalid: session model not resolvable" };
    await showPrompt(bashDecision(), ctx, store, dspa);
    expect(shownPrompt().body).toContain("🚧 dspa: not auto-allowed — judge invalid: session model not resolvable");
  });

  it("gate ok, verdict present → 💭 Judge line (unchanged)", async () => {
    const dspa: DspaFallthrough = {
      gate: { ok: true },
      verdict: { model: "llama-cpp/qwen", explanation: "E.", approve: "approve", risk: "medium" },
    };
    await showPrompt(bashDecision(), ctx, store, dspa);
    expect(shownPrompt().body).toContain("APPROVE (medium) — not auto-allowed (risk must be low)");
  });

  it("gate ok, deny verdict → REJECT without the not-auto-allowed note", async () => {
    const dspa: DspaFallthrough = {
      gate: { ok: true },
      verdict: { model: "llama-cpp/qwen", explanation: "E.", approve: "deny", risk: "high" },
    };
    await showPrompt(bashDecision(), ctx, store, dspa);
    const body = shownPrompt().body;
    expect(body).toContain("→ suggests: REJECT (high)");
    expect(body).not.toContain("not auto-allowed (risk must be low)");
  });
});
