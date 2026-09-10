/**
 * dspat-mode.ts — advisory-mode state, model-scoped session stats, status.
 */
import { describe, it, expect, beforeEach, vi } from "vitest";
import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import { visibleWidth } from "@earendil-works/pi-tui";
import {
  isDspatActive,
  setDspatActive,
  resetDspat,
  recordDspatOutcome,
  getDspatStats,
  updateDspatWidget,
  setDspatJudging,
} from "../modes/dspat-mode";
import { onStatusChange } from "../modes/status-bus";
import { updateStatus } from "../ui/widget";

const { judgeStatusMock } = vi.hoisted(() => ({
  judgeStatusMock: vi.fn<() => { state: string; modelLabel: string | null; reason: string | null }>(),
}));
vi.mock("../judge/verdict", () => ({ judgeStatus: judgeStatusMock }));

beforeEach(() => {
  resetDspat();
  judgeStatusMock.mockReset();
  judgeStatusMock.mockReturnValue({ state: "off", modelLabel: null, reason: null });
  // Production wiring (index.ts): the unified status is the status-bus
  // listener — mode → bus → status → setStatus.
  onStatusChange(updateStatus);
});

describe("mode toggle", () => {
  it("off by default, toggles on/off", () => {
    expect(isDspatActive()).toBe(false);
    setDspatActive(true);
    expect(isDspatActive()).toBe(true);
    setDspatActive(false);
    expect(isDspatActive()).toBe(false);
  });

  it("resetDspat clears the mode and all stats", () => {
    setDspatActive(true);
    recordDspatOutcome("m1", true, true, "ls");
    resetDspat();
    expect(isDspatActive()).toBe(false);
    expect(getDspatStats()).toEqual({
      model: null,
      total: 0,
      agreed: 0,
      lastDisagreement: null,
    });
  });
});

describe("stats", () => {
  it("records an agreement", () => {
    recordDspatOutcome("m1", true, true, "ls");
    expect(getDspatStats()).toEqual({
      model: "m1",
      total: 1,
      agreed: 1,
      lastDisagreement: null,
    });
  });

  it("records a disagreement with the target", () => {
    recordDspatOutcome("m1", true, false, "curl -x http://evil");
    const s = getDspatStats();
    expect(s.agreed).toBe(0);
    expect(s.lastDisagreement).toBe("curl -x http://evil");
  });

  it("a model change resets the counters (old-model stats never mix in)", () => {
    recordDspatOutcome("m1", true, true, "a");
    recordDspatOutcome("m1", true, true, "b");
    recordDspatOutcome("m2", true, false, "c");
    expect(getDspatStats()).toEqual({
      model: "m2",
      total: 1,
      agreed: 0,
      lastDisagreement: "c",
    });
  });

  it("truncates long disagreement targets", () => {
    recordDspatOutcome("m1", true, false, "x".repeat(200));
    expect(getDspatStats().lastDisagreement).toHaveLength(80);
  });

  it("flattens newlines in multi-line disagreement targets", () => {
    recordDspatOutcome("m1", true, false, 'python3 -c "\na = 1\nb = 2"');
    const t = getDspatStats().lastDisagreement;
    expect(t).not.toMatch(/[\r\n]/);
    expect(t).toBe('python3 -c " a = 1 b = 2"');
  });
});

describe("status (unified halter status — see widget.ts)", () => {
  function makeCtx(hasUI = true) {
    let status: unknown;
    const theme = { fg: (_c: string, s: string) => s, bold: (s: string) => s };
    const ctx = {
      hasUI,
      ui: {
        setStatus: (_id: string, v?: unknown) => {
          status = v;
        },
        setWidget: () => {}, // legacy id clears
        theme,
      },
    } as unknown as ExtensionContext;
    return { ctx, status: () => status };
  }

  it("indicator + agreement counter (last disagreement dropped in the migration)", () => {
    judgeStatusMock.mockReturnValue({
      state: "ok",
      modelLabel: "llama-cpp/Qwen3.8-27B (session)",
      reason: null,
    });
    setDspatActive(true);
    recordDspatOutcome("llama-cpp/Qwen3.8-27B", true, true, "a");
    recordDspatOutcome("llama-cpp/Qwen3.8-27B", true, false, "curl evil");
    const { ctx, status } = makeCtx();
    updateDspatWidget(ctx);
    expect(status()).toBe("◎ DSPAT: 1/2 agreed");
    expect(String(status())).not.toContain("last:");
  });

  it("judging transitions refresh the status without painting the stage", () => {
    judgeStatusMock.mockReturnValue({
      state: "ok",
      modelLabel: "m (session)",
      reason: null,
    });
    setDspatActive(true);
    const { ctx, status } = makeCtx();
    updateDspatWidget(ctx);
    expect(status()).toBe("◎ DSPAT");
    const before = status();
    setDspatJudging(1, ctx); // transition — status re-set with the same string
    expect(status()).toBe(before);
    setDspatJudging(2, ctx); // stage switch — still nothing painted
    expect(status()).toBe(before);
    setDspatJudging(null, ctx);
    expect(status()).toBe(before);
    expect(String(status())).not.toContain("judging");
  });

  it("stays within the fixed budget regardless of target length", () => {
    const longTarget = "mkdir -p /tmp/gallop-trace && cat > /tmp/gallop-trace/package.json <<'EOF'";
    setDspatActive(true);
    recordDspatOutcome("m1", true, false, longTarget);
    const { ctx, status } = makeCtx();
    updateDspatWidget(ctx);
    expect(status()).toBe("◎ DSPAT: 0/1 agreed");
    expect(visibleWidth(String(status()))).toBeLessThanOrEqual(40);
  });

  it("no counter before the first verdict (indicator only)", () => {
    setDspatActive(true);
    const { ctx, status } = makeCtx();
    updateDspatWidget(ctx);
    expect(status()).toBe("◎ DSPAT");
  });

  it("stays up while the judge is off (mode indicator only)", () => {
    judgeStatusMock.mockReturnValue({ state: "off", modelLabel: null, reason: null });
    setDspatActive(true);
    const { ctx, status } = makeCtx();
    updateDspatWidget(ctx);
    expect(status()).toBe("◎ DSPAT");
  });

  it("clears entirely while the judge is not ok (e.g. model switched away)", () => {
    judgeStatusMock.mockReturnValue({
      state: "invalid",
      modelLabel: null,
      reason: "session model not resolvable",
    });
    setDspatActive(true);
    recordDspatOutcome("m1", true, true, "a");
    const { ctx, status } = makeCtx();
    updateDspatWidget(ctx);
    expect(status()).toBeUndefined();
    // Back to a resolvable model → status reappears on the next update.
    judgeStatusMock.mockReturnValue({ state: "ok", modelLabel: "llama-cpp/Qwen (session)", reason: null });
    updateDspatWidget(ctx);
    expect(status()).toBe("◎ DSPAT: 1/1 agreed");
  });

  it("clears when inactive", () => {
    const { ctx, status } = makeCtx();
    updateDspatWidget(ctx);
    expect(status()).toBeUndefined();
  });

  it("no-op without UI", () => {
    const { ctx, status } = makeCtx(false);
    setDspatActive(true);
    updateDspatWidget(ctx);
    expect(status()).toBeUndefined();
  });
});
