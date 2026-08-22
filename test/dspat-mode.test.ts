/**
 * dspat-mode.ts — advisory-mode state, model-scoped session stats, widget.
 */
import { describe, it, expect, beforeEach, vi } from "vitest";
import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import {
  isDspatActive,
  setDspatActive,
  resetDspat,
  recordDspatOutcome,
  getDspatStats,
  updateDspatWidget,
} from "../dspat-mode";

const { judgeStatusMock } = vi.hoisted(() => ({
  judgeStatusMock: vi.fn<() => { state: string; modelLabel: string | null; reason: string | null }>(),
}));
vi.mock("../judge-prompt", () => ({ judgeStatus: judgeStatusMock }));

beforeEach(() => {
  resetDspat();
  judgeStatusMock.mockReset();
  judgeStatusMock.mockReturnValue({ state: "off", modelLabel: null, reason: null });
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
});

describe("widget", () => {
  function makeCtx(hasUI = true) {
    const widgets: Array<{ id: string; fn: unknown }> = [];
    const theme = { fg: (_c: string, s: string) => s, bold: (s: string) => s };
    const ctx = {
      hasUI,
      ui: { setWidget: (id: string, fn: unknown) => widgets.push({ id, fn }) },
    } as unknown as ExtensionContext;
    return { ctx, widgets, theme };
  }

  it("is a one-line mode indicator (no stats displayed)", () => {
    judgeStatusMock.mockReturnValue({
      state: "ok",
      modelLabel: "llama-cpp/Qwen3.8-27B (session)",
      reason: null,
    });
    setDspatActive(true);
    recordDspatOutcome("llama-cpp/Qwen3.8-27B", true, true, "a");
    recordDspatOutcome("llama-cpp/Qwen3.8-27B", true, false, "curl evil");
    const { ctx, widgets, theme } = makeCtx();
    updateDspatWidget(ctx);
    expect(widgets).toHaveLength(1);
    expect(widgets[0].id).toBe("dspat");
    const w = (widgets[0].fn as (tui: unknown, theme: unknown) => {
      render: (w: number) => string[];
    })(null, theme);
    const lines = w.render(200);
    expect(lines).toHaveLength(1);
    expect(lines[0]).toContain("👁 dspat: judge advises on every permission prompt");
    expect(lines[0]).not.toContain("disagree");
  });

  it("stays up while the judge is off (mode indicator only)", () => {
    judgeStatusMock.mockReturnValue({ state: "off", modelLabel: null, reason: null });
    setDspatActive(true);
    const { ctx, widgets, theme } = makeCtx();
    updateDspatWidget(ctx);
    const w = (widgets[0].fn as (t: unknown, th: unknown) => {
      render: () => string[];
    })(null, theme);
    expect(w.render()).toHaveLength(1);
  });

  it("hides entirely while the judge is not ok (e.g. model switched away)", () => {
    judgeStatusMock.mockReturnValue({
      state: "invalid",
      modelLabel: null,
      reason: "session model not resolvable",
    });
    setDspatActive(true);
    recordDspatOutcome("m1", true, true, "a");
    const { ctx, widgets, theme } = makeCtx();
    updateDspatWidget(ctx);
    const w = (widgets[0].fn as (t: unknown, th: unknown) => {
      render: () => string[];
    })(null, theme);
    expect(w.render()).toEqual([]);
    // Back to a resolvable model → widget reappears on the next render.
    judgeStatusMock.mockReturnValue({ state: "ok", modelLabel: "llama-cpp/Qwen (session)", reason: null });
    expect(w.render().length).toBeGreaterThan(0);
  });

  it("clears when inactive", () => {
    const { ctx, widgets } = makeCtx();
    updateDspatWidget(ctx);
    expect(widgets).toHaveLength(1);
    expect(widgets[0].fn).toBeUndefined();
  });

  it("no-op without UI", () => {
    const { ctx, widgets } = makeCtx(false);
    setDspatActive(true);
    updateDspatWidget(ctx);
    expect(widgets).toHaveLength(0);
  });
});
