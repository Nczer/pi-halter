/**
 * dspa-mode.ts — auto-allow mode state, model-scoped session counters, widget.
 */
import { describe, it, expect, beforeEach, vi } from "vitest";
import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import {
  isDspaActive,
  setDspaActive,
  resetDspa,
  recordDspaAutoAllowed,
  getDspaStats,
  updateDspaWidget,
} from "../dspa-mode";

const { judgeStatusMock } = vi.hoisted(() => ({
  judgeStatusMock: vi.fn<() => { state: string; modelLabel: string | null; reason: string | null }>(),
}));
vi.mock("../judge-prompt", () => ({ judgeStatus: judgeStatusMock }));

beforeEach(() => {
  resetDspa();
  judgeStatusMock.mockReset();
  judgeStatusMock.mockReturnValue({ state: "off", modelLabel: null, reason: null });
});

describe("mode toggle", () => {
  it("off by default, toggles on/off", () => {
    expect(isDspaActive()).toBe(false);
    setDspaActive(true);
    expect(isDspaActive()).toBe(true);
    setDspaActive(false);
    expect(isDspaActive()).toBe(false);
  });

  it("disabling resets the counters (fresh stats when re-enabled)", () => {
    setDspaActive(true);
    recordDspaAutoAllowed("m1", "cargo build");
    setDspaActive(false);
    expect(getDspaStats().autoAllowed).toBe(0);
    setDspaActive(true);
    recordDspaAutoAllowed("m1", "cargo build");
    expect(getDspaStats().autoAllowed).toBe(1);
  });

  it("resetDspa clears mode and stats", () => {
    setDspaActive(true);
    recordDspaAutoAllowed("m1", "ls");
    resetDspa();
    expect(isDspaActive()).toBe(false);
    expect(getDspaStats()).toEqual({ model: null, autoAllowed: 0, lastTarget: null });
  });
});

describe("counters", () => {
  it("records auto-allows with target", () => {
    recordDspaAutoAllowed("m1", "cargo build --release");
    expect(getDspaStats()).toEqual({
      model: "m1",
      autoAllowed: 1,
      lastTarget: "cargo build --release",
    });
  });

  it("a model change resets the counters", () => {
    recordDspaAutoAllowed("m1", "a");
    recordDspaAutoAllowed("m1", "b");
    recordDspaAutoAllowed("m2", "c");
    expect(getDspaStats()).toEqual({ model: "m2", autoAllowed: 1, lastTarget: "c" });
  });

  it("truncates long targets", () => {
    recordDspaAutoAllowed("m1", "x".repeat(200));
    expect(getDspaStats().lastTarget).toHaveLength(80);
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

  it("shows counters when active", () => {
    judgeStatusMock.mockReturnValue({
      state: "ok",
      modelLabel: "llama-cpp/Qwen3.8-27B (session)",
      reason: null,
    });
    setDspaActive(true);
    recordDspaAutoAllowed("llama-cpp/Qwen3.8-27B", "cargo build");
    const { ctx, widgets, theme } = makeCtx();
    updateDspaWidget(ctx);
    expect(widgets).toHaveLength(1);
    expect(widgets[0].id).toBe("dspa");
    const w = (widgets[0].fn as (tui: unknown, theme: unknown) => {
      render: () => string[];
    })(null, theme);
    const lines = w.render();
    expect(lines[0]).toContain("auto-allowed 1");
    expect(lines[0]).toContain("llama-cpp/Qwen3.8-27B");
    expect(lines[1]).toContain("last: cargo build");
  });

  it("hides while the judge is not ok, reappears when it is ok again", () => {
    judgeStatusMock.mockReturnValue({
      state: "invalid",
      modelLabel: null,
      reason: "session model not resolvable",
    });
    setDspaActive(true);
    const { ctx, widgets, theme } = makeCtx();
    updateDspaWidget(ctx);
    const w = (widgets[0].fn as (t: unknown, th: unknown) => {
      render: () => string[];
    })(null, theme);
    expect(w.render()).toEqual([]);
    judgeStatusMock.mockReturnValue({
      state: "ok",
      modelLabel: "llama-cpp/Qwen3.8-27B (session)",
      reason: null,
    });
    expect(w.render().length).toBeGreaterThan(0);
  });

  it("clears when inactive", () => {
    const { ctx, widgets } = makeCtx();
    updateDspaWidget(ctx);
    expect(widgets).toHaveLength(1);
    expect(widgets[0].fn).toBeUndefined();
  });

  it("no-op without UI", () => {
    const { ctx, widgets } = makeCtx(false);
    setDspaActive(true);
    updateDspaWidget(ctx);
    expect(widgets).toHaveLength(0);
  });
});
