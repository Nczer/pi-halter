/**
 * dspa-mode.ts — auto-allow mode state, model-scoped session counters, widget.
 */
import { describe, it, expect, beforeEach, vi } from "vitest";
import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import { visibleWidth } from "@earendil-works/pi-tui";
import {
  isDspaActive,
  setDspaActive,
  resetDspa,
  recordDspaAutoAllowed,
  getDspaStats,
  updateDspaWidget,
  setDspaJudging,
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

  it("flattens newlines in multi-line targets (one widget element = one screen row)", () => {
    // Regression: a multi-line python3 -c command auto-allowed under /dspa
    // stored a raw \n in lastTarget; the widget line wrapped mid-row and
    // desynced the TUI diff renderer.
    recordDspaAutoAllowed("m1", 'cd /tmp/x && python3 -c "\na = 1\nb = 2\n"');
    const t = getDspaStats().lastTarget;
    expect(t).not.toMatch(/[\r\n]/);
    expect(t).toBe('cd /tmp/x && python3 -c " a = 1 b = 2 "');
  });
});

describe("widget (unified halter widget — see widget.ts)", () => {
  function makeCtx(hasUI = true) {
    const widgets: Array<{ id: string; fn: unknown }> = [];
    const theme = { fg: (_c: string, s: string) => s, bold: (s: string) => s };
    const ctx = {
      hasUI,
      ui: { setWidget: (id: string, fn: unknown) => widgets.push({ id, fn }) },
    } as unknown as ExtensionContext;
    return { ctx, widgets, theme };
  }

  type Renderable = { render: (width: number) => string[] };
  // The update re-sets the legacy ids (undefined) first, then "halter".
  const halterLine = (widgets: Array<{ id: string; fn: unknown }>, theme: unknown) => {
    const w = widgets.filter(x => x.id === "halter").pop();
    if (!w || !w.fn) return null;
    return (w.fn as (tui: unknown, theme: unknown) => Renderable)(null, theme);
  };

  it("renders the counter + last target on ONE line, pinned in the widget", () => {
    judgeStatusMock.mockReturnValue({
      state: "ok",
      modelLabel: "llama-cpp/Qwen3.8-27B (session)",
      reason: null,
    });
    setDspaActive(true);
    recordDspaAutoAllowed("llama-cpp/Qwen3.8-27B", "cargo build");
    const { ctx, widgets, theme } = makeCtx();
    updateDspaWidget(ctx);
    const w = halterLine(widgets, theme);
    expect(w).not.toBeNull();
    const lines = w!.render(200);
    expect(lines).toHaveLength(1); // one line, not two
    expect(lines[0]).toContain("» DSPA");
    expect(lines[0]).toContain("auto-allowed 1 this session");
    expect(lines[0]).toContain("llama-cpp/Qwen3.8-27B");
    expect(lines[0]).toContain("— last: cargo build");
    expect(lines[0].indexOf("auto-allowed")).toBeLessThan(lines[0].indexOf("last: cargo build"));
  });

  it("drops the last-target before truncating the line (narrow terminals)", () => {
    // Regression: the lines were truncated to a hardcoded 160, so a long
    // target rendered over-width lines and crashed pi (doRender width check).
    setDspaActive(true);
    recordDspaAutoAllowed("llama-cpp/Qwen3.8-27B", "x".repeat(120));
    const { ctx, widgets, theme } = makeCtx();
    updateDspaWidget(ctx);
    const w = halterLine(widgets, theme)!;
    expect(w.render(200)[0]).toContain("— last:");
    for (const width of [95, 80, 40]) {
      for (const line of w.render(width)) {
        expect(visibleWidth(line), `line exceeds width ${width}: ${JSON.stringify(line)}`).toBeLessThanOrEqual(width);
      }
    }
    // Main (~60 cols) still doesn't fit 40 → truncated main, detail gone.
    expect(w.render(40)[0]).not.toContain("last:");
  });

  it("renders judging… inline on the mode line while a call is in flight", () => {
    judgeStatusMock.mockReturnValue({
      state: "ok",
      modelLabel: "llama-cpp/Qwen3.8-27B (session)",
      reason: null,
    });
    setDspaActive(true);
    recordDspaAutoAllowed("llama-cpp/Qwen3.8-27B", "cargo build");
    const { ctx, widgets, theme } = makeCtx();
    updateDspaWidget(ctx);
    const line = () => halterLine(widgets, theme)!.render(200)[0];
    expect(line()).toContain("» DSPA");
    setDspaJudging(true, ctx); // re-renders the widget (forces a repaint)
    expect(line()).toContain("auto-allowed 1 this session — judging…");
    expect(line()).toContain("— last: cargo build");
    setDspaJudging(true, ctx); // no-op (already judging — no extra set)
    expect(widgets.filter(x => x.id === "halter")).toHaveLength(2); // initial + judging toggle
    setDspaJudging(false, ctx);
    expect(line()).not.toContain("judging…");
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
    const w = halterLine(widgets, theme);
    expect(w).not.toBeNull(); // widget registered (mode active)…
    expect(w!.render(200)).toEqual([]); // …but the line hides (no rules either)
    judgeStatusMock.mockReturnValue({
      state: "ok",
      modelLabel: "llama-cpp/Qwen3.8-27B (session)",
      reason: null,
    });
    expect(w!.render(200).length).toBeGreaterThan(0);
  });

  it("clears when inactive", () => {
    const { ctx, widgets } = makeCtx();
    updateDspaWidget(ctx);
    const w = widgets.filter(x => x.id === "halter").pop();
    expect(w).toBeDefined();
    expect(w!.fn).toBeUndefined();
  });

  it("no-op without UI", () => {
    const { ctx, widgets } = makeCtx(false);
    setDspaActive(true);
    updateDspaWidget(ctx);
    expect(widgets).toHaveLength(0);
  });
});
