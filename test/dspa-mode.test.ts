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
  recordDspaStop,
  getDspaStats,
  updateDspaWidget,
  setDspaJudging,
} from "../modes/dspa-mode";
import { onStatusChange } from "../modes/status-bus";
import { updateWidget } from "../ui/widget";

const { judgeStatusMock } = vi.hoisted(() => ({
  judgeStatusMock: vi.fn<() => { state: string; modelLabel: string | null; reason: string | null }>(),
}));
vi.mock("../judge/verdict", () => ({ judgeStatus: judgeStatusMock }));

beforeEach(() => {
  resetDspa();
  judgeStatusMock.mockReset();
  judgeStatusMock.mockReturnValue({ state: "off", modelLabel: null, reason: null });
  // Production wiring (index.ts): the unified widget is the status-bus
  // listener — mode → bus → widget → setWidget.
  onStatusChange(updateWidget);
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
    expect(getDspaStats()).toEqual({ model: null, autoAllowed: 0, lastTarget: null, gate: 0, deny: 0, declined: 0, defer: 0 });
  });
});

describe("counters", () => {
  it("records auto-allows with target", () => {
    recordDspaAutoAllowed("m1", "cargo build --release");
    expect(getDspaStats()).toEqual({
      model: "m1",
      autoAllowed: 1,
      lastTarget: "cargo build --release",
      gate: 0,
      deny: 0,
      declined: 0,
      defer: 0,
    });
  });

  it("a model change resets the counters", () => {
    recordDspaAutoAllowed("m1", "a");
    recordDspaAutoAllowed("m1", "b");
    recordDspaAutoAllowed("m2", "c");
    expect(getDspaStats()).toEqual({ model: "m2", autoAllowed: 1, lastTarget: "c", gate: 0, deny: 0, declined: 0, defer: 0 });
  });

  it("stop counters: each kind increments its own bucket", () => {
    // The first NON-NULL model establishes the model scope (a prior null-
    // model stop would have been reset by it — covered below).
    recordDspaStop("gate", "m1");
    recordDspaStop("gate", null); // null model: counted, no reset
    recordDspaStop("deny", "m1");
    recordDspaStop("declined", "m1");
    recordDspaStop("defer", "m1");
    recordDspaStop("defer", null);
    expect(getDspaStats()).toMatchObject({ model: "m1", gate: 2, deny: 1, declined: 1, defer: 2 });
  });

  it("a stop with a NEW model resets all counters (model-scoped)", () => {
    recordDspaAutoAllowed("m1", "a");
    recordDspaStop("deny", "m1");
    recordDspaStop("gate", "m2");
    expect(getDspaStats()).toEqual({ model: "m2", autoAllowed: 0, lastTarget: null, gate: 1, deny: 0, declined: 0, defer: 0 });
  });

  it("a gate stop with no verdict (model null) never resets the counters", () => {
    recordDspaAutoAllowed("m1", "a");
    recordDspaStop("gate", null);
    expect(getDspaStats().autoAllowed).toBe(1);
    expect(getDspaStats().model).toBe("m1");
    expect(getDspaStats().gate).toBe(1);
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
    expect(lines[0]).toContain("1a");
    expect(lines[0]).toContain("llama-cpp/Qwen3.8-27B");
    expect(lines[0]).toContain("— last: cargo build");
    expect(lines[0].indexOf("1a")).toBeLessThan(lines[0].indexOf("last: cargo build"));
  });

  it("renders stop counts compactly, non-zero only (a g r c d order)", () => {
    judgeStatusMock.mockReturnValue({ state: "ok", modelLabel: null, reason: null });
    setDspaActive(true);
    recordDspaAutoAllowed("m1", "cargo build");
    recordDspaAutoAllowed("m1", "ls");
    recordDspaStop("gate", null);
    recordDspaStop("deny", "m1");
    recordDspaStop("defer", "m1");
    // declined stays hidden (zero)
    const { ctx, widgets, theme } = makeCtx();
    updateDspaWidget(ctx);
    const w = halterLine(widgets, theme);
    const line = w!.render(200)[0];
    // exact count run — a non-zero declined would break this ("…1r 1c 1d…")
    expect(line).toContain("2a 1g 1r 1d — last:");
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
    expect(line()).toContain("1a — judging…");
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
