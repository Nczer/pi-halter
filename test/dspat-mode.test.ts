/**
 * dspat-mode.ts — advisory-mode state, model-scoped session stats, widget.
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
import { updateWidget } from "../ui/widget";

const { judgeStatusMock } = vi.hoisted(() => ({
  judgeStatusMock: vi.fn<() => { state: string; modelLabel: string | null; reason: string | null }>(),
}));
vi.mock("../judge/verdict", () => ({ judgeStatus: judgeStatusMock }));

beforeEach(() => {
  resetDspat();
  judgeStatusMock.mockReset();
  judgeStatusMock.mockReturnValue({ state: "off", modelLabel: null, reason: null });
  // Production wiring (index.ts): the unified widget is the status-bus
  // listener — mode → bus → widget → setWidget.
  onStatusChange(updateWidget);
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

  it("merges indicator + counter + last disagreement onto ONE line", () => {
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
    const w = halterLine(widgets, theme);
    expect(w).not.toBeNull();
    const lines = w!.render(200);
    expect(lines).toHaveLength(1); // one line, not two
    expect(lines[0]).toContain("◎ DSPAT: judge advises on every permission prompt");
    expect(lines[0]).toContain("1/2 agreed");
    expect(lines[0]).toContain("— last: curl evil"); // last disagreement target
    expect(lines[0].indexOf("1/2 agreed")).toBeLessThan(lines[0].indexOf("last: curl evil"));
  });

  it("renders judging… inline on the mode line while a call is in flight", () => {
    judgeStatusMock.mockReturnValue({
      state: "ok",
      modelLabel: "m (session)",
      reason: null,
    });
    setDspatActive(true);
    const { ctx, widgets, theme } = makeCtx();
    updateDspatWidget(ctx);
    const line = () => halterLine(widgets, theme)!.render(200)[0];
    expect(line()).toContain("◎ DSPAT: judge advises");
    setDspatJudging(true, ctx);
    expect(line()).toContain("◎ DSPAT — judging stage 1…");
    setDspatJudging(false, ctx);
    expect(line()).not.toContain("judging");
  });

  it("drops details from the tail before truncating (narrow terminals)", () => {
    // Regression: the lines were truncated to a hardcoded 160, so a long
    // disagreement target rendered a 99-col line in a 95-col terminal and
    // crashed pi with an uncaughtException (doRender width check).
    const longTarget = "mkdir -p /tmp/gallop-trace && cat > /tmp/gallop-trace/package.json <<'EOF'";
    setDspatActive(true);
    recordDspatOutcome("m1", true, false, longTarget);
    const { ctx, widgets, theme } = makeCtx();
    updateDspatWidget(ctx);
    const w = halterLine(widgets, theme)!;
    // Wide: indicator + counter + last target.
    expect(w.render(200)[0]).toContain("0/1 agreed");
    expect(w.render(200)[0]).toContain("— last:");
    // 95/80: the long last-target drops, the counter stays.
    expect(w.render(95)[0]).toContain("0/1 agreed");
    expect(w.render(95)[0]).not.toContain("last:");
    for (const width of [95, 80, 40]) {
      for (const line of w.render(width)) {
        expect(visibleWidth(line), `line exceeds width ${width}: ${JSON.stringify(line)}`).toBeLessThanOrEqual(width);
      }
    }
    // 40: even the counter drops; the indicator itself truncates.
    expect(w.render(40)[0]).not.toContain("agreed");
  });

  it("no counter before the first verdict (indicator only)", () => {
    setDspatActive(true);
    const { ctx, widgets, theme } = makeCtx();
    updateDspatWidget(ctx);
    const w = halterLine(widgets, theme)!;
    const lines = w.render(200);
    expect(lines).toHaveLength(1);
    expect(lines.join("")).not.toContain("agreed");
  });

  it("stays up while the judge is off (mode indicator only)", () => {
    judgeStatusMock.mockReturnValue({ state: "off", modelLabel: null, reason: null });
    setDspatActive(true);
    const { ctx, widgets, theme } = makeCtx();
    updateDspatWidget(ctx);
    const w = halterLine(widgets, theme)!;
    expect(w.render(200)).toHaveLength(1);
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
    const w = halterLine(widgets, theme);
    expect(w).not.toBeNull(); // widget registered (mode active)…
    expect(w!.render(200)).toEqual([]); // …but the line hides (no rules either)
    // Back to a resolvable model → line reappears on the next render.
    judgeStatusMock.mockReturnValue({ state: "ok", modelLabel: "llama-cpp/Qwen (session)", reason: null });
    expect(w!.render(200).length).toBeGreaterThan(0);
  });

  it("clears when inactive", () => {
    const { ctx, widgets } = makeCtx();
    updateDspatWidget(ctx);
    const w = widgets.filter(x => x.id === "halter").pop();
    expect(w).toBeDefined();
    expect(w!.fn).toBeUndefined();
  });

  it("no-op without UI", () => {
    const { ctx, widgets } = makeCtx(false);
    setDspatActive(true);
    updateDspatWidget(ctx);
    expect(widgets).toHaveLength(0);
  });
});
