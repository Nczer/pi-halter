import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { isDspActive, setDspActive, updateDspWidget } from "../modes/dsp-mode";
import { onStatusChange } from "../modes/status-bus";
import { updateWidget } from "../ui/widget";

describe("dsp-mode", () => {
  beforeEach(() => {
    setDspActive(false);
    // Production wiring (index.ts): the unified widget is the status-bus
    // listener. The widget-delegation tests below exercise mode → bus →
    // widget → setWidget through that real edge.
    onStatusChange(updateWidget);
  });

  afterEach(() => {
    setDspActive(false);
  });

  describe("isDspActive / setDspActive", () => {
    it("defaults to inactive", () => {
      expect(isDspActive()).toBe(false);
    });

    it("activates when set to true", () => {
      setDspActive(true);
      expect(isDspActive()).toBe(true);
    });

    it("deactivates when set to false", () => {
      setDspActive(true);
      setDspActive(false);
      expect(isDspActive()).toBe(false);
    });
  });

  describe("updateDspWidget (delegates to the unified halter widget — widget.ts)", () => {
    it("is a no-op when hasUI is false", () => {
      const ctx = { hasUI: false } as any;
      expect(() => updateDspWidget(ctx)).not.toThrow();
    });

    it("sets the unified widget when dsp is active", () => {
      const setWidget = vi.fn();
      const ctx = { hasUI: true, ui: { setWidget } } as any;
      setDspActive(true);
      updateDspWidget(ctx);
      expect(setWidget).toHaveBeenCalledWith("halter", expect.any(Function), { placement: "belowEditor" });
      // The legacy per-mode ids are cleared (no stale duplicate warning).
      expect(setWidget).toHaveBeenCalledWith("dsp-warning", undefined);
    });

    it("clears the widget when dsp is inactive and no rules exist", () => {
      const setWidget = vi.fn();
      const ctx = { hasUI: true, ui: { setWidget } } as any;
      setDspActive(false);
      updateDspWidget(ctx);
      expect(setWidget).toHaveBeenLastCalledWith("halter", undefined);
    });

    it("widget render returns the warning line alone when active (rules hidden)", () => {
      const setWidget = vi.fn();
      const ctx = { hasUI: true, ui: { setWidget } } as any;
      setDspActive(true);
      updateDspWidget(ctx);

      // Extract the unified widget builder and call it
      const builder = setWidget.mock.calls.find((c: unknown[]) => c[0] === "halter")![1];
      const theme = { fg: (c: string, t: string) => `[${c}]${t}`, bold: (t: string) => t };
      const widget = builder(null, theme);

      expect(typeof widget.render).toBe("function");
      const rendered = widget.render(80);
      expect(Array.isArray(rendered)).toBe(true);
      expect(rendered).toHaveLength(1); // warning alone — session rules are noise in DSP mode
      expect(rendered[0]).toContain("DSP");
      expect(rendered[0]).toContain("all permissions bypassed");
    });

    it("toggle off then on re-creates the widget", () => {
      const setWidget = vi.fn();
      const ctx = { hasUI: true, ui: { setWidget } } as any;

      // Toggle ON
      setDspActive(true);
      updateDspWidget(ctx);
      expect(setWidget).toHaveBeenLastCalledWith("halter", expect.any(Function), { placement: "belowEditor" });

      // Toggle OFF (no rules) → cleared
      setDspActive(false);
      updateDspWidget(ctx);
      expect(setWidget).toHaveBeenLastCalledWith("halter", undefined);

      // Toggle ON again
      setDspActive(true);
      updateDspWidget(ctx);
      expect(setWidget).toHaveBeenLastCalledWith("halter", expect.any(Function), { placement: "belowEditor" });
    });
  });
});
