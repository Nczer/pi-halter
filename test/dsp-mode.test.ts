import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { isDspActive, setDspActive, updateDspWidget } from "../dsp-mode";

describe("dsp-mode", () => {
  beforeEach(() => {
    setDspActive(false);
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

  describe("updateDspWidget", () => {
    it("is a no-op when hasUI is false", () => {
      const ctx = { hasUI: false } as any;
      expect(() => updateDspWidget(ctx)).not.toThrow();
    });

    it("sets the widget when dsp is active", () => {
      const setWidget = vi.fn();
      const ctx = { hasUI: true, ui: { setWidget } } as any;
      setDspActive(true);
      updateDspWidget(ctx);
      expect(setWidget).toHaveBeenCalledWith("dsp-warning", expect.any(Function), { placement: "belowEditor" });
    });

    it("clears the widget when dsp is inactive", () => {
      const setWidget = vi.fn();
      const ctx = { hasUI: true, ui: { setWidget } } as any;
      setDspActive(false);
      updateDspWidget(ctx);
      expect(setWidget).toHaveBeenCalledWith("dsp-warning", undefined);
    });

    it("widget render returns array with warning text when active", () => {
      const setWidget = vi.fn();
      const ctx = { hasUI: true, ui: { setWidget } } as any;
      setDspActive(true);
      updateDspWidget(ctx);

      // Extract the widget builder function and call it
      const builder = setWidget.mock.calls[0][1];
      const theme = { fg: (c: string, t: string) => `[${c}]${t}`, bold: (t: string) => t };
      const widget = builder(null, theme);

      expect(typeof widget.render).toBe("function");
      const rendered = widget.render(80);
      expect(Array.isArray(rendered)).toBe(true);
      expect(rendered[0]).toContain("DSP");
    });

    it("toggle off then on re-creates correct widget", () => {
      const setWidget = vi.fn();
      const ctx = { hasUI: true, ui: { setWidget } } as any;

      // Toggle ON
      setDspActive(true);
      updateDspWidget(ctx);
      expect(setWidget).toHaveBeenLastCalledWith("dsp-warning", expect.any(Function), { placement: "belowEditor" });

      // Toggle OFF
      setDspActive(false);
      updateDspWidget(ctx);
      expect(setWidget).toHaveBeenLastCalledWith("dsp-warning", undefined);

      // Toggle ON again
      setDspActive(true);
      updateDspWidget(ctx);
      expect(setWidget).toHaveBeenLastCalledWith("dsp-warning", expect.any(Function), { placement: "belowEditor" });
    });
  });
});
