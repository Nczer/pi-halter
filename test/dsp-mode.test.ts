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
  });
});
