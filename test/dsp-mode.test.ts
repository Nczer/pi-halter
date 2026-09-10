import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { isDspActive, setDspActive } from "../modes/dsp-mode";
import { notifyStatus, onStatusChange } from "../modes/status-bus";
import { updateStatus } from "../ui/widget";

const theme = { fg: (_c: string, t?: string) => t ?? "", bold: (t?: string) => t ?? "" };

describe("dsp-mode", () => {
  beforeEach(() => {
    setDspActive(false);
    // Production wiring (index.ts): the unified status is the status-bus
    // listener. The delegation tests below exercise mode → bus → status →
    // setStatus through that real edge.
    onStatusChange(updateStatus);
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

  describe("mode → status bus → unified status (widget.ts)", () => {
    it("sets the warning status when dsp is active", () => {
      const setStatus = vi.fn();
      const ctx = { hasUI: true, ui: { setStatus, setWidget: vi.fn(), theme } } as any;
      setDspActive(true);
      notifyStatus(ctx);
      // The DSP bypass hides the session rules — the warning stands alone.
      expect(setStatus).toHaveBeenCalledWith("halter", "⚠ DSP");
    });

    it("clears the status when dsp is inactive and no rules exist", () => {
      const setStatus = vi.fn();
      const ctx = { hasUI: true, ui: { setStatus, setWidget: vi.fn(), theme } } as any;
      setDspActive(false);
      notifyStatus(ctx);
      expect(setStatus).toHaveBeenLastCalledWith("halter", undefined);
    });

    it("toggle off then on re-sets the status", () => {
      const setStatus = vi.fn();
      const ctx = { hasUI: true, ui: { setStatus, setWidget: vi.fn(), theme } } as any;

      // Toggle ON
      setDspActive(true);
      notifyStatus(ctx);
      expect(setStatus).toHaveBeenLastCalledWith("halter", "⚠ DSP");

      // Toggle OFF (no rules) → cleared
      setDspActive(false);
      notifyStatus(ctx);
      expect(setStatus).toHaveBeenLastCalledWith("halter", undefined);

      // Toggle ON again
      setDspActive(true);
      notifyStatus(ctx);
      expect(setStatus).toHaveBeenLastCalledWith("halter", "⚠ DSP");
    });
  });
});
