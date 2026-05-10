import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import { truncateToWidth } from "@earendil-works/pi-tui";

// ── DSP (Dangerously Skip Permissions) state ──

let dspActive = false;

export function isDspActive(): boolean {
  return dspActive;
}

export function setDspActive(value: boolean): void {
  dspActive = value;
}

// ── DSP warning widget ──

/** Show or clear the DSP warning widget below the editor. */
export function updateDspWidget(ctx: ExtensionContext): void {
  if (!ctx.hasUI) return;

  if (dspActive) {
    ctx.ui.setWidget("dsp-warning", (_tui, theme) => {
      const line = theme.fg("error", theme.bold("⚠ DSP MODE — all permissions bypassed ⚠"));
      return {
        render: (width: number) => [truncateToWidth(line, width)],
        invalidate: () => {},
      };
    }, { placement: "belowEditor" });
  } else {
    ctx.ui.setWidget("dsp-warning", undefined);
  }
}
