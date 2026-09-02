import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import { notifyStatus } from "./status-bus";

// ── DSP (Dangerously Skip Permissions) state ──

let dspActive = false;

export function isDspActive(): boolean {
  return dspActive;
}

export function setDspActive(value: boolean): void {
  dspActive = value;
}

// ── DSP warning ──

/**
 * Re-render the unified halter widget (widget.ts): the DSP warning line is
 * pinned on top of it while DSP is active (alone — the session rules are
 * noise while everything is bypassed).
 */
export function updateDspWidget(ctx: ExtensionContext): void {
  if (!ctx.hasUI) return;
  notifyStatus(ctx);
}
