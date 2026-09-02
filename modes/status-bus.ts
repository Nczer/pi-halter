/**
 * status-bus — the single edge from the mode modules to the UI.
 *
 * Mode state (dsp/dspa/dspat) lives in the mode modules; the unified
 * widget (ui/widget.ts) is the one UI surface that renders it. Before this
 * bus, every mode module imported updateWidget from ui/widget while
 * widget.ts imported the mode state back — a module cycle. Now the mode
 * modules emit notifyStatus(ctx) on every state change; index.ts
 * registers the widget as the listener (onStatusChange). A test (or an
 * embed without a widget) that registers no listener gets a no-op.
 */
import type { ExtensionContext } from "@earendil-works/pi-coding-agent";

type StatusListener = (ctx: ExtensionContext) => void;

let listener: StatusListener | null = null;

/** Register the UI listener (index.ts — the single consumer). */
export function onStatusChange(fn: StatusListener): void {
  listener = fn;
}

/** Mode modules call this on every state change that affects the widget. */
export function notifyStatus(ctx: ExtensionContext): void {
  if (listener) listener(ctx);
}
