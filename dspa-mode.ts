/**
 * dspa-mode.ts — judge auto-allow mode state, model-scoped session counters,
 * widget.
 *
 * /dspa is the automatic counterpart of /dspat: operations that pass the
 * deterministic hard gate (dspa-gate.ts) AND get an approving judge verdict
 * within the stage's risk authority (stage 1: low; stage 2: low or medium)
 * run without a prompt (visible toast + decision-log line). Anything else
 * falls through to the normal prompt with its full Always options.
 *
 * Like /dspat, counters are session-scoped and model-scoped: judge quality
 * is model-dependent, so a model change resets the stats.
 */
import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import { updateWidget } from "./widget";

let active = false;
let model: string | null = null;
let autoAllowed = 0;
let lastTarget: string | null = null;
/** True while a judge call is in flight — rendered inline on this widget's
 *  line ("… — judging…") instead of a separate in-flight widget. */
let judging = false;

export function setDspaActive(on: boolean): void {
  active = on;
  if (!on) resetCounters();
}

export function isDspaActive(): boolean {
  return active;
}

export function resetDspa(): void {
  active = false;
  resetCounters();
}

function resetCounters(): void {
  model = null;
  autoAllowed = 0;
  lastTarget = null;
  judging = false;
}

/** True while a judge call is in flight (the unified widget renders the
 *  "… — judging…" tag inline on the DSPA line). */
export function isDspaJudging(): boolean {
  return judging;
}

/**
 * Flip the inline judging state (judge-prompt.ts calls it at the start and
 * end of every judge stage while /dspa is active). Re-renders the widget so
 * the change paints immediately (setWidget forces a TUI repaint).
 */
export function setDspaJudging(on: boolean, ctx: ExtensionContext): void {
  if (judging === on) return;
  judging = on;
  updateDspaWidget(ctx);
}

/** Record one auto-allowed operation. A model change resets the counters. */
export function recordDspaAutoAllowed(m: string, target: string): void {
  if (model !== m) {
    model = m;
    autoAllowed = 0;
    lastTarget = null;
  }
  autoAllowed++;
  // Flatten newlines: the widget line array is one element per screen row;
  // an embedded \n makes the terminal wrap mid-row and desyncs the TUI diff.
  lastTarget = target.replace(/[\r\n]+/g, " ").slice(0, 80);
}

export function getDspaStats(): {
  model: string | null;
  autoAllowed: number;
  lastTarget: string | null;
} {
  return { model, autoAllowed, lastTarget };
}

/**
 * Re-render the unified halter widget (widget.ts): the DSPA line is pinned
 * on top of it, ONE line (counter + `last: <target>` merged — the detail is
 * dropped from the tail before the line itself truncates). Hidden only while
 * the judge is invalid (see the unified widget's render).
 */
export function updateDspaWidget(ctx: ExtensionContext): void {
  if (!ctx.hasUI) return;
  updateWidget(ctx);
}
