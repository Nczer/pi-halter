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
import { notifyStatus } from "./status-bus";
import { readSettingsFile, writeSettings } from "../halter-settings";

let active = false;
let model: string | null = null;
let autoAllowed = 0;
let lastTarget: string | null = null;
// Stop counters — what kept the floor or the judge from auto-allowing.
// Model-scoped like autoAllowed (judge quality is model-dependent, so a
// model change resets everything); the widget renders them compactly
// (`2r 1d` …) next to the auto-allow count.
let gateStops = 0;
let denials = 0;
let declines = 0;
let defers = 0;
/** The in-flight judge stage (1: stateless check, 2: session-context
 *  intent pass), null when idle — painted inline on the status line
 *  ("— judging stage 2…"); the transition refreshes the unified status. */
let judging: 1 | 2 | null = null;

export function setDspaActive(on: boolean): void {
  active = on;
  if (!on) resetCounters();
}

/**
 * Persistent startup mode (settings-ext.json, `halter.mode`): the mode a
 * NEW session starts in. /dspa is the only session-persistent mode — /dsp
 * (the full bypass) and /dspat (advisory) are session-scoped by design,
 * and a persisted /dsp must never be the silent default of a new session.
 * The /dspa command is the only writer (index.ts); session_start applies it.
 */
export type PersistedMode = "manual" | "dspa";

/**
 * Read the persisted startup mode. Fail-closed on any settings error:
 * a broken settings file must never start a session in dspa.
 */
export function readPersistedMode(filePath?: string): PersistedMode {
  try {
    return readSettingsFile(filePath).mode === "dspa" ? "dspa" : "manual";
  } catch {
    return "manual";
  }
}

/** Persist the /dspa toggle ("dspa" when on, "manual" when off). */
export function persistDspaMode(on: boolean, filePath?: string): void {
  writeSettings({ mode: on ? "dspa" : "manual" }, filePath);
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
  gateStops = 0;
  denials = 0;
  declines = 0;
  defers = 0;
  judging = null;
}

/** Judge quality is model-dependent — a model switch starts stats fresh. */
function switchModel(m: string): void {
  resetCounters();
  model = m;
}

/**
 * Why a dspa operation did NOT auto-allow (recorded at the single
 * fall-through point, gate.ts tryDspaAutoAllow):
 *  - `gate`     — the deterministic floor stopped it (danger-class or
 *                 advisory: the stop stands, any verdict is advisory);
 *  - `deny`     — the final judge verdict was REJECT;
 *  - `declined` — the final verdict was approve, but the risk sat above
 *                 the stage's authority (approve+high, or stage-1-only
 *                 approve+medium) — the judge said yes, the bar said no;
 *  - `defer`    — the final verdict was DEFER, or NO verdict at all
 *                 (timeout / failed call / invalid judge — the fail-safe
 *                 class; a defer means "I can't vouch", so both share the
 *                 bucket for session health).
 */
export type DspaStopKind = "gate" | "deny" | "declined" | "defer";

/**
 * Record one non-auto-allowed dspa operation. `verdictModel` is the
 * verdict's model; null when no verdict exists (a null model never resets
 * the counters — the floor can stop before any judge call).
 */
export function recordDspaStop(kind: DspaStopKind, verdictModel: string | null): void {
  if (verdictModel !== null && verdictModel !== model) switchModel(verdictModel);
  switch (kind) {
    case "gate": gateStops++; break;
    case "deny": denials++; break;
    case "declined": declines++; break;
    case "defer": defers++; break;
  }
}

/** The in-flight judge stage (1: stateless check, 2: session-context
 *  intent pass), null when idle — no longer painted since the
 *  status-line migration (the status carries stats, not in-flight stage). */
export function getDspaJudgingStage(): 1 | 2 | null {
  return judging;
}

/**
 * Set the in-flight judging stage (verdict.ts calls it at the start and end
 * of every judge stage while /dspa is active; null clears it). Refreshes
 * the unified status on every transition, which paints the stage inline
 * on the mode line ("— judging stage 2…").
 */
export function setDspaJudging(stage: 1 | 2 | null, ctx: ExtensionContext): void {
  if (judging === stage) return;
  judging = stage;
  updateDspaWidget(ctx);
}

/** Record one auto-allowed operation. A model change resets the counters. */
export function recordDspaAutoAllowed(m: string, target: string): void {
  if (model !== m) switchModel(m);
  autoAllowed++;
  // Flatten newlines: the widget line array is one element per screen row;
  // an embedded \n makes the terminal wrap mid-row and desyncs the TUI diff.
  lastTarget = target.replace(/[\r\n]+/g, " ").slice(0, 80);
}

export function getDspaStats(): {
  model: string | null;
  autoAllowed: number;
  lastTarget: string | null;
  /** Floor stops (gate) — the deterministic layer, not the judge. */
  gate: number;
  /** Final judge verdict REJECT. */
  deny: number;
  /** Final verdict approve, risk above the stage's authority. */
  declined: number;
  /** Final verdict DEFER, or no verdict at all (fail-safe). */
  defer: number;
} {
  return { model, autoAllowed, lastTarget, gate: gateStops, deny: denials, declined: declines, defer: defers };
}

/**
 * Refresh the unified status (widget.ts): the DSPA main carries the counter
 * run ("» DSPA: 3a 2g") ahead of the rule segments; hidden only while the
 * judge is invalid (see updateStatus).
 */
export function updateDspaWidget(ctx: ExtensionContext): void {
  if (!ctx.hasUI) return;
  notifyStatus(ctx);
}
