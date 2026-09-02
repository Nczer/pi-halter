import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import { notifyStatus } from "./status-bus";

/**
 * /dspat — judge advisory mode (session-scoped).
 *
 * When ON, the judge runs automatically on every permission prompt (bash,
 * file, tool) and the prompt shows the full verdict (explanation +
 * approve/reject suggestion). D17: BOTH stages run (never skipped, even on
 * stage-1 approve+low — the cross-check of stage-1 lows is exactly the
 * data /dspa's auto-allow path cannot produce) and the FINAL verdict is
 * stage 2's, or stage 1's when stage 2 produced none; stage disagreement
 * is mirrored to the always-on judge ledger (.log/judge.jsonl). The human
 * always takes the call — this mode never changes the gate's decision.
 *
 * The widget is the unified halter widget's mode line: an indicator plus
 * the agreement counter merged onto ONE line (`… — 12/14 agreed — last:
 * <target>`) once the first verdict is in. The
 * stats are session-scoped and model-scoped (never persisted — judge
 * quality is model-dependent and a model change resets the counters);
 * the decision log keeps the durable history.
 */

let dspatActive = false;
/** The judge stage in flight (1 | 2), or null — rendered inline on the
 *  widget line ("… — judging stage N…") instead of a separate in-flight
 *  widget. D17: dspat runs BOTH stages; the stage number is the progress
 *  the user sees while the second call is in flight. */
let judging: 1 | 2 | null = null;

interface DspatStats {
  /** The model that produced the counted verdicts (null = none yet). */
  model: string | null;
  /** Prompts the judge produced a verdict for, since the current model started. */
  total: number;
  /** Verdicts whose approve/reject suggestion matched the human's decision. */
  agreed: number;
  /** Target of the most recent disagreement (truncated), if any. */
  lastDisagreement: string | null;
}

const stats: DspatStats = { model: null, total: 0, agreed: 0, lastDisagreement: null };

function resetStats(): void {
  stats.model = null;
  stats.total = 0;
  stats.agreed = 0;
  stats.lastDisagreement = null;
  judging = null;
}

/**
 * Set the inline judging state (verdict.ts calls it with the stage at the
 * start of a judge stage while /dspat is active, and null at its end).
 * Re-sets the widget so the change paints immediately (setWidget forces a
 * TUI repaint).
 */
export function setDspatJudging(stage: 1 | 2 | null, ctx: ExtensionContext): void {
  if (judging === stage) return;
  judging = stage;
  updateDspatWidget(ctx);
}

export function isDspatActive(): boolean {
  return dspatActive;
}

/** The judge stage in flight (the unified widget renders the
 *  "… — judging stage N…" tag inline on the DSPAT line); null = idle. */
export function getDspatJudgingStage(): 1 | 2 | null {
  return judging;
}

export function setDspatActive(value: boolean): void {
  dspatActive = value;
}

/** Full session reset (mode + stats) — called on session_shutdown. */
export function resetDspat(): void {
  dspatActive = false;
  resetStats();
}

/**
 * Record one judged prompt and its human outcome. A verdict from a model
 * other than the one currently counted resets the counters first (old-model
 * stats must not mix into the agreement number).
 */
export function recordDspatOutcome(
  model: string,
  suggestedApprove: boolean,
  humanApproved: boolean,
  target: string,
): void {
  if (stats.model !== null && stats.model !== model) resetStats();
  stats.model = model;
  stats.total++;
  if (suggestedApprove === humanApproved) {
    stats.agreed++;
  } else {
    // Flatten newlines — widget lines must never contain \n (see dspa-mode).
    stats.lastDisagreement = target.replace(/[\r\n]+/g, " ").slice(0, 80);
  }
}

export function getDspatStats(): DspatStats {
  return { ...stats };
}

// ── Widget ──

/**
 * Re-render the unified halter widget (widget.ts): the DSPAT line is pinned
 * on top of it, ONE line (indicator + agreement counter + last disagreement
 * merged — details drop from the tail before the line truncates). Stays up
 * while the judge is off (the user's own choice), hidden only while the
 * judge is invalid (see the unified widget's render).
 */
export function updateDspatWidget(ctx: ExtensionContext): void {
  if (!ctx.hasUI) return;
  notifyStatus(ctx);
}
