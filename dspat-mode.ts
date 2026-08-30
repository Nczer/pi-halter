import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import { truncateToWidth } from "@earendil-works/pi-tui";
import { judgeStatus } from "./judge-prompt";

/**
 * /dspat — judge advisory mode (session-scoped).
 *
 * When ON, the judge runs automatically on every permission prompt (bash,
 * file) and the prompt shows the full verdict (explanation +
 * approve/reject suggestion). The human always takes the call — this mode
 * never changes the gate's decision.
 *
 * The widget is a mode indicator plus an agreement counter line
 * (`◎ 12/14 agreed — last: <target>`) once the first verdict is in. The
 * stats are session-scoped and model-scoped (never persisted — judge
 * quality is model-dependent and a model change resets the counters);
 * the decision log keeps the durable history.
 */

let dspatActive = false;
/** True while a judge call is in flight — rendered inline on this widget's
 *  line ("… — judging…") instead of a separate in-flight widget. */
let judging = false;

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
  judging = false;
}

/**
 * Flip the inline judging state (judge-prompt.ts calls it at the start and
 * end of every judge stage while /dspat is active). Re-sets the widget so
 * the change paints immediately (setWidget forces a TUI repaint).
 */
export function setDspatJudging(on: boolean, ctx: ExtensionContext): void {
  if (judging === on) return;
  judging = on;
  updateDspatWidget(ctx);
}

export function isDspatActive(): boolean {
  return dspatActive;
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

/** Show or clear the dspat status widget below the editor. */
export function updateDspatWidget(ctx: ExtensionContext): void {
  if (!ctx.hasUI) return;

  if (dspatActive) {
    // `◎` is a text-default glyph (monochrome in every terminal) — the mode
    // follows the DSP widget's style: no color emoji, all-caps name.
    const main = `◎ DSPAT${judging ? " — judging…" : ""}: judge advises on every permission prompt`;
    ctx.ui.setWidget("dspat", (_tui, theme) => {
      const render = (width: number) => {
        // Live judge state: the widget stays up when the judge is off
        // (the user's own choice, visible in settings-ext.json), but DISAPPEARS
        // when the judge is invalid (e.g. session model switched to
        // something unresolvable); the prompt body carries the "⚠️ Judge
        // invalid" line there. ctx.model is a live getter, so a switch is
        // picked up on the next repaint.
        const js = judgeStatus(ctx);
        if (js.state === "invalid") return [];
        // width is the live terminal width (terminal.columns) — the same
        // value the TUI's render check enforces. Never hardcode a width:
        // an untruncated line crashes pi with an uncaughtException.
        const lines = [truncateToWidth(theme.fg("accent", theme.bold(main)), width)];
        // Agreement counter (same muted second line as the /dspa widget).
        // updateDspatWidget is re-run after every recorded outcome, so the
        // numbers are live.
        if (stats.total > 0) {
          const stat = `◎ ${stats.agreed}/${stats.total} agreed` +
            (stats.lastDisagreement ? ` — last: ${stats.lastDisagreement}` : "");
          lines.push(truncateToWidth(theme.fg("muted", stat), width));
        }
        return lines;
      };
      return { render, invalidate: () => {} };
    }, { placement: "belowEditor" });
  } else {
    ctx.ui.setWidget("dspat", undefined);
  }
}
