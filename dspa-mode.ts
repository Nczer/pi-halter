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
import { truncateToWidth } from "@earendil-works/pi-tui";
import { judgeStatus } from "./judge-prompt";

let active = false;
let model: string | null = null;
let autoAllowed = 0;
let lastTarget: string | null = null;

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

/** Update (or clear) the status-bar widget. */
export function updateDspaWidget(ctx: ExtensionContext): void {
  if (!ctx.hasUI) return;
  if (!active) {
    ctx.ui.setWidget("dspa", undefined);
    return;
  }
  const modelTag = model ? ` (${model})` : "";
  const main =
    autoAllowed > 0
      ? `⚡ dspa${modelTag}: auto-allowed ${autoAllowed} this session`
      : `⚡ dspa${modelTag}: auto-allowing gate+judge-approved operations`;
  const last = lastTarget;
  ctx.ui.setWidget(
    "dspa",
    (_tui, theme) => {
      const render = (width: number) => {
        // Hidden only while the judge is invalid (see the dspat widget).
        const js = judgeStatus(ctx);
        if (js.state === "invalid") return [];
        // width is the live terminal width (terminal.columns) — the same
        // value the TUI's render check enforces.
        const lines = [truncateToWidth(theme.fg("accent", theme.bold(main)), width)];
        if (last) {
          lines.push(truncateToWidth(theme.fg("muted", `last: ${last}`), width));
        }
        return lines;
      };
      return { render, invalidate: () => {} };
    },
    { placement: "belowEditor" },
  );
}
