/**
 * dspa-mode.ts — judge auto-allow mode state, model-scoped session counters,
 * widget.
 *
 * /dspa is the automatic counterpart of /dspat: operations that pass the
 * deterministic hard gate (dspa-gate.ts) AND get an approving low-risk judge
 * verdict run without a prompt (visible toast + decision-log line). Anything
 * else falls through to the normal prompt with its full Always options.
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
  lastTarget = target.slice(0, 80);
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
      const render = () => {
        // Hidden only while the judge is invalid (see the dspat widget).
        const js = judgeStatus(ctx);
        if (js.state === "invalid") return [];
        const lines = [truncateToWidth(theme.fg("accent", theme.bold(main)), 160)];
        if (last) {
          lines.push(truncateToWidth(theme.fg("muted", `last: ${last}`), 160));
        }
        return lines;
      };
      return { render, invalidate: () => {} };
    },
    { placement: "belowEditor" },
  );
}
