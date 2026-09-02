import type { ExtensionContext, Theme } from "@earendil-works/pi-coding-agent";
import { truncateToWidth, visibleWidth } from "@earendil-works/pi-tui";
import { store } from "../gate/store";
import { isDspActive } from "../modes/dsp-mode";
import { isDspaActive, isDspaJudging, getDspaStats } from "../modes/dspa-mode";
import { isDspatActive, isDspatJudging, getDspatStats } from "../modes/dspat-mode";
import {judgeStatus} from "../judge/verdict";

// ── Path deduplication ──

/** Remove paths that are sub-paths of another entry in the same list. */
export function filterSubPaths(paths: string[]): string[] {
  const sorted = [...paths].sort();
  const result: string[] = [];
  for (const p of sorted) {
    // Normalize: strip trailing slash for comparison
    const pNorm = p.endsWith("/") ? p.slice(0, -1) : p;
    let isSub = false;
    for (const parent of result) {
      const parentNorm = parent.endsWith("/") ? parent.slice(0, -1) : parent;
      if (pNorm === parentNorm || pNorm.startsWith(parentNorm + "/")) { isSub = true; break; }
    }
    if (!isSub) result.push(p);
  }
  return result;
}

// ── Command grouping ──

/** Group command signature variants for compact display (e.g. "git(-am, -m)" or "ls(-a)"). */
export function groupCommandVariants(items: string[]): string[] {
  const groups = new Map<string, Set<string>>();
  for (const sig of items) {
    const [cmd, ...flags] = sig.split(/\s+/);
    const group = groups.get(cmd) ?? new Set();
    group.add(flags.join(" "));
    groups.set(cmd, group);
  }
  const result: string[] = [];
  for (const [cmd, flags] of groups) {
    const nonEmpty = [...flags].filter(f => f).sort();
    const hasNoFlags = flags.has("");
    if (nonEmpty.length === 0) {
      result.push(cmd);
    } else if (hasNoFlags) {
      // bare cmd subsumes all variants
      result.push(`${cmd}(*)`);
    } else if (nonEmpty.length === 1) {
      result.push(`${cmd}(${nonEmpty[0]})`);
    } else {
      result.push(`${cmd}(${nonEmpty.join(", ")})`);
    }
  }
  return result;
}

// ── Widget rendering ──

/**
 * One mode line = main (accent, bold) + details (muted), merged into ONE
 * screen row to keep the bottom bar compact. When the merged line exceeds
 * width, details are dropped from the tail first (the last-target, then the
 * counter) before the main itself is truncated — the detail is the
 * dispensable part.
 */
function modeLine(width: number, theme: Pick<Theme, "fg" | "bold">, main: string, details: string[]): string {
  const parts = [main, ...details];
  while (parts.length > 1 && visibleWidth(parts.join(" — ")) > width) parts.pop();
  if (parts.length === 1) {
    return truncateToWidth(theme.fg("accent", theme.bold(main)), width);
  }
  const styled =
    theme.fg("accent", theme.bold(main)) +
    theme.fg("muted", " — " + parts.slice(1).join(" — "));
  return truncateToWidth(styled, width);
}

/**
 * The single halter status widget (below the editor):
 *
 *   ⚠ DSP MODE — all permissions bypassed ⚠        (DSP active — alone)
 *   » DSPA (model): 79a 3g 2r 1c 2d — last: <target> (DSPA active)
 *     (compact session-health counts, non-zero only: a auto-allowed,
 *      g floor stop, r judge reject, c declined (approve, risk too high),
 *      d defer/no verdict)
 *   ◎ DSPAT: judge advises… — M/N agreed — last: …  (DSPAT active)
 *   Bash: …  R: …  R/W: …  Pkg: …  Cwd: …  Tools: … (session rules)
 *
 * ONE widget, because pi renders same-placement widgets in set order and a
 * re-set moves the widget to the end — with separate "dspa"/"dspat" widgets
 * the mode lines floated below the rule lines after every rules update.
 * Merged here, the mode lines are pinned on top and each is one line.
 */
export function updateWidget(ctx: ExtensionContext): void {
  const bashItems = [...store.listAllowedBash()];
  const readPathItems = filterSubPaths([...store.listAllowedReadPaths()]);
  const writePathItems = filterSubPaths([...store.listAllowedWritePaths()]);
  const readDirItems = filterSubPaths([...store.listAllowedReadDirs()]);
  const writeDirItems = filterSubPaths([...store.listAllowedWriteDirs()]);
  const pkgItems = [...store.listTrustedPackages()];
  const toolGrantItems = [...store.listToolGrants()];
  const cwdItems = store
    .listAllowedBashCwds()
    .map(({ sig, cwd }) => `${sig} @ ${cwd}`);

  // Merge dirs + paths; since write implies read, R/W paths don't also appear in R
  const allReadPaths = filterSubPaths([...readDirItems, ...readPathItems]);
  const allWritePaths = filterSubPaths([...writeDirItems, ...writePathItems]);
  const readOnlyPaths = allReadPaths.filter(p => !allWritePaths.some(wp => p === wp || p.startsWith(wp + "/")));

  const hasSessionRules =
    bashItems.length > 0 ||
    readOnlyPaths.length > 0 ||
    allWritePaths.length > 0 ||
    cwdItems.length > 0 ||
    pkgItems.length > 0 ||
    toolGrantItems.length > 0;

  // Legacy per-mode widget ids (pre-merge): clear them so a same-process
  // /reload cannot leave stale duplicates above or below this one.
  ctx.ui.setWidget("dsp-warning", undefined);
  ctx.ui.setWidget("dspa", undefined);
  ctx.ui.setWidget("dspat", undefined);

  if (!hasSessionRules && !isDspActive() && !isDspaActive() && !isDspatActive()) {
    ctx.ui.setWidget("halter", undefined);
    return;
  }

  ctx.ui.setWidget("halter", (_tui, theme) => {
    const render = (width: number) => {
      const lines: string[] = [];

      if (isDspActive()) {
        // DSP bypasses the whole gate — the session rules are noise, so the
        // widget shows the warning line alone (pre-merge: "halter" was
        // cleared and a separate "dsp-warning" widget showed the same line).
        lines.push(
          truncateToWidth(theme.fg("error", theme.bold("⚠ DSP MODE — all permissions bypassed ⚠")), width),
        );
        return lines;
      }

      // Judge-mode lines: hidden only while the judge is invalid (the prompt
      // body carries the "⚠️ Judge invalid" line there). judgeStatus is a
      // live read (settings + session model), so a model switch is picked up
      // on the next repaint.
      const judgeOk = judgeStatus(ctx).state !== "invalid";

      if (isDspaActive() && judgeOk) {
        const s = getDspaStats();
        // `»` is a text-default glyph (monochrome in every terminal) — the
        // mode follows the DSP widget's style: no color emoji, all-caps name.
        const modelTag = s.model ? ` (${s.model})` : "";
        // Session health as compact counts (only non-zero), in stop-source
        // order: a = auto-allowed, g = floor stop, r = judge REJECT,
        // c = approve-but-above-authority (declined), d = DEFER/no verdict.
        const counts: string[] = [];
        if (s.autoAllowed > 0) counts.push(`${s.autoAllowed}a`);
        if (s.gate > 0) counts.push(`${s.gate}g`);
        if (s.deny > 0) counts.push(`${s.deny}r`);
        if (s.declined > 0) counts.push(`${s.declined}c`);
        if (s.defer > 0) counts.push(`${s.defer}d`);
        const main =
          (counts.length > 0
            ? `» DSPA${modelTag}: ${counts.join(" ")}`
            : `» DSPA${modelTag}: auto-allowing gate+judge-approved operations`) +
          (isDspaJudging() ? " — judging…" : "");
        lines.push(modeLine(width, theme, main, s.lastTarget ? [`last: ${s.lastTarget}`] : []));
      }

      if (isDspatActive() && judgeOk) {
        const s = getDspatStats();
        const main = `◎ DSPAT${isDspatJudging() ? " — judging…" : ""}: judge advises on every permission prompt`;
        // Agreement counter + last disagreement, merged onto the mode line.
        // updateWidget is re-run after every recorded outcome, so live.
        const details =
          s.total > 0
            ? [`${s.agreed}/${s.total} agreed`, ...(s.lastDisagreement ? [`last: ${s.lastDisagreement}`] : [])]
            : [];
        lines.push(modeLine(width, theme, main, details));
      }

      if (hasSessionRules) {
        if (bashItems.length > 0) {
          const grouped = groupCommandVariants(bashItems);
          lines.push(theme.fg("muted", "Bash:") + " " + theme.fg("dim", grouped.join(" ")));
        }
        if (readOnlyPaths.length > 0) {
          lines.push(theme.fg("muted", "R:") + " " + theme.fg("dim", readOnlyPaths.join(" ")));
        }
        if (allWritePaths.length > 0) {
          lines.push(theme.fg("muted", "R/W:") + " " + theme.fg("dim", allWritePaths.join(" ")));
        }
        if (pkgItems.length > 0) {
          // D10: trusted packages (fetchable run forms — npx/uvx/dlx …)
          lines.push(theme.fg("muted", "Pkg:") + " " + theme.fg("dim", pkgItems.join(" ")));
        }
        if (cwdItems.length > 0) {
          // Cwd-bound bash grants (relative-path tools): shown with the cwd
          // they bind to, since the same sig is a different grant elsewhere.
          lines.push(theme.fg("muted", "Cwd:") + " " + theme.fg("dim", cwdItems.join(" ")));
        }
        if (toolGrantItems.length > 0) {
          // Tool-plugin grants: `blender` (whole tool) or `blender:kind:read`.
          lines.push(theme.fg("muted", "Tools:") + " " + theme.fg("dim", toolGrantItems.join(" ")));
        }
      }

      return lines.map(l => truncateToWidth(l, width));
    };
    return { render, invalidate: () => {} };
  }, { placement: "belowEditor" });
}
