import type { ExtensionContext, Theme } from "@earendil-works/pi-coding-agent";
import { truncateToWidth, visibleWidth } from "@earendil-works/pi-tui";
import { homedir } from "node:os";
import { store } from "../gate/store";
import { isDspActive } from "../modes/dsp-mode";
import { isDspaActive, getDspaJudgingStage, getDspaStats } from "../modes/dspa-mode";
import { isDspatActive, getDspatJudgingStage, getDspatStats } from "../modes/dspat-mode";
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

// ── Path display helpers ──

/** Display-only shortening: absolute paths under $HOME render with a `~`
 *  prefix (cwd-relative paths pass through). Grants stay real — this only
 *  shapes the display. */
export function shortenHomePath(p: string): string {
  const home = homedir() + "/";
  if (p.startsWith(home)) return "~" + p.slice(homedir().length);
  return p;
}

/** Longest common prefix of two paths cut at a directory boundary (trailing
 *  slash); "" when the paths share no directory (incl. top-level siblings). */
function commonDirPrefix(a: string, b: string): string {
  let k = 0;
  const min = Math.min(a.length, b.length);
  while (k < min && a[k] === b[k]) k++;
  const slash = a.lastIndexOf("/", k - 1);
  return slash > 0 ? a.slice(0, slash + 1) : "";
}

/** Common directory prefix (trailing slash) over a whole group; "" when the
 *  shared part carries no directory boundary (top-level siblings). */
function groupCommonDir(group: string[]): string {
  const first = group[0];
  let k = first.length;
  for (const p of group.slice(1)) {
    while (k > 0 && (k >= p.length || p[k - 1] !== first[k - 1])) k--;
  }
  const slash = first.lastIndexOf("/", k - 1);
  return slash > 0 ? first.slice(0, slash + 1) : "";
}

/** Display-only combining of paths that share a directory prefix —
 *  a/b/x a/b/y → "a/b/x & y" (reconstructable: shared prefix + names).
 *  Applied after ~-shortening, and only when it actually saves width. */
export function combineCommonPaths(paths: string[]): string {
  const sorted = [...paths].sort();
  const parts: string[] = [];
  let i = 0;
  while (i < sorted.length) {
    let j = i + 1;
    while (j < sorted.length && commonDirPrefix(sorted[i], sorted[j]) !== "") j++;
    if (j - i >= 2) {
      const group = sorted.slice(i, j);
      const prefix = groupCommonDir(group);
      if (prefix !== "") {
        const combined = `${prefix.slice(0, -1)}/${group.map((p) => p.slice(prefix.length)).join(" & ")}`;
        if (combined.length < group.join(" ").length) {
          parts.push(combined);
          i = j;
          continue;
        }
      }
    }
    parts.push(sorted[i]);
    i++;
  }
  return parts.join(" ");
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
 * One session-rules line: `· R/W: … · R: … · Bash: … · Pkg: … · Cwd: … ·
 * Tools: …` — every grant category on ONE row (same style as the other
 * bottom-bar lines), in safety-priority order (the write boundary first).
 * Each category caps its items (paths 3, commands 5, cwd 2, tools 3) with a
 * `…+N` tail; when the line outgrows the width, whole low-priority segments
 * drop behind one `…+N` marker (N = hidden categories). The widget is thus
 * bounded: one rules line no matter how many grants exist.
 */
export function renderRulesLine(
  width: number,
  theme: Pick<Theme, "fg">,
  segments: { label: string; text: string }[],
): string | null {
  if (segments.length === 0) return null;
  const n = segments.length;
  const styled = segments.map(
    (seg) => theme.fg("muted", `${seg.label}: `) + theme.fg("dim", seg.text),
  );
  // Drop whole lowest-priority segments until the FULL line (leading `· `,
  // separators and the `…+N` marker included) fits the width.
  for (let keep = n; keep >= 1; keep--) {
    const hidden = n - keep;
    const line =
      theme.fg("muted", "· ") +
      styled.slice(0, keep).join(" · ") +
      (hidden > 0 ? theme.fg("dim", ` · …+${hidden}`) : "");
    if (visibleWidth(line) <= width) return line;
  }
  // Even one segment overflows — return it anyway; the caller's final
  // truncateToWidth applies.
  return theme.fg("muted", "· ") + styled[0] + theme.fg("dim", ` · …+${n - 1}`);
}

/** Plain item list capped at `cap` with a `…+N` tail. */
function capList(items: string[], cap: number): string {
  const shown = items.slice(0, cap);
  const tail = items.length > cap ? ` …+${items.length - cap}` : "";
  return shown.join(" ") + tail;
}

/** Path list for the rules line: sorted (stable display order), capped, then
 *  sibling-combined for width; overflow rides a `…+N` tail. */
function displayPaths(paths: string[], cap: number): string {
  const sorted = [...paths].sort();
  const shown = sorted.slice(0, cap);
  const tail = sorted.length > cap ? ` …+${sorted.length - cap}` : "";
  return combineCommonPaths(shown) + tail;
}

/**
 * The single halter status widget (below the editor):
 *
 *   ⚠ DSP MODE — all permissions bypassed ⚠        (DSP active — alone)
 *   » DSPA: 79a 3g 2r 1c 2d — last: <target>        (DSPA active)
 *     (compact session-health counts, non-zero only: a auto-allowed,
 *      g floor stop, r judge reject, c declined (approve, risk too high),
 *      d defer/no verdict. A model tag `(Name)` appears only when the judge
 *      model differs from the session model — the status line below already
 *      names that one.)
 *   ◎ DSPAT: judge advises… — M/N agreed — last: …  (DSPAT active)
 *   · R/W: … · R: … · Bash: … · Pkg: … · Cwd: … · Tools: … (one line)
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
        // The judge model tag only when it is NOT the session model (pi's
        // status line one row below already names that one): `» DSPA:` bare,
        // or `» DSPA (Other-9B):` for a differently-configured judge.
        const sessionRef = ctx.model ? `${ctx.model.provider}/${ctx.model.id}` : null;
        const modelTag =
          s.model === null || s.model === sessionRef
            ? ""
            : ` (${s.model.split("/").pop()})`;
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
          (() => {
            const st = getDspaJudgingStage();
            return st ? ` — judging stage ${st}…` : "";
          })();
        lines.push(modeLine(width, theme, main, s.lastTarget ? [`last: ${s.lastTarget.replace(homedir() + "/", "~/")}`] : []));
      }

      if (isDspatActive() && judgeOk) {
        const s = getDspatStats();
        const stage = getDspatJudgingStage();
        const main = `◎ DSPAT${stage ? ` — judging stage ${stage}…` : ""}: judge advises on every permission prompt`;
        // Agreement counter + last disagreement, merged onto the mode line.
        // updateWidget is re-run after every recorded outcome, so live.
        const details =
          s.total > 0
            ? [`${s.agreed}/${s.total} agreed`, ...(s.lastDisagreement ? [`last: ${s.lastDisagreement}`] : [])]
            : [];
        lines.push(modeLine(width, theme, main, details));
      }

      if (hasSessionRules) {
        // One line for every grant category, safety-priority order (the write
        // boundary first, cosmetic tool grants last). Paths are ~-shortened
        // and sibling-combined for display; command sigs keep their grouping.
        const segments: { label: string; text: string }[] = [];
        if (allWritePaths.length > 0) {
          segments.push({ label: "R/W", text: displayPaths(allWritePaths.map(shortenHomePath), 3) });
        }
        if (readOnlyPaths.length > 0) {
          segments.push({ label: "R", text: displayPaths(readOnlyPaths.map(shortenHomePath), 3) });
        }
        if (bashItems.length > 0) {
          segments.push({ label: "Bash", text: capList(groupCommandVariants(bashItems), 5) });
        }
        if (pkgItems.length > 0) {
          // D10: trusted packages (fetchable run forms — npx/uvx/dlx …)
          segments.push({ label: "Pkg", text: capList(pkgItems, 5) });
        }
        if (cwdItems.length > 0) {
          // Cwd-bound bash grants (relative-path tools): shown with the cwd
          // they bind to, since the same sig is a different grant elsewhere.
          segments.push({ label: "Cwd", text: capList(cwdItems.map(shortenHomePath), 2) });
        }
        if (toolGrantItems.length > 0) {
          // Tool-plugin grants: `blender` (whole tool) or `blender:kind:read`.
          segments.push({ label: "Tools", text: capList(toolGrantItems, 3) });
        }
        const ruleLine = renderRulesLine(width, theme, segments);
        if (ruleLine) lines.push(ruleLine);
      }

      return lines.map(l => truncateToWidth(l, width));
    };
    return { render, invalidate: () => {} };
  }, { placement: "belowEditor" });
}
