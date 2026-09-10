import type { ExtensionContext, Theme } from "@earendil-works/pi-coding-agent";
import { truncateToWidth, visibleWidth } from "@earendil-works/pi-tui";
import { homedir } from "node:os";
import { store } from "../gate/store";
import { isDspActive } from "../modes/dsp-mode";
import { isDspaActive, getDspaStats } from "../modes/dspa-mode";
import { isDspatActive, getDspatStats } from "../modes/dspat-mode";
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

// ── Status rendering ──

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
 * The single bounded halter status string, set via ctx.ui.setStatus(
 * "halter", …). With the footer extension (separate ext) it gets its own
 * line above the meta line; without it (pi's default footer) it renders on
 * pi's extension-status line, key-sorted with the others. The budget is
 * FIXED — setStatus has no width parameter — so the string trims itself:
 *
 *   ⚠ DSP                                       (DSP active — alone, rules hidden)
 *   » DSPA: 79a 3g 2r                           (DSPA: session-health counts,
 *   » DSPA (Other-9B): 3a                        non-zero only, in stop-source
 *   » DSPA: auto-allowing                        order: a auto-allowed, g floor stop,
 *   ◎ DSPAT: 3/4 agreed                          r judge reject, c declined, d defer;
 *   · R/W: … · R: … · Bash: … · Pkg: …           the description stands in while all
 *   · R: … · Bash: …                             counts are zero (pre-first-op).
 *                                                 The model tag shows only when the
 *                                                 judge model differs from the session
 *                                                 model. The rule segments ride the
 *                                                 remaining budget, dropping whole
 *                                                 low-priority segments behind …+N.)
 *
 * Dropped vs. the former widget (live in the prompts/toasts, not the
 * overview line): the judging stage, "last: <target>", the DSPAT
 * description and last disagreement.
 */
const STATUS_BUDGET = 40; // visible chars, terminal-independent

export function updateStatus(ctx: ExtensionContext): void {
  const theme = ctx.ui.theme;
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

  // Legacy widget ids (pre-status migration, incl. the pre-merge per-mode
  // ids): clear them so a same-process /reload from an old build cannot
  // leave stale widgets where the status line now lives.
  ctx.ui.setWidget("halter", undefined);
  ctx.ui.setWidget("dsp-warning", undefined);
  ctx.ui.setWidget("dspa", undefined);
  ctx.ui.setWidget("dspat", undefined);

  if (isDspActive()) {
    // DSP bypasses the whole gate — the session rules are noise, so the
    // warning stands alone.
    ctx.ui.setStatus("halter", theme.fg("error", theme.bold("⚠ DSP")));
    return;
  }

  // Judge-mode main: hidden only while the judge is invalid (the prompt
  // body carries the "⚠️ Judge invalid" line there). judgeStatus is a live
  // read (settings + session model), so a model switch is picked up on the
  // next status update. The modes are mutually exclusive (index.ts), so
  // if/else — one line can carry one main.
  const judgeOk = judgeStatus(ctx).state !== "invalid";
  let main = "";
  if (isDspaActive() && judgeOk) {
    const s = getDspaStats();
    // `»` is a text-default glyph (monochrome in every terminal) — the mode
    // follows the DSP style: no color emoji, all-caps name. The judge model
    // tag only when it is NOT the session model (the stats line already
    // names that one): `» DSPA:` bare, or `» DSPA (Other-9B):`.
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
    const body = counts.length > 0 ? counts.join(" ") : "auto-allowing";
    main = theme.fg("accent", theme.bold(`» DSPA${modelTag}: ${body}`));
  } else if (isDspatActive() && judgeOk) {
    const s = getDspatStats();
    // Agreement counter only — updateStatus re-runs after every recorded
    // outcome, so live.
    main = theme.fg(
      "accent",
      theme.bold(s.total > 0 ? `◎ DSPAT: ${s.agreed}/${s.total} agreed` : "◎ DSPAT"),
    );
  }

  if (hasSessionRules) {
    // One segment per grant category, safety-priority order (the write
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

    const remaining = STATUS_BUDGET - visibleWidth(main) - (main !== "" ? 1 : 0);
    if (remaining >= 8) {
      const ruleLine = renderRulesLine(remaining, theme, segments);
      if (ruleLine) {
        // renderRulesLine fits `remaining` except in the single-segment
        // overflow case — cap that here so the whole status stays bounded.
        const fitted =
          visibleWidth(ruleLine) <= remaining ? ruleLine : truncateToWidth(ruleLine, remaining, "…");
        main += (main !== "" ? " " : "") + fitted;
      }
    }
  }

  if (main === "") {
    ctx.ui.setStatus("halter", undefined);
  } else {
    ctx.ui.setStatus("halter", main);
  }
}
