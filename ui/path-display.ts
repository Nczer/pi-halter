import { homedir } from "node:os";

// ── Shared path display (widget status line + bash prompt) ──
//
// Everything here is DISPLAY-ONLY. A grant is minted from the raw dir list in
// decide/rule-generator.ts; summarizing a list for a human never widens or
// narrows what the session rule covers.

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

// ── Directory-list summary (bash prompt body line + Always labels) ──

/** Below this many dirs the plain list is already readable, so no summary.
 *  Matches the widget's path cap — the same "3 fit comfortably" judgement. */
export const DIR_SUMMARY_MIN = 4;

/** Always-label cap: dirs named outright before an `…+N more dirs` tail. */
export const DIR_LABEL_CAP = 3;

export interface DirSummary {
  /** The location most of the dirs sit under, display-shortened, with a
   *  trailing slash. NOT necessarily one of the dirs being granted — it is
   *  their common ancestor, named to give the list a place to hang on. */
  covering: string;
  /** Entries sitting under `covering` (always ≥ 2). */
  covered: number;
  /** Entries elsewhere. */
  others: number;
}

/** Proper ancestor dirs of a path, innermost first; the filesystem root is
 *  never a candidate (a grant for it is refused, so it names nothing useful). */
function ancestorsOf(d: string): string[] {
  const out: string[] = [];
  let i = d.lastIndexOf("/");
  while (i > 0) {
    out.push(d.slice(0, i));
    i = d.lastIndexOf("/", i - 1);
  }
  return out;
}

/**
 * Pick the one dir worth naming for a set of dirs: the candidate with the most
 * entries under it, ties broken to the deepest (most specific) so the summary
 * never claims more reach than the entries imply.
 *
 * null — no summary, show the list — when: fewer than DIR_SUMMARY_MIN dirs;
 * any entry is an unresolved marker (`<unresolved-cwd>`, opaque-var prefix),
 * because that signal must stay visible in full; or nothing covers 2+ entries,
 * because a scattered set has no single location and the scatter is the point.
 */
export function pickCoveringDir(dirs: string[]): DirSummary | null {
  const unique = filterSubPaths(dirs);
  if (unique.length < DIR_SUMMARY_MIN) return null;
  if (unique.some((d) => d.startsWith("<"))) return null;

  let best: { dir: string; count: number } | null = null;
  for (const d of unique) {
    for (const anc of ancestorsOf(d)) {
      const count = unique.filter((e) => e.startsWith(anc + "/")).length;
      if (count < 2) continue;
      if (!best || count > best.count || (count === best.count && anc.length > best.dir.length)) {
        best = { dir: anc, count };
      }
    }
  }
  if (!best) return null;
  return {
    covering: shortenHomePath(best.dir + "/"),
    covered: best.count,
    others: unique.length - best.count,
  };
}

/** The `⚠️ outside cwd: …` body line's dir list. Summarized when one dir
 *  covers the set, otherwise every dir, sibling-combined for width. */
export function dirListBody(dirs: string[]): string {
  const s = pickCoveringDir(dirs);
  if (s) {
    return `${s.covering} (${s.covered} dirs under it)${s.others ? ` +${s.others} others` : ""}`;
  }
  const unique = filterSubPaths(dirs);
  return unique.length <= DIR_SUMMARY_MIN - 1 ? unique.join(", ") : combineCommonPaths(unique);
}

/**
 * The Always choice's label for a dir tier ("Read" included, matching the
 * per-dir form the option used before). `writeDirs` selects the verb per dir: a
 * dir the prompt stopped as a WRITE target is labeled `Write <dir>/*` — a grant
 * labeled Read cannot satisfy a write stop, and that mislabel is what made the
 * same command prompt again after the click.
 *
 * The summary form deliberately does NOT
 * use the `<dir>/*` shape: that is how a minted rule reads, and the covering
 * dir is usually not granted at all — its sub-directories are. So the label
 * says what it counts. An empty tier yields "" (no dir Always tier exists).
 */
export function dirGrantLabel(dirs: string[], writeDirs: string[] = []): string {
  const writes = dirs.filter((d) => writeDirs.includes(d));
  const reads = dirs.filter((d) => !writeDirs.includes(d));
  if (writes.length === 0) return dirGrantLabelTier(reads, "Read");
  if (reads.length === 0) return dirGrantLabelTier(writes, "Write");
  return [dirGrantLabelTier(reads, "Read"), dirGrantLabelTier(writes, "Write")].filter(Boolean).join(" + ");
}

function dirGrantLabelTier(dirs: string[], word: "Read" | "Write"): string {
  const s = pickCoveringDir(dirs);
  if (s) {
    return `${word} ${s.covered} dirs under ${s.covering}${s.others ? ` +${s.others} more` : ""}`;
  }
  const unique = filterSubPaths(dirs);
  const shown = unique.slice(0, DIR_LABEL_CAP).map((d) => `${word} ${d}/*`);
  return shown.join(", ") + (unique.length > DIR_LABEL_CAP ? ` …+${unique.length - DIR_LABEL_CAP} more dirs` : "");
}
