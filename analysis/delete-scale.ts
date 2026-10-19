/**
 * delete-scale.ts — what a delete REACHES, and which delete shapes the floor
 * never judges (docs/dspa-intent-floor.md §6 D-c).
 *
 * The rm carve-out used to decide scale by SYNTAX: any `* ? [ ~ $ \`` in a
 * target stopped it ("rm target not explicit"). Scale is not syntax. A
 * statically rooted target inside the bars is countable, and the count is the
 * fact the judge and the user need (`deletes 312 files, recursive`); a shape
 * whose reach the shell only knows at run time is not countable, and no
 * amount of intent makes it countable — that half stays absolute.
 *
 * So one operand scan answers both questions:
 *   SHAPE (absolute): computed targets (`$D`, backticks, `$(…)`), root-level
 *     targets (`/`, home, any top-level dir — `/mnt`, `/home`, `/tmp`
 *     itself), a target that sits ABOVE the working directory (`rm -rf ..`),
 *     and the mass forms (`find -delete`, `find -exec rm`, `xargs`-fed rm,
 *     `truncate` with a glob operand);
 *   REACH (counted): the entries a delete touches, walked under a cap so a
 *     huge tree costs bounded time (precedent: the capped glob verification
 *     in analysis/credentials.ts and analysis/bash-parser.ts). More than
 *     DELETE_SCALE_ABSOLUTE entries reached OUTSIDE the temp dirs
 *     (config/path-rules allowedWritePaths) is an absolute stop — the
 *     operator's rule, 2026-10-19: "the count should affect any dir outside
 *     of tmp". Inside the temp dirs the count is informational.
 *
 * Deliberately NOT seen: deletes inside inline-code bodies (`sh -c 'rm -rf
 * /'`, `shutil.rmtree`) — the segments handed in are the top-level parse, so
 * a body's deletes are not operands here. That gap is documented
 * (docs/dspa-intent-floor.md §9), not papered over.
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { allowedWritePaths } from "../config/path-rules";
import { skipEnvPrefixes } from "../config/bash-patterns";
import { getDelegatedCommand } from "./segment-helpers";
import { tokenizeSegment } from "./tokenizer";
import { expandTilde } from "./path-util";

/** More than this many entries reached outside the temp dirs → absolute stop. */
export const DELETE_SCALE_ABSOLUTE = 50;

/** Walk budget: past it the count is reported as `N+` (bounded cost per
 *  command — a full walk of a huge tree is not the floor's job). */
export const DELETE_WALK_CAP = 4096;

/** Glob and brace metacharacters (what the shell expands, not a name). */
const GLOB_CHARS_RE = /[*?[{]/;
/** A value only the shell knows at run time. */
const COMPUTED_RE = /[$`]/;

/** Commands that delete by name, and the verbs a mass form can carry. */
const DELETE_VERBS = new Set(["rm", "rmdir", "unlink", "truncate"]);

const HOME_REAL = (() => {
  try { return fs.realpathSync(os.homedir()); } catch { return path.resolve(os.homedir()); }
})();

/** One operand of one segment, with the base that segment runs in. */
export interface DeleteSegment {
  text: string;
  /** Effective base dir of the segment; null when the segment's base is not
   *  statically provable (an unresolved `cd`) — relative operands then have no
 *  location to count. */
  base: string | null;
}

export interface DeleteOperand {
  /** the deleting command (`rm`). */
  cmd: string;
  /** the operand as written (quotes stripped). */
  raw: string;
  /** statically resolved location; the STATIC ROOT for a glob ("" when computed). */
  resolved: string;
  recursive: boolean;
  glob: boolean;
  computed: boolean;
  /** entries this delete reaches (-1 = not countable). */
  entries: number;
  capped: boolean;
  /** entries reached outside the temp dirs. */
  outsideTemp: number;
}

export interface DeleteScale {
  operands: DeleteOperand[];
  /** Absolute reasons — the floor stops; the judge never rules on these. */
  absolute: string[];
  /** Total entries reached by countable delete operands. */
  entries: number;
  /** Entries reached outside the temp dirs (the ceiling's measure). */
  outsideTemp: number;
  capped: boolean;
  recursive: boolean;
  /** Judge-packet / prompt line, e.g. `deletes 312 files, recursive`. */
  note: string | null;
}

/** Inside the temp/informational zone (config-allowed scratch dirs). */
export function inTempZone(p: string): boolean {
  return allowedWritePaths.some((d) => !!d && (p === d || p.startsWith(d + "/")));
}

/** `/`, the home directory, or any top-level directory: deleting one is
 *  never a routine operation, and its reach is the whole subtree. */
export function isRootLevelTarget(resolved: string): boolean {
  if (resolved === "/" || resolved === HOME_REAL || resolved === path.resolve(os.homedir())) return true;
  return path.dirname(resolved) === "/";
}

/** true when `resolved` is a proper ancestor of `base` (`rm -rf ..`). */
export function escapesAboveBase(resolved: string, base: string): boolean {
  return resolved !== base && base.startsWith(resolved + "/");
}

/** Strip one pair of matching quotes (the tokenizer already removed most). */
function unquote(t: string): string {
  if (t.length >= 2 && t[0] === t[t.length - 1] && (t[0] === '"' || t[0] === "'")) return t.slice(1, -1);
  return t;
}

/** The tokens a segment OPERATES with — env prefixes stripped, wrapper
 *  delegation resolved (`sudo rm` is rm). Shared with the gate's rm branch. */
export function operativeTokens(seg: string): string[] {
  const rest = literalTokens(seg);
  const deleg = getDelegatedCommand(rest.join(" "));
  return deleg ? deleg.tail.split(/\s+/) : rest;
}

/** Same stripping, WITHOUT resolving wrapper delegation — the words the user
 *  typed (`xargs rm -f` keeps its `xargs`, which is what will feed the rm). */
function literalTokens(seg: string): string[] {
  const tokens = tokenizeSegment(seg);
  return tokens.slice(skipEnvPrefixes(tokens));
}

/**
 * The STATIC ROOT of a possibly-globbed operand: the longest run of
 * metachar-free path components. `build/` + `*` → `build`; `wp9_x.jpg`
 * (pattern in the last component) → the segment's base; a three-level pattern
 * under `/tmp/x` → `/tmp/x`. Relative to `base`.
 */
export function staticRootOf(raw: string, base: string): string {
  const comps = raw.split("/");
  let i = 0;
  while (i < comps.length && !GLOB_CHARS_RE.test(comps[i])) i++;
  const root = comps.slice(0, i).join("/");
  if (raw.startsWith("/") || root.startsWith("/")) return path.normalize(root || "/");
  return path.resolve(base, root === "" ? "." : root);
}

/** Entries under `dir` (recursive, symlinks not followed), capped. */
function countUnder(dir: string, cap: number): { n: number; capped: boolean } {
  let n = 0;
  const stack = [dir];
  while (stack.length > 0) {
    const d = stack.pop() as string;
    let it: fs.DirectoryHandle;
    try {
      it = fs.opendirSync(d);
    } catch {
      continue; // unreadable / vanished — the delete would not reach it either
    }
    try {
      for (;;) {
        let ent: fs.Dirent | null;
        try { ent = it.readSync(); } catch { break; }
        if (!ent) break;
        n += 1;
        if (n >= cap) return { n, capped: true };
        // Dirent types come from lstat, so a symlinked dir is not descended
        // into — which is what `rm -r` does too.
        if (ent.isDirectory()) stack.push(path.join(d, ent.name));
      }
    } finally {
      try { it.closeSync(); } catch { /* already closed */ }
    }
  }
  return { n, capped: false };
}

/** Expand a rooted glob under the walk cap. Null = not expandable (fail closed). */
function globMatches(absPattern: string, cap: number): string[] | null {
  if (typeof fs.globSync !== "function") return null;
  try {
    const m = fs.globSync(absPattern);
    return m.length > cap ? m.slice(0, cap) : m;
  } catch {
    return null; // bad pattern / unreadable dir — the reach is unknown
  }
}

/** What one statically-rooted operand reaches. `resolved` is the glob pattern
 *  (absolute) or the concrete path. */
function operandReach(resolved: string, glob: boolean, recursive: boolean): { entries: number; capped: boolean; countable: boolean } {
  let matches: string[];
  if (glob) {
    const m = globMatches(resolved, DELETE_WALK_CAP);
    if (m === null) return { entries: -1, capped: false, countable: false };
    matches = m;
  } else {
    try {
      fs.lstatSync(resolved);
      matches = [resolved];
    } catch {
      return { entries: 0, capped: false, countable: true }; // nothing there — nothing reached
    }
  }
  let n = matches.length;
  let capped = matches.length >= DELETE_WALK_CAP;
  if (recursive) {
    for (const m of matches) {
      if (n >= DELETE_WALK_CAP) { capped = true; break; }
      let st: fs.Stats;
      try { st = fs.lstatSync(m); } catch { continue; }
      if (!st.isDirectory()) continue; // rm does not follow a symlinked dir
      const sub = countUnder(m, DELETE_WALK_CAP - n);
      n += sub.n;
      capped ||= sub.capped;
    }
  }
  return { entries: n, capped, countable: true };
}

/** `-r`/`-R`/`--recursive` in a flag list. */
function hasRecursiveFlag(words: string[]): boolean {
  return words.some(
    (t) => t === "--recursive" || (t.startsWith("-") && !t.startsWith("--") && t !== "-" && /[rR]/.test(t)),
  );
}

/** Mass forms: a delete whose targets the shell supplies (`find -delete`,
 *  `find -exec rm`, `xargs rm`, `truncate *`). Returns a reason or null.
 *  `words` are the OPERATIVE tokens (what will run) while `fedByXargs` comes
 *  from the typed words — the delegation resolves `xargs rm` to `rm`, which is
 *  exactly the shape that has no targets of its own. */
function massFormReason(words: string[], fedByXargs: boolean): string | null {
  const cmd = words[0]?.split("/").pop()?.toLowerCase() ?? "";
  if (fedByXargs && DELETE_VERBS.has(cmd)) return "delete fed by xargs (targets unbounded)";
  if (cmd === "find") {
    if (words.includes("-delete")) return "delete via find -delete (targets unbounded)";
    for (let i = 0; i < words.length; i++) {
      if (words[i] !== "-exec" && words[i] !== "-execdir" && words[i] !== "-ok" && words[i] !== "-okdir") continue;
      const next = (words[i + 1] ?? "").split("/").pop()?.toLowerCase() ?? "";
      if (DELETE_VERBS.has(next) || next === "find") return `delete fed by find ${words[i]} (targets unbounded)`;
    }
    return null;
  }
  if (cmd === "truncate") {
    const glob = words.slice(1).find((t) => !t.startsWith("-") && GLOB_CHARS_RE.test(unquote(t)));
    return glob ? `truncate with glob operand (${glob.slice(0, 40)})` : null;
  }
  if (cmd === "xargs") {
    for (const t of words.slice(1)) {
      const w = unquote(t);
      const name = w.split("/").pop()?.toLowerCase() ?? "";
      if (DELETE_VERBS.has(name) || name === "find") return "delete fed by xargs (targets unbounded)";
    }
    return null;
  }
  return null;
}

/**
 * Scan the command's delete operands. `segments` carry their own effective
 * base, so `cd out && rm -rf *` counts `out`, not the session cwd.
 */
export function assessDeletes(segments: DeleteSegment[]): DeleteScale {
  const operands: DeleteOperand[] = [];
  const absolute: string[] = [];
  let entries = 0;
  let outsideTemp = 0;
  let capped = false;
  let recursive = false;

  const reject = (op: DeleteOperand, reason: string): void => {
    if (!absolute.includes(reason)) absolute.push(reason);
    operands.push(op);
  };

  for (const { text: stage, base } of segments) {
    const words = operativeTokens(stage);
    if (words.length === 0) continue;
    const cmd = words[0]?.split("/").pop()?.toLowerCase() ?? "";
    const fedByXargs = (literalTokens(stage)[0]?.split("/").pop()?.toLowerCase() ?? "") === "xargs";
    const mass = massFormReason(words, fedByXargs);
    if (mass) {
      if (!absolute.includes(mass)) absolute.push(mass);
      continue;
    }
    if (cmd !== "rm") continue;

    const segRecursive = hasRecursiveFlag(words.slice(1));
    recursive ||= segRecursive;
    // A QUOTED tilde is a literal filename to the shell — the tokenizer has
    // already removed the quotes, so its real location is not statically known.
    const quotedTildeOf = (t: string) =>
      t.startsWith("~") && (stage.includes(`'${t}`) || stage.includes(`"${t}`));

    for (const a of words.slice(1)) {
      if (a.startsWith("-")) continue;
      const raw = unquote(a);
      if (/^[\d<>]/.test(raw)) continue; // redirection residue
      const computed = COMPUTED_RE.test(raw) || quotedTildeOf(raw);
      const glob = !computed && GLOB_CHARS_RE.test(raw);
      // A pure tilde is deterministic ($HOME) — expand it, as the gate does.
      const written = !quotedTildeOf(raw) && (raw === "~" || raw.startsWith("~/")) ? expandTilde(raw) : raw;
      const op: DeleteOperand = {
        cmd: "rm", raw, resolved: "", recursive: segRecursive, glob, computed,
        entries: -1, capped: false, outsideTemp: 0,
      };
      if (computed) {
        reject(op, `delete target not static (${raw.slice(0, 40)})`);
        continue;
      }
      // A relative operand under a segment whose base the parser could not
      // resolve has no location to count — the same fail-closed half as a
      // computed target (the D7 sentinel covers it too; this is the scale
      // module's own honest statement).
      if (base === null && !path.isAbsolute(written)) {
        reject(op, `delete target location unprovable (${raw.slice(0, 40)})`);
        continue;
      }
      const b = base ?? "/"; // absolute operands never use it
      op.resolved = glob ? staticRootOf(written, b) : path.resolve(b, written);
      // Deleting the directory the work sits in is unbounded in effect whatever
      // the entry count says — name it before the scale rules do. A glob never
      // matches `.` itself, so a pattern rooted at the base is not this case.
      if (op.resolved === b && !glob) {
        reject(op, `delete target is the working directory itself (${raw.slice(0, 40)})`);
        continue;
      }
      // The LOCATION rules apply outside the temp zone only: inside it the
      // strict-zone rule makes the reach informational whatever the shape — a
      // temp dir can be an ancestor of a temp cwd, and `/tmp` itself is a
      // top-level directory, but both are temp state. Provenance rules (a
      // computed target, an unresolvable base, deleting the cwd itself) are
      // zone-independent and already ran above.
      if (!inTempZone(op.resolved)) {
        // The escaping check comes before the root-level one: it names the more
        // specific truth about `rm -rf ..` (it deletes the directory the work
        // sits in), which root-level would report as a bare `/tmp`.
        if (escapesAboveBase(op.resolved, base ?? "")) {
          reject(op, `delete target escapes above the working directory (${raw.slice(0, 40)})`);
          continue;
        }
        // Root-level: a top-level filesystem directory, or `/` itself. A GLOB
        // does not delete its root, it deletes its matches — so a pattern is
        // root-level only when it is rooted at `/` (a top-level wipe whatever
        // the count). Everywhere else the count below is the ceiling.
        if (glob ? op.resolved === "/" : isRootLevelTarget(op.resolved)) {
          reject(op, `delete target is root-level (${raw.slice(0, 40)})`);
          continue;
        }
      }
      // REACH counts what the shell's expansion touches: for a glob that is the
      // absolute PATTERN (`build/` + `*` → `<base>/build/*`), while op.resolved
      // keeps the static root — the location the bars and the temp-zone rule
      // are checked against.
      const reach = operandReach(path.resolve(b, written), glob, segRecursive);
      if (!reach.countable) {
        reject(op, `delete reach uncountable (${raw.slice(0, 40)})`);
        continue;
      }
      op.entries = reach.entries;
      op.capped = reach.capped;
      // Zone is the operand's own root: its children inherit it (temp dirs are
      // subtrees), so a temp-rooted delete reports no outside-temp reach.
      op.outsideTemp = inTempZone(op.resolved) ? 0 : reach.entries;
      operands.push(op);
      entries += reach.entries;
      outsideTemp += op.outsideTemp;
      capped ||= reach.capped;
    }
  }

  // The ceiling, on the AGGREGATE reach outside the temp dirs: two 30-file
  // deletes outside tmp are one 60-file delete for the floor's purposes. The
  // number names the reach the bar keys on (outside temp), not the total —
  // the packet's own note carries the total.
  if (outsideTemp > DELETE_SCALE_ABSOLUTE) {
    absolute.push(`delete scale (${outsideTemp}${capped ? "+" : ""} files outside temp dirs${recursive ? ", recursive" : ""})`);
  }

  // Informational for the judge and the prompt (spec §6: `deletes 312 files,
  // recursive`). A single-file delete has nothing to report.
  const note = entries >= 2
    ? `deletes ${entries}${capped ? "+" : ""} files${recursive ? ", recursive" : ""}`
    : null;
  return { operands, absolute, entries, outsideTemp, capped, recursive, note };
}
