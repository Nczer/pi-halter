import path from "node:path";
import { expandTilde } from "./path-util";

/**
 * Cwd-local command-substitution modeling.
 *
 * A `$(…)` substitution is CWD-LOCAL when every value it can produce is a
 * name relative to the runtime cwd — i.e. `x=$(…); cat $x` (or `for f in
 * $(…); do cat $f; done`) touches only `<base>/**`, never elsewhere. This
 * lets the parser classify loop in-lists and assignment values against the
 * tracked working directory instead of treating them as fully opaque.
 *
 * Phase-1 shapes (closed; anything else stays opaque):
 *   find . [flags…]                        — plain enumeration, relative start
 *   find . … | head|sort|uniq [flags]      — output-preserving filters
 *   find . … | xargs grep -l <pattern>     — grep -l prints a subset of the
 *                                            names find fed it
 *   grep [flags] -l PATTERN START…         — -l prints the START paths (with
 *   (first stage)                            recursion: START/…), all relative
 *                                            to the runtime cwd — the 2026-08-31
 *                                            log case: sed -n "…,+16p"
 *                                            "$(grep -rln 'pat' config/ …)"
 *
 * Rejected (the output may leave the base, or is not statically knowable):
 *   - an absolute, `..`-bearing, or globbed find start path
 *   - a grep start that is absolute, ~/, .., `-` (stdin), or expanded
 *   - find -exec/-execdir/-ok/-okdir (the executed command's stdout replaces
 *     find's — arbitrary values)
 *   - any other stage command (awk, sed, wc, …), any extra grep operand, a
 *     bare numeric not fed by a flag (`sort 5` reads a file)
 *   - `$`, backtick, `;`, `&` in the inner text (computed paths, a second
 *     command)
 *   - a substitution that is not the ENTIRE word (`$(find .) extra`)
 */

/** `find -exec/-execdir/-ok/-okdir` — executed command output escapes the base. */
const FIND_EXEC_RE = /(^|\s)-(?:exec|execdir|ok|okdir)(\s|$)/;

/**
 * Whitespace-split that keeps quoted words whole (one level of '…' / "…",
 * quotes may contain spaces). Used by the grep -l stage, where the PATTERN
 * is positional: a naive split would shred a quoted multi-word pattern into
 * fragments that the start checks would misread. Unterminated quote → null
 * (fail closed).
 */
function splitShellWords(text: string): string[] | null {
  const out: string[] = [];
  let cur = "";
  let quote: string | null = null;
  for (const ch of text) {
    if (quote) {
      if (ch === quote) quote = null;
      cur += ch;
    } else if (ch === "'" || ch === '"') {
      quote = ch;
      cur += ch;
    } else if (/(\s)/.test(ch)) {
      if (cur) { out.push(cur); cur = ""; }
    } else {
      cur += ch;
    }
  }
  if (quote) return null; // unterminated quote — the shape is not provable
  if (cur) out.push(cur);
  return out;
}

/**
 * One word of a grep -l STARTS list: a relative literal (or quoted literal)
 * — not absolute, not ~/, no `..` segment, no expansion, not `-` (stdin).
 * Globs are allowed: they never match `/`, so every match stays under the
 * word's static prefix (which is under the runtime cwd by construction).
 */
function isGrepLStartWord(w: string): boolean {
  let t = w;
  const q = w.match(/^(['"])(.*)\1$/);
  if (q) {
    if (q[1] === '"' && /[$`]/.test(q[2])) return false; // expansion inside double quotes
    t = q[2];
  } else if (/['"`]$/.test(w) || /^["']/.test(w)) {
    return false; // dangling quote — the word boundaries are not provable
  }
  if (!t || t === "-") return false;
  if (/[`$]/.test(t)) return false; // runtime expansion
  if (t.startsWith("/") || t.startsWith("~")) return false; // absolute / home-pinned
  if (/(^|\/)\.\.(\/|$)/.test(t)) return false; // .. segment escapes the base
  if (t.startsWith("-")) return false; // a flag after the pattern position
  return true;
}

/**
 * Grep stage: `grep [flags] -l PATTERN START…` — the FIRST (and only) grep
 * shape that stays cwd-local. `-l` (list files) makes grep print the START
 * paths — with recursion, `START/sub/…` — instead of line content, so every
 * output value is a name relative to the runtime cwd.
 *
 * Closed set: letter-flag clusters only (r/R/l/F) — an `e` or `f` cluster
 * char consumes a pattern VALUE the scanner cannot position, and long flags
 * (--include, …) shift positions too and are rejected outright. The pattern
 * is the first non-flag token (after an optional `--`); every remaining
 * token is a START (isGrepLStartWord). At least one start — a stdin read
 * prints `-`, not names. A grep stage may not FOLLOW another stage: its own
 * starts would then ignore the piped input (the output is not a subset).
 */
function isGrepLStage(tokens: string[]): boolean {
  if (tokens[0] !== "grep") return false;
  let i = 1;
  let hasL = false;
  for (; i < tokens.length; i++) {
    const t = tokens[i];
    if (t === "--") { i++; break; } // terminator: the next token is the pattern
    if (t.startsWith("-")) {
      if (t.startsWith("--") || !/^[a-zA-Z]+$/.test(t.slice(1))) return false;
      if (/[ef]/.test(t)) return false; // -e/-f: a pattern value shifts the positions
      hasL = hasL || t.includes("l");
      continue;
    }
    break; // first non-flag: the pattern
  }
  if (!hasL || i >= tokens.length) return false; // -l required, pattern required
  const pattern = tokens[i];
  if (pattern.startsWith("-")) return false; // leading-dash pattern — ambiguous with a flag
  i++;
  let starts = 0;
  for (; i < tokens.length; i++) {
    if (!isGrepLStartWord(tokens[i])) return false;
    starts++;
  }
  return starts > 0;
}

/** First stage: `find <relative non-glob start> [flags…]` without exec forms. */
function isFindLocalStage(tokens: string[]): boolean {
  if (tokens[0] !== "find") return false;
  const start = tokens[1];
  if (!start || start.startsWith("-")) return false;
  if (FIND_EXEC_RE.test(" " + tokens.join(" ") + " ")) return false;
  const t = expandTilde(start);
  if (path.isAbsolute(t)) return false;
  if (/[?*[\]$`]/.test(start)) return false;
  if (/(^|\/)\.\.(\/|$)/.test(start)) return false;
  return true;
}

/** Filter stage: head/sort/uniq with flags (and flag-fed numbers) only — a
 *  file operand would replace the names with the file's contents. */
function isFilterStage(tokens: string[]): boolean {
  const cmd = tokens[0];
  if (cmd !== "head" && cmd !== "sort" && cmd !== "uniq") return false;
  let lastWasFlag = false;
  for (let i = 1; i < tokens.length; i++) {
    const t = tokens[i];
    if (t.startsWith("-")) {
      lastWasFlag = true;
      continue;
    }
    if (lastWasFlag && /^\d+$/.test(t)) {
      lastWasFlag = false;
      continue;
    }
    return false;
  }
  return true;
}

/** xargs stage: `xargs [flags] grep [flags] -l <pattern>` — grep -l prints a
 *  subset of the names xargs fed it; exactly one non-flag grep operand (the
 *  pattern; the names come from xargs, not the command line). */
function isXargsGrepLStage(tokens: string[]): boolean {
  if (tokens[0] !== "xargs") return false;
  let i = 1;
  while (i < tokens.length && tokens[i].startsWith("-")) i++; // xargs flags
  if (tokens[i] !== "grep") return false;
  i++;
  let hasL = false;
  let operands = 0;
  while (i < tokens.length) {
    const t = tokens[i];
    if (t === "-l") hasL = true;
    else if (!t.startsWith("-")) operands++;
    i++;
  }
  return hasL && operands === 1;
}

/** True when the `$(…)` INNER text only ever yields names relative to the
 *  runtime cwd (see module doc for the closed set). */
export function isCwdLocalSubstitution(inner: string): boolean {
  const text = inner.trim();
  if (!text) return false;
  if (/[;&`$]/.test(text)) return false; // second command / computed path
  const stages = text.split("|").map(s => s.trim().split(/\s+/).filter(Boolean));
  if (stages.some(t => t.length === 0)) return false;
  // The grep stage tokenizes quote-aware (its pattern is positional); the
  // other stages are flag-scanned, so the naive split suffices for them.
  const grepTokens = splitShellWords(stages[0].join(" "));
  if (!isFindLocalStage(stages[0]) && !(grepTokens && isGrepLStage(grepTokens))) return false;
  for (let i = 1; i < stages.length; i++) {
    if (!isFilterStage(stages[i]) && !isXargsGrepLStage(stages[i])) return false;
  }
  return true;
}

/**
 * True when an in-list (or value) WORD is exactly one cwd-local substitution:
 * `$(find …)` filling the whole word, unquoted or single-quoted. A
 * double-quoted word containing `$`/backtick expands at runtime and is
 * rejected; a word with any literal glue (`$(find .) extra`) is rejected.
 */
export function isCwdLocalWord(word: string): boolean {
  let t = word;
  const q = word.match(/^(['"])(.*)\1$/);
  if (q) {
    if (q[1] === '"' && /[$`]/.test(q[2])) return false; // expansion inside double quotes
    t = q[2];
  }
  const m = t.match(/^\$\((.*)\)$/s);
  return !!m && isCwdLocalSubstitution(m[1]);
}
