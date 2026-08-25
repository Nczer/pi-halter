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
 *
 * Rejected (the output may leave the base, or is not statically knowable):
 *   - an absolute, `..`-bearing, or globbed find start path
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
  if (!isFindLocalStage(stages[0])) return false;
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
