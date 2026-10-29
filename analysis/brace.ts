/**
 * Brace arithmetic — the one place a `{a,b}` group is opened.
 *
 * Two consumers read it:
 *  - the credential scan (analysis/credentials.ts), which needs the NAMES a
 *    token spells so a secret name written `{"id_rsa",".env"}` still matches;
 *  - the location model (analysis/path-word, docs/dspa-intent-floor.md L2),
 *    which needs the WORDS a group names, so each is judged on its own and the
 *    prompt can offer a folder that actually exists.
 *
 * The scan and the floor want different limits, so the limits are the caller's:
 * the scan casts wide (a false negative is a secret read), the floor stops at
 * L2's caps (16 words out of one token, nesting no deeper than 3 — the number
 * `SUBST_MAX_DEPTH` already uses for substitution nesting) and refuses above
 * them, which is what it did for EVERY group before the group opened.
 *
 * A brace group that is not alternation stays literal text, exactly as bash
 * leaves it: `{a}` (one branch), `{2,4}` (a regex quantifier in a `sed`
 * program), an unbalanced `{`, and `\{a,b\}`. A RANGE (`{1..200}`) is
 * countable but is not a set of words the text names — the caller refuses it.
 */

/** L2: at most this many words out of one token. */
export const BRACE_WORD_CAP = 16;
/** L2: nesting no deeper than this (the SUBST_MAX_DEPTH number). */
export const BRACE_NEST_MAX = 3;
/** A brace range: `{1..9}`, `{a..z}`, `{1..200}`. */
export const BRACE_RANGE_RE = /\{[^{}]*\.\.[^{}]*\}/;

/** Index of the `}` closing the `{` at `start` (nesting + `\` honoured), or -1 when unbalanced. */
function findBraceClose(text: string, start: number): number {
  let depth = 0;
  for (let i = start; i < text.length; i++) {
    const c = text[i]!;
    if (c === "\\") { i++; continue; }
    if (c === "{") depth++;
    else if (c === "}" && --depth === 0) return i;
  }
  return -1;
}

/** Split a brace group's body at its top-level commas. */
function braceAlternatives(body: string): string[] {
  const alts: string[] = [""];
  let depth = 0;
  for (let i = 0; i < body.length; i++) {
    const c = body[i]!;
    if (c === "\\") {
      alts[alts.length - 1] += c + (body[i + 1] ?? "");
      i++;
      continue;
    }
    if (c === "," && depth === 0) { alts.push(""); continue; }
    if (c === "{") depth++;
    else if (c === "}") depth = Math.max(0, depth - 1);
    alts[alts.length - 1] += c;
  }
  return alts;
}

/**
 * Expand the brace alternations in one string into the strings it spells. A
 * group WITHOUT a top-level comma is not alternation (see the module note) and
 * its braces stay literal characters. Alternatives may contain `/` — bash
 * expands a group across directory levels (`a/{b/c,d}e` is `a/b/c` and `a/de`)
 * — so this walks the string, it does not split it into path components. A branch may itself be a group, and is
 * expanded too: every name the word spells comes back whole.
 *
 *
 * Limits are the caller's. `cap` is the total number of strings; `maxDepth` is
 * the group budget: every opened group costs one level, so with 3 three nested
 * groups open (`{a,{b,{c,d}}}` → 4 words) and a fourth is refused, and a chain
 * of groups in sequence (`{a,b}{c,d}{e,f}`) costs the same budget. Returns null
 * when either limit is passed — the caller refuses the whole word rather than
 * returning it half-opened.
 */
export function braceVariants(
  text: string,
  cap: number,
  maxDepth: number,
  depth = 0,
): string[] | null {
  if (depth > maxDepth) return null;
  let prefix = "";
  for (let i = 0; i < text.length; i++) {
    const c = text[i]!;
    if (c === "\\") { prefix += c + (text[i + 1] ?? ""); i++; continue; }
    if (c !== "{") { prefix += c; continue; }
    const close = findBraceClose(text, i);
    const alts = close < 0 ? null : braceAlternatives(text.slice(i + 1, close));
    if (!alts || alts.length < 2) { prefix += "{"; continue; } // literal brace group
    const tail = braceVariants(text.slice(close + 1), cap, maxDepth, depth + 1);
    if (tail === null) return null;
    const out: string[] = [];
    for (const alt of alts) {
      for (const t of tail) {
        // A branch may itself be a group: `{a,{b,c}}` is three words.
        const branch = braceVariants(alt + t, cap, maxDepth, depth + 1);
        if (branch === null) return null;
        for (const b of branch) {
          out.push(prefix + b);
          if (out.length > cap) return null;
        }
      }
    }
    return out;
  }
  return [prefix];
}

/** What a word's braces do. `open` carries every word the group names; the
 *  other answers say the word names ONE place as written (`literal`), or that
 *  the text cannot be opened at all (`range`, `tooMany`) — in which case the
 *  caller keeps the word and refuses to name a place for it. */
export type BraceOpening =
  | { kind: "open"; words: string[] }
  | { kind: "literal" }
  | { kind: "range" }
  | { kind: "tooMany" };

/**
 * Open one WORD's brace groups under L2's limits. Callers pass a word whose
 * braces the shell would actually expand (an unquoted word — quotes make the
 * braces part of the name). Braces left inside an opened word are literal by
 * construction: the walk expands every alternation it can find, so what stays
 * (`{{a,b}` opens to `{a` and `{b`, as bash does) is part of the name.
 */
export function openBraces(word: string): BraceOpening {
  if (BRACE_RANGE_RE.test(word)) return { kind: "range" };
  const variants = braceVariants(word, BRACE_WORD_CAP, BRACE_NEST_MAX);
  if (variants === null) return { kind: "tooMany" };
  if (variants.length < 2) return { kind: "literal" };
  return { kind: "open", words: variants };
}
