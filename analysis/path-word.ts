import path from "node:path";
import os from "node:os";
import { promises as fsPromises } from "node:fs";
import { resolvePathReal } from "./path-analysis";
import { OPAQUE_VAR_DIR, UNKNOWN_CWD_MARKER, expandTilde, staticPrefixOf } from "./path-util";
import { openBraces, BRACE_RANGE_RE } from "./brace";

/**
 * A PATH WORD — the unit the location model is built on
 * (docs/dspa-intent-floor.md §9 L1, S2). One entry per word that names a
 * location in the command text, carrying what the text says about it: the word
 * as TYPED, what kind of name it is, the places it can become, and whether
 * that list is everything it can become.
 *
 * The lists every consumer reads (`paths`, the prompt's `outsidePaths` /
 * `outsideDirs`, the ledgers' path fields) are VIEWS over these records — a
 * caller that needs one place at a time loops `locations`, a caller that prints
 * one line per place flattens them. Before this, those lists were produced
 * independently in several places and two of them disagreed about the same
 * token (3.44.0: a brace token named a dir no run could produce, so the grant
 * recorded for it was dead).
 *
 * Deliberately NOT on the record yet: the read/write ROLE. The write-role table
 * (analysis/write-roles.ts) answers it from the verb and the operand position,
 * and moving it here is a change to the write bar — its own step, with its own
 * proof (S6: one behavioral move per pass).
 */
export interface PathWord {
  /** The word as it appears in the command text (`~/{a,b}/x`, `$f`, `./notes`),
   *  with any flag prefix cut (`--file=/x` → `/x`) — the form the operator
   *  recognizes and a confirmation keys on. */
  text: string;
  kind: PathWordKind;
  /** The places this word can name, in resolved real-disk form. A word that
   *  names no place has an empty list, not a guessed one. */
  locations: string[];
  /** The folder every expansion of this word must sit under — set only for a
   *  word whose places the text cannot name (a brace group past the caps, a
   *  range: docs/dspa-intent-floor.md S5). A bar tests the word here instead,
   *  so the stop still fires and the "Always" option is a folder the next run
   *  can actually match. Left undefined for every other word. */
  anchor?: string;
  /** Is `locations` the complete set this word can name? False for a wildcard
   *  (it names a prefix, and which leaves match is a disk question) and for a
   *  name the text cannot open (a brace group or range, until it is opened). */
  complete: boolean;
}

/** How the text names its location — what a consumer may conclude from it. */
export type PathWordKind =
  /** One place, provable from the text. */
  | "exact"
  /** Carries a glob: the prefix is known, the leaf set is a disk question. */
  | "wildcard"
  /** A brace group (`{a,b}`) the text can in principle open; unopened here. */
  | "group"
  /** A brace range (`{1..200}`): countable, but the count is not a location set. */
  | "range"
  /** An expansion the analysis could not bind — the `<unresolved-var>` sentinel. */
  | "opaque-var"
  /** A word whose base the cd chain could not resolve — the `<unresolved-cwd>` marker. */
  | "unknown-cwd";

/** Glob metacharacters (`[` covers a character class and an extglob opener). */
const WILDCARD_RE = /[*?[]/;
/** A brace alternation: `{a,b}` or `{a,}` — alternation needs a comma. */
const BRACE_GROUP_RE = /\{[^{}]*,[^{}]*\}/;

/**
 * Does this LOCATION string name one literal place? Any brace left in it means
 * the group was never opened (a quoted word, a runtime expansion, a refused
 * group) — the string is text, not a place a run can produce.
 */
const namesLiteralPlace = (l: string): boolean => !WILDCARD_RE.test(l) && !/[{}]/.test(l);

/**
 * What the brace walk concluded about this word — the TEXT alone cannot say it:
 * the same `{a,b}` is alternation in `ls ~/{a,b}`, part of the name in
 * `cat '{a,b}'` (quotes), and part of the name again in an escaped word.
 */
export type BraceOutcome =
  /** No openable group: the braces are literal characters, or there are none. */
  | "literal"
  /** The word's braces are quoted, so they spell part of its name. */
  | "quoted"
  /** The word carries a runtime expansion, so its braces are not statically openable. */
  | "dynamic"
  /** Opened: `locations` is one per branch (docs/dspa-intent-floor.md L2). */
  | "opened"
  /** A range (`{1..200}`): countable, but the count is not a set of places. */
  | "range"
  /** A group past L2's caps (over 16 words, or nested past 3): refused. */
  | "tooMany";

/** What kind of name this text is, given the location it resolved to. */
export function kindOfWord(
  text: string,
  location: string | undefined,
  brace: BraceOutcome = "literal",
): PathWordKind {
  // The sentinels win over the text: an unbound ref's token may carry a glob
  // (`$e/*.ts`) and still name no place — its kind says WHY it names nothing.
  if (location?.includes(UNKNOWN_CWD_MARKER)) return "unknown-cwd";
  if (location?.startsWith(`${OPAQUE_VAR_DIR}/`) || location === OPAQUE_VAR_DIR) return "opaque-var";
  if (brace === "quoted") return WILDCARD_RE.test(text) ? "wildcard" : "exact";
  if (brace === "range") return "range";
  if (brace === "opened" || brace === "tooMany") return "group";
  if (BRACE_RANGE_RE.test(text)) return "range";
  if (BRACE_GROUP_RE.test(text)) return "group";
  if (WILDCARD_RE.test(text)) return "wildcard";
  return "exact";
}

/**
 * Mint one record. `locations` is what the caller's resolution proved; a word
 * that proved nothing passes [] (it still reaches the prompt as a word — the
 * stop is on the word, not on a fabricated place). `brace` is what the brace
 * walk concluded; a caller that never walked the text passes nothing and gets
 * the text's own shape.
 */
export function pathWord(text: string, locations: string[], brace?: BraceOutcome): PathWord {
  const kind = kindOfWord(text, locations[0], brace);
  // Complete = these locations are everything the word can name. A wildcard's
  // leaf set is a disk question; an unopened group or a range names no place at
  // all (its anchor does). An OPENED group is complete when every branch is a
  // literal place (`~/{a,b}` names exactly two) and incomplete when a branch
  // still carries a glob (`AB8673GP10{1,3,4}*.pdf` names an unknown number of
  // leaves under three prefixes — docs/dspa-intent-floor.md S3).
  const complete = kind === "exact" || kind === "opaque-var" || kind === "unknown-cwd"
    || (kind === "group" && locations.length > 0 && locations.every(namesLiteralPlace));
  const word: PathWord = { text, kind, locations, complete };
  return word;
}

/**
 * Mint the record for one shell WORD: open its brace group under L2's caps and
 * resolve every name the group spells through `resolve` — the caller's recipe
 * for one word → its real-disk location, so tilde, home-token and cwd handling
 * stay where they already live.
 *
 * A group the caps refuse, and a range, names NO place: the record carries the
 * folder every expansion must sit under instead (S5) — the anchor is set here,
 * not in pathWord, because finding it needs the caller's resolver (a relative
 * word anchors on the cwd it resolves against). That is what replaced the filter
 * that used to drop brace-carved dirs from the grant options — the bogus
 * location is never minted, so nothing has to be filtered back out afterwards.
 */
export function mintWord(
  text: string,
  resolve: (word: string) => string,
  opts?: { quotedBraces?: boolean; dynamic?: boolean },
): PathWord {
  if (opts?.quotedBraces || opts?.dynamic) {
    // Braces the shell will not expand for us: quoted (they spell part of the
    // name) or behind a runtime expansion (the word names no static place).
    return pathWord(text, [resolve(text)], opts.quotedBraces ? "quoted" : "dynamic");
  }
  const open = openBraces(text);
  if (open.kind === "open") return pathWord(text, open.words.map(resolve), "opened");
  if (open.kind === "literal") return pathWord(text, [resolve(text)], "literal");
  const word = pathWord(text, [], open.kind); // "range" | "tooMany"
  const prefix = anchorOf(resolve(text), resolve);
  if (prefix) word.anchor = prefix;
  return word;
}

/**
 * The folder every expansion of `text` must sit under, resolved by the same
 * recipe as the word itself. "" when the word pins none (relative, or its very
 * first segment is already dynamic).
 */
function anchorOf(text: string, resolve: (word: string) => string): string {
  const prefix = staticPrefixOf(text);
  return prefix ? resolve(prefix) : "";
}

/** The path list every bar and ledger reads: the locations, in record order. */
export function locationsOf(words: PathWord[]): string[] {
  return words.flatMap((w) => w.locations);
}

/**
 * What a bar tests a word against: its places when it names any, otherwise —
 * for a word whose braces the text cannot open — the folder every expansion
 * must sit under (S5). A word with neither names nothing at all (a token the
 * parser refused for another reason) and contributes no stop.
 */
export function barLocations(words: PathWord[]): string[] {
  return words.flatMap((w) => (w.locations.length ? w.locations : w.anchor ? [w.anchor] : []));
}

/**
 * The folder an outside location sits in — the ONE place that answer is written
 * (it used to be `resolvePathsToDirs` plus a second, ad-hoc prefix cut for
 * unbound tokens; both keyed off the string's shape, which is how they
 * disagreed). Keyed here off the record: a marker keeps its marker (a stat would
 * degrade `<unresolved-cwd>/x` to `.`), an unbound token keeps the static prefix
 * its own text pins, a location that still carries an unopened brace group keeps
 * its static prefix, anything else is a disk question — the location itself when
 * it is a directory, its parent otherwise.
 *
 * `only` restricts the answer to locations some bar already selected (the
 * outside set): the stat runs for those, as it always has.
 *
 * A word that names no place is asked at its ANCHOR (S5), and an OPENED group is
 * asked at each of its branches — both are what the text proved, so both give a
 * folder the next run can match.
 */
export async function dirsOfLocations(words: PathWord[], only?: string[]): Promise<string[]> {
  const dirs: string[] = [];
  for (const w of words) {
    const ps = barLocations([w]);
    for (const p of only ? ps.filter((l) => only.includes(l)) : ps) {
      if (p.includes(UNKNOWN_CWD_MARKER)) dirs.push(UNKNOWN_CWD_MARKER);
      else if (p.startsWith(`${OPAQUE_VAR_DIR}/`) || p === OPAQUE_VAR_DIR) dirs.push(staticPrefixAnchor(p) ?? OPAQUE_VAR_DIR);
      else if (BRACE_GROUP_RE.test(p) || BRACE_RANGE_RE.test(p)) {
        // The location's own text carries a group the walk did NOT open — a
        // quoted word, or one backed by a runtime expansion. The string is not a
        // folder any run produces, so the answer is the deepest folder every
        // expansion sits in, which is what an "Always" grant can match. This is
        // 3.44.0's dead grant: `ls ~/{Applications,apps,bin,.local/bin}` was one
        // token, its dirname cut INSIDE the group, and the intent pass granted
        // `$HOME/{Applications,apps,bin,.local` while the four real dirs got
        // nothing. An opened group never lands here — its locations are branches.
        const anchor = staticPrefixOf(p);
        if (anchor && anchor !== "/") dirs.push(anchor);
      } else {
        try {
          const stat = await fsPromises.stat(p);
          dirs.push(stat.isDirectory() ? p : path.dirname(p));
        } catch {
          dirs.push(path.dirname(p));
        }
      }
    }
  }
  return [...new Set(dirs)].sort();
}

/**
 * The grantable static prefix of an unbound token: the leading portion before
 * the first `$`/backtick, when it is absolute (or `~/`) and pins to a real
 * directory. `~/.pi/x/$f` → the real `~/.pi/x`; `$f`, `./x/$f`,
 * `/?x/b/$f` → null (no static prefix, base-dependent, or glob-prefixed —
 * a glob prefix spans several dirs, none of which is provably the prefix).
 *
 * The token's location arrives as `<unresolved-var>/<as typed>`, so the cut is
 * the marker, not a guess about the token.
 */
function staticPrefixAnchor(location: string): string | null {
  const raw = location.startsWith(`${OPAQUE_VAR_DIR}/`)
    ? location.slice(OPAQUE_VAR_DIR.length + 1)
    : location;
  let idx = raw.length;
  for (const c of ["$", "`"]) {
    const i = raw.indexOf(c);
    if (i !== -1 && i < idx) idx = i;
  }
  if (idx <= 0) return null;
  const prefix = raw.slice(0, idx).replace(/\/+$/, "");
  if (!prefix) return null;
  // A brace in the prefix is a group the token has not opened: the cut
  // string is no more a directory than `/etc/{a,b}` is, and offering it as
  // an "Always" option is the 3.44.0 dead grant.
  if (/[\\`*?\[\]{}$]/.test(prefix)) return null;
  if (/(^|\/)\.\.(\/|$)/.test(prefix)) return null;
  if (prefix === "~" || prefix.startsWith("~/")) {
    if (!/^~\/[A-Za-z0-9._/-]+$/.test(prefix)) return null;
    const t = expandTilde(prefix);
    return path.isAbsolute(t) ? resolvePathReal(t, os.homedir()) : null;
  }
  if (!prefix.startsWith("/")) return null; // relative — base-dependent
  return resolvePathReal(prefix, os.homedir());
}
