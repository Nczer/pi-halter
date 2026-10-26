import path from "node:path";
import os from "node:os";

/** Current username for `~user` expansion (os.userInfo can throw in exotic
 *  environments — null falls back to /home/<user> for every user). */
let currentUsername: string | null = null;
try {
  currentUsername = os.userInfo().username;
} catch {
  currentUsername = null;
}

/** `~user` / `~user/…` — a word-initial tilde with a username (the shell
 *  expands these via the passwd database; `~/…` and bare `~` are handled
 *  before this). */
const TILDE_USER_RE = /^~([A-Za-z_][A-Za-z0-9._-]*)(?:\/(.*))?$/;

/**
 * Expand tilde (~) to home directory. `~user` expands to that user's home:
 *  the current user is well-defined (os.homedir), any other user is modeled
 *  as the standard /home/<user> — a home stored elsewhere still lands
 *  outside the session base and forces approval (conservative, never
 *  under-scoped).
 */
export function expandTilde(p: string): string {
  if (p.startsWith("~/")) return path.join(os.homedir(), p.slice(2));
  if (p === "~") return os.homedir();
  const m = TILDE_USER_RE.exec(p);
  if (m) {
    const user = m[1];
    const home =
      currentUsername !== null && user === currentUsername ? os.homedir() : path.join("/home", user);
    return m[2] ? path.join(home, m[2]) : home;
  }
  return p;
}

/**
 * Statically resolvable variable-path tokens — a closed set. `$HOME`/`${HOME}`
 * expand to os.homedir() independent of any cd; any other variable or
 * expansion (`$D/x`, `${HOME:-/tmp}`) is a computed path and stays opaque
 * (its value is only knowable by running the shell).
 */
export const HOME_TOKEN_RE = /^\$(?:\{HOME\}|HOME)(?:\/|(?![a-zA-Z0-9_]))/;

/** Expand a leading $HOME / ${HOME} to the home directory (no-op otherwise). */
export function expandHomeToken(p: string): string {
  const m = p.match(/^\$(?:\{HOME\}|HOME)(?:\/(.*))?$/);
  if (!m) return p;
  return m[1] !== undefined ? path.join(os.homedir(), m[1]) : os.homedir();
}

/**
 * Expand every $HOME / ${HOME} occurrence INSIDE argument text (a script body
 * or a quoted substitution), leaving other expansions alone. Only meaningful
 * where the shell would expand — the caller checks that (a double-quoted arg)
 * and that HOME is not reassigned. A backslash-escaped `\$HOME` stays literal.
 */
export function expandHomeLiterals(text: string): string {
  return text.replace(/(?<!\\)\$(?:\{HOME\}|HOME)(?![A-Za-z0-9_])/g, os.homedir());
}

/**
 * Sentinel dir for paths whose runtime location is statically unbound (an
 * opaque expansion the analysis could not bind). It sits outside every real
 * dir, so the outside-cwd check can never drop a path carrying it.
 */
export const OPAQUE_VAR_DIR = "<unresolved-var>";

/** Display marker for paths that resolve against an unknown effective cwd.
 *  Lives here, next to the other unnameable-location spelling, so the one
 *  containment test can refuse both (step 1 of the location model). */
export const UNKNOWN_CWD_MARKER = "<unresolved-cwd>";

/** Both spellings of "this word names no location I can compare". */
const UNRESOLVED_MARKER_RE = /<(?:unresolved-var|unresolved-cwd)>/;

/**
 * Only the two marker spellings — for a caller that resolves relatives itself
 * (the judge's report sanitizer resolves against the operation's cwd, so a
 * relative word is not unresolved there, and only a marker is unfixable).
 */
export function isUnresolvedMarker(p: string): boolean {
  return UNRESOLVED_MARKER_RE.test(p);
}

/**
 * Does this word name no location? True for a relative path (it still needs a
 * base) and for either unnameable-location spelling. A caller that has to SHOW
 * such a word, or stop on it anyway, tests here first — `under` refuses one
 * rather than answering wrongly.
 */
export function isUnresolvedPath(p: string): boolean {
  return !path.isAbsolute(p) || isUnresolvedMarker(p);
}

/**
 * THE containment test: is `child` the same place as `parent`, or under it?
 * Both sides must already be in real-disk form — absolute, marker-free and
 * normalized (what `resolvePathReal` returns). An unresolved side is a bug at
 * the call site: "inside" would be a false allow and "outside" a stop the
 * operator cannot explain, so it throws. halter's tool handler turns a throw
 * into a block (index.ts, fail-closed), so a missed call site stops loudly.
 *
 * Until 3.45.0 this answer was written five times over (plus 18 inline
 * `x === r || x.startsWith(r + "/")` copies), and two of those copies disagreed
 * about the same token — the gate stopped on it while the ledger diagnostic
 * called it a floor blind spot that did not exist (3.44.0).
 */
export function under(child: string, parent: string): boolean {
  for (const side of [child, parent]) {
    if (!path.isAbsolute(side) || UNRESOLVED_MARKER_RE.test(side)) {
      throw new Error(
        `under(): ${JSON.stringify(side)} names no location — resolve it (resolvePathReal) or test isUnresolvedPath first`,
      );
    }
    if (path.normalize(side) !== side) {
      throw new Error(`under(): ${JSON.stringify(side)} is not in real-disk form (path.normalize would change it)`);
    }
  }
  return child === parent || child.startsWith(parent === "/" ? "/" : `${parent}/`);
}

/**
 * Positional/one-letter shell parameters — a reference whose value comes from
 * a CALL SITE, never from the text of the command being judged: `$1`…`$9`,
 * `${12}`, `$0`, the argument list `$@`/`$*`, and the shell's own status
 * vars (`$#`, `$?`, `$!`, `$-`). Matches anywhere in a token, so the compound
 * forms an unquoted expansion produces (`${2}V*.txt`) count too.
 *
 * Why callers care: confirmed resolutions are keyed by the token AS WRITTEN
 * (store.confirmResolution), so a confirmed `$2` vouches for one script's
 * argument and then silently re-applies it to every other command spelling
 * the same token — a false resolution, i.e. under-flagging. Such tokens never
 * converge; they keep prompting (fail closed).
 */
const POSITIONAL_REF_RE = /\$(?:[0-9]|[-@*#?!])|\$\{\s*(?:[0-9]+|[@*])/;

export function isPositionalRef(token: string): boolean {
  return POSITIONAL_REF_RE.test(token);
}

/**
 * Display form of an unresolved token for prompts/reasons: first line,
 * truncated to `max` chars with an ellipsis. Tokens can be whole glob
 * expansions of a long base — one short line is all the operator needs to
 * recognize the reference (the full token stays in the unresolved log).
 */
export function shortenToken(token: string, max = 60): string {
  const line = token.split("\n")[0].trim();
  if (line.length <= max) return line;
  return line.slice(0, max - 1) + "…";
}

/** A path segment with anything dynamic in it: a variable, a substitution,
 *  a glob or extglob brace, an unresolved-marker sentinel, an escape. */
const DYNAMIC_SEGMENT_RE = /[$`*[\]{}<>\\]/;

/**
 * The static PREFIX anchor of a path token — the deepest directory every
 * expansion of that token must sit under, i.e. what the floor knows even when
 * it cannot name the leaf. "" (no anchor) when the token is relative or when
 * its first segment is already dynamic.
 *
 * Used in both directions of the same decision: the gate cuts a miss's anchor
 * here (dspa-gate.anchorOf, and §4.2 requires a reported path to land under
 * it), and the D13 diagnostic counts a judge report as covered by the floor
 * when it lands under the anchor of one of the floor's own paths (3.44.0 —
 * without this, `/tmp/snap-x/exa` read as a blind spot for a floor path of
 * `/tmp/snap-x/$e`).
 */
export function staticPrefixOf(raw: string): string {
  const text = expandTilde(raw);
  const body = text.startsWith(`${OPAQUE_VAR_DIR}/`)
    ? `/${text.slice(OPAQUE_VAR_DIR.length + 1)}`
    : text;
  if (!path.isAbsolute(body)) return "";
  const comps = body.split("/").slice(1);
  let i = 0;
  while (i < comps.length && comps[i] !== "" && !DYNAMIC_SEGMENT_RE.test(comps[i])) i++;
  if (i === 0) return ""; // nothing static before the first dynamic part
  return path.normalize(`/${comps.slice(0, i).join("/")}`);
}

/**
 * The folder an approval can REMEMBER for a path word — "which folder do I
 * allow so this stops prompting". For a word that names its leaf, that is the
 * containing dir. For a word that cannot name its leaf (`~/notes/*`,
 * `/tmp/{a,b}/x`) it is the deepest folder every expansion must sit under, so
 * the remembered dir is a real one that the next run can match.
 *
 * The old rule — cut at the last slash — mints a dir no run can ever match when
 * the dynamic part is not the last segment: `/tmp/{a,b}/x` remembered
 * `/tmp/{a,b}`, which is not a directory, so the command re-stopped after the
 * user had already allowed it (the 3.44.0 read-bar case; step 1 of the location
 * model, docs/dspa-intent-floor.md §9 L3). "" = the word pins no folder that an
 * approval may remember — relative, dynamic in its first segment, or pinned only
 * to the root (step-1 corpus replay: `ls /optfoo`, a word in a top-level folder
 * that does not exist, is pinned to `/`, and "everything under the root" is the
 * bar switched off rather than a folder the operator named; the stop still
 * fires, and the caller keeps the word itself as the location it cannot name).
 */
export function rememberedDirOf(word: string): string {
  const expanded = expandTilde(word);
  if (!path.isAbsolute(expanded)) return "";
  if (expanded.split("/").some((c) => c !== "" && DYNAMIC_SEGMENT_RE.test(c))) {
    const prefix = staticPrefixOf(expanded);
    return prefix === "/" ? "" : prefix;
  }
  const dir = path.dirname(expanded);
  return dir === "/" ? "" : dir;
}
