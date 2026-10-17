import path from "node:path";
import fs from "node:fs";
import { expandTilde } from "./path-util";
import { resolvePathReal } from "./path-analysis";
import { tokenizeSegment } from "./tokenizer";
import { commandPositionWord } from "./wrapper-unwrap";

/**
 * Where a program comes from (G4, 2026-10-17 round-6 audit).
 *
 * `ls` and `/tmp/evil/ls` are the same word to a basename lookup, which is how
 * `bin/ls`, `~/Downloads/ls`, `/tmp/evil/git status` and
 * `node_modules/.bin/tsc` auto-allowed: the analysis basename-matched the
 * program against the allow table and minted NO path for the program itself, so
 * the read bar never saw the binary the shell execs. `RELATIVE_PATH_RE` (`./`,
 * `../` only) is why the existing relative-tool base binding never saw
 * `bin/ls`.
 *
 * The rule: a program the user does not control is a PATH OPERAND. Its own
 * location joins the path set (so the read bar tests it), and it matches only
 * an exact, base-bound grant — never a basename against the allow table. Only
 * argv0 under a directory the SYSTEM owns keeps bare-name semantics: those are
 * the programs every command in the table depends on, and prompting for
 * `/usr/bin/ls` buys nothing the name `ls` doesn't already say.
 *
 * The set is deliberately the dirs the distro's package manager owns
 * (`/usr/bin`, `/sbin`, …). `/usr/local/bin` and `/opt/homebrew/bin` are
 * admin/homebrew-writable — the exact class this rule targets — so they are
 * NOT system dirs here; the first such call prompts once and the location
 * grant (or the base-bound signature grant) covers it after that.
 */
const SYSTEM_PROGRAM_DIRS = ["/bin", "/sbin", "/usr/bin", "/usr/sbin"];

const SYSTEM_DIRS_REAL: string[] = SYSTEM_PROGRAM_DIRS.map((d) => {
  try {
    return fs.realpathSync(d);
  } catch {
    return d; // A dir this platform lacks simply never matches.
  }
});

export type Argv0Class =
  /** A bare name — resolved off PATH, which is checked separately
   *  (the env-PATH warning); bare-name semantics apply. */
  | "bare"
  /** Under a system-owned program dir — bare-name semantics apply. */
  | "system"
  /** Any other path-qualified invocation: relative or absolute. Its own
   *  location faces the read bar, and only an exact base-bound grant covers it. */
  | "qualified";

/**
 * Classify one argv0 word against the base the shell would resolve it from.
 * `base === null` (an unresolvable cwd) is fail-closed: a relative form whose
 * base is unknown cannot be shown to be a system program.
 */
export function classifyArgv0(word: string, base: string | null): Argv0Class {
  const expanded = expandTilde(word.replace(/^\\+/, ""));
  if (!expanded.includes("/")) return "bare";
  if (base === null) return "qualified";
  if (expanded.startsWith("-")) return "bare"; // not an executable position
  const abs = resolvePathReal(expanded, base);
  const dirReal = resolvePathReal(path.dirname(abs), base);
  return SYSTEM_DIRS_REAL.includes(dirReal) ? "system" : "qualified";
}

/**
 * Classify the command position of a STAGE (or segment) text: inline env
 * assignments (`FOO=bar /tmp/x`) and prefix/wrapper delegation
 * (`nice /tmp/x`, `env PATH=… /tmp/x`) are resolved by the one unwrapper, so a
 * wrapper in front cannot move the answer. `command -v /tmp/x` keeps bare-name
 * semantics: a lookup executes nothing, so nothing's location is touched.
 */
export function classifyStageArgv0(stageText: string, base: string | null): Argv0Class {
  if (!stageText.includes("/")) return "bare"; // no path-qualified form possible
  const { word, lookup } = commandPositionWord(tokenizeSegment(stageText));
  if (lookup || !word) return "bare";
  return classifyArgv0(word, base);
}
