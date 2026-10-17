import path from "node:path";
import { wrapperCommands } from "../config";

/**
 * The command position of a word list: the ONE unwrapper for shell prefixes
 * (`command`/`builtin`/`exec`/`env`) and pass-through wrappers
 * (`timeout`/`nice`/`ionice`/`stdbuf`/`xargs`/`watch`/`parallel`).
 *
 * Every rule that keys on "what does this segment run" — the signature a grant
 * is stored under, the allow table, the operand model that mints paths, the
 * egress check, the base-access/base-write checks — has to agree on that
 * answer, or a wrapper in front of the command moves the answer per consumer.
 * `nice command cat /etc/hosts` was `nice` to the parser (no path-aware program
 * → the operand model never ran → paths=[], no location bar at all),
 * `nice command` to the signature, and `cat` to nobody (2026-10-17 round-6
 * audit). Fixpoint, not one hop: prefixes nest, and unwrapping once stops at
 * the NEXT prefix (`nice command ssh` → `command`, which names nothing).
 */

/** Wrapper arg skip. */
const WRAPPER_ENV_ASSIGN_RE = /=/;
// GNU timeout durations: plain (5), suffixed (5s, 1.5m), suffixed chains
// (1h30m, 1h30m5s), or clock form (00:05, 1:30:00).
const WRAPPER_TIMEOUT_RE = /^(?:(?:\d+(\.\d+)?[smhd])+\d*|\d+(\.\d+)?|\d{1,2}(?::\d{1,2}){1,2})$/;
const WRAPPER_NICE_RE = /^\d+$/;

/**
 * Wrapper flags that consume the NEXT token as their value (space form).
 * Without this, `watch -n 1 curl` would resolve "1" as the delegated command.
 */
const WRAPPER_VALUE_FLAGS: Record<string, Set<string>> = {
  watch: new Set(["-n", "--interval"]),
  xargs: new Set(["-n", "--max-args", "-L", "--max-lines", "-P", "--max-procs", "-s", "--arg-size", "-I", "--replace", "-d", "--delimiter", "-a", "--arg-file", "-E", "--eof"]),
  parallel: new Set(["-j", "--jobs", "-i", "--input-file", "--block-size", "--group-size", "--jobserver", "--jobserver-batch-size", "--tmpdir", "--basefile", "--results"]),
  timeout: new Set(["-s", "--signal"]),
  stdbuf: new Set(["-i", "-o", "-e"]),
};

/**
 * Determine if a wrapper argument should be skipped (is a flag or wrapper-specific option).
 */
export function skipWrapperArg(wrapper: string, arg: string): boolean {
  if (arg.startsWith("-")) return true;
  if (wrapper === "env" && WRAPPER_ENV_ASSIGN_RE.test(arg) && !arg.startsWith("/")) return true;
  if (wrapper === "timeout" && WRAPPER_TIMEOUT_RE.test(arg)) return true;
  if (wrapper === "nice" && WRAPPER_NICE_RE.test(arg)) return true;
  if (wrapper === "ionice" && WRAPPER_NICE_RE.test(arg)) return true;
  return false;
}

/** Result of resolving the command a prefix/wrapper delegates to. */
export interface DelegatedResolution {
  /** Lowercased basename of the delegated command. */
  cmd: string;
  /** Index of the delegated command token in `words`. */
  index: number;
  /** True for `command -v/-V` lookups (no command is executed). */
  lookup: boolean;
  /**
   * The chain ran past MAX_UNWRAP_HOPS: there is no program identity. `cmd` is
   * empty. Consumers that key a rule on the program, or that mint operands at
   * that program's positions, must treat this as OBSCURING the command (worst
   * case), not as "the first word" — the first word is a wrapper, which names
   * nothing and silently skips the operand model.
   */
  capped: boolean;
}

/**
 * How far a command position may be buried under prefixes and wrappers before
 * the segment stops naming a program at all. A one-hop model is the bug this
 * exists for: `nice command cat /etc/hosts` unwraps to `command`, which is not
 * path-aware, so the operand model never ran and `/etc/hosts` left no trace.
 * Iterating past a cap would be its own blind spot (an unbounded chain is a DoS
 * at best), so beyond the cap the answer is "no identity" + fail closed.
 */
export const MAX_UNWRAP_HOPS = 4;

/**
 * One hop: the index of the word `words[from]` delegates to, or null when that
 * word is not a prefix/wrapper. Skips the prefix/wrapper flags, option values,
 * and env assignments to find the actual command token.
 */
function unwrapOneHop(words: string[], from: number): { index: number; lookup: boolean } | null {
  if (from >= words.length) return null;
  const first = (words[from] ?? "").replace(/^\\+/, "");
  const f = first.toLowerCase();
  let i = from + 1;
  let lookup = false;
  if (f === "command" || f === "builtin" || f === "exec") {
    // `command [-p] [-v|-V] name` / `exec [-cl] [-a name] [command]` — skip
    // lookup/exec flags so the real command name is found.
    while (i < words.length && /^-[pVvlc]+$/.test(words[i])) {
      if (f === "command" && /[vV]/.test(words[i])) lookup = true;
      i++;
    }
    if (words[i] === "-a" && i + 1 < words.length) i += 2;
  } else if (f === "env") {
    // env [-i] [-u NAME] [--unset=NAME] [-C DIR] [FOO=bar …] cmd
    while (i < words.length) {
      const a = words[i];
      if (a === "-i" || a === "--ignore-environment" || a === "-S" || a === "--split-string") { i++; continue; }
      if ((a === "-u" || a === "--unset" || a === "-C" || a === "--chdir") && i + 1 < words.length) { i += 2; continue; }
      if (a.startsWith("--unset=") || a.startsWith("--chdir=")) { i++; continue; }
      if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(a)) { i++; continue; }
      break;
    }
  } else if (wrapperCommands.has(f)) {
    // wrapper [FLAGS/VALUES] cmd — skip flags, their values, and wrapper
    // option arguments (timeout durations, nice/ionice numbers, env assigns).
    const valueFlags = WRAPPER_VALUE_FLAGS[f];
    let skipNext = false;
    while (i < words.length) {
      const a = words[i];
      if (skipNext) { skipNext = false; i++; continue; }
      if (a.startsWith("-")) {
        if (valueFlags?.has(a)) skipNext = true;
        i++;
        continue;
      }
      if (skipWrapperArg(f, a)) { i++; continue; }
      break;
    }
  } else {
    return null;
  }
  return { index: i, lookup };
}

/**
 * Resolve the command a shell prefix (command/builtin/exec/env) or wrapper
 * (timeout/xargs/watch/parallel/nice/ionice/stdbuf) delegates to — to a
 * FIXPOINT, because prefixes nest and a one-hop unwrap stops at the next
 * prefix: `nice command ssh`, `timeout 5 nice cat`, `command env nice cat`.
 * Returns null when the segment doesn't delegate to another command (or the
 * delegated token isn't a command name), and a `capped` resolution when the
 * chain is too deep to name a program.
 */
export function resolveDelegatedTokens(words: string[]): DelegatedResolution | null {
  let index = 0;
  let lookup = false;
  for (let hop = 0; hop <= MAX_UNWRAP_HOPS; hop++) {
    const step = unwrapOneHop(words, index);
    if (!step) break;
    index = step.index;
    lookup = lookup || step.lookup;
    if (hop === MAX_UNWRAP_HOPS) return { cmd: "", index, lookup, capped: true };
  }
  if (index === 0) return null;
  const word = words[index] ?? "";
  if (!word || word.startsWith("-") || word === "__STR__" || word === "__CMD_SUBST__") return null;
  return { cmd: path.basename(word.toLowerCase()), index, lookup, capped: false };
}
