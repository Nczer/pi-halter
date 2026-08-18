import path from "node:path";
import { isFirstTokenRelativePath } from "./path-analysis";
import { isWriteOperation, PACKAGE_MANAGERS, wrapperCommands } from "../config";
import { splitOnPipe, tokenizeSegment } from "./tokenizer";

// splitPipeline is splitOnPipe — same semantics (split on | not ||)
export { splitOnPipe as splitPipeline };

// ── Segment helpers (pure string utilities) ──

const CMD_SUBST_MARKER = "__CMD_SUBST__";

// ── Pre-compiled regexes for hot paths ──

/** Detect command substitution in quoted strings. */
const CMD_SUBST_IN_QUOTE_RE = /\$\s*\(/;
const BACKTICK_RE = /`/;
/** Write redirect patterns. */
export const STARTS_WITH_REDIRECT_RE = /^[0-9]*&?>+/;
const WRITE_REDIRECT_RE = />+\s*\S/;
const IN_TEST_RE = /\[\s.*\]/;
const TEST_CMD_RE = /test\s/;
/** Null redirect stripping. */
const NULL_REDIRECT_RE1 = /[0-9]*&?>+\s*(?:\/dev\/(?:null|stderr))\b/g;
const NULL_REDIRECT_RE2 = /[0-9]*>&[0-9]+/g;
/** Signature extraction. */
const SIG_REDIRECT_RE = /&?[0-9]*>>?\s*\S+/g;
const SIG_INPUT_RE = /<\s*\S+/g;
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
/** Find/fd/rg exec detection. */
const FIND_EXEC_RE = /-(?:exec|execdir)\b\s+(\S+)/;
const FD_EXEC_RE = /-(?:x|X)\b\s+(\S+)/;
const RG_PRE_RE = /--pre(?:=|\s+)(\S+)/;

/**
 * Package-manager flags that consume the NEXT token as their value (space-separated
 * form). Without this, `npm --prefix /x test` yields signature "npm /x" — junk in the
 * auto-allow list and a misleading "Always" label.
 * Flags with inline values (--prefix=/x) start with "-" and are skipped already.
 */
const PM_VALUE_FLAGS = new Set([
  "--prefix", "--registry", "--cache", "--cache-dir", "--userconfig", "--globalconfig",
  "--workspace", "-w", "--loglevel", "--cwd", "--manifest-path", "--config",
  "--target", "--target-dir", "-Z", "--index-url", "--extra-index-url", "-i",
]);
/** stripQuotedStrings. */
const QUOTE_DOUBLE_RE = /"(?:[^"\\]|\\.)*"/g;
const QUOTE_SINGLE_RE = /'[^']*'/g;
const QUOTE_DOLLAR_RE = /\$'[^']*'/g;
// Bash only treats `#` as a comment at the START of a word (line start or after
// whitespace). A mid-word `#` is literal: `cat foo#;rm -rf .` executes rm.
// A looser regex (\s*#) would strip the `;rm -rf .` and hide the chained command
// from COMPOUND_RE in FastAllowRule — an auto-allow bypass.
const QUOTE_COMMENT_RE = /(^|\s)#.*$/gm;

/** Check if a string contains command substitution markers from stripQuotedStrings. */
export function containsCommandSubstitution(s: string): boolean {
  return s.includes(CMD_SUBST_MARKER);
}

export function stripQuotedStrings(cmd: string): string {
  let s = cmd.replace(QUOTE_DOUBLE_RE, (match) => {
    if (CMD_SUBST_IN_QUOTE_RE.test(match) || BACKTICK_RE.test(match)) return CMD_SUBST_MARKER;
    return "__STR__";
  });
  s = s.replace(QUOTE_SINGLE_RE, "__STR__");
  s = s.replace(QUOTE_DOLLAR_RE, "__STR__");
  s = s.replace(QUOTE_COMMENT_RE, "$1");
  return s;
}

/**
 * Detect terminal escape/OSC sequences in echo/printf arguments — screen
 * spoofing (\033[2J + fake prompt) or OSC 52 clipboard write (\033]52;c;…).
 * Matches both literal ESC bytes and the escape notations bash interprets:
 * \033, \x1b, \e (printf always; echo with -e or $'…' quoting).
 */
const TERMINAL_ESCAPE_RE = /\\033|\\x1[bB]|\\x9[dD]|\\e(?![a-zA-Z0-9_])|[\x1b\x9d]/;

export function hasTerminalEscape(segment: string): boolean {
  return TERMINAL_ESCAPE_RE.test(segment);
}

/**
 * True if an `echo` invocation will interpret backslash escapes.
 * Echo options are the LEADING flag tokens; clusters are legal (-ne = -n -e)
 * and the last e/E in a cluster wins (bash processes left to right: -Ee →
 * escapes on, -eE → off). ANSI-C quoting ($'…') always interprets escapes.
 * Stops at the first non-option token (once arguments start, -e is data).
 */
export function echoInterpretsEscapes(segment: string): boolean {
  if (/\$'/.test(segment)) return true;
  const tokens = tokenizeSegment(segment);
  for (let i = 1; i < tokens.length; i++) {
    const t = tokens[i];
    if (!t.startsWith("-") || t === "--" || t.startsWith("--")) break;
    if (t.lastIndexOf("e") > t.lastIndexOf("E")) return true;
  }
  return false;
}

export function getFirstWord(segment: string): string {
  const word = segment.trim().split(/\s+/)[0].toLowerCase();
  return path.basename(word);
}

/** Result of resolving the command a prefix/wrapper delegates to. */
interface DelegatedResolution {
  /** Lowercased basename of the delegated command. */
  cmd: string;
  /** Index of the delegated command token in `words`. */
  index: number;
  /** True for `command -v/-V` lookups (no command is executed). */
  lookup: boolean;
}

/**
 * Resolve the command a shell prefix (command/builtin/exec/env) or wrapper
 * (timeout/xargs/watch/parallel/nice/ionice/stdbuf) delegates to. Skips the
 * prefix/wrapper flags, option values, and env assignments to find the actual
 * command token. Returns null when the segment doesn't delegate to another
 * command (or the delegated token isn't a command name).
 */
function resolveDelegatedTokens(words: string[]): DelegatedResolution | null {
  if (words.length < 2) return null;
  const first = (words[0] ?? "").replace(/^\\+/, "");
  const f = first.toLowerCase();
  let i = 1;
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
  const word = words[i] ?? "";
  if (!word || word.startsWith("-") || word === "__STR__" || word === "__CMD_SUBST__") return null;
  return { cmd: path.basename(word.toLowerCase()), index: i, lookup };
}

/**
 * Get the effective command name after shell prefix wrappers. `command …`,
 * `builtin …`, `exec …`, and `env …` all *execute* the following command, so
 * checks keyed on the first word (printf/echo terminal escapes, sort -o, …)
 * would miss `command printf '\033]52;…'` or `env sort -o x y`. Also strips
 * leading backslashes (\printf) and `env` flags/assignments. Pure text.
 */
export function getEffectiveCommand(segment: string): string {
  const words = tokenizeSegment(segment);
  const res = resolveDelegatedTokens(words);
  if (res) return res.cmd;
  // Non-delegating segment: effective command is the first word itself
  // (same as pre-wrapper-resolution behavior, incl. leading-backslash forms).
  const word = words[0] ?? "";
  return path.basename(word.toLowerCase());
}

/**
 * The command a segment actually executes when its first word is a shell
 * prefix (command/builtin/exec/env) or wrapper (timeout/xargs/watch/…).
 * `tail` is the text from the delegated command onward (quote-stripped tokens
 * re-joined) so it can be evaluated as if it were a bare first word.
 * Returns null for non-delegating segments and `command -v/-V` lookups.
 */
export function getDelegatedCommand(segment: string): { cmd: string; tail: string } | null {
  const words = tokenizeSegment(segment);
  const res = resolveDelegatedTokens(words);
  if (!res || res.lookup) return null;
  return { cmd: res.cmd, tail: words.slice(res.index).join(" ") };
}

/** Strip /dev/null, /dev/stderr redirects and fd-to-fd redirects from a command string. */
export function stripNullRedirects(cmd: string): string {
  return cmd
    .replace(NULL_REDIRECT_RE1, "")
    .replace(NULL_REDIRECT_RE2, "");
}

/**
 * Check if a command string contains a write redirect (> or >> to a file).
 * Ignores /dev/null, /dev/stderr, fd-to-fd redirects, and test/[ conditionals.
 * Quote-aware: operators inside quoted strings (e.g. a grep pattern containing
 * "=>" or ">") are not treated as redirects. Unquoted command substitution
 * $(...) is preserved, so real redirects inside subshells are still detected.
 */
export function hasWriteRedirect(cmd: string): boolean {
  const noQuotes = stripQuotedStrings(cmd);
  const trimmed = noQuotes.trim();
  if (STARTS_WITH_REDIRECT_RE.test(trimmed)) {
    if (!stripNullRedirects(trimmed).trim()) return false;
  }
  const stripped = stripNullRedirects(noQuotes);
  if (WRITE_REDIRECT_RE.test(stripped)) {
    const inTest = IN_TEST_RE.test(stripped) || TEST_CMD_RE.test(stripped);
    if (!inTest) return true;
  }
  return false;
}

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

/**
 * Iterate wrapper command args (skipping flags/options) and apply a predicate.
 * @param firstOnly - If true, check only the first non-flag arg. If false, check all.
 */
function checkWrapperArg(segment: string, predicate: (arg: string) => boolean, firstOnly = false): boolean {
  const args = segment.trim().split(/\s+/);
  const firstWord = args[0].toLowerCase();
  for (let i = 1; i < args.length; i++) {
    const arg = args[i];
    if (skipWrapperArg(firstWord, arg)) continue;
    if (predicate(arg)) return true;
    if (firstOnly) break;
  }
  return false;
}

/**
 * Check if a wrapper command (xargs, timeout, nice, etc.) is running a write operation.
 * @param includeRelativePath - If true, also returns true for relative path targets (./foo).
 */
export function isWrapperRunningWrite(segment: string, includeRelativePath = true): boolean {
  return checkWrapperArg(segment, (arg) => {
    if (includeRelativePath && isFirstTokenRelativePath(arg)) return true;
    return isWriteOperation(arg.toLowerCase(), segment);
  });
}

/**
 * Check if a wrapper command is targeting a relative path (./foo, ../foo).
 */
export function isWrapperRunningRelativePath(segment: string): boolean {
  return checkWrapperArg(segment, (arg) => isFirstTokenRelativePath(arg), true);
}

/**
 * Extract a command signature, stripping redirects and quotes.
 * For pipelines, uses the first command's signature.
 * For package managers, includes the subcommand for granular allow control.
 */
export function getCommandSignature(segment: string): string {
  const firstCmd = splitOnPipe(segment)[0] ?? segment;
  const cleaned = firstCmd
    .replace(SIG_REDIRECT_RE, "")
    .replace(SIG_INPUT_RE, "")
    .trim();
  const tokens = stripQuotedStrings(cleaned).split(/\s+/);
  const cmd = tokens[0].toLowerCase();

  const cmdBase = path.basename(cmd);
  // Wrapper/prefix transparency: a wrapped command's signature must name the
  // delegated command, so an "Always" grant on `timeout curl` can't cover
  // `timeout ssh`, and a bare `timeout` grant covers nothing wrapped at all.
  const deleg = resolveDelegatedTokens(tokens);
  if (deleg && !deleg.lookup) {
    return `${cmdBase} ${deleg.cmd}`;
  }

  // Package managers: include subcommand for granular control
  // npm test → "npm test", npm install → "npm install"
  // npm -v → "npm" (flag only, no subcommand)
  if (PACKAGE_MANAGERS.has(cmdBase)) {
    // Find the subcommand: first non-flag token, skipping values of flags that
    // consume the next token (--prefix /x). Inline values (--prefix=/x) are
    // part of the flag token and skipped with it.
    for (let i = 1; i < tokens.length; i++) {
      const t = tokens[i];
      if (t.startsWith("-")) {
        if (PM_VALUE_FLAGS.has(t) && !t.includes("=")) i++; // skip the flag's value
        continue;
      }
      return `${cmdBase} ${t}`;
    }
    return cmdBase; // e.g. "npm" with only flags
  }

  const flags = tokens.slice(1).filter(t => t.startsWith("-")).sort();
  return flags.length === 0 ? cmd : `${cmd} ${flags.join(" ")}`;
}

/**
 * Check if a tool's exec/pre flag triggers a write operation.
 * Generic helper for find -exec, fd -x, rg --pre, etc.
 */
function checkExecWrite(segment: string, regex: RegExp): boolean {
  const match = segment.match(regex);
  if (!match) return false;
  const cmd = match[1].toLowerCase();
  const after = segment.slice(match.index! + match[0].length);
  return isWriteOperation(cmd, after);
}

export function isFindExecWrite(segment: string): boolean {
  return checkExecWrite(segment, FIND_EXEC_RE);
}

export function isFdExecWrite(segment: string): boolean {
  return checkExecWrite(segment, FD_EXEC_RE);
}

export function isRgPreWrite(segment: string): boolean {
  return checkExecWrite(segment, RG_PRE_RE);
}

/** Pre-compiled regex for git clean flags. */
const GIT_CLEAN_FLAGS_RE = /-[a-z]*[fdx][a-z]*/;

/**
 * `git -c name=value` / `--config name=value` inline config values that make
 * git execute a command:
 *   - alias.*=!…      → shell alias: `git st` runs the `!` command
 *   - core.pager=…    → run as pager (tty)
 *   - core.editor=…   → run as editor
 *   - core.sshCommand=… → run instead of ssh
 *   - core.fsmonitor=…  → run on every refresh (unconditional)
 *   - core.askpass=…    → run to prompt for credentials
 */
const GIT_DANGEROUS_CONFIG_RE = /^(?:alias\.[^=]+=!|credential\.helper=!|diff\.external=|filter\.[^=]+\.(?:clean|smudge)=|pager\.[^=]+=|interactive\.diffFilter=|sequence\.editor=|core\.(?:pager|editor|sshCommand|fsmonitor|askpass)=)/;

/** True if a `-c`/`--config` value configures git to execute a command. */
function isDangerousGitConfigValue(value: string | undefined): boolean {
  return value !== undefined && GIT_DANGEROUS_CONFIG_RE.test(value);
}

/** True if a git global arg (plus its value token) carries dangerous inline config. */
function hasDangerousInlineConfig(arg: string, next: string | undefined): boolean {
  if (arg === "-c" || arg === "--config") return isDangerousGitConfigValue(next);
  if (arg.startsWith("-c") && !arg.startsWith("-C") && arg.includes("=")) return isDangerousGitConfigValue(arg.slice(2));
  if (arg.startsWith("--config=")) return isDangerousGitConfigValue(arg.slice("--config=".length));
  return false;
}

// ── Git subcommand danger handlers ──

const GIT_DANGER_HANDLERS: Array<{ match: (sub: string, subArgs: string[]) => boolean }> = [
  { match: (sub) => sub === "rm" },
  { match: (sub, a) => sub === "clean" && a.some(x => GIT_CLEAN_FLAGS_RE.test(x)) },
  { match: (sub, a) => sub === "reset" && a.includes("--hard") },
  { match: (sub, a) => sub === "push" && a.some(x => x === "--force" || x === "--force-with-lease" || x === "-f") },
  { match: (sub, a) => sub === "reflog" && a.includes("expire") },
  { match: (sub, a) => sub === "gc" && a.some(x => x.startsWith("--prune")) },
];

/** Git global flags that appear before the subcommand. */
const GIT_GLOBAL_FLAGS = new Set(["-c", "-C", "--git-dir", "--work-tree", "--no-pager", "-p", "--paginate", "--no-replace-objects", "--literal-pathspec", "--no-optional-locks", "--bare", "--help"]);

/**
 * Check if a git command is dangerous.
 * Used by segment-analysis.ts (pipeline loop) and GitEvaluator.
 * Skips global flags to find the actual subcommand.
 */
export function isGitDangerous(segment: string): boolean {
  // Quote-aware tokenization: `git -c "alias.st=!rm /tmp/x" st` must be seen
  // as -c + one value token, not split on the space inside the quotes.
  const args = tokenizeSegment(segment);
  if (args.length < 2) return false;

  // Skip global flags to find the actual subcommand
  let subIdx = 1;
  while (subIdx < args.length) {
    const arg = args[subIdx];
    // Inline config that executes code is dangerous regardless of subcommand.
    if (hasDangerousInlineConfig(arg, args[subIdx + 1])) return true;
    if (GIT_GLOBAL_FLAGS.has(arg)) {
      // -c and -C take a value argument
      if (arg === "-c" || arg === "-C") subIdx++;
      // --git-dir, --work-tree take a value argument
      if (arg.startsWith("--git-dir") || arg.startsWith("--work-tree")) subIdx++;
      subIdx++;
      continue;
    }
    // --flag=value form (e.g., --git-dir=x)
    if (arg.startsWith("--") && arg.includes("=")) {
      subIdx++;
      continue;
    }
    break;
  }

  if (subIdx >= args.length) return false;
  const sub = args[subIdx].toLowerCase();
  const subArgs = args.slice(subIdx + 1);
  return GIT_DANGER_HANDLERS.some(h => h.match(sub, subArgs));
}


