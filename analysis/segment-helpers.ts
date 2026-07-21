import path from "node:path";
import { isFirstTokenRelativePath } from "./path-analysis";
import { isWriteOperation, PACKAGE_MANAGERS } from "../config";
import { splitOnPipe } from "./tokenizer";

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
const WRAPPER_TIMEOUT_RE = /^\d+(\.\d+)?(?:[smhd])?$/;
const WRAPPER_NICE_RE = /^\d+$/;
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

export function getFirstWord(segment: string): string {
  const word = segment.trim().split(/\s+/)[0].toLowerCase();
  return path.basename(word);
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

  // Package managers: include subcommand for granular control
  // npm test → "npm test", npm install → "npm install"
  // npm -v → "npm" (flag only, no subcommand)
  const cmdBase = path.basename(cmd);
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
const GIT_CLEAN_FLAGS_RE = /-[fdx]/;

// ── Git subcommand danger handlers ──

const GIT_DANGER_HANDLERS: Array<{ match: (sub: string, subArgs: string[]) => boolean }> = [
  { match: (sub) => sub === "rm" },
  { match: (sub, a) => sub === "clean" && a.some(x => GIT_CLEAN_FLAGS_RE.test(x)) },
  { match: (sub, a) => sub === "reset" && a.includes("--hard") },
  { match: (sub, a) => sub === "push" && a.some(x => x === "--force" || x === "--force-with-lease" || x === "-f") },
  { match: (sub, a) => sub === "reflog" && a.includes("expire") },
  { match: (sub, a) => sub === "gc" && a.some(x => x.startsWith("--prune")) },
];

/**
 * Check if a git command is dangerous.
 * Used by segment-analysis.ts (pipeline loop) and GitEvaluator.
 */
export function isGitDangerous(segment: string): boolean {
  const args = segment.trim().split(/\s+/);
  if (args.length < 2) return false;
  const sub = args[1].toLowerCase();
  const subArgs = args.slice(2);
  return GIT_DANGER_HANDLERS.some(h => h.match(sub, subArgs));
}


