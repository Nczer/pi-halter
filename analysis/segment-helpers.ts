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
/** stripQuotedStrings. */
const QUOTE_DOUBLE_RE = /"(?:[^"\\\\]|\\\\.)*"/g;
const QUOTE_SINGLE_RE = /'[^']*'/g;
const QUOTE_DOLLAR_RE = /\$'[^']*'/g;
const QUOTE_COMMENT_RE = /\s*#.*$/gm;

/** Check if a string contains command substitution markers from stripQuotedStrings. */
export function containsCommandSubstitution(s: string): boolean {
  return s.includes(CMD_SUBST_MARKER);
}

function stripQuotedStrings(cmd: string): string {
  let s = cmd.replace(QUOTE_DOUBLE_RE, (match) => {
    if (CMD_SUBST_IN_QUOTE_RE.test(match) || BACKTICK_RE.test(match)) return CMD_SUBST_MARKER;
    return "__STR__";
  });
  s = s.replace(QUOTE_SINGLE_RE, "__STR__");
  s = s.replace(QUOTE_DOLLAR_RE, "__STR__");
  s = s.replace(QUOTE_COMMENT_RE, "");
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
 */
export function hasWriteRedirect(cmd: string): boolean {
  const trimmed = cmd.trim();
  if (STARTS_WITH_REDIRECT_RE.test(trimmed)) {
    if (!stripNullRedirects(trimmed).trim()) return false;
  }
  const stripped = stripNullRedirects(cmd);
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
 * Check if a wrapper command (xargs, timeout, nice, etc.) is running a write operation.
 * @param includeRelativePath - If true, also returns true for relative path targets (./foo).
 */
export function isWrapperRunningWrite(segment: string, includeRelativePath = true): boolean {
  const args = segment.trim().split(/\s+/);
  const firstWord = args[0].toLowerCase();
  for (let i = 1; i < args.length; i++) {
    const arg = args[i];
    if (skipWrapperArg(firstWord, arg)) continue;
    const wrappedCmd = arg.toLowerCase();
    if (includeRelativePath && isFirstTokenRelativePath(arg)) return true;
    if (isWriteOperation(wrappedCmd, segment)) return true;
    continue;
  }
  return false;
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
    const subIdx = tokens.findIndex((t, i) => i > 0 && !t.startsWith("-"));
    if (subIdx >= 0) {
      const sub = tokens[subIdx];
      return `${cmdBase} ${sub}`;
    }
    return cmdBase; // e.g. "npm" with only flags
  }

  const flags = tokens.slice(1).filter(t => t.startsWith("-")).sort();
  return flags.length === 0 ? cmd : `${cmd} ${flags.join(" ")}`;
}

/**
 * Check if find/fd/rg execution triggers a write operation.
 */
export function isFindExecWrite(segment: string): boolean {
  const execMatch = segment.match(FIND_EXEC_RE);
  if (!execMatch) return false;
  const execCmd = execMatch[1].toLowerCase();
  const afterExec = segment.slice(execMatch.index! + execMatch[0].length);
  return isWriteOperation(execCmd, afterExec);
}

export function isFdExecWrite(segment: string): boolean {
  const execMatch = segment.match(FD_EXEC_RE);
  if (!execMatch) return false;
  const execCmd = execMatch[1].toLowerCase();
  const afterExec = segment.slice(execMatch.index! + execMatch[0].length);
  return isWriteOperation(execCmd, afterExec);
}

export function isRgPreWrite(segment: string): boolean {
  const preMatch = segment.match(RG_PRE_RE);
  if (!preMatch) return false;
  const preCmd = preMatch[1].toLowerCase();
  const afterPre = segment.slice(preMatch.index! + preMatch[0].length);
  return isWriteOperation(preCmd, afterPre);
}
