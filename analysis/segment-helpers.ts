import path from "node:path";
import { isFirstTokenRelativePath } from "./path-analysis";
import { isWriteOperation, PACKAGE_MANAGERS, dangerousFindFlags, wrapperCommands } from "../config";
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
const QUOTE_DOUBLE_RE = /"(?:[^"\\]|\\.)*"/g;
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

/**
 * Check if a pipeline stage is dangerous.
 * Used by both segment-analysis.ts (pipeline loop) and evaluators.
 * Returns { dangerous, reasons, severity } for the stage.
 */
export interface StageDanger {
  dangerous: boolean;
  reasons: string[];
  severity: "high" | "medium" | null;
}

// ── Pipeline stage danger handlers ──

/** Stage danger check: match + evaluate → { dangerous, reason?, severity? } */
const STAGE_DANGER_HANDLERS: Array<{
  match: (cmd: string, stage: string) => boolean;
  evaluate: (cmd: string, stage: string) => { dangerous: boolean; reason?: string; severity?: "high" | "medium" }
}> = [
  { match: (c, s) => c === "find" && dangerousFindFlags.test(s),
    evaluate: () => ({ dangerous: true, reason: "find with dangerous flags" }) },
  { match: (c, s) => c === "find" && isFindExecWrite(s),
    evaluate: () => ({ dangerous: true, reason: "find -exec with write operation" }) },
  { match: (c, s) => c === "fd" && isFdExecWrite(s),
    evaluate: () => ({ dangerous: true, reason: "fd -x with write operation" }) },
  { match: (c, s) => c === "rg" && isRgPreWrite(s),
    evaluate: () => ({ dangerous: true, reason: "rg --pre with write operation" }) },
  { match: (c, s) => c === "sed" && isWriteOperation(c, s),
    evaluate: () => ({ dangerous: true, reason: "sed -i in pipeline (in-place file modification)", severity: "high" }) },
  { match: (c, s) => c === "perl" && isWriteOperation(c, s),
    evaluate: () => ({ dangerous: true, reason: "perl -pi/-i in pipeline (in-place file modification)", severity: "high" }) },
  { match: (c) => wrapperCommands.has(c),
    evaluate: (_, s) => ({ dangerous: isWrapperRunningWrite(s) }) },
  { match: () => true,
    evaluate: (_, s) => ({ dangerous: hasWriteRedirect(s) }) },
];

export function checkStageDanger(stage: string): StageDanger {
  const reasons: string[] = [];
  let severity: "high" | "medium" | null = null;
  let dangerous = false;

  const stageCmd = getFirstWord(stage);

  for (const handler of STAGE_DANGER_HANDLERS) {
    if (handler.match(stageCmd, stage)) {
      const result = handler.evaluate(stageCmd, stage);
      if (result.dangerous) {
        dangerous = true;
        if (result.reason) reasons.push(result.reason);
        if (result.severity && (!severity || result.severity === "high")) severity = result.severity;
      }
    }
  }

  return { dangerous, reasons, severity };
}
