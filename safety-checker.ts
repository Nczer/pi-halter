import {
  allowedBashPatterns,
  dangerousFindFlags,
  dangerousPerlFlags,
  dangerousSedFlags,
  dangerousCommandPatterns,
  dangerousContextPatterns,
  isTrustedScriptCommand,
  wrapperCommands,
  writeCapableCommands,
} from "./config";
import type { BashSegment } from "./bash-parser";
import { isFirstTokenRelativePath } from "./path-analysis";
import { getFirstWord, splitPipeline } from "./segment-helpers";

// ── Constants ──

const SHELL_INTERPRETERS = new Set(["bash", "sh", "zsh", "fish", "dash", "ksh", "csh", "tcsh"]);
const LOOKUP_COMMANDS = new Set(["which", "type", "command", "hash", "whence"]);
const ECHO_COMMANDS = new Set(["echo", "printf", "true", "false"]);
const PROCESS_INSPECTION_COMMANDS = new Set(["pgrep", "pidof"]);

// ── Write redirect detection ──

function hasWriteRedirect(cmd: string): boolean {
  const trimmed = cmd.trim();
  if (/^[0-9]*&?>+/.test(trimmed)) {
    let stripped = trimmed;
    stripped = stripped.replace(/[0-9]*&?>+\s*(?:\/dev\/(?:null|stderr))\b/g, "");
    stripped = stripped.replace(/[0-9]*>&[0-9]+/g, "");
    if (!stripped.trim()) return false;
  }

  let stripped = cmd;
  stripped = stripped.replace(/[0-9]*&?>+\s*(?:\/dev\/(?:null|stderr))\b/g, "");
  stripped = stripped.replace(/[0-9]*>&[0-9]+/g, "");
  if (/>+\s*\S/.test(stripped)) {
    const inTest = /\[\s.*\]/.test(stripped) || /test\s/.test(stripped);
    if (!inTest) return true;
  }
  return false;
}

// ── Obfuscation detection ──

function detectObfuscation(cmd: string): { detected: boolean; techniques: string[] } {
  const techniques: string[] = [];
  if (/\$\{!/.test(cmd) || /\$[A-Z_]+\s/.test(cmd)) {
    techniques.push("variable indirection");
  }
  if (/[a-z]"[a-z]/.test(cmd) || /[a-z]'[a-z]/.test(cmd)) {
    techniques.push("character concatenation");
  }
  if (/base64\s+[-d]/i.test(cmd) || /printf\s+.*\\x/i.test(cmd)) {
    techniques.push("encoding/decoding");
  }
  if (/xargs\s.*\brm\b/.test(cmd)) {
    techniques.push("indirect command via xargs");
  }
  if (/\b(alias|declare|typeset)\s+\w+=\s*(rm|sudo|curl|wget|ssh)\b/i.test(cmd)) {
    techniques.push("alias/function obfuscation");
  }
  return { detected: techniques.length > 0, techniques };
}

function isSegmentObfuscated(seg: string): boolean {
  // stripQuotedStrings is in segment-helpers but not exported — check inline
  return /__CMD_SUBST__/.test(seg) || detectObfuscation(seg).detected;
}

// ── Git ──

function isGitDangerous(segment: string): boolean {
  const args = segment.trim().split(/\s+/);
  if (args.length < 2) return false;
  const sub = args[1].toLowerCase();
  const subArgs = args.slice(2);

  if (sub === "rm") return true;
  if (sub === "clean" && subArgs.some(a => /-[fdx]/.test(a))) return true;
  if (sub === "reset" && subArgs.includes("--hard")) return true;
  if (sub === "push" && subArgs.some(a => a === "--force" || a === "--force-with-lease" || a === "-f")) return true;
  if (sub === "reflog" && subArgs.includes("expire")) return true;
  if (sub === "gc" && subArgs.some(a => a.startsWith("--prune"))) return true;
  return false;
}

// ── Wrapper commands ──

function skipWrapperArg(firstWord: string, arg: string): boolean {
  if (arg.startsWith("-")) return true;
  if (firstWord === "timeout" && /^\d+(\.\d+)?(?:[smhd])?$/.test(arg)) return true;
  if (firstWord === "nice" && /^\d+$/.test(arg)) return true;
  if (firstWord === "ionice" && /^\d+$/.test(arg)) return true;
  if (firstWord === "env" && /=/.test(arg) && !arg.startsWith("/")) return true;
  return false;
}

function isWrapperRunningWrite(segment: string): boolean {
  const args = segment.trim().split(/\s+/);
  const firstWord = args[0].toLowerCase();
  for (let i = 1; i < args.length; i++) {
    const arg = args[i];
    if (skipWrapperArg(firstWord, arg)) continue;
    const wrappedCmd = arg.toLowerCase();
    if (writeCapableCommands.has(wrappedCmd)) {
      const rest = args.slice(i + 1);
      if (wrappedCmd === "sed" && /-\bi(?:\.\S*)?(?:\s|$)|--in-place(?:\b|\s)/.test(segment)) return true;
      if (wrappedCmd === "perl" && /-\bi(?:\.\S*)?(?:\s|$)|-pi\b|-p.*-i\b/.test(segment)) return true;
      if (wrappedCmd === "rm" || wrappedCmd === "rmdir" || wrappedCmd === "unlink") return true;
      if (wrappedCmd === "mv" || wrappedCmd === "cp") return true;
      if (wrappedCmd === "chmod" || wrappedCmd === "chown") return true;
      if (wrappedCmd === "touch" || wrappedCmd === "mkdir") return true;
      if (wrappedCmd === "dd" || wrappedCmd === "truncate") return true;
      if (wrappedCmd === "patch" || wrappedCmd === "install") return true;
      if (["tar", "zip", "unzip", "gzip", "gunzip"].includes(wrappedCmd)) return true;
      if (["pip", "npm", "yarn", "cargo", "go", "uv"].includes(wrappedCmd)) return true;
      if (wrappedCmd === "tee" && /\btee\b.*\S/.test(segment)) return true;
    }
    break;
  }
  return false;
}

function isWrapperRunningRelativePath(segment: string): boolean {
  const args = segment.trim().split(/\s+/);
  const firstWord = args[0].toLowerCase();
  for (let i = 1; i < args.length; i++) {
    const arg = args[i];
    if (skipWrapperArg(firstWord, arg)) continue;
    if (isFirstTokenRelativePath(arg)) return true;
    break;
  }
  return false;
}

// ── find -exec ──

function isFindExecWrite(segment: string): boolean {
  const execMatch = segment.match(/-(?:exec|execdir)\b\s+(\S+)/);
  if (!execMatch) return false;

  const execCmd = execMatch[1].toLowerCase();
  if (SHELL_INTERPRETERS.has(execCmd)) return true;

  if (writeCapableCommands.has(execCmd)) {
    const afterExec = segment.slice(execMatch.index! + execMatch[0].length);
    if (execCmd === "sed" && /-\bi(?:\.\S*)?(?:\s|$)|--in-place(?:\b|\s)/.test(afterExec)) return true;
    if (execCmd === "perl" && /-\bi(?:\.\S*)?(?:\s|$)|-pi\b|-p.*-i\b/.test(afterExec)) return true;
    if (execCmd === "rm" || execCmd === "rmdir" || execCmd === "unlink") return true;
    if (execCmd === "mv" || execCmd === "cp") return true;
    if (execCmd === "chmod" || execCmd === "chown") return true;
    if (execCmd === "touch" || execCmd === "mkdir") return true;
    if (execCmd === "dd" || execCmd === "truncate") return true;
    if (execCmd === "patch" || execCmd === "install") return true;
    if (["tar", "zip", "unzip", "gzip", "gunzip"].includes(execCmd)) return true;
    if (["pip", "npm", "yarn", "cargo", "go", "uv"].includes(execCmd)) return true;
  }
  return false;
}

// ── Pipeline checks ──

function hasDangerousSedInPipeline(segment: string): boolean {
  return splitPipeline(segment).some(part => {
    const cmd = getFirstWord(part);
    return cmd === "sed" && dangerousSedFlags.test(part);
  });
}

function hasDangerousPerlInPipeline(segment: string): boolean {
  return splitPipeline(segment).some(part => {
    const cmd = getFirstWord(part);
    return cmd === "perl" && dangerousPerlFlags.test(part);
  });
}

function hasWrapperRunningWriteInPipeline(segment: string): boolean {
  return splitPipeline(segment).some(part => {
    const cmd = getFirstWord(part);
    return wrapperCommands.has(cmd) && isWrapperRunningWrite(part);
  });
}

function hasDangerousCommandInPipeline(segment: string): boolean {
  return splitPipeline(segment).some(part => {
    const cmd = getFirstWord(part);
    return dangerousCommandPatterns.some(({ pattern }) => pattern.test(cmd))
      || dangerousContextPatterns.some(({ pattern }) => pattern.test(part));
  });
}

// ── Safety check entry points ──

/**
 * Check if a segment is a simple allowed command.
 * Returns true only when the command is on the allowlist, has no subshells,
 * no dangerous flags, no write redirects, and no unsafe pipeline stages.
 */
export async function isSimpleAllowedCommand(seg: BashSegment, cwd: string): Promise<boolean> {
  const segment = seg.text;
  const trimmed = segment.trim();
  if (/^[0-9]*&?>+/.test(trimmed)) {
    return !hasWriteRedirect(segment);
  }

  if (isTrustedScriptCommand(segment, cwd)) return true;
  if (isFirstTokenRelativePath(segment)) return false;

  const firstWord = getFirstWord(segment);
  if (!allowedBashPatterns.some(p => p.test(firstWord))) return false;
  if (seg.hasSubshell) return false;
  if (firstWord === "find" && dangerousFindFlags.test(segment)) return false;
  if (firstWord === "find" && isFindExecWrite(segment)) return false;
  if (firstWord === "sed" && dangerousSedFlags.test(segment)) return false;
  if (firstWord === "perl" && dangerousPerlFlags.test(segment)) return false;
  if (hasDangerousSedInPipeline(segment)) return false;
  if (hasDangerousPerlInPipeline(segment)) return false;
  if (firstWord === "git" && isGitDangerous(segment)) return false;
  if (wrapperCommands.has(firstWord) && isWrapperRunningWrite(segment)) return false;
  if (wrapperCommands.has(firstWord) && isWrapperRunningRelativePath(segment)) return false;
  if (hasWrapperRunningWriteInPipeline(segment)) return false;
  if (hasWriteRedirect(segment)) return false;
  if (!await areAllPipelineStagesSimple(segment, cwd)) return false;
  return true;
}

/** Check that every stage in a pipeline is a simple allowed command. */
async function areAllPipelineStagesSimple(segment: string, cwd: string): Promise<boolean> {
  const stages = splitPipeline(segment);
  if (stages.length <= 1) return true;
  for (let i = 1; i < stages.length; i++) {
    const stage = stages[i];
    if (isFirstTokenRelativePath(stage)) return false;
    const stageCmd = getFirstWord(stage);
    if (!allowedBashPatterns.some(p => p.test(stageCmd))) return false;
    if (stageCmd === "find" && (dangerousFindFlags.test(stage) || isFindExecWrite(stage))) return false;
    if (stageCmd === "sed" && dangerousSedFlags.test(stage)) return false;
    if (stageCmd === "perl" && dangerousPerlFlags.test(stage)) return false;
    if (stageCmd === "git" && isGitDangerous(stage)) return false;
    if (wrapperCommands.has(stageCmd) && isWrapperRunningWrite(stage)) return false;
    if (hasWriteRedirect(stage)) return false;
    if (dangerousCommandPatterns.some(({ pattern }) => pattern.test(stageCmd))) return false;
    if (dangerousContextPatterns.some(({ pattern }) => pattern.test(stage))) return false;
  }
  return true;
}

/**
 * Check if a segment matches any unsafe pattern (subshell, obfuscation, dangerous flags, etc.).
 */
export async function isSegmentUnsafe(seg: BashSegment, cwd: string): Promise<boolean> {
  const segment = seg.text;
  const trimmed = segment.trim();
  if (/^[0-9]*&?>+/.test(trimmed) && !hasWriteRedirect(segment)) return false;

  const trusted = isTrustedScriptCommand(segment, cwd);
  const firstWord = getFirstWord(segment);
  const isLookupOrEcho = LOOKUP_COMMANDS.has(firstWord) || ECHO_COMMANDS.has(firstWord) || PROCESS_INSPECTION_COMMANDS.has(firstWord);

  return seg.hasSubshell
    || isSegmentObfuscated(segment)
    || (firstWord === "find" && dangerousFindFlags.test(segment))
    || (firstWord === "find" && isFindExecWrite(segment))
    || (firstWord === "sed" && dangerousSedFlags.test(segment))
    || (firstWord === "perl" && dangerousPerlFlags.test(segment))
    || hasDangerousSedInPipeline(segment)
    || hasDangerousPerlInPipeline(segment)
    || (firstWord === "git" && isGitDangerous(segment))
    || (wrapperCommands.has(firstWord) && isWrapperRunningWrite(segment))
    || hasWrapperRunningWriteInPipeline(segment)
    || hasWriteRedirect(segment)
    || (!trusted && !isLookupOrEcho && (
      dangerousCommandPatterns.some(({ pattern }) => pattern.test(firstWord))
      || dangerousContextPatterns.some(({ pattern }) => pattern.test(segment))
      || hasDangerousCommandInPipeline(segment)
    ));
}
