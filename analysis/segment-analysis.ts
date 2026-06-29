import {
  isAllowedCommand,
  dangerousFindFlags,
  dangerousPerlFlags,
  dangerousSedFlags,
  dangerousCommandPatterns,
  dangerousContextPatterns,
  isTrustedScriptCommand,
  wrapperCommands,
  isWriteOperation,
} from "../config";
import type { BashSegment } from "./bash-parser";
import { isFirstTokenRelativePath } from "./path-analysis";
import {
  containsCommandSubstitution,
  getFirstWord,
  splitPipeline,
  hasWriteRedirect,
  isWrapperRunningWrite,
  skipWrapperArg,
  isFindExecWrite,
  isFdExecWrite,
  isRgPreWrite,
} from "./segment-helpers";
import { isTmuxDangerous } from "./tmux-helpers";
import { ShellEvaluator } from "./evaluators/shell-evaluator";
import { SystemEvaluator } from "./evaluators/system-evaluator";
import { GitEvaluator } from "./evaluators/git-evaluator";
import { TmuxEvaluator } from "./evaluators/tmux-evaluator";
import { DiskEvaluator } from "./evaluators/disk-evaluator";
import { ToolEvaluator } from "./evaluators/tool-evaluator";
import type { EvaluatorResult, RiskEvaluator } from "./evaluators/types";

// ── Constants ──

const LOOKUP_COMMANDS = new Set(["which", "type", "command", "hash", "whence"]);
const ECHO_COMMANDS = new Set(["echo", "printf", "true", "false"]);
const PROCESS_INSPECTION_COMMANDS = new Set(["pgrep", "pidof"]);
const EVALUATORS: RiskEvaluator[] = [
  ShellEvaluator,
  SystemEvaluator,
  GitEvaluator,
  TmuxEvaluator,
  DiskEvaluator,
  ToolEvaluator,
];

// ── Result type ──

/** Risk assessment for a single segment. */
export interface SegmentRisk {
  severity: "high" | "medium" | null;
  reasons: string[];
}

/**
 * Unified analysis of a single command segment.
 * Combines safety checks (simple/unsafe/danger) with risk assessment (reasons/severity).
 * One call replaces hasKnownDanger + isSimpleAllowedCommand + isSegmentUnsafe + analyzeSegmentRisk.
 */
export interface SegmentAnalysis {
  /** Command is a simple allowed command (allowlist, no subshells, no dangerous flags). */
  isSimple: boolean;
  /** Segment matches any unsafe pattern (danger flags, obfuscation, dangerous commands). */
  isUnsafe: boolean;
  /** Segment has known danger patterns (cached result of hasKnownDanger). */
  hasDanger: boolean;
  /** Risk assessment with human-readable reasons and severity. */
  risk: SegmentRisk;
}

// ── Pattern checks (shared by danger detection and risk reasons) ──

export function detectObfuscation(cmd: string): { detected: boolean; techniques: string[] } {
  const techniques: string[] = [];
  if (/\$\{!/.test(cmd)) techniques.push("variable indirection");
  if (/(?:^|;|\|\||&&)\s*\$[A-Z_][A-Z0-9_]*\s+\w/.test(cmd)) techniques.push("variable holding command");
  if (/[a-z]"[a-z]/.test(cmd) || /[a-z]'[a-z]/.test(cmd)) techniques.push("character concatenation");
  if (/base64\s+[-d]/i.test(cmd) || /printf\s+.*\\x/i.test(cmd)) techniques.push("encoding/decoding");
  if (/xargs\s.*\brm\b/.test(cmd)) techniques.push("indirect command via xargs");
  if (/xargs\s+sh\s+-c\b/.test(cmd) || /xargs\s+bash\s+-c\b/.test(cmd)) techniques.push("xargs piping to shell interpreter");
  if (/\b(alias|declare|typeset)\s+\w+=\s*(rm|sudo|curl|wget|ssh)\b/i.test(cmd)) techniques.push("alias/function obfuscation");
  return { detected: techniques.length > 0, techniques };
}

function hasFlag(args: string[], flag: string): boolean {
  return args.includes(flag) || args.some((a) => a.startsWith(flag + "=") || a.startsWith(flag + "."));
}

function anyArgStartsWith(args: string[], prefix: string): boolean {
  return args.some((a) => a.startsWith(prefix));
}

// ── Git ──

export function isGitDangerous(segment: string): boolean {
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

// ── Unified segment analysis ──

/**
 * Analyze a single command segment. Produces safety booleans and risk assessment
 * in one pass. Replaces hasKnownDanger + isSimpleAllowedCommand + isSegmentUnsafe + analyzeSegmentRisk.
 */
export async function analyzeSegment(seg: BashSegment, cwd: string): Promise<SegmentAnalysis> {
  const segment = seg.text;
  const trimmed = segment.trim();
  const firstWord = getFirstWord(segment);
  const args = trimmed.split(/\s+/);
  const rest = args.slice(1);
  const ops = seg.ops;

  // Run evaluators
  const evaluatorResults = EVALUATORS.map(ev => ({ evaluator: ev.name, result: ev.evaluate(seg, cwd) }));

  // Merge evaluator results
  const aggregatedReasons: string[] = [];
  let aggregatedSeverity: "high" | "medium" | null = null;
  let aggregatedHasDanger = false;
  let allStagesSimple = true;
  // Track command keys already covered by evaluators to avoid duplicate pattern reasons
  const coveredKeys = new Set<string>();

  for (const { evaluator, result } of evaluatorResults) {
    if (result.hasDanger) aggregatedHasDanger = true;
    if (result.severity === "high" || (!aggregatedSeverity && result.severity === "medium")) {
      aggregatedSeverity = result.severity;
    }
    for (const reason of result.reasons) {
      const tag = evaluator.charAt(0).toUpperCase() + evaluator.slice(1);
      const tagged = `[${tag}] ${reason}`;
      if (!aggregatedReasons.includes(tagged)) aggregatedReasons.push(tagged);
      // Extract first word of reason as coverage key (e.g. "rm" from "rm -rf (recursive deletion)")
      const key = reason.split(/\s/)[0].toLowerCase();
      coveredKeys.add(key);
    }
    if (result.isSimple === false) allStagesSimple = false;
  }

  // Pipeline analysis
  const stages = splitPipeline(segment);
  if (stages.length > 1) {
    for (let i = 1; i < stages.length; i++) {
      const stage = stages[i];
      const stageCmd = getFirstWord(stage);

      if (isFirstTokenRelativePath(stage)) {
        allStagesSimple = false;
        continue;
      }

      if (!isAllowedCommand(stageCmd)) {
        allStagesSimple = false;
        if (new Set(["sh", "bash", "zsh", "fish"]).has(stageCmd)) {
          const reason = "[Pipeline] pipe to a shell (possible remote code execution)";
          if (!aggregatedReasons.includes(reason)) {
            aggregatedReasons.push(reason);
            aggregatedSeverity = "high";
          }
        }
        if (dangerousCommandPatterns.some(({ pattern }) => pattern.test(stageCmd))) {
          aggregatedHasDanger = true;
        }
        if (dangerousContextPatterns.some(({ pattern }) => pattern.test(stage))) {
          aggregatedHasDanger = true;
        }
        continue;
      }

      let stageDangerous = false;
      if (stageCmd === "find" && (dangerousFindFlags.test(stage) || isFindExecWrite(stage))) stageDangerous = true;
      if (stageCmd === "fd" && isFdExecWrite(stage)) stageDangerous = true;
      if (stageCmd === "rg" && isRgPreWrite(stage)) stageDangerous = true;
      if (stageCmd === "sed" && dangerousSedFlags.test(stage)) {
        stageDangerous = true;
        const reason = "[Pipeline] sed -i in pipeline (in-place file modification)";
        if (!aggregatedReasons.includes(reason)) {
          aggregatedReasons.push(reason);
          aggregatedSeverity = "high";
        }
      }
      if (stageCmd === "perl" && dangerousPerlFlags.test(stage)) {
        stageDangerous = true;
        const reason = "[Pipeline] perl -pi/-i in pipeline (in-place file modification)";
        if (!aggregatedReasons.includes(reason)) {
          aggregatedReasons.push(reason);
          aggregatedSeverity = "high";
        }
      }
      if (stageCmd === "git" && isGitDangerous(stage)) stageDangerous = true;
      if (stageCmd === "tmux" && isTmuxDangerous(stage)) stageDangerous = true;
      if (wrapperCommands.has(stageCmd) && isWrapperRunningWrite(stage)) stageDangerous = true;
      if (hasWriteRedirect(stage)) stageDangerous = true;
      if (dangerousCommandPatterns.some(({ pattern }) => pattern.test(stageCmd))) stageDangerous = true;
      if (dangerousContextPatterns.some(({ pattern }) => pattern.test(stage))) stageDangerous = true;

      if (stageDangerous) {
        allStagesSimple = false;
        aggregatedHasDanger = true;
      }
    }
  }

  // Obfuscation
  const obfuscation = detectObfuscation(segment);
  const isObfuscated = containsCommandSubstitution(segment) || obfuscation.detected;
  if (obfuscation.techniques.length > 0) {
    for (const tech of obfuscation.techniques) {
      const tagged = `[Shell] ${tech}`;
      if (!aggregatedReasons.includes(tagged)) aggregatedReasons.push(tagged);
    }
    aggregatedSeverity = "high";
  }

  // Regex-based safety net — single pass, results reused for isUnsafe
  const isLookupOrEcho = LOOKUP_COMMANDS.has(firstWord) || ECHO_COMMANDS.has(firstWord) || PROCESS_INSPECTION_COMMANDS.has(firstWord);
  const isTrusted = isTrustedScriptCommand(segment, cwd);

  let matchedDangerousCommand = false;
  let matchedDangerousContext = false;
  if (!isTrusted && !isLookupOrEcho) {
    for (const { pattern, label } of dangerousCommandPatterns) {
      const tagged = `[Pattern] ${label}`;
      if (pattern.test(firstWord)) {
        matchedDangerousCommand = true;
        if (!aggregatedSeverity) aggregatedSeverity = "medium";
        // Only add reason if not already covered by an evaluator
        const key = label.split(/\s|[\/]/)[0].toLowerCase();
        if (!coveredKeys.has(key)) {
          if (!aggregatedReasons.includes(tagged)) {
            aggregatedReasons.push(tagged);
          }
        }
      }
    }
    for (const { pattern, label } of dangerousContextPatterns) {
      const tagged = `[Pattern] ${label}`;
      if (pattern.test(segment)) {
        matchedDangerousContext = true;
        if (!aggregatedSeverity) aggregatedSeverity = "medium";
        // Only add reason if not already covered by an evaluator
        const key = label.split(/\s/)[0].toLowerCase();
        if (!coveredKeys.has(key)) {
          if (!aggregatedReasons.includes(tagged)) {
            aggregatedReasons.push(tagged);
          }
        }
      }
    }
  }

  // Derive booleans
  const hasDanger = aggregatedHasDanger;
  const writeRedirect = hasWriteRedirect(segment);
  const isRedirectOnly = /^[0-9]*&?>+/.test(trimmed);

  // isSimple: allowed command, no danger, no relative path, all pipeline stages simple
  let isSimple: boolean;
  if (isRedirectOnly) {
    isSimple = !writeRedirect;
  } else if (isTrusted) {
    isSimple = true;
  } else if (isFirstTokenRelativePath(segment)) {
    isSimple = false;
  } else {
    isSimple = isAllowedCommand(firstWord) && !hasDanger
      && !(wrapperCommands.has(firstWord) && isWrapperRunningRelativePath(segment))
      && allStagesSimple;
  }

  // isUnsafe: danger flag, obfuscation, or dangerous command/context patterns
  let isUnsafe: boolean;
  if (isRedirectOnly && !writeRedirect) {
    isUnsafe = false;
  } else {
    isUnsafe = hasDanger || isObfuscated || matchedDangerousCommand || matchedDangerousContext;
  }

  return { isSimple, isUnsafe, hasDanger, risk: { severity: aggregatedSeverity, reasons: aggregatedReasons } };
}
