import path from "node:path";
import {
  isAllowedCommand,
  dangerousCommandPatterns,
  dangerousContextPatterns,
  isTrustedScriptCommand,
  wrapperCommands,
  SHELL_INTERPRETERS,
} from "../config";
import type { BashSegment } from "./bash-parser";
import type { StageDanger } from "./segment-helpers";
import { isFirstTokenRelativePath } from "./path-analysis";
import {
  containsCommandSubstitution,
  getFirstWord,
  splitPipeline,
  hasWriteRedirect,
  checkStageDanger,
  isGitDangerous,
  isWrapperRunningRelativePath,
} from "./segment-helpers";
// StageDanger imported as type above
import { isTmuxDangerous } from "./tmux-helpers";
import { detectObfuscation } from "./obfuscation";
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

// ── Pipeline stage danger check ──

/** Check if a pipeline stage (after first) is dangerous. Combines shared + pipeline-specific checks. */
function checkPipelineStageDanger(stage: string, stageCmd: string): StageDanger {
  // Start with shared danger checks (sed/perl, find/fd/rg, wrapper, write redirect)
  const shared = checkStageDanger(stage);
  if (shared.dangerous) {
    // Git/tmux/pattern checks only set boolean, no extra reasons beyond shared
    return { ...shared, dangerous: true };
  }

  // Pipeline-specific checks (git, tmux, dangerous patterns)
  let dangerous = false;
  if (stageCmd === "git" && isGitDangerous(stage)) dangerous = true;
  if (stageCmd === "tmux" && isTmuxDangerous(stage)) dangerous = true;
  if (dangerousCommandPatterns.some(({ pattern }) => pattern.test(stageCmd))) dangerous = true;
  if (dangerousContextPatterns.some(({ pattern }) => pattern.test(stage))) dangerous = true;

  return { ...shared, dangerous };
}

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

const REDIRECT_ONLY_RE = /^[0-9]*&?>+/;
const PIPELINE_RELATIVE_RE1 = /^\.\//;
const PIPELINE_RELATIVE_RE2 = /^\.\.\//;

// ── Unified segment analysis ──

/**
 * Analyze a single command segment. Produces safety booleans and risk assessment
 * in one pass. Replaces hasKnownDanger + isSimpleAllowedCommand + isSegmentUnsafe + analyzeSegmentRisk.
 */
export async function analyzeSegment(seg: BashSegment, cwd: string): Promise<SegmentAnalysis> {
  const segment = seg.text;
  const trimmed = segment.trim();
  const firstWord = getFirstWord(segment);

  // Cache expensive checks to avoid duplicates across evaluators and pipeline analysis
  const cachedObfuscation = detectObfuscation(segment);
  const cachedGitDangerous = firstWord === "git" ? isGitDangerous(segment) : false;

// Run evaluators with cached results
  const evaluatorResults = EVALUATORS.map(ev => ({ evaluator: ev.name, result: ev.evaluate(seg, cwd, { firstWord, obfuscation: cachedObfuscation, gitDangerous: cachedGitDangerous }) }));

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
      // Extract first token once (avoids double split in getFirstWord + isFirstTokenRelativePath)
      const stageTokens = stage.trim().split(/\s+/);
      const stageFirst = stageTokens[0];
      const stageCmd = path.basename(stageFirst.toLowerCase());
      const isRelativeFirst = PIPELINE_RELATIVE_RE1.test(stageFirst) || PIPELINE_RELATIVE_RE2.test(stageFirst);

      if (isRelativeFirst) {
        allStagesSimple = false;
        continue;
      }

      if (!isAllowedCommand(stageCmd)) {
        allStagesSimple = false;
        if (SHELL_INTERPRETERS.has(stageCmd)) {
          const reason = "[Pipeline] pipe to a shell (possible remote code execution)";
          if (!aggregatedReasons.includes(reason)) {
            aggregatedReasons.push(reason);
            aggregatedSeverity = "high";
          }
        }
        for (const { pattern, label } of dangerousCommandPatterns) {
          if (pattern.test(stageCmd)) {
            aggregatedHasDanger = true;
            if (!aggregatedSeverity) aggregatedSeverity = "medium";
            const tagged = `[Pipeline] ${label}`;
            const key = label.split(/\s|[\/]/)[0].toLowerCase();
            if (!coveredKeys.has(key) && !aggregatedReasons.includes(tagged)) {
              aggregatedReasons.push(tagged);
            }
          }
        }
        for (const { pattern, label } of dangerousContextPatterns) {
          if (pattern.test(stage)) {
            aggregatedHasDanger = true;
            if (!aggregatedSeverity) aggregatedSeverity = "medium";
            const tagged = `[Pipeline] ${label}`;
            const key = label.split(/\s/)[0].toLowerCase();
            if (!coveredKeys.has(key) && !aggregatedReasons.includes(tagged)) {
              aggregatedReasons.push(tagged);
            }
          }
        }
        continue;
      }

      // Combined danger checks (shared + pipeline-specific)
      const stageDanger = checkPipelineStageDanger(stage, stageCmd);
      if (stageDanger.dangerous) {
        for (const reason of stageDanger.reasons) {
          const tagged = `[Pipeline] ${reason}`;
          if (!aggregatedReasons.includes(tagged)) {
            aggregatedReasons.push(tagged);
          }
        }
        if (stageDanger.severity === "high" || (!aggregatedSeverity && stageDanger.severity === "medium")) {
          aggregatedSeverity = stageDanger.severity;
        }
        allStagesSimple = false;
        aggregatedHasDanger = true;
      }
    }
  }

  // Obfuscation (use cached result)
  const isObfuscated = containsCommandSubstitution(segment) || cachedObfuscation.detected;
  if (cachedObfuscation.techniques.length > 0) {
    for (const tech of cachedObfuscation.techniques) {
      const tagged = `[Shell] ${tech}`;
      if (!aggregatedReasons.includes(tagged)) aggregatedReasons.push(tagged);
    }
    aggregatedSeverity = "high";
  }

  // Regex-based safety net — single pass, results reused for isUnsafe
  const isLookupOrEcho = LOOKUP_COMMANDS.has(firstWord) || ECHO_COMMANDS.has(firstWord) || PROCESS_INSPECTION_COMMANDS.has(firstWord);
  const isTrusted = isTrustedScriptCommand(segment, cwd);

  // `command` is in LOOKUP_COMMANDS, but only `-v`/`-V` are pure lookups.
  // `command -p rm` and `command rm` execute the command — must not skip pattern checks.
  const isCommandExec = firstWord === "command" && !(/\s-[vV](?:\s|$)/.test(segment));

  let matchedDangerousCommand = false;
  let matchedDangerousContext = false;
  if (!isTrusted && (!isLookupOrEcho || isCommandExec)) {
    // Check firstWord against dangerousCommandPatterns (normal path)
    for (const { pattern, label } of dangerousCommandPatterns) {
      const tagged = `[Pattern] ${label}`;
      if (pattern.test(firstWord)) {
        matchedDangerousCommand = true;
        if (!aggregatedSeverity) aggregatedSeverity = "medium";
        const key = label.split(/\s|[\/]/)[0].toLowerCase();
        if (!coveredKeys.has(key)) {
          if (!aggregatedReasons.includes(tagged)) {
            aggregatedReasons.push(tagged);
          }
        }
      }
    }
    // For `command -p <cmd>` or `command <cmd>`, also check the executed command
    if (isCommandExec) {
      const args = segment.trim().split(/\s+/);
      for (let i = 1; i < args.length; i++) {
        if (args[i].startsWith("-")) continue; // skip flags like -p
        const execCmd = getFirstWord(args[i]);
        for (const { pattern, label } of dangerousCommandPatterns) {
          const tagged = `[Pattern] ${label}`;
          if (pattern.test(execCmd)) {
            matchedDangerousCommand = true;
            if (!aggregatedSeverity) aggregatedSeverity = "medium";
            const key = label.split(/\s|[\/]/)[0].toLowerCase();
            if (!coveredKeys.has(key)) {
              if (!aggregatedReasons.includes(tagged)) {
                aggregatedReasons.push(tagged);
              }
            }
          }
        }
        break; // only check the first non-flag argument (the command)
      }
    }
    for (const { pattern, label } of dangerousContextPatterns) {
      const tagged = `[Pattern] ${label}`;
      if (pattern.test(segment)) {
        matchedDangerousContext = true;
        if (!aggregatedSeverity) aggregatedSeverity = "medium";
        const key = label.split(/\s/)[0].toLowerCase();
        if (!coveredKeys.has(key)) {
          if (!aggregatedReasons.includes(tagged)) {
            aggregatedReasons.push(tagged);
          }
        }
      }
    }
  }

  // Derive booleans — merge evaluator danger with pattern-matched danger
  const hasDanger = aggregatedHasDanger || matchedDangerousCommand || matchedDangerousContext;
  const writeRedirect = hasWriteRedirect(segment);
  const isRedirectOnly = REDIRECT_ONLY_RE.test(trimmed);

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
