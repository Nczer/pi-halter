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
        if (dangerousCommandPatterns.some(({ pattern }) => pattern.test(stageCmd))) {
          aggregatedHasDanger = true;
        }
        if (dangerousContextPatterns.some(({ pattern }) => pattern.test(stage))) {
          aggregatedHasDanger = true;
        }
        continue;
      }

      let stageDangerous = false;

      // Shared danger checks (sed/perl, find/fd/rg, wrapper, write redirect)
      const stageDanger = checkStageDanger(stage);
      if (stageDanger.dangerous) {
        stageDangerous = true;
        for (const reason of stageDanger.reasons) {
          const tagged = `[Pipeline] ${reason}`;
          if (!aggregatedReasons.includes(tagged)) {
            aggregatedReasons.push(tagged);
          }
        }
        if (stageDanger.severity === "high" || (!aggregatedSeverity && stageDanger.severity === "medium")) {
          aggregatedSeverity = stageDanger.severity;
        }
      }

      // Pipeline-specific checks (git, tmux, dangerous patterns)
      if (stageCmd === "git" && isGitDangerous(stage)) stageDangerous = true;
      if (stageCmd === "tmux" && isTmuxDangerous(stage)) stageDangerous = true;
      if (dangerousCommandPatterns.some(({ pattern }) => pattern.test(stageCmd))) stageDangerous = true;
      if (dangerousContextPatterns.some(({ pattern }) => pattern.test(stage))) stageDangerous = true;

      if (stageDangerous) {
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
