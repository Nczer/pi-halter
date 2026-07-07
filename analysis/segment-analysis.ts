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
  isGitDangerous,
  isWrapperRunningRelativePath,
} from "./segment-helpers";
import { detectObfuscation } from "./obfuscation";
import { ShellEvaluator } from "./evaluators/shell-evaluator";
import { SystemEvaluator } from "./evaluators/system-evaluator";
import { GitEvaluator } from "./evaluators/git-evaluator";
import { TmuxEvaluator } from "./evaluators/tmux-evaluator";
import { DiskEvaluator } from "./evaluators/disk-evaluator";
import { ToolEvaluator } from "./evaluators/tool-evaluator";
import type { RiskEvaluator } from "./evaluators/types";

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
      // Split on space or forward slash so "curl/wget" → "curl" (matches pattern key extraction)
      const key = reason.split(/[\s/]/)[0].toLowerCase();
      coveredKeys.add(key);
    }
  }

  // Pipeline analysis: route secondary stages through evaluators
  // (eliminates duplicate dangerousCommandPatterns/dangerousContextPatterns checks
  //  and checkStageDanger — evaluators handle all of these uniformly)
  const stages = splitPipeline(segment);
  if (stages.length > 1) {
    for (let i = 1; i < stages.length; i++) {
      const stage = stages[i];
      const stageTokens = stage.trim().split(/\s+/);
      const stageFirst = stageTokens[0];
      const stageCmd = path.basename(stageFirst.toLowerCase());

      if (PIPELINE_RELATIVE_RE1.test(stageFirst) || PIPELINE_RELATIVE_RE2.test(stageFirst)) {
        allStagesSimple = false;
        continue;
      }

      if (!isAllowedCommand(stageCmd)) {
        allStagesSimple = false;
        // Pipe-to-interpreter is a unique pipeline concern — not caught by evaluators
        if (SHELL_INTERPRETERS.has(stageCmd)) {
          const reason = "[Pipeline] pipe to a shell (possible remote code execution)";
          if (!aggregatedReasons.includes(reason)) {
            aggregatedReasons.push(reason);
            aggregatedSeverity = "high";
          }
        }
      }

      // Run evaluators on each pipeline stage — catches system/tool/git/tmux/shell danger
      // that evaluators handle for the primary segment but can't see in pipeline stages.
      // (Main segment analysis only examines the first command's firstWord, so rm/sed -i
      //  in stage 2+ would be invisible without this per-stage pass.)
      const pseudoSeg: BashSegment = { text: stage, ops: [], hasSubshell: false };
      for (const ev of EVALUATORS) {
        const result = ev.evaluate(pseudoSeg, cwd);
        if (result.hasDanger) {
          aggregatedHasDanger = true;
          allStagesSimple = false;
        }
        if (result.severity === "high" || (!aggregatedSeverity && result.severity === "medium")) {
          aggregatedSeverity = result.severity;
        }
        for (const reason of result.reasons) {
          const tag = ev.name.charAt(0).toUpperCase() + ev.name.slice(1);
          const tagged = `[Pipeline/${tag}] ${reason}`;
          if (!aggregatedReasons.includes(tagged)) aggregatedReasons.push(tagged);
        }
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

  // Trusted scripts: evaluators flag python/node/uv etc., but the user has explicitly
  // opted into running from these paths via the trusted-scripts config.
  // Clear evaluator danger so the pattern safety net's `!isTrusted` alone governs.
  if (isTrusted) {
    aggregatedHasDanger = false;
    aggregatedSeverity = null;
    aggregatedReasons.length = 0;
  }

  // `command` is in LOOKUP_COMMANDS, but only `-v`/`-V` are pure lookups.
  // `command -p rm` and `command rm` execute the command — must not skip pattern checks.
  const isCommandExec = firstWord === "command" && !(/\s-[vV](?:\s|$)/.test(segment));
  // echo/printf/pgrep are normally inert (so their arguments aren't scanned), but a
  // command substitution (`$(...)` / backticks) inside one executes real code — once
  // the segment has a subshell, it's no longer inert and must go through the pattern scan
  // so RCE patterns like `curl | sh` inside `echo "$(curl |sh)"` are surfaced.
  const isEchoWithSubshell = ECHO_COMMANDS.has(firstWord) && seg.hasSubshell;

  let matchedDangerousCommand = false;
  let matchedDangerousContext = false;
  if (!isTrusted && (!isLookupOrEcho || isCommandExec || isEchoWithSubshell)) {
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
