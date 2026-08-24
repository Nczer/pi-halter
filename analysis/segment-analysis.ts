import path from "node:path";
import {
  isAllowedCommand,
  dangerousCommandPatterns,
  dangerousContextPatterns,
  isTrustedScriptCommand,
  wrapperCommands,
  SHELL_INTERPRETERS,
  SCRIPT_INTERPRETERS,
} from "../config";
import type { BashSegment } from "./bash-parser";
import { isFirstTokenRelativePath } from "./path-analysis";
import {
  containsCommandSubstitution,
  getFirstWord,
  getDelegatedCommand,
  splitPipeline,
  hasWriteRedirect,
  isGitDangerous,
  isWrapperRunningRelativePath,
  stripQuotedStrings,
} from "./segment-helpers";
import { detectObfuscation } from "./obfuscation";
import { ShellEvaluator } from "./evaluators/shell-evaluator";
import { SystemEvaluator } from "./evaluators/system-evaluator";
import { GitEvaluator } from "./evaluators/git-evaluator";
import { TmuxEvaluator } from "./evaluators/tmux-evaluator";
import { DiskEvaluator } from "./evaluators/disk-evaluator";
import { ToolEvaluator } from "./evaluators/tool-evaluator";
import type { RiskEvaluator, EvaluatorResult } from "./evaluators/types";

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

// ── Risk merge helper ──
//
// The "run evaluators → tag reasons → dedupe → merge severity" loop appears
// in four shapes in this file (core analysis, delegated command, pipeline
// stages, and the post-trust-clear re-merge). One accumulator + one merge
// keeps the severity ordering (high beats medium; first medium sticks) and
// the first-seen dedupe identical at every site.

interface DangerAccum {
  hasDanger: boolean;
  severity: "high" | "medium" | null;
  reasons: string[];
}

function newDangerAccum(): DangerAccum {
  return { hasDanger: false, severity: null, reasons: [] };
}

function capFirst(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

/** Add an already-tagged reason (dedupe, first-seen order). */
function addReason(acc: DangerAccum, tagged: string): void {
  if (!acc.reasons.includes(tagged)) acc.reasons.push(tagged);
}

/** Tag a raw evaluator reason as `[${prefix}${Cap(evName)}] reason`. */
const tagEvaluator =
  (evName: string, prefix = ""): ((reason: string) => string) =>
  (reason) => `[${prefix}${capFirst(evName)}] ${reason}`;

/**
 * Merge a risk source (a raw evaluator result, or a pre-tagged delegated
 * analysis) into the accumulator: danger is OR'd, severity max'd, reasons
 * tagged via `tag` and deduped.
 */
function mergeRisk(
  acc: DangerAccum,
  source: EvaluatorResult,
  tag: (reason: string) => string,
): void {
  if (source.hasDanger) acc.hasDanger = true;
  if (source.severity === "high" || (acc.severity === null && source.severity === "medium")) {
    acc.severity = source.severity;
  }
  for (const reason of source.reasons) addReason(acc, tag(reason));
}

/**
 * Wrapper-transparency evaluation. When a segment's first word delegates to
 * another command (`command -p sh …`, `timeout 5 curl …`, `xargs git …`), the
 * delegated command must pass the same checks a bare first word would: the
 * full evaluator pass (git/find/tmux/system flags…) plus the dangerous-command
 * patterns and the shell/script interpreter check. Wrapping must never grant
 * auto-allow powers the wrapped command lacks on its own.
 */
function analyzeDelegated(
  delegated: { cmd: string; tail: string },
  cwd: string,
  seg: BashSegment,
  cwdKnown = true,
): DangerAccum {
  const { cmd, tail } = delegated;
  const acc = newDangerAccum();

  const pseudoSeg: BashSegment = {
    text: tail,
    ops: seg.ops,
    hasSubshell: seg.hasSubshell,
    subshellTexts: seg.subshellTexts,
  };
  for (const ev of EVALUATORS) {
    const result = ev.evaluate(pseudoSeg, cwd, {
      firstWord: cmd,
      obfuscation: { detected: false, techniques: [] },
      gitDangerous: cmd === "git" ? isGitDangerous(tail) : false,
      cwdKnown,
    });
    mergeRisk(acc, result, tagEvaluator(ev.name));
  }

  // Dangerous command patterns against the delegated command name (a wrapper
  // running curl/ssh/rm … is as dangerous as the bare command).
  for (const { pattern, label } of dangerousCommandPatterns) {
    if (pattern.test(cmd)) {
      acc.hasDanger = true;
      if (!acc.severity) acc.severity = "medium";
      addReason(acc, `[Pattern] ${label}`);
    }
  }

  // Shell/script interpreters — arbitrary code execution.
  if (SHELL_INTERPRETERS.has(cmd) || SCRIPT_INTERPRETERS.has(cmd)) {
    acc.hasDanger = true;
    acc.severity = "high";
    addReason(acc, `[Pattern] ${cmd} (shell/script interpreter execution)`);
  }

  return acc;
}

// ── Unified segment analysis ──

/**
 * Analyze a single command segment. Produces safety booleans and risk assessment
 * in one pass. Replaces hasKnownDanger + isSimpleAllowedCommand + isSegmentUnsafe + analyzeSegmentRisk.
 *
 * cwdKnown=false when cwd is the unknown-base marker ("/"): evaluators must
 * not resolve relative tokens against it (a relative rm target would resolve
 * to "/x", a real system location that is not the runtime location).
 */
export async function analyzeSegment(seg: BashSegment, cwd: string, cwdKnown = true): Promise<SegmentAnalysis> {
  const segment = seg.text;
  const trimmed = segment.trim();
  const firstWord = getFirstWord(segment);

  // Cache expensive checks to avoid duplicates across evaluators and pipeline analysis
  const cachedObfuscation = detectObfuscation(segment);
  const cachedGitDangerous = firstWord === "git" ? isGitDangerous(segment) : false;

// Run evaluators with cached results
  const evaluatorResults = EVALUATORS.map(ev => ({ evaluator: ev.name, result: ev.evaluate(seg, cwd, { firstWord, obfuscation: cachedObfuscation, gitDangerous: cachedGitDangerous, cwdKnown }) }));

  // Merge evaluator results
  const acc = newDangerAccum();
  let allStagesSimple = true;
  // Track command keys already covered by evaluators to avoid duplicate pattern reasons
  const coveredKeys = new Set<string>();

  for (const { evaluator, result } of evaluatorResults) {
    mergeRisk(acc, result, tagEvaluator(evaluator));
    // Extract first word of reason as coverage key (e.g. "rm" from "rm -rf (recursive deletion)")
    // Split on space or forward slash so "curl/wget" → "curl" (matches pattern key extraction)
    for (const reason of result.reasons) {
      const key = reason.split(/[\s/]/)[0].toLowerCase();
      coveredKeys.add(key);
    }
  }

  // Wrapper transparency: if the first word delegates to another command
  // (command -p sh …, timeout 5 curl …, xargs git …), that command must pass
  // the same checks a bare first word would — evaluators, dangerous patterns,
  // and (in isSimple below) the static allowlist. Wrapping must never grant
  // powers the wrapped command lacks on its own.
  const delegated = getDelegatedCommand(segment);
  if (delegated) {
    // d.reasons are already tagged — pass through.
    mergeRisk(acc, analyzeDelegated(delegated, cwd, seg, cwdKnown), (r) => r);
  }

  // Pipeline analysis: route secondary stages through evaluators
  // (eliminates duplicate dangerousCommandPatterns/dangerousContextPatterns checks
  //  and checkStageDanger — evaluators handle all of these uniformly).
  //
  // Pipeline-stage danger is tracked in its OWN accumulators, separate from the
  // core (script/interpreter) danger. A trusted script covers only the
  // interpreter+script invocation — it does NOT cover other commands joined by
  // `|`. Keeping them apart lets the trust clear wipe the core "arbitrary code
  // execution" flag while leaving pipeline danger (e.g. `trusted.sh | bash`) intact.
  const pipeAcc = newDangerAccum();

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
        // Pipe-to-interpreter is a unique pipeline concern — not caught by evaluators.
        // hasDanger MUST be set: without it isUnsafe stays false and SafetyRule's
        // signature branch auto-allows on the FIRST segment's first word (echo/ls/…)
        // — `ls | bash /any/script` would run arbitrary scripts (see log 2026-08-24,
        // the aiu-update session: risk:high "pipe to a shell" yet auto-allowed).
        if (SHELL_INTERPRETERS.has(stageCmd)) {
          pipeAcc.hasDanger = true;
          addReason(pipeAcc, "[Pipeline] pipe to a shell (possible remote code execution)");
          pipeAcc.severity = "high";
        }
      }

      // Run evaluators on each pipeline stage — catches system/tool/git/tmux/shell danger
      // that evaluators handle for the primary segment but can't see in pipeline stages.
      // (Main segment analysis only examines the first command's firstWord, so rm/sed -i
      //  in stage 2+ would be invisible without this per-stage pass.)
      const pseudoSeg: BashSegment = { text: stage, ops: [], hasSubshell: false };
      for (const ev of EVALUATORS) {
        const result = ev.evaluate(pseudoSeg, cwd, { cwdKnown });
        if (result.hasDanger) allStagesSimple = false;
        mergeRisk(pipeAcc, result, tagEvaluator(ev.name, "Pipeline/"));
      }

      // Wrapper transparency for pipeline stages too (ls | xargs curl, find | timeout …).
      const stageDeleg = getDelegatedCommand(stage);
      if (stageDeleg) {
        if (!isAllowedCommand(stageDeleg.cmd)) allStagesSimple = false;
        const d = analyzeDelegated(stageDeleg, cwd, pseudoSeg, cwdKnown);
        if (d.hasDanger) allStagesSimple = false;
        // d.reasons are already tagged — prefix them with Pipeline/.
        mergeRisk(pipeAcc, d, (r) => r.replace(/^\[/, "[Pipeline/"));
      }
    }
  }

  // Obfuscation (use cached result) + quoted command-substitution safety net.
  // The __CMD_SUBST__ marker only exists AFTER stripQuotedStrings (the original
  // check ran it against the raw segment, where the marker can never appear —
  // dead code). The marker proves $(…)/backticks inside double quotes: when the
  // parser surfaced the subshell (seg.hasSubshell), ShellEvaluator already
  // judges the content (safe formatting like $(basename …) stays auto-allowable;
  // dangerous commands are flagged). When the parser did NOT surface it (e.g.
  // parse error), the marker is the backstop — opaque code must not run.
  const strippedSegment = stripQuotedStrings(segment);
  const isObfuscated =
    (containsCommandSubstitution(strippedSegment) && !seg.hasSubshell) ||
    cachedObfuscation.detected;
  if (cachedObfuscation.techniques.length > 0) {
    for (const tech of cachedObfuscation.techniques) {
      addReason(acc, `[Shell] ${tech}`);
    }
    acc.severity = "high";
  }

  // Regex-based safety net — single pass, results reused for isUnsafe
  const isLookupOrEcho = LOOKUP_COMMANDS.has(firstWord) || ECHO_COMMANDS.has(firstWord) || PROCESS_INSPECTION_COMMANDS.has(firstWord);
  // `python3 --version` / `node --help` / `uv --version`: sole argument is a
  // read-only flag — no -c, no script file, nothing executes. These commands
  // are NOT in the allowlist, so isSimple below must grant the exemption too.
  const versionOnlyRest = trimmed.split(/\s+/).slice(1);
  const isVersionOnlyInvocation = /^(?:python[\d.]*|node|uv)$/.test(firstWord)
    && versionOnlyRest.length === 1 && (versionOnlyRest[0] === "--version" || versionOnlyRest[0] === "--help");
  const isTrusted = isTrustedScriptCommand(segment, cwd);

  // Trusted scripts: evaluators flag python/node/uv etc., but the user has explicitly
  // opted into running from these paths via the trusted-scripts config.
  // Clear evaluator danger so the pattern safety net's `!isTrusted` alone governs.
  if (isTrusted) {
    acc.hasDanger = false;
    acc.severity = null;
    acc.reasons.length = 0;
  }

  // Re-merge pipeline-stage danger AFTER the trust clear. Script trust must not
  // extend to other commands joined by `|`, so `trusted.sh | bash` / `trusted.sh | rm -rf`
  // keep their danger and prompt even though the leading script is trusted.
  // (pipeAcc reasons are already tagged — pass through.)
  mergeRisk(acc, pipeAcc, (r) => r);

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
  if (!isTrusted && !isVersionOnlyInvocation && (!isLookupOrEcho || isCommandExec || isEchoWithSubshell)) {
    // Check firstWord against dangerousCommandPatterns (normal path)
    for (const { pattern, label } of dangerousCommandPatterns) {
      if (pattern.test(firstWord)) {
        matchedDangerousCommand = true;
        if (!acc.severity) acc.severity = "medium";
        const key = label.split(/\s|[\/]/)[0].toLowerCase();
        if (!coveredKeys.has(key)) addReason(acc, `[Pattern] ${label}`);
      }
    }
    // (The executed command of `command -p <cmd>` / `command <cmd>` is checked
    //  against these patterns in the wrapper-transparency pass above.)
    // Strip quoted strings before context-pattern matching to avoid matching
    // command names inside grep/echo arguments (e.g. `grep "curl | bash" file`
    // should not trigger the "curl/wget | interpreter" pattern). The existing
    // evaluators + pipeline analysis catch all real threats from $(…) content.
    const cleanedForContext = strippedSegment;
    for (const { pattern, label } of dangerousContextPatterns) {
      if (pattern.test(cleanedForContext)) {
        matchedDangerousContext = true;
        if (!acc.severity) acc.severity = "medium";
        const key = label.split(/\s/)[0].toLowerCase();
        if (!coveredKeys.has(key)) addReason(acc, `[Pattern] ${label}`);
      }
    }
  }

  // Derive booleans — merge evaluator danger with pattern-matched danger
  const hasDanger = acc.hasDanger || matchedDangerousCommand || matchedDangerousContext;
  const writeRedirect = hasWriteRedirect(segment);
  const isRedirectOnly = REDIRECT_ONLY_RE.test(trimmed);

  // isSimple: allowed command, no danger, no relative path, all pipeline stages simple
  let isSimple: boolean;
  if (isRedirectOnly) {
    isSimple = !writeRedirect;
  } else if (isTrusted) {
    // The interpreter+script invocation is trusted, but shell operators AROUND
    // it are separate side effects not covered by trust and still require review:
    //   • a pipe stage is another command (`q.sh | bash` → RCE via the output)
    //   • a write redirect writes the output to a file (`q.sh > ./pwned`)
    //   • command substitution in args runs before the script (`script.py "$(rm …)"`)
    isSimple = allStagesSimple && !writeRedirect && !seg.hasSubshell;
  } else if (isFirstTokenRelativePath(segment)) {
    isSimple = false;
  } else {
    isSimple = (isAllowedCommand(firstWord) || isVersionOnlyInvocation) && !hasDanger
      && !(delegated && !isAllowedCommand(delegated.cmd))
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

  return { isSimple, isUnsafe, hasDanger, risk: { severity: acc.severity, reasons: acc.reasons } };
}
