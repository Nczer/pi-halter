import { ABORT_REMEMBER_MS, isAllowedCommand, isSafeSubcommand, unconditionallySafeCommands } from "../config";
import { getFirstWord } from "../analysis/segment-helpers";
import type { Store, BashRequest, Decision } from "../decision-engine";
import type { CommandAnalysis } from "../analysis/command-analysis";

export type BashRule = (req: BashRequest, store: Store, analysis?: CommandAnalysis) => Decision | Promise<Decision | null> | null;

/**
 * Blocks if a user rule explicitly denies this command.
 */
export const UserDenyRule: BashRule = (req, store) => {
  if (store.getUserRuleAction("bash", req.command) === "deny") {
    return {
      kind: "block",
      reason: `Blocked by user rule: command matches a denied pattern.`,
    };
  }
  return null;
};

/**
 * Blocks if the command was aborted recently (retry-loop prevention).
 */
export const RetryLoopRule: BashRule = (req, store) => {
  const lastAbort = store.getLastAbort(req.command);
  if (lastAbort && Date.now() - lastAbort < ABORT_REMEMBER_MS) {
    return {
      kind: "block",
      reason: "Blocked by bash-guard: command was already aborted recently.",
    };
  }
  return null;
};

/**
 * Auto-allows trivial commands without needing full tree-sitter analysis.
 */
export const FastAllowRule: BashRule = (req) => {
  const COMPOUND_RE = /\$\(|`|&&|\|\||[|;&<>]/;
  if (COMPOUND_RE.test(req.command)) return null;

  const tokens = req.command.trim().split(/\s+/);
  if (tokens.length < 1) return null;

  const bare = getFirstWord(req.command);
  if (!unconditionallySafeCommands.has(bare)) return null;

  for (let i = 1; i < tokens.length; i++) {
    const token = tokens[i];
    if (token.startsWith("/") || token.startsWith("~/") || token.startsWith("./") || token.startsWith("../")) {
      return null;
    }
  }

  return { kind: "auto-allow" };
};

/**
 * Core safety and auto-allow logic based on command analysis.
 */
export const SafetyRule: BashRule = (_req, store, analysis?: CommandAnalysis) => {
  if (!analysis) return null;

  const outsidePaths = analysis.prompt.outsidePaths ?? [];
  const canAutoAllow = analysis.safety.canBeAutoAllowed && outsidePaths.length === 0;

  if (analysis.segments.length > 0 && analysis.safety.isSimple && canAutoAllow) {
    return { kind: "auto-allow" };
  }

  // All segments are safe subcommands (stricter than allowed commands — excludes wrappers like timeout)
  const segIsSafeSubcommand = analysis.segments.map(seg => isSafeSubcommand(seg));
  if (segIsSafeSubcommand.every(Boolean) && canAutoAllow) {
    return { kind: "auto-allow" };
  }

  const relPathIdxSet = new Set(analysis.relativePathSegmentIndices);
  const sigFirstWords = analysis.signatures.map(getFirstWord);
  const isSigApproved = (sig: string, segIdx: number) => {
    if (store.hasAllowedBash(sig)) return true;
    if (store.hasAllowedBashPrefix(sig)) return true;
    if (store.getUserRuleAction("bash", sig) === "allow") return true;
    if (relPathIdxSet.has(segIdx)) return false;
    if (segIsSafeSubcommand[segIdx]) return true;
    return isAllowedCommand(sigFirstWords[segIdx]);
  };

  if (analysis.signatures.every((sig, i) => isSigApproved(sig, i)) && canAutoAllow) {
    return { kind: "auto-allow" };
  }

  if (analysis.signatures.every(sig => store.getUserRuleAction("bash", sig) === "allow")) {
    return { kind: "auto-allow" };
  }

  return null;
};

/**
 * Final fallback: generate the prompt.
 * Thin mapper — all derived data comes from CommandAnalysis.
 */
export const PromptFallbackRule: BashRule = (req, _store, analysis?: CommandAnalysis) => {
  if (!analysis) return null;

  const prompt = analysis.prompt;
  return {
    kind: "prompt",
    promptData: {
      type: "bash",
      command: req.command,
      cwd: req.cwd,
      outsideDirs: prompt.outsideDirs ?? [],
      segments: analysis.segments,
      signatures: prompt.promptSignatures,
      nonAllowedSegmentIndices: prompt.nonAllowlistedSegmentIndices,
      riskDangerous: analysis.risk.dangerous,
      riskSeverity: analysis.risk.severity,
      riskReasons: analysis.risk.reasons,
      hasUnsafePattern: analysis.safety.hasUnsafePattern,
      needsCommandApproval: !analysis.safety.isSimple,
      needsPathApproval: prompt.needsPathApproval ?? false,
    },
  };
};
