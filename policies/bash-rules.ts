import { ABORT_REMEMBER_MS, isAllowedCommand, isSafeSubcommand, unconditionallySafeCommands } from "../config";
import { getFirstWord, stripQuotedStrings } from "../analysis/segment-helpers";
import { checkCommandForCredentialPaths, CREDENTIAL_SCAN_RE } from "../analysis/path-analysis";
import type { Store, BashRequest, Decision } from "../decision-engine";
import type { CommandAnalysis } from "../analysis/command-analysis";

export type BashRule = (req: BashRequest, store: Store, analysis?: CommandAnalysis) => Decision | Promise<Decision | null> | null;

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
 * Blocks commands that reference denied credential paths (.ssh, .gnupg, etc.).
 * Runs before FastAllowRule so even `cat .ssh/id_rsa` is blocked.
 */
export const CredentialDenyRule: BashRule = (req) => {
  const credCheck = checkCommandForCredentialPaths(req.command, req.cwd);
  if (credCheck.denied) {
    return {
      kind: "block",
      reason: `Blocked: '${credCheck.denied}' is a denied path (credentials/secrets)`,
    };
  }
  return null;
};

/**
 * Auto-allows trivial commands without needing full tree-sitter analysis.
 */
export const FastAllowRule: BashRule = (req) => {
  const COMPOUND_RE = /\$\(|`|&&|\|\||[|;&<>]/;
  // Strip quoted strings so operators inside arguments (e.g. echo "a|b", grep "=>") don't
  // falsely trigger the compound check. Unquoted $(...) is preserved as __CMD_SUBST__.
  // Without this, echo "hello > world" or grep "setTimeout(() =>" waste a tree-sitter parse.
  const stripped = stripQuotedStrings(req.command);
  if (COMPOUND_RE.test(stripped)) return null;

  // Credential check — don't auto-allow if the command references credential paths
  if (CREDENTIAL_SCAN_RE.test(req.command)) return null;

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

  // Zero segments + parse error means tree-sitter couldn't parse the command.
  // Never auto-allow — prompt so the user can inspect.
  // (Zero segments without parse error is valid: shell builtins like export/unset.)
  if (analysis.segments.length === 0 && analysis.hasParseError) return null;

  const outsidePaths = analysis.prompt.outsidePaths ?? [];
  const canAutoAllow = analysis.safety.canBeAutoAllowed && outsidePaths.length === 0 && !analysis.hasCredentialPath;

  if (analysis.safety.isSimple && canAutoAllow) {
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
    if (relPathIdxSet.has(segIdx)) return false;
    if (segIsSafeSubcommand[segIdx]) return true;
    return isAllowedCommand(sigFirstWords[segIdx]);
  };

  if (analysis.signatures.every((sig, i) => isSigApproved(sig, i)) && canAutoAllow) {
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
      credentialRule: analysis.credentialRule,
      needsCommandApproval: !analysis.safety.isSimple,
      needsPathApproval: prompt.needsPathApproval ?? false,
    },
  };
};
