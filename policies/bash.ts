import path from "node:path";
import { promises as fs } from "node:fs";
import { ABORT_REMEMBER_MS, isAllowedCommand, isSafeSubcommand, PACKAGE_MANAGERS, unconditionallySafeCommands } from "../config";
import { analyzeCommand } from "../command-analysis";
import {
  getOutsideCwdPaths,
} from "../path-analysis";
import type { Store, AllowRules, BashRequest, Decision, BashPromptData } from "../decision-engine";

// ── Fast pre-check (avoids tree-sitter for trivial commands) ──

/**
 * Detect compound shell operators with a simple string scan.
 * Not perfect (doesn't handle quotes/escapes) — used only as a fast
 * reject filter. False positives fall through to full tree-sitter parse.
 */
const COMPOUND_RE = /\$\(|`|&&|\|\||[|;&<>]/;

/**
 * Fast pre-check: if the command is a single allowed command with no
 * compound operators and no path arguments, auto-allow before touching tree-sitter.
 * Returns true if we can short-circuit, false if full analysis is needed.
 *
 * Only safe for commands with no path arguments — any path could be outside cwd
 * and require approval. Relative paths (./foo, ../foo) also require path analysis.
 */
function fastAllow(command: string): boolean {
  // Quick reject: compound operators
  if (COMPOUND_RE.test(command)) return false;

  const tokens = command.trim().split(/\s+/);
  if (tokens.length < 1) return false;

  // Extract first word
  const firstWord = tokens[0].toLowerCase();
  // Strip path prefix if present (e.g. "./ls" → "ls")
  const bare = firstWord.replace(/^.*\//, "");

  if (!unconditionallySafeCommands.has(bare)) return false;

  // Reject if any argument looks like a path (could be outside cwd)
  for (let i = 1; i < tokens.length; i++) {
    const token = tokens[i];
    if (token.startsWith("/") || token.startsWith("~/") || token.startsWith("./") || token.startsWith("../")) {
      return false;
    }
  }

  return true;
}

export async function decideBash(req: BashRequest, store: Store): Promise<Decision> {
  // 1. User Rule Check (Priority 1) — deny only, applied to full command
  const userAction = store.getUserRuleAction("bash", req.command);
  if (userAction === "deny") {
    return {
      kind: "block",
      reason: `Blocked by user rule: command matches a denied pattern.`,
    };
  }
  // Note: user ALLOW is NOT checked against the full command here.
  // "ls *" must not match "ls x && rm -rf y" — allow rules are checked
  // per-segment (signature) below so each part of a compound command
  // must be individually approved.

  // Retry-loop prevention
  const lastAbort = store.getLastAbort(req.command);
  if (lastAbort && Date.now() - lastAbort < ABORT_REMEMBER_MS) {
    return {
      kind: "block",
      reason:
        "Blocked by bash-guard: command was already aborted recently. " +
        "Ask the user for a safer alternative; do not retry the same command.",
    };
  }

  // Fast pre-check: single allowed command, no compound operators → skip tree-sitter
  if (fastAllow(req.command)) {
    return { kind: "auto-allow" };
  }

  const analysis = await analyzeCommand(req.command, req.cwd);
  const outsidePaths = getOutsideCwdPaths(
    analysis.paths,
    req.cwd,
    store.listAllowedReadDirs(),
    store.listAllowedWriteDirs(),
  );

  // Auto-allow: all segments simple + no unsafe patterns + no unapproved outside paths + non-empty segments
  if (analysis.segments.length === 0 && req.command.trim().length > 0) {
    // Command exists but produced zero segments — parser couldn't extract commands (heredoc to interpreter, etc.)
  } else if (analysis.allSimple && !analysis.hasUnsafePattern && outsidePaths.length === 0) {
    return { kind: "auto-allow" };
  }

  // Auto-allow if all segments are safe subcommands (npm test, tsc, etc.)
  if (analysis.segments.every(seg => isSafeSubcommand(seg)) && !analysis.hasUnsafePattern && outsidePaths.length === 0) {
    return { kind: "auto-allow" };
  }

  // Auto-allow if all signatures are either previously approved or in the static allowlist
  const relPathIdxSet = new Set(analysis.relativePathSegmentIndices);
  const isSigApproved = (sig: string, segIdx: number) => {
    if (store.hasAllowedBash(sig)) return true;
    if (store.hasAllowedBashPrefix(sig)) return true;
    // User rule: getUserRuleAction handles trailing wildcard stripping
    if (store.getUserRuleAction("bash", sig) === "allow") return true;
    if (relPathIdxSet.has(segIdx)) return false;
    if (isSafeSubcommand(analysis.segments[segIdx])) return true;
    return isAllowedCommand(sig.split(/\s+/)[0]);
  };

  // User rules approved every segment — explicit user intent, bypass safety heuristics
  const allByUserRule = analysis.signatures.every(sig => store.getUserRuleAction("bash", sig) === "allow");
  if (allByUserRule) {
    return { kind: "auto-allow" };
  }

  if (analysis.signatures.every((sig, i) => isSigApproved(sig, i))) {
    if (!analysis.hasUnsafePattern && outsidePaths.length === 0) {
      return { kind: "auto-allow" };
    }
  }

  const outsideDirResults = await Promise.all(outsidePaths.map(async p => {
    try {
      const stat = await fs.stat(p);
      return stat.isDirectory() ? p : path.dirname(p);
    } catch {
      return path.dirname(p);
    }
  }));
  const outsideDirs = [...new Set(outsideDirResults)].sort();
  const needsCommandApproval = !analysis.allSimple;
  const needsPathApproval = outsidePaths.length > 0;

  const isRedirectOnly = (text: string) => /^[0-9]*&?>+/.test(text.trim());
  const nonAllowlistedSegmentIndices = analysis.signatures
    .map((sig, i) =>
      isRedirectOnly(analysis.segments[i])
        ? -1
        : isSafeSubcommand(analysis.segments[i])
        ? -1
        : isAllowedCommand(sig.split(/\s+/)[0]) ? -1 : i,
    )
    .filter(i => i >= 0);
  const nonAllowlistedSigs = nonAllowlistedSegmentIndices.map(i => analysis.signatures[i]);
  const uniqueSigs = [...new Set(nonAllowlistedSigs)];

  const allowRules: AllowRules = {};
  let allowBroaderRules: AllowRules | undefined;
  if (needsPathApproval) {
    allowRules.readDirs = outsideDirs;
  }
  if (needsCommandApproval && nonAllowlistedSigs.length > 0) {
    allowRules.bashSigs = nonAllowlistedSigs;
    const pmSigs = nonAllowlistedSigs.filter(sig => {
      const cmd = sig.split(" ")[0];
      return PACKAGE_MANAGERS.has(cmd);
    });
    const broaderSigs = pmSigs.length > 0
      ? [...new Set(pmSigs.map(sig => sig.split(" ")[0]))]
      : [];
    if (broaderSigs.some(s => !nonAllowlistedSigs.includes(s))) {
      allowBroaderRules = {
        bashSigs: broaderSigs,
        ...(needsPathApproval ? { readDirs: outsideDirs } : {}),
      };
    }
  }

  const hasBoth = needsCommandApproval && needsPathApproval;
  const allowPathsRules = hasBoth
    ? { readDirs: outsideDirs }
    : undefined;

  return {
    kind: "prompt",
    promptData: {
      type: "bash",
      command: req.command,
      cwd: req.cwd,
      outsideDirs,
      segments: analysis.segments,
      signatures: uniqueSigs,
      nonAllowedSegmentIndices: nonAllowlistedSegmentIndices,
      riskDangerous: analysis.risk.dangerous,
      riskSeverity: analysis.risk.severity,
      riskReasons: analysis.risk.reasons,
      hasUnsafePattern: analysis.hasUnsafePattern,
      needsCommandApproval,
      needsPathApproval,
    },
    allowRules,
    allowBroaderRules,
    allowPathsRules,
    includePathsOption: hasBoth,
    includeBroaderOption: !!allowBroaderRules,
  };
}
