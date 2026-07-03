import path from "node:path";
import {
  resolvePathReal,
  expandTilde,
  isInsideCwd,
  isInsideAutoAllowedDir,
  isAllowedReadPath,
  isAllowedWritePath,
  isProjectPiPathResolved,
  isPathDeniedResolved,
  isPathWarnedResolved,
} from "../analysis/path-analysis";
import type { Store, AllowRules, FileRequest, Decision, FilePromptData } from "../decision-engine";

export function decideFile(req: FileRequest, store: Store): Decision {
  const resolved = req.resolvedPath ?? resolvePathReal(expandTilde(req.filePath), req.cwd);

  // 1. User Rule Check (Priority 1)
  const type = req.toolName === "read" ? "read" : "write";
  const userActionRaw = store.getUserRuleAction(type, req.filePath);
  const userActionResolved = store.getUserRuleAction(type, resolved);
  const finalUserAction = userActionRaw || userActionResolved;

  if (finalUserAction === "deny") {
    return { kind: "block", reason: `Blocked by user rule: path matches a denied pattern for ${type}.` };
  }

  // Denied paths block everything — check before any auto-allow
  const deniedResult = isPathDeniedResolved(req.filePath, resolved);
  if (deniedResult.denied) {
    return { kind: "block", reason: `Blocked: '${deniedResult.matchedRule}' is a denied path (credentials/secrets)` };
  }

  if (finalUserAction === "allow") {
    return { kind: "auto-allow" };
  }

  // Warned paths — may contain credentials, prompt with warning
  const warnResult = isPathWarnedResolved(req.filePath, resolved);

  // Auto-allow checks
  if (isProjectPiPathResolved(resolved, req.cwd)) return { kind: "auto-allow" };
  if (req.toolName === "read" && store.hasAllowedReadPath(resolved)) return { kind: "auto-allow" };
  if (req.toolName === "read" && store.hasAllowedWritePath(resolved)) return { kind: "auto-allow" }; // write implies read
  if (req.toolName !== "read" && store.hasAllowedWritePath(resolved)) return { kind: "auto-allow" };

  // Session auto-allowed dirs (write dirs imply read)
  // Cache to avoid redundant Set copies from listAllowed*()
  const allowedReadDirs = store.listAllowedReadDirs();
  const allowedWriteDirs = store.listAllowedWriteDirs();
  if (req.toolName === "read") {
    if (isInsideAutoAllowedDir(resolved, allowedReadDirs)) return { kind: "auto-allow" };
    if (isInsideAutoAllowedDir(resolved, allowedWriteDirs)) return { kind: "auto-allow" };
  } else {
    if (isInsideAutoAllowedDir(resolved, allowedWriteDirs)) return { kind: "auto-allow" };
  }

  // Static config paths
  if (req.toolName === "read" && isAllowedReadPath(resolved)) return { kind: "auto-allow" };
  if (req.toolName !== "read" && isAllowedWritePath(resolved)) return { kind: "auto-allow" };

  // Inside cwd (read only, unless warned)
  const insideCwd = isInsideCwd(resolved, req.cwd);
  if (req.toolName === "read" && insideCwd && !warnResult.warned) return { kind: "auto-allow" };
  const action = req.toolName.charAt(0).toUpperCase() + req.toolName.slice(1);
  const isWriteOp = req.toolName !== "read";

  // Pre-compute values reused multiple times
  const resolvedDir = path.dirname(resolved);
  const originalParent = path.dirname(expandTilde(req.filePath));
  const symlinkHint = originalParent !== resolvedDir
    ? `${originalParent} → ${resolvedDir}`
    : null;

  const promptData: FilePromptData = {
    type: "file",
    action,
    filePath: req.filePath,
    resolved,
    cwd: req.cwd,
    outsideDir: insideCwd ? null : resolvedDir,
    isWriteOp,
    deniedRule: deniedResult.matchedRule,
    warnedRule: warnResult.matchedRule,
    symlinkHint,
  };

  return { kind: "prompt", promptData };
}
