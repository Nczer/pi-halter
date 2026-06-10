import path from "node:path";
import {
  resolvePathReal,
  expandTilde,
  isInsideCwd,
  isInsideAutoAllowedDir,
  isAllowedReadPath,
  isAllowedWritePath,
  isProjectPiPath,
  isPathDenied,
  isPathWarned,
} from "../path-analysis";
import type { Store, AllowRules, FileRequest, Decision, FilePromptData } from "../decision-engine";

export function decideFile(req: FileRequest, store: Store): Decision {
  const resolved = resolvePathReal(expandTilde(req.filePath), req.cwd);

  // 1. User Rule Check (Priority 1)
  const type = req.toolName === "read" ? "read" : "write";
  const userActionRaw = store.getUserRuleAction(type, req.filePath);
  const userActionResolved = store.getUserRuleAction(type, resolved);
  const finalUserAction = userActionRaw || userActionResolved;

  if (finalUserAction === "deny") {
    return { kind: "block", reason: `Blocked by user rule: path matches a denied pattern for ${type}.` };
  }

  // Denied paths block everything — check before any auto-allow
  const deniedResult = isPathDenied(req.filePath, req.cwd);
  if (deniedResult.denied) {
    return { kind: "block", reason: `Blocked: '${deniedResult.matchedRule}' is a denied path (credentials/secrets)` };
  }

  if (finalUserAction === "allow") {
    return { kind: "auto-allow" };
  }

  // Warned paths — may contain credentials, prompt with warning
  const warnResult = isPathWarned(req.filePath, req.cwd);

  // Auto-allow checks
  if (isProjectPiPath(req.filePath, req.cwd)) return { kind: "auto-allow" };
  if (req.toolName === "read" && store.hasAllowedReadPath(resolved)) return { kind: "auto-allow" };
  if (req.toolName !== "read" && store.hasAllowedWritePath(resolved)) return { kind: "auto-allow" };

  const autoAllowedDirs = req.toolName === "read"
    ? store.listAllowedReadDirs()
    : store.listAllowedWriteDirs();

  if (!isInsideCwd(resolved, req.cwd) && isInsideAutoAllowedDir(resolved, autoAllowedDirs)) {
    return { kind: "auto-allow" };
  }
  if (req.toolName === "read" && isAllowedReadPath(resolved)) return { kind: "auto-allow" };
  if (req.toolName !== "read" && isAllowedWritePath(resolved)) return { kind: "auto-allow" };
  if (req.toolName === "read" && isInsideCwd(resolved, req.cwd) && !warnResult.warned) return { kind: "auto-allow" };
  const action = req.toolName.charAt(0).toUpperCase() + req.toolName.slice(1);
  const isWriteOp = req.toolName !== "read";

  // Detect symlink: compare parent of original path vs parent of resolved path
  const originalParent = path.dirname(expandTilde(req.filePath));
  const resolvedParent = path.dirname(resolved);
  const symlinkHint = originalParent !== resolvedParent
    ? `${originalParent} → ${resolvedParent}`
    : null;

  const promptData: FilePromptData = {
    type: "file",
    action,
    filePath: req.filePath,
    resolved,
    cwd: req.cwd,
    outsideDir: isInsideCwd(resolved, req.cwd) ? null : path.dirname(resolved),
    isWriteOp,
    deniedRule: deniedResult.matchedRule,
    warnedRule: warnResult.matchedRule,
    symlinkHint,
  };

  const allowRules: AllowRules = isInsideCwd(resolved, req.cwd)
    ? (isWriteOp ? { writePaths: [resolved] } : { readPaths: [resolved] })
    : (isWriteOp ? { writeDirs: [path.dirname(resolved)] } : { readDirs: [path.dirname(resolved)] });

  const allowFileRules = isInsideCwd(resolved, req.cwd)
    ? undefined
    : (isWriteOp ? { writePaths: [resolved] } : { readPaths: [resolved] });

  // Directory-level allow for inside-cwd files (broader than file-only)
  const allowBroaderRules = isInsideCwd(resolved, req.cwd)
    ? (isWriteOp ? { writeDirs: [path.dirname(resolved)] } : { readDirs: [path.dirname(resolved)] })
    : undefined;

  return { kind: "prompt", promptData, allowRules, allowFileRules, allowBroaderRules, includeBroaderOption: isInsideCwd(resolved, req.cwd) };
}
