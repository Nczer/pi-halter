import path from "node:path";
import fs from "node:fs";
import {
  resolvePathReal,
  expandTilde,
  isInsideCwd,
  isAllowedReadPath,
  isAllowedWritePath,
  isProjectPiPathResolved,
  isPathDeniedResolved,
  isPathWarnedResolved,
} from "../analysis/path-analysis";
import type { Store, AllowRules, FileRequest, Decision, FilePromptData } from "../decision-engine";

export function decideFile(req: FileRequest, store: Store): Decision {
  const resolved = req.resolvedPath ?? resolvePathReal(expandTilde(req.filePath), req.cwd);

  // Denied paths block everything — credentials/secrets
  const deniedResult = isPathDeniedResolved(req.filePath, resolved);
  if (deniedResult.denied) {
    return { kind: "block", reason: `Blocked: '${deniedResult.matchedRule}' is a denied path (credentials/secrets)` };
  }

  // Warned paths — may contain credentials, prompt with warning
  const warnResult = isPathWarnedResolved(req.filePath, resolved);

  // Auto-allow checks
  if (isProjectPiPathResolved(resolved, req.cwd)) return { kind: "auto-allow" };
  if (req.toolName === "read" && store.hasAllowedReadPath(resolved)) return { kind: "auto-allow" };
  if (req.toolName === "read" && store.hasAllowedWritePath(resolved)) return { kind: "auto-allow" }; // write implies read
  if (req.toolName !== "read" && store.hasAllowedWritePath(resolved)) return { kind: "auto-allow" };

  // Session auto-allowed dirs (write dirs imply read) — checks membership directly, no Set copy
  if (req.toolName === "read") {
    if (store.isInsideAllowedDir(resolved, "read")) return { kind: "auto-allow" };
  } else {
    if (store.isInsideAllowedDir(resolved, "write")) return { kind: "auto-allow" };
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
  // Compare against the absolute lexical parent — path.dirname(expandTilde(...)) alone
  // is relative for relative inputs (".") and would mismatch resolvedDir on every
  // relative path, producing a bogus symlink hint.
  const originalParent = path.dirname(path.resolve(req.cwd, expandTilde(req.filePath)));
  const symlinkHint = originalParent !== resolvedDir
    ? `${originalParent} → ${resolvedDir}`
    : null;

  // Check if the target file already exists (informational for write prompts).
  // Skip for warned paths (.env, .aws, etc.) — no filesystem operations on credential paths.
  const exists = req.toolName === "write" && !warnResult.warned && fs.existsSync(resolved);

  const promptData: FilePromptData = {
    type: "file",
    action,
    filePath: req.filePath,
    resolved,
    cwd: req.cwd,
    outsideDir: insideCwd ? null : resolvedDir,
    isWriteOp,
    warnedRule: warnResult.matchedRule,
    symlinkHint,
    exists,
  };

  return { kind: "prompt", promptData };
}
