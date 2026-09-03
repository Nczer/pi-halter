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
import type {Store, AllowRules, FileRequest, Decision, FilePromptData, DecideOptions} from "./types";

export function decideFile(req: FileRequest, store: Store, opts?: DecideOptions): Decision {
  const resolved = req.resolvedPath ?? resolvePathReal(expandTilde(req.filePath), req.cwd);

  // Denied paths block everything — credentials/secrets
  const deniedResult = isPathDeniedResolved(req.filePath, resolved);
  if (deniedResult.denied) {
    return { kind: "block", reason: `Blocked: '${deniedResult.matchedRule}' is a denied path (credentials/secrets)` };
  }

  // Warned paths — may contain credentials, prompt with warning
  const warnResult = isPathWarnedResolved(req.filePath, resolved);

  // Auto-allow checks. D3/D11 (docs/dspa-redesign.md): with
  // judgeWriteAutoAllows (dspa mode only) a WRITE auto-allow falls through
  // to the prompt decision instead — the location is trusted, the content is
  // judged in full (the gate's file branch lets every manual-bar write
  // through). Without the flag (manual/dspat), auto-allow, as before. Reads
  // are never judged — their fast paths are unaffected.
  const isWriteOp = req.toolName !== "read";
  const judged = isWriteOp && !!opts?.judgeWriteAutoAllows;
  if (!judged && isProjectPiPathResolved(resolved, req.cwd)) return { kind: "auto-allow" };
  if (!isWriteOp && store.hasAllowedReadPath(resolved)) return { kind: "auto-allow" };
  if (!isWriteOp && store.hasAllowedWritePath(resolved)) return { kind: "auto-allow" }; // write implies read
  if (!judged && store.hasAllowedWritePath(resolved)) return { kind: "auto-allow" };

  // Session auto-allowed dirs (write dirs imply read) — checks membership directly, no Set copy
  if (!isWriteOp) {
    if (store.isInsideAllowedDir(resolved, "read")) return { kind: "auto-allow" };
  } else if (!judged && store.isInsideAllowedDir(resolved, "write")) {
    return { kind: "auto-allow" };
  }

  // Static config paths
  if (!isWriteOp && isAllowedReadPath(resolved)) return { kind: "auto-allow" };
  if (!judged && isAllowedWritePath(resolved)) return { kind: "auto-allow" };

  // Read of a path that does not exist: nothing can be read (ENOENT) —
  // auto-allow in every mode instead of a prompt. Warned (credential-
  // pattern) paths keep prompting — no fs probes on credential paths.
  // TOCTOU (file appears between check and read) is the same millisecond
  // window the rm carve-out's fs.statSync already accepts.
  if (!isWriteOp && !warnResult.warned && !fs.existsSync(resolved)) {
    return { kind: "auto-allow" };
  }

  // Inside cwd (read only, unless warned)
  const insideCwd = isInsideCwd(resolved, req.cwd);
  if (!isWriteOp && insideCwd && !warnResult.warned) return { kind: "auto-allow" };
  const action = req.toolName.charAt(0).toUpperCase() + req.toolName.slice(1);

  // Pre-compute values reused multiple times
  const resolvedDir = path.dirname(resolved);
  // Compare against the absolute lexical parent — path.dirname(expandTilde(...)) alone
  // is relative for relative inputs (".") and would mismatch resolvedDir on every
  // relative path, producing a bogus symlink hint.
  const originalParent = path.dirname(path.resolve(req.cwd, expandTilde(req.filePath)));
  const symlinkHint = originalParent !== resolvedDir
    ? `${originalParent} → ${resolvedDir}`
    : null;

  // Whether the target file exists on disk (judge packet: "file exists:
  // yes/no"). ALL write ops — write and edit: a false "no" for an in-place
  // edit contradicts the session context (the file was just read) and made
  // the judge defer on safe edits. Skip for warned paths (.env, .aws, etc.)
  // — no filesystem operations on credential paths.
  const exists = isWriteOp && !warnResult.warned && fs.existsSync(resolved);

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
    content: req.toolName === "read" ? undefined : req.content,
  };

  return { kind: "prompt", promptData };
}
