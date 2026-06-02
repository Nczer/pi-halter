import path from "node:path";
import os from "node:os";
import fs from "node:fs";
import { allowedReadPaths, allowedWritePaths, deniedPaths, warnPaths, isTrustedScriptPath } from "./config";

// ── Relative path detection ──

/**
 * Check if the first token is a relative path (./foo, ../foo).
 * Absolute paths (/bin/cat, /usr/bin/find) are allowed through.
 */
export function isFirstTokenRelativePath(segment: string): boolean {
  const token = segment.trim().split(/\s+/)[0];
  return /^\.\/|^\.\./.test(token);
}

/**
 * Check if a segment string contains any relative path token (./foo, ../foo).
 * Covers both the first token and arguments.
 */
export function hasRelativePath(segment: string): boolean {
  const tokens = segment.trim().split(/\s+/);
  for (const token of tokens) {
    if (/^\.\/|^\.\./.test(token)) return true;
  }
  return false;
}

// ── Path resolution ──

export function expandTilde(p: string): string {
  if (p.startsWith("~/")) return path.join(os.homedir(), p.slice(2));
  if (p === "~") return os.homedir();
  return p;
}

export function resolvePathReal(inputPath: string, cwd: string): string {
  const resolved = path.resolve(cwd, inputPath);
  try {
    return fs.realpathSync(resolved);
  } catch {
    // Path doesn't exist — walk up to find the deepest existing parent,
    // resolve it (catches symlinks in parent directories), then re-append
    // the remaining components.
    let p = resolved;
    let suffix = "";
    while (p !== path.dirname(p)) {
      try {
        const real = fs.realpathSync(p);
        const result = suffix ? path.join(real, suffix) : real;
        return result;
      } catch {
        suffix = path.join(path.basename(p), suffix) || path.basename(p);
        p = path.dirname(p);
      }
    }
    // No existing parent found (e.g. /tmp/new/sub/file) — return as-is
    return resolved;
  }
}

// ── Path containment checks ──

/** Check if child is inside (or equal to) parent, using path.relative for correctness. */
function isChildOf(child: string, parent: string): boolean {
  if (child === parent) return true;
  const rel = path.relative(parent, child);
  return rel !== "" && !rel.startsWith("..") && !path.isAbsolute(rel);
}

export function isInsideCwd(resolved: string, cwd: string): boolean {
  return isChildOf(resolved, cwd);
}

export function isInsideAutoAllowedDir(resolved: string, dirs: Set<string>): boolean {
  return dirs.has(resolved) || [...dirs].some(d => isChildOf(resolved, d));
}

export function isAllowedReadPath(resolved: string): boolean {
  return allowedReadPaths.some(d => isChildOf(resolved, d));
}

export function isAllowedWritePath(resolved: string): boolean {
  return allowedWritePaths.some(d => isChildOf(resolved, d));
}

export function getOutsideCwdPaths(
  paths: string[],
  cwd: string,
  autoAllowedReadDirs: Set<string>,
  autoAllowedWriteDirs: Set<string>,
): string[] {
  return paths.filter(p => {
    if (isInsideCwd(p, cwd)) return false;
    if (isInsideAutoAllowedDir(p, autoAllowedReadDirs)) return false;
    if (isInsideAutoAllowedDir(p, autoAllowedWriteDirs)) return false;
    if (isAllowedReadPath(p)) return false;
    if (isAllowedWritePath(p)) return false;
    if (isTrustedScriptPath(p)) return false;
    return true;
  });
}

// ── Policy checks ──

export function isProjectPiPath(filePath: string, cwd: string): boolean {
  const resolved = resolvePathReal(expandTilde(filePath), cwd);
  const piDir = resolvePathReal(".pi", cwd);
  const homePiDir = resolvePathReal(path.join(os.homedir(), ".pi"), cwd);
  return isChildOf(resolved, piDir) && !isChildOf(resolved, homePiDir);
}

export function isPathDenied(filePath: string, cwd: string): { denied: boolean; matchedRule: string | null } {
  const resolved = resolvePathReal(expandTilde(filePath), cwd);
  const basename = path.basename(filePath);
  const resolvedBasename = path.basename(resolved);
  const basenamesToCheck = new Set([basename, resolvedBasename]);

  for (const nameToCheck of basenamesToCheck) {
    for (const denied of deniedPaths) {
      if (nameToCheck === denied) return { denied: true, matchedRule: denied };
      if (resolved.includes(`/${denied}/`) || resolved.endsWith(`/${denied}`)) {
        return { denied: true, matchedRule: denied };
      }
    }
  }
  return { denied: false, matchedRule: null };
}

export function isPathWarned(filePath: string, cwd: string): { warned: boolean; matchedRule: string | null } {
  const resolved = resolvePathReal(expandTilde(filePath), cwd);
  const basename = path.basename(filePath);
  const resolvedBasename = path.basename(resolved);
  const basenamesToCheck = new Set([basename, resolvedBasename]);

  for (const nameToCheck of basenamesToCheck) {
    for (const warn of warnPaths) {
      if (nameToCheck === warn) return { warned: true, matchedRule: warn };
      if (resolved.includes(`/${warn}/`) || resolved.endsWith(`/${warn}`)) {
        return { warned: true, matchedRule: warn };
      }
    }
    // .env.* pattern (e.g. .env.production, .env.development)
    if (/^\.env\.[^/]*$/.test(nameToCheck)) {
      return { warned: true, matchedRule: ".env.*" };
    }
  }
  return { warned: false, matchedRule: null };
}
