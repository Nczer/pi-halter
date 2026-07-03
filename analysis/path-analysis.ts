import path from "node:path";
import os from "node:os";
import fs from "node:fs";
import { promises as fsPromises } from "node:fs";
import { allowedReadPaths, allowedWritePaths, deniedPaths, warnPaths, isTrustedScriptPath } from "../config";
import { expandTilde } from "./path-util";
import { tokenizeSegment } from "./tokenizer";
export { expandTilde }; // Re-export for existing importers

// ── Relative path detection ──

/** Pre-compiled regex for relative path detection (./foo, ../foo). */
const RELATIVE_PATH_RE = /^\.\/|^\.\.\//;
/** Pre-compiled regex for .env.* pattern detection. */
const ENV_FILE_RE = /^\.env\.[^/]*$/;

/**
 * Check if the first token is a relative path (./foo, ../foo).
 * Absolute paths (/bin/cat, /usr/bin/find) are allowed through.
 */
export function isFirstTokenRelativePath(segment: string): boolean {
  const token = segment.trim().split(/\s+/)[0];
  return RELATIVE_PATH_RE.test(token);
}

/**
 * Check if a segment string contains any relative path token (./foo, ../foo).
 * Covers both the first token and arguments.
 */
export function hasRelativePath(segment: string): boolean {
  const tokens = segment.trim().split(/\s+/);
  for (const token of tokens) {
    if (RELATIVE_PATH_RE.test(token)) return true;
  }
  return false;
}

// ── Path resolution ──

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

/** Check if child is inside (or equal to) parent. Uses prefix check for O(1) performance. */
function isChildOf(child: string, parent: string): boolean {
  if (child === parent) return true;
  return child.startsWith(parent + "/");
}

export function isInsideCwd(resolved: string, cwd: string): boolean {
  return isChildOf(resolved, cwd);
}

export function isInsideAutoAllowedDir(resolved: string, dirs: Set<string>): boolean {
  if (dirs.has(resolved)) return true;
  for (const d of dirs) {
    if (isChildOf(resolved, d)) return true;
  }
  return false;
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
  isInsideAllowedDir?: (p: string) => boolean,
): string[] {
  return paths.filter(p => {
    if (isInsideCwd(p, cwd)) return false;
    if (isInsideAllowedDir?.(p)) return false;
    if (isAllowedReadPath(p)) return false;
    if (isAllowedWritePath(p)) return false;
    if (isTrustedScriptPath(p)) return false;
    return true;
  });
}

// ── Policy checks ──

/** Cached realpath of `~/.pi` — constant for the session. The input is absolute, so
 *  `path.resolve` ignores its base; resolving against homedir is equivalent to the previous
 *  `resolvePathReal(path.join(os.homedir(), ".pi"), cwd)` but cwd-independent. */
let cachedHomePiDir: string | null = null;
function getHomePiDir(): string {
  if (cachedHomePiDir !== null) return cachedHomePiDir;
  cachedHomePiDir = resolvePathReal(path.join(os.homedir(), ".pi"), os.homedir());
  return cachedHomePiDir;
}

/** Per-cwd cache for resolvePathReal(".pi", cwd) — avoids 2-3 realpathSync per file decision. */
const projectPiDirCache = new Map<string, string>();

/**
 * Check if a pre-resolved path is inside the project's `.pi` dir (but not `~/.pi`).
 * Accepts the already-resolved real path to avoid redundant `realpathSync` calls on the hot path.
 */
export function isProjectPiPathResolved(resolved: string, cwd: string): boolean {
  let piDir = projectPiDirCache.get(cwd);
  if (piDir === undefined) {
    piDir = resolvePathReal(".pi", cwd);
    projectPiDirCache.set(cwd, piDir);
  }
  return isChildOf(resolved, piDir) && !isChildOf(resolved, getHomePiDir());
}

export function isProjectPiPath(filePath: string, cwd: string): boolean {
  const resolved = resolvePathReal(expandTilde(filePath), cwd);
  return isProjectPiPathResolved(resolved, cwd);
}

/** Check a pre-resolved path against denied/warned patterns. Returns matched pattern or null. */
function checkPatternsResolved(filePath: string, resolved: string, patterns: string[]): string | null {
  const names = [path.basename(filePath), path.basename(resolved)];

  for (const nameToCheck of names) {
    for (const pattern of patterns) {
      if (nameToCheck === pattern) return pattern;
      if (resolved.includes(`/${pattern}/`) || resolved.endsWith(`/${pattern}`)) {
        return pattern;
      }
    }
  }
  return null;
}

export function isPathDeniedResolved(filePath: string, resolved: string): { denied: boolean; matchedRule: string | null } {
  const matched = checkPatternsResolved(filePath, resolved, deniedPaths);
  return { denied: matched !== null, matchedRule: matched };
}

export function isPathDenied(filePath: string, cwd: string): { denied: boolean; matchedRule: string | null } {
  const resolved = resolvePathReal(expandTilde(filePath), cwd);
  return isPathDeniedResolved(filePath, resolved);
}

export function isPathWarnedResolved(filePath: string, resolved: string): { warned: boolean; matchedRule: string | null } {
  const matched = checkPatternsResolved(filePath, resolved, warnPaths);
  if (matched) return { warned: true, matchedRule: matched };

  // .env.* pattern (e.g. .env.production, .env.development)
  const names = [path.basename(filePath), path.basename(resolved)];
  for (const nameToCheck of names) {
    if (ENV_FILE_RE.test(nameToCheck)) {
      return { warned: true, matchedRule: ".env.*" };
    }
  }
  return { warned: false, matchedRule: null };
}

export function isPathWarned(filePath: string, cwd: string): { warned: boolean; matchedRule: string | null } {
  const resolved = resolvePathReal(expandTilde(filePath), cwd);
  return isPathWarnedResolved(filePath, resolved);
}

// ── Credential path detection for bash commands ──

/**
 * Pre-compiled regex for fast credential pattern detection in bash commands.
 * Loose match — false positives just trigger the more expensive resolve+check.
 * Matches credential file/dir name roots: .ssh, .env, .aws, .docker/config.json, etc.
 */
export const CREDENTIAL_SCAN_RE = /\.(?:ssh|gnupg|gpg|vault|secret|secrets|env|aws|gcloud|azure|git-credentials|hg|netrc|npmrc|pypirc|docker)\b/;

/**
 * Check a bash command string for credential path references.
 * Returns the first denied and/or warned pattern found.
 * Uses a fast regex pre-scan to skip the common case (no credential patterns).
 */
export function checkCommandForCredentialPaths(
  command: string,
  cwd: string,
): { denied: string | null; warned: string | null } {
  // Fast pre-scan: if no credential pattern appears in the command, skip entirely
  if (!CREDENTIAL_SCAN_RE.test(command)) {
    return { denied: null, warned: null };
  }

  // Quote-aware tokenization (strips quotes so '.env' is detected as .env)
  const tokens = tokenizeSegment(command);
  let denied: string | null = null;
  let warned: string | null = null;

  // Valid env-var name pattern: starts with letter/underscore, only alphanumeric/underscore.
  // Flags like `--output=path` have a leading dash, so they won't match.
  // Valid env-var name pattern: starts with letter/underscore, only alphanumeric/underscore.
  const ENV_VAR_NAME_RE = /^[a-zA-Z_][a-zA-Z0-9_]*$/;

  /** Check a path string against denied/warned patterns, returning the matched rule. */
  const checkPath = (pathStr: string): { denied: string | null; warned: string | null } => {
    const resolved = resolvePathReal(expandTilde(pathStr), cwd);
    const deniedResult = isPathDeniedResolved(pathStr, resolved);
    if (deniedResult.denied) return { denied: deniedResult.matchedRule, warned: null };
    const warnedResult = isPathWarnedResolved(pathStr, resolved);
    return { denied: null, warned: warnedResult.matchedRule };
  };

  for (const token of tokens) {
    if (!token) continue;

    // Handle --flag=value syntax: extract value after = and check it as a path.
    // Handles cases like docker --env-file=.env, cat --config=~/.aws/config, etc.
    if (token.startsWith("-") || token.startsWith("--")) {
      const eqIdx = token.indexOf("=");
      if (eqIdx > 0 && eqIdx < token.length - 1) {
        const value = token.slice(eqIdx + 1);
        if (value) {
          const result = checkPath(value);
          if (result.denied) return { denied: result.denied, warned };
          if (result.warned && !warned) warned = result.warned;
        }
      }
      continue;
    }

    // Skip actual env assignments (FOO=bar, FOO=/path) — the part before = is a
    // valid environment variable name (no leading dash).
    const eqIdx = token.indexOf("=");
    if (eqIdx !== -1) {
      const beforeEquals = token.slice(0, eqIdx);
      if (ENV_VAR_NAME_RE.test(beforeEquals)) continue;
    }

    const result = checkPath(token);
    if (result.denied) return { denied: result.denied, warned };
    if (result.warned && !warned) warned = result.warned;
  }

  return { denied, warned };
}

// ── Path-to-directory resolution ──

/**
 * Resolve a list of paths to their containing directories.
 * For directories, returns the path as-is. For files (or non-existent paths),
 * returns the parent directory.
 */
export async function resolvePathsToDirs(paths: string[]): Promise<string[]> {
  if (!paths.length) return [];
  const results = await Promise.all(paths.map(async p => {
    try {
      const stat = await fsPromises.stat(p);
      return stat.isDirectory() ? p : path.dirname(p);
    } catch {
      return path.dirname(p);
    }
  }));
  return [...new Set(results)].sort();
}
