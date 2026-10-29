import path from "node:path";
import os from "node:os";
import fs from "node:fs";
import { allowedReadPaths, allowedWritePaths, warnPaths, isTrustedScriptPath } from "../config";
import { under, isUnresolvedPath } from "./path-util";

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

/**
 * Memo for resolvePathReal, keyed by the fully resolved (absolute,
 * normalized) path. The real-path of an existing prefix is stable for the
 * process's lifetime — same staleness class as getHomePiDir/HOME_REAL —
 * and every analysis pass re-resolves the same project paths, so without
 * this the credential scan, symlink checks, and policy probes each pay
 * their own realpathSync walk-up. Bounded: a full map clears rather than
 * growing unbounded in long sessions (evicting everything keeps the cache
 * O(1) with no LRU bookkeeping; the survivors are re-resolved lazily).
 */
const realPathMemo = new Map<string, string>();
const REAL_PATH_MEMO_MAX = 8192;

export function resolvePathReal(inputPath: string, cwd: string): string {
  const resolved = path.resolve(cwd, inputPath);
  const memoized = realPathMemo.get(resolved);
  if (memoized !== undefined) return memoized;
  let found: string | null = null;
  try {
    found = fs.realpathSync(resolved);
  } catch {
    // Path doesn't exist — walk up to find the deepest existing parent,
    // resolve it (catches symlinks in parent directories), then re-append
    // the remaining components.
    let p = resolved;
    let suffix = "";
    while (p !== path.dirname(p) && found === null) {
      try {
        const real = fs.realpathSync(p);
        found = suffix ? path.join(real, suffix) : real;
      } catch {
        suffix = path.join(path.basename(p), suffix);
        p = path.dirname(p);
      }
    }
  }
  const result = found ?? resolved; // no existing parent (e.g. /tmp/new/sub/file) — as-is
  if (realPathMemo.size >= REAL_PATH_MEMO_MAX) realPathMemo.clear();
  realPathMemo.set(resolved, result);
  return result;
}

// ── Path containment checks ──
// The answer itself is `under` (analysis/path-util.ts) — one test, real-disk
// form on both sides. These wrappers only name the bar being asked about.

export function isAllowedReadPath(resolved: string): boolean {
  return allowedReadPaths.some(d => under(resolved, d));
}

export function isAllowedWritePath(resolved: string): boolean {
  return allowedWritePaths.some(d => under(resolved, d));
}

export function getOutsideCwdPaths(
  paths: string[],
  cwd: string,
  isInsideAllowedDir?: (p: string) => boolean,
): string[] {
  return paths.filter(p => {
    // A word that names no location is OUTSIDE by definition — dropping it here
    // is how an unbound path used to slip the bar (the sentinel sits outside
    // every real dir on purpose).
    if (isUnresolvedPath(p)) return true;
    if (under(p, cwd)) return false;
    if (isInsideAllowedDir?.(p)) return false;
    if (isAllowedReadPath(p)) return false;
    if (isAllowedWritePath(p)) return false;
    if (isTrustedScriptPath(p)) return false;
    return true;
  });
}

/**
 * The WRITE bar (G3). A write target may sit only in the working directory,
 * the config write dirs (temp dirs), or a location the user granted a WRITE
 * for this session — and nothing else. The read exemptions are deliberately
 * absent: `allowedReadPaths` (~/.pi — the agent's own skills and extensions)
 * and trusted script paths say something about READING, so reusing the read
 * predicate let `mkdir ~/.pi/agent/pwned-dir` auto-allow while the same verb
 * into any other home directory prompted.
 */
export function getOutsideWritePaths(
  paths: string[],
  cwd: string,
  isInsideAllowedWriteDir?: (p: string) => boolean,
): string[] {
  return paths.filter(p => {
    if (isUnresolvedPath(p)) return true; // an unnameable location is in no write bar
    if (under(p, cwd)) return false;
    if (isInsideAllowedWriteDir?.(p)) return false;
    if (isAllowedWritePath(p)) return false;
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
  return under(resolved, piDir) && !under(resolved, getHomePiDir());
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
      // Glob patterns (e.g. "*.pem") — suffix match on the basename.
      if (pattern.startsWith("*.") && nameToCheck.endsWith(pattern.slice(1))) {
        return pattern;
      }
    }
  }
  return null;
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
