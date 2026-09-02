import path from "node:path";
import os from "node:os";
import fs from "node:fs";
import { promises as fsPromises } from "node:fs";
import { allowedReadPaths, allowedWritePaths, deniedPaths, warnPaths, isTrustedScriptPath } from "../config";
import { expandTilde, OPAQUE_VAR_DIR } from "./path-util";
import { UNKNOWN_CWD_MARKER } from "./cwd-tracking";
export { expandTilde, OPAQUE_VAR_DIR }; // Re-export for existing importers

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

/** Check if child is inside (or equal to) parent. Uses prefix check for O(1) performance. */
export function isChildOf(child: string, parent: string): boolean {
  if (child === parent) return true;
  return child.startsWith(parent + "/");
}

export function isInsideCwd(resolved: string, cwd: string): boolean {
  return isChildOf(resolved, cwd);
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

export function isPathDeniedResolved(filePath: string, resolved: string): { denied: boolean; matchedRule: string | null } {
  const matched = checkPatternsResolved(filePath, resolved, deniedPaths);
  return { denied: matched !== null, matchedRule: matched };
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

// ── Path-to-directory resolution ──

/**
 * The grantable static prefix of an opaque token: the leading portion before
 * the first $/backtick, when it is absolute (or ~/) and pins to a real
 * directory. `~/.pi/x/$f` → the real `~/.pi/x`; `$f`, `./x/$f`,
 * `/?x/b/$f` → null (no static prefix, base-dependent, or glob-prefixed —
 * a glob prefix spans several dirs, none of which is provably the prefix).
 */
export function opaqueStaticPrefixDir(raw: string): string | null {
  let idx = raw.length;
  for (const c of ["$", "`"]) {
    const i = raw.indexOf(c);
    if (i !== -1 && i < idx) idx = i;
  }
  if (idx <= 0) return null;
  const prefix = raw.slice(0, idx).replace(/\/+$/, "");
  if (!prefix) return null;
  if (/[\\`*?\[\]$]/.test(prefix)) return null;
  if (/(^|\/)\.\.(\/|$)/.test(prefix)) return null;
  if (prefix === "~" || prefix.startsWith("~/")) {
    if (!/^~\/[A-Za-z0-9._/-]+$/.test(prefix)) return null;
    const t = expandTilde(prefix);
    return path.isAbsolute(t) ? resolvePathReal(t, os.homedir()) : null;
  }
  if (!prefix.startsWith("/")) return null; // relative — base-dependent
  return resolvePathReal(prefix, os.homedir());
}

/**
 * Resolve a list of paths to their containing directories.
 * For directories, returns the path as-is. For files (or non-existent paths),
 * returns the parent directory.
 */
export async function resolvePathsToDirs(paths: string[]): Promise<string[]> {
  if (!paths.length) return [];
  const results = await Promise.all(paths.map(async p => {
    // Unknown-cwd marker paths don't exist on disk — stat fails and
    // path.dirname would degrade them to `.` (or the literal prefix). Keep
    // the marker so the prompt reads `outside <unresolved-cwd>`.
    if (p.includes(UNKNOWN_CWD_MARKER)) return UNKNOWN_CWD_MARKER;
    // Unbound opaque reference: show the static prefix the token provably
    // pins (real dir), or the bare sentinel when it pins nothing.
    if (p.startsWith(OPAQUE_VAR_DIR + "/")) {
      return opaqueStaticPrefixDir(p.slice(OPAQUE_VAR_DIR.length + 1)) ?? OPAQUE_VAR_DIR;
    }
    try {
      const stat = await fsPromises.stat(p);
      return stat.isDirectory() ? p : path.dirname(p);
    } catch {
      return path.dirname(p);
    }
  }));
  return [...new Set(results)].sort();
}
