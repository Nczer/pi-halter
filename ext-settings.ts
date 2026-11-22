/**
 * ext-settings.ts — one owner for the two files every extension reads and
 * writes underneath pi:
 *
 *  • `settings-ext.json` — the one shared settings file for all extensions
 *    (pi owns settings.json; extensions never write into it). Each extension
 *    owns one top-level namespace in it.
 *  • pi's `settings.json` — read-only here: the global file in the agent
 *    directory, overridden per key by the project's `.pi/settings.json`.
 *
 * Semantics for `settings-ext.json`:
 *  • The namespace object is merged per key over the passed defaults; nested
 *    plain objects merge recursively, so a partial object in the file never
 *    clobbers the other defaults.
 *  • Defaults are materialized: keys missing from the file are written back on
 *    first read, so every option is visible and editable in the file.
 *  • A corrupt file (bad JSON, or a top level that is not an object) is copied
 *    to `<file>.bak` and the defaults apply — the operator's settings are
 *    preserved, never silently discarded. When that copy fails, nothing is
 *    written over the file: `patchExtSettings` reports it (`throwOnCorruptUnbacked`).
 *  • Writes go through a sibling temp file + rename (name carries pid +
 *    sequence), so a crash or a second extension cannot leave or rename over a
 *    half-written file.
 *  • Reads are cached on `(path, mtimeMs, size)`: a hot path pays one
 *    `statSync`, and under a TTL not even that.
 *
 * `filePath` is a test seam (defaults to the production path).
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

/**
 * Pi's agent directory: `PI_CODING_AGENT_DIR` when set (a leading `~` expanded,
 * like pi's own getAgentDir), else `~/.pi/agent`. Reading settings, a metadata
 * store or auth.json under a hardcoded HOME silently misses all of them when
 * the agent directory is relocated. Resolved per call, so a test that stubs
 * `HOME` or `PI_CODING_AGENT_DIR` is respected without a module reload.
 */
export function agentDir(): string {
  const env = process.env.PI_CODING_AGENT_DIR;
  if (env) {
    if (env === "~") return os.homedir();
    if (env.startsWith("~/") || env.startsWith("~\\")) {
      return path.join(os.homedir(), env.slice(2));
    }
    return env;
  }
  return path.join(os.homedir(), ".pi", "agent");
}

/** Production settings-ext.json path, resolved on every call. */
export function settingsExtPath(): string {
  return path.join(agentDir(), "settings-ext.json");
}

/** Import-time snapshot, for callers that want a constant path. */
export const SETTINGS_PATH = settingsExtPath();

/** Sequence for temp names, so two writers never share a temp file. */
let atomicSeq = 0;

/**
 * Write via temp file + rename so a crash cannot leave half-written JSON. The
 * temp name carries pid + sequence: concurrent callers (or a retry after a
 * failure) would otherwise rename over each other's half-written temp.
 */
export function atomicWrite(filePath: string, content: string): void {
  const dir = path.dirname(filePath);
  const tmp = path.join(
    dir,
    `.${path.basename(filePath)}.${process.pid}.${++atomicSeq}.tmp`,
  );
  try {
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(tmp, content, "utf8");
    fs.renameSync(tmp, filePath);
  } catch (err) {
    try {
      fs.unlinkSync(tmp);
    } catch {
      /* the temp file never made it that far */
    }
    throw err;
  }
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Recursive per-key merge: the file's values win, keys it never names keep their default. */
export function mergeSettings(
  defaults: Record<string, unknown>,
  file: Record<string, unknown>,
): Record<string, unknown> {
  const out: Record<string, unknown> = { ...file };
  for (const [k, d] of Object.entries(defaults)) {
    const f = file[k];
    out[k] =
      isPlainObject(d) && isPlainObject(f)
        ? mergeSettings(d, f)
        : f === undefined
          ? d
          : f;
  }
  return out;
}

// ── settings-ext.json: cached read, atomic whole-file write ────────────────

interface ExtCacheEntry {
  mtimeMs: number;
  size: number;
  data: Record<string, unknown>;
  /** The file is unreadable AND the `.bak` copy failed: writing over it would
   *  destroy the operator's only copy, so no writer runs until it is fixed. */
  corruptUnbacked: boolean;
}

const extCache = new Map<string, ExtCacheEntry>();

/** Test seam: drop every cached read of both settings files. */
export function resetSettingsCache(): void {
  extCache.clear();
  piSettingsCache.clear();
}

/** Returns false when the backup itself failed — the caller then withholds the write. */
function backupCorrupt(filePath: string): boolean {
  try {
    fs.copyFileSync(filePath, filePath + ".bak");
    return true;
  } catch {
    return false;
  }
}

function readWholeCached(filePath: string): {
  data: Record<string, unknown>;
  corruptUnbacked: boolean;
} {
  let mtimeMs: number;
  let size: number;
  try {
    const st = fs.statSync(filePath);
    mtimeMs = st.mtimeMs;
    size = st.size;
  } catch {
    // No file is a normal state — an empty namespace, nothing to back up.
    extCache.delete(filePath);
    return { data: {}, corruptUnbacked: false };
  }

  const hit = extCache.get(filePath);
  if (hit && hit.mtimeMs === mtimeMs && hit.size === size) {
    return { data: hit.data, corruptUnbacked: hit.corruptUnbacked };
  }

  let data: Record<string, unknown> = {};
  let corruptUnbacked = false;
  try {
    const parsed: unknown = JSON.parse(fs.readFileSync(filePath, "utf8"));
    if (isPlainObject(parsed)) data = parsed;
    else corruptUnbacked = !backupCorrupt(filePath);
  } catch {
    corruptUnbacked = !backupCorrupt(filePath);
  }

  extCache.set(filePath, { mtimeMs, size, data, corruptUnbacked });
  return { data, corruptUnbacked };
}

function writeWhole(filePath: string, file: Record<string, unknown>): void {
  atomicWrite(filePath, JSON.stringify(file, null, 2) + "\n");
  try {
    const st = fs.statSync(filePath);
    extCache.set(filePath, {
      mtimeMs: st.mtimeMs,
      size: st.size,
      data: file,
      corruptUnbacked: false,
    });
  } catch {
    extCache.delete(filePath);
  }
}

/**
 * This extension's namespace merged over its defaults, with missing keys
 * materialized back into the file so the whole surface is editable there.
 */
export function loadExtSettings<T extends object>(
  namespace: string,
  defaults: T,
  filePath: string = settingsExtPath(),
): T {
  const { data: file, corruptUnbacked } = readWholeCached(filePath);
  const raw = file[namespace];
  const mine = mergeSettings(
    defaults as Record<string, unknown>,
    isPlainObject(raw) ? raw : {},
  ) as T;

  if (!corruptUnbacked && JSON.stringify(raw) !== JSON.stringify(mine)) {
    try {
      writeWhole(filePath, { ...file, [namespace]: mine });
    } catch {
      /* the file is read-only or owned elsewhere: the in-memory values still apply */
    }
  }
  return mine;
}

/**
 * Merge a patch into this extension's namespace; other namespaces are preserved.
 * An undefined value deletes the key. Writes are skipped when the resolved
 * namespace already says this.
 */
export function patchExtSettings(
  namespace: string,
  patch: Record<string, unknown>,
  filePath: string = settingsExtPath(),
  opts?: {
    /** Throw instead of returning the in-memory merge when the file is corrupt
     *  and unbackable — a settings command should say so out loud. */
    throwOnCorruptUnbacked?: boolean;
    /** Merge the stored namespace over these defaults before applying the patch,
     *  so a partial file never answers for a key the caller never named. */
    defaults?: Record<string, unknown>;
  },
): Record<string, unknown> {
  const { data: file, corruptUnbacked } = readWholeCached(filePath);
  const raw = isPlainObject(file[namespace]) ? (file[namespace] as Record<string, unknown>) : {};
  const base = opts?.defaults ? mergeSettings(opts.defaults, raw) : { ...raw };
  const mine: Record<string, unknown> = { ...base };
  for (const [k, v] of Object.entries(patch)) {
    if (v === undefined) delete mine[k];
    else mine[k] = v;
  }

  if (corruptUnbacked) {
    if (opts?.throwOnCorruptUnbacked) {
      throw new Error(
        `${namespace}: ${filePath} is not valid JSON and could not be copied to ${filePath}.bak — fix or delete it by hand; not overwriting it.`,
      );
    }
    return mine;
  }

  if (JSON.stringify(mine) === JSON.stringify(raw)) return mine;
  try {
    writeWhole(filePath, { ...file, [namespace]: mine });
  } catch (err) {
    if (opts?.throwOnCorruptUnbacked) throw err;
  }
  return mine;
}

// ── pi's settings.json: read-only, cached, project overrides global per key ─

export interface PiCompactionSettings {
  reserveTokens: number;
  enabled: boolean;
  keepRecentTokens: number;
}

/** pi's own defaults (coding-agent settings): the answer when no file names the key. */
export const PI_COMPACTION_DEFAULTS: PiCompactionSettings = {
  reserveTokens: 16_384,
  enabled: true,
  keepRecentTokens: 20_000,
};

interface PiSettingsCacheEntry {
  checkedAt: number;
  mtimeMs: number;
  size: number;
  value: Record<string, unknown> | null;
}

const piSettingsCache = new Map<string, PiSettingsCacheEntry>();

/**
 * Read a JSON settings file, cached on (mtime, size) with a TTL and a negative
 * entry for a missing or unreadable file: a footer frame that runs ten times a
 * second pays neither the stat nor the ENOENT error stack.
 */
export function readPiSettingsJson(
  filePath: string,
  ttlMs = 1500,
): Record<string, unknown> | null {
  const now = Date.now();
  const hit = piSettingsCache.get(filePath);
  if (hit && ttlMs > 0 && now - hit.checkedAt < ttlMs) return hit.value;

  let mtimeMs: number;
  let size: number;
  try {
    const st = fs.statSync(filePath);
    mtimeMs = st.mtimeMs;
    size = st.size;
  } catch {
    piSettingsCache.set(filePath, { checkedAt: now, mtimeMs: -1, size: -1, value: null });
    return null;
  }

  if (hit && hit.mtimeMs === mtimeMs && hit.size === size) {
    hit.checkedAt = now; // within TTL from now on, without another stat
    return hit.value;
  }

  let value: Record<string, unknown> | null = null;
  try {
    const parsed: unknown = JSON.parse(fs.readFileSync(filePath, "utf8"));
    if (isPlainObject(parsed)) value = parsed;
  } catch {
    /* an unreadable settings file answers with the defaults, not an error */
  }
  piSettingsCache.set(filePath, { checkedAt: now, mtimeMs, size, value });
  return value;
}

/**
 * pi's compaction settings: the project's `.pi/settings.json` overriding the
 * agent directory's `settings.json` key by key — pi's order, the footer's
 * order, gallop's order. A file that names one key never decides the other.
 * Pass `ttlMs = 0` in a one-shot command or a test, where an edit landed
 * moments ago must be visible.
 */
export function readPiCompactionSettings(
  cwd: string,
  globalPath: string = path.join(agentDir(), "settings.json"),
  ttlMs = 1500,
): PiCompactionSettings {
  const comp = (p: string): Record<string, unknown> => {
    const c = readPiSettingsJson(p, ttlMs)?.compaction;
    return isPlainObject(c) ? c : {};
  };
  const global = comp(globalPath);
  const project = comp(path.join(cwd, ".pi", "settings.json"));
  const num = (p: Record<string, unknown>, k: string): number | undefined =>
    typeof p[k] === "number" ? (p[k] as number) : undefined;
  const bool = (p: Record<string, unknown>, k: string): boolean | undefined =>
    typeof p[k] === "boolean" ? (p[k] as boolean) : undefined;
  return {
    reserveTokens:
      num(project, "reserveTokens") ??
      num(global, "reserveTokens") ??
      PI_COMPACTION_DEFAULTS.reserveTokens,
    enabled:
      bool(project, "enabled") ??
      bool(global, "enabled") ??
      PI_COMPACTION_DEFAULTS.enabled,
    keepRecentTokens:
      num(project, "keepRecentTokens") ??
      num(global, "keepRecentTokens") ??
      PI_COMPACTION_DEFAULTS.keepRecentTokens,
  };
}
