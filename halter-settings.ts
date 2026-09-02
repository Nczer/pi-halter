/**
 * halter-settings.ts — single owner of halter's namespace in
 * ~/.pi/agent/settings-ext.json — the one shared settings file for all
 * extensions (pi owns settings.json, written under a lock; extensions keep
 * their own namespace here instead).
 *
 * The decision-log toggle (decision-log.ts) and the judge settings (judge.ts)
 * persist under the `halter` namespace. All reads and writes of the file go
 * through here so there is exactly one corrupt policy and one read path:
 *
 *  • corrupt file (bad JSON or non-object top level) → copied to <file>.bak
 *    and defaults apply — user settings are preserved, never silently
 *    discarded. The backup happens once per file state (the read is cached),
 *    so widget repaints cannot spam .bak copies.
 *  • reads are cached keyed on (path, mtimeMs, size): a widget that
 *    re-renders every frame pays a single fs.statSync per read, and
 *    readFileSync + JSON.parse only when the file actually changed.
 *  • missing keys are materialized: the namespace is merged per key over
 *    HALTER_DEFAULTS (the nested judge object merges recursively) and the
 *    merged result is written back on first read, so every option is
 *    visible and editable in the file.
 *
 * The returned object must be treated as read-only; writeSettings merges a
 * patch into the namespace (a copy) and updates the cache.
 */
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import type { ThinkingLevel } from "@earendil-works/pi-ai";

/** Shared settings file; halter owns the "halter" namespace in it (the
 * /judge command and /halter-decision-log persist here; see README
 * "Decision log" / "Judge settings"). */
export const SETTINGS_PATH = path.join(os.homedir(), ".pi", "agent", "settings-ext.json");

const NAMESPACE = "halter";

/** Judge configuration defaults (typed JudgeSettings in judge.ts; the
 * /judge command and readJudgeSettings merge per key over this). */
export const JUDGE_DEFAULTS: {
  enabled: boolean;
  provider: string | null;
  model: string | null;
  thinking: "off" | ThinkingLevel;
  timeoutMs: number;
} = {
  enabled: true,
  provider: null,
  model: null,
  // Eval 2026-08-22 (Qwen3 27B, 16-case matrix incl. 10 hard traps):
  // `low` matched xhigh's 10/10 on the hard set with no 34s-style tail.
  thinking: "low",
  // FIRST-TOKEN deadline (ms): the call is aborted if the model produces
  // no output within this window (a dead or saturated model fails fast).
  // The whole response is separately capped (JUDGE_RESPONSE_CAP_MS in
  // judge/judge.ts), so a slow-but-responsive model can still finish a
  // long verdict — and stage 2 gets 3× this window (larger packet →
  // slower prefill; see STAGE2_TIMEOUT_FACTOR in judge/verdict.ts).
  timeoutMs: 8000,
};

/** Default content of the halter namespace (materialized on first read). */
export const HALTER_DEFAULTS: Record<string, unknown> = {
  decisionLog: false,
  judge: JUDGE_DEFAULTS,
};

// Single-slot stat cache (production always reads SETTINGS_PATH; tests pass
// tmp paths, which simply re-parse on every miss).
let cachedPath: string | null = null;
let cachedMtimeMs: number = -1;
let cachedSize: number = -1;
let cachedData: Record<string, unknown> = {};

/** Drop the read cache (module (re)load, tests). */
export function resetSettingsCache(): void {
  cachedPath = null;
  cachedMtimeMs = -1;
  cachedSize = -1;
  cachedData = {};
}

function backupCorrupt(filePath: string): void {
  try {
    fs.copyFileSync(filePath, filePath + ".bak");
  } catch {
    /* best effort — defaults still apply */
  }
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Recursive merge: file values win per key; nested plain objects merge
 * recursively. Keys present in the file but not in the defaults are
 * preserved (never drop user data on materialization). */
function merge(defaults: Record<string, unknown>, file: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = { ...file };
  for (const [k, d] of Object.entries(defaults)) {
    const f = file[k];
    out[k] = isPlainObject(d) && isPlainObject(f) ? merge(d, f) : f === undefined ? d : f;
  }
  return out;
}

/** Refresh the stat cache deterministically (do not rely on mtime
 * granularity). */
function refreshCache(filePath: string, data: Record<string, unknown>): void {
  try {
    const st = fs.statSync(filePath);
    cachedPath = filePath;
    cachedMtimeMs = st.mtimeMs;
    cachedSize = st.size;
    cachedData = data;
  } catch {
    /* next read re-stats anyway */
  }
}

/** Write the whole shared file, preserving every other namespace. */
function writeWhole(filePath: string, file: Record<string, unknown>): void {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, JSON.stringify(file, null, 2) + "\n");
  refreshCache(filePath, file);
}

/** Merge the halter namespace over the defaults; when it differs from the
 * file's raw namespace (missing keys), write the merged namespace back so
 * every option is visible in the file. Returns the merged namespace. */
function materialize(filePath: string, file: Record<string, unknown>): Record<string, unknown> {
  const merged = merge(HALTER_DEFAULTS, isPlainObject(file[NAMESPACE]) ? file[NAMESPACE] : {});
  if (JSON.stringify(file[NAMESPACE]) !== JSON.stringify(merged)) {
    writeWhole(filePath, { ...file, [NAMESPACE]: merged });
  }
  return merged;
}

/**
 * Read the whole shared file as an object. Missing file → {}. Corrupt file
 * → backed up to <file>.bak, then {}. Cached by (path, mtimeMs, size) —
 * unchanged files cost one statSync per read.
 */
function readWholeCached(filePath: string): Record<string, unknown> {
  let mtimeMs: number;
  let size: number;
  try {
    const st = fs.statSync(filePath);
    mtimeMs = st.mtimeMs;
    size = st.size;
  } catch {
    return {};
  }
  if (cachedPath === filePath && cachedMtimeMs === mtimeMs && cachedSize === size) {
    return cachedData;
  }

  let data: Record<string, unknown> = {};
  try {
    const parsed: unknown = JSON.parse(fs.readFileSync(filePath, "utf-8"));
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      data = parsed as Record<string, unknown>;
    } else {
      backupCorrupt(filePath);
    }
  } catch {
    backupCorrupt(filePath);
  }

  cachedPath = filePath;
  cachedMtimeMs = mtimeMs;
  cachedSize = size;
  cachedData = data;
  return data;
}

/**
 * Read halter's namespace: per-key merged over HALTER_DEFAULTS, with
 * missing keys materialized back into the file (so every option is
 * visible). Missing file → defaults (materialized). Corrupt → defaults +
 * .bak backup.
 */
export function readSettingsFile(filePath: string = SETTINGS_PATH): Record<string, unknown> {
  return materialize(filePath, readWholeCached(filePath));
}

/**
 * Merge a top-level patch into halter's namespace (other namespaces in the
 * shared file are preserved, as are other halter keys — e.g. the judge
 * section while writing the log toggle). Returns the merged namespace.
 */
export function writeSettings(
  patch: Record<string, unknown>,
  filePath: string = SETTINGS_PATH,
): Record<string, unknown> {
  const file = readWholeCached(filePath);
  const ns = merge(HALTER_DEFAULTS, isPlainObject(file[NAMESPACE]) ? file[NAMESPACE] : {});
  for (const [k, v] of Object.entries(patch)) {
    if (v === undefined) delete ns[k];
    else ns[k] = v;
  }
  writeWhole(filePath, { ...file, [NAMESPACE]: ns });
  return ns;
}
