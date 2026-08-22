/**
 * halter-settings.ts — the single owner of ~/.pi/agent/halter.json.
 *
 * Both the decision-log toggle (decision-log.ts) and the judge settings
 * (judge.ts) persist to this file; pi owns settings.json (written under a
 * lock), so extensions keep their own. All reads and writes of the file go
 * through here so there is exactly one corrupt policy and one read path:
 *
 *  • corrupt file (bad JSON or non-object top level) → copied to <file>.bak
 *    and defaults apply — user settings are preserved, never silently
 *    discarded. The backup happens once per file state (the read is cached),
 *    so widget repaints cannot spam .bak copies.
 *  • reads are cached keyed on (path, mtimeMs, size): a widget that re-renders
 *    every frame pays a single fs.statSync per read, and readFileSync +
 *    JSON.parse only when the file actually changed.
 *
 * The returned object must be treated as read-only; writeSettings merges a
 * patch on a copy and updates the cache.
 */
import fs from "node:fs";
import path from "node:path";
import os from "node:os";

/** Halter's own settings file (the /judge command and /halter-decision-log
 * persist here; see README "Decision log" / "Judge settings"). */
export const SETTINGS_PATH = path.join(os.homedir(), ".pi", "agent", "halter.json");

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

/**
 * Read the settings file as an object. Missing file → {}. Corrupt file →
 * backed up to <file>.bak, then {}. Cached by (path, mtimeMs, size) —
 * unchanged files cost one statSync per read.
 */
export function readSettingsFile(filePath: string = SETTINGS_PATH): Record<string, unknown> {
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
 * Merge a top-level patch into the settings file (other keys are preserved,
 * e.g. the judge section while writing the log toggle). A corrupt existing
 * file is backed up via the read. Returns the merged top-level object.
 */
export function writeSettings(
  patch: Record<string, unknown>,
  filePath: string = SETTINGS_PATH,
): Record<string, unknown> {
  const settings = { ...readSettingsFile(filePath), ...patch };
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, JSON.stringify(settings, null, 2) + "\n");
  // Refresh the cache deterministically (do not rely on mtime granularity).
  if (cachedPath === filePath) {
    try {
      const st = fs.statSync(filePath);
      cachedMtimeMs = st.mtimeMs;
      cachedSize = st.size;
      cachedData = settings;
    } catch {
      /* next read re-stats anyway */
    }
  }
  return settings;
}
