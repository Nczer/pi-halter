/**
 * halter-settings.ts — halter's typed facade over the vendored
 * `./ext-settings.ts` (authored in ui-kit/, synced by `npm run sync:kit`).
 *
 * halter owns the `halter` namespace in `settings-ext.json` — the one shared
 * settings file for all extensions (pi owns settings.json; extensions never
 * write into it). The log toggles (decisionLog — gate/decision-log.ts;
 * ledgerLog — the three diagnostic ledgers, config/logging.ts), the judge
 * settings (judge/judge.ts) and the startup mode (modes/dspa-mode.ts) all
 * persist here, and all of them reach the file through this file: one
 * corrupt policy, one read path, one write path.
 *
 * What ext-settings.ts guarantees, and why halter depends on it:
 *  • corrupt file (bad JSON or non-object top level) → copied to `<file>.bak`
 *    and the defaults apply — the operator's settings are preserved, never
 *    silently discarded; and when that copy fails, nothing is written over the
 *    file (see writeSettings).
 *  • reads cached on (path, mtimeMs, size): a widget that re-renders every
 *    frame pays one fs.statSync per read, and parse only when it changed.
 *  • missing keys are materialized: the namespace is merged per key over
 *    HALTER_DEFAULTS (nested plain objects merge recursively) and the merged
 *    result is written back on first read, so every option is visible and
 *    editable in the file.
 *  • writes are sibling-temp + rename, so a crash or a second extension cannot
 *    leave or rename over a half-written file.
 *  • the agent directory is resolved through PI_CODING_AGENT_DIR, so a
 *    relocated `~/.pi/agent` is found here too.
 *
 * The returned object must be treated as read-only; writeSettings merges a
 * patch into the namespace (a copy) and updates the cache.
 */
import type { ThinkingLevel } from "@earendil-works/pi-ai";
import {
  SETTINGS_PATH,
  loadExtSettings,
  patchExtSettings,
  resetSettingsCache,
  settingsExtPath,
} from "./ext-settings";

// Re-exported so every consumer of halter's settings keeps importing them from
// here — the file is the seam, ext-settings is the mechanism.
export { SETTINGS_PATH, resetSettingsCache };

const NAMESPACE = "halter";

/** Judge configuration defaults (typed JudgeSettings in judge/judge.ts; the
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

/** Default content of the halter namespace (materialized on first read).
 *
 * `mode` — the persistent STARTUP mode (modes/dspa-mode.ts): which mode a
 * new session starts in. Only /dspa is session-persistent ("manual" | "dspa")
 * — /dsp (the full bypass) and /dspat (advisory) are deliberately
 * session-scoped and never written here.
 *
 * `ledgerLog` — the diagnostic-ledger toggle (the three ledgers: unresolved,
 * judge, glob-err; config/logging.ts), ON by default; decisionLog stays off
 * by default.
 *
 * `readDirs` — operator scope grants for the READ bar (dirs, `~` allowed).
 * Read once at activation and appended to `config/path-rules.ts` →
 * `allowedReadPaths`: commands that only read inside those dirs need no prompt
 * and no judge call. Read half only — a durable WRITE grant in a settings file
 * is G3's bad click with nobody in the loop (see path-rules for the full rule).
 * Applied at activation, so an edit lands next session / `/reload`. */
export const HALTER_DEFAULTS: Record<string, unknown> = {
  decisionLog: false,
  ledgerLog: true,
  judge: JUDGE_DEFAULTS,
  mode: "manual",
  readDirs: [],
};

/**
 * Read halter's namespace: per-key merged over HALTER_DEFAULTS, with
 * missing keys materialized back into the file (so every option is
 * visible). Missing file → defaults (materialized). Corrupt → defaults +
 * .bak backup.
 */
export function readSettingsFile(filePath: string = settingsExtPath()): Record<string, unknown> {
  return loadExtSettings(NAMESPACE, HALTER_DEFAULTS, filePath);
}

/**
 * The operator's read-bar grants (the raw `readDirs` list). Normalizing and
 * registering is the bar's own job — `registerAllowedReadDirs`
 * (config/path-rules.ts) expands `~`, drops `/`, existing files and junk.
 */
export function readConfigReadDirs(filePath: string = settingsExtPath()): unknown {
  const v = readSettingsFile(filePath)["readDirs"];
  return Array.isArray(v) ? v : [];
}

/**
 * Merge a top-level patch into halter's namespace (other namespaces in the
 * shared file are preserved, as are other halter keys — e.g. the judge
 * section while writing the log toggle). Returns the merged namespace.
 *
 * `defaults` matters here, not just on the read path: the stored namespace is
 * merged over HALTER_DEFAULTS before the patch is applied, so a partial file
 * never answers for a key the caller never named. `throwOnCorruptUnbacked` is
 * the guard that a corrupt file whose `.bak` copy failed is the operator's only
 * copy, and an explicit write would destroy it. Refusing costs a toggle until
 * the file is fixed; overwriting costs the file. Callers surface the message
 * (the extension host reports handler errors); nothing here silently drops the
 * operator's command.
 */
export function writeSettings(
  patch: Record<string, unknown>,
  filePath: string = settingsExtPath(),
): Record<string, unknown> {
  return patchExtSettings(NAMESPACE, patch, filePath, {
    throwOnCorruptUnbacked: true,
    defaults: HALTER_DEFAULTS,
  });
}
