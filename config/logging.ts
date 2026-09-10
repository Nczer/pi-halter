/**
 * Decision log — compile-time DEFAULT (JSONL blast-radius log — see
 * decision-log.ts).
 *
 * OFF by default. The live toggle is /halter-decision-log [on|off],
 * persisted in the halter namespace of ~/.pi/agent/settings-ext.json. When
 * enabled, every gated decision (auto-allow / prompt / block) is appended as
 * one JSON line to <extension dir>/.log/decisions.jsonl (5 MiB rotation).
 * Useful after changing gate code: diff what now prompts vs. what used to
 * auto-allow, or mine repeatedly-prompting commands into contract rows.
 *
 * D17 toggle split: this toggle covers decisions.jsonl ONLY. The small
 * diagnostic ledgers (unresolved.jsonl, judge.jsonl, glob-err.jsonl) are ON
 * BY DEFAULT but user-toggleable together — one /halter-ledger-log (key
 * `ledgerLog` in the same settings file); the env seams (HALTER_UNRESOLVED_LOG,
 * HALTER_JUDGE_LOG, HALTER_GLOBERR_LOG) accept `off` for test hermeticity and
 * win over the toggle when set.
 *
 * Transient override: HALTER_DECISION_LOG=<path> (enables at that path) or
 * HALTER_DECISION_LOG=off (forces off).
 */
export const DECISION_LOG_ENABLED = false;

/** Compile-time default for the diagnostic ledgers — ON by default,
 *  user-toggleable together (see the D17 split note above). */
export const LEDGER_LOG_ENABLED = true;

// ── Diagnostic-ledger toggle (the three ledgers, on by default) ────────
//
// The three small ledgers share ONE toggle: /halter-ledger-log —
//   .log/unresolved.jsonl (unresolved-token fate), .log/judge.jsonl (judge
//   signal), .log/glob-err.jsonl (failed glob-expansion probes — on-signal
//   only, a healthy run writes nothing). ON by default, persisted like the
//   decision log (key `ledgerLog`). Test seams HALTER_UNRESOLVED_LOG /
//   HALTER_JUDGE_LOG / HALTER_GLOBERR_LOG (scratch path / `off`) win over
//   the toggle, same convention per file.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { SETTINGS_PATH, readSettingsFile, writeSettings } from "../halter-settings";

// Anchored to the extension ROOT (one level above config/).
const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const GLOBERR_LOG_FILE = path.join(ROOT, ".log", "glob-err.jsonl");

// Module state — re-read from the settings file on every (re)load of the
// extension, like the decision-log toggle in gate/decision-log.ts.
let ledgerLogEnabled = readLedgerToggleSetting();

/** Read the ledger toggle (missing key → compile-time default). */
export function readLedgerToggleSetting(filePath: string = SETTINGS_PATH): boolean {
  const value = readSettingsFile(filePath)["ledgerLog"];
  return value !== undefined ? value !== false : LEDGER_LOG_ENABLED;
}

/** Set the toggle (in-memory + persisted). The command handler calls this. */
export function setLedgerLogEnabled(enabled: boolean, filePath: string = SETTINGS_PATH): void {
  ledgerLogEnabled = enabled;
  writeSettings({ ledgerLog: enabled }, filePath);
}

export function isLedgerLogEnabled(): boolean {
  return ledgerLogEnabled;
}

/** Resolve the glob-err log path. No env var → the live toggle
 * (/halter-ledger-log, on by default). `HALTER_GLOBERR_LOG` wins when set
 * (scratch path); `off` disables it (vitest hermeticity). */
export function resolveGlobErrLogPath(): string | null {
  const v = process.env.HALTER_GLOBERR_LOG;
  if (v === undefined) return ledgerLogEnabled ? GLOBERR_LOG_FILE : null;
  return v === "off" ? null : v;
}

/** Record one failed glob-expansion probe. Never throws. */
export function logGlobVerifyError(pattern: string, err: unknown, cwd: string): void {
  try {
    const file = resolveGlobErrLogPath();
    if (!file) return;
    const e = err as { name?: string; message?: string } | null;
    const line = JSON.stringify({
      ts: new Date().toISOString(),
      pattern: pattern.slice(0, 200),
      name: e?.name ?? "unknown",
      message: String(e?.message ?? err).slice(0, 200),
      cwd: cwd.slice(0, 200),
    }) + "\n";
    fs.appendFileSync(file, line);
  } catch {
    /* never throw */
  }
}
