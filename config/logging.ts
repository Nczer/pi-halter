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
 * diagnostic ledgers — unresolved.jsonl (parser convergence) and
 * judge.jsonl (stage diffs / infra failures / D13 path mismatches) — are
 * ALWAYS ON; their env seams (HALTER_UNRESOLVED_LOG, HALTER_JUDGE_LOG)
 * accept `off` for test hermeticity only.
 *
 * Transient override: HALTER_DECISION_LOG=<path> (enables at that path) or
 * HALTER_DECISION_LOG=off (forces off).
 */
export const DECISION_LOG_ENABLED = false;

// ── Glob-verify error ledger (always-on, on-signal only) ───────────────
//
// A fourth small ledger: <extension dir>/.log/glob-err.jsonl — one line per
// failed relative-glob expansion probe (fs.globSync threw or is unavailable).
// On-signal only — a healthy run writes nothing. The bare-symlink check
// fails closed on such errors, and the error is otherwise swallowed, so
// this is the mineable record of WHY (e.g. a runtime whose globSync throws
// on no-match). Test seam HALTER_GLOBERR_LOG (scratch path / `off`), same
// convention as the other ledgers.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

// Anchored to the extension ROOT (one level above config/).
const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const GLOBERR_LOG_FILE = path.join(ROOT, ".log", "glob-err.jsonl");

function resolveGlobErrLogPath(): string | null {
  const v = process.env.HALTER_GLOBERR_LOG;
  if (v === undefined) return GLOBERR_LOG_FILE;
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
