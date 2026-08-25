/**
 * JSONL decision log — blast-radius measurement.
 *
 * Every decision that flows through the gate is appended as one JSON line,
 * so "what the gate decided, and why" can be reviewed after the fact:
 *  • after changing gate code — did anything that used to auto-allow start
 *    prompting (or vice versa)?
 *  • mining contract rows — which commands prompt repeatedly?
 *
 * Fire-and-forget: a logging failure must never affect the gate decision
 * (this runs inside the gate; a throw would become a fail-closed block).
 *
 * OFF by default. Toggle: /halter-decision-log [on|off] — persisted in
 * halter's own settings file ~/.pi/agent/halter.json (pi owns settings.json
 * and writes it under a lock, so extensions keep their own file; the
 * setting never lived in settings.json, so no legacy fallback). The
 * compile-time default is config/logging.ts DECISION_LOG_ENABLED.
 * Path: <extension dir>/.log/decisions.jsonl, rotated to decisions.jsonl.1
 * when it exceeds 5 MiB (older backup overwritten).
 * Transient override: HALTER_DECISION_LOG=<path> (enables at that path) or
 * HALTER_DECISION_LOG=off (forces off).
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { DECISION_LOG_ENABLED } from "./config/logging";
import { SETTINGS_PATH, readSettingsFile, writeSettings } from "./halter-settings";
import { summarizePrompt } from "./prompt-builder";
import type { Decision, PermissionRequest } from "./decision-engine";

const here = path.dirname(fileURLToPath(import.meta.url));

// ── Persisted toggle (~/.pi/agent/halter.json, gallop pattern) ──

const SETTING_KEY = "decisionLogEnabled";

/** Read the toggle from a settings file (missing file → compile-time default). */
export function readToggleSetting(filePath: string = SETTINGS_PATH): boolean {
  const value = readSettingsFile(filePath)[SETTING_KEY];
  return value !== undefined ? value !== false : DECISION_LOG_ENABLED;
}

/** Write the toggle to a settings file (merges with other halter keys). */
export function writeToggleSetting(enabled: boolean, filePath: string = SETTINGS_PATH): void {
  writeSettings({ [SETTING_KEY]: enabled }, filePath);
}

// Module state — re-read from disk on every (re)load of the extension.
let decisionLogEnabled = readToggleSetting();

/** Set the toggle (in-memory + persisted). The command handler calls this. */
export function setDecisionLogEnabled(enabled: boolean, filePath: string = SETTINGS_PATH): void {
  decisionLogEnabled = enabled;
  writeToggleSetting(enabled, filePath);
}

export function isDecisionLogEnabled(): boolean {
  return decisionLogEnabled;
}

export const DEFAULT_LOG_FILE = path.join(here, ".log", "decisions.jsonl");
export const MAX_LOG_BYTES = 5 * 1024 * 1024;
const MAX_TARGET_LEN = 1000;

/**
 * The dsp regime a decision was made under — present only where a judge
 * mode actually participated: a prompt shown while /dspa or /dspat was
 * active (the modes are exclusive), or the synthetic dspa judge
 * auto-allow line. Absent = the manual regime. The dsp bypass regime
 * never reaches the log — the gate (and thus the log) is skipped.
 */
export type DspModeTag = "dspa" | "dspat";

export interface DecisionLogEntry {
  /** ISO timestamp. */
  ts: string;
  tool: "bash" | "file" | "mcp";
  /**
   * `deny` is the phase-3 dspa denial flow (D4): a judge-rejected
   * operation returned to the AGENT instead of a user prompt. It is a
   * synthetic entry (no Decision exists for it) emitted by the denial
   * flow, not by logDecision; phase 2 does not emit it. Its reason is
   * `dspa: judge denied (stage N)` — plumbing only, no model text
   * (verdict content stays session-scoped per the NOTE below).
   */
  kind: Decision["kind"] | "deny";
  /**
   * The dsp regime this decision was made under; absent = manual regime.
   * A regime marker, not verdict content (see the NOTE below).
   */
  mode?: DspModeTag;

  /**
   * dspa prompt fall-through only (absent otherwise): which layer stopped
   * the auto-allow before the prompt was shown (see dspaStopTag, gate.ts).
   *  - `gate: <reason>` — the deterministic hard gate (code-produced;
   *    accumulates safely across sessions).
   *  - `judge: declined (stage 2)` — the gate passed, the intent pass's
   *    verdict did not auto-allow (verdict content stays session-scoped,
   *    see the NOTE).
   *  - `judge: stage 2 failed` — stage 1 produced a verdict but the intent
   *    pass did not (an infra fact).
   *  - `judge: <note>` — no verdict was produced at all (judge invalid or
   *    call failed — plumbing, not verdict quality).
   */
  dspa?: string;

  /** Block reason, or a one-line summary of why a prompt was needed; null for auto-allow. */
  reason: string | null;
  /** Bash command (truncated), file path, or "server/tool". */
  target: string;
  /** The tool call's working directory (bash + file). */
  cwd?: string;
}

/**
 * NOTE: judge verdicts (dspat/dspa) are deliberately NOT written to this
 * log. Judge quality is model-dependent — the user's session model can
 * change between sessions — so verdict + human-decision stats stay
 * session-scoped (dspat-mode.ts) and never accumulate cross-session.
 * This log measures the GATE's decisions, which are model-independent.
 * The `mode` tag (DspModeTag) marks which judge mode a prompt was shown
 * under — it is a regime marker, not verdict content. The `dspa` stop-tag
 * on dspa prompt lines likewise records only WHICH layer stopped the
 * auto-allow (the gate's code-produced reason, or the fact that the judge
 * declined/failed) — still no verdict content.
 */

/** Resolve the active log file. null = logging disabled. */
export function resolveLogPath(): string | null {
  const env = process.env.HALTER_DECISION_LOG;
  if (env === "off" || env === "") return null;
  if (env) return env;
  return decisionLogEnabled ? DEFAULT_LOG_FILE : null;
}

/**
 * Append one decision to the JSONL log. Never throws — logging problems are
 * silently dropped; the gate's behavior must not depend on disk state.
 *
 * @param mode - dsp regime tag (see DspModeTag); omit for the manual regime.
 *   undefined is dropped by JSON.stringify, so untagged lines carry no
 *   `mode` key at all.
 * @param dspaStop - dspa stop-tag (see DecisionLogEntry.dspa); omit outside
 *   dspa prompt fall-throughs.
 */
export function logDecision(
  request: PermissionRequest,
  decision: Decision,
  mode?: DspModeTag,
  dspaStop?: string,
): void {
  try {
    const file = resolveLogPath();
    if (!file) return;

    const entry: DecisionLogEntry = {
      ts: new Date().toISOString(),
      tool: request.type,
      kind: decision.kind,
      mode,
      dspa: dspaStop,
      reason:
        decision.kind === "block"
          ? decision.reason
          : decision.kind === "prompt"
            ? summarizePrompt(decision)
            : decision.reason ?? null, // auto-allow: /dspa audit reason, else null
      target: targetOf(request).slice(0, MAX_TARGET_LEN),
      cwd: "cwd" in request ? request.cwd : undefined,
    };
    const line = JSON.stringify(entry) + "\n";

    let size = 0;
    try {
      size = fs.statSync(file).size;
    } catch {
      /* new file */
    }
    if (size + line.length > MAX_LOG_BYTES) {
      try {
        fs.renameSync(file, file + ".1");
      } catch {
        /* keep logging even if the backup fails */
      }
    }
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.appendFileSync(file, line);
  } catch {
    /* never throw */
  }
}

// The one-line prompt summary lives in prompt-builder (summarizePrompt);
// targetOf stays here — it covers the REQUEST shape, including blocks.
function targetOf(request: PermissionRequest): string {
  if (request.type === "bash") return request.command;
  if (request.type === "file") return request.filePath;
  return `${request.server}/${request.tool}`;
}
