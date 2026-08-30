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
 * OFF by default. Toggle: /halter-decision-log [on|off] — persisted in the
 * halter namespace of ~/.pi/agent/settings-ext.json (the shared extension
 * settings file; pi owns settings.json and writes it under a lock). The
 * compile-time default is config/logging.ts DECISION_LOG_ENABLED.
 * Path: <extension dir>/.log/decisions.jsonl, rotated to decisions.jsonl.1
 * when it exceeds 5 MiB (older backup overwritten).
 * Transient override: HALTER_DECISION_LOG=<path> (enables at that path) or
 * HALTER_DECISION_LOG=off (forces off).
 *
 * A second, independent file records unresolved-token outcomes
 * (logUnresolved): <extension dir>/.log/unresolved.jsonl, same rotation,
 * same module toggle (/halter-decision-log). The env switch only REDIRECTS
 * the decision log to a scratch path (it is not an override for the
 * unresolved log's location) — except `off`, which disables BOTH (test
 * hermeticity: the vitest setup forces off so fixture lines never reach the
 * live logs).
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { DECISION_LOG_ENABLED } from "./config/logging";
import { SETTINGS_PATH, readSettingsFile, writeSettings } from "./halter-settings";
import { summarizePrompt } from "./prompt-builder";
import type { Decision, FilePromptData, PermissionRequest } from "./decision-engine";

const here = path.dirname(fileURLToPath(import.meta.url));

// ── Persisted toggle ("decisionLog" in the halter namespace of
 // settings-ext.json, shared with the judge settings) ──

const SETTING_KEY = "decisionLog";

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
export const UNRESOLVED_LOG_FILE = path.join(here, ".log", "unresolved.jsonl");

/** Resolve the unresolved-token log path. `HALTER_UNRESOLVED_LOG` is a
 * test seam (point the log at a scratch path); production never sets it. */
export function resolveUnresolvedLogPath(): string {
  return process.env.HALTER_UNRESOLVED_LOG || UNRESOLVED_LOG_FILE;
}
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
  tool: "bash" | "file";
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
   *    verdict did not auto-allow (a REJECT verdict's explanation rides
   *    along in `judgeDeny` — the NOTE's debug exception).
   *  - `judge: stage 2 failed` — stage 1 produced a verdict but the intent
   *    pass did not (an infra fact).
   *  - `judge: <note>` — no verdict was produced at all (judge invalid or
   *    call failed — plumbing, not verdict quality).
   */
  dspa?: string;

  /**
   * dspa prompt fall-through only, and only when the FINAL verdict is a
   * REJECT (approve === "deny"): the LLM's own words for why it refused.
   * The NOTE's debug exception — raw verdict content for inspecting judge
   * behavior, never aggregated (stats stay session-scoped).
   */
  judgeDeny?: string;

  /**
   * D13: the stage-2 judge's report of the paths the operation touches
   * (sanitized absolute paths, capped) — only when the final stage-2
   * verdict reported any. A second NOTE debug exception, and a parser-gap
   * probe: paired with `judgePathMisses`, `log-inspect.mjs dspa --paths`
   * lists every path the judge saw that the static floor never did.
   */
  judgePaths?: string[];
  /**
   * D13: reported paths NOT covered by the floor's knowledge (analysis
   * paths, outside list, confirmed dirs, cwd) — the parser-gap diagnostic
   * (a miss is either a real static-analysis hole or a judge
   * hallucination; both are worth mining). Only when non-empty.
   */
  judgePathMisses?: string[];

  /** Block reason, or a one-line summary of why a prompt was needed; null for auto-allow. */
  reason: string | null;
  /** Bash command (truncated), or file path. */
  target: string;
  /**
   * File prompt only: the directory the prompt offers to grant — the
   * resolved path's containing dir (the outside-cwd primary grant and the
   * inside-cwd "Always (path)" option are both `dirname(resolved)`).
   * Absent when the parent is the root (a root file prompt offers the
   * file, not "/"). Debug aid for the path resolver: cross-check against
   * `target` (raw) + `cwd` to see where the resolver landed.
   */
  promptDir?: string;
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
 * declined/failed) — still no verdict content, with one exception:
 * `judgeDeny` carries a dspa REJECT verdict's explanation verbatim — a
 * raw debug aid for judge behavior, read by a human inspecting the log,
 * never aggregated into stats. Second exception (D13): `judgePaths` /
 * `judgePathMisses` carry the stage-2 judge's path report and its
 * cross-check against the floor's own knowledge — model output, but
 * sanitized, capped, and diagnostic-only: nothing in the gate reads these
 * fields back (the floor is never fed LLM output), they exist purely to be
 * mined by a human (log-inspect.mjs dspa --paths).
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
 * @param judgeDeny - the LLM's reject explanation (see
 *   DecisionLogEntry.judgeDeny); omit unless the fall-through verdict is
 *   a REJECT.
 * @param judgePaths - D13: the stage-2 judge's path report (see
 *   DecisionLogEntry.judgePaths); omit unless a stage-2 verdict reported
 *   paths.
 * @param judgePathMisses - D13: reported paths the floor never saw (see
 *   DecisionLogEntry.judgePathMisses); omit when empty.
 */
export function logDecision(
  request: PermissionRequest,
  decision: Decision,
  mode?: DspModeTag,
  dspaStop?: string,
  judgeDeny?: string,
  judgePaths?: string[],
  judgePathMisses?: string[],
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
      judgeDeny,
      judgePaths,
      judgePathMisses,
      reason:
        decision.kind === "block"
          ? decision.reason
          : decision.kind === "prompt"
            ? summarizePrompt(decision)
            : decision.reason ?? null, // auto-allow: /dspa audit reason, else null
      target: targetOf(request).slice(0, MAX_TARGET_LEN),
      promptDir:
        decision.kind === "prompt" && decision.promptData.type === "file"
          ? promptDirOf(decision.promptData)
          : undefined,
      cwd: "cwd" in request ? request.cwd : undefined,
    };
    const line = JSON.stringify(entry) + "\n";
    appendJsonl(file, line);
  } catch {
    /* never throw */
  }
}

/**
 * Append one line to a JSONL log with size-based rotation. Shared by the
 * decision log and the unresolved-token log.
 */
function appendJsonl(file: string, line: string): void {
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
}

// ── Unresolved-token log ─────────────────────────────────────────────────

export interface UnresolvedLogEntry {
  /** ISO timestamp (set by logUnresolved when absent). */
  ts?: string;
  /** The bash command (truncated). */
  cmd: string;
  /** The tool call's working directory. */
  cwd?: string;
  /** The unresolved token (full — this is the debug file, not the UI). */
  token: string;
  /** Dirs the path resolver (LLM) reported for the token, if any. */
  llm?: string[];
  /** Whether a confirmed resolution was stored for the token by this run's
   *  user decision (or, for auto-allowed runs: was in effect). */
  persisted: boolean;
  /**
   * `prompted` — a permission prompt was shown (the `decision` field names
   * the user's choice); `gate-stop` — the dspa gate stopped the
   * auto-allow on an unresolved/confirmed-outside sentinel, then the
   * prompt's `decision` followed; `auto-allowed` — no prompt: the gate
   * passed because the token's resolution was already confirmed.
   */
  outcome: "prompted" | "gate-stop" | "auto-allowed";
  /** The prompt outcome ("yes" | "no" | "always" | "alwaysPaths" | …); "auto-allow" for auto-allowed. */
  decision?: string;
}

/**
 * Record one unresolved token's fate (see UnresolvedLogEntry). The point
 * of this log: watching the convergence loop — first run prompts with an
 * LLM suggestion, the user's choice confirms, later runs auto-allow
 * (outcome flips from "prompted" to "auto-allowed" for the same token).
 * Never throws.
 */
export function logUnresolved(e: UnresolvedLogEntry): void {
  try {
    if (!decisionLogEnabled) return;
    // `off` disables both logs — the vitest setup forces this so fixture
    // lines never reach the live .log/ dir.
    if (process.env.HALTER_DECISION_LOG === "off") return;
    const entry: UnresolvedLogEntry = {
      ts: new Date().toISOString(),
      ...e,
      cmd: e.cmd.slice(0, 200),
    };
    appendJsonl(resolveUnresolvedLogPath(), JSON.stringify(entry) + "\n");
  } catch {
    /* never throw */
  }
}

// The one-line prompt summary lives in prompt-builder (summarizePrompt);
// targetOf stays here — it covers the REQUEST shape, including blocks.
function targetOf(request: PermissionRequest): string {
  if (request.type === "bash") return request.command;
  return request.filePath;
}

// The directory a file prompt offers to grant (see promptDir): the
// outside-cwd primary grant and the inside-cwd "Always (path)" option are
// both the resolved path's containing dir. The root is never offered — a
// root file prompt grants the file, not "/".
function promptDirOf(pd: FilePromptData): string | undefined {
  const dir = path.dirname(pd.resolved);
  return dir === "/" ? undefined : dir;
}
