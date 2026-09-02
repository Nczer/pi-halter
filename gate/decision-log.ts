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
 * A second file (logUnresolved) records unresolved-token outcomes:
 * <extension dir>/.log/unresolved.jsonl — the parser-convergence ledger
 * (the same token's outcome flipping prompted → gate-stop → auto-allowed).
 * ALWAYS ON (D17): it is small — one line per unresolved token, on signal
 * only — and the /halter-decision-log toggle deliberately does not cover
 * it.
 *
 * A third file (logJudge) records judge diagnostics:
 * <extension dir>/.log/judge.jsonl — stage 1 / stage 2 verdict
 * DISAGREEMENTS (both judge modes), judge infra failures (no-model /
 * no-auth / call-failed / no-explanation), and stage-2 path-report
 * mismatches (the D13 parser-gap signal, mirrored into decisions.jsonl
 * while that log is on). ALWAYS ON for the same reason.
 *
 * Both ledgers are append-only and NOT version-bound (unlike
 * decisions.jsonl, which is reviewed per gate version).
 *
 * Test hermeticity: the vitest worker setup forces ALL THREE off —
 * HALTER_DECISION_LOG=off (decision log), plus HALTER_UNRESOLVED_LOG=off
 * and HALTER_JUDGE_LOG=off (the always-on ledgers). Test files that need
 * one set the matching env var to a tmp path per-test.
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { DECISION_LOG_ENABLED } from "../config/logging";
import { SETTINGS_PATH, readSettingsFile, writeSettings } from "../halter-settings";
import { summarizePrompt } from "../ui/prompt-builder";
import type {Decision, FilePromptData, PermissionRequest, PromptData} from "../decide/types";
import type {Store} from "./store";
import type {JudgeResult} from "../judge/judge";
import { judgePathLogFields } from "../judge/paths";

// Anchored to the extension ROOT, not this file's dir (gate/): the log
// lives at <extension dir>/.log/ regardless of where the module lives.
const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));

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

export const DEFAULT_LOG_FILE = path.join(root, ".log", "decisions.jsonl");
export const UNRESOLVED_LOG_FILE = path.join(root, ".log", "unresolved.jsonl");
export const JUDGE_LOG_FILE = path.join(root, ".log", "judge.jsonl");

/** Resolve the unresolved-token log path. `HALTER_UNRESOLVED_LOG` is a
 * test seam (point the log at a scratch path); `off` disables it (vitest
 * hermeticity). Production never sets it. */
export function resolveUnresolvedLogPath(): string | null {
  const v = process.env.HALTER_UNRESOLVED_LOG;
  if (v === undefined) return UNRESOLVED_LOG_FILE;
  return v === "off" ? null : v;
}

/** Resolve the judge-ledger path. `HALTER_JUDGE_LOG` is a test seam
 * (scratch path); `off` disables it (vitest hermeticity). Production
 * never sets it. */
export function resolveJudgeLogPath(): string | null {
  const v = process.env.HALTER_JUDGE_LOG;
  if (v === undefined) return JUDGE_LOG_FILE;
  return v === "off" ? null : v;
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
  tool: "bash" | "file" | "tool";
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
    // Always-on (D17): the toggle covers decisions.jsonl only — the
    // convergence ledger must not depend on it. The env seam is the only
    // gate (vitest hermeticity).
    const file = resolveUnresolvedLogPath();
    if (!file) return;
    const entry: UnresolvedLogEntry = {
      ts: new Date().toISOString(),
      ...e,
      cmd: e.cmd.slice(0, 200),
    };
    appendJsonl(file, JSON.stringify(entry) + "\n");
  } catch {
    /* never throw */
  }
}

// ── Judge ledger (always-on, D17) ──────────────────────────────────────

export type JudgeLogMode = "dspa" | "dspat" | "manual";

export interface JudgeLogEntry {
  /** ISO timestamp. */
  ts: string;
  /** diff — the two judge stages disagreed · infra — a stage produced no
   *  verdict · paths — stage-2 path report vs the floor (D13). */
  kind: "diff" | "infra" | "paths";
  /** The regime that produced the signal. */
  mode: JudgeLogMode;
  /** The judge model (absent when the failure preceded model resolution). */
  model?: string;
  /** The operation (command / file path / tool label), truncated. */
  cmd?: string;
  // kind: "diff" — compact stage verdicts, "approve/low" form.
  s1?: string;
  s2?: string;
  // kind: "infra".
  stage?: 1 | 2;
  error?: "no-model" | "no-auth" | "call-failed" | "no-explanation";
  // kind: "paths" — the report as sanitized, plus the floor mismatches.
  judgePaths?: string[];
  misses?: string[];
}

/** The operation a log line is about (logJudge truncates to 200). */
function judgeCmdOf(pd: PromptData): string {
  return pd.type === "bash" ? pd.command : pd.type === "file" ? pd.filePath : `${pd.tool}/${pd.label}`;
}

/**
 * Append one line to the always-on judge ledger (see JudgeLogEntry). Only
 * on signal: diffs and mismatches, never the agreeing/covered majority.
 * Never throws.
 */
export function logJudge(e: Omit<JudgeLogEntry, "ts">): void {
  try {
    const file = resolveJudgeLogPath();
    if (!file) return;
    // Log economy: the ledger is mineable by eye — truncate the operation.
    const line = { ts: new Date().toISOString(), ...e };
    if (line.cmd) line.cmd = line.cmd.slice(0, 200);
    appendJsonl(file, JSON.stringify(line) + "\n");
  } catch {
    /* never throw */
  }
}

/**
 * Both judge stages rendered verdicts and they DISAGREE (on approve or on
 * risk) — the judge-quality signal the agreement counters cannot see. A
 * no-op when either stage produced no verdict or the two agree. Called
 * from /dspa (both stages) and /dspat (both stages, always — D17).
 */
export function logJudgeDiff(
  pd: PromptData,
  mode: JudgeLogMode,
  v1: JudgeResult | null,
  v2: JudgeResult | null,
): void {
  if (!v1 || !v2) return;
  if (v1.approve === v2.approve && v1.risk === v2.risk) return;
  logJudge({
    kind: "diff",
    mode,
    model: v2.model,
    cmd: judgeCmdOf(pd),
    s1: `${v1.approve}/${v1.risk}`,
    s2: `${v2.approve}/${v2.risk}`,
  });
}

/**
 * D13: a stage-2 verdict whose path report the floor never saw — the
 * parser-gap / hallucination signal, mirrored to the always-on ledger so
 * it survives the decision log being off (or wiped on /reload). A no-op
 * when the report is absent or fully covered by the floor.
 */
export function logJudgePaths(
  pd: PromptData,
  store: Store,
  verdict: JudgeResult,
  mode: JudgeLogMode,
): void {
  if (pd.type !== "bash") return;
  const f = judgePathLogFields(pd, store, verdict.paths);
  if (!f.judgePathMisses?.length) return;
  logJudge({
    kind: "paths",
    mode,
    model: verdict.model,
    cmd: judgeCmdOf(pd),
    judgePaths: f.judgePaths,
    misses: f.judgePathMisses,
  });
}

/**
 * A judge stage failed to produce a verdict — runJudgeStage calls this at
 * each failure site. The judge being OFF (settings) is a choice, not an
 * infra failure: it is never logged.
 */
export function logJudgeInfra(
  pd: PromptData,
  mode: JudgeLogMode,
  stage: 1 | 2,
  error: NonNullable<JudgeLogEntry["error"]>,
  model?: string,
): void {
  logJudge({ kind: "infra", mode, stage, error, cmd: judgeCmdOf(pd), model });
}

// The one-line prompt summary lives in prompt-builder (summarizePrompt);
// targetOf stays here — it covers the REQUEST shape, including blocks.
function targetOf(request: PermissionRequest): string {
  if (request.type === "bash") return request.command;
  if (request.type === "tool") return `${request.tool}/${request.label}`;
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
