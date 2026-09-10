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
 * ON BY DEFAULT (D17): it is small — one line per unresolved token, on
 * signal only. The /halter-decision-log toggle deliberately does not cover
 * it; it and the judge ledger (and the glob-err ledger) share one toggle:
 * /halter-ledger-log (key `ledgerLog`, state in config/logging.ts).
 *
 * A third file (logJudge) records judge diagnostics:
 * <extension dir>/.log/judge.jsonl — stage-2 TIGHTENINGS over stateless
 * stage 1 (both judge modes — a stage-2 loosening is the expected
 * direction for a stateless stage 1, not a line), judge infra failures (no-model /
 * no-auth / call-failed / no-explanation), and stage-2 path-report
 * mismatches (the D13 parser-gap signal, mirrored into decisions.jsonl
 * while that log is on). ON by default for the same reason; same shared
 * toggle.
 *
 * Both ledgers are append-only and NOT version-bound (unlike
 * decisions.jsonl, which is reviewed per gate version).
 *
 * Test hermeticity: the vitest worker setup forces ALL THREE off —
 * HALTER_DECISION_LOG=off (decision log), plus HALTER_UNRESOLVED_LOG=off
 * and HALTER_JUDGE_LOG=off (the on-by-default ledgers). Test files that need
 * one set the matching env var to a tmp path per-test.
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { DECISION_LOG_ENABLED, LEDGER_LOG_ENABLED, isLedgerLogEnabled } from "../config/logging";
import { SETTINGS_PATH, readSettingsFile, writeSettings } from "../halter-settings";
import { summarizePrompt } from "../ui/prompt-builder";
import type {Decision, FilePromptData, PermissionRequest, PromptData} from "../decide/types";
import type {Store} from "./store";
import type {JudgeResult} from "../judge/judge";
import { judgePathLogFields } from "../judge/paths";

// Anchored to the extension ROOT, not this file's dir (gate/): the log
// lives at <extension dir>/.log/ regardless of where the module lives.
const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));

// ── Persisted toggles (halter namespace of settings-ext.json, shared with
 // the judge settings): decisionLog (this file) / ledgerLog (the three
 // diagnostic ledgers, state lives in config/logging.ts) ──

export type LedgerToggle = "decisionLog" | "ledgerLog";

const TOGGLE_DEFAULTS: Record<LedgerToggle, boolean> = {
  decisionLog: DECISION_LOG_ENABLED,
  ledgerLog: LEDGER_LOG_ENABLED,
};

/** Read one log toggle from a settings file (missing key → compile-time default). */
export function readToggleSetting(which: LedgerToggle = "decisionLog", filePath: string = SETTINGS_PATH): boolean {
  const value = readSettingsFile(filePath)[which];
  return value !== undefined ? value !== false : TOGGLE_DEFAULTS[which];
}

/** Write one log toggle to a settings file (merges with other halter keys). */
export function writeToggleSetting(which: LedgerToggle = "decisionLog", enabled: boolean, filePath: string = SETTINGS_PATH): void {
  writeSettings({ [which]: enabled }, filePath);
}

// Module state — re-read from disk on every (re)load of the extension.
let decisionLogEnabled = readToggleSetting("decisionLog");

/** Set the toggle (in-memory + persisted). The command handler calls this. */
export function setDecisionLogEnabled(enabled: boolean, filePath: string = SETTINGS_PATH): void {
  decisionLogEnabled = enabled;
  writeToggleSetting("decisionLog", enabled, filePath);
}

export function isDecisionLogEnabled(): boolean {
  return decisionLogEnabled;
}

export const DEFAULT_LOG_FILE = path.join(root, ".log", "decisions.jsonl");
const UNRESOLVED_LOG_FILE = path.join(root, ".log", "unresolved.jsonl");
const JUDGE_LOG_FILE = path.join(root, ".log", "judge.jsonl");

/** Resolve the unresolved-token log path. No env var → the shared ledger
 * toggle (/halter-ledger-log, on by default). `HALTER_UNRESOLVED_LOG` wins
 * when set (point the log at a scratch path); `off` disables it (vitest
 * hermeticity). */
export function resolveUnresolvedLogPath(): string | null {
  const v = process.env.HALTER_UNRESOLVED_LOG;
  if (v === undefined) return isLedgerLogEnabled() ? UNRESOLVED_LOG_FILE : null;
  return v === "off" ? null : v;
}

/** Resolve the judge-ledger path. No env var → the shared ledger toggle
 * (/halter-ledger-log, on by default). `HALTER_JUDGE_LOG` wins when set
 * (scratch path); `off` disables it (vitest hermeticity). */
export function resolveJudgeLogPath(): string | null {
  const v = process.env.HALTER_JUDGE_LOG;
  if (v === undefined) return isLedgerLogEnabled() ? JUDGE_LOG_FILE : null;
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
   * probe: paired with `floorMisses`, `log-inspect.mjs dspa --paths`
   * lists every path the judge saw that the static floor never did.
   */
  judgePaths?: string[];
  /**
   * D13: judge-reported paths NOT covered by the floor's knowledge
   * (analysis paths, outside list, confirmed dirs, cwd) — the FLOOR's
   * blind spots, i.e. the floor's misses (the name says so: bare
   * "misses" read as misses OF the judge, the opposite direction).
   * Diagnostic only: each entry is either a real static-analysis hole or a
   * judge hallucination; both are worth mining. Only when non-empty.
   */
  floorMisses?: string[];

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
 * `floorMisses` carry the stage-2 judge's path report and its
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
 * @param floorMisses - D13: judge-reported paths the floor never saw (see
 *   DecisionLogEntry.floorMisses); omit when empty.
 */
export function logDecision(
  request: PermissionRequest,
  decision: Decision,
  mode?: DspModeTag,
  dspaStop?: string,
  judgeDeny?: string,
  judgePaths?: string[],
  floorMisses?: string[],
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
      floorMisses,
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
    // The /halter-decision-log toggle covers decisions.jsonl only — the
    // convergence ledger must not depend on it. Its toggle is the shared
    // /halter-ledger-log (on by default); the env seam wins when set
    // (vitest hermeticity).
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

// ── Judge ledger (on by default, D17) ──────────────────────────────────────

export type JudgeLogMode = "dspa" | "dspat" | "manual";

export interface JudgeLogEntry {
  /** ISO timestamp. */
  ts: string;
  /** diff — stage 2 (session context) tightened over stateless stage 1 ·
   *  infra — a stage produced no verdict ·
   *  paths — stage-2 path report vs the floor (D13). */
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
  // kind: "infra" — the normalized sub-reason (JudgeResult.reason, ≤200ch):
  // "timeout" / "no-tool-call" / "bad-args: {…}" / "call-failed: <msg>".
  detail?: string;
  // kind: "paths" — the report as sanitized, plus the floor's blind spots
  // (judge-reported paths the floor never saw — "floorMisses": the floor's
  // misses, not the judge's).
  judgePaths?: string[];
  floorMisses?: string[];
}

/** The operation a log line is about (logJudge truncates to 200). */
function judgeCmdOf(pd: PromptData): string {
  return pd.type === "bash" ? pd.command : pd.type === "file" ? pd.filePath : `${pd.tool}/${pd.label}`;
}

/**
 * Append one line to the judge ledger (see JudgeLogEntry; on by default,
 * /halter-ledger-log). Only on signal: diffs and mismatches, never the
 * agreeing/covered majority. Never throws.
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

/** Strictness order — approve < defer < deny, low < medium < high. Stage 1
 *  is stateless (no session context), so it is EXPECTED to be the more
 *  conservative stage: a stage-2 LOOSENING (s1 stricter) is the design
 *  working, not a disagreement. Only a stage-2 TIGHTENING — context
 *  revealing risk the stateless view missed (the D4 blind spot) — is signal. */
const ACTION_RANK: Record<JudgeResult["approve"], number> = { approve: 0, defer: 1, deny: 2 };
const RISK_RANK: Record<string, number> = { low: 0, medium: 1, high: 2 };
const verdictStrictness = (v: JudgeResult): number =>
  ACTION_RANK[v.approve] * 10 + (RISK_RANK[v.risk ?? ""] ?? 0);

/**
 * Stage-2 TIGHTENING signal: both stages rendered verdicts and stage 2
 * (with session context) came out STRICTER than stateless stage 1 — the
 * judge-quality signal the agreement counters cannot see. No-op when either
 * stage produced no verdict, the two agree, or stage 2 is looser (the
 * expected direction for a stateless stage 1). Called from /dspa (both
 * stages) and /dspat (both stages, always — D17).
 */
export function logJudgeDiff(
  pd: PromptData,
  mode: JudgeLogMode,
  v1: JudgeResult | null,
  v2: JudgeResult | null,
): void {
  if (!v1 || !v2) return;
  if (verdictStrictness(v2) <= verdictStrictness(v1)) return;
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
 * parser-gap / hallucination signal, mirrored to the on-by-default ledger so
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
  if (!f.floorMisses?.length) return;
  logJudge({
    kind: "paths",
    mode,
    model: verdict.model,
    cmd: judgeCmdOf(pd),
    judgePaths: f.judgePaths,
    floorMisses: f.floorMisses,
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
  detail?: string,
): void {
  logJudge({ kind: "infra", mode, stage, error, cmd: judgeCmdOf(pd), model, detail });
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
