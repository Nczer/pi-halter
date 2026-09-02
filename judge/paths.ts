/**
 * judge-paths.ts — D13 (docs/dspa-redesign.md): the stage-2 judge's path
 * report, cross-checked against what the deterministic floor saw.
 *
 * The stage-2 judge (judge.ts) reports the filesystem paths the operation
 * touches (JudgeResult.paths). This module sanitizes that report and
 * extracts the MISMATCH — the paths the judge saw that the static analysis
 * never saw (its paths list, the outside list, confirmed resolution dirs,
 * and the cwd are all the floor's own knowledge).
 *
 * The mismatch is a DIAGNOSTIC, not enforcement:
 *  - the floor is never fed LLM output (it must stay untrusting — a
 *    hallucinated path must not be able to stop an auto-allow);
 *  - the judge stays advisory: the report may inform its verdict (an
 *    unexplained path is a hidden effect — deny/defer per its rules), but
 *    this module changes no gate decision.
 *
 * The value is in the log: each `judgePathMisses` line is either a real
 * static-parser gap (mine it — that is how D7–D12 were found) or a judge
 * hallucination (also worth mining — it measures the report's reliability).
 * tools/log-inspect.mjs `dspa --paths` lists them.
 */
import path from "node:path";
import { expandTilde } from "../analysis/path-util";
import { OPAQUE_VAR_DIR } from "../analysis/bash-parser";
import { UNKNOWN_CWD_MARKER } from "../analysis/cwd-tracking";
import type {PromptData} from "../decide/types";
import type { Store } from "../gate/store";

/** Log economy: cap the stored report. */
const JUDGE_PATHS_MAX = 8;
/** Log economy: cap the stored misses. */
const JUDGE_MISSES_MAX = 5;

/** Glob characters — a floor entry containing these covers its expansions. */
const GLOB_RE = /[*?[]/;

/** The floor's own marker sentinels (echoed back by the model — not paths). */
function isSentinel(p: string): boolean {
  return p.startsWith(OPAQUE_VAR_DIR) || p.startsWith(UNKNOWN_CWD_MARKER);
}

/**
 * Sanitize the model's raw report to concrete absolute paths: sentinels
 * dropped, ~ expanded, relatives resolved against the operation's cwd,
 * deduped, capped. Pure model text is never stored — only this form.
 */
export function sanitizeJudgePaths(
  reported: string[] | undefined,
  cwd: string,
): string[] {
  if (!reported) return [];
  const out: string[] = [];
  for (const raw of reported) {
    if (typeof raw !== "string") continue;
    const p = raw.trim();
    if (!p || isSentinel(p)) continue;
    let abs = p.startsWith("~") ? expandTilde(p) : p;
    if (!abs.startsWith("/")) abs = path.resolve(cwd, abs);
    if (!out.includes(abs)) out.push(abs);
    if (out.length >= JUDGE_PATHS_MAX) break;
  }
  return out;
}

/**
 * A reported path is COVERED by the floor's knowledge when it is a floor
 * path itself or lies under one; a floor path lying under the report
 * counts only when it is a GLOB (a literal floor path narrower than the
 * report means the judge claims more reach than the command references).
 */
function isCovered(p: string, known: string[]): boolean {
  return known.some(
    (f) =>
      p === f ||
      p.startsWith(f + "/") ||
      (f.startsWith(p + "/") && GLOB_RE.test(f)),
  );
}

export interface JudgePathReport {
  /** The model's touched paths, sanitized (omitted when empty). */
  paths?: string[];
  /** Paths not covered by the floor's knowledge (omitted when empty). */
  misses?: string[];
}

export interface JudgePathFloor {
  /** The operation's cwd (part of the floor's knowledge). */
  cwd: string;
  /** The floor's paths — analysis.paths (absolute, may carry sentinels)
   *  plus the outside list. */
  floorPaths: string[];
  /** Confirmed (user-accepted) resolution dirs. */
  confirmedDirs?: string[];
}

/**
 * Cross-check one model report against the floor. `{}` when the model
 * reported nothing usable.
 */
export function judgePathReport(
  reported: string[] | undefined,
  floor: JudgePathFloor,
): JudgePathReport {
  const paths = sanitizeJudgePaths(reported, floor.cwd);
  if (paths.length === 0) return {};
  const known = [
    floor.cwd,
    ...(floor.confirmedDirs ?? []),
    ...floor.floorPaths.filter((p) => p.startsWith("/") && !isSentinel(p)),
  ];
  const misses = paths
    .filter((p) => !isCovered(p, known))
    .slice(0, JUDGE_MISSES_MAX);
  return misses.length > 0 ? { paths, misses } : { paths };
}

/**
 * Decision-log fields for a judged operation (gate.ts calls this with the
 * FINAL stage-2 verdict). `{}` unless a stage-2 bash verdict reported
 * paths — stage 1 never asks for them, file ops have no path list.
 */
export function judgePathLogFields(
  pd: PromptData,
  store: Store,
  reported: string[] | undefined,
): { judgePaths?: string[]; judgePathMisses?: string[] } {
  if (pd.type !== "bash" || !reported?.length || !pd.analysis) return {};
  const analysis = pd.analysis;
  // Confirmed dirs are the floor's own (deterministic) knowledge — the
  // analysis layer already resolved them into analysis.paths, but the
  // re-derivation keeps the floor set complete when a confirmed token's
  // marker still rides in the paths list.
  const confirmedDirs: string[] = [];
  for (const u of analysis.prompt.unresolved) {
    for (const d of store.getConfirmedResolution(u.token) ?? []) confirmedDirs.push(d);
  }
  const r = judgePathReport(reported, {
    cwd: pd.cwd,
    floorPaths: [...analysis.paths, ...(analysis.prompt.outsidePaths ?? [])],
    confirmedDirs,
  });
  return { judgePaths: r.paths, judgePathMisses: r.misses };
}
