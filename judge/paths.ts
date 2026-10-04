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
 *  - the judge stays advisory: the report may inform its verdict (an
 *    unexplained path is a hidden effect — deny/defer per its rules), but
 *    this module changes no gate decision.
 *
 * ONE DELIBERATE AMENDMENT (D19, 2026-09-12): the floor was "never fed
 * LLM output" — a hallucinated path must not stop an auto-allow. The
 * user's trust decision relaxed this for exactly one class: the
 * stage-2 report's `writes` field (write/creating/deleting paths) faces
 * the deterministic WRITE BAR in the SAME PASS as the auto-allow decision
 * (gate/dspa-gate.ts `judgeWriteOutside`, applied in gate/fallthrough.ts).
 * The feed is per-run, never persisted: every run re-judges the fresh
 * script content (fenced in the packet), so a changed script re-reports
 * and is judged fresh — there is no learned state that could go stale.
 * A reported write outside the manual write bar can only cause a
 * FALSE STOP (the advisory stop the user can dismiss or grant past),
 * never a false auto-allow — the bar only narrows, grants stay
 * user-only. /dspat never vetoes (it is pure measurement).
 *
 * The value is in the log (judge.jsonl, kind "paths"): a line is a
 * floor↔judge disagreement that RAN THROUGH the floor (the gate passed —
 * auto-allow or judge-declined prompt; a floor stop writes no ledger line,
 * the prompt's decision line still carries the report). Both sides sit on
 * the line — floorPaths (the floor's own path set, sentinels included) and
 * judgePaths — plus the mismatch, split by cause: floorMisses (the floor's
 * blind spots — mine them, that is how D7–D12 were found) and contextMisses
 * (the stage-2 judge echoing a path it only saw in the Session context
 * section — a judge-side defect, kept so its rate is measurable).
 *
 * Wording: the name names the SUBJECT — `floorMisses` = paths the JUDGE
 * reported that the FLOOR never saw (the floor's blind spots), not misses
 * of the judge. Bare "miss" read as the judge missing something, which is
 * the opposite direction.
 * tools/log-inspect.mjs `dspa --paths` lists them.
 */
import path from "node:path";
import { expandTilde } from "../analysis/path-util";
import { OPAQUE_VAR_DIR } from "../analysis/bash-parser";
import { UNKNOWN_CWD_MARKER } from "../analysis/cwd-tracking";
import type {PromptData} from "../decide/types";
import type { Store } from "../gate/store";
import { executedScriptPaths } from "../analysis/script-payload";
import type { JudgeResult } from "./judge";
import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import { sessionContextPaths } from "./session-context";

/** Log economy: cap the stored report. */
const JUDGE_PATHS_MAX = 8;
/** Log economy: cap the stored floor misses. */
const JUDGE_MISSES_MAX = 5;

/** The floor's own marker sentinels (echoed back by the model — not paths). */
function isSentinel(p: string): boolean {
  return p.startsWith(OPAQUE_VAR_DIR) || p.startsWith(UNKNOWN_CWD_MARKER);
}

/** One path to absolute form: ~ expanded, relatives resolved against `cwd`,
 * `..` collapsed (the floor's own paths are already resolved — comparing
 * un-normalized text against them would invent a mismatch). */
function toAbs(p: string, cwd: string): string {
  return path.resolve(cwd, p.startsWith("~") ? expandTilde(p) : p);
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
    const abs = toAbs(p, cwd);
    if (!out.includes(abs)) out.push(abs);
    if (out.length >= JUDGE_PATHS_MAX) break;
  }
  return out;
}

/**
 * A reported path is COVERED by the floor's knowledge when it is a floor
 * path itself, lies under one, or is an ANCESTOR of one (2026-10-04, D23:
 * the judge named `/home/nczer/.pi/agent/extensions/memory` for a command
 * whose floor saw `…/memory/SKILL.md` — the same location, generalized
 * upward, not a location the gate never saw).
 *
 * The previous rule counted an ancestor only when the floor entry was a
 * GLOB, on the grounds that a literal floor path narrower than the report
 * means the judge claims more reach than the command references. That holds
 * for ENFORCEMENT, and enforcement does not use this function: the write bar
 * (dspa-gate.ts judgeWriteOutside) faces the sanitized `writes` list
 * directly, so a judge-reported write that is an ancestor of a known path
 * still escalates there. For the DIAGNOSTIC the old rule was noise — it
 * reported a real floor sighting as a blind spot.
 */
function isCovered(p: string, known: string[]): boolean {
  return known.some((f) => p === f || p.startsWith(f + "/") || f.startsWith(p + "/"));
}

export interface JudgePathReport {
  /** The model's touched paths, sanitized (omitted when empty). */
  paths?: string[];
  /** Judge-reported paths not covered by the floor's knowledge — the
   *  floor's blind spots (omitted when empty). */
  floorMisses?: string[];
  /** Misses that are only a STAGE-2 CONTEXT ECHO: the path is named in the
   *  Session context section (an earlier tool call's target, a path the user
   *  mentioned, a granted dir), so the judge had it in view without this
   *  operation reaching it (omitted when empty). Kept, never suppressed —
   *  the bleed rate is what makes the prompt fix measurable. */
  contextMisses?: string[];
}

export interface JudgePathFloor {
  /** The operation's cwd (part of the floor's knowledge). */
  cwd: string;
  /** The floor's paths — analysis.paths (absolute, may carry sentinels)
   *  plus the outside list. */
  floorPaths: string[];
  /** Confirmed (user-accepted) resolution dirs. */
  confirmedDirs?: string[];
  /** Paths named in the stage-2 Session context section (sessionContextPaths)
   *  — a miss matching one is classified as context bleed, not a floor gap. */
  contextPaths?: string[];
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
  const misses = paths.filter((p) => !isCovered(p, known));
  // Context paths arrive as written in the session (relative, ~, `..`); they
  // must be compared in the same absolute form the report was sanitized to.
  const inContext = (floor.contextPaths ?? [])
    .map((c) => c.trim())
    .filter((c) => c !== "" && !isSentinel(c))
    .map((c) => toAbs(c, floor.cwd));
  const contextMisses = misses
    .filter((p) => inContext.some((c) => p === c || p.startsWith(c + "/") || c.startsWith(p + "/")))
    .slice(0, JUDGE_MISSES_MAX);
  const floorMisses = misses.filter((p) => !contextMisses.includes(p)).slice(0, JUDGE_MISSES_MAX);
  const r: JudgePathReport = { paths };
  if (floorMisses.length > 0) r.floorMisses = floorMisses;
  if (contextMisses.length > 0) r.contextMisses = contextMisses;
  return r;
}

/**
 * Path-report fields for a judged operation (gate.ts calls this with the
 * FINAL stage-2 verdict for the decision line — judgePaths + floorMisses;
 * the ledger (logJudgePaths) also takes floorPaths — the floor's own side
 * of the disagreement). `{}` unless a stage-2 bash verdict reported paths
 * — stage 1 never asks for them, file ops have no path list.
 */
export function judgePathLogFields(
  pd: PromptData,
  store: Store,
  reported: string[] | undefined,
  ctx?: ExtensionContext,
): { judgePaths?: string[]; floorPaths?: string[]; floorMisses?: string[]; contextMisses?: string[] } {
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
  // The floor's own side, as raw knowledge (sentinels included — an
  // unbound-var marker is the floor's limited knowledge of that location).
  // The coverage check below still ignores non-absolute/sentinel entries.
  // Executed scripts join the floor's knowledge too: the floor identified
  // (and possibly trusted) the script, so a judge report of its path is not
  // a blind spot (2026-09-30 judge.jsonl floorMiss on a trusted skill
  // script). Ledger-only — see executedScriptPaths for why this stays out
  // of analysis.paths.
  const floorPaths = [
    ...analysis.paths,
    ...(analysis.prompt.outsidePaths ?? []),
    ...executedScriptPaths(analysis, pd.cwd),
  ];
  const r = judgePathReport(reported, {
    cwd: pd.cwd,
    floorPaths,
    confirmedDirs,
    contextPaths: ctx ? sessionContextPaths(ctx, store) : undefined,
  });
  return {
    judgePaths: r.paths,
    floorPaths: floorPaths.slice(0, JUDGE_PATHS_MAX),
    floorMisses: r.floorMisses,
    contextMisses: r.contextMisses,
  };
}
