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
 * 3.44.0, two corrections to how this module's caps are applied:
 *  - `sanitizeJudgePaths` no longer truncates. The 8-path economy cap was
 *    baked into the sanitizer, so it also cut the INPUTS: the D19 write bar
 *    (`dspa-gate.judgeWriteOutside`) checked only the first 8 reported writes
 *    and §4.2's answer set only the first 8 reported paths. A report of 12
 *    writes therefore faced the bar on 8 — a 9th reported write outside the
 *    manual write bar could auto-allow unchecked, which is the false-allow
 *    direction this file's D19 note claims is impossible. The cap is now a
 *    LOG-SITE concern (`JUDGE_PATHS_MAX` applied where a row is written), and
 *    a truncated row says so (`judgePathsMore` / `floorPathsMore`).
 *  - 3.44.1 removed the last silent cap in this file. `JUDGE_MISSES_MAX = 5`
 *    sliced `floorMisses`, `contextMisses` and both role lists, unmarked — the
 *    same shape as the bug above, in the one place where a cut costs the most:
 *    the miss list IS why a paths row exists, and the entry past slot 5 was the
 *    likeliest to be the blind spot worth finding. The four disagreement lists
 *    are uncapped. Row economy stays on the SETS (`JUDGE_PATHS_MAX`, applied
 *    where the row is written, marked by `judgePathsMore`/`floorPathsMore`).
 *  - coverage uses the floor's OWN anchor (3.44.0): a floor path with a
 *    dynamic segment (`/tmp/snap-x/$e`, `/etc/*.conf`) pins a directory, so
 *    `staticPrefixOf` of it joins the covered set — exactly the anchor the
 *    gate computes for the same token in `dspa-gate.anchorOf`. Without it the
 *    2026-10-26 ledger burned 2 of 5 miss slots on `/tmp/snap-x/exa` and
 *    `/tmp/snap-x/gallop`, locations the floor had pinned.
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
 * section — a judge-side defect, kept so its rate is measurable). Two more
 * fields split the SAME disagreement by ROLE instead of location (3.43.0,
 * out of cwd only): roleFloorMisses (the judge reports a WRITE at a location
 * the floor knows but its write-role set does not cover — a parser role-table
 * gap) and roleJudgeMisses (the floor has an out-of-cwd write operand the
 * judge never claims as a write — the verdict reasoned about a write as if it
 * were a read, the common case being a report that leaves `writes` empty).
 * Attribution stays disjoint: a location the floor never derived is already a
 * floorMiss, the stronger fact.
 *
 * Wording: the name names the SUBJECT — `floorMisses` = paths the JUDGE
 * reported that the FLOOR never saw (the floor's blind spots), not misses
 * of the judge. Bare "miss" read as the judge missing something, which is
 * the opposite direction.
 * tools/log-inspect.mjs `dspa --paths` lists them.
 */
import { expandTilde, staticPrefixOf, under, isUnresolvedPath, isUnresolvedMarker } from "../analysis/path-util";
import { resolvePathReal } from "../analysis/path-analysis";
import type {PromptData} from "../decide/types";
import type { Store } from "../gate/store";
import { executedScriptPaths } from "../analysis/script-payload";
import type { JudgeResult } from "./judge";
import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import { sessionContextPaths } from "./session-context";

/**
 * Log economy: cap the STORED report and floor set. Enforcement and the §4.2
 * answer set are never capped — see the header.
 */
export const JUDGE_PATHS_MAX = 8;

/**
 * §4.5 (docs/dspa-intent-floor.md): a scheme-shaped token is not a location.
 * The sampled report sent `http://127.0.0.1:8080`, and `toAbs` resolved it
 * against the cwd into `<cwd>/http:/127.0.0.1:8080` (realpath collapses the
 * `//`) — a fake path under the operation's own base, absorbed by cwd
 * coverage in the diagnostic. Since 3.40.0 the damage is worse than a bogus
 * ledger line: that text also SATISFIES §4.2's answer-that-token guard for a
 * cwd-rooted miss, so a report defect could clear a stop. Dropped here, at
 * the single choke point every consumer shares (ledger, write bar, §4.2).
 */
const URL_SHAPED_RE = /^[a-z][a-z0-9+.-]*:\/\//i;

/** One path to absolute form: ~ expanded, relatives resolved against `cwd`,
 * `..` collapsed, THEN realpath'd (the floor's own paths are already
 * resolved — comparing lexically-normalized text against them would invent
 * a mismatch for every symlinked prefix, e.g. /tmp vs /private/tmp on
 * macOS). The resolution also faces the D19 write bar
 * (dspa-gate.judgeWriteOutside): an unresolved path under a symlink could
 * pass the bar while its real target sits outside it. */
function toAbs(p: string, cwd: string): string {
  return resolvePathReal(p.startsWith("~") ? expandTilde(p) : p, cwd);
}

/** Did the judge name this without a folder? (A `~` form names its own root.) */
function isRelativeReport(p: string): boolean {
  return !p.startsWith("/") && !p.startsWith("~") && !isUnresolvedMarker(p);
}

/** The candidate locations for ONE folderless report word: one per folder the
 *  command sat in. Shared by `sanitizeJudgePaths` (which emits them) and the
 *  coverage check below (which has to group a word's joins back together to
 *  tell an answered report from a blind spot). */
export function reportJoins(
  word: string,
  cwd: string,
  bases: readonly string[] = [],
): string[] {
  return [cwd, ...bases.filter((b) => b !== cwd)].map((b) => toAbs(word, b));
}

/**
 * The folders a command could have been sitting in (`docs/dspa-redesign.md`
 * — the judge-report join bases): the session cwd plus every base its own
 * `cd` chain set, unresolvable bases dropped. A report entry that carries no
 * folder has to be resolved against one, and the session cwd is the WRONG
 * answer for `cd X && …` (observed 2026-11-08 judge.jsonl: three rows named
 * paths under the SESSION cwd for files that never existed there). The set is the
 * honest form: the report is not attributed to a pipeline stage, so no single
 * base is knowable.
 *
 * An unresolvable base (D24: a `cd` inside a `||` chain, an opaque variable)
 * is dropped rather than counted as outside-everything: that command already
 * carries an unresolved miss of its own, so the location question is already
 * in front of the operator, and the bar cannot name a folder it cannot work
 * out.
 */
export function reportBases(pd: PromptData): string[] {
  if (pd.type !== "bash") return []; // only a shell command moves between folders
  const out = [pd.cwd];
  for (const c of pd.analysis?.effectiveCwds ?? []) {
    if (c && !isUnresolvedPath(c) && !out.includes(c)) out.push(c);
  }
  return out;
}

/**
 * Sanitize the model's raw report to concrete absolute paths: sentinels
 * dropped, ~ expanded, relatives resolved against the operation's cwd — or,
 * when `bases` gives more than one folder the command visited, against EVERY
 * of them, so the guess is visible as a set instead of hidden in one join —
 * deduped. NOT capped — the callers that enforce (the D19 write bar) and the
 * §4.2 answer set need every path the judge claimed; only the ledger rows
 * slice, and they record the remainder. Pure model text is never stored —
 * only this form.
 *
 * The two consumers read the multi-join set in opposite directions, and both
 * are correct because the set is complete:
 *  • the D19 write bar admits the report only when NO join falls outside the
 *    bar — a write it cannot place is a write it cannot allow (bar-only-
 *    narrows; a wrong join can cost a prompt, never an allow);
 *  • §4.2's "did the judge name this location" accepts when ANY join is the
 *    missed location — under a plausible base the judge did name it.
 */
export function sanitizeJudgePaths(
  reported: string[] | undefined,
  cwd: string,
  bases: readonly string[] = [],
): string[] {
  if (!reported) return [];
  const out: string[] = [];
  for (const raw of reported) {
    if (typeof raw !== "string") continue;
    const p = raw.trim();
    if (!p || isUnresolvedMarker(p) || URL_SHAPED_RE.test(p)) continue;
    if (isRelativeReport(p)) {
      for (const abs of reportJoins(p, cwd, bases)) {
        if (!out.includes(abs)) out.push(abs);
      }
      continue;
    }
    const abs = toAbs(p, cwd);
    if (!out.includes(abs)) out.push(abs);
  }
  return out;
}

/**
 * A reported path is COVERED by the floor's knowledge when it is a floor
 * path itself, lies under one, or is an ANCESTOR of one (2026-10-04, D23:
 * the judge named `/home/user/.pi/agent/extensions/memory` for a command
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
  return known.some((f) => under(p, f) || under(f, p));
}

export interface JudgePathReport {
  /** The model's touched paths, sanitized, uncapped (omitted when empty). */
  paths?: string[];
  /** Judge-reported paths not covered by the floor's knowledge — the
   *  floor's blind spots, including locations whose text the command carried
   *  and the parse did not mint (3.49.0). Uncapped (3.44.1): this list is the
   *  row's evidence (omitted when empty). */
  floorMisses?: string[];
  /** Misses that are only a STAGE-2 CONTEXT ECHO: the path is named in the
   *  Session context section (an earlier tool call's target, a path the user
   *  mentioned, a granted dir) AND the command text never carried it, so the
   *  judge had it in view without this operation reaching it (omitted when
   *  empty). Kept, never suppressed — the bleed rate is what makes the prompt
   *  fix measurable. A location the command's own text names belongs to
   *  `floorMisses` (3.49.0). */
  contextMisses?: string[];
  /** 3.43.0: the judge reports a WRITE at a location the floor DID derive,
   *  and the floor's write-role set does not cover it — the floor got the
   *  ROLE wrong (omitted when empty; see the role block in
   *  judgePathReport for the ownership split). */
  roleFloorMisses?: string[];
  /** 3.43.0: an out-of-cwd floor write operand with no judge-reported write
   *  covering it — the stage-2 verdict reasoned about a write as if it were a
   *  read, including a report that never populates `writes` (omitted when
   *  empty). */
  roleJudgeMisses?: string[];
  /** The judge's own words for a report path that had to be joined (a
   *  folderless name, resolved against more than one folder the command
   *  visited) — recorded so a miner can tell "the judge named a place" from
   *  "we guessed which place it meant" (omitted when every report was
   *  absolute, ~-rooted, or had exactly one base). */
  relativeReports?: string[];
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
  /** 3.43.0: the floor's WRITE-role operands (`analysis.writePaths` —
   *  `sed -i f`, `cp a d`, `mkdir d`, `> f`). Absent = no role comparison
   *  (the write set is what makes a role disagreement observable at all). */
  floorWritePaths?: string[];
  /** 3.49.0: the command as the operator typed it, code bodies included
   *  (`pd.command`). What makes the miss SPLIT honest: a location the command
   *  text itself names was available to the floor, so the row blames the
   *  floor, not the judge's Session context. */
  commandText?: string;
  /** The other folders the command sat in (`reportBases` minus the session
   *  cwd) — the bases a folderless report path is joined against. */
  cwdBases?: readonly string[];
}

/**
 * Cross-check one model report against the floor. `{}` when the model
 * reported nothing usable.
 *
 * @param writes - the stage-2 report's WRITE subset (JudgeResult.writes,
 *   D19); pass it to get the role comparison (3.43.0). Omit and the report
 *   carries only the set-level fields.
 */
export function judgePathReport(
  reported: string[] | undefined,
  floor: JudgePathFloor,
  writes?: string[],
): JudgePathReport {
  const paths = sanitizeJudgePaths(reported, floor.cwd, floor.cwdBases);
  if (paths.length === 0) return {};
  // A folderless report on a command that visited more than one folder is a
  // join we made, not a path the judge gave.
  const joinCount = 1 + new Set((floor.cwdBases ?? []).filter((b) => b !== floor.cwd)).size;
  const relativeReports =
    joinCount > 1 && reported
      ? [...new Set(reported.filter((p) => typeof p === "string" && isRelativeReport(p.trim())).map((p) => p.trim()))]
      : [];
  const floorConcrete = floor.floorPaths.filter((p) => !isUnresolvedPath(p));
  // The floor's pinned anchors: a floor path with a dynamic segment names a
  // DIRECTORY it does know (`/tmp/snap-x/$e` → `/tmp/snap-x`) even though it
  // cannot name the leaf. Same rule the gate applies to the same token
  // (`dspa-gate.anchorOf` / `staticPrefixOf`), so the diagnostic and the
  // enforcement agree about what the floor saw.
  const anchors = floorConcrete
    .map((p) => staticPrefixOf(p))
    .filter((a) => a !== "" && a !== "/" && !floorConcrete.includes(a));
  const known = [toAbs(floor.cwd, floor.cwd), ...(floor.confirmedDirs ?? []), ...floorConcrete, ...anchors];
  const misses = paths.filter((p) => !isCovered(p, known));
  // A join WE invented is not evidence. A folderless word on a multi-folder
  // command yields one candidate per folder the command sat in; the WORD is what
  // the judge said, and the row already carries it (`relativeReports`). Logging
  // the joins as blind spots would let our own guess manufacture floor misses —
  // two per word after a `cd`, half of them fiction (2026-11-13 round-7 audit;
  // the pre-fix ledger had no such entries because the cd base was never joined).
  const invented = new Set<string>();
  for (const word of relativeReports) {
    for (const j of reportJoins(word, floor.cwd, floor.cwdBases ?? [])) invented.add(j);
  }
  const blind = misses.filter((p) => !invented.has(p));
  // Context paths arrive as written in the session (relative, ~, `..`); they
  // must be compared in the same absolute form the report was sanitized to.
  const inContext = (floor.contextPaths ?? [])
    .map((c) => c.trim())
    .filter((c) => c !== "" && !isUnresolvedPath(c))
    .map((c) => toAbs(c, floor.cwd));
  // §4.4: with NO concrete location of its own, the floor cannot have been
  // out-of-date about a path it never derived — the cause is its own blindness,
  // so the row stays a floorMiss even when the path is named in the Session
  // context section. Re-classifying it as context bleed hid a parser gap
  // (observed 2026-10-18T03:02:28, the sweep.sh row).
  //
  // The other half of the same rule (3.49.0): a location whose TEXT the command
  // itself carries is not a context echo either. The Session context section
  // only explains a path the operation never mentioned; when the command's own
  // text — a code body's literal path, an operand the parse ignores — carries
  // the location, the row's owner is the floor, which had it in view and did not
  // mint it. Measured on the 26 contextMiss entries of the 2026-10-31 window: 7
  // carried their text in the command (a payload's `'/mnt/Ndr/Download/…jpg'`
  // string, the base a `cd` set), and each blamed the judge for a floor gap.
  const namedInCommand = (p: string): boolean =>
    floor.commandText !== undefined && floor.commandText.includes(p);
  const contextMisses =
    floorConcrete.length === 0
      ? []
      : blind.filter(
          (p) => !namedInCommand(p) && inContext.some((c) => under(p, c) || under(c, p)),
        );
  const floorMisses = blind.filter((p) => !contextMisses.includes(p));
  const r: JudgePathReport = { paths };
  if (floorMisses.length > 0) r.floorMisses = floorMisses;
  if (contextMisses.length > 0) r.contextMisses = contextMisses;
  if (relativeReports.length > 0) r.relativeReports = relativeReports;

  // ── 3.43.0: ROLE disagreement ────────────────────────────────────────────
  // The set comparison above asks "did the floor get the LOCATION wrong".
  // These two fields ask whether it got the ROLE wrong at a location it DOES
  // know — the floor and the judge can name the same place and disagree about
  // whether the command writes it, and today that disagreement writes no line
  // at all. Split by cause, one owner per field (attribution stays disjoint):
  //  • roleFloorMisses — the judge reports a write there, the floor's write set
  //    does not cover it: a missing write-verb / redirect role entry, the class
  //    the §4.1 redirect-target and D18/D21 baseWrite fixes were. Mine these to
  //    find role-table gaps the parser never surfaces (nothing stopped, because
  //    the READ bar admitted the location).
  //  • roleJudgeMisses — a floor write with no judge-reported write covering
  //    it, INCLUDING a report that never populates `writes` (the common model
  //    omission): the verdict argued about a write as if it were a read. The
  //    floor is not exposed here — its own write operands already face the write
  //    bar (dspa-gate.ts:1078) — this measures the judge's own reasoning.
  // Out of cwd only: writes inside the session cwd are the working set (no bar,
  // no grant involved), so a role gap there can change no outcome. Disjoint from
  // the set misses: a location the floor never derived is already a floorMiss —
  // the stronger fact, and the judge's raw writes list faces the write bar
  // regardless (judgeWriteOutside). Coverage uses isCovered in both directions,
  // the same ancestor-tolerant rule the gate's own writeRoleAt uses, so the log
  // describes the comparison the gate actually makes. Operand roles only: a base
  // write the floor derives via baseWriteAccess is not a writePaths entry.
  if (writes !== undefined || floor.floorWritePaths?.length) {
    const cwdAbs = toAbs(floor.cwd, floor.cwd);
    const floorWrites = (floor.floorWritePaths ?? []).filter((p) => !isUnresolvedPath(p));
    const judgeWrites = sanitizeJudgePaths(writes, floor.cwd, floor.cwdBases);
    const roleFloorMisses: string[] = [];
    for (const p of paths) {
      if (under(p, cwdAbs) || isCovered(p, misses)) continue;
      if (judgeWrites.length > 0 && isCovered(p, judgeWrites) && !isCovered(p, floorWrites)) {
        roleFloorMisses.push(p);
      }
    }
    const roleJudgeMisses = floorWrites.filter(
      (w) => !under(w, cwdAbs) && !isCovered(w, judgeWrites),
    );
    if (roleFloorMisses.length > 0) r.roleFloorMisses = roleFloorMisses;
    if (roleJudgeMisses.length > 0) r.roleJudgeMisses = roleJudgeMisses;
  }
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
  writes?: string[],
): {
  judgePaths?: string[];
  /** Report paths beyond the stored cap (only when the row is truncated). */
  judgePathsMore?: number;
  floorPaths?: string[];
  /** Floor paths beyond the stored cap (only when the row is truncated). */
  floorPathsMore?: number;
  floorMisses?: string[];
  contextMisses?: string[];
  roleFloorMisses?: string[];
  roleJudgeMisses?: string[];
  relativeReports?: string[];
} {
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
  const floorPaths = [...new Set([
    ...analysis.paths,
    ...(analysis.prompt.outsidePaths ?? []),
    ...executedScriptPaths(analysis, pd.cwd),
    // The bases the command itself set. A `cd` is knowledge: for `cd <dir> &&
    // git push` the judge reporting that directory is not a blind spot
    // (2026-10-31 ledger: the base a `cd` had set was logged as
    // `MISS: <that same base>`). Ledger-only, like `executedScriptPaths` — the
    // gate's coverage questions keep asking about operands, not the shell's cwd.
    ...analysis.effectiveCwds.filter((c): c is string => c !== null),
  ])];
  const bases = reportBases(pd);
  const r = judgePathReport(reported, {
    cwd: pd.cwd,
    cwdBases: bases.slice(1),
    floorPaths,
    confirmedDirs,
    contextPaths: ctx ? sessionContextPaths(ctx, store) : undefined,
    floorWritePaths: analysis.writePaths,
    commandText: pd.command,
  }, writes);
  // The economy cap lives HERE, at the row-writing site, and a cut row says so
  // — a silent cut hides a real blind spot (2026-10-26 judge.jsonl row: 12
  // reported paths, 8 stored, `/tmp/snap-x/memory` never recorded).
  const judgePaths = (r.paths ?? []).slice(0, JUDGE_PATHS_MAX);
  const judgePathsMore = (r.paths?.length ?? 0) - judgePaths.length;
  const storedFloorPaths = floorPaths.slice(0, JUDGE_PATHS_MAX);
  return {
    judgePaths,
    ...(judgePathsMore > 0 ? { judgePathsMore } : {}),
    floorPaths: storedFloorPaths,
    ...(floorPaths.length > storedFloorPaths.length
      ? { floorPathsMore: floorPaths.length - storedFloorPaths.length }
      : {}),
    floorMisses: r.floorMisses,
    contextMisses: r.contextMisses,
    roleFloorMisses: r.roleFloorMisses,
    roleJudgeMisses: r.roleJudgeMisses,
    relativeReports: r.relativeReports,
  };
}
