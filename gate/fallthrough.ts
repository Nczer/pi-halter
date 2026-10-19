/**
 * dspa fall-through — the /dspa auto-allow attempt and the data the
 * prompt carries when it declines (gate/fallthrough.ts).
 *
 * /dspa is the automatic counterpart of /dspat: an operation that passes
 * the deterministic hard gate (dspa-gate.ts) AND gets an approving judge
 * verdict within the stage's risk authority runs without a prompt.
 * Everything else falls through to the normal prompt — `DspaFallthrough`
 * is the WHY that prompt shows (gate reason and/or judge verdict).
 *
 * This module is the producer of DspaFallthrough (gate.ts attempts the
 * auto-allow, ui/prompt-flow.ts renders it) — the type lives here so the
 * UI layer imports it from the gate, not the other way around.
 */
import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import type {PermissionRequest, Decision, PromptData} from "../decide/types";
import type { Store } from "./store";
import { logDecision, logJudgeDiff, logJudgePaths, logUnresolved } from "./decision-log";
import { findExecutedScript } from "../analysis/script-payload";
import { checkDspaGate, hasFileScriptOutsideCwd, judgeWriteOutside, intentGuardFaults, type DspaGateResult, type MissFact } from "./dspa-gate";
import { sanitizeJudgePaths } from "../judge/paths";
import {getJudgeVerdict, getStage2Verdict, getStage1Outcome, getStage2Outcome, judgeFailPhrase, judgeStatus} from "../judge/verdict";
import { judgePathLogFields } from "../judge/paths";
import { pdTargetLabel } from "../ui/prompt-builder";
import { recordDspaAutoAllowed, recordDspaStop, updateDspaWidget, type DspaStopKind } from "../modes/dspa-mode";
import type {JudgeResult} from "../judge/judge";

/**
 * Carried into showPrompt when /dspa declined to auto-allow, so the
 * fall-through prompt explains WHY (gate reason and/or judge verdict).
 */
export interface DspaFallthrough {
  gate: DspaGateResult;
  /** The FINAL verdict — stage 2 when it rendered one, else stage 1. */
  verdict: JudgeResult | null;
  /** Stage of the carried verdict (1 = stateless, 2 = intent pass); null = no verdict. */
  stage: 1 | 2 | null;
  /** Set when the gate passed but a judge stage produced no verdict — why. */
  note?: string;
  /** judge()'s typed class for the stage-2 failure (`timeout 8.0s`), when the
   *  intent pass produced none but stage 1 did — the ledger tag needs it,
   *  because "stage 2 fails while the server is up" is otherwise unmeasurable. */
  judgeFail?: string;
}

/**
 * The dspa stop-tag for the decision log: which layer stopped the
 * auto-allow — the deterministic hard gate (its code-produced reason is
 * safe to accumulate) or the judge (only the declined/failed fact; a
 * REJECT's explanation is logged separately via dspaJudgeDeny as a debug
 * aid — verdict stats stay session-scoped by design).
 * The stage is plumbing (which judge layer decided), not verdict content:
 *  - `judge: declined (stage 2)` — the intent pass rendered a verdict that
 *    did not auto-allow (the final call on the operation);
 *  - `judge: stage 2 failed (timeout 8.0s)` — the stateless pass rendered a
 *    verdict but the intent pass produced none (timeout/auth/model — an infra
 *    fact, typed by judge());
 *  - `judge: <note>` — no verdict at all.
 * undefined outside dspa prompt fall-throughs.
 */
export function dspaStopTag(f: DspaFallthrough | undefined): string | undefined {
  if (!f) return undefined;
  if (!f.gate.ok) return `gate: ${f.gate.reason}`;
  if (f.verdict) {
    if (f.stage === 2) return "judge: declined (stage 2)";
    return `judge: stage 2 failed${f.judgeFail ? ` (${f.judgeFail})` : ""}`;
  }
  return `judge: ${f.note ?? "no verdict"}`;
}

/**
 * The LLM's reject words for the decision log (the NOTE's debug exception
 * in decision-log.ts): the FINAL verdict's explanation when it is a
 * REJECT. Which layer stopped first does not matter for debugging the
 * judge — the stop tag already says that; this is what the model said.
 */
export function dspaJudgeDeny(f: DspaFallthrough | undefined): string | undefined {
  if (!f?.verdict || f.verdict.approve !== "deny") return undefined;
  return f.verdict.explanation;
}

/** Record + surface one dspa auto-allow (D6: the log reason carries the
 * stage — which judge layer approved — and the model that rendered it). */
export function dspaAutoAllowed(
  request: PermissionRequest,
  pd: PromptData,
  ctx: ExtensionContext,
  store: Store,
  verdict: JudgeResult,
  stage: 1 | 2,
  misses?: MissFact[],
): void {
  // D13: a stage-2 auto-allow logs the judge's path report (and any path
  // the floor never saw) — the parser-gap probe. Stage 1 never reports.
  const jp = stage === 2 ? judgePathLogFields(pd, store, verdict.paths, ctx) : {};
  logDecision(
    request,
    { kind: "auto-allow", reason: misses
      ? `dspa: intent over miss stop (${[...new Set(misses.map((m) => m.kind))].join("+")}, ${verdict.model})`
      : `dspa: judge approved (stage ${stage}, ${verdict.model})` },
    "dspa", undefined, undefined, jp.judgePaths, jp.floorMisses,
  );
  // D17: the same path report also goes to the on-by-default judge ledger
  // (decisions.jsonl is toggle-gated and version-bound; the ledger is the
  // durable home for D13 mining).
  if (stage === 2) {
    logJudgePaths(pd, store, verdict, "dspa", ctx);
  }
  // Unresolved-token log: an auto-allow of a command WITH unresolved tokens
  // — either their resolutions were already user-confirmed (the convergence
  // end-state, persisted) or the floor passed on bounded candidates with no
  // confirmed resolution (judge-absorbed, not persisted — it re-logs on the
  // next identical command, which is the honest signal).
  if (misses) {
    // The intent path logs its own line per unknown location (§7) — the more
    // specific outcome tag replaces the generic one, and D-f's no-toggle
    // promise depends on these rows being in the ledger.
    logIntentMisses(pd, misses, "intent-allowed");
  } else if (pd.type === "bash" && pd.unresolved?.length) {
    for (const u of pd.unresolved) {
      const confirmed = store.getConfirmedResolution(u.token);
      logUnresolved({
        cmd: pd.command,
        cwd: pd.cwd,
        token: u.token,
        llm: confirmed ?? undefined,
        persisted: (confirmed?.length ?? 0) > 0,
        outcome: "auto-allowed",
        decision: "auto-allow",
      });
    }
  }
  try {
    ctx.ui.notify(`✓ Stage ${stage}: ${verdict.explanation}`, "info");
  } catch {
    /* toast must never break the allow */
  }
  recordDspaAutoAllowed(verdict.model, pdTargetLabel(pd));
  updateDspaWidget(ctx);
}

/**
 * One convergence-ledger line per unknown location an intent verdict was
 * asked about (§7, docs/dspa-intent-floor.md): `intent-allowed` is a stop the
 * verdict cleared, `intent-declined` a guard or verdict that kept it. The
 * manual path's rows stay unchanged, so the deterministic fix work keeps a
 * live corpus; these rows are how a bad class shows up without a toggle (D-f).
 */
function logIntentMisses(
  pd: PromptData,
  misses: MissFact[],
  outcome: "intent-allowed" | "intent-declined",
  guard?: string,
): void {
  if (pd.type !== "bash") return;
  for (const m of misses) {
    logUnresolved({
      cmd: pd.command,
      cwd: pd.cwd,
      token: m.token,
      persisted: false,
      outcome,
      decision: outcome === "intent-allowed" ? "auto-allow" : undefined,
      missKind: m.kind,
      guard,
    });
  }
}

/**
 * The D19/D-g write bar on a fresh stage-2 report: a reported write outside
 * the manual write bar synthesizes the exact D18 advisory stop, so the
 * `Allow writes` option and the post-grant steady state work unchanged. One
 * shape for both call sites (the gate-passed path and the intent-over-miss
 * path) so the reason text cannot drift.
 */
function writeOutsideStop(
  pd: PromptData,
  store: Store,
  writes: string[] | undefined,
): { ok: false; advisory: true; reason: string; writeOutside: string[] } | null {
  const out = judgeWriteOutside(pd, store, writes);
  if (out.length === 0) return null;
  return {
    ok: false,
    advisory: true,
    reason: `write outside base (${out.slice(0, 2).join(", ")})`,
    writeOutside: out,
  };
}

/**
 * §3/§4 (docs/dspa-intent-floor.md): intent over a MISS stop — the location
 * the floor could not name goes to the intent pass to BECOME a location, and
 * the guards decide whether the verdict may clear the stop. Stage 1 is not
 * run: it is the stateless pass, eval-locked out of path reports
 * (judge/judge.ts), so it cannot answer the question this stop asks. One
 * stage-2 call replaces the stage-1 call these rows used to spend (D22's skip
 * inverted; §3.4 accepts the uncached cost as cheaper than a prompt).
 * D-g's invariant is preserved on the way out: the union set faces the WRITE
 * bar with no leniency, so an out-of-bar write still produces the same
 * `Allow writes` prompt.
 */
async function tryIntentOverMiss(
  request: PermissionRequest,
  pd: Extract<PromptData, { type: "bash" }>,
  ctx: ExtensionContext,
  store: Store,
  gateResult: DspaGateResult,
): Promise<{ autoAllowed: boolean; fallthrough: DspaFallthrough }> {
  const misses = gateResult.ok ? [] : gateResult.misses ?? [];
  const o2 = await getStage2Outcome(pd, ctx, store);
  const v2 = o2.verdict;
  logJudgeDiff(pd, "dspa", null, v2);
  // A decline is the FLOOR's stop standing — same counters and same prompt
  // shape as the D16 advisory path, plus the stage-2 verdict when it ran.
  const stop = (
    why: string,
    gate: DspaGateResult,
    verdict: JudgeResult | null,
    bucket: DspaStopKind,
  ): { autoAllowed: false; fallthrough: DspaFallthrough } => {
    logIntentMisses(pd, misses, "intent-declined", why);
    recordDspaStop(bucket, verdict?.model ?? o2.model ?? null);
    updateDspaWidget(ctx);
    return { autoAllowed: false, fallthrough: { gate, verdict, stage: verdict ? 2 : null } };
  };
  // Any judge failure resolves to the prompt — never an allow.
  if (!v2) return stop("no verdict", gateResult, null, "gate");
  // D-g: the judge's own write report faces the write bar first.
  const wStop = writeOutsideStop(pd, store, v2.writes);
  if (wStop) return stop(`reported write outside the write bar (${wStop.writeOutside.join(", ")})`, wStop, v2, "gate");
  // The verdict's own authority comes before the §4 guards: the ledger's
  // `guard` field names what DECIDED, and a denial decides by itself.
  const authorized = v2.approve === "approve" && (v2.risk === "low" || v2.risk === "medium");
  if (!authorized) {
    return stop(
      `stage 2 ${v2.approve}${v2.risk ? ` (${v2.risk})` : ""}`,
      gateResult,
      v2,
      v2.approve === "deny" ? "deny" : v2.approve === "defer" ? "defer" : "declined",
    );
  }
  const faults = intentGuardFaults(misses, sanitizeJudgePaths(v2.paths, pd.cwd));
  if (faults.length > 0) return stop(faults.join("; "), gateResult, v2, "gate");
  // The judge-ledger paths line stays reserved for what RAN THROUGH the
  // floor (D17): a declined attempt never executed, so its report rides the
  // prompt's decision line only — the parser-gap probe must not fill with stops.
  logJudgePaths(pd, store, v2, "dspa", ctx);
  dspaAutoAllowed(request, pd, ctx, store, v2, 2, misses);
  return { autoAllowed: true, fallthrough: { gate: gateResult, verdict: v2, stage: 2 } };
}

/**
 * Two-stage dspa attempt (docs/dspa-redesign.md, D2/Q4):
 *  1. Hard gate (dspa-gate.ts) — the floor; failure → advisory
 *     fall-through (D16/D22): stage 1 runs and its verdict renders in
 *     the prompt; stage 2 only when stage 1 did not approve.
 *  2. Stage 1 (stateless, cached): approve+low → auto-allow. Skipped
 *     entirely for a bash command that executes a file script (T3,
 *     content-classes: the class always escalates, so stage 1 would only
 *     add a call — the script content already rides in the stage-2 packet).
 *  3. Stage 2 (reasoning-blind session context, uncached): runs when stage
 *     1 did not auto-allow (or immediately for script payloads);
 *     approve+{low, medium} → auto-allow. Its verdict is final —
 *     approve+high and reject never auto-allow (phase 2: both
 *     still prompt; the phase-3 denial flow changes only the destination).
 * Any judge failure resolves to fall-through — never an allow.
 */
export async function tryDspaAutoAllow(
  request: PermissionRequest,
  decision: Extract<Decision, { kind: "prompt" }>,
  ctx: ExtensionContext,
  store: Store,
): Promise<{ autoAllowed: boolean; fallthrough: DspaFallthrough }> {
  const pd = decision.promptData;
  const gateResult = await checkDspaGate(pd, store);
  if (!gateResult.ok) {
    // D-g/§3 (docs/dspa-intent-floor.md): a MISS stop — one whose locations
    // the floor could not name — is the one stop class intent may clear.
    // Only a bash command can carry misses (every miss site is in the bash
    // path analysis), hence the type guard alongside.
    if (pd.type === "bash" && gateResult.misses?.length) {
      return await tryIntentOverMiss(request, pd, ctx, store, gateResult);
    }
    // D16 (docs/dspa-redesign.md): EVERY floor stop is advisory — the
    // judge still runs and its verdict renders in the prompt as input to
    // the allow/deny/grant decision. D22: stage 2 is skipped when stage 1
    // already approved — the stop stands either way, so the intent pass
    // (session context) would only add a sequential call, never change
    // the outcome. Never an auto-allow: the floor's stop stands. (A bare
    // stop — no judge call — is the defensive fallback below; the gate
    // currently never emits one.)
    if (gateResult.advisory) {
      const v1 = await getJudgeVerdict(pd, ctx, store);
      const v2 = v1 && v1.approve === "approve"
        ? null
        : await getStage2Verdict(pd, ctx, store);
      // Judge-self disagreement is still logged (the judge ran, whatever
      // the floor's stop) — but NO paths line: the floor stopped the
      // command, so the miss never ran through the floor. The ledger
      // records faults that ran through; the prompt's decision line still
      // carries the report (gate.ts).
      logJudgeDiff(pd, "dspa", v1, v2);
      const final = (v2 ?? v1) ?? null;
      // The stop is the FLOOR's (any verdict here is advisory) — count it as
      // a gate stop, with the verdict's model for counter scoping.
      recordDspaStop("gate", final?.model ?? null);
      updateDspaWidget(ctx);
      return {
        autoAllowed: false,
        fallthrough: {
          gate: gateResult,
          verdict: final,
          stage: v2 ? 2 : v1 ? 1 : null,
        },
      };
    }
    recordDspaStop("gate", null);
    updateDspaWidget(ctx);
    return { autoAllowed: false, fallthrough: { gate: gateResult, verdict: null, stage: null } };
  }
  // T3 (content-classes): a bash command that executes a file script (the
  // D3/D11 identification) skips stage 1 — the class always escalates,
  // so stage 1 would only add a call; stage 2 (low|medium) is the
  // authority. Absent analysis (hand-constructed prompt data) → no skip
  // (the conservative direction: an extra call, never a skipped judge).
  const skipStage1 =
    pd.type === "bash" && pd.analysis != null &&
    findExecutedScript(pd.analysis, pd.cwd) !== null;
  // Stage 1 — stateless (the packet's static analysis is the whole input).
  const o1 = skipStage1 ? null : await getStage1Outcome(pd, ctx, store);
  const v1 = o1?.verdict ?? null;
  // D19: a file script OUTSIDE the working set never auto-allows here —
  // its writes surface only in the stage-2 report, which the write bar
  // checks in the same pass (the stateless pass is eval-locked out of
  // path reports). Deterministic + LLM from the first run.
  if (v1 && v1.approve === "approve" && v1.risk === "low" && !hasFileScriptOutsideCwd(pd)) {
    dspaAutoAllowed(request, pd, ctx, store, v1, 1);
    return { autoAllowed: true, fallthrough: { gate: gateResult, verdict: v1, stage: 1 } };
  }
  // Stage 2 — intent pass (session context, uncached, final verdict).
  const o2 = await getStage2Outcome(pd, ctx, store);
  const v2 = o2.verdict;
  logJudgeDiff(pd, "dspa", v1, v2);
  // D19: the deterministic write bar on the judge's FRESH write report —
  // same pass, first run included, nothing learned or persisted. A
  // reported write outside the manual write bar synthesizes the exact
  // D18 advisory stop: no auto-allow, the prompt carries the verdict +
  // the `Allow writes` option, and after the grant the identical run
  // re-reports the same writes — now inside the bar — and auto-allows.
  const writeStop = writeOutsideStop(pd, store, v2?.writes);
  if (writeStop) {
    // D17: the report RAN THROUGH the floor — the ledger line stands
    // (each stage-2 verdict logs exactly once; the auto-allow and the
    // judge-declined branches below log their own).
    logJudgePaths(pd, store, v2!, "dspa", ctx);
    // The stop is the write bar's (the floor layer) — count it as a gate
    // stop, with the verdict's model for counter scoping.
    recordDspaStop("gate", v2?.model ?? v1?.model ?? null);
    updateDspaWidget(ctx);
    return {
      autoAllowed: false,
      fallthrough: { gate: writeStop, verdict: (v2 ?? v1) ?? null, stage: v2 ? 2 : v1 ? 1 : null },
    };
  }
  if (v2 && v2.approve === "approve" && (v2.risk === "low" || v2.risk === "medium")) {
    dspaAutoAllowed(request, pd, ctx, store, v2, 2);
    return { autoAllowed: true, fallthrough: { gate: gateResult, verdict: v2, stage: 2 } };
  }
  // Gate passed but neither stage auto-allowed. The fall-through prompt
  // carries the FINAL verdict (stage 2 when it rendered one); when a stage
  // produced no verdict, say WHY so the prompt is never silently bare.
  const final = (v2 ?? v1) ?? null;
  // D17: stage-2 path report → on-by-default judge ledger (the auto-allow
  // branch logs it in dspaAutoAllowed, the write-stop branch above logs
  // its own — each stage-2 verdict exactly once).
  if (v2) {
    logJudgePaths(pd, store, v2, "dspa", ctx);
  }
  let note: string | undefined;
  if (!v2 && !v1) {
    const jstatus = judgeStatus(ctx);
    // The typed class from judge() (timeout / call-failed / auth / bad reply),
    // not a guess: "stage 2 fails while the server is up" is only diagnosable
    // if the prompt says which kind of failure it was.
    const why = judgeFailPhrase(o2) || judgeFailPhrase(o1);
    const stop = skipStage1
      ? "stage 2 call failed (stage 1 skipped — script payload)"
      : "judge call failed";
    note = jstatus.state === "invalid"
      ? `judge invalid: ${jstatus.reason}`
      : `${stop}${why ? ` (${why})` : ""}`;
  } else if (v1 && !v2) {
    const why = judgeFailPhrase(o2);
    note = `stage 2 produced no verdict${why ? ` (${why})` : ""} — stateless stage-1 verdict only`;
  }
  const judgeFail = v1 && !v2 ? judgeFailPhrase(o2) || undefined : undefined;
  // The judge (or its absence) is the stop here: classify by the FINAL
  // verdict — no verdict at all joins the defer (fail-safe) bucket.
  recordDspaStop(
    final === null ? "defer" : final.approve === "deny" ? "deny" : final.approve === "defer" ? "defer" : "declined",
    final?.model ?? null,
  );
  updateDspaWidget(ctx);
  return {
    autoAllowed: false,
    fallthrough: { gate: gateResult, verdict: final, stage: v2 ? 2 : v1 ? 1 : null, note, judgeFail },
  };
}
