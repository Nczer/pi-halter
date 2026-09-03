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
import { checkDspaGate, type DspaGateResult } from "./dspa-gate";
import {getJudgeVerdict, getStage2Verdict, judgeStatus} from "../judge/verdict";
import { judgePathLogFields } from "../judge/paths";
import { pdTargetLabel } from "../ui/prompt-builder";
import { recordDspaAutoAllowed, recordDspaStop, updateDspaWidget } from "../modes/dspa-mode";
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
 *  - `judge: stage 2 failed` — the stateless pass rendered a verdict but
 *    the intent pass produced none (timeout/auth/model — an infra fact);
 *  - `judge: <note>` — no verdict at all.
 * undefined outside dspa prompt fall-throughs.
 */
export function dspaStopTag(f: DspaFallthrough | undefined): string | undefined {
  if (!f) return undefined;
  if (!f.gate.ok) return `gate: ${f.gate.reason}`;
  if (f.verdict) return f.stage === 2 ? "judge: declined (stage 2)" : "judge: stage 2 failed";
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
): void {
  // D13: a stage-2 auto-allow logs the judge's path report (and any path
  // the floor never saw) — the parser-gap probe. Stage 1 never reports.
  const jp = stage === 2 ? judgePathLogFields(pd, store, verdict.paths) : {};
  logDecision(request, { kind: "auto-allow", reason: `dspa: judge approved (stage ${stage}, ${verdict.model})` }, "dspa", undefined, undefined, jp.judgePaths, jp.judgePathMisses);
  // D17: the same path report also goes to the always-on judge ledger
  // (decisions.jsonl is toggle-gated and version-bound; the ledger is the
  // durable home for D13 mining).
  if (stage === 2) logJudgePaths(pd, store, verdict, "dspa");
  // Unresolved-token log: an auto-allow of a command WITH unresolved tokens
  // means their resolutions were already user-confirmed — the convergence
  // end-state (no prompt, no LLM call for the scope).
  if (pd.type === "bash" && pd.unresolved?.length) {
    for (const u of pd.unresolved) {
      logUnresolved({
        cmd: pd.command,
        cwd: pd.cwd,
        token: u.token,
        llm: store.getConfirmedResolution(u.token) ?? undefined,
        persisted: true,
        outcome: "auto-allowed",
        decision: "auto-allow",
      });
    }
  }
  try {
    ctx.ui.notify(`✓ Judge auto-allowed (stage ${stage}): ${verdict.explanation}`, "info");
  } catch {
    /* toast must never break the allow */
  }
  recordDspaAutoAllowed(verdict.model, pdTargetLabel(pd));
  updateDspaWidget(ctx);
}

/**
 * Two-stage dspa attempt (docs/dspa-redesign.md, D2/Q4):
 *  1. Hard gate (dspa-gate.ts) — the floor; failure → fall-through.
 *  2. Stage 1 (stateless, cached): approve+low → auto-allow.
 *  3. Stage 2 (reasoning-blind session context, uncached): runs when stage
 *     1 did not auto-allow; approve+{low, medium} → auto-allow. Its verdict
 *     is final — approve+high and reject never auto-allow (phase 2: both
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
    // D16 (docs/dspa-redesign.md): EVERY floor stop is advisory — the
    // judge still runs both stages and its verdict renders in the prompt
    // as input to the allow/deny/grant decision. Never an auto-allow: the
    // floor's stop stands. (A bare stop — no judge call — is the
    // defensive fallback below; the gate currently never emits one.)
    if (gateResult.advisory) {
      const v1 = await getJudgeVerdict(pd, ctx, store);
      const v2 = await getStage2Verdict(pd, ctx, store);
      logJudgeDiff(pd, "dspa", v1, v2);
      if (v2) logJudgePaths(pd, store, v2, "dspa");
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
  // Stage 1 — stateless (the packet's static analysis is the whole input).
  const v1 = await getJudgeVerdict(pd, ctx, store);
  if (v1 && v1.approve === "approve" && v1.risk === "low") {
    dspaAutoAllowed(request, pd, ctx, store, v1, 1);
    return { autoAllowed: true, fallthrough: { gate: gateResult, verdict: v1, stage: 1 } };
  }
  // Stage 2 — intent pass (session context, uncached, final verdict).
  const v2 = await getStage2Verdict(pd, ctx, store);
  logJudgeDiff(pd, "dspa", v1, v2);
  if (v2 && v2.approve === "approve" && (v2.risk === "low" || v2.risk === "medium")) {
    dspaAutoAllowed(request, pd, ctx, store, v2, 2);
    return { autoAllowed: true, fallthrough: { gate: gateResult, verdict: v2, stage: 2 } };
  }
  // Gate passed but neither stage auto-allowed. The fall-through prompt
  // carries the FINAL verdict (stage 2 when it rendered one); when a stage
  // produced no verdict, say WHY so the prompt is never silently bare.
  const final = (v2 ?? v1) ?? null;
  // D17: stage-2 path report → always-on judge ledger (the auto-allow
  // branch logs it in dspaAutoAllowed — each stage-2 verdict exactly once).
  if (v2) logJudgePaths(pd, store, v2, "dspa");
  let note: string | undefined;
  if (!v2 && !v1) {
    const jstatus = judgeStatus(ctx);
    note = jstatus.state === "invalid" ? `judge invalid: ${jstatus.reason}` : "judge call failed";
  } else if (v1 && !v2) {
    note = "stage 2 produced no verdict — stateless stage-1 verdict only";
  }
  // The judge (or its absence) is the stop here: classify by the FINAL
  // verdict — no verdict at all joins the defer (fail-safe) bucket.
  recordDspaStop(
    final === null ? "defer" : final.approve === "deny" ? "deny" : final.approve === "defer" ? "defer" : "declined",
    final?.model ?? null,
  );
  updateDspaWidget(ctx);
  return {
    autoAllowed: false,
    fallthrough: { gate: gateResult, verdict: final, stage: v2 ? 2 : v1 ? 1 : null, note },
  };
}
