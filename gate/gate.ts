import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import type {PermissionRequest, Decision, DecideOptions} from "../decide/types";
import {decide} from "../decide/engine";
import { logDecision, type DspModeTag } from "./decision-log";
import { showPrompt } from "../ui/prompt-flow";
import type { Store } from "./store";
import { isDspaActive } from "../modes/dspa-mode";
import { isDspatActive } from "../modes/dspat-mode";
import { tryDspaAutoAllow, dspaStopTag, dspaJudgeDeny, type DspaFallthrough } from "./fallthrough";
import { applyDspaConversions } from "./conversions";
import { judgePathLogFields } from "../judge/paths";

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

  // D3/D11 (docs/dspa-redesign.md): in dspa, reviewable manual auto-allows
  // are content-judged, not blind auto-allows — the location / command form
  // is trusted, the content goes through the same two-stage judge as a
  // prompt (gate/conversions.ts). An explicit SESSION GRANT is the user's
  // own decision about that location and stays auto-allowed. Judge
  // off/invalid → no conversion (dspa never adds a prompt on its own).
  decision = await applyDspaConversions(request, decision, store, ctx);

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
    const result = await showPrompt(decision, ctx, store, dspaFallthrough, request);
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

