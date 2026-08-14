import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import type { PermissionRequest, Decision } from "./decision-engine";
import { decide } from "./decision-engine";
import { showPrompt } from "./prompt-flow";
import type { Store } from "./store";

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
  const decision = precomputedDecision ?? await gateDecide(request, store, ctx);

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
    const result = await showPrompt(decision, ctx, store);
    if (!result.allowed) {
      return onReject(decision, result);
    }
  } finally {
    restoreTools(ctx);
  }

  return;
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
): Promise<Decision> {
  try {
    return await decide(request, store);
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
 * Common reject handler for MCP tool calls.
 * Formats reason with server/tool info, sends notification.
 */
export function rejectMcp(
  decision: Decision,
  result: PromptResult,
  store: Store,
  ctx: ExtensionContext,
): { block: true; reason: string } {
  if (decision.kind !== "prompt") return { block: true, reason: "Permission denied" };

  const pd = decision.promptData;
  if (pd.type !== "mcp") return { block: true, reason: "Permission denied" };

  const reasonDetail = result.reason ? ` Reason: ${result.reason}.` : "";

  ctx.ui.notify(`Permission denied: MCP tool '${pd.tool}'`, "error");

  return {
    block: true,
    reason: `[USER REJECTED] MCP tool '${pd.tool}' from server '${pd.server}' rejected.${reasonDetail}`,
  };
}
