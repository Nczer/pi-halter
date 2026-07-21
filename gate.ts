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
 */
export async function gate(
  request: PermissionRequest,
  ctx: ExtensionContext,
  store: Store,
  onReject: RejectHandler,
): Promise<undefined | { block: true; reason: string }> {
  const decision = await decide(request, store);

  if (decision.kind === "auto-allow") return;

  if (decision.kind === "block") {
    return { block: true, reason: decision.reason };
  }

  // No UI available — block
  if (!ctx.hasUI) {
    return { block: true, reason: "[Permission Policy] Auto-blocked (no UI): requires confirmation" };
  }

  const wasExpanded = ctx.ui.getToolsExpanded();
  if (!wasExpanded) ctx.ui.setToolsExpanded(true);

  try {
    const result = await showPrompt(decision, ctx, store);
    if (!result.allowed) {
      return onReject(decision, result);
    }
  } finally {
    ctx.ui.setToolsExpanded(wasExpanded);
  }

  return;
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
    reason: `[USER REJECTED] You denied this bash command: ${pd.command.slice(0, 120)}.${detail}${reasonDetail}`,
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
    reason: `[USER REJECTED] You denied ${action} access to ${pd.filePath.split("/").pop() || pd.filePath} (${resolved}).${reasonDetail}`,
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
    reason: `[USER REJECTED] You denied MCP tool '${pd.tool}' from server '${pd.server}'.${reasonDetail}`,
  };
}
