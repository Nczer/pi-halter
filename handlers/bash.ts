import type { ExtensionContext, ToolCallEvent } from "@earendil-works/pi-coding-agent";
import { isToolCallEventType } from "@earendil-works/pi-coding-agent";
import type { BashRequest } from "../decision-engine";
import { decide } from "../decision-engine";
import { showPrompt } from "../prompt-flow";
import { store } from "../store";

export async function handleBash(
  event: ToolCallEvent,
  ctx: ExtensionContext,
) {
  if (!isToolCallEventType("bash", event)) return;
  const cmd = event.input.command;
  if (!cmd || cmd.trim().length === 0) return;

  const request: BashRequest = { type: "bash", command: cmd, cwd: ctx.cwd };
  const decision = await decide(request, store);

  // Auto-allow: proceed without prompting
  if (decision.kind === "auto-allow") return;

  // Block: no prompt shown
  if (decision.kind === "block") {
    return { block: true, reason: decision.reason };
  }

  // No UI available — block
  if (!ctx.hasUI) {
    return { block: true, reason: "[Permission Policy] Auto-blocked (no UI): Bash command requires confirmation" };
  }

  const wasExpanded = ctx.ui.getToolsExpanded();
  if (!wasExpanded) ctx.ui.setToolsExpanded(true);

  try {
    const result = await showPrompt(decision, ctx, store);
    if (!result.allowed) {
      store.recordAbort(cmd);
      const pd = decision.promptData;
      const isBash = pd.type === "bash";
      const detail = isBash && pd.riskDangerous
        ? ` Danger flags: ${pd.riskReasons.join(", ")}.`
        : "";
      const reasonDetail = result.reason ? ` Reason: ${result.reason}.` : "";
      ctx.ui.notify(`Permission denied: ${isBash && pd.riskDangerous ? "dangerous " : ""}bash command`, "error");
      return { block: true, reason: `[USER REJECTED] You denied this bash command: ${cmd.slice(0, 120)}.${detail}${reasonDetail}` };
    }
  } finally {
    ctx.ui.setToolsExpanded(wasExpanded);
  }

  return;
}
