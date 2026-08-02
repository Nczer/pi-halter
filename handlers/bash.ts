import type { ExtensionContext, ToolCallEvent } from "@earendil-works/pi-coding-agent";
import { isToolCallEventType } from "@earendil-works/pi-coding-agent";
import type { BashRequest } from "../decision-engine";
import { gate, rejectBash } from "../gate";
import { store } from "../store";

export async function handleBash(
  event: ToolCallEvent,
  ctx: ExtensionContext,
) {
  if (!isToolCallEventType("bash", event)) return;
  // Fail closed on unexpected input shape: a direct MCP/custom tool named `bash`
  // (or a malformed builtin call) with no `command` string would otherwise pass
  // every handler unchecked and execute without a permission decision.
  const cmd = event.input?.command;
  if (typeof cmd !== "string" || cmd.trim().length === 0) {
    return {
      block: true,
      reason: "[Permission Policy] Built-in bash tool called with unexpected input shape — blocked (missing `command` string).",
    };
  }

  const request: BashRequest = { type: "bash", command: cmd, cwd: ctx.cwd };

  return await gate(request, ctx, store, (decision, result) =>
    rejectBash(decision, result, store, ctx),
  );
}
