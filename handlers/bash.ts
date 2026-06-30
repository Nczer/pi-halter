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
  const cmd = event.input.command;
  if (!cmd || cmd.trim().length === 0) return;

  const request: BashRequest = { type: "bash", command: cmd, cwd: ctx.cwd };

  return await gate(request, ctx, store, (decision, result) =>
    rejectBash(decision, result, store, ctx),
  );
}
