import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import type { SubagentRequest } from "../decision-engine";
import { decide } from "../decision-engine";
import { showPrompt } from "../prompt-flow";
import { store } from "../store";

export async function handleSubagent(
  event: { toolName: string; input: { agent?: string; tasks?: Array<{ agent?: string }> } },
  ctx: ExtensionContext,
) {
  if (event.toolName !== "subagent") return;

  const agent = event.input.agent as string | undefined;
  const tasks = event.input.tasks as Array<{ agent?: string; paths?: string[]; task?: string }> | undefined;
  const paths = event.input.paths as string[] | undefined;
  const agentNames: string[] = tasks
    ? tasks.map((t: { agent?: string }) => t.agent).filter((x): x is string => !!x)
    : agent
      ? [agent]
      : [];

  if (agentNames.length === 0) return;

  // For parallel mode, collect all paths from individual tasks
  const mergedPaths = tasks
    ? [...new Set((tasks as Array<{ paths?: string[] }>).flatMap(t => t.paths || []))]
    : paths;

  // Extract task description(s) for display
  const task = agent
    ? (event.input.task as string | undefined)
    : tasks
      ? tasks.map((t: { task?: string }) => t.task).filter(Boolean).join(" \n")
      : undefined;

  const request: SubagentRequest = { type: "subagent", agentNames, paths: mergedPaths, task };
  const decision = await decide(request, store);

  // Auto-allow: proceed without prompting
  if (decision.kind === "auto-allow") return;

  // Block: no prompt shown
  if (decision.kind === "block") {
    return { block: true, reason: decision.reason };
  }

  // No UI available — block
  if (!ctx.hasUI) {
    return { block: true, reason: "[Permission Policy] Auto-blocked (no UI): subagent spawning requires confirmation" };
  }

  const wasExpanded = ctx.ui.getToolsExpanded();
  if (!wasExpanded) ctx.ui.setToolsExpanded(true);

  try {
    const result = await showPrompt(decision, ctx, store);
    if (!result.allowed) {
      const pd = decision.promptData;
      const names = pd.type === "subagent" ? pd.agentNames : [];
      const agentsDisplay = names.length > 1 ? names.join(", ") : (names[0] ?? "unknown");
      const reasonDetail = result.reason ? ` Reason: ${result.reason}.` : "";
      ctx.ui.notify("Permission denied: subagent spawning", "error");
      return { block: true, reason: `[USER REJECTED] You denied subagent spawning for: ${agentsDisplay}.${reasonDetail}` };
    }
  } finally {
    ctx.ui.setToolsExpanded(wasExpanded);
  }

  return;
}
