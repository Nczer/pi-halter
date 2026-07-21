import type { ExtensionContext, ToolCallEvent } from "@earendil-works/pi-coding-agent";
import { isToolCallEventType } from "@earendil-works/pi-coding-agent";
import type { McpRequest } from "../decision-engine";
import { gate, rejectMcp } from "../gate";
import { store } from "../store";
import { resolveServerFromToolName, deriveProxyTarget, METADATA_OPS } from "../analysis/mcp-resolver";
import { formatMcpProxyToolCallLines, formatMcpDirectToolCallLines, buildArgsPreview } from "../renderers/mcp";

// ── Handlers ───────────────────────────────────────────────────────────

/**
 * Handle MCP proxy tool calls (mcp({ tool: "...", args: "..." })).
 * Auto-allows metadata operations (status, list, search, describe, connect).
 * Prompts for tool invocations.
 */
export async function handleMcp(
  event: ToolCallEvent,
  ctx: ExtensionContext,
) {
  if (!isToolCallEventType("mcp", event)) return;

  const params = event.input ?? {};
  const { server, tool, op } = deriveProxyTarget(params);

  // Metadata operations are always allowed
  if (METADATA_OPS.has(op)) return;

  // Only tool calls need permission
  if (op !== "call") return;

  const callLabel = formatMcpProxyToolCallLines(params, 1500, false).join(": ");
  const argsPreview = buildArgsPreview(params);

  // Resolve server from tool name if not explicitly provided
  const resolvedServer = resolveServerFromToolName(tool ?? "", server);
  if (!resolvedServer) {
    return {
      block: true,
      reason: `[Permission Policy] Could not resolve MCP server for tool '${tool ?? "unknown"}'. Refusing to proceed with unresolvable server identifier. Specify the server explicitly.`,
    };
  }

  const request: McpRequest = {
    type: "mcp",
    server: resolvedServer,
    tool: callLabel,
    argsPreview,
  };

  return await gate(request, ctx, store, (decision, result) =>
    rejectMcp(decision, result, store, ctx),
  );
}

/**
 * Handle direct MCP tool calls (e.g., exa_web_search_exa, context7_...);
 * These are MCP tools registered as individual pi tools, bypassing the proxy.
 * Detects direct tools by matching tool name against known MCP server names.
 */
export async function handleMcpDirectTool(
  event: ToolCallEvent,
  ctx: ExtensionContext,
) {
  const toolName = event.toolName as string;

  // Skip if it's the mcp proxy tool (handled by handleMcp)
  if (toolName === "mcp") return;

  const resolvedServer = resolveServerFromToolName(toolName, null);
  if (!resolvedServer) return;

  const params = event.input ?? {};
  const callLabel = formatMcpDirectToolCallLines(toolName, params, 1500, false).join(": ");
  const argsPreview = buildArgsPreview(params);

  const request: McpRequest = {
    type: "mcp",
    server: resolvedServer,
    tool: callLabel,
    argsPreview,
  };

  return await gate(request, ctx, store, (decision, result) =>
    rejectMcp(decision, result, store, ctx),
  );
}
