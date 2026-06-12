import type { ExtensionContext, ToolCallEvent } from "@earendil-works/pi-coding-agent";
import { isToolCallEventType } from "@earendil-works/pi-coding-agent";
import type { McpRequest } from "../decision-engine";
import { decide } from "../decision-engine";
import { showPrompt } from "../prompt-flow";
import { store } from "../store";
import { resolveServerFromToolName, deriveProxyTarget, METADATA_OPS } from "../analysis/mcp-resolver";

// ── MCP formatting helpers (inlined from mcp-format.ts) ────────────────

const DEFAULT_MAX_CALL_INPUT_CHARS = 1500;

export interface McpProxyToolCallInput {
  tool?: string;
  args?: string;
  connect?: string;
  describe?: string;
  search?: string;
  regex?: boolean;
  includeSchemas?: boolean;
  server?: string;
  action?: string;
}

function truncateText(value: string, maxChars: number): string {
  if (value.length <= maxChars) return value;
  return `${value.slice(0, Math.max(0, maxChars - 1))}…`;
}

function formatJsonish(value: unknown, maxChars: number): string {
  if (typeof value === "string") {
    try {
      return truncateText(JSON.stringify(JSON.parse(value), null, 2), maxChars);
    } catch {
      return truncateText(value, maxChars);
    }
  }
  try {
    return truncateText(JSON.stringify(value, null, 2), maxChars);
  } catch {
    return truncateText(String(value), maxChars);
  }
}

function formatMcpProxyToolCallLines(
  args: McpProxyToolCallInput,
  maxInputChars = DEFAULT_MAX_CALL_INPUT_CHARS,
  includeArgs = true,
): string[] {
  if (args.action === "ui-messages") return [`mcp ${args.action}`];
  if (args.tool) {
    const target = args.server ? `${args.tool} @ ${args.server}` : args.tool;
    const lines = [`mcp call ${target}`];
    if (includeArgs && args.args) lines.push(formatJsonish(args.args, maxInputChars));
    return lines;
  }
  if (args.connect) return [`mcp connect ${args.connect}`];
  if (args.describe) return [`mcp describe ${args.describe}`];
  if (args.search) {
    let line = `mcp search ${args.search}`;
    if (args.server) line += ` @ ${args.server}`;
    if (args.regex === true) line += " (regex)";
    if (args.includeSchemas === false) line += " (schemas hidden)";
    return [line];
  }
  if (args.server) return [`mcp list ${args.server}`];
  if (args.action) return [`mcp ${args.action}`];
  return ["mcp status"];
}

function formatMcpDirectToolCallLines(
  displayName: string,
  args: Record<string, unknown>,
  maxInputChars = DEFAULT_MAX_CALL_INPUT_CHARS,
  includeArgs = true,
): string[] {
  if (typeof args !== "object" || args === null || Array.isArray(args) || !Object.keys(args).length) {
    return [displayName];
  }
  if (!includeArgs) return [displayName];
  return [displayName, formatJsonish(args, maxInputChars)];
}

function buildArgsPreview(params: Record<string, unknown>, maxChars = 300): string | undefined {
  const argsParam = typeof params.args === "string" ? params.args : null;
  if (argsParam) {
    try {
      const parsed = JSON.parse(argsParam);
      return formatJsonish(parsed, maxChars);
    } catch {
      return truncateText(argsParam, maxChars);
    }
  }
  const meaningfulKeys = Object.keys(params).filter(k =>
    typeof params[k] !== "undefined" && params[k] !== null && params[k] !== "",
  );
  if (meaningfulKeys.length === 0) return undefined;
  const subset: Record<string, unknown> = {};
  meaningfulKeys.forEach(k => { subset[k] = params[k]; });
  return formatJsonish(subset, maxChars);
}

// ── Permission check (shared by proxy and direct tool paths) ───────────

async function checkMcpPermission(
  server: string,
  tool: string,
  argsPreview: string | undefined,
  ctx: ExtensionContext,
): Promise<undefined | { block: true; reason: string }> {
  const request: McpRequest = {
    type: "mcp",
    server,
    tool,
    argsPreview,
  };

  const decision = await decide(request, store);

  // Auto-allow: proceed without prompting
  if (decision.kind === "auto-allow") return;

  // Block: no prompt shown
  if (decision.kind === "block") {
    return { block: true, reason: decision.reason };
  }

  // No UI available — block
  if (!ctx.hasUI) {
    return { block: true, reason: "[Permission Policy] Auto-blocked (no UI): MCP tool call requires confirmation" };
  }

  const wasExpanded = ctx.ui.getToolsExpanded();
  if (!wasExpanded) ctx.ui.setToolsExpanded(true);

  try {
    const result = await showPrompt(decision, ctx, store);
    if (!result.allowed) {
      const reasonDetail = result.reason ? ` Reason: ${result.reason}.` : "";
      ctx.ui.notify(`Permission denied: MCP tool '${tool}'`, "error");
      return { block: true, reason: `[USER REJECTED] You denied MCP tool '${tool}' from server '${server}'.${reasonDetail}` };
    }
  } finally {
    ctx.ui.setToolsExpanded(wasExpanded);
  }

  return;
}

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

  const callLabel = formatMcpProxyToolCallLines(params as McpProxyToolCallInput, 1500, false).join(": ");
  const argsPreview = buildArgsPreview(params);

  // Resolve server from tool name if not explicitly provided
  const resolvedServer = resolveServerFromToolName(tool ?? "", server);
  if (!resolvedServer) {
    return {
      block: true,
      reason: `[Permission Policy] Could not resolve MCP server for tool '${tool ?? "unknown"}'. Refusing to proceed with unresolvable server identifier. Specify the server explicitly.`,
    };
  }

  return await checkMcpPermission(
    resolvedServer,
    callLabel,
    argsPreview,
    ctx,
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

  return await checkMcpPermission(
    resolvedServer,
    callLabel,
    argsPreview,
    ctx,
  );
}
