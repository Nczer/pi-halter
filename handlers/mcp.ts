import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import { isToolCallEventType } from "@earendil-works/pi-coding-agent";
import type { McpRequest } from "../decision-engine";
import { decide } from "../decision-engine";
import { showPrompt } from "../prompt-flow";
import { store } from "../store";
import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";

// ── Metadata cache resolution ──────────────────────────────────────────

/**
 * Load the MCP metadata cache and build a map of tool names to server names.
 * This lets us resolve the server for any tool call, even when the user
 * doesn't specify a server param.
 */
interface McpCacheTool {
  name: string;
}

interface McpCacheServer {
  tools: McpCacheTool[];
}

interface McpCache {
  version: number;
  servers: Record<string, McpCacheServer>;
}

function loadToolToServerMap(): Map<string, string> {
  const map = new Map<string, string>();
  const cachePaths = [
    join(homedir(), ".pi", "agent", "mcp-cache.json"),
  ];

  // Load prefix mode from mcp.json settings
  let prefixMode: "server" | "none" | "short" = "server"; // default
  const configPaths = [
    join(homedir(), ".pi", "agent", "mcp.json"),
    join(homedir(), ".config", "mcp", "mcp.json"),
  ];
  for (const configPath of configPaths) {
    if (!existsSync(configPath)) continue;
    try {
      const config = JSON.parse(readFileSync(configPath, "utf-8"));
      const settings = config.settings ?? {};
      if (settings.toolPrefix) {
        prefixMode = settings.toolPrefix;
      }
      break;
    } catch {
      // Try next config path
    }
  }

  for (const cachePath of cachePaths) {
    if (!existsSync(cachePath)) continue;
    try {
      const cache = JSON.parse(readFileSync(cachePath, "utf-8")) as McpCache;
      if (!cache?.servers || typeof cache.servers !== "object") continue;

      for (const [serverName, entry] of Object.entries(cache.servers)) {
        if (!entry?.tools || !Array.isArray(entry.tools)) continue;
        for (const tool of entry.tools) {
          if (!tool?.name) continue;

          // Store raw name
          map.set(tool.name, serverName);

          // Store prefixed names based on toolPrefix setting
          if (prefixMode === "server") {
            map.set(`${serverName}_${tool.name}`, serverName);
          } else if (prefixMode === "none") {
            map.set(`${tool.name}_${serverName}`, serverName);
          } else if (prefixMode === "short") {
            const shortName = serverName.split("/").pop() ?? serverName;
            map.set(`${shortName}_${tool.name}`, serverName);
          }
        }
      }
    } catch {
      // Skip invalid cache files
    }
  }

  return map;
}

/**
 * Resolve an MCP tool name to its server using the metadata cache.
 * Falls back to pattern matching against known server names from mcp.json.
 */
function resolveServerFromToolName(
  toolName: string,
  serverParam: string | null,
): string | null {
  // If server was explicitly provided, use it
  if (serverParam) return serverParam;

  // Try metadata cache first (most reliable)
  const toolMap = loadToolToServerMap();
  const cachedServer = toolMap.get(toolName);
  if (cachedServer) return cachedServer;

  // Fall back to pattern matching against mcp.json server names
  const directToolMap = loadDirectToolMap();
  for (const [key] of directToolMap) {
    if (!key.startsWith("__server__:")) continue;
    const serverName = key.slice(11); // strip "__server__:"

    // Pattern: {server}_{tool} (prefix=server with multiple servers)
    if (toolName.startsWith(`${serverName}_`)) {
      return serverName;
    }

    // Pattern: {tool}_{server} (prefix=none)
    const suffix = `_${serverName}`;
    if (toolName.endsWith(suffix) && !toolName.startsWith(`${serverName}_`)) {
      return serverName;
    }
  }

  return null;
}

/** MCP operations that are metadata-only and auto-allowed. */
const METADATA_OPS = new Set(["connect", "describe", "search", "list", "status"]);

// ── Direct tool detection ──────────────────────────────────────────────

/**
 * Load the MCP config and build a map of direct tool names to server info.
 * Reloads on each call — config file is small JSON, overhead is negligible.
 */
function loadDirectToolMap(): Map<string, { server: string; originalName: string }> {
  const map = new Map<string, { server: string; originalName: string }>();
  const configPaths = [
    join(homedir(), ".pi", "agent", "mcp.json"),
    join(homedir(), ".config", "mcp", "mcp.json"),
  ];

  for (const configPath of configPaths) {
    if (!existsSync(configPath)) continue;
    try {
      const config = JSON.parse(readFileSync(configPath, "utf-8"));
      const servers = config.mcpServers ?? {};

      for (const [serverName, definition] of Object.entries(servers)) {
        const def = definition as Record<string, unknown>;
        const directTools = def.directTools;
        if (directTools !== true && !Array.isArray(directTools)) continue;

        map.set(`__server__:${serverName}`, { server: serverName, originalName: "" });
      }
    } catch {
      // Skip invalid configs
    }
  }

  return map;
}

// ── Argument preview ───────────────────────────────────────────────────

/**
 * Build a human-readable preview of tool arguments for permission prompts.
 */
function buildArgsPreview(params: Record<string, unknown>): string | undefined {
  // For proxy tool calls, args come as a JSON string
  const argsParam = typeof params.args === "string" ? params.args : null;
  if (argsParam) {
    try {
      const parsed = JSON.parse(argsParam);
      const entries = Object.entries(parsed as Record<string, unknown>).slice(0, 5);
      let preview = entries.map(([k, v]) =>
        `${k}: ${typeof v === "string" ? v.slice(0, 80) : JSON.stringify(v).slice(0, 80)}`,
      ).join(", ");
      if (Object.keys(parsed).length > 5) preview += ", ...";
      return preview;
    } catch {
      return argsParam.slice(0, 120);
    }
  }

  // For direct tool calls, params ARE the arguments
  const meaningfulKeys = Object.keys(params).filter(k =>
    typeof params[k] !== "undefined" && params[k] !== null && params[k] !== "",
  );
  if (meaningfulKeys.length === 0) return undefined;

  const entries = meaningfulKeys.slice(0, 5).map(k => {
    const v = params[k];
    return `${k}: ${typeof v === "string" ? v.slice(0, 80) : JSON.stringify(v).slice(0, 80)}`;
  });
  let preview = entries.join(", ");
  if (meaningfulKeys.length > 5) preview += ", ...";
  return preview;
}

// ── Proxy tool handling ────────────────────────────────────────────────

/**
 * Parse a qualified MCP tool name of the form `server:tool`.
 * Returns `{ server, tool }` or `null` if not qualified.
 */
function parseQualifiedMcpToolName(value: string): { server: string; tool: string } | null {
  const trimmed = value.trim();
  if (!trimmed) return null;

  const colonIndex = trimmed.indexOf(":");
  if (colonIndex <= 0 || colonIndex >= trimmed.length - 1) return null;

  const server = trimmed.slice(0, colonIndex).trim();
  const tool = trimmed.slice(colonIndex + 1).trim();
  if (!server || !tool) return null;

  return { server, tool };
}

/**
 * Derive server and tool name from MCP proxy call parameters.
 */
function deriveProxyTarget(params: Record<string, unknown>): { server: string | null; tool: string | null; op: string } {
  const toolParam = typeof params.tool === "string" ? params.tool : null;
  const serverParam = typeof params.server === "string" ? params.server : null;
  const connectParam = typeof params.connect === "string" ? params.connect : null;
  const describeParam = typeof params.describe === "string" ? params.describe : null;
  const searchParam = typeof params.search === "string" ? params.search : null;

  if (toolParam) {
    const qualified = parseQualifiedMcpToolName(toolParam);
    return {
      server: qualified?.server ?? serverParam,
      tool: qualified?.tool ?? toolParam,
      op: "call",
    };
  }
  if (connectParam) return { server: connectParam, tool: null, op: "connect" };
  if (describeParam) {
    const qualified = parseQualifiedMcpToolName(describeParam);
    return {
      server: qualified?.server ?? serverParam,
      tool: qualified?.tool ?? describeParam,
      op: "describe",
    };
  }
  if (searchParam) return { server: serverParam, tool: searchParam, op: "search" };
  if (serverParam) return { server: serverParam, tool: null, op: "list" };
  return { server: null, tool: null, op: "status" };
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
  event: { toolName: string; input: Record<string, unknown> },
  ctx: ExtensionContext,
) {
  if (!isToolCallEventType("mcp", event)) return;

  const params = event.input ?? {};
  const { server, tool, op } = deriveProxyTarget(params);

  // Metadata operations are always allowed
  if (METADATA_OPS.has(op)) return;

  // Only tool calls need permission
  if (op !== "call") return;

  const argsPreview = buildArgsPreview(params);

  // Resolve server from tool name if not explicitly provided
  const resolvedServer = resolveServerFromToolName(tool ?? "", server);

  return await checkMcpPermission(
    resolvedServer ?? "unknown",
    tool ?? "unknown",
    argsPreview,
    ctx,
  );
}

/**
 * Handle direct MCP tool calls (e.g., exa_web_search_exa, context7_...).
 * These are MCP tools registered as individual pi tools, bypassing the proxy.
 * Detects direct tools by matching tool name against known MCP server names.
 */
export async function handleMcpDirectTool(
  event: { toolName: string; input: Record<string, unknown> },
  ctx: ExtensionContext,
) {
  const toolName = event.toolName as string;

  // Skip if it's the mcp proxy tool (handled by handleMcp)
  if (toolName === "mcp") return;

  const resolvedServer = resolveServerFromToolName(toolName, null);
  if (!resolvedServer) return;

  const params = event.input ?? {};
  const argsPreview = buildArgsPreview(params);

  return await checkMcpPermission(
    resolvedServer,
    toolName,
    argsPreview,
    ctx,
  );
}
