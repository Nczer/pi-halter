import type { Store, McpRequest, Decision } from "../decision-engine";

/**
 * Parse qualified tool name `server:tool` to extract server.
 */
function parseServerFromTool(tool: string): string | null {
  const colonIndex = tool.indexOf(":");
  if (colonIndex > 0 && colonIndex < tool.length - 1) {
    return tool.slice(0, colonIndex).trim();
  }
  return null;
}

export function decideMcp(req: McpRequest, store: Store): Decision {
  // Auto-allow if server is already approved
  if (store.hasAllowedMcpServer(req.server)) {
    return { kind: "auto-allow" };
  }

  // Try to extract server from tool name if not explicitly provided
  const toolServer = parseServerFromTool(req.tool);
  const effectiveServer = toolServer ?? req.server;

  // Never allow "unknown" servers — they would auto-allow all unresolvable tools
  if (effectiveServer === "unknown") {
    return {
      kind: "block",
      reason: `Blocked: cannot resolve MCP server for tool '${req.tool}'. Refusing unresolvable server identifier.`,
    };
  }

  return {
    kind: "prompt",
    promptData: {
      type: "mcp",
      server: effectiveServer,
      tool: req.tool,
      op: "call",
      argsPreview: req.argsPreview,
    },
  };
}
