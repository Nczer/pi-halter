import type { Store, McpRequest, Decision } from "../decision-engine";

export function decideMcp(req: McpRequest, store: Store): Decision {
  // Auto-allow if server is already approved
  if (store.hasAllowedMcpServer(req.server)) {
    return { kind: "auto-allow" };
  }

  // Never allow "unknown" servers — they would auto-allow all unresolvable tools.
  // The handler resolves the server before constructing the request, so req.server
  // is already authoritative — no need to re-parse it from the tool label.
  if (req.server === "unknown") {
    return {
      kind: "block",
      reason: `Blocked: cannot resolve MCP server for tool '${req.tool}'. Refusing unresolvable server identifier.`,
    };
  }

  return {
    kind: "prompt",
    promptData: {
      type: "mcp",
      server: req.server,
      tool: req.tool,
      op: "call",
      argsPreview: req.argsPreview,
    },
  };
}
