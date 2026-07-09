const DEFAULT_MAX_CALL_INPUT_CHARS = 1500;

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

/** Format an MCP proxy tool call into display lines. */
export function formatMcpProxyToolCallLines(
  args: Record<string, unknown>,
  maxInputChars = DEFAULT_MAX_CALL_INPUT_CHARS,
  includeArgs = true,
): string[] {
  const action = typeof args.action === "string" ? args.action : undefined;
  const tool = typeof args.tool === "string" ? args.tool : undefined;
  const server = typeof args.server === "string" ? args.server : undefined;
  const argsParam = typeof args.args === "string" ? args.args : undefined;
  const connect = typeof args.connect === "string" ? args.connect : undefined;
  const describe = typeof args.describe === "string" ? args.describe : undefined;
  const search = typeof args.search === "string" ? args.search : undefined;
  const regex = args.regex === true;
  const includeSchemas = args.includeSchemas === false;

  if (action === "ui-messages") return [`mcp ${action}`];
  if (tool) {
    const target = server ? `${tool} @ ${server}` : tool;
    const lines = [`mcp call ${target}`];
    if (includeArgs && argsParam) lines.push(formatJsonish(argsParam, maxInputChars));
    return lines;
  }
  if (connect) return [`mcp connect ${connect}`];
  if (describe) return [`mcp describe ${describe}`];
  if (search) {
    let line = `mcp search ${search}`;
    if (server) line += ` @ ${server}`;
    if (regex) line += " (regex)";
    if (includeSchemas) line += " (schemas hidden)";
    return [line];
  }
  if (server) return [`mcp list ${server}`];
  if (action) return [`mcp ${action}`];
  return ["mcp status"];
}

/** Format a direct MCP tool call into display lines. */
export function formatMcpDirectToolCallLines(
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

/** Build a truncated args preview from MCP call parameters. */
export function buildArgsPreview(params: Record<string, unknown>, maxChars = 300): string | undefined {
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
