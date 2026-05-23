/**
 * MCP tool call formatting helpers — shared with mcp-adapter tool-result-renderer.ts
 * Stripped of TUI-specific rendering; plain string output for permission prompts.
 */

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

export function formatJsonish(value: unknown, maxChars: number): string {
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

function hasUsefulObjectContent(value: unknown): boolean {
  return typeof value === "object" && value !== null && !Array.isArray(value) && Object.keys(value).length > 0;
}

export function formatMcpProxyToolCallLines(
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

export function formatMcpDirectToolCallLines(
  displayName: string,
  args: Record<string, unknown>,
  maxInputChars = DEFAULT_MAX_CALL_INPUT_CHARS,
  includeArgs = true,
): string[] {
  if (!hasUsefulObjectContent(args)) return [displayName];
  if (!includeArgs) return [displayName];
  return [displayName, formatJsonish(args, maxInputChars)];
}

/**
 * Build a compact, single-line args preview for permission prompts.
 * Replaces the old buildArgsPreview with formatJsonish for consistency.
 */
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
