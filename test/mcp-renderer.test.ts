import { describe, expect, it } from "vitest";
import {
  formatMcpProxyToolCallLines,
  formatMcpDirectToolCallLines,
  buildArgsPreview,
} from "../renderers/mcp";

describe("formatMcpProxyToolCallLines", () => {
  it("formats tool call without server", () => {
    const input = { tool: "my_tool" };
    expect(formatMcpProxyToolCallLines(input)).toEqual(["mcp call my_tool"]);
  });

  it("formats tool call with server", () => {
    const input = { tool: "my_tool", server: "context7" };
    expect(formatMcpProxyToolCallLines(input)).toEqual(["mcp call my_tool @ context7"]);
  });

  it("formats tool call with args", () => {
    const input = { tool: "my_tool", args: '{"key":"value"}' };
    const lines = formatMcpProxyToolCallLines(input);
    expect(lines).toHaveLength(2);
    expect(lines[0]).toBe("mcp call my_tool");
    expect(lines[1]).toContain("key");
  });

  it("omits args when includeArgs is false", () => {
    const input = { tool: "my_tool", args: '{"key":"value"}' };
    expect(formatMcpProxyToolCallLines(input, 1500, false)).toEqual(["mcp call my_tool"]);
  });

  it("formats connect action", () => {
    expect(formatMcpProxyToolCallLines({ connect: "server1" })).toEqual(["mcp connect server1"]);
  });

  it("formats describe action", () => {
    expect(formatMcpProxyToolCallLines({ describe: "tool1" })).toEqual(["mcp describe tool1"]);
  });

  it("formats search action", () => {
    expect(formatMcpProxyToolCallLines({ search: "query" })).toEqual(["mcp search query"]);
  });

  it("formats search with server", () => {
    expect(formatMcpProxyToolCallLines({ search: "query", server: "exa" })).toEqual(["mcp search query @ exa"]);
  });

  it("formats search with regex flag", () => {
    expect(formatMcpProxyToolCallLines({ search: "query", regex: true })).toEqual(["mcp search query (regex)"]);
  });

  it("formats search with schemas hidden", () => {
    expect(formatMcpProxyToolCallLines({ search: "query", includeSchemas: false })).toEqual(["mcp search query (schemas hidden)"]);
  });

  it("formats server list", () => {
    expect(formatMcpProxyToolCallLines({ server: "context7" })).toEqual(["mcp list context7"]);
  });

  it("formats generic action", () => {
    expect(formatMcpProxyToolCallLines({ action: "auth-start" })).toEqual(["mcp auth-start"]);
  });

  it("formats ui-messages action", () => {
    expect(formatMcpProxyToolCallLines({ action: "ui-messages" })).toEqual(["mcp ui-messages"]);
  });

  it("falls back to status for empty input", () => {
    expect(formatMcpProxyToolCallLines({})).toEqual(["mcp status"]);
  });

  it("truncates long args", () => {
    const longJson = JSON.stringify({ data: "x".repeat(2000) });
    const input = { tool: "my_tool", args: longJson };
    const lines = formatMcpProxyToolCallLines(input, 100);
    expect(lines[1].length).toBeLessThanOrEqual(101); // 100 + ellipsis char
    expect(lines[1]).toContain("\u2026");
  });
});

describe("formatMcpDirectToolCallLines", () => {
  it("formats with args", () => {
    const lines = formatMcpDirectToolCallLines("tool_name", { key: "value" });
    expect(lines).toHaveLength(2);
    expect(lines[0]).toBe("tool_name");
    expect(lines[1]).toContain("key");
  });

  it("omits args when includeArgs is false", () => {
    expect(formatMcpDirectToolCallLines("tool_name", { key: "value" }, 1500, false)).toEqual(["tool_name"]);
  });

  it("returns only name for empty object", () => {
    expect(formatMcpDirectToolCallLines("tool_name", {})).toEqual(["tool_name"]);
  });

  it("returns only name for null args", () => {
    expect(formatMcpDirectToolCallLines("tool_name", null as any)).toEqual(["tool_name"]);
  });

  it("returns only name for array args", () => {
    expect(formatMcpDirectToolCallLines("tool_name", [1, 2] as any)).toEqual(["tool_name"]);
  });

  it("truncates long args", () => {
    const lines = formatMcpDirectToolCallLines("tool_name", { data: "x".repeat(2000) }, 100);
    expect(lines[1].length).toBeLessThanOrEqual(101);
    expect(lines[1]).toContain("\u2026");
  });
});

describe("buildArgsPreview", () => {
  it("parses JSON string args", () => {
    const result = buildArgsPreview({ args: '{"key":"value"}' });
    expect(result).toContain("key");
    expect(result).toContain("value");
  });

  it("truncates parsed JSON args", () => {
    const result = buildArgsPreview({ args: JSON.stringify({ data: "x".repeat(500) }) }, 100);
    expect(result).toBeDefined();
    expect(result!.length).toBeLessThanOrEqual(101);
  });

  it("handles malformed JSON string args", () => {
    const result = buildArgsPreview({ args: "{not valid json" });
    expect(result).toContain("not valid json");
  });

  it("returns meaningful keys when no args field", () => {
    const result = buildArgsPreview({ tool: "my_tool", server: "exa" });
    expect(result).toContain("tool");
    expect(result).toContain("server");
  });

  it("returns undefined for all-empty params", () => {
    expect(buildArgsPreview({ args: undefined, tool: null, server: "" })).toBeUndefined();
  });

  it("filters out null, undefined, and empty string values", () => {
    const result = buildArgsPreview({ a: undefined, b: null, c: "", d: 0 });
    expect(result).toContain("d");
    expect(result).not.toContain('"a"');
    expect(result).not.toContain('"b"');
    expect(result).not.toContain('"c"');
  });

  it("truncates preview at maxChars", () => {
    const result = buildArgsPreview({ data: "x".repeat(500) }, 100);
    expect(result).toBeDefined();
    expect(result!.length).toBeLessThanOrEqual(101);
  });
});
