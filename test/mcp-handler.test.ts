import { describe, it, expect } from "vitest";
import { METADATA_OPS, deriveProxyTarget } from "../analysis/mcp-resolver";

// Test parseQualifiedMcpToolName logic via inline reproduction
// (function is internal to mcp.ts, testing behavior through decision-engine
// which is already covered in decision-engine.test.ts)

describe("parseQualifiedMcpToolName", () => {
  function parse(value: string): { server: string; tool: string } | null {
    const trimmed = value.trim();
    if (!trimmed) return null;
    const colonIndex = trimmed.indexOf(":");
    if (colonIndex <= 0 || colonIndex >= trimmed.length - 1) return null;
    const server = trimmed.slice(0, colonIndex).trim();
    const tool = trimmed.slice(colonIndex + 1).trim();
    if (!server || !tool) return null;
    return { server, tool };
  }

  it("parses server:tool format", () => {
    expect(parse("exa:web_search")).toEqual({ server: "exa", tool: "web_search" });
  });

  it("returns null for unqualified name", () => {
    expect(parse("web_search")).toBeNull();
  });

  it("returns null for leading colon", () => {
    expect(parse(":tool")).toBeNull();
  });

  it("returns null for trailing colon", () => {
    expect(parse("server:")).toBeNull();
  });

  it("handles whitespace", () => {
    expect(parse("  server : tool  ")).toEqual({ server: "server", tool: "tool" });
  });

  it("returns null for empty string", () => {
    expect(parse("")).toBeNull();
  });
});

describe("deriveProxyTarget", () => {
  it("derives call from tool param", () => {
    expect(deriveProxyTarget({ tool: "search" })).toEqual({ server: null, tool: "search", op: "call" });
  });

  it("derives server from qualified tool", () => {
    expect(deriveProxyTarget({ tool: "exa:search" })).toEqual({ server: "exa", tool: "search", op: "call" });
  });

  it("derives connect op", () => {
    expect(deriveProxyTarget({ connect: "exa" })).toEqual({ server: "exa", tool: null, op: "connect" });
  });

  it("derives describe op with qualified name", () => {
    expect(deriveProxyTarget({ describe: "exa:search" })).toEqual({ server: "exa", tool: "search", op: "describe" });
  });

  it("derives search op", () => {
    expect(deriveProxyTarget({ search: "keyword" })).toEqual({ server: null, tool: "keyword", op: "search" });
  });

  it("derives list op when only server provided", () => {
    expect(deriveProxyTarget({ server: "exa" })).toEqual({ server: "exa", tool: null, op: "list" });
  });

  it("derives status op for empty params", () => {
    expect(deriveProxyTarget({})).toEqual({ server: null, tool: null, op: "status" });
  });
});

describe("METADATA_OPS", () => {
  it("includes all metadata operations", () => {
    expect(METADATA_OPS.has("connect")).toBe(true);
    expect(METADATA_OPS.has("describe")).toBe(true);
    expect(METADATA_OPS.has("search")).toBe(true);
    expect(METADATA_OPS.has("list")).toBe(true);
    expect(METADATA_OPS.has("status")).toBe(true);
  });

  it("does not include call", () => {
    expect(METADATA_OPS.has("call")).toBe(false);
  });
});

// ── Metadata ops contract: every metadata-style param → op in METADATA_OPS ──

describe("handleMcp: metadata params produce auto-allow ops", () => {
  // Verifies the contract that metadata operations resolve to ops in METADATA_OPS,
  // which means handleMcp will auto-allow them (return undefined).
  // This is the core logic without needing to mock the handler itself.

  const metadataParams: Array<{ desc: string; params: Record<string, unknown> }> = [
    { desc: "connect", params: { connect: "exa" } },
    { desc: "describe", params: { describe: "exa:web_search" } },
    { desc: "search", params: { search: "keyword" } },
    { desc: "search with server", params: { search: "keyword", server: "exa" } },
    { desc: "search with regex", params: { search: "pattern", regex: true } },
    { desc: "list server", params: { server: "exa" } },
    { desc: "status (empty)", params: {} },
    { desc: "status (null)", params: { tool: null, server: null } as any },
  ];

  it.each(metadataParams)("auto-allows $desc", ({ params }) => {
    const { op } = deriveProxyTarget(params);
    expect(METADATA_OPS.has(op)).toBe(true);
  });

  it("does NOT auto-allow a tool call", () => {
    const { op } = deriveProxyTarget({ tool: "exa:web_search", args: '{"query":"hello"}' });
    expect(op).toBe("call");
    expect(METADATA_OPS.has("call")).toBe(false);
  });
});
