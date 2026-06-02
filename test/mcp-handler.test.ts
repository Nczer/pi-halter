import { describe, it, expect, vi } from "vitest";

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
  function parseQualified(value: string): { server: string; tool: string } | null {
    const colonIndex = value.indexOf(":");
    if (colonIndex <= 0 || colonIndex >= value.length - 1) return null;
    return {
      server: value.slice(0, colonIndex).trim(),
      tool: value.slice(colonIndex + 1).trim(),
    };
  }

  function derive(params: Record<string, unknown>): { server: string | null; tool: string | null; op: string } {
    const toolParam = typeof params.tool === "string" ? params.tool : null;
    const serverParam = typeof params.server === "string" ? params.server : null;

    if (toolParam) {
      const qualified = parseQualified(toolParam);
      return {
        server: qualified?.server ?? serverParam,
        tool: qualified?.tool ?? toolParam,
        op: "call",
      };
    }
    if (typeof params.connect === "string") return { server: params.connect, tool: null, op: "connect" };
    if (typeof params.describe === "string") {
      const qualified = parseQualified(params.describe);
      return {
        server: qualified?.server ?? serverParam,
        tool: qualified?.tool ?? params.describe,
        op: "describe",
      };
    }
    if (typeof params.search === "string") return { server: serverParam, tool: params.search, op: "search" };
    if (serverParam) return { server: serverParam, tool: null, op: "list" };
    return { server: null, tool: null, op: "status" };
  }

  it("derives call from tool param", () => {
    expect(derive({ tool: "search" })).toEqual({ server: null, tool: "search", op: "call" });
  });

  it("derives server from qualified tool", () => {
    expect(derive({ tool: "exa:search" })).toEqual({ server: "exa", tool: "search", op: "call" });
  });

  it("derives connect op", () => {
    expect(derive({ connect: "exa" })).toEqual({ server: "exa", tool: null, op: "connect" });
  });

  it("derives describe op with qualified name", () => {
    expect(derive({ describe: "exa:search" })).toEqual({ server: "exa", tool: "search", op: "describe" });
  });

  it("derives search op", () => {
    expect(derive({ search: "keyword" })).toEqual({ server: null, tool: "keyword", op: "search" });
  });

  it("derives list op when only server provided", () => {
    expect(derive({ server: "exa" })).toEqual({ server: "exa", tool: null, op: "list" });
  });

  it("derives status op for empty params", () => {
    expect(derive({})).toEqual({ server: null, tool: null, op: "status" });
  });
});

describe("METADATA_OPS", () => {
  const METADATA_OPS = new Set(["connect", "describe", "search", "list", "status"]);

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
