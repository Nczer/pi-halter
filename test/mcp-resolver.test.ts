/**
 * MCP resolver tests — resolveServerFromToolName, loadToolToServerMap,
 * loadDirectToolMap, FileCache mtime invalidation, prefix modes, fallback.
 *
 * mcp-resolver.ts hardcodes homedir()-based config paths at module-eval time.
 * We mock os.homedir() per test via vi.doMock + vi.resetModules + dynamic import
 * so each test gets fresh module-level state (FileCache instances + path arrays).
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import path from "node:path";
import * as actualOs from "node:os";

let tmpBase = "";

beforeEach(() => {
	tmpBase = fs.mkdtempSync(path.join(actualOs.tmpdir(), "mcp-resolver-"));
});

afterEach(() => {
	vi.resetModules();
	fs.rmSync(tmpBase, { recursive: true, force: true });
});

/** Re-import mcp-resolver with homedir() pointing to homeDir. Fresh FileCache each call. */
async function loadResolver(homeDir: string) {
	vi.resetModules();
	vi.doMock("node:os", () => ({ ...actualOs, homedir: () => homeDir }));
	return await import("../analysis/mcp-resolver");
}

function writeCache(homeDir: string, servers: Record<string, { tools: { name: string }[] }>) {
	const p = path.join(homeDir, ".pi", "agent", "mcp-cache.json");
	fs.mkdirSync(path.dirname(p), { recursive: true });
	fs.writeFileSync(p, JSON.stringify({ version: 1, servers }));
}

function writeConfig(
	homeDir: string,
	config: Record<string, unknown>,
	location: "pi" | "config" = "pi",
) {
	const p =
		location === "pi"
			? path.join(homeDir, ".pi", "agent", "mcp.json")
			: path.join(homeDir, ".config", "mcp", "mcp.json");
	fs.mkdirSync(path.dirname(p), { recursive: true });
	fs.writeFileSync(p, JSON.stringify(config));
}

// ── Explicit server param ──────────────────────────────────────────────

describe("resolveServerFromToolName: explicit server param", () => {
	it("returns serverParam when provided, ignoring cache", async () => {
		writeCache(tmpBase, { exa: { tools: [{ name: "web_search" }] } });
		const mod = await loadResolver(tmpBase);
		expect(mod.resolveServerFromToolName("any_tool", "my-server")).toBe("my-server");
	});

	it("returns serverParam even when tool is in cache for a different server", async () => {
		writeCache(tmpBase, { exa: { tools: [{ name: "web_search" }] } });
		const mod = await loadResolver(tmpBase);
		expect(mod.resolveServerFromToolName("web_search", "other")).toBe("other");
	});
});

// ── Metadata cache (prefix=server, default) ────────────────────────────

describe("resolveServerFromToolName: metadata cache (prefix=server)", () => {
	it("resolves by raw tool name", async () => {
		writeCache(tmpBase, { exa: { tools: [{ name: "web_search" }] } });
		const mod = await loadResolver(tmpBase);
		expect(mod.resolveServerFromToolName("web_search", null)).toBe("exa");
	});

	it("resolves by prefixed name (server_tool)", async () => {
		writeCache(tmpBase, { exa: { tools: [{ name: "web_search" }] } });
		const mod = await loadResolver(tmpBase);
		expect(mod.resolveServerFromToolName("exa_web_search", null)).toBe("exa");
	});
});

// ── Prefix modes ───────────────────────────────────────────────────────

describe("resolveServerFromToolName: prefix modes", () => {
	it("prefix=none: resolves by tool_server", async () => {
		writeConfig(tmpBase, { settings: { toolPrefix: "none" } });
		writeCache(tmpBase, { exa: { tools: [{ name: "web_search" }] } });
		const mod = await loadResolver(tmpBase);
		expect(mod.resolveServerFromToolName("web_search_exa", null)).toBe("exa");
	});

	it("prefix=short: resolves by shortName_tool (last path segment)", async () => {
		writeConfig(tmpBase, { settings: { toolPrefix: "short" } });
		writeCache(tmpBase, { "earendil-works/exa": { tools: [{ name: "web_search" }] } });
		const mod = await loadResolver(tmpBase);
		// shortName = "earendil-works/exa".split("/").pop() = "exa"
		expect(mod.resolveServerFromToolName("exa_web_search", null)).toBe("earendil-works/exa");
	});

	it("prefix=server (default): raw tool name always resolves", async () => {
		// No config file → default prefix mode "server"
		writeCache(tmpBase, { exa: { tools: [{ name: "web_search" }] } });
		const mod = await loadResolver(tmpBase);
		expect(mod.resolveServerFromToolName("web_search", null)).toBe("exa");
	});
});

// ── Fallback pattern matching (directTools in mcp.json) ─────────────────

describe("resolveServerFromToolName: fallback pattern matching", () => {
	it("matches {server}_{tool} pattern from directTools config", async () => {
		writeConfig(tmpBase, { mcpServers: { joplin: { directTools: true } } });
		const mod = await loadResolver(tmpBase);
		expect(mod.resolveServerFromToolName("joplin_get_notes", null)).toBe("joplin");
	});

	it("matches {tool}_{server} pattern (prefix=none style)", async () => {
		writeConfig(tmpBase, { mcpServers: { joplin: { directTools: true } } });
		const mod = await loadResolver(tmpBase);
		expect(mod.resolveServerFromToolName("get_notes_joplin", null)).toBe("joplin");
	});

	it("prefers exact cache match over fallback pattern", async () => {
		writeCache(tmpBase, { exa: { tools: [{ name: "joplin_tool" }] } });
		writeConfig(tmpBase, { mcpServers: { joplin: { directTools: true } } });
		const mod = await loadResolver(tmpBase);
		// "joplin_tool" is in cache as exa's tool, not joplin's
		expect(mod.resolveServerFromToolName("joplin_tool", null)).toBe("exa");
	});
});

// ── No match ───────────────────────────────────────────────────────────

describe("resolveServerFromToolName: no match", () => {
	it("returns null when tool is unknown and no config files exist", async () => {
		const mod = await loadResolver(tmpBase);
		expect(mod.resolveServerFromToolName("unknown_tool", null)).toBeNull();
	});

	it("returns null when tool not in cache and no directTools config", async () => {
		writeCache(tmpBase, { exa: { tools: [{ name: "web_search" }] } });
		const mod = await loadResolver(tmpBase);
		expect(mod.resolveServerFromToolName("unknown_tool", null)).toBeNull();
	});
});

// ── Multiple servers ───────────────────────────────────────────────────

describe("resolveServerFromToolName: multiple servers", () => {
	it("resolves tools from different servers", async () => {
		writeCache(tmpBase, {
			exa: { tools: [{ name: "web_search" }, { name: "web_fetch" }] },
			joplin: { tools: [{ name: "get_notes" }] },
		});
		const mod = await loadResolver(tmpBase);
		expect(mod.resolveServerFromToolName("web_search", null)).toBe("exa");
		expect(mod.resolveServerFromToolName("web_fetch", null)).toBe("exa");
		expect(mod.resolveServerFromToolName("get_notes", null)).toBe("joplin");
		expect(mod.resolveServerFromToolName("exa_web_search", null)).toBe("exa");
		expect(mod.resolveServerFromToolName("joplin_get_notes", null)).toBe("joplin");
	});
});

// ── FileCache mtime invalidation ───────────────────────────────────────

describe("FileCache mtime invalidation", () => {
	it("rebuilds map when config file mtime advances", async () => {
		writeCache(tmpBase, { exa: { tools: [{ name: "web_search" }] } });
		const cachePath = path.join(tmpBase, ".pi", "agent", "mcp-cache.json");
		const t = Math.floor(Date.now() / 1000);
		fs.utimesSync(cachePath, t, t);

		const mod = await loadResolver(tmpBase);
		expect(mod.resolveServerFromToolName("web_search", null)).toBe("exa");

		// Overwrite with different server, bump mtime by 10s
		writeCache(tmpBase, { brave: { tools: [{ name: "web_search" }] } });
		fs.utimesSync(cachePath, t + 10, t + 10);

		expect(mod.resolveServerFromToolName("web_search", null)).toBe("brave");
	});

	it("serves cached value when mtime does not change", async () => {
		writeCache(tmpBase, { exa: { tools: [{ name: "web_search" }] } });
		const cachePath = path.join(tmpBase, ".pi", "agent", "mcp-cache.json");
		const t = Math.floor(Date.now() / 1000);
		fs.utimesSync(cachePath, t, t);

		const mod = await loadResolver(tmpBase);
		expect(mod.resolveServerFromToolName("web_search", null)).toBe("exa");

		// Same mtime → cache hit even though file content changed on disk.
		// (The cache only checks mtime, not content — this is by design.)
		writeCache(tmpBase, { brave: { tools: [{ name: "web_search" }] } });
		fs.utimesSync(cachePath, t, t); // same mtime

		expect(mod.resolveServerFromToolName("web_search", null)).toBe("exa"); // stale but cached
	});
});

// ── Alternate config location ──────────────────────────────────────────

describe("Config at ~/.config/mcp/mcp.json", () => {
	it("reads toolPrefix from alternate location when ~/.pi/agent/mcp.json absent", async () => {
		writeConfig(tmpBase, { settings: { toolPrefix: "none" } }, "config");
		writeCache(tmpBase, { exa: { tools: [{ name: "web_search" }] } });
		const mod = await loadResolver(tmpBase);
		// prefix=none → tool_server mapping should exist
		expect(mod.resolveServerFromToolName("web_search_exa", null)).toBe("exa");
	});

	it("reads directTools from alternate location", async () => {
		writeConfig(tmpBase, { mcpServers: { joplin: { directTools: true } } }, "config");
		const mod = await loadResolver(tmpBase);
		expect(mod.resolveServerFromToolName("joplin_get_notes", null)).toBe("joplin");
	});
});

// ── Robustness: malformed cache ─────────────────────────────────────────

describe("Robustness: malformed cache entries", () => {
	it("skips servers with missing or invalid tools array", async () => {
		const cachePath = path.join(tmpBase, ".pi", "agent", "mcp-cache.json");
		fs.mkdirSync(path.dirname(cachePath), { recursive: true });
		fs.writeFileSync(
			cachePath,
			JSON.stringify({
				version: 1,
				servers: {
					exa: { tools: [{ name: "web_search" }] },
					bad: { tools: "not-an-array" },
					bad2: {},
					bad3: { tools: [{ notName: true }, { name: "valid_tool" }] },
				},
			}),
		);
		const mod = await loadResolver(tmpBase);
		expect(mod.resolveServerFromToolName("web_search", null)).toBe("exa");
		expect(mod.resolveServerFromToolName("valid_tool", null)).toBe("bad3");
		// bad and bad2 are skipped gracefully
		expect(mod.resolveServerFromToolName("bad_tool", null)).toBeNull();
	});
});
