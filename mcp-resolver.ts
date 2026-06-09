import { readFileSync, statSync, existsSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";

/** MCP operations that are metadata-only and auto-allowed. */
export const METADATA_OPS = new Set(["connect", "describe", "search", "list", "status"]);

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

/** Derive server and tool name from MCP proxy call parameters. */
export function deriveProxyTarget(params: Record<string, unknown>): { server: string | null; tool: string | null; op: string } {
  const toolParam = typeof params.tool === "string" ? params.tool : null;
  const serverParam = typeof params.server === "string" ? params.server : null;
  const connectParam = typeof params.connect === "string" ? params.connect : null;
  const describeParam = typeof params.describe === "string" ? params.describe : null;
  const searchParam = typeof params.search === "string" ? params.search : null;
  if (toolParam) {
    const qualified = parseQualifiedMcpToolName(toolParam);
    return { server: qualified?.server ?? serverParam, tool: qualified?.tool ?? toolParam, op: "call" };
  }
  if (connectParam) return { server: connectParam, tool: null, op: "connect" };
  if (describeParam) {
    const qualified = parseQualifiedMcpToolName(describeParam);
    return { server: qualified?.server ?? serverParam, tool: qualified?.tool ?? describeParam, op: "describe" };
  }
  if (searchParam) return { server: serverParam, tool: searchParam, op: "search" };
  if (serverParam) return { server: serverParam, tool: null, op: "list" };
  return { server: null, tool: null, op: "status" };
}

// ── Cache helpers ──────────────────────────────────────────────────────

/** Simple mtime-based cache for lazily-loaded data derived from config files. */
class FileCache<T> {
  private cached: { mtime: number; value: T } | null = null;

  get(files: string[], build: () => T): T {
    let latestMtime = 0;
    for (const f of files) {
      try {
        const mtime = statSync(f).mtimeMs;
        if (mtime > latestMtime) latestMtime = mtime;
      } catch {
        // File doesn't exist — skip
      }
    }
    if (this.cached && latestMtime <= this.cached.mtime) {
      return this.cached.value;
    }
    const value = build();
    this.cached = { mtime: latestMtime || Date.now(), value };
    return value;
  }
}

// ── Metadata cache resolution ──────────────────────────────────────────

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

const toolMapCache = new FileCache<Map<string, string>>();
const configFilePaths = [
  join(homedir(), ".pi", "agent", "mcp-cache.json"),
  join(homedir(), ".pi", "agent", "mcp.json"),
  join(homedir(), ".config", "mcp", "mcp.json"),
];

function loadToolToServerMap(): Map<string, string> {
  return toolMapCache.get(configFilePaths, () => {
    const map = new Map<string, string>();

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

    const cachePaths = [
      join(homedir(), ".pi", "agent", "mcp-cache.json"),
    ];
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
  });
}

// ── Direct tool detection ──────────────────────────────────────────────

const directToolMapCache = new FileCache<Map<string, { server: string; originalName: string }>>();
const mcpConfigPaths = [
  join(homedir(), ".pi", "agent", "mcp.json"),
  join(homedir(), ".config", "mcp", "mcp.json"),
];

function loadDirectToolMap(): Map<string, { server: string; originalName: string }> {
  return directToolMapCache.get(mcpConfigPaths, () => {
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
  });
}

// ── Public API ─────────────────────────────────────────────────────────

/**
 * Resolve an MCP tool name to its server using the metadata cache.
 * Falls back to pattern matching against known server names from mcp.json.
 */
export function resolveServerFromToolName(
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
