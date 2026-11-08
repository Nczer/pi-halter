import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import type { HalterPlugin, PluginSlot } from "./types";

/**
 * Tool-plugin loader: scans the extensions root for <ext>/halter/index.ts
 * files and validates each against the HalterPlugin contract.
 *
 * Slots are keyed by the plugin's DISPATCH KEY — its `match` glob when it has
 * one, otherwise the gated tool's `name`. Exact keys dispatch by equality;
 * glob keys (`mcp__blender__*`) dispatch by pattern so one plugin can gate a
 * whole namespace (an MCP server's tools, a multi-verb ext). Use the glob for
 * ONE server/namespace, never `*`: a plugin covering every tool makes what
 * gates what unauditable, and the loader rejects a pattern with no literal
 * characters for that reason.
 *
 * Contract enforcement is fail-CLOSED by construction: a broken plugin's tool
 * is still known — on import/contract failure the loader sniffs the `match:`
 * literal, then `name:`, from the plugin file (neither → the ext directory
 * name), so the core blocks every call it can name (handlers/tool.ts) instead
 * of letting them pass ungated. A tool ext without a halter/ subfolder is
 * simply not gated (the plugin is how a tool opts in).
 *
 * The one honest limit of glob keys: a BROKEN plugin whose sniffed glob cannot
 * be parsed scopes no block, so the tools it meant to protect stay ungated.
 * Validation rejects the only syntax that makes that likely (`?`, `[`, `]`),
 * and the broken slot is reported — fix plugin errors before trusting a
 * gated namespace.
 *
 * Two plugins claiming the same key: the last scanned wins (the extensions
 * root is user-managed; no two exts should gate one tool).
 */

/** Extensions root = the parent of halter's own directory. */
function extensionsRoot(): string {
  return path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
}

/** `*` matches any characters (pi's own toolExposure rule, docs/mcp.md); all else is literal. */
export function globToRegExp(pattern: string): RegExp {
  const body = pattern
    .split("*")
    .map((part) => part.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"))
    .join(".*");
  return new RegExp(`^${body}$`);
}

/** True when the key is a glob rather than an exact tool name. */
export function isGlobKey(key: string): boolean {
  return key.includes("*");
}

function validate(plugin: unknown): asserts plugin is HalterPlugin {
  if (typeof plugin !== "object" || plugin === null) {
    throw new Error("plugin must default-export an object");
  }
  const p = plugin as HalterPlugin;
  if (typeof p.name !== "string" || p.name.length === 0) {
    throw new Error("plugin.name must be a non-empty string (the tool name this plugin gates)");
  }
  if (p.match !== undefined) {
    if (typeof p.match !== "string" || p.match.length === 0) {
      throw new Error("plugin.match must be a non-empty glob (`*` matches any characters)");
    }
    if (/[?[\]]/.test(p.match)) {
      throw new Error(`plugin.match must use only \`*\` as a wildcard (rejected ${JSON.stringify(p.match)})`);
    }
    if (!p.match.replace(/\*/g, "").trim()) {
      throw new Error("plugin.match must name a namespace (a literal prefix) — a wildcard-only pattern gates every tool");
    }
  }
  if (typeof p.buildRequest !== "function") {
    throw new Error("plugin.buildRequest must be a function");
  }
}

/**
 * Fail-closed key recovery: when a plugin FAILS to import, its dispatch key is
 * still readable as a literal — sniff `match:` first (a namespace gate protects
 * more than one tool), then `name:`, then fall back to the ext directory.
 */
function sniffField(file: string, field: string): string | undefined {
  try {
    const m = fs.readFileSync(file, "utf8").match(new RegExp(`^\\s*${field}:\\s*["']([^"']+)["']`, "m"));
    return m?.[1];
  } catch {
    return undefined;
  }
}

/**
 * Scan `root` (default: the real extensions root) for halter plugins.
 * Returns a slot per plugin, keyed by its dispatch key (exact name or glob);
 * exts without a plugin are absent from the map. A plugin that fails to import
 * or validate yields a "broken" slot (its tools are then blocked fail-closed,
 * never ungated).
 */
export async function loadPlugins(root?: string): Promise<Map<string, PluginSlot>> {
  const base = root ?? extensionsRoot();
  const slots = new Map<string, PluginSlot>();
  loadError = null;
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(base, { withFileTypes: true });
  } catch (err) {
    // Fail CLOSED at the seam that decides which tools are gated: with no
    // listing we cannot prove any plugin exists, and a silent empty map would
    // let every gated tool through ungated (handlers/tool.ts blocks them).
    loadError = err instanceof Error ? err.message : String(err);
    return slots;
  }
  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    const file = path.join(base, entry.name, "halter", "index.ts");
    if (!fs.existsSync(file)) continue;
    try {
      const mod = await import(pathToFileURL(file).href);
      validate(mod.default);
      const plugin = mod.default as HalterPlugin;
      slots.set(plugin.match ?? plugin.name, { state: "ok", plugin });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      const key = sniffField(file, "match") ?? sniffField(file, "name") ?? entry.name;
      slots.set(key, { state: "broken", error: msg.slice(0, 200) });
    }
  }
  return slots;
}

/** A found slot plus the key that matched it (differs from the tool name for globs). */
export type LoadedSlot = { key: string; slot: PluginSlot };

/**
 * Dispatch a tool name to its plugin slot: exact keys win; among glob keys the
 * first in sorted order matches (sorted so "first wins" is deterministic and
 * independent of directory listing order).
 */
export function findLoadedSlot(toolName: string): LoadedSlot | undefined {
  const exact = loaded.get(toolName);
  if (exact) return { key: toolName, slot: exact };
  for (const key of [...loaded.keys()].sort()) {
    if (!isGlobKey(key)) continue;
    let matched = false;
    try {
      matched = globToRegExp(key).test(toolName);
    } catch {
      // Unparseable (only possible for a broken plugin's sniffed glob): fall
      // back to a literal-prefix block so the failure still protects a subset.
      matched = toolName.startsWith(key.split("*")[0] ?? "");
    }
    if (matched) return { key, slot: loaded.get(key)! };
  }
  return undefined;
}

// ── Session-scoped loaded state ─────────────────────────────────────────
// index.ts loads once at extension load; handlers and the widget read it
// from here (avoids threading the map through every call site).

let loaded: Map<string, PluginSlot> = new Map();
/** Why the plugin scan could not read the extensions root, if it could not. */
let loadError: string | null = null;

export function setLoadedPlugins(slots: Map<string, PluginSlot>): void {
  loaded = slots;
}

/** The plugin scan's failure (unreadable extensions root), or null. */
export function getPluginLoadError(): string | null {
  return loadError;
}

export function getLoadedPlugins(): Map<string, PluginSlot> {
  return loaded;
}
