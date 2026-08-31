import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import type { HalterPlugin, PluginSlot } from "./types";

/**
 * Tool-plugin loader: scans the extensions root for <ext>/halter/index.ts
 * files and validates each against the HalterPlugin contract.
 *
 * Slots are keyed by the GATED TOOL's name (plugin.name), not the ext
 * directory — a multi-tool ext can gate any of its tools. Contract
 * enforcement is fail-CLOSED by construction: a broken plugin's tool is
 * known — on import/contract failure the loader sniffs the `name:` literal
 * from the plugin file (no literal → falls back to the ext directory name),
 * so the core blocks ALL calls to that tool (handlers/tool.ts) instead of
 * letting them pass ungated. A tool ext without a halter/ subfolder is
 * simply not gated (the plugin is how a tool opts in).
 *
 * Two plugins declaring the same tool name: the last scanned wins (the
 * extensions root is user-managed; no two exts should gate one tool).
 */

/** Extensions root = the parent of halter's own directory. */
function extensionsRoot(): string {
  return path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
}

function validate(plugin: unknown): asserts plugin is HalterPlugin {
  if (typeof plugin !== "object" || plugin === null) {
    throw new Error("plugin must default-export an object");
  }
  const p = plugin as HalterPlugin;
  if (typeof p.name !== "string" || p.name.length === 0) {
    throw new Error("plugin.name must be a non-empty string (the tool name this plugin gates)");
  }
  if (typeof p.buildRequest !== "function") {
    throw new Error("plugin.buildRequest must be a function");
  }
}

/**
 * Fail-closed name recovery: when a plugin FAILS to import, its declared
 * tool name is still readable as a literal — sniff it so the broken slot
 * blocks the REAL tool (not just the ext directory name).
 */
function sniffName(file: string): string | undefined {
  try {
    const m = fs.readFileSync(file, "utf8").match(/^\s*name:\s*["']([^"']+)["']/m);
    return m?.[1];
  } catch {
    return undefined;
  }
}

/**
 * Scan `root` (default: the real extensions root) for halter plugins.
 * Returns a slot per tool that HAS a plugin file; exts without one are
 * absent from the map. A plugin that fails to import or validate yields a
 * "broken" slot (the tool is then blocked fail-closed, never ungated).
 */
export async function loadPlugins(root?: string): Promise<Map<string, PluginSlot>> {
  const base = root ?? extensionsRoot();
  const slots = new Map<string, PluginSlot>();
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(base, { withFileTypes: true });
  } catch {
    return slots;
  }
  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    const file = path.join(base, entry.name, "halter", "index.ts");
    if (!fs.existsSync(file)) continue;
    try {
      const mod = await import(pathToFileURL(file).href);
      validate(mod.default);
      slots.set((mod.default as HalterPlugin).name, { state: "ok", plugin: mod.default });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      slots.set(sniffName(file) ?? entry.name, { state: "broken", error: msg.slice(0, 200) });
    }
  }
  return slots;
}

// ── Session-scoped loaded state ─────────────────────────────────────────
// index.ts loads once at extension load; handlers and the widget read it
// from here (avoids threading the map through every call site).

let loaded: Map<string, PluginSlot> = new Map();

export function setLoadedPlugins(slots: Map<string, PluginSlot>): void {
  loaded = slots;
}

export function getLoadedPlugins(): Map<string, PluginSlot> {
  return loaded;
}
