import type { ExtensionContext, ToolCallEvent } from "@earendil-works/pi-coding-agent";
import type {ToolRequest} from "../decide/types";
import { gate, rejectTool } from "../gate/gate";
import { store } from "../gate/store";
import { findLoadedSlot, getPluginLoadError } from "../plugins/loader";
import type { ToolGateRequest } from "../plugins/types";

/**
 * Handle plugin-gated tool calls. Dispatch is by tool NAME against the
 * loaded plugin slots (plugins/loader.ts) — exact first, then a glob slot —
 * so one plugin can gate a whole namespace (an MCP server's tools). A tool is
 * gated IFF its ext ships a <ext>/halter plugin. Fail-closed at both seams:
 *  - a BROKEN plugin (import/contract failure) blocks every call it can name —
 *    its dispatch key (`name`, or the `match` glob) is sniffed from the file,
 *    so the gate can never degrade to pass-through;
 *  - a plugin that THROWS in buildRequest blocks the call with the error.
 * A null classification passes ungated (discovery actions, status).
 */
export async function handleTool(
  event: ToolCallEvent,
  ctx: ExtensionContext,
) {
  // The plugin scan could not read the extensions root: which tools are gated
  // is unknown, so a pass-through would be an unverifiable allow. Block and
  // say why (the invariant is fail-closed per tool, plugins/loader.ts).
  const loadError = getPluginLoadError();
  if (loadError) {
    return {
      block: true,
      reason: `[Permission Policy] halter could not read the extensions root — plugin gating is unavailable, so tool calls are blocked (fail closed): ${loadError.slice(0, 200)}. Fix the directory and /reload.`,
    };
  }

  const name = typeof event.toolName === "string" ? event.toolName : null;
  if (!name) return;

  // Exact slot first, then a glob slot (one plugin gating a namespace, e.g. an
  // MCP server). The slot is named by its DISPATCH KEY — a broken glob plugin
  // must be fixable from the message, so say which key matched, not just the tool.
  const hit = findLoadedSlot(name);
  if (!hit) return; // no plugin — not halter's surface
  const slot = hit.slot;
  const byGlob = hit.key !== name;

  if (slot.state === "broken") {
    return {
      block: true,
      reason: `[Permission Policy] halter plugin for '${name}'${byGlob ? ` (gated by the pattern '${hit.key}')` : ""} failed to load (${slot.error}) — blocked (fail closed). Fix the plugin and /reload.`,
    };
  }

  let req: ToolGateRequest | null;
  try {
    req = slot.plugin.buildRequest(event, ctx);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return {
      block: true,
      reason: `[Permission Policy] halter plugin '${name}'${byGlob ? ` (pattern '${hit.key}')` : ""} threw while classifying the call — blocked (fail closed): ${msg.slice(0, 200)}`,
    };
  }
  if (!req) return; // pass (discovery/status)

  const request: ToolRequest = {
    type: "tool",
    tool: name,
    label: req.label,
    gate: req.kind,
    cwd: ctx.cwd,
    script: req.kind === "exec" ? req.script : undefined,
    path: req.kind === "file" ? req.path : undefined,
    consentKind:
      req.kind === "consent" || req.kind === "egress" ? req.consentKind : undefined,
    argsPreview: req.kind !== "file" ? req.argsPreview : undefined,
    note: req.kind !== "file" ? req.note : undefined,
  };

  return await gate(request, ctx, store, (decision, result) =>
    rejectTool(decision, result, store, ctx),
  );
}
