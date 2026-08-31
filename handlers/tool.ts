import type { ExtensionContext, ToolCallEvent } from "@earendil-works/pi-coding-agent";
import type { ToolRequest } from "../decision-engine";
import { gate, rejectTool } from "../gate";
import { store } from "../store";
import { getLoadedPlugins } from "../plugins/loader";
import type { ToolGateRequest } from "../plugins/types";

/**
 * Handle plugin-gated tool calls. Dispatch is by tool NAME against the
 * loaded plugin slots (plugins/loader.ts) — a tool is gated IFF its ext
 * ships a <ext>/halter plugin. Fail-closed at both seams:
 *  - a BROKEN plugin (import/contract failure) blocks every call to its
 *    tool — the tool name is known (name must equal the ext dir), so the
 *    gate can never degrade to pass-through;
 *  - a plugin that THROWS in buildRequest blocks the call with the error.
 * A null classification passes ungated (discovery actions, status).
 */
export async function handleTool(
  event: ToolCallEvent,
  ctx: ExtensionContext,
) {
  const name = typeof event.toolName === "string" ? event.toolName : null;
  if (!name) return;

  const slot = getLoadedPlugins().get(name);
  if (!slot) return; // no plugin — not halter's surface

  if (slot.state === "broken") {
    return {
      block: true,
      reason: `[Permission Policy] halter plugin for '${name}' failed to load (${slot.error}) — blocked (fail closed). Fix the plugin and /reload.`,
    };
  }

  let req: ToolGateRequest | null;
  try {
    req = slot.plugin.buildRequest(event, ctx);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return {
      block: true,
      reason: `[Permission Policy] halter plugin '${name}' threw while classifying the call — blocked (fail closed): ${msg.slice(0, 200)}`,
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
    consentKind: req.kind === "consent" ? req.consentKind : undefined,
    argsPreview: req.kind !== "file" ? req.argsPreview : undefined,
    note: req.kind !== "file" ? req.note : undefined,
  };

  return await gate(request, ctx, store, (decision, result) =>
    rejectTool(decision, result, store, ctx),
  );
}
