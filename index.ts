import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { updateWidget } from "./widget";
import { handleBash, handleFile, handleMcp, handleMcpDirectTool } from "./handlers";
import { isDspActive, setDspActive, updateDspWidget } from "./dsp-mode";
import { isDecisionLogEnabled, setDecisionLogEnabled } from "./decision-log";
import { store } from "./store";

// ── Main extension ──

export default async function halterExtension(pi: ExtensionAPI) {
  // ── Session shutdown ──
  pi.on("session_shutdown", async (_event, ctx) => {
    store.reset();
    setDspActive(false);
    ctx.ui.setWidget("halter", undefined);
    ctx.ui.setWidget("dsp-warning", undefined);
  });

  // ── /dsp command ──
  pi.registerCommand("dsp", {
    description: "Toggle Dangerous Skip Permissions mode (bypass all permission checks)",
    handler: async (_args, ctx) => {
      // Show confirm prompt before enabling; disabling toggles instantly
      if (!isDspActive() && ctx.hasUI) {
        const ok = await ctx.ui.confirm("Enable DSP (Dangerously Skip Permissions)?", "This bypasses ALL permission checks.");
        if (!ok) return; // cancelled or No
      }

      setDspActive(!isDspActive());
      updateDspWidget(ctx);
      // Hide the normal halter widget when DSP is active; restore it when DSP is off
      if (isDspActive()) {
        ctx.ui.setWidget("halter", undefined);
      } else {
        updateWidget(ctx);
      }
      ctx.ui.notify(
        isDspActive() ? "DSP MODE ON — all permissions bypassed" : "DSP MODE OFF — permissions restored",
        isDspActive() ? "warning" : "info",
      );
    },
  });

  // ── /halter-decision-log command ──
  pi.registerCommand("halter-decision-log", {
    description: "Toggle the JSONL decision log on/off. Pass 'on', 'off', or nothing to toggle. Saved in ~/.pi/agent/halter.json.",
    handler: async (args, ctx) => {
      const arg = (args ?? "").trim().toLowerCase();
      const next =
        arg === "on" || arg === "enable" ? true : arg === "off" || arg === "disable" ? false : !isDecisionLogEnabled();
      setDecisionLogEnabled(next);
      ctx.ui.notify(
        `Halter: decision log ${next ? "enabled" : "disabled"} (${next ? ".log/decisions.jsonl" : "no logging"})`,
        next ? "info" : "warning",
      );
    },
  });

  // ── Tool call interception ──
  pi.on("tool_call", async (event, ctx) => {
    // DSP mode: bypass all permission checks
    if (isDspActive()) return;

    try {
      return await handleMcp(event, ctx)
        ?? await handleMcpDirectTool(event, ctx)
        ?? await handleBash(event, ctx)
        ?? await handleFile(event, ctx);
    } catch (err) {
      // Fail closed (defense in depth): an internal gate error must never
      // leave a command un-gated. The pi harness currently catches handler
      // throws (agent-loop prepareToolCall → error tool result), but
      // emitToolCall itself has no try/catch (perm #452-A1) — halter must
      // not depend on harness behavior for its fail-closed guarantee.
      const message = err instanceof Error ? err.message : String(err);
      return { block: true, reason: `halter gate error: ${message}` };
    }
  });
}
