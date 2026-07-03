import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { updateWidget } from "./widget";
import { handleBash, handleFile, handleMcp, handleMcpDirectTool } from "./handlers";
import { isDspActive, setDspActive, updateDspWidget } from "./dsp-mode";
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

  // ── Tool call interception ──
  pi.on("tool_call", async (event, ctx) => {
    // DSP mode: bypass all permission checks
    if (isDspActive()) return;

    return await handleMcp(event, ctx)
      ?? await handleMcpDirectTool(event, ctx)
      ?? await handleBash(event, ctx)
      ?? await handleFile(event, ctx);
  });
}
