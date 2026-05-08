import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { resetState, updateWidget } from "./permission-state";
import { handleBash, handleSubagent, handleFile, handleMcp, handleMcpDirectTool } from "./handlers";

// ── Main extension ──

export default function (pi: ExtensionAPI) {
  // ── Session shutdown ──
  pi.on("session_shutdown", async (_event, ctx) => {
    resetState();
    ctx.ui.setWidget("permissions", undefined);
  });

  // ── Tool call interception ──
  pi.on("tool_call", async (event, ctx) => {
    return await handleMcp(event, ctx)
      ?? await handleMcpDirectTool(event, ctx)
      ?? await handleBash(event, ctx)
      ?? await handleSubagent(event, ctx)
      ?? await handleFile(event, ctx);
  });
}
