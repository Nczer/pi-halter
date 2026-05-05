import type { ExtensionAPI, ExtensionContext } from "@mariozechner/pi-coding-agent";
import { resetState, updateWidget } from "./permission-state";
import { handleBash, handleSubagent, handleFile } from "./handlers";

// ── Main extension ──

export default function (pi: ExtensionAPI) {
  // ── Session shutdown ──
  pi.on("session_shutdown", async (_event, ctx) => {
    resetState();
    ctx.ui.setWidget("permissions", undefined);
  });

  // ── Tool call interception ──
  pi.on("tool_call", async (event, ctx) => {
    return await handleBash(event, ctx)
      ?? await handleSubagent(event, ctx)
      ?? await handleFile(event, ctx);
  });
}
