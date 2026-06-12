import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { updateWidget } from "./widget";
import { handleBash, handleFile, handleMcp, handleMcpDirectTool } from "./handlers";
import { isDspActive, setDspActive, updateDspWidget } from "./dsp-mode";
import { store } from "./store";

// ── Main extension ──

export default async function permissionExtension(pi: ExtensionAPI) {
  // Initialize user permissions from disk
  await store.init();

  // ── Session shutdown ──
  pi.on("session_shutdown", async (_event, ctx) => {
    store.reset();
    setDspActive(false);
    ctx.ui.setWidget("permissions", undefined);
    ctx.ui.setWidget("dsp-warning", undefined);
  });

  // ── /dsp command ──
  pi.registerCommand("dsp", {
    description: "Toggle Dangerous Skip Permissions mode (bypass all permission checks)",
    handler: async (_args, ctx) => {
      setDspActive(!isDspActive());
      updateDspWidget(ctx);
      // Hide the normal permissions widget when DSP is active; restore it when DSP is off
      if (isDspActive()) {
        ctx.ui.setWidget("permissions", undefined);
      } else {
        updateWidget(ctx);
      }
      ctx.ui.notify(
        isDspActive() ? "DSP MODE ON — all permissions bypassed" : "DSP MODE OFF — permissions restored",
        isDspActive() ? "warning" : "info",
      );
    },
  });

  // ── /perms command ──
  pi.registerCommand("perms", {
    description: "Audit and manage permanent permission rules. Usage: /perms [list|remove <type> <index>]",
    handler: async (args, ctx) => {
      const [action, type, indexStr] = args;

      if (action === "remove") {
        if (!type || !indexStr) {
          return ctx.ui.notify("Usage: /perms remove <bash|read|write> <index>", "error");
        }
        const index = parseInt(indexStr, 10);
        if (isNaN(index)) {
          return ctx.ui.notify("Index must be a number", "error");
        }
        try {
          await store.removeUserRule(type as "bash" | "read" | "write", index);
          ctx.ui.notify(`Removed rule ${index} from ${type} rules.`, "info");
        } catch (e) {
          ctx.ui.notify(`Failed to remove rule: ${e instanceof Error ? e.message : String(e)}`, "error");
        }
        return;
      }

      // Default: List rules
      const rules = await store.listUserRules();
      let message = "### Permanent Permission Rules\n\n";

      for (const type of ["bash", "read", "write"] as const) {
        const typeRules = rules[type];
        message += `**${type.toUpperCase()}**:\n`;
        if (typeRules.length === 0) {
          message += "- No rules\n";
        } else {
          typeRules.forEach((r, i) => {
            message += `${i}. [${r.action}] ${r.pattern}\n`;
          });
        }
        message += "\n";
      }

      message += "\nTo remove a rule: `/perms remove <type> <index>`";
      ctx.ui.notify(message, "info");
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
