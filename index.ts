import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { updateWidget } from "./widget";
import { handleBash, handleFile, handleMcp, handleMcpDirectTool } from "./handlers";
import { isDspActive, setDspActive, updateDspWidget } from "./dsp-mode";
import { isDspatActive, resetDspat, setDspatActive, updateDspatWidget } from "./dspat-mode";
import { isDspaActive, resetDspa, setDspaActive, updateDspaWidget } from "./dspa-mode";
import { isDecisionLogEnabled, setDecisionLogEnabled } from "./decision-log";
import { readJudgeSettings, writeJudgeSettings, resetJudgeCache, THINKING_VALUES, type JudgeSettings } from "./judge";
import { judgeStatus } from "./judge-prompt";
import { store } from "./store";

// ── Main extension ──

/**
 * The dsp modes are one machine with four states: manual (none active — the
 * default), dsp, dspa, dspat. Enabling one leaves the others off; leaving a
 * judge mode resets its session stats (as toggling it off does). The command
 * handlers below are the only writers of mode state, so the booleans can
 * never be simultaneously true.
 *
 * @returns the mode that was active before the switch (null when manual),
 *   for the "(X off)" note in the toast.
 */
function applyMode(ctx: ExtensionContext, next: "manual" | "dsp" | "dspa" | "dspat"): string | null {
  const displaced = isDspActive() ? "DSP" : isDspaActive() ? "DSPA" : isDspatActive() ? "DSPAT" : null;
  const wasDsp = isDspActive();
  setDspActive(false);
  resetDspa();
  resetDspat();
  if (next === "dsp") setDspActive(true);
  else if (next === "dspa") setDspaActive(true);
  else if (next === "dspat") setDspatActive(true);
  // Each update fn syncs its own widget (render when active, clear when not).
  updateDspWidget(ctx);
  updateDspaWidget(ctx);
  updateDspatWidget(ctx);
  // The normal halter widget is hidden while DSP bypasses the gate —
  // restored only when LEAVING dsp (matching the pre-switch behavior).
  if (isDspActive()) ctx.ui.setWidget("halter", undefined);
  else if (wasDsp) updateWidget(ctx);
  return displaced;
}

export default async function halterExtension(pi: ExtensionAPI) {
  // ── Session shutdown ──
  pi.on("session_shutdown", async (_event, ctx) => {
    store.reset();
    setDspActive(false);
    resetDspat();
    resetDspa();
    resetJudgeCache();
    ctx.ui.setWidget("halter", undefined);
    ctx.ui.setWidget("dsp-warning", undefined);
    ctx.ui.setWidget("dspat", undefined);
    ctx.ui.setWidget("dspa", undefined);
    ctx.ui.setWidget("judge", undefined);
  });

  // ── /dsp command (exclusive with /dspa and /dspat) ──
  pi.registerCommand("dsp", {
    description: "Toggle Dangerous Skip Permissions mode (bypass all permission checks); exclusive with /dspa and /dspat",
    handler: async (_args, ctx) => {
      // Show confirm prompt before enabling; disabling toggles instantly
      if (!isDspActive() && ctx.hasUI) {
        const ok = await ctx.ui.confirm("Enable DSP (Dangerously Skip Permissions)?", "This bypasses ALL permission checks.");
        if (!ok) return; // cancelled or No — the current mode stays
      }
      const displaced = applyMode(ctx, isDspActive() ? "manual" : "dsp");
      ctx.ui.notify(
        isDspActive()
          ? `DSP MODE ON — all permissions bypassed${displaced ? ` (${displaced} off)` : ""}`
          : "DSP MODE OFF — permissions restored",
        isDspActive() ? "warning" : "info",
      );
    },
  });

  // ── /dspat command (exclusive with /dspa and /dsp) ──
  pi.registerCommand("dspat", {
    description:
      "Toggle judge advisory mode: the judge explains every bash prompt and suggests approve/reject; you still decide (verdicts are logged). Exclusive with /dspa and /dsp",
    handler: async (_args, ctx) => {
      const displaced = applyMode(ctx, isDspatActive() ? "manual" : "dspat");
      ctx.ui.notify(
        isDspatActive()
          ? `DSPAT ON — judge advises on every bash prompt (you decide)${displaced ? ` (${displaced} off)` : ""}`
          : "DSPAT OFF — judge suggestions disabled",
        "info",
      );
    },
  });

  // ── /dspa command (exclusive with /dspat and /dsp) ──
  pi.registerCommand("dspa", {
    description:
      "Toggle judge auto-allow mode: operations passing the hard gate AND an approving low-risk judge verdict run without a prompt (visible toast); everything else prompts as usual. Exclusive with /dspat and /dsp",
    handler: async (_args, ctx) => {
      const displaced = applyMode(ctx, isDspaActive() ? "manual" : "dspa");
      ctx.ui.notify(
        isDspaActive()
          ? `DSPA ON — gate+judge-approved operations auto-allow (toast per allow)${displaced ? ` (${displaced} off)` : ""}`
          : "DSPA OFF — all prompts restored",
        "info",
      );
    },
  });

  // ── /judge command ──
  pi.registerCommand("judge", {
    description:
      "Judge settings: bare = show; 'on|off', 'model <provider/id|session>', 'thinking <off|minimal|low|medium|high|xhigh|max>', 'timeout <ms>'",
    handler: async (args, ctx) => {
      const arg = (args ?? "").trim();
      const show = (s = readJudgeSettings()): void => {
        const js = judgeStatus(ctx);
        ctx.ui.notify(
          `Judge: ${s.enabled ? "on" : "off"} — model: ${js.modelLabel ?? "(unresolvable)"} — thinking: ${s.thinking} — timeout: ${s.timeoutMs}ms (${js.state === "invalid" ? `⚠ ${js.reason}` : "~/.pi/agent/halter.json"})`,
          js.state === "invalid" ? "warning" : "info",
        );
      };
      if (!arg) {
        show();
        return;
      }
      const [cmd, ...rest] = arg.split(/\s+/);
      const value = rest.join(" ").trim();
      switch (cmd) {
        case "on":
        case "enable":
          writeJudgeSettings({ enabled: true });
          show();
          return;
        case "off":
        case "disable":
          writeJudgeSettings({ enabled: false });
          show();
          return;
        case "model":
          if (!value) { show(); return; }
          if (value.toLowerCase() === "session") {
            writeJudgeSettings({ provider: null, model: null });
          } else {
            const slash = value.indexOf("/");
            if (slash <= 0) {
              ctx.ui.notify("Judge: model must be '<provider>/<id>' or 'session'", "warning");
              return;
            }
            writeJudgeSettings({ provider: value.slice(0, slash), model: value.slice(slash + 1) });
          }
          show();
          return;
        case "thinking": {
          if (!value || !THINKING_VALUES.has(value.toLowerCase())) {
            ctx.ui.notify(`Judge: thinking must be one of ${[...THINKING_VALUES].join(" | ")}`, "warning");
            return;
          }
          writeJudgeSettings({ thinking: value.toLowerCase() as JudgeSettings["thinking"] });
          show();
          return;
        }
        case "timeout": {
          const ms = Number(value);
          if (!Number.isFinite(ms) || ms <= 0) {
            ctx.ui.notify("Judge: timeout must be a positive number of ms", "warning");
            return;
          }
          writeJudgeSettings({ timeoutMs: Math.round(ms) });
          show();
          return;
        }
        default:
          show();
      }
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
