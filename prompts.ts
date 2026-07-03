import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import type { BuiltPrompt } from "./prompt-builder";
import { store } from "./store";
import { showSelectIndex, showReasonEditor } from "./selector";

/** User's response to a two-tier prompt. */
type PromptResult = "yes" | "always" | "alwaysPaths" | "alwaysFile" | "no" | { kind: "no"; reason: string };

/** Choice action tags — decoupled from display labels. */
enum Choice {
  Yes = 0,
  Always = 1,
  AlwaysAlt = 2,   // broader / paths / file (variant by layout)
  AlwaysBroader = 2, // alias for AlwaysAlt
  Permanent = 3,
  NoWithReason = 4,
  No = 5,
}

/** Tier-2 choice indices. */
enum Tier2 {
  Confirm = 0,
  Back = 1,
}

/**
 * Two-tier "always" confirmation flow.
 *
 * Tier 1: Ask user Yes / Always / No (with optional "Always (paths only)").
 * Tier 2: If user selects an "Always" option, confirm with a second prompt.
 *
 * Consumes a BuiltPrompt for all content — no string concatenation at call sites.
 * Calls the appropriate mutation callback on confirmed "always".
 *
 * Uses index-based choice dispatch (not string matching) so label changes
 * cannot break the decision logic.
 */
export async function twoTierAlwaysPrompt(
  prompt: BuiltPrompt,
  ctx: ExtensionContext,
  onAlways: () => void,
  onAlwaysPaths: () => void,
  onAlwaysFile: () => void,
  onAlwaysBroader?: () => void,
  onCustomAlways?: (pattern: string) => Promise<void>,
): Promise<PromptResult | { kind: "custom"; pattern: string }> {
  const { title, body, tier2Everything, tier2Paths, tier2File, tier2Broader, includePathsOption, includeFileOption, includeBroaderOption, includeAlwaysOption, includePermanentOption, alwaysLabel, alwaysBroaderLabel, alwaysPathsLabel, alwaysFileLabel, permanentAllowExamples } = prompt;

  while (true) {
    const { over, count } = store.incrementPromptCount();

    // Build choices and a dispatch map: index → handler
    type DispatchFn = () => PromptResult | { kind: "custom"; pattern: string } | null | Promise<PromptResult | { kind: "custom"; pattern: string } | null>;
    let choices: string[];
    let dispatch: Map<number, DispatchFn>;

    // Permanent allow is suppressed for MCP (no `mcp` rule bucket) — see includePermanentOption.
    const hasPermanent = includePermanentOption !== false;

    // Build the "Always" option labels (middle of the list), then append the tail
    // (Permanent? + No-with-reason + No). Permanent sits 3rd from the end when present.
    const alwaysOptions: string[] = [];
    if (includeAlwaysOption) {
      if (includeBroaderOption && includePathsOption) {
        alwaysOptions.push(`Always: ${alwaysLabel}`, `Always: ${alwaysBroaderLabel}`, `Always (paths): ${alwaysPathsLabel}`);
      } else if (includeBroaderOption) {
        alwaysOptions.push(`Always: ${alwaysLabel}`, `Always: ${alwaysBroaderLabel}`);
      } else if (includePathsOption) {
        alwaysOptions.push(`Always: ${alwaysLabel}`, `Always (paths): ${alwaysPathsLabel}`);
      } else if (includeFileOption) {
        alwaysOptions.push(`Always (path): ${alwaysLabel}`, `Always (file): ${alwaysFileLabel}`);
      } else {
        alwaysOptions.push(`Always: ${alwaysLabel}`);
      }
    }
    choices = ["Yes", ...alwaysOptions];
    if (hasPermanent) choices.push("Permanent Always (config)");
    choices.push("No (with reason)", "No");

    const warningPrefix = over
      ? `\u26a0\ufe0f High prompt frequency (${count} prompts this session). "Always" reduces future prompts.\n\n`
      : "";

    const idx = await showSelectIndex(ctx, warningPrefix + title + "\n---\n" + body, choices);
    if (idx === null) return "no"; // cancelled

    // ── Adjust indices when Always options are suppressed ──
    const effectiveIdx = !includeAlwaysOption
      ? idx // [Yes, Permanent, NoWithReason, No] → 0,1,2,3
      : idx; // [Yes, Always, ..., Permanent, NoWithReason, No] → enum indices

    // ── Direct actions (no tier-2) ──
    if (effectiveIdx === Choice.Yes) return "yes";

    // No index depends on layout; compute from end
    const noIdx = choices.length - 1;
    const noWithReasonIdx = choices.length - 2;
    if (effectiveIdx === noIdx) return "no";

    // Permanent always: 3rd from end, present only when includePermanentOption !== false
    if (hasPermanent && effectiveIdx === choices.length - 3) {
      const examples = permanentAllowExamples || "Example: 'npm test *' or '/mnt/data/logs/*'";
      const pattern = await showReasonEditor(ctx, `Enter a wildcard pattern for permanent allow (saved to ~/.pi/agent/permissions.json).\n\nPatterns are case-insensitive:\n• '*' matches any characters\n• '?' matches one character\n\n${examples}`);
      if (pattern === null || pattern.trim().length === 0) continue;
      const p = pattern.trim();
      if (onCustomAlways) await onCustomAlways(p);
      return { kind: "custom", pattern: p };
    }

    if (effectiveIdx === noWithReasonIdx) {
      const reason = await showReasonEditor(ctx, "Reason for rejection:");
      if (reason === null) continue;
      return { kind: "no", reason: reason?.trim() || "No reason provided" };
    }

    // ── Tier-2 confirmation for "Always" choices ──
    // Build dispatch table: choice index → (tier2Config, callback)
    interface Tier2Entry { config: { title: string; body: string }; fn: () => PromptResult; }
    const entries: Tier2Entry[] = [];

    // Primary "Always" (always at Choice.Always = index 1)
    {
      const primaryConfig = includeBroaderOption || includePathsOption || includeFileOption
        ? tier2Everything
        : {
            title: tier2Everything.title,
            body: tier2Everything.body
              ? tier2Everything.body + "\n\n\u26a0\ufe0f This grants permission for the ENTIRE SESSION. Any subsequent matching operation will auto-allow without further prompts."
              : "\u26a0\ufe0f This grants permission for the ENTIRE SESSION. Any subsequent matching operation will auto-allow without further prompts.",
          };
      entries.push({ config: primaryConfig, fn: () => { onAlways(); return "always" as PromptResult; } });
    }

    // Broader option (e.g. "npm *" instead of "npm test *")
    if (includeBroaderOption) {
      entries.push({ config: tier2Broader ?? tier2Everything, fn: () => { onAlwaysBroader?.(); return "always" as PromptResult; } });
    }

    // Paths-only option (bash with outside dirs)
    if (includePathsOption) {
      entries.push({ config: tier2Paths ?? tier2Everything, fn: () => { onAlwaysPaths(); return "alwaysPaths" as PromptResult; } });
    }

    // File-only option (file outside cwd)
    if (includeFileOption) {
      entries.push({ config: tier2File!, fn: () => { onAlwaysFile(); return "alwaysFile" as PromptResult; } });
    }

    // Resolve: idx maps to entry index (Choice.Always=1 → entries[0], Choice.AlwaysAlt=2 → entries[1], etc.)
    const entryIdx = idx - Choice.Always;
    const entry = entries[entryIdx];
    if (!entry) {
      // Fallback: should not happen given the choices array is built consistently
      const tier2Body = "\u26a0\ufe0f This grants permission for the ENTIRE SESSION. Any subsequent matching operation will auto-allow without further prompts.";
      const tier2Config = { title: tier2Everything.title, body: tier2Body };
      const callback = () => { onAlways(); return "always" as PromptResult; };
      const tier2Idx = await showSelectIndex(ctx, tier2Config.title + "\n---\n" + tier2Config.body, ["Always Yes", "Back"]);
      if (tier2Idx === Tier2.Confirm) return callback();
      continue;
    }

    // Show tier-2 confirmation
    const tier2Idx = await showSelectIndex(ctx, entry.config.title + "\n---\n" + entry.config.body, ["Always Yes", "Back"]);
    if (tier2Idx === Tier2.Confirm) return entry.fn();
    // tier2Idx === Back || null → loop
  }
}

