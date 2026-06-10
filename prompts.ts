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
  const { title, body, tier2Everything, tier2Paths, tier2File, tier2Broader, includePathsOption, includeFileOption, includeBroaderOption, includeAlwaysOption, alwaysLabel, alwaysBroaderLabel, alwaysPathsLabel, alwaysFileLabel, permanentAllowExamples } = prompt;

  while (true) {
    const { over, count } = store.incrementPromptCount();

    // Build choices and a dispatch map: index → handler
    type DispatchFn = () => PromptResult | { kind: "custom"; pattern: string } | null | Promise<PromptResult | { kind: "custom"; pattern: string } | null>;
    let choices: string[];
    let dispatch: Map<number, DispatchFn>;

    if (!includeAlwaysOption) {
      choices = ["Yes", "Permanent always (config)", "No (with reason)", "No"];
    } else if (includeBroaderOption) {
      choices = ["Yes", `Always: ${alwaysLabel}`, `Always: ${alwaysBroaderLabel}`, "Permanent always (config)", "No (with reason)", "No"];
    } else if (includePathsOption) {
      choices = ["Yes", `Always: ${alwaysLabel}`, `Always (paths): ${alwaysPathsLabel}`, "Permanent always (config)", "No (with reason)", "No"];
    } else if (includeFileOption) {
      choices = ["Yes", `Always (path): ${alwaysLabel}`, `Always (file): ${alwaysFileLabel}`, "Permanent always (config)", "No (with reason)", "No"];
    } else {
      choices = ["Yes", `Always: ${alwaysLabel}`, "Permanent always (config)", "No (with reason)", "No"];
    }

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

    // Permanent always: always 3rd from end (before NoWithReason and No)
    const permanentIdx = choices.length - 3;
    if (effectiveIdx === permanentIdx) {
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
    // Resolve which callback and tier-2 config to use based on layout + index
    let tier2Config: { title: string; body: string };
    let callback: () => PromptResult;

    if (includeBroaderOption && includeFileOption) {
      // File with both directory and file options
      if (idx === Choice.Always) {
        tier2Config = tier2Everything;
        callback = () => { onAlways(); return "always" as PromptResult; };
      } else {
        tier2Config = tier2Broader ?? tier2Everything;
        callback = () => { onAlwaysBroader?.(); return "always" as PromptResult; };
      }
    } else if (includeBroaderOption) {
      if (idx === Choice.Always) {
        // Always: specific sigs
        tier2Config = tier2Everything;
        callback = () => { onAlways(); return "always" as PromptResult; };
      } else {
        // Always: broader sigs
        tier2Config = tier2Broader ?? tier2Everything;
        callback = () => { onAlwaysBroader?.(); return "always" as PromptResult; };
      }
    } else if (includeFileOption) {
      if (idx === Choice.Always) {
        // Always (path)
        tier2Config = tier2Everything;
        callback = () => { onAlways(); return "always" as PromptResult; };
      } else {
        // Always (file)
        tier2Config = tier2File!;
        callback = () => { onAlwaysFile(); return "alwaysFile" as PromptResult; };
      }
    } else if (includePathsOption) {
      if (idx === Choice.Always) {
        // Always: sigs + paths
        tier2Config = tier2Everything;
        callback = () => { onAlways(); return "always" as PromptResult; };
      } else {
        // Always (paths)
        tier2Config = tier2Paths ?? tier2Everything;
        callback = () => { onAlwaysPaths(); return "alwaysPaths" as PromptResult; };
      }
    } else {
      // Default: single Always option
      const tier2Body = tier2Everything.body
        ? tier2Everything.body + "\n\n\u26a0\ufe0f This grants permission for the ENTIRE SESSION. Any subsequent matching operation will auto-allow without further prompts."
        : "\u26a0\ufe0f This grants permission for the ENTIRE SESSION. Any subsequent matching operation will auto-allow without further prompts.";
      tier2Config = { title: tier2Everything.title, body: tier2Body };
      callback = () => { onAlways(); return "always" as PromptResult; };
    }

    // Show tier-2 confirmation
    const tier2Idx = await showSelectIndex(ctx, tier2Config.title + "\n---\n" + tier2Config.body, ["Always Yes", "Back"]);
    if (tier2Idx === Tier2.Confirm) return callback();
    // tier2Idx === Back || null → loop
  }
}

