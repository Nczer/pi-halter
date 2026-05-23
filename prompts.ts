import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import type { BuiltPrompt } from "./prompt-builder";
import { store } from "./store";
import { showSelect, showReasonEditor } from "./selector";

/** User's response to a two-tier prompt. */
type PromptResult = "yes" | "always" | "alwaysPaths" | "alwaysFile" | "no" | { kind: "no"; reason: string };

/**
 * Two-tier "always" confirmation flow.
 *
 * Tier 1: Ask user Yes / Always / No (with optional "Always (paths only)").
 * Tier 2: If user selects an "Always" option, confirm with a second prompt.
 *
 * Consumes a BuiltPrompt for all content — no string concatenation at call sites.
 * Calls the appropriate mutation callback on confirmed "always".
 */
export async function twoTierAlwaysPrompt(
  prompt: BuiltPrompt,
  ctx: ExtensionContext,
  onAlways: () => void,
  onAlwaysPaths: () => void,
  onAlwaysFile: () => void,
): Promise<PromptResult> {
  const { title, body, tier2Everything, tier2Paths, tier2File, includePathsOption, includeFileOption } = prompt;

  while (true) {
    const { over, count } = store.incrementPromptCount();
    let choices: string[];
    if (includePathsOption) {
      choices = ["Yes", "Always (everything)", "Always (paths only)", "No (with reason)", "No"];
    } else if (includeFileOption) {
      choices = ["Yes", "Always (this session)", "Always (this file only)", "No (with reason)", "No"];
    } else {
      choices = ["Yes", "Always (this session)", "No (with reason)", "No"];
    }
    const warningPrefix = over
      ? `\u26a0\ufe0f High prompt frequency (${count} prompts this session). "Always" reduces future prompts.\n\n`
      : "";

    const answer = await showSelect(ctx, warningPrefix + title + "\n---\n" + body, choices);

    if (answer === "Yes") return "yes";
    if (!answer || answer === "No") return "no";
    if (answer === "No (with reason)") {
      const reason = await showReasonEditor(ctx, "Reason for rejection:");
      if (reason === null) continue; // Escaped — back to selector
      return { kind: "no", reason: reason?.trim() || "No reason provided" };
    }

    if (includeFileOption && answer === "Always (this file only)") {
      const config = tier2File!;
      const tier2 = await showSelect(ctx, config.title, ["Always Yes", "Back"]);
      if (tier2 === "Always Yes") { onAlwaysFile(); return "alwaysFile"; }
      continue;
    }

    if (includePathsOption && answer === "Always (paths only)") {
      const config = tier2Paths ?? tier2Everything;
      const tier2 = await showSelect(ctx, config.title, ["Always Yes", "Back"]);
      if (tier2 === "Always Yes") { onAlwaysPaths(); return "alwaysPaths"; }
      continue;
    }

    const tier2Body = tier2Everything.body
      ? tier2Everything.body + "\n\n\u26a0\ufe0f This grants permission for the ENTIRE SESSION. Any subsequent matching operation will auto-allow without further prompts."
      : "\u26a0\ufe0f This grants permission for the ENTIRE SESSION. Any subsequent matching operation will auto-allow without further prompts.";
    const tier2 = await showSelect(ctx, tier2Everything.title + "\n---\n" + tier2Body, ["Always Yes", "Back"]);
    if (tier2 === "Always Yes") { onAlways(); return "always"; }
  }
}
