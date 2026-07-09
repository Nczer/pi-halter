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
 *
 * For file prompts with broaderPaths, a three-level structure is used:
 *   Level 1: Yes / file / path (1 level up) / broader (2+ levels up) / No
 *   Level 2 (broader): pick which parent directory
 *   Level 3: confirm "Always Yes"
 */
export async function twoTierAlwaysPrompt(
  prompt: BuiltPrompt,
  ctx: ExtensionContext,
  onAlways: () => void,
  onAlwaysPaths: () => void,
  onAlwaysFile: () => void,
  onAlwaysBroader?: (dir?: string) => void,
): Promise<PromptResult> {
  const { title, body, tier2Everything, tier2Paths, tier2File, tier2Broader, includePathsOption, includeFileOption, includeBroaderOption, includeAlwaysOption, alwaysLabel, alwaysBroaderLabel, alwaysPathsLabel, alwaysFileLabel, broaderPaths } = prompt;

  // Count this prompt once — not once per loop iteration (Back from tier-2
  // shouldn't inflate the frequency warning).
  const { over, count } = store.incrementPromptCount();

  while (true) {
    // Build the "Always" option labels (middle of the list), then append the tail
    // (No-with-reason + No).
    const alwaysOptions: string[] = [];
    if (includeAlwaysOption) {
      if (includeFileOption && includeBroaderOption && broaderPaths && broaderPaths.length > 0) {
        // Outside-cwd with broader: path / file / broader
        alwaysOptions.push(`Always (path): ${alwaysLabel}`);
        alwaysOptions.push(`Always (file): ${alwaysFileLabel}`);
        alwaysOptions.push(`Always (broader)`);
      } else if (includeBroaderOption && broaderPaths && broaderPaths.length > 0) {
        // Inside-cwd: file / path (1 parent) / broader (remaining parents)
        alwaysOptions.push(`Always (file): ${alwaysLabel}`);
        alwaysOptions.push(`Always (path): ${broaderPaths[0].label}`);
        if (broaderPaths.length > 1) {
          alwaysOptions.push(`Always (broader)`);
        }
      } else if (includeBroaderOption && includePathsOption) {
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
    const choices = ["Yes", ...alwaysOptions, "No (with reason)", "No"];

    const warningPrefix = over
      ? `\u26a0\ufe0f High prompt frequency (${count} prompts this session). "Always" reduces future prompts.\n\n`
      : "";

    const idx = await showSelectIndex(ctx, warningPrefix + title + "\n---\n" + body, choices);
    if (idx === null) return "no"; // cancelled

    // ── Direct actions (no tier-2) ──
    if (idx === Choice.Yes) return "yes";

    // No / No-with-reason are the last two choices
    const noIdx = choices.length - 1;
    const noWithReasonIdx = choices.length - 2;
    if (idx === noIdx) return "no";

    if (idx === noWithReasonIdx) {
      const reason = await showReasonEditor(ctx, "Reason for rejection:");
      if (reason === null) continue;
      return { kind: "no", reason: reason?.trim() || "No reason provided" };
    }

    // ── Tier-2 for "Always" choices ──
    interface Tier2Entry { config: { title: string; body: string }; fn: () => PromptResult; }
    const entries: Tier2Entry[] = [];

    // Track whether the umbrella "broader" entry was added
    let hasBroaderUmbrella = false;

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

    // File-only option — always at entries[1] for outside-cwd
    if (includeFileOption) {
      entries.push({ config: tier2File!, fn: () => { onAlwaysFile(); return "alwaysFile" as PromptResult; } });
    }

    // Broader options
    if (includeBroaderOption) {
      if (broaderPaths && broaderPaths.length > 0) {
        if (includeFileOption) {
          // Outside-cwd: all broader paths under umbrella sub-prompt (entries[2] since file is at [1])
          hasBroaderUmbrella = true;
          entries.push({
            config: { title: "", body: "" },
            fn: () => "always" as PromptResult,
          });
        } else {
          // Inside-cwd: first parent level (path) shown directly
          entries.push({
            config: {
              title: "Confirm Always Allow",
              body: `"Always Yes" will auto-allow read for this directory this session (write/edit will still prompt):\n\n  ${broaderPaths[0].dir}/*`,
            },
            fn: () => { onAlwaysBroader?.(broaderPaths[0].dir); return "always" as PromptResult; },
          });
          // Remaining parent levels under umbrella "broader"
          if (broaderPaths.length > 1) {
            hasBroaderUmbrella = true;
            entries.push({
              config: { title: "", body: "" },
              fn: () => "always" as PromptResult,
            });
          }
        }
      } else {
        // Bash: single broader option (package manager prefix)
        entries.push({
          config: tier2Broader ?? tier2Everything,
          fn: () => { onAlwaysBroader?.(); return "always" as PromptResult; },
        });
      }
    }

    // Paths-only option (bash with outside dirs)
    if (includePathsOption) {
      entries.push({ config: tier2Paths ?? tier2Everything, fn: () => { onAlwaysPaths(); return "alwaysPaths" as PromptResult; } });
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

    // ── Handle umbrella "Always (broader)" — show sub-prompt ──
    if (hasBroaderUmbrella && entryIdx === 2) {
      // For outside-cwd (includeFileOption): show all broaderPaths
      // For inside-cwd: skip the first broaderPath (shown directly as "path")
      const startIdx = includeFileOption ? 0 : 1;
      const subLabels = broaderPaths!.slice(startIdx).map(bp => bp.label);
      const subChoices = [...subLabels, "Back"];
      const subIdx = await showSelectIndex(ctx, "Select a broader directory to always allow:", subChoices);
      if (subIdx === null || subIdx === subLabels.length) continue; // Back / cancel

      const chosen = broaderPaths![subIdx + startIdx];
      const tier2Body = `"Always Yes" will auto-allow read for this directory this session (write/edit will still prompt):\n\n  ${chosen.dir}/*`;
      const tier2Idx = await showSelectIndex(ctx, "Confirm Always Allow\n---\n" + tier2Body, ["Always Yes", "Back"]);
      if (tier2Idx === Tier2.Confirm) {
        onAlwaysBroader?.(chosen.dir);
        return "always" as PromptResult;
      }
      continue;
    }

    // ── Standard tier-2 confirmation ──
    const tier2Idx = await showSelectIndex(ctx, entry.config.title + "\n---\n" + entry.config.body, ["Always Yes", "Back"]);
    if (tier2Idx === Tier2.Confirm) return entry.fn();

    // tier2Idx === Back || null → loop
  }
}
