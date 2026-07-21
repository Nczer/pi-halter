import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import type { BuiltPrompt } from "./prompt-builder";
import type { Store } from "./store";
import { showSelectIndex, showReasonEditor } from "./selector";

/** User's response to a two-tier prompt. */
type PromptResult = "yes" | "always" | "alwaysPaths" | "alwaysFile" | "no" | { kind: "no"; reason: string };

/** Tier-2 choice indices. */
enum Tier2 {
  Confirm = 0,
  Back = 1,
}

const SESSION_SCOPE_WARNING =
  "\n\n⚠️ This grants permission for the ENTIRE SESSION. Any subsequent matching operation will auto-allow without further prompts.";

// ── Data-driven tier-1 options ──

/** Mutation callbacks supplied by the caller for each "Always" flavor. */
interface AlwaysCallbacks {
  onAlways: () => void;
  onAlwaysPaths: () => void;
  onAlwaysFile: () => void;
  onAlwaysBroader?: (dir?: string) => void;
}

/** A tier-1 "Always" option that confirms via a standard tier-2 prompt. */
interface ConfirmOption {
  kind: "confirm";
  label: string;
  title: string;
  body: string;
  /** Runs the mutation callback and returns the flow result. */
  apply: () => PromptResult;
}

/** A tier-1 option that opens a sub-menu of broader parent directories. */
interface UmbrellaOption {
  kind: "umbrella";
  label: string;
  /** Index into prompt.broaderPaths where the sub-menu starts. */
  startIdx: number;
}

type AlwaysOption = ConfirmOption | UmbrellaOption;

function confirmOpt(
  label: string,
  config: { title: string; body: string },
  apply: () => PromptResult,
): ConfirmOption {
  return { kind: "confirm", label, title: config.title, body: config.body, apply };
}

/**
 * Build the tier-1 "Always" options for a prompt.
 *
 * Single source of truth for both the display labels and the behavior of each
 * option — adding a new "Always" flavor means appending one entry here, with
 * no index arithmetic to keep in sync.
 */
function buildAlwaysOptions(prompt: BuiltPrompt, cb: AlwaysCallbacks): AlwaysOption[] {
  if (!prompt.includeAlwaysOption) return [];

  const { broaderPaths } = prompt;
  const hasBroaderPaths = !!(prompt.includeBroaderOption && broaderPaths && broaderPaths.length > 0);

  // File prompts with a parent-directory hierarchy (inside or outside cwd)
  if (hasBroaderPaths) {
    if (prompt.includeFileOption) {
      // Outside cwd: path / file / broader umbrella (all parents)
      return [
        confirmOpt(`Always (path): ${prompt.alwaysLabel}`, prompt.tier2Everything, () => { cb.onAlways(); return "always"; }),
        confirmOpt(`Always (file): ${prompt.alwaysFileLabel}`, prompt.tier2File!, () => { cb.onAlwaysFile(); return "alwaysFile"; }),
        { kind: "umbrella", label: "Always (broader)", startIdx: 0 },
      ];
    }
    // Inside cwd: file / path (immediate parent) / broader umbrella (remaining parents)
    const options: AlwaysOption[] = [
      confirmOpt(`Always (file): ${prompt.alwaysLabel}`, prompt.tier2Everything, () => { cb.onAlways(); return "always"; }),
      confirmOpt(
        `Always (path): ${broaderPaths![0].label}`,
        {
          title: "Confirm Always Allow",
          body: prompt.tier2Broader?.body
            ?? `"Always Yes" will auto-allow for this directory this session:\n\n  ${broaderPaths![0].dir}/*`,
        },
        () => { cb.onAlwaysBroader?.(broaderPaths![0].dir); return "always"; },
      ),
    ];
    if (broaderPaths!.length > 1) {
      options.push({ kind: "umbrella", label: "Always (broader)", startIdx: 1 });
    }
    return options;
  }

  // Standard layout: primary + optional variants (bash, MCP, outside-cwd file without parents)
  const hasVariants = prompt.includeBroaderOption || prompt.includePathsOption || prompt.includeFileOption;
  const primaryConfig = hasVariants
    ? prompt.tier2Everything
    : {
        title: prompt.tier2Everything.title,
        body: prompt.tier2Everything.body
          ? prompt.tier2Everything.body + SESSION_SCOPE_WARNING
          : SESSION_SCOPE_WARNING.trimStart(),
      };

  const options: AlwaysOption[] = [
    confirmOpt(
      prompt.includeFileOption ? `Always (path): ${prompt.alwaysLabel}` : `Always: ${prompt.alwaysLabel}`,
      primaryConfig,
      () => { cb.onAlways(); return "always"; },
    ),
  ];
  if (prompt.includeFileOption) {
    options.push(confirmOpt(`Always (file): ${prompt.alwaysFileLabel}`, prompt.tier2File!, () => { cb.onAlwaysFile(); return "alwaysFile"; }));
  }
  if (prompt.includeBroaderOption) {
    // Bash: broader package-manager prefix (e.g. "npm *")
    options.push(confirmOpt(`Always: ${prompt.alwaysBroaderLabel}`, prompt.tier2Broader ?? prompt.tier2Everything, () => { cb.onAlwaysBroader?.(); return "always"; }));
  }
  if (prompt.includePathsOption) {
    options.push(confirmOpt(`Always (paths): ${prompt.alwaysPathsLabel}`, prompt.tier2Paths ?? prompt.tier2Everything, () => { cb.onAlwaysPaths(); return "alwaysPaths"; }));
  }
  return options;
}

// ── Prompt helpers ──

/** Show a tier-2 confirmation ("Always Yes" / "Back"). Returns true on confirm. */
async function confirmAlways(ctx: ExtensionContext, title: string, body: string): Promise<boolean> {
  const idx = await showSelectIndex(ctx, title + "\n---\n" + body, ["Always Yes", "Back"]);
  return idx === Tier2.Confirm;
}

/**
 * Run the umbrella "Always (broader)" sub-menu: pick a parent directory,
 * then confirm. Returns the flow result on confirm, or null to loop back
 * to tier-1 (Back / cancel at any level).
 */
async function runBroaderUmbrella(
  prompt: BuiltPrompt,
  startIdx: number,
  ctx: ExtensionContext,
  onAlwaysBroader?: (dir?: string) => void,
): Promise<PromptResult | null> {
  const broaderPaths = prompt.broaderPaths!;
  const subLabels = broaderPaths.slice(startIdx).map(bp => bp.label);
  const subIdx = await showSelectIndex(ctx, "Select a broader directory to always allow:", [...subLabels, "Back"]);
  if (subIdx === null || subIdx === subLabels.length) return null; // Back / cancel

  const chosen = broaderPaths[subIdx + startIdx];
  const action = chosen.label.split(" ")[0];
  const isWrite = action !== "Read";
  const body = isWrite
    ? `"Always Yes" will auto-allow ${action.toLowerCase()} for this directory this session (includes read):\n\n  ${chosen.dir}/*`
    : `"Always Yes" will auto-allow read for this directory this session (write/edit will still prompt):\n\n  ${chosen.dir}/*`;

  if (await confirmAlways(ctx, "Confirm Always Allow", body)) {
    onAlwaysBroader?.(chosen.dir);
    return "always";
  }
  return null;
}

/**
 * Two-tier "always" confirmation flow.
 *
 * Tier 1: Ask user Yes / Always… / No (options derived data-driven from the BuiltPrompt).
 * Tier 2: If user selects an "Always" option, confirm with a second prompt.
 *
 * Consumes a BuiltPrompt for all content — no string concatenation at call sites.
 * Calls the appropriate mutation callback on confirmed "always".
 *
 * Uses index-based choice dispatch (not string matching) so label changes
 * cannot break the decision logic. Labels and behaviors come from a single
 * options list (buildAlwaysOptions), so the two can never drift apart.
 *
 * For file prompts with broaderPaths, a three-level structure is used:
 *   Level 1: Yes / file / path (1 level up) / broader (2+ levels up) / No
 *   Level 2 (broader): pick which parent directory
 *   Level 3: confirm "Always Yes"
 */
export async function twoTierAlwaysPrompt(
  prompt: BuiltPrompt,
  store: Store,
  ctx: ExtensionContext,
  onAlways: () => void,
  onAlwaysPaths: () => void,
  onAlwaysFile: () => void,
  onAlwaysBroader?: (dir?: string) => void,
): Promise<PromptResult> {
  const options = buildAlwaysOptions(prompt, { onAlways, onAlwaysPaths, onAlwaysFile, onAlwaysBroader });

  // Count this prompt once — not once per loop iteration (Back from tier-2
  // shouldn't inflate the frequency warning).
  const { over, count } = store.incrementPromptCount();

  while (true) {
    const choices = ["Yes", ...options.map(o => o.label), "No (with reason)", "No"];

    const warningPrefix = over
      ? `⚠️ High prompt frequency (${count} prompts this session). "Always" reduces future prompts.\n\n`
      : "";

    const idx = await showSelectIndex(ctx, warningPrefix + prompt.title + "\n---\n" + prompt.body, choices);
    if (idx === null) return "no"; // cancelled

    // ── Direct actions (no tier-2) ──
    if (idx === 0) return "yes";
    if (idx === choices.length - 1) return "no";

    if (idx === choices.length - 2) {
      const reason = await showReasonEditor(ctx, "Reason for rejection:");
      if (reason === null) continue;
      return { kind: "no", reason: reason.trim() || "No reason provided" };
    }

    // ── "Always" options ──
    const option = options[idx - 1]; // idx 0 is "Yes"
    if (!option) continue; // defensive: index/option count mismatch

    if (option.kind === "umbrella") {
      const result = await runBroaderUmbrella(prompt, option.startIdx, ctx, onAlwaysBroader);
      if (result) return result;
      continue;
    }

    if (await confirmAlways(ctx, option.title, option.body)) {
      return option.apply();
    }
    // Back / cancel → loop
  }
}
