import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import type { BuiltPrompt } from "./prompt-builder";
import type { Store } from "../gate/store";
import { withUILock } from "../ui-lock";
import { PROMPT_WARNING_THRESHOLD } from "../config";
import { shortenHomePath } from "./path-display";
/** Native select → option index, or null on cancel. Keeps index-based dispatch. */
async function selectIndex(ctx: ExtensionContext, title: string, options: string[]): Promise<number | null> {
  // Serialized against the ask dialogs: pi runs the tool calls of one message
  // concurrently and a second dialog replaces this one (see ui-lock.ts).
  const sel = await withUILock(() => ctx.ui.select(title, options));
  return sel === undefined ? null : options.indexOf(sel);
}

/** User's response to a two-tier prompt. */
/**
 * The click. `abort` is dismissing the prompt without answering (Escape /
 * cancel at the picker): it behaves exactly like the reason-less No — the
 * operation is blocked either way — but it is a DIFFERENT fact about a floor
 * (L1, docs/dspa-credential-vouch.md §7): "the operator refused" and "the
 * operator walked away" must not share one tally.
 */
type PromptResult = "yes" | "always" | "alwaysPaths" | "alwaysFile" | "no" | "abort" | { kind: "no"; reason: string };

/**
 * On-demand judge hook: when provided, tier-1 gets an "Explain" option.
 * Selecting it runs `explain` (async, widget handled by the caller) and,
 * on a non-null result, re-shows tier-1 with the verdict block appended to
 * the body and the option removed. Null (failed call) → re-show with the
 * failure line instead; the option is always consumed.
 */
export interface JudgeExplain {
  explain: () => Promise<string | null>;
}

/**
 * dspa fall-through retry hook: when provided, tier-1 gets a repeatable
 * "Judge again" option. Selecting it re-runs the judge (the caller's
 * business — in production, a fresh uncached stage-2 call).
 *  - `autoAllowed: true` — the new verdict auto-allows; the prompt
 *    resolves as "yes" (the side effects are the caller's).
 *  - otherwise `body` (when non-null) REPLACES the prompt body for the
 *    re-show (the new verdict block or a failure note); null keeps it.
 * The option stays available on every re-show — each selection is a fresh
 * model call (the user is explicitly asking for it).
 */
export interface JudgeRetry {
  retry: () => Promise<{ autoAllowed: boolean; body: string | null }>;
}

/** Tier-2 choice indices. */
enum Tier2 {
  Confirm = 0,
  Back = 1,
}

// Every grant is session-scoped — the scope is in the option's own words
// ("this session"), so no separate warning repeats it. A grant that reaches
// further than the operator expects is a copy problem, not a footnote: name
// the scope once, in the tier-2 body that shows what is minted.

// ── Data-driven tier-1 options ──

/** Mutation callbacks supplied by the caller for each "Always" flavor. */
interface AlwaysCallbacks {
  onAlways: () => void;
  onAlwaysPaths: () => void;
  onAlwaysFile: () => void;
  onAlwaysBroader?: (dir?: string) => void;
  /** D10: trust the prompt's untrusted packages (session grant). */
  onTrust?: () => void;
  /** D18: grant write (implies read) for the stopped base dirs (session).
   *  Allow-writes option. */
  onWriteGrant?: () => void;
  /** Accredit the stopped credential dir (session). Accreditation option. */
  onAccredit?: () => void;
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
  // The paths-only tier is independent of includeAlwaysOption: a dir grant
  // can never auto-allow an unsafe/credential command (canBeAutoAllowed
  // stays false), so it stays offered even when the command tier is
  // suppressed. The command tier is not. (File prompts' dir umbrella and
  // bash's package-trust option are independent too — the umbrella needs
  // broaderPaths, Trust needs trustPackages.)
  if (!prompt.includeAlwaysOption && !prompt.includePathsOption && !prompt.trustPackages?.length && !prompt.writeGrantDirs?.length && !prompt.accreditDir) return [];

  const { broaderPaths } = prompt;
  const hasBroaderPaths = !!(prompt.includeBroaderOption && broaderPaths && broaderPaths.length > 0);

  // File prompts with a parent-directory hierarchy (inside or outside cwd).
  // Layout marker: fileHierarchy when set (buildFilePrompt), else the legacy
  // includeFileOption convention (test fixtures). An option is offered only
  // when its scope is not already covered by a standing session grant —
  // buildFilePrompt pre-filters broaderPaths and sets the *Covered flags.
  const hierarchy = hasBroaderPaths
    ? prompt.fileHierarchy ?? (prompt.includeFileOption ? "outside" : "inside")
    : null;
  if (hierarchy === "outside") {
    // path (outsideDir) / file / broader umbrella (all uncovered parents)
    const options: AlwaysOption[] = [];
    if (!prompt.pathOptionCovered) {
      options.push(
        confirmOpt(`Always (path): ${prompt.alwaysLabel}`, prompt.tier2Everything, () => { cb.onAlways(); return "always"; }),
      );
    }
    if (!prompt.fileOptionCovered) {
      options.push(
        confirmOpt(`Always (file): ${prompt.alwaysFileLabel}`, prompt.tier2File!, () => { cb.onAlwaysFile(); return "alwaysFile"; }),
      );
    }
    options.push({ kind: "umbrella", label: "Always (broader)", startIdx: 0 });
    return options;
  }
  if (hierarchy === "inside") {
    // file / path (first uncovered parent) / broader umbrella (remaining parents)
    const options: AlwaysOption[] = [];
    if (!prompt.fileOptionCovered) {
      options.push(
        confirmOpt(`Always (file): ${prompt.alwaysLabel}`, prompt.tier2Everything, () => { cb.onAlways(); return "always"; }),
      );
    }
    options.push(
      confirmOpt(
        `Always (path): ${broaderPaths![0].label}`,
        {
          title: "Confirm Always Allow",
          body: prompt.tier2Broader?.body
            ?? `Auto-allow this session:\n  ${shortenHomePath(broaderPaths![0].dir)}/*`,
        },
        () => { cb.onAlwaysBroader?.(broaderPaths![0].dir); return "always"; },
      ),
    );
    if (broaderPaths!.length > 1) {
      options.push({ kind: "umbrella", label: "Always (broader)", startIdx: 1 });
    }
    return options;
  }

  // Standard layout: primary + optional variants (bash, outside-cwd file without parents)
  const primaryConfig = prompt.tier2Everything;

  const options: AlwaysOption[] = [];
  // *Covered flags: the option's scope already has a standing session grant
  // (file prompts only — bash/tool prompts never set them).
  if (prompt.includeAlwaysOption && !prompt.pathOptionCovered) {
    options.push(
      confirmOpt(
        prompt.includeFileOption ? `Always (path): ${prompt.alwaysLabel}` : `Always: ${prompt.alwaysLabel}`,
        primaryConfig,
        () => { cb.onAlways(); return "always"; },
      ),
    );
  }
  if (prompt.includeFileOption && !prompt.fileOptionCovered) {
    options.push(confirmOpt(`Always (file): ${prompt.alwaysFileLabel}`, prompt.tier2File!, () => { cb.onAlwaysFile(); return "alwaysFile"; }));
  }
  if (prompt.includePathsOption) {
    options.push(confirmOpt(`Always (paths): ${prompt.alwaysPathsLabel}`, prompt.tier2Paths ?? prompt.tier2Everything, () => { cb.onAlwaysPaths(); return "alwaysPaths"; }));
  }
  if (prompt.trustPackages?.length && cb.onTrust) {
    // D10: per-package trust for fetchable run forms (npx tsc, uvx tsc, …)
    // — the ONLY command grant for those forms: any args/flags, across
    // npx/uvx/dlx/x run forms (session-scoped).
    options.push(
      confirmOpt(
        `Trust: ${prompt.trustPackages.join(", ")}`,
        {
          title: "Confirm Trust Package",
          body: `Auto-allow run forms this session (npx/uvx/dlx, any args):\n${prompt.trustPackages.map(p => `  \u2022 ${p}`).join("\n")}`,
        },
        () => { cb.onTrust?.(); return "always"; },
      ),
    );
  }
  // D18: the floor stopped a bash base write lacking a write grant — granting
  // it is what makes the next identical run pass the floor (the judge then
  // sees the write state and decides). Session scope, said in full in the
  // tier-2. One row per grant: when a paths row is on the table and its mint
  // already records these dirs as WRITES (prompt-flow moved them into the write
  // tier), that row grants the same thing plus the token resolutions, so a
  // separate row would be a second click for one decision.
  const pathsRowGrantsWrites = prompt.includePathsOption
    && (prompt.writeGrantDirs ?? []).every(d => (prompt.pathGrantDirs ?? []).includes(d));
  if (prompt.writeGrantDirs?.length && cb.onWriteGrant && !pathsRowGrantsWrites) {
    const shown = prompt.writeGrantDirs.map(shortenHomePath);
    options.push(
      confirmOpt(
        `Allow writes: ${shown.join(", ")}`,
        {
          title: "Confirm Write Grant",
          body: `Grant read + write this session:\n${shown.map(d => `  • ${d}/*`).join("\n")}`,
        },
        () => { cb.onWriteGrant?.(); return "always"; },
      ),
    );
  }
  // The credential floor (docs/dspa-credential-vouch.md): the operator vouches
  // for the credential material under one directory, read-only, for this
  // session. Not a grant of permission to run something — it moves one floor so
  // the judge can rule, and the label says so (`reads`, not `writes`/`allow`).
  if (prompt.accreditDir && cb.onAccredit) {
    const shown = shortenHomePath(prompt.accreditDir);
    options.push(
      confirmOpt(
        `Allow credential reads: ${shown}`,
        {
          title: "Confirm Credential Accreditation",
          body:
            `Let the judge review credential reads this session (not auto-allow; .env/id_rsa/stores stay blocked):\n  • ${shown}/**`,
        },
        () => { cb.onAccredit?.(); return "always"; },
      ),
    );
  }
  return options;
}

// ── Prompt helpers ──

/** Show a tier-2 confirmation ("Always Yes" / "Back"). Returns true on confirm. */
async function confirmAlways(ctx: ExtensionContext, title: string, body: string): Promise<boolean> {
  const idx = await selectIndex(ctx, title + "\n" + body, ["Always Yes", "Back"]);
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
  const subIdx = await selectIndex(ctx, "Select a broader directory to always allow:", [...subLabels, "Back"]);
  if (subIdx === null || subIdx === subLabels.length) return null; // Back / cancel

  const chosen = broaderPaths[subIdx + startIdx];
  const action = chosen.label.split(" ")[0];
  const isWrite = action !== "Read";
  const body = isWrite
    ? `Auto-allow ${action.toLowerCase()} (and read) this session:\n  ${shortenHomePath(chosen.dir)}/*`
    : `Auto-allow read this session:\n  ${shortenHomePath(chosen.dir)}/*`;

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
 * Session consent (T4, content-classes): single tier — the prompt's only
 * choice IS the session grant (`sessionConsent.label` → onAlways), plus
 * "No". No one-shot Yes, no tier-2 (the explicit label + session lifetime
 * is the boundary).
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
  judge?: JudgeExplain,
  onTrust?: () => void,
  retryJudge?: JudgeRetry,
  onWriteGrant?: () => void,
  onAccredit?: () => void,
): Promise<PromptResult> {
  const options = buildAlwaysOptions(prompt, { onAlways, onAlwaysPaths, onAlwaysFile, onAlwaysBroader, onTrust, onWriteGrant, onAccredit });

  // Count this prompt once — not once per loop iteration (Back from tier-2
  // shouldn't inflate the frequency warning).
  const { over, count } = store.incrementPromptCount();

  let activePrompt = prompt;
  let judgeExplained = false;

  while (true) {
    const showJudge = !!judge && !judgeExplained;

    // The frequency tip fires once, on the prompt that crosses the threshold
    // (the count is per prompt, not per loop iteration) — prepending it to
    // every later prompt trained the eye to skip it.
    const warningPrefix = over && count === PROMPT_WARNING_THRESHOLD + 1
      ? `Tip: ${count} prompts this session — "Always" reduces repeats.\n`
      : "";
    const renderPrompt = (p: BuiltPrompt) =>
      warningPrefix + (p.body ? `${p.title}\n${p.body}` : p.title);

    // ── Session consent (T4): single tier — the grant IS the choice ──
    if (activePrompt.sessionConsent) {
      const sc = activePrompt.sessionConsent;
      const choices = [
        sc.label,
        ...(showJudge ? ["Explain"] : []),
        "No",
      ];
      const idx = await selectIndex(ctx, renderPrompt(activePrompt), choices);
      if (idx === null) return "abort"; // dismissed without answering (Escape)
      if (idx === 0) {
        onAlways();
        return "always";
      }
      if (idx === choices.length - 1) {
        const reason = await withUILock(() => ctx.ui.input("Reason for rejection:"));
        if (reason === undefined) continue;
        return { kind: "no", reason: reason.trim() || "No reason provided" };
      }
      if (showJudge && idx === 1) {
        const block = await judge!.explain();
        activePrompt = {
          ...activePrompt,
          body: block
            ? activePrompt.body + "\n" + block
            : activePrompt.body + "\n⚠️ Judge: no verdict (call failed or reply unparseable)",
        };
        judgeExplained = true;
        continue;
      }
      continue; // defensive: index/choice count mismatch
    }

    const showRetry = !!retryJudge;
    // "No" is the with-reason path (it asks on pick); escape/cancel is the
    // reason-less path (selectIndex null → "abort" below). Both block the
    // operation; they are recorded apart (L1: a refusal and a walk-away are
    // different facts about a floor).
    const choices = [
      "Yes",
      ...options.map(o => o.label),
      ...(showJudge ? ["Explain"] : []),
      ...(showRetry ? ["Judge again"] : []),
      "No",
    ];

    const idx = await selectIndex(ctx, renderPrompt(activePrompt), choices);
    if (idx === null) return "abort"; // dismissed without answering (Escape)

    // ── Direct actions (no tier-2) ──
    if (idx === 0) return "yes";
    if (idx === choices.length - 1) {
      const reason = await withUILock(() => ctx.ui.input("Reason for rejection:"));
      if (reason === undefined) continue;
      return { kind: "no", reason: reason.trim() || "No reason provided" };
    }

    // ── On-demand judge explanation ──
    if (showJudge && idx === 1 + options.length) {
      const block = await judge.explain();
      // A failed call is surfaced, not swallowed: the option is consumed
      // and the body says what happened.
      activePrompt = {
        ...activePrompt,
        body: block
          ? activePrompt.body + "\n" + block
          : activePrompt.body + "\n⚠️ Judge: no verdict (call failed or reply unparseable)",
      };
      judgeExplained = true;
      continue;
    }

    // ── Judge again (dspa fall-through retry — repeatable) ──
    if (showRetry && idx === 1 + options.length + (showJudge ? 1 : 0)) {
      const r = await retryJudge.retry();
      if (r.autoAllowed) return "yes";
      if (r.body) activePrompt = { ...activePrompt, body: r.body };
      continue;
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
