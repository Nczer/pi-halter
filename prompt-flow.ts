import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import type { Decision } from "./decision-engine";
import type { Store } from "./store";
import { buildPrompt, pdTargetLabel } from "./prompt-builder";
import { twoTierAlwaysPrompt } from "./prompts";
import { updateWidget } from "./widget";
import { RuleGenerator } from "./rule-generator";
import { getJudgeVerdict, judgeStatus, judgeVerdictBlock } from "./judge-prompt";
import { isDspatActive, recordDspatOutcome, updateDspatWidget } from "./dspat-mode";
import type { JudgeResult } from "./judge";
import type { DspaGateResult } from "./dspa-gate";

/**
 * Carried into showPrompt when /dspa declined to auto-allow, so the
 * fall-through prompt explains WHY (gate reason and/or judge verdict).
 */
export interface DspaFallthrough {
  gate: DspaGateResult;
  verdict: JudgeResult | null;
  /** Set when the gate passed but the judge produced no verdict — why. */
  note?: string;
}

/** Result of showing a permission prompt to the user. */
interface PromptFlowResult {
  /** User confirmed (yes or always). */
  allowed: boolean;
  /** Optional rejection reason from user. */
  reason?: string;
}

/**
 * Show a permission prompt and apply store mutations on "always" confirmation.
 *
 * Owns the entire UI interaction loop: builds the prompt from the decision,
 * displays it, mutates the store on "always", and updates the widget.
 *
 * The handler only needs to handle the rejection case.
 */
export async function showPrompt(
  decision: Decision,
  ctx: ExtensionContext,
  store: Store,
  dspa?: DspaFallthrough,
): Promise<PromptFlowResult> {
  if (decision.kind !== "prompt") {
    return { allowed: true };
  }

  let prompt = buildPrompt(decision);

  const pd = decision.promptData;

  // /dspa fall-through: explain why the operation was not auto-allowed —
  // the gate reason, and/or the judge verdict that declined to approve.
  if (dspa) {
    if (!dspa.gate.ok) {
      prompt = {
        ...prompt,
        body: prompt.body + `\n🚧 dspa: not auto-allowed — ${dspa.gate.reason}`,
      };
    } else if (dspa.verdict) {
      // An approving verdict that did not auto-allow did so only because the
      // risk was not low — say so on the suggests line.
      const note =
        dspa.verdict.approve === "approve" ? "— not auto-allowed (risk must be low)" : undefined;
      prompt = { ...prompt, body: prompt.body + "\n" + judgeVerdictBlock(dspa.verdict, note) };
    } else if (dspa.note) {
      prompt = {
        ...prompt,
        body: prompt.body + `\n🚧 dspa: not auto-allowed — ${dspa.note}`,
      };
    }
  }

  // Judge status is computed once per prompt and drives both the judge
  // behavior and the visible state: an invalid judge (e.g. session model
  // became unresolvable after a switch) is surfaced in the prompt body
  // instead of silently vanishing. "off" (disabled in settings) stays
  // silent — that is the user's choice.
  const jstatus = judgeStatus(ctx);

  // /dspat (advisory): the judge runs automatically on every prompt type
  // (bash / file / mcp) and the prompt shows the full verdict (explanation
  // + suggestion). The human always takes the call; the verdict + decision
  // feed the session stats (model-scoped, never persisted). The
  // `!dspa?.verdict` guard is defensive — the modes are exclusive
  // (index.ts), so a dspa fall-through never coexists with dspat.
  let dspatVerdict: JudgeResult | null = null;
  if (isDspatActive() && !dspa?.verdict) {
    if (jstatus.state === "invalid") {
      prompt = {
        ...prompt,
        body: prompt.body + `\n⚠️ Judge invalid: ${jstatus.reason}`,
      };
    } else {
      const verdict = await getJudgeVerdict(pd, ctx, store);
      if (verdict) {
        dspatVerdict = verdict;
        prompt = { ...prompt, body: prompt.body + "\n" + judgeVerdictBlock(verdict) };
      } else {
        // The call failed (auth, timeout, bad reply) — surface it instead
        // of silently showing a bare prompt.
        prompt = {
          ...prompt,
          body: prompt.body + "\n⚠️ Judge: no verdict (call failed or timed out)",
        };
      }
    }
  } else if (jstatus.state === "invalid" && (!dspa || dspa.gate.ok)) {
    // Default mode: explains why the 💭 Explain option is missing.
    prompt = {
      ...prompt,
      body: prompt.body + `\n⚠️ Judge invalid: ${jstatus.reason}`,
    };
  }

  // On-demand "💭 Explain" (default mode; hidden under /dspat, where the
  // verdict or its failure state is already shown). Offered only when the
  // judge can actually run. It renders the same full verdict block dspat
  // shows (on-demand dspat) — and, unlike dspat, the verdict is NOT
  // recorded in the agreement stats: the human picks when to consult, so
  // the decisions are a self-selected subset, not the shadow regime.
  const judge =
    !isDspatActive() && jstatus.state === "ok" && !dspa?.verdict
      ? {
          explain: async () => {
            const verdict = await getJudgeVerdict(pd, ctx, store);
            return verdict ? judgeVerdictBlock(verdict) : null;
          },
        }
      : undefined;

  const result = await twoTierAlwaysPrompt(prompt, store, ctx, () => {
    store.addAllowed(RuleGenerator.generatePrimaryRules(decision.promptData));
    updateWidget(ctx);
  }, () => {
    const rules = RuleGenerator.generatePathsOnlyRules(decision.promptData);
    if (rules) {
      store.addAllowed(rules);
      updateWidget(ctx);
    }
  }, () => {
    const rules = RuleGenerator.generateFileOnlyRules(decision.promptData);
    if (rules) {
      store.addAllowed(rules);
      updateWidget(ctx);
    }
  }, (dir?: string) => {
    const rules = RuleGenerator.generateBroaderRules(decision.promptData, dir);
    if (rules) {
      store.addAllowed(rules);
      updateWidget(ctx);
    }
  }, judge);

  // /dspat: record the verdict paired with the human's decision —
  // session-scoped stats only (judge quality is model-dependent).
  if (dspatVerdict) {
    const approved =
      result === "yes" || result === "always" || result === "alwaysPaths" || result === "alwaysFile";
    recordDspatOutcome(dspatVerdict.model, dspatVerdict.approve === "approve", approved, pdTargetLabel(pd));
    updateDspatWidget(ctx);
  }

  if (result === "no") {
    return { allowed: false };
  }
  if (typeof result === "object" && result.kind === "no") {
    return { allowed: false, reason: result.reason };
  }

  return { allowed: true };
}
