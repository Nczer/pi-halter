import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import type { Decision } from "./decision-engine";
import type { Store } from "./store";
import { buildPrompt, pdTargetLabel } from "./prompt-builder";
import { twoTierAlwaysPrompt } from "./prompts";
import { updateWidget } from "./widget";
import { RuleGenerator } from "./rule-generator";
import { getJudgeVerdict, judgeStatus, judgeVerdictBlock } from "./judge-prompt";
import { resolveUnresolvedPaths, type ResolutionMap } from "./path-resolver";
import { isDspatActive, recordDspatOutcome, updateDspatWidget } from "./dspat-mode";
import type { JudgeResult } from "./judge";
import { makeManualBar, type DspaGateResult } from "./dspa-gate";
import { logUnresolved } from "./decision-log";

/**
 * Carried into showPrompt when /dspa declined to auto-allow, so the
 * fall-through prompt explains WHY (gate reason and/or judge verdict).
 */
export interface DspaFallthrough {
  gate: DspaGateResult;
  /** The FINAL verdict — stage 2 when it rendered one, else stage 1. */
  verdict: JudgeResult | null;
  /** Stage of the carried verdict (1 = stateless, 2 = intent pass); null = no verdict. */
  stage: 1 | 2 | null;
  /** Set when the gate passed but a judge stage produced no verdict — why. */
  note?: string;
  /** D10: bare package names that stopped the command — the prompt offers a
   *  "Trust" option for them (session grant), and the carried verdict is
   *  advisory (the floor's stop stands). */
  untrustedPackages?: string[];
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

  const pd = decision.promptData;

  // Judge status is computed once per prompt and drives the judge, the path
  // resolver, and the visible state: an invalid judge (e.g. session model
  // became unresolvable after a switch) is surfaced in the prompt body
  // instead of silently vanishing. "off" (disabled in settings) stays
  // silent — that is the user's choice.
  const jstatus = judgeStatus(ctx);

  // Path resolver: for bash prompts with statically unresolved tokens, the
  // judge model (second use of the judge — same settings) reports where the
  // tokens land at runtime. Display-only until the user accepts a grant —
  // then it is persisted as a confirmed resolution and the next identical
  // run is deterministic (gate + store, no LLM). Judge off → no LLM lines,
  // the prompt looks exactly as before.
  let resolutions: ResolutionMap | null = null;
  if (pd.type === "bash" && (pd.unresolved?.length ?? 0) > 0 && jstatus.state === "ok") {
    resolutions = await resolveUnresolvedPaths(pd, ctx);
  }

  // A dspa gate stop caused by a CONFIRMED resolution falling outside the
  // bar: the gate already knows the token's dirs (deterministic — no LLM
  // call) and the prompt offers a grant for exactly them. Merge into the
  // resolution view so the body labels the dirs `confirmed` and the paths
  // option grants them.
  const confirmedTokens = new Set<string>();
  if (pd.type === "bash" && dspa && !dspa.gate.ok && dspa.gate.confirmedOutside?.length) {
    const merged = new Map(resolutions ?? []);
    for (const { token, dirs } of dspa.gate.confirmedOutside) {
      const prev = merged.get(token);
      merged.set(token, prev ? [...new Set([...prev, ...dirs])] : dirs);
      confirmedTokens.add(token);
    }
    resolutions = merged;
  }

  let prompt = buildPrompt(decision, resolutions ?? undefined, confirmedTokens);

  // /dspa fall-through: explain why the operation was not auto-allowed —
  // the gate reason, and/or the judge verdict that declined to approve.
  if (dspa) {
    if (!dspa.gate.ok) {
      // The floor-stop line leads the body: appended, it sat after the
      // command, path lists, and chain listing — off-screen on long
      // prompts, so "what stopped the auto-allow" was invisible (the
      // latency heuristic existed because of this).
      prompt = {
        ...prompt,
        body: `🚧 DSPA: not auto-allowed — ${dspa.gate.reason}\n\n` + prompt.body,
      };
      if (dspa.verdict) {
        // D10: untrusted-package stop — the judge ran anyway; its verdict is
        // advisory input for the Trust/Yes/No decision, not an auto-allow.
        prompt = {
          ...prompt,
          body: prompt.body + "\n" + judgeVerdictBlock(dspa.verdict, "— advisory (floor stop stands)"),
        };
      }
      if (dspa.note) {
        prompt = {
          ...prompt,
          body: prompt.body + `\n🚧 DSPA: ${dspa.note}`,
        };
      }
    } else if (dspa.verdict) {
      // An approving verdict that did not auto-allow did so only because the
      // risk tier was above the stage's authority — say so on the suggests
      // line (Q4: stage 1 needs low; stage 2, whose intent context exists
      // to de-risk, needs low or medium).
      const note = dspa.verdict.approve === "approve"
        ? dspa.stage === 2
          ? "— not auto-allowed (risk must be low or medium)"
          : "— not auto-allowed (risk must be low)"
        : undefined;
      prompt = { ...prompt, body: prompt.body + "\n" + judgeVerdictBlock(dspa.verdict, note) };
      if (dspa.note) {
        prompt = { ...prompt, body: prompt.body + `\n🚧 DSPA: ${dspa.note}` };
      }
    } else if (dspa.note) {
      prompt = {
        ...prompt,
        body: prompt.body + `\n🚧 DSPA: not auto-allowed — ${dspa.note}`,
      };
    }
  }

  // /dspat (advisory): the judge runs automatically on every prompt type
  // (bash / file) and the prompt shows the full verdict (explanation
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

  // D10: surface the untrusted packages as a tier-1 "Trust" option. The
  // grant is per bare package name (npx/uvx/dlx run forms, any args).
  if (dspa?.untrustedPackages && dspa.untrustedPackages.length > 0) {
    prompt = { ...prompt, trustPackages: dspa.untrustedPackages };
  }

  /**
   * Persist resolutions as user-confirmed (store.confirmResolution) so the
   * same command + tokens pass the dspa gate deterministically next run.
   * `all` — the user accepted an option that granted exactly these dirs
   * (Always / Always (paths)): persist every resolution. Otherwise (a
   * one-shot Yes, or a non-paths Always) — only tokens whose dirs are ALL
   * inside the manual bar: Yes vouches for this exact run, and in-bar dirs
   * never needed a grant, so confirming them is semantics-neutral and
   * makes the next run judgeable instead of a floor stop.
   */
  const persistedTokens = new Set<string>();
  const bar = pd.type === "bash" ? makeManualBar(store, pd.cwd) : null;
  const persistResolutions = (all: boolean) => {
    if (!resolutions) return;
    for (const [token, dirs] of resolutions) {
      if (all || (bar ? dirs.every(d => bar(d)) : false)) {
        store.confirmResolution(token, dirs);
        persistedTokens.add(token);
      }
    }
  };

  const result = await twoTierAlwaysPrompt(prompt, store, ctx, () => {
    store.addAllowed(RuleGenerator.generatePrimaryRules(decision.promptData));
    // The primary option's tier-2 text lists the resolver dirs too — grant
    // what the confirmation showed.
    if (prompt.resolverDirs?.length) store.addAllowed({ readDirs: prompt.resolverDirs });
    persistResolutions(true);
    updateWidget(ctx);
  }, () => {
    // Always (paths): the concrete outside-cwd dirs plus the resolver dirs
    // — exactly the union the option label named (pathGrantDirs).
    const concrete = RuleGenerator.generatePathsOnlyRules(decision.promptData)?.readDirs ?? [];
    const dirs = [...new Set([...concrete, ...(prompt.resolverDirs ?? [])])];
    if (dirs.length > 0) {
      store.addAllowed({ readDirs: dirs });
      updateWidget(ctx);
    }
    persistResolutions(true);
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
  }, judge, () => {
    for (const pkg of dspa!.untrustedPackages!) store.trustPackage(pkg);
    updateWidget(ctx);
  });

  // /dspat: record the verdict paired with the human's decision —
  // session-scoped stats only (judge quality is model-dependent).
  if (dspatVerdict) {
    const approved =
      result === "yes" || result === "always" || result === "alwaysPaths" || result === "alwaysFile";
    recordDspatOutcome(dspatVerdict.model, dspatVerdict.approve === "approve", approved, pdTargetLabel(pd));
    updateDspatWidget(ctx);
  }

  // One-shot Yes (or an Always that came through a non-paths option —
  // broader/trust; the paths options already persisted in their
  // callbacks): confirm only all-in-bar resolutions.
  if (result === "yes" || result === "always") persistResolutions(false);

  const rejected = result === "no" || (typeof result === "object" && result.kind === "no");

  /** Unresolved-token log (decision-log.logUnresolved): what the resolver
   * suggested, what the user decided, whether it was confirmed. Runs on
   * every outcome (the persistedTokens set is final by then — the grants
   * happened in the callbacks, the in-bar confirms above). */
  if (pd.type === "bash" && pd.unresolved?.length) {
    const gateStop = dspa && !dspa.gate.ok;
    for (const u of pd.unresolved) {
      logUnresolved({
        cmd: pd.command,
        cwd: pd.cwd,
        token: u.token,
        llm: resolutions?.get(u.token),
        persisted: persistedTokens.has(u.token),
        outcome: gateStop ? "gate-stop" : "prompted",
        decision: typeof result === "string" ? result : "no",
      });
    }
  }

  if (rejected) {
    return { allowed: false, ...(typeof result === "object" ? { reason: result.reason } : {}) };
  }
  return { allowed: true };
}
