/**
 * Judge wiring — the LLM judge's verdict inside the permission prompts.
 *
 * Display-only (manual/dspat): when a prompt (bash / file) is about to
 * be shown, a one-shot model call (judge.ts) explains what the operation will
 * actually do, and the verdict block is appended to the prompt body. The
 * verdict never reaches the agent's context, never pre-fills the rejection
 * reason, and never alters the gate's decision — under /dspa the same verdict
 * additionally sits behind the hard gate (dspa-gate.ts) as the auto-allow
 * authority. ANY failure here (settings off, model unresolved, auth failed,
 * timeout, bad reply) resolves to "no verdict" and the prompt looks exactly
 * as it did before.
 *
 * Script payloads: when the command executes an untrusted local script,
 * analysis/script-payload.ts identifies it and its content is handed to the
 * judge fenced as untrusted data (trusted skill scripts are excluded — the
 * user already vouches for that directory).
 */
import { stream } from "@earendil-works/pi-ai/compat";
import { truncateToWidth } from "@earendil-works/pi-tui";
import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import type {BashPromptData, PromptData} from "../decide/types";
import type { Store } from "../gate/store";
import { analyzeCommand } from "../analysis/command-analysis";
import { findExecutedScript } from "../analysis/script-payload";
import {judge, JUDGE_STAGE2_SYSTEM_PROMPT, readJudgeSettings, resolveJudgeModel, resolveJudgeAuth, JudgeStreamFn, JudgeResult, JudgeSettings} from "./judge";
import type {JudgmentBashInput, JudgmentInput, JudgmentScript} from "./packet";
import { buildSessionContext } from "./session-context";
import { isDspaActive, setDspaJudging } from "../modes/dspa-mode";
import { isDspatActive, setDspatJudging } from "../modes/dspat-mode";

// ── Stage-2 timeout headroom ──

/**
 * The judge timeout (judge.timeoutMs) is a FIRST-TOKEN deadline: the call
 * is aborted if the model produces no output (any stream event past the
 * `start` handshake) within that window; the whole response is separately
 * capped (JUDGE_RESPONSE_CAP_MS). Stage 2's packet is structurally larger
 * (full operation content + session context), so its PREFILL — the wait
 * before the first token — is the part most likely to exceed the base
 * window on a slow model (local llama-cpp); an unmet stage-2 deadline
 * leaves the stage-1 verdict with a "stage 2 unavailable" note and the
 * prompt falls through. Stage 2 therefore gets this factor × the base
 * first-token deadline; stage 1 keeps the base (it must stay snappy — it
 * runs on every prompt under /dspat too).
 */
const STAGE2_TIMEOUT_FACTOR = 3;

// ── Judgment input from any prompt ──

/**
 * Build the judgment input for a prompt, per type. Bash uses the analysis
 * carried on the prompt (single analysis per decision — re-run only for
 * hand-constructed prompt data) so the packet shows exactly what the gate
 * decided on; file maps straight from the prompt data (writes/edits carry
 * the new content, fenced as untrusted).
 */
async function buildJudgmentInput(
  pd: PromptData,
  store: Store,
): Promise<JudgmentInput> {
  if (pd.type === "bash") {
    // The packet must show the analysis the decision was made from (single
    // analysis per decision); re-analyze only for hand-constructed prompt data.
    const analysis =
      pd.analysis ??
      (await analyzeCommand(pd.command, pd.cwd, {
        isInsideAllowedDir: (p) => store.isInsideAllowedDir(p, "read"),
        getConfirmedResolution: (t) => store.getConfirmedResolution(t),
      }));
    const script = findExecutedScript(analysis, pd.cwd);
    const input: JudgmentBashInput = {
      command: pd.command,
      cwd: pd.cwd,
      segments: analysis.segments,
      riskReasons: analysis.risk.reasons,
      hasUnsafePattern: analysis.safety.hasUnsafePattern,
      hasParseError: analysis.hasParseError,
      credentialRule: pd.credentialRule,
      paths: analysis.paths,
      outsidePaths: analysis.prompt.outsidePaths ?? [],
      script,
    };
    return input;
  }
  if (pd.type === "tool") {
    return {
      kind: "tool",
      tool: pd.tool,
      label: pd.label,
      gate: pd.gate,
      note: pd.note,
      script: pd.script,
      path: pd.resolved,
      outsideDir: pd.outsideDir,
      argsPreview: pd.argsPreview,
    };
  }
  return {
    type: "file",
    action: pd.action,
    resolved: pd.resolved,
    cwd: pd.cwd,
    outsideDir: pd.outsideDir,
    isWriteOp: pd.isWriteOp,
    exists: pd.exists,
    warnedRule: pd.warnedRule,
    symlinkHint: pd.symlinkHint,
    content: pd.content,
  };
}

// ── Entry point ──

/**
 * Judge status for this context — drives both behavior (offer Explain,
 * run the judge) and the visible state (widgets, prompt lines). The judge
 * must never fail SILENTLY: an invalid state is surfaced, an "off" state
 * (user disabled it in settings) is intentional and stays silent.
 *
 * - "off": settings.enabled is false → no UI, no calls.
 * - "ok": a model is resolvable (configured provider/model, or the session
 *   model) → modelLabel names it so the user can check what is judging.
 * - "invalid": enabled but no model resolvable (e.g. the session model
 *   became unresolvable after a switch) → reason is displayed wherever a
 *   judge output would have appeared.
 *
 * Never throws. `settings` is a test seam (production reads
 * ~/.pi/agent/settings-ext.json). ctx.model is a live getter, so calling this
 * per render tracks session model switches.
 */
export interface JudgeStatus {
  state: "off" | "ok" | "invalid";
  /** Model that would be used, e.g. "llama-cpp/Qwen3.8-27B (session)". */
  modelLabel: string | null;
  /** Why the judge cannot run (state === "invalid"). */
  reason: string | null;
}

export function judgeStatus(
  ctx: ExtensionContext,
  settings?: JudgeSettings,
): JudgeStatus {
  try {
    const s = settings ?? readJudgeSettings();
    if (!s.enabled) return { state: "off", modelLabel: null, reason: null };
    const configured = s.provider !== null && s.model !== null;
    const model = resolveJudgeModel(s, ctx.modelRegistry, ctx.model);
    if (!model) {
      return {
        state: "invalid",
        modelLabel: null,
        reason: configured
          ? `configured model not found (${s.provider}/${s.model})`
          : "session model not resolvable",
      };
    }
    return {
      state: "ok",
      modelLabel: `${model.provider}/${model.id} (${configured ? "configured" : "session"})`,
      reason: null,
    };
  } catch {
    return { state: "invalid", modelLabel: null, reason: "judge settings error" };
  }
}

/**
 * True when the judge can actually run (state === "ok"). Never throws —
 * used to decide whether the "💭 Explain" option is offered.
 */
export function judgeAvailable(
  ctx: ExtensionContext,
  settings?: JudgeSettings,
): boolean {
  return judgeStatus(ctx, settings).state === "ok";
}

/**
 * Test seam: `complete` (the model call) and settings are injectable.
 * Production uses the real `complete` from @earendil-works/pi-ai and
 * ~/.pi/agent/settings-ext.json.
 */
export interface JudgePromptDeps {
  stream?: JudgeStreamFn;
  settings?: JudgeSettings;
}

/**
 * One judge stage for a prompt (bash / file), or null (never throws).
 * Shows a status widget while the model call is in flight. A verdict that
 * failed to produce an explanation (defer) is treated as "no verdict".
 *
 * Stage 1 (stateless): today's packet + prompt, LRU-cached on the operation.
 * Stage 2 (dspa intent pass): same operation, plus the reasoning-blind
 * "## Session context" section, under the intent-rules prompt, UNcached
 * (its context includes the just-blocked operation → a hit is impossible).
 */
async function runJudgeStage(
  pd: PromptData,
  ctx: ExtensionContext,
  store: Store,
  deps: JudgePromptDeps,
  stage: 1 | 2,
): Promise<JudgeResult | null> {
  // The in-flight state folds into the active judge mode's widget line
  // ("» DSPA … — judging…" / "◎ DSPAT … — judging…"); only manual mode
  // (on-demand Explain) gets the standalone widget. Captured at call start
  // so a mid-call mode toggle cannot route cleanup to the wrong widget.
  const dspaMode = isDspaActive();
  const dspatMode = !dspaMode && isDspatActive();
  let widgetShown = false;
  try {
    const settings = deps.settings ?? readJudgeSettings();
    if (!settings.enabled) return null;

    const model = resolveJudgeModel(settings, ctx.modelRegistry, ctx.model);
    if (!model) return null;
    const auth = await resolveJudgeAuth(model, ctx.modelRegistry);
    if (!auth) return null;

    const input = await buildJudgmentInput(pd, store);

    try {
      if (dspaMode) setDspaJudging(stage as 1 | 2, ctx);
      else if (dspatMode) setDspatJudging(true, ctx); // /dspat judges stage 1 only
      else {
        ctx.ui.setWidget("judge", (_tui, theme) => ({
          render: (width: number) => [
            truncateToWidth(theme.fg("muted", `⏳ Judge: stage ${stage} — explaining…`), width),
          ],
          invalidate: () => {},
        }), { placement: "belowEditor" });
        widgetShown = true;
      }
    } catch {
      /* the explanation still works without a widget */
    }

    const result = await judge(input, {
      model,
      stream: deps.stream ?? stream,
      apiKey: auth.apiKey,
      headers: auth.headers,
      timeoutMs: stage === 2 ? Math.round(settings.timeoutMs * STAGE2_TIMEOUT_FACTOR) : settings.timeoutMs,
      thinking: settings.thinking,
      systemPrompt: stage === 2 ? JUDGE_STAGE2_SYSTEM_PROMPT : undefined,
      extraPacket: stage === 2 ? buildSessionContext(ctx, store) : undefined,
      uncached: stage === 2,
    });
    return result.explanation ? result : null;
  } catch {
    return null;
  } finally {
    try {
      if (dspaMode) setDspaJudging(null, ctx);
      else if (dspatMode) setDspatJudging(false, ctx);
      else if (widgetShown) ctx.ui.setWidget("judge", undefined);
    } catch {
      /* widget cleanup must never mask the result */
    }
  }
}

/**
 * Stage 1 — the stateless verdict (all modes: dspat display, dspa auto-
 * allow, on-demand Explain). See runJudgeStage.
 */
export async function getJudgeVerdict(
  pd: PromptData,
  ctx: ExtensionContext,
  store: Store,
  deps: JudgePromptDeps = {},
): Promise<JudgeResult | null> {
  return runJudgeStage(pd, ctx, store, deps, 1);
}

/**
 * Stage 2 — the dspa intent pass. Runs only when stage 1 did not auto-
 * allow; adds the reasoning-blind session context (Q3) and the intent
 * rules to the judgment. Verdict policy (Q4): approve+{low, medium}
 * auto-allows; approve+high and reject never do (gate.ts applies it).
 */
export async function getStage2Verdict(
  pd: PromptData,
  ctx: ExtensionContext,
  store: Store,
  deps: JudgePromptDeps = {},
): Promise<JudgeResult | null> {
  return runJudgeStage(pd, ctx, store, deps, 2);
}

/**
 * The judge-verdict block for prompt bodies — one shape for every
 * presentation site (/dspat auto-advice, /dspa fall-through, on-demand
 * "💭 Explain"):
 *
 *   💭 Judge: <explanation>
 *    → suggests: APPROVE (low)
 *
 * The suggests line uses the verdict's own word — a defer renders DEFER,
 * not REJECT: "the model could not verify" is a different signal from
 * "the model saw something bad", and the operator reading the line (and
 * the dspat stats review) needs the distinction. Auto-allow authority is
 * per stage (Q4): stage 1 approve+low, stage 2 approve+{low, medium}.
 *
 * `note` appends to the suggests line (the /dspa fall-through's
 * "not auto-allowed" explanation for an approving but not-low verdict).
 */
export function judgeVerdictBlock(
  verdict: JudgeResult,
  note?: string,
): string {
  const suggestion =
    verdict.approve === "approve" ? "APPROVE"
    : verdict.approve === "defer" ? "DEFER"
    : "REJECT";
  return `💭 Judge: ${verdict.explanation}\n   → suggests: ${suggestion} (${verdict.risk})${note ? ` ${note}` : ""}`;
}
