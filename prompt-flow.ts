import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import type { Decision } from "./decision-engine";
import type { Store } from "./store";
import { buildPrompt } from "./prompt-builder";
import { twoTierAlwaysPrompt } from "./prompts";
import { updateWidget } from "./widget";

/** Result of showing a permission prompt to the user. */
export interface PromptFlowResult {
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
): Promise<PromptFlowResult> {
  if (decision.kind !== "prompt") {
    return { allowed: true };
  }

  const prompt = buildPrompt(decision);
  const result = await twoTierAlwaysPrompt(prompt, ctx, () => {
    store.addAllowed(decision.allowRules);
    updateWidget(ctx);
  }, () => {
    if (decision.allowPathsRules) {
      store.addAllowed(decision.allowPathsRules);
      updateWidget(ctx);
    }
  }, () => {
    if (decision.allowFileRules) {
      store.addAllowed(decision.allowFileRules);
      updateWidget(ctx);
    }
  });

  if (result === "no") {
    return { allowed: false };
  }
  if (typeof result === "object" && result.kind === "no") {
    return { allowed: false, reason: result.reason };
  }

  return { allowed: true };
}
