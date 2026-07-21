import { analyzeCommand } from "../analysis/command-analysis";
import type { Store, BashRequest, Decision } from "../decision-engine";
import { RetryLoopRule, FastAllowRule, SafetyRule, PromptFallbackRule, CredentialDenyRule } from "./bash-rules";

export async function decideBash(req: BashRequest, store: Store): Promise<Decision> {
  const rules = [
    RetryLoopRule,
    CredentialDenyRule,
    FastAllowRule,
  ];

  for (const rule of rules) {
    const decision = await rule(req, store);
    if (decision) return decision;
  }

  const analysis = await analyzeCommand(req.command, req.cwd, {
    isInsideAllowedDir: (p) => store.isInsideAllowedDir(p, "read") || store.isInsideAllowedDir(p, "write"),
  });

  const analysisRules = [
    SafetyRule,
    PromptFallbackRule,
  ];

  for (const rule of analysisRules) {
    const decision = await rule(req, store, analysis);
    if (decision) return decision as Decision;
  }

  return {
    kind: "block",
    reason: "Internal error in bash permission policy pipeline.",
  };
}
