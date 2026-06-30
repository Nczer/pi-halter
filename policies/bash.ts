import { analyzeCommand } from "../analysis/command-analysis";
import type { Store, BashRequest, Decision } from "../decision-engine";
import { UserDenyRule, RetryLoopRule, FastAllowRule, SafetyRule, PromptFallbackRule } from "./bash-rules";

export async function decideBash(req: BashRequest, store: Store): Promise<Decision> {
  const rules = [
    UserDenyRule,
    RetryLoopRule,
    FastAllowRule,
  ];

  for (const rule of rules) {
    const decision = rule(req, store);
    if (decision) return decision as Decision;
  }

  const analysis = await analyzeCommand(req.command, req.cwd, {
    allowedReadDirs: store.listAllowedReadDirs(),
    allowedWriteDirs: store.listAllowedWriteDirs(),
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
