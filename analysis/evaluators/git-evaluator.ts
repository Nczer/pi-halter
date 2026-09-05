import { EvaluationBuilder } from "./builder";
import { EvalCache, EvaluatorResult, RiskEvaluator } from "./types";
import { getFirstWord, isGitDangerous, parseGitSubcommand } from "../segment-helpers";

/**
 * Evaluates git commands for dangerous operations.
 */
export const GitEvaluator: RiskEvaluator = {
  name: "git",
  evaluate(seg, cwd, cache): EvaluatorResult {
    const segment = seg.text;
    const firstWord = cache?.firstWord ?? getFirstWord(segment);
    const b = new EvaluationBuilder();

    if (firstWord !== "git") return b.build();

    // Use cached result or compute inline
    const dangerous = cache?.gitDangerous ?? isGitDangerous(segment);
    if (dangerous) {
      // Subcommand resolved past global flags (git -C dir push → push) so the
      // reason and severity describe what isGitDangerous actually flagged.
      const parsed = parseGitSubcommand(segment);
      const sub = parsed?.sub ?? "?";
      const subArgs = parsed?.subArgs ?? [];
      const forcePush = sub === "push" && (subArgs.includes("--force") || subArgs.includes("--force-with-lease") || subArgs.includes("-f"));
      // Include specific flag context so prompts show why it's dangerous
      const reason =
        sub === "reset" ? `git reset --hard (discards uncommitted changes)`
        : sub === "push" ? (forcePush ? `git push --force (rewrites remote history)` : `git push (writes to remote)`)
        : sub === "clean" ? `git clean -fdx (deletes untracked files)`
        : sub === "rm" ? `git rm (removes files from working tree)`
        : sub === "reflog" ? `git reflog expire (removes recovery history)`
        : sub === "gc" ? `git gc --prune (permanently deletes objects)`
        : `git ${sub} (dangerous)`;
      // Destructive git ops are high; a plain (non-force) push is a normal
      // remote write — medium, still dangerous.
      if (sub === "push" && !forcePush) b.danger(reason); else b.high(reason);
    }

    return b.build();
  },
};
