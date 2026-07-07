import { EvaluationBuilder } from "./builder";
import { EvalCache, RiskEvaluator } from "./types";
import { getFirstWord, isGitDangerous } from "../segment-helpers";

/**
 * Evaluates git commands for dangerous operations.
 */
export const GitEvaluator: RiskEvaluator = {
  name: "git",
  evaluate(seg, cwd, cache): ReturnType<EvaluationBuilder["build"]> {
    const segment = seg.text;
    const firstWord = cache?.firstWord ?? getFirstWord(segment);
    const args = segment.trim().split(/\s+/);
    const rest = args.slice(1);
    const sub = rest[0];
    const subArgs = rest.slice(1);
    const b = new EvaluationBuilder();

    if (firstWord !== "git") return b.build();

    // Use cached result or compute inline
    const dangerous = cache?.gitDangerous ?? isGitDangerous(segment);
    if (dangerous) {
      b.setHigh();
      b.markDanger();
      // Include specific flag context so prompts show why it's dangerous
      if (sub === "reset")      b.addReason(`git reset --hard (discards uncommitted changes)`);
      else if (sub === "push")  b.addReason(`git push --force (rewrites remote history)`);
      else if (sub === "clean") b.addReason(`git clean -fdx (deletes untracked files)`);
      else if (sub === "rm")    b.addReason(`git rm (removes files from working tree)`);
      else if (sub === "reflog") b.addReason(`git reflog expire (removes recovery history)`);
      else if (sub === "gc")   b.addReason(`git gc --prune (permanently deletes objects)`);
      else                      b.addReason(`git ${sub} (dangerous)`);
    }

    return b.build();
  },
};
