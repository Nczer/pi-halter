import { EvaluationBuilder } from "./builder";
import { EvalCache, RiskEvaluator } from "./types";
import { getFirstWord, isGitDangerous, parseGitSubcommand } from "../segment-helpers";

/**
 * Evaluates git commands for dangerous operations.
 */
export const GitEvaluator: RiskEvaluator = {
  name: "git",
  evaluate(seg, cwd, cache): ReturnType<EvaluationBuilder["build"]> {
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
      // Destructive git ops are high; a plain (non-force) push is a normal
      // remote write — medium.
      if (sub === "push" && !forcePush) b.setMedium(); else b.setHigh();
      b.markDanger();
      // Include specific flag context so prompts show why it's dangerous
      if (sub === "reset")      b.addReason(`git reset --hard (discards uncommitted changes)`);
      else if (sub === "push")  b.addReason(forcePush ? `git push --force (rewrites remote history)` : `git push (writes to remote)`);
      else if (sub === "clean") b.addReason(`git clean -fdx (deletes untracked files)`);
      else if (sub === "rm")    b.addReason(`git rm (removes files from working tree)`);
      else if (sub === "reflog") b.addReason(`git reflog expire (removes recovery history)`);
      else if (sub === "gc")   b.addReason(`git gc --prune (permanently deletes objects)`);
      else                      b.addReason(`git ${sub} (dangerous)`);
    }

    return b.build();
  },
};
