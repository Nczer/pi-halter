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

    b.addReason(sub ? `git ${sub} (git command)` : "git (git command)");

    // Use cached result or compute inline
    const dangerous = cache?.gitDangerous ?? isGitDangerous(segment);
    if (dangerous) {
      b.setHigh();
      b.markDanger();
    }

    // Add specific reasons for dangerous subcommands
    if (sub === "rm") {
      b.addReason("git rm (deletes files from working tree and stages deletions)");
    }
    if (sub === "clean" && subArgs.some(a => a.includes("-f") || a === "-d" || a === "-x")) {
      b.addReason("git clean (can delete untracked files)");
    }
    if (sub === "reset" && subArgs.includes("--hard")) {
      b.addReason("git reset --hard (discard changes)");
    }
    if ((sub === "checkout" || sub === "restore") && (subArgs.includes(".") || subArgs.includes("--") || subArgs.includes("--source"))) {
      b.addReason("git checkout/restore (can overwrite working tree)");
    }
    if (sub === "push" && subArgs.some(a => a === "--force" || a === "--force-with-lease" || a === "-f")) {
      b.addReason("git push --force (rewrite remote history)");
    }
    if (sub === "reflog" && subArgs.includes("expire")) {
      b.addReason("git reflog expire (can remove recovery history)");
    }
    if (sub === "gc" && subArgs.some((a) => a.startsWith("--prune"))) {
      b.addReason("git gc --prune (can permanently delete objects)");
    }

    return b.build();
  },
};
