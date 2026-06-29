import { EvaluatorResult, EvalCache, RiskEvaluator } from "./types";
import { getFirstWord } from "../segment-helpers";

/**
 * Evaluates git commands for dangerous operations.
 */
export const GitEvaluator: RiskEvaluator = {
  name: "git",
  evaluate(seg, cwd, cache): EvaluatorResult {
    const segment = seg.text;
    const firstWord = cache?.firstWord ?? getFirstWord(segment);
    const args = segment.trim().split(/\s+/);
    const rest = args.slice(1);
    const sub = rest[0];
    const subArgs = rest.slice(1);
    const reasons: string[] = [];
    let severity: "high" | "medium" | null = null;
    let hasDanger = false;
    const setSeverity = (s: "high" | "medium") => {
      if (s === "high" || !severity) severity = s;
    };

    if (firstWord !== "git") return { reasons, severity, hasDanger, isSimple: undefined };

    reasons.push(sub ? `git ${sub} (git command)` : "git (git command)");

    // Use cached result
    if (cache?.gitDangerous) {
      hasDanger = true;
      setSeverity("high");
    }

    if (sub === "rm") {
      setSeverity("high");
      reasons.push("git rm (deletes files from working tree and stages deletions)");
    }
    if (sub === "clean" && (subArgs.some((a) => a.includes("-f")) || subArgs.includes("-d") || subArgs.includes("-x"))) {
      setSeverity("high");
      reasons.push("git clean (can delete untracked files)");
    }
    if (sub === "reset" && subArgs.includes("--hard")) {
      setSeverity("high");
      reasons.push("git reset --hard (discard changes)");
    }
    if ((sub === "checkout" || sub === "restore") && (subArgs.includes(".") || subArgs.includes("--") || subArgs.includes("--source"))) {
      reasons.push("git checkout/restore (can overwrite working tree)");
    }
    if (sub === "push" && (subArgs.includes("--force") || subArgs.includes("--force-with-lease") || subArgs.includes("-f"))) {
      setSeverity("high");
      reasons.push("git push --force (rewrite remote history)");
    }
    if (sub === "reflog" && subArgs.includes("expire")) {
      setSeverity("high");
      reasons.push("git reflog expire (can remove recovery history)");
    }
    if (sub === "gc" && subArgs.some((a) => a.startsWith("--prune"))) {
      setSeverity("high");
      reasons.push("git gc --prune (can permanently delete objects)");
    }

    return { reasons, severity, hasDanger, isSimple: undefined };
  },
};
