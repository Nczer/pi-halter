import { EvaluationBuilder } from "./builder";
import { EvalCache, RiskEvaluator } from "./types";
import {
  dangerousSedFlags,
  dangerousPerlFlags,
  wrapperCommands,
} from "../../config";
import {
  getFirstWord,
  hasWriteRedirect,
  isWrapperRunningWrite,
} from "../segment-helpers";

/** Pre-compiled regex for heredoc-to-interpreter detection. */
const HEREDOC_INTERPRETER_RE = /^(python|node|ruby|php|lua|perl|deno|bun|jruby|pypy|graalvm|uv|bash|sh|zsh|fish|csh|tcsh|ksh)$/i;

/**
 * Evaluates shell constructs: subshells, heredocs, redirects, sed/perl, obfuscation, wrappers.
 * Pipeline analysis is done in segment-analysis.ts (needs access to dangerousCommandPatterns).
 */
export const ShellEvaluator: RiskEvaluator = {
  name: "shell",
  evaluate(seg, cwd, cache): ReturnType<EvaluationBuilder["build"]> {
    const segment = seg.text;
    const firstWord = cache?.firstWord ?? getFirstWord(segment);
    const b = new EvaluationBuilder();

    // Subshell
    if (seg.hasSubshell) {
      b.addHigh("command substitution (subshell)");
    }

    // Heredoc to interpreter
    const hasHeredoc = seg.ops.includes("<<") || seg.ops.includes("<<<");
    const isInterpreterWithHeredoc = hasHeredoc && HEREDOC_INTERPRETER_RE.test(firstWord);
    if (isInterpreterWithHeredoc) {
      b.addHigh("heredoc to shell interpreter (executable code)");
    }

    // Write redirect
    if (hasWriteRedirect(segment)) {
      b.addMedium("shell output redirection (can overwrite files)");
      b.markDanger();
    }

    // sed/perl flags
    if (firstWord === "sed" && dangerousSedFlags.test(segment)) {
      b.addHigh("sed -i (in-place file modification)");
    }
    if (firstWord === "perl" && dangerousPerlFlags.test(segment)) {
      b.addHigh("perl -pi/-i (in-place file modification)");
    }

    // Wrapper running write (not relative path - that only affects isSimple)
    if (wrapperCommands.has(firstWord) && isWrapperRunningWrite(segment, false)) {
      b.addHigh(`${firstWord} wrapper running write operation`);
    }

    // Obfuscation (use cached result)
    const obfuscation = cache?.obfuscation ?? { detected: false, techniques: [] };
    if (obfuscation.detected) {
      for (const tech of obfuscation.techniques) {
        b.addReason(tech);
      }
      b.setHigh();
    }

    return b.build();
  },
};


