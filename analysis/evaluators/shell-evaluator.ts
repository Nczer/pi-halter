import { EvaluatorResult, RiskEvaluator } from "./types";
import {
  dangerousSedFlags,
  dangerousPerlFlags,
  wrapperCommands,
} from "../../config";
import {
  containsCommandSubstitution,
  getFirstWord,
  hasWriteRedirect,
  isWrapperRunningWrite,
} from "../segment-helpers";
import { detectObfuscation } from "../segment-analysis";

/**
 * Evaluates shell constructs: subshells, heredocs, redirects, sed/perl, obfuscation, wrappers.
 * Pipeline analysis is done in segment-analysis.ts (needs access to dangerousCommandPatterns).
 */
export const ShellEvaluator: RiskEvaluator = {
  name: "shell",
  evaluate(seg, cwd): EvaluatorResult {
    const segment = seg.text;
    const firstWord = getFirstWord(segment);
    const reasons: string[] = [];
    let severity: "high" | "medium" | null = null;
    let hasDanger = false;
    const setSeverity = (s: "high" | "medium") => {
      if (s === "high" || !severity) severity = s;
    };

    // Subshell
    if (seg.hasSubshell) {
      hasDanger = true;
      reasons.push("command substitution (subshell)");
      setSeverity("high");
    }

    // Heredoc to interpreter
    const hasHeredoc = seg.ops.includes("<<") || seg.ops.includes("<<<");
    const isInterpreterWithHeredoc = hasHeredoc && new RegExp(
      "^(python|node|ruby|php|lua|perl|deno|bun|jruby|pypy|graalvm|uv|bash|sh|zsh|fish|csh|tcsh|ksh)", "i"
    ).test(firstWord);
    if (isInterpreterWithHeredoc) {
      hasDanger = true;
      reasons.push("heredoc to shell interpreter (executable code)");
      setSeverity("high");
    }

    // Write redirect
    const writeRedirect = hasWriteRedirect(segment);
    if (writeRedirect) {
      hasDanger = true;
      reasons.push("shell output redirection (can overwrite files)");
      setSeverity("medium");
    }

    // sed/perl flags
    if (firstWord === "sed" && dangerousSedFlags.test(segment)) {
      hasDanger = true;
      reasons.push("sed -i (in-place file modification)");
      setSeverity("high");
    }
    if (firstWord === "perl" && dangerousPerlFlags.test(segment)) {
      hasDanger = true;
      reasons.push("perl -pi/-i (in-place file modification)");
      setSeverity("high");
    }

    // Wrapper running write (not relative path - that only affects isSimple)
    if (wrapperCommands.has(firstWord) && isWrapperRunningWrite(segment, false)) {
      hasDanger = true;
      setSeverity("high");
      reasons.push(`${firstWord} wrapper running write operation`);
    }

    // Obfuscation
    const obfuscation = detectObfuscation(segment);
    if (obfuscation.detected) {
      for (const tech of obfuscation.techniques) {
        if (!reasons.includes(tech)) reasons.push(tech);
      }
      setSeverity("high");
    }

    return { reasons, severity, hasDanger, isSimple: undefined };
  },
};


