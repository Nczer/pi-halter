import { EvaluatorResult, RiskEvaluator } from "./types";
import {
  dangerousSedFlags,
  dangerousPerlFlags,
  wrapperCommands,
  isWriteOperation,
  isAllowedCommand,
} from "../../config";
import {
  containsCommandSubstitution,
  stripNullRedirects,
  getFirstWord,
} from "../segment-helpers";
import { isFirstTokenRelativePath } from "../path-analysis";
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

function hasWriteRedirect(cmd: string): boolean {
  const trimmed = cmd.trim();
  if (/^[0-9]*&?>+/.test(trimmed)) {
    if (!stripNullRedirects(trimmed).trim()) return false;
  }
  const stripped = stripNullRedirects(cmd);
  if (/>+\s*\S/.test(stripped)) {
    const inTest = /\[\s.*\]/.test(stripped) || /test\s/.test(stripped);
    if (!inTest) return true;
  }
  return false;
}

function isWrapperRunningWrite(segment: string, includeRelativePath = true): boolean {
  const args = segment.trim().split(/\s+/);
  const firstWord = args[0].toLowerCase();
  for (let i = 1; i < args.length; i++) {
    const arg = args[i];
    if (skipWrapperArg(firstWord, arg)) continue;
    const wrappedCmd = arg.toLowerCase();
    if (includeRelativePath && isFirstTokenRelativePath(arg)) return true;
    if (isWriteOperation(wrappedCmd, segment)) return true;
    break;
  }
  return false;
}

function skipWrapperArg(wrapper: string, arg: string): boolean {
  if (arg.startsWith("-")) return true;
  if (wrapper === "env" && /=/.test(arg) && !arg.startsWith("/")) return true;
  if (wrapper === "timeout" && /^\d+(\.\d+)?(?:[smhd])?$/.test(arg)) return true;
  if (wrapper === "nice" && /^\d+$/.test(arg)) return true;
  if (wrapper === "ionice" && /^\d+$/.test(arg)) return true;
  return false;
}
