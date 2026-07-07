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

/** Commands safe inside subshells (pure path formatting, no side effects or I/O). */
const SAFE_SUBSHELL_CMDS = new Set(["basename", "dirname"]);

/** Download-and-execute RCE pattern for subshell inner text: curl/wget piped to a shell interpreter. */
const RCE_IN_SUBSHELL_RE = /\b(?:curl|wget)\b[\s\S]*?\|\s*(?:sh|bash|zsh|fish|ksh|dash|tcsh|csh|python[\d.]*|perl|ruby|node|php|lua|eval)\b/i;

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

    // Subshell — downgrade to informational for known-safe formatting commands
    if (seg.hasSubshell) {
      const innerTexts = seg.subshellTexts;
      if (innerTexts && innerTexts.length > 0) {
        const allSafe = innerTexts.every(inner => {
          const fw = getFirstWord(inner);
          if (!SAFE_SUBSHELL_CMDS.has(fw)) return false;
          // Must not pipe, redirect, background, or contain nested subshells
          if (/[|&><]/.test(inner)) return false;
          if (/\(/.test(inner)) return false;    // nested $(…)
          if (/`/.test(inner)) return false;      // nested backtick
          return true;
        });
        if (allSafe) {
          b.addMedium("command substitution (subshell)");
        } else {
          b.addHigh("command substitution (subshell)");
          // Surface RCE reason for curl/wget piped to shell inside the subshell
          if (innerTexts.some(inner => RCE_IN_SUBSHELL_RE.test(inner))) {
            b.addReason("curl/wget | interpreter (download & execute remote code)");
          }
        }
      } else {
        b.addHigh("command substitution (subshell)");
      }
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

    // bash -c/-i (shell with inline/script command)
    if (firstWord === "bash" && /\s-(?:[a-z]*c[a-z]*|[a-z]*i[a-z]*)(?:\s|$)/.test(segment)) {
      b.addHigh("bash -c/-i (shell with inline/script command)");
    }

    // source (config/secrets loading)
    if (firstWord === "source" && /\.(?:env|bashrc|zshrc|profile|secret|local)\b/i.test(segment)) {
      b.addHigh("source (config/secrets loading)");
    }

    // eval (arbitrary code execution)
    if (firstWord === "eval") {
      b.addHigh("eval (arbitrary code execution)");
    }

    // Obfuscation (use cached result)
    const obfuscation = cache?.obfuscation ?? { detected: false, techniques: [] };
    if (obfuscation.detected) {
      for (const tech of obfuscation.techniques) {
        b.addReason(tech);
      }
      b.setHigh();
      b.markDanger();
    }

    return b.build();
  },
};


