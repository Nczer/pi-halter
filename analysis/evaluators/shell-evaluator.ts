import { EvaluationBuilder } from "./builder";
import { EvalCache, EvaluatorResult, RiskEvaluator } from "./types";
import { wrapperCommands } from "../../config";
import { dangerousSedFlags, dangerousPerlFlags, SORT_OUTPUT_RE } from "../../config/bash-patterns";
import {
  getFirstWord,
  getEffectiveCommand,
  hasWriteRedirect,
  isWrapperRunningWrite,
  hasTerminalEscape,
  echoInterpretsEscapes,

  stripQuotedStrings,
} from "../segment-helpers";

/** Pre-compiled regex for heredoc-to-interpreter detection. */
const HEREDOC_INTERPRETER_RE = /^(python|node|ruby|php|lua|perl|deno|bun|jruby|pypy|graalvm|uv|bash|sh|zsh|fish|csh|tcsh|ksh)$/i;



/** Download-and-execute RCE pattern for subshell inner text: curl/wget piped to a shell interpreter. */
const RCE_IN_SUBSHELL_RE = /\b(?:curl|wget)\b[\s\S]*?\|\s*(?:sh|bash|zsh|fish|ksh|dash|tcsh|csh|python[\d.]*|perl|ruby|node|php|lua|eval)\b/i;

/**
 * Evaluates shell constructs: subshells, heredocs, redirects, sed/perl, obfuscation, wrappers.
 * Pipeline analysis is done in segment-analysis.ts (needs access to dangerousCommandPatterns).
 */
export const ShellEvaluator: RiskEvaluator = {
  name: "shell",
  evaluate(seg, cwd, cache): EvaluatorResult {
    const segment = seg.text;
    const firstWord = cache?.firstWord ?? getFirstWord(segment);
    // `command printf …`, `env sort -o …`, `\printf …` execute the same
    // command — firstWord-based checks must use the effective command name.
    const effectiveFirst = getEffectiveCommand(segment);
    const b = new EvaluationBuilder();

    // Command substitution: the body is a program the shell runs before the
    // outer command starts, so it is analyzed as one — analyzeSubstBodies
    // parses each body and runs it through the full segment pipeline under the
    // parent's effective base (operands, flags, its own cd, nested bodies).
    // The name-list-over-text check that used to live here ("is every body
    // command read-only?") was a second allow table: it missed flags
    // (`fd -x rm`), relative operands (`cat .env`) and a `cd` inside the body.
    // What stays here is the case the parser cannot hand over: a substitution
    // node with no extractable body fails closed.
    if (seg.hasSubshell) {
      const innerTexts = seg.subshellTexts;
      if (!innerTexts || innerTexts.length === 0) {
        b.high("command substitution (subshell)");
      }
      // Surface RCE reason for curl/wget piped to shell inside the subshell
      if (innerTexts?.some(inner => RCE_IN_SUBSHELL_RE.test(inner))) {
        b.note("curl/wget | interpreter (download & execute remote code)");
      }
    }

    // Heredoc to interpreter
    const hasHeredoc = seg.ops.includes("<<") || seg.ops.includes("<<<");
    const isInterpreterWithHeredoc = hasHeredoc && HEREDOC_INTERPRETER_RE.test(effectiveFirst);
    if (isInterpreterWithHeredoc) {
      b.high("heredoc to shell interpreter (executable code)");
    }

    // Write redirect
    if (hasWriteRedirect(segment)) {
      b.danger("shell output redirection (can overwrite files)");
    }

    // sed/perl flags (check quote-stripped text so `-i` inside a quoted regex/script does not match)
    const stripped = stripQuotedStrings(segment);
    if (effectiveFirst === "sed" && dangerousSedFlags.test(stripped)) {
      b.high("sed -i (in-place file modification)");
    }
    if (effectiveFirst === "perl" && dangerousPerlFlags.test(stripped)) {
      b.high("perl -pi/-i (in-place file modification)");
    }

    // sort -o/--output (writes/truncates a file)
    if (effectiveFirst === "sort" && SORT_OUTPUT_RE.test(stripped)) {
      b.high("sort -o/--output (can truncate files)");
    }

    // echo/printf terminal escape sequences — screen spoofing (\033[2J + fake
    // prompt) and OSC 52 clipboard writes (\033]52;c;…). printf interprets
    // escapes unconditionally; echo only with -e or $'…' ANSI-C quoting.
    if (effectiveFirst === "printf" && hasTerminalEscape(segment)) {
      b.high("terminal escape sequence in printf (screen spoofing / clipboard write)");
    }
    if (effectiveFirst === "echo" && echoInterpretsEscapes(segment) && hasTerminalEscape(segment)) {
      b.high("terminal escape sequence in echo (screen spoofing / clipboard write)");
    }

    // Wrapper running write (not relative path - that only affects isSimple)
    if (wrapperCommands.has(firstWord) && isWrapperRunningWrite(segment, false)) {
      b.high(`${firstWord} wrapper running write operation`);
    }

    // bash -c/-i (shell with inline/script command)
    if (effectiveFirst === "bash" && /\s-(?:[a-z]*c[a-z]*|[a-z]*i[a-z]*)(?:\s|$)/.test(segment)) {
      b.high("bash -c/-i (shell with inline/script command)");
    }

    // source (config/secrets loading)
    if (effectiveFirst === "source" && /\.(?:env|bashrc|zshrc|profile|secret|local)\b/i.test(segment)) {
      b.high("source (config/secrets loading)");
    }

    // eval (arbitrary code execution)
    if (effectiveFirst === "eval") {
      b.high("eval (arbitrary code execution)");
    }

    // Obfuscation (use cached result)
    const obfuscation = cache?.obfuscation ?? { detected: false, techniques: [] };
    if (obfuscation.detected) {
      for (const tech of obfuscation.techniques) {
        b.note(tech);
      }
      b.high();
    }

    return b.build();
  },
};


