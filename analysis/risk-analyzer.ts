import { isAllowedCommand } from "../config";
import { DOUBLE_BRACKET_COND_RE, getFirstWord, splitPipeline, stripNullRedirects, stripQuotedStrings } from "./segment-helpers";
import type { SegmentRisk } from "./segment-analysis";

// ── Types ──

/** Full command risk assessment (dangerous + reasons + severity). */
export interface CommandRisk {
  dangerous: boolean;
  reasons: string[];
  severity: "high" | "medium" | null;
}

/** Pre-compiled regex for whole-command write redirect check. */
const WHOLE_CMD_WRITE_REDIRECT_RE = /[0-9]*&?>+\s*\S/;

/**
 * An INPUT redirect (`< file`), excluding the heredoc operators. `<<`/`<<<` are
 * heredoc/herestring: the body is code the interpreter pass already sees, and
 * flagging them here read as "input redirection" on every `python3 - <<'PY'`
 * (58 of 69 multiline rows in the .log/ replay carried the flag, 53 of them on
 * nothing but the operator). A real `<` reads a FILE, which is what the flag
 * claims.
 */
const WHOLE_CMD_INPUT_REDIRECT_RE = /(?<![<>])<(?!<)/;

// ── Whole-command risk analysis ──

/**
 * Analyze whole-command risk factors that cannot be detected per-segment.
 * Merges per-segment risks (from segment-analysis.ts) with operator-level checks.
 *
 * `shellText` is the parser's heredoc-body-stripped view of the same command
 * (`parseCommand → heredocStrippedCommand`). The operator scans below run on
 * IT, never on the raw command: a heredoc body is code handed to an
 * interpreter, and scanning it as shell syntax invented redirects out of python
 * (`if a>2:` -> "shell output redirection") and pipes out of `a | b`.
 */
export async function analyzeWholeCommandRisk(
  segmentRisks: SegmentRisk[],
  shellText: string,
): Promise<CommandRisk> {
  const reasons: string[] = [];
  let severity: "high" | "medium" | null = null;
  const setSeverity = (s: "high" | "medium") => {
    if (s === "high" || !severity) severity = s;
  };

  // Collect per-segment risks
  for (const segRisk of segmentRisks) {
    if (segRisk.severity === "high") setSeverity("high");
    else if (segRisk.severity === "medium" && !severity) setSeverity("medium");
    for (const r of segRisk.reasons) {
      if (!reasons.includes(r)) reasons.push(r);
    }
  }

  // Whole-command operator checks. Strip quoted strings first so operators that
  // appear inside quotes (e.g. a grep pattern containing "=>" or "<") are not
  // misread as shell redirects. Unquoted $(...) is preserved.
  const cmdNoQuotes = stripQuotedStrings(shellText).replace(DOUBLE_BRACKET_COND_RE, "");
  const cmdNoNullRedirect = stripNullRedirects(cmdNoQuotes);
  const hasRealWriteRedirect = WHOLE_CMD_WRITE_REDIRECT_RE.test(cmdNoNullRedirect);
  if (hasRealWriteRedirect && !reasons.some(r => r.includes("shell output redirection"))) {
    reasons.push("[Risk] shell output redirection (can overwrite files)");
    setSeverity("medium");
  }

  // Input redirect
  if (WHOLE_CMD_INPUT_REDIRECT_RE.test(cmdNoQuotes) && !reasons.some(r => r.includes("input redirection"))) {
    reasons.push("[Risk] shell input redirection");
  }

  // Shell compound keywords that can lead a pipeline stage. Their bodies are
  // analyzed as their own segments, so the stage needs no first-word check —
  // flagging them (e.g. `for …; do a | b; done`) was pure reason noise.
  const COMPOUND_STAGE_KEYWORDS = new Set([
    "for", "while", "until", "if", "case", "select", "function", "coproc", "time", "!", "{", "(",
  ]);

  // Pipe operator — only flag if at least one stage is NOT an allowed command
  if (shellText.includes("|") && !reasons.some(r => r.includes("pipe operator"))) {
    const allStagesSafe = splitPipeline(shellText).every(part => {
      const stage = stripNullRedirects(part).trim();
      if (!stage) return true;
      const first = getFirstWord(stage);
      if (COMPOUND_STAGE_KEYWORDS.has(first)) return true;
      return isAllowedCommand(first);
    });
    if (!allStagesSafe) {
      reasons.push("[Risk] pipe operator (chained commands)");
      setSeverity("medium");
    }
  }

  return { dangerous: reasons.length > 0, reasons, severity };
}
