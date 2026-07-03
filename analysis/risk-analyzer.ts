import { isAllowedCommand } from "../config";
import { getFirstWord, splitPipeline, stripNullRedirects, stripQuotedStrings } from "./segment-helpers";
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

// ── Whole-command risk analysis ──

/**
 * Analyze whole-command risk factors that cannot be detected per-segment.
 * Merges per-segment risks (from segment-analysis.ts) with operator-level checks.
 */
export async function analyzeWholeCommandRisk(
  cmd: string,
  segmentRisks: SegmentRisk[],
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
  const cmdNoQuotes = stripQuotedStrings(cmd);
  const cmdNoNullRedirect = stripNullRedirects(cmdNoQuotes);
  const hasRealWriteRedirect = WHOLE_CMD_WRITE_REDIRECT_RE.test(cmdNoNullRedirect);
  if (hasRealWriteRedirect && !reasons.some(r => r.includes("shell output redirection"))) {
    reasons.push("[Risk] shell output redirection (can overwrite files)");
    setSeverity("medium");
  }

  // Input redirect
  if (cmdNoQuotes.includes("<") && !reasons.some(r => r.includes("input redirection"))) {
    reasons.push("[Risk] shell input redirection");
  }

  // Pipe operator — only flag if at least one stage is NOT an allowed command
  if (cmd.includes("|") && !reasons.some(r => r.includes("pipe operator"))) {
    const allStagesSafe = splitPipeline(cmd).every(part => {
      const stage = stripNullRedirects(part).trim();
      if (!stage) return true;
      return isAllowedCommand(getFirstWord(stage));
    });
    if (!allStagesSafe) {
      reasons.push("[Risk] pipe operator (chained commands)");
      setSeverity("medium");
    }
  }

  return { dangerous: reasons.length > 0, reasons, severity };
}
