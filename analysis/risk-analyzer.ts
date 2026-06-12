import {
  dangerousCommandPatterns,
  dangerousContextPatterns,
  isAllowedCommand,
} from "../config";
import type { BashSegment } from "./bash-parser";
import { getFirstWord, splitPipeline, stripNullRedirects } from "./segment-helpers";

// ── Types ──

export interface CommandRisk {
  dangerous: boolean;
  reasons: string[];
  severity: "high" | "medium" | null;
}

interface SegmentRisk {
  severity: "high" | "medium" | null;
  reasons: string[];
}

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

  // Whole-command operator checks (these operate on the full command string)
  const cmdNoNullRedirect = stripNullRedirects(cmd);
  const hasRealWriteRedirect = /[0-9]*&?>+\s*\S/.test(cmdNoNullRedirect);
  if (hasRealWriteRedirect && !reasons.some(r => r.includes("shell output redirection"))) {
    reasons.push("[Risk] shell output redirection (can overwrite files)");
    setSeverity("medium");
  }

  // Input redirect
  if (cmd.includes("<") && !reasons.some(r => r.includes("input redirection"))) {
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
