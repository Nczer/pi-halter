import { parseCommand, type BashSegment } from "./bash-parser";
import { analyzeSegment, type SegmentRisk } from "./segment-analysis";
import { analyzeWholeCommandRisk } from "./risk-analyzer";
import { hasRelativePath } from "./path-analysis";
import { getCommandSignature } from "./segment-helpers";

// ── Types ──

/** Full analysis of a shell command — single source of truth for parsing, safety, and risk. */
interface CommandAnalysis {
  /** Raw segment strings, split on &&, ||, ;, |, etc. */
  segments: string[];
  /** Command signatures for auto-allow matching (e.g. "git -R", "ls"). */
  signatures: string[];
  /** All extracted file/dir paths, resolved to absolute. */
  paths: string[];
  /** Every segment is a simple allowed command (allowlist, no subshells/redirects/dangerous flags). */
  allSimple: boolean;
  /** Any segment matches an unsafe pattern (subshell, obfuscation, dangerous flags, write redirect, danger regex). */
  hasUnsafePattern: boolean;
  /** Detailed risk assessment from token-based and regex-based analysis. */
  risk: CommandRisk;
  /** Indices of segments that contain relative path tokens (./foo, ../foo). */
  relativePathSegmentIndices: number[];
}

export interface CommandRisk {
  dangerous: boolean;
  reasons: string[];
  severity: "high" | "medium" | null;
}

// ── Public interface ──

/**
 * Analyze a shell command. Single source of truth for parsing, path extraction,
 * safety evaluation, and risk assessment.
 *
 * Uses tree-sitter-bash AST for accurate segmentation, path extraction,
 * and operator detection (handles heredocs, comments, quotes, subshells,
 * and redirects correctly).
 */
export async function analyzeCommand(cmd: string, cwd: string): Promise<CommandAnalysis> {
  // Single AST parse: segments, paths, and subshell flags in one pass
  const result = await parseCommand(cmd, cwd);
  const { segments, paths } = result;
  const segmentTexts = segments.map(s => s.text);
  const signatures = segmentTexts.map(getCommandSignature);

  // Unified segment analysis: one call per segment replaces
  // hasKnownDanger + isSimpleAllowedCommand + isSegmentUnsafe + analyzeSegmentRisk
  const segmentAnalyses = await Promise.all(segments.map(seg => analyzeSegment(seg, cwd)));

  const allSimple = segmentAnalyses.every(a => a.isSimple);
  const hasUnsafe = segmentAnalyses.some(a => a.isUnsafe);

  // Merge per-segment risks with whole-command risk
  const segmentRisks = segmentAnalyses.map(a => a.risk);
  const wholeRisk = await analyzeWholeCommandRisk(cmd, segmentRisks);

  // Pre-compute relative path indices — decision engine consumes this instead of scanning tokens
  const relativePathSegmentIndices = segmentTexts
    .map((seg, i) => hasRelativePath(seg) ? i : -1)
    .filter(i => i >= 0);

  return { segments: segmentTexts, signatures, paths, allSimple, hasUnsafePattern: hasUnsafe, risk: wholeRisk, relativePathSegmentIndices };
}
