import { parseCommand, type BashSegment } from "./bash-parser";
import { isSimpleAllowedCommand, isSegmentUnsafe } from "./safety-checker";
import { analyzeRisk, type CommandRisk } from "./risk-analyzer";
import { getCommandSignature, isFirstTokenRelativePath } from "./segment-helpers";

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
}

// ── Public interface ──

/** Re-export for decision-engine.ts which needs relative-path checks. */
export { isFirstTokenRelativePath };

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
  const allSimple = (await Promise.all(segments.map(seg => isSimpleAllowedCommand(seg, cwd)))).every(Boolean);
  const hasUnsafe = (await Promise.all(segments.map(seg => isSegmentUnsafe(seg, cwd)))).some(Boolean);
  const risk = await analyzeRisk(cmd, segments);

  return { segments: segmentTexts, signatures, paths, allSimple, hasUnsafePattern: hasUnsafe, risk };
}
