import { parseCommand, type BashSegment } from "./bash-parser";
import { isSimpleAllowedCommand, isSegmentUnsafe, hasKnownDanger } from "./safety-checker";
import { analyzeRisk, type CommandRisk } from "./risk-analyzer";
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

  // Compute all safety checks in one pass per segment to avoid running
  // hasKnownDanger() twice (once for isSimple, once for isUnsafe)
  const safetyResults = await Promise.all(segments.map(async (seg, i) => {
    const danger = hasKnownDanger(seg);
    const [simple, unsafe] = await Promise.all([
      // Pass cached danger result to avoid recomputation
      isSimpleAllowedCommand(seg, cwd, danger),
      isSegmentUnsafe(seg, cwd, danger),
    ]);
    return { simple, unsafe };
  }));

  const allSimple = safetyResults.every(r => r.simple);
  const hasUnsafe = safetyResults.some(r => r.unsafe);
  const risk = await analyzeRisk(cmd, segments);

  // Pre-compute relative path indices — decision engine consumes this instead of scanning tokens
  const relativePathSegmentIndices = segmentTexts
    .map((seg, i) => hasRelativePath(seg) ? i : -1)
    .filter(i => i >= 0);

  return { segments: segmentTexts, signatures, paths, allSimple, hasUnsafePattern: hasUnsafe, risk, relativePathSegmentIndices };
}
