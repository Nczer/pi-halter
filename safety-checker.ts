import type { BashSegment } from "./bash-parser";
import { analyzeSegment } from "./segment-analysis";

// ── Legacy exports (thin wrappers around segment-analysis.ts) ──

/**
 * Check if a segment is a simple allowed command.
 * @deprecated Use analyzeSegment() directly for unified analysis.
 */
export async function isSimpleAllowedCommand(seg: BashSegment, cwd: string): Promise<boolean> {
  return (await analyzeSegment(seg, cwd)).isSimple;
}

/**
 * Check if a segment matches any unsafe pattern.
 * @deprecated Use analyzeSegment() directly for unified analysis.
 */
export async function isSegmentUnsafe(seg: BashSegment, cwd: string): Promise<boolean> {
  return (await analyzeSegment(seg, cwd)).isUnsafe;
}
