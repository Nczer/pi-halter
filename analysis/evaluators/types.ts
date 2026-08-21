import type { BashSegment } from "../bash-parser";

export interface EvaluatorResult {
  reasons: string[];
  severity: "high" | "medium" | null;
  hasDanger: boolean;
}

/** Cached results to avoid redundant computation across evaluators. */
export interface EvalCache {
  firstWord?: string;
  obfuscation?: { detected: boolean; techniques: string[] };
  gitDangerous?: boolean;
  /**
   * False when the segment's cwd is the unknown-base marker ("/") — relative
   * tokens must not be resolved against it (they would resolve to "/x", a
   * real system location that may not be the runtime location).
   */
  cwdKnown?: boolean;
}

export interface RiskEvaluator {
  name: string;
  evaluate(seg: BashSegment, cwd: string, cache?: EvalCache): EvaluatorResult;
}
