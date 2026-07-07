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
}

export interface RiskEvaluator {
  name: string;
  evaluate(seg: BashSegment, cwd: string, cache?: EvalCache): EvaluatorResult;
}
