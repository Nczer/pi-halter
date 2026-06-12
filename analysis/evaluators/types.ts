import type { BashSegment } from "../bash-parser";

export interface EvaluatorResult {
  reasons: string[];
  severity: "high" | "medium" | null;
  hasDanger: boolean;
  isSimple: boolean | undefined; // Optional override for isSimple
}

export interface RiskEvaluator {
  name: string;
  evaluate(seg: BashSegment, cwd: string): EvaluatorResult;
}
