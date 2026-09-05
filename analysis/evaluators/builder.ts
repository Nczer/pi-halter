import type { EvaluatorResult } from "./types";

/**
 * Builder for EvaluatorResult — the accumulator every evaluator ends with.
 *
 * Four verbs, one per state a check can express:
 *   note(r)    — a reason, no severity change
 *   high(r?)   — high severity + danger, optional reason
 *   danger(r?) — medium severity + danger, optional reason
 *   medium(r?) — medium severity (NOT dangerous), optional reason
 *
 * Severity max's (high wins), danger OR's, reasons accumulate in order.
 */
export class EvaluationBuilder {
  private reasons: string[] = [];
  private severity: "high" | "medium" | null = null;
  private hasDanger = false;

  note(reason: string): void {
    this.reasons.push(reason);
  }

  high(reason?: string): void {
    this.severity = "high";
    this.hasDanger = true;
    if (reason) this.reasons.push(reason);
  }

  danger(reason?: string): void {
    if (this.severity !== "high") this.severity = "medium";
    this.hasDanger = true;
    if (reason) this.reasons.push(reason);
  }

  medium(reason?: string): void {
    if (this.severity !== "high") this.severity = "medium";
    if (reason) this.reasons.push(reason);
  }

  build(): EvaluatorResult {
    return {
      reasons: this.reasons,
      severity: this.severity,
      hasDanger: this.hasDanger,
    };
  }
}
