import type { EvaluatorResult } from "./types";

/**
 * Builder for EvaluatorResult — eliminates boilerplate across evaluators.
 *
 * Usage:
 *   const b = new EvaluationBuilder();
 *   if (condition) b.addHigh("reason text");
 *   if (condition) b.addMedium("reason text");
 *   return b.build();
 */
export class EvaluationBuilder {
  private reasons: string[] = [];
  private severity: "high" | "medium" | null = null;
  private hasDanger = false;

  /** Add a reason with high severity and mark as dangerous. */
  addHigh(reason: string): void {
    this.reasons.push(reason);
    this.severity = "high";
    this.hasDanger = true;
  }

  /** Add a reason with medium severity (unless already high). */
  addMedium(reason: string): void {
    this.reasons.push(reason);
    if (!this.severity) this.severity = "medium";
  }

  /** Add a reason without changing severity. */
  addReason(reason: string): void {
    this.reasons.push(reason);
  }

  /** Mark as dangerous without adding a reason. */
  markDanger(): void {
    this.hasDanger = true;
  }

  /** Force high severity without adding a reason. */
  setHigh(): void {
    this.severity = "high";
  }

  /** Force medium severity (unless already high). */
  setMedium(): void {
    if (!this.severity) this.severity = "medium";
  }

  /** Force severity (unless already higher). */
  setSeverity(severity: "high" | "medium"): void {
    if (severity === "high" || !this.severity) this.severity = severity;
  }

  /** Build the final EvaluatorResult. */
  build(): EvaluatorResult {
    return {
      reasons: this.reasons,
      severity: this.severity,
      hasDanger: this.hasDanger,
      isSimple: undefined,
    };
  }
}
