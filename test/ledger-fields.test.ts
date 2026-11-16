/**
 * L2/L3 of docs/dspa-credential-vouch.md §7, at the pure-function level.
 *
 * gate.ts writes what these two helpers return, so the ledger's truth table
 * lives here: what the verdict STATE is, why it did not decide, and the ONE
 * slug naming what stopped the operation. The end-to-end rows are pinned in
 * test/dspa.test.ts; this file pins the derivation, including the combinations
 * the live cascade reaches rarely (a defer, an approve held by the floor).
 */
import { describe, expect, it } from "vitest";
import { dspaStopClass, judgeLedgerFields, type DspaFallthrough } from "../gate/fallthrough";
import type { JudgeResult } from "../judge/judge";
import type { DspaGateResult } from "../gate/dspa-gate";
import type { StopClass } from "../decide/types";

function verdict(approve: JudgeResult["approve"], over: Partial<JudgeResult> = {}): JudgeResult {
  return {
    approve,
    risk: approve === "approve" ? "low" : "high",
    explanation: "the model's one line",
    reason: "a factor",
    model: "llama-cpp/qwen",
    latencyMs: 120,
    cached: false,
    ...over,
  } as JudgeResult;
}

const pass: DspaGateResult = { ok: true };
function stop(stopClass: StopClass, reason = "the floor's sentence"): DspaGateResult {
  return { ok: false, stopClass, reason } as DspaGateResult;
}

function f(over: Partial<DspaFallthrough>): DspaFallthrough {
  return { gate: pass, verdict: null, stage: null, ...over };
}

describe("judgeLedgerFields (L2)", () => {
  it("names every verdict, so a reader never infers one from an absence", () => {
    expect(judgeLedgerFields(f({ verdict: verdict("approve"), stage: 2 }))).toEqual({
      judgeVerdict: "approve",
      judgeStage: 2,
      judgeModel: "llama-cpp/qwen",
    });
    // The old `judgeDeny` recorded nothing here, so a DEFER and a skipped
    // stage 2 looked identical in the ledger.
    expect(judgeLedgerFields(f({ verdict: verdict("defer"), stage: 2 })).judgeExplain).toBe(
      "the model's one line",
    );
    expect(judgeLedgerFields(f({ verdict: verdict("deny"), stage: 1 })).judgeVerdict).toBe("deny");
    expect(judgeLedgerFields(f({}))).toEqual({ judgeVerdict: "none" });
  });

  it("carries the skip reason beside the value", () => {
    expect(judgeLedgerFields(f({ verdict: verdict("approve"), stage: 2, judgeSkipped: "risk-tier" }))).toMatchObject({
      judgeVerdict: "approve",
      judgeSkipped: "risk-tier",
    });
    expect(judgeLedgerFields(f({ judgeSkipped: "d22" }))).toEqual({
      judgeVerdict: "none",
      judgeSkipped: "d22",
    });
    expect(judgeLedgerFields(f({ judgeSkipped: "floor-before-verdict" })).judgeSkipped).toBe(
      "floor-before-verdict",
    );
  });

  it("explains a non-approve and stays silent on an approve", () => {
    for (const a of ["deny", "defer"] as const) {
      expect(judgeLedgerFields(f({ verdict: verdict(a), stage: 2 })).judgeExplain).toBeTruthy();
    }
    expect("judgeExplain" in judgeLedgerFields(f({ verdict: verdict("approve"), stage: 2 }))).toBe(false);
  });

  it("returns nothing at all without a fall-through", () => {
    expect(judgeLedgerFields(undefined)).toEqual({});
  });
});

describe("dspaStopClass (L3)", () => {
  it("lets the floor outrank the verdict (D16: no verdict grants over a bar)", () => {
    const c = dspaStopClass(f({ gate: stop("credential-pattern", "credential pattern (*.pem)"), verdict: verdict("approve"), stage: 2, judgeSkipped: "floor-before-verdict" }));
    expect(c).toEqual({ stopClass: "credential-pattern", stopDetail: "credential pattern (*.pem)" });
  });

  it("calls an approve held by the risk tier judge-unauthorized, not judge-declined", () => {
    // Blaming a yes in the rollup would put the model's non-decision in the
    // same bucket as its rejections.
    const c = dspaStopClass(f({ verdict: verdict("approve"), stage: 2, judgeSkipped: "risk-tier" }));
    expect(c?.stopClass).toBe("judge-unauthorized");
    expect(c?.stopDetail).toContain("risk authority");
  });

  it("names a stage-2 verdict that did not approve judge-declined", () => {
    expect(dspaStopClass(f({ verdict: verdict("deny"), stage: 2 }))?.stopClass).toBe("judge-declined");
    expect(dspaStopClass(f({ verdict: verdict("defer"), stage: 2 }))).toEqual({
      stopClass: "judge-declined",
      stopDetail: "defer (stage 2)",
    });
  });

  it("names a judge that produced nothing usable judge-failed, with its typed reason", () => {
    expect(dspaStopClass(f({ verdict: verdict("deny"), stage: 1, judgeFail: "timeout 8.0s" }))).toEqual({
      stopClass: "judge-failed",
      stopDetail: "no usable verdict (timeout 8.0s)",
    });
    expect(dspaStopClass(f({ note: "judge off (settings)" }))).toEqual({
      stopClass: "judge-failed",
      stopDetail: "no usable verdict (judge off (settings))",
    });
    expect(dspaStopClass(f({}))).toEqual({ stopClass: "judge-failed", stopDetail: "no usable verdict" });
  });

  it("returns nothing at all without a fall-through", () => {
    expect(dspaStopClass(undefined)).toBeUndefined();
  });
});
