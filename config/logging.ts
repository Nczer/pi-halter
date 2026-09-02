/**
 * Decision log — compile-time DEFAULT (JSONL blast-radius log — see
 * decision-log.ts).
 *
 * OFF by default. The live toggle is /halter-decision-log [on|off],
 * persisted in the halter namespace of ~/.pi/agent/settings-ext.json. When
 * enabled, every gated decision (auto-allow / prompt / block) is appended as
 * one JSON line to <extension dir>/.log/decisions.jsonl (5 MiB rotation).
 * Useful after changing gate code: diff what now prompts vs. what used to
 * auto-allow, or mine repeatedly-prompting commands into contract rows.
 *
 * D17 toggle split: this toggle covers decisions.jsonl ONLY. The small
 * diagnostic ledgers — unresolved.jsonl (parser convergence) and
 * judge.jsonl (stage diffs / infra failures / D13 path mismatches) — are
 * ALWAYS ON; their env seams (HALTER_UNRESOLVED_LOG, HALTER_JUDGE_LOG)
 * accept `off` for test hermeticity only.
 *
 * Transient override: HALTER_DECISION_LOG=<path> (enables at that path) or
 * HALTER_DECISION_LOG=off (forces off).
 */
export const DECISION_LOG_ENABLED = false;
