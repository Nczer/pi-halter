/**
 * Decision log — compile-time DEFAULT (JSONL blast-radius log — see
 * decision-log.ts).
 *
 * OFF by default. The live toggle is /halter-decision-log [on|off],
 * persisted in ~/.pi/agent/halter.json (halter's own settings file). When
 * enabled, every gated decision (auto-allow / prompt / block) is appended as
 * one JSON line to <extension dir>/.log/decisions.jsonl (5 MiB rotation).
 * Useful after changing gate code: diff what now prompts vs. what used to
 * auto-allow, or mine repeatedly-prompting commands into contract rows.
 *
 * Transient override: HALTER_DECISION_LOG=<path> (enables at that path) or
 * HALTER_DECISION_LOG=off (forces off).
 */
export const DECISION_LOG_ENABLED = false;
