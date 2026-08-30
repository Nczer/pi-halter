/**
 * Vitest worker setup — runs before every test file in each worker
 * (setupFiles in vitest.config.ts; globalSetup would NOT work: it runs in
 * the main process, not the workers).
 *
 * On dev machines the user's ~/.pi/agent/settings-ext.json has the decision log
 * enabled, and module state (decision-log.ts) picks that up on import.
 * Without this guard, every test that runs the real gate flow appends
 * fixture lines to the live .log/decisions.jsonl — the 2026-08-25 log
 * collected 24 fixture lines from 6 vitest runs ("boom" fail-closed blocks,
 * `cat /etc/passwd`, `~/.ssh/id_rsa` blocks).
 *
 * Force-off for the whole worker: logDecision becomes a no-op. Test files
 * that need the log set HALTER_DECISION_LOG to a tmp path per-test and
 * restore it (decision-log.test.ts, dspa.test.ts) — that still wins.
 */
process.env.HALTER_DECISION_LOG = "off";
