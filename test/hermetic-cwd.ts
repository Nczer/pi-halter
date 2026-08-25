/**
 * Hermetic contract cwd for decide()/analyzeCommand() suites.
 *
 * The gate probes the real filesystem (lstat on bare tokens, statSync on cd
 * and rm targets). Running suites against a fixed home dir makes decisions
 * depend on whatever happens to live there; a per-file temp dir keeps every
 * row deterministic and the suite portable across machines.
 *
 * Each vitest worker runs one test file, so create in beforeAll and remove in
 * afterAll, per file. No subdirs are pre-created: the contract rows only cd
 * into absolute, tilde, or variable paths. A row that cds into a relative
 * dir must create that dir in its own fixture — `cd <nonexistent>`
 * short-circuits (resolveCdTarget stats the target) and would silently
 * weaken the row.
 *
 * The base dir is under $HOME (dot-prefixed), deliberately NOT under
 * os.tmpdir() or /tmp: those are in allowedWriteDirs (config/path-rules.ts)
 * and a cwd inside them auto-allows every in-cwd file write, flipping the
 * "write → prompt" contract. It must also stay out of any .pi dir, where
 * path rules auto-allow reads/writes by location.
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

export function createContractCwd(): string {
	return fs.mkdtempSync(path.join(os.homedir(), ".halter-cwd-"));
}

export function removeContractCwd(dir: string): void {
	fs.rmSync(dir, { recursive: true, force: true });
}
