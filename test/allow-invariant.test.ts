/**
 * allow-invariant.test.ts — the fast path may never out-run the full pipeline.
 *
 * FastAllowRule decides for `unconditionallySafeCommands` without the
 * tree-sitter parse; the table in config/bash-patterns.ts is the single
 * source of truth for both allow sets. This test pins the invariant the
 * table's comment promises:
 *
 *  (static)      every unconditionally-safe entry is allowlisted;
 *  (behavioral)  for every unconditionally-safe entry, a bare invocation is
 *                auto-allowed by the FULL pipeline (analyzeCommand +
 *                SafetyRule) — so anything the fast path auto-allows,
 *                SafetyRule auto-allows too.
 *
 * If an entry drifts (e.g. `sort` loses its exclusion reason, or loses its
 * allowlist membership, or grows a danger flag), this fails.
 */
import { describe, it, expect } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { unconditionallySafeCommands, isAllowedCommand } from "../config";
import { FastAllowRule, SafetyRule } from "../policies/bash-rules";
import { analyzeCommand } from "../analysis/command-analysis";
import { createStore } from "../store";
import type { BashRequest } from "../decision-engine";

describe("unconditionallySafeCommands invariant", () => {
  const cwd = mkdtempSync(path.join(tmpdir(), "halter-allow-invariant-"));
  const store = createStore();
  const req = (cmd: string): BashRequest => ({ type: "bash", command: cmd, cwd });

  it("is a subset of the allowlist (static)", () => {
    const missing = [...unconditionallySafeCommands].filter((cmd) => !isAllowedCommand(cmd));
    expect(missing).toEqual([]);
  });

  it("fast path and full pipeline agree on every entry (behavioral)", async () => {
    const drift: string[] = [];
    for (const cmd of unconditionallySafeCommands) {
      const fast = FastAllowRule(req(cmd), store);
      const full = SafetyRule(req(cmd), store, await analyzeCommand(cmd, cwd));
      if (fast?.kind !== "auto-allow") drift.push(`${cmd}: fast=${fast?.kind ?? "null"}`);
      if (full?.kind !== "auto-allow") drift.push(`${cmd}: full=${full?.kind ?? "null"}`);
    }
    expect(drift).toEqual([]);
  });
});
