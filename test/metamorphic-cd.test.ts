/**
 * Metamorphic property (perm #645 recipe, class 2): a decision must not
 * depend on how the same command is spelled. Here: prefixing any contract
 * command with `cd <subdir> && ` (subdir ⊂ the test cwd) must not change
 * the decision kind.
 *
 * Why it should hold:
 *  • relative paths resolve against cwd/subdir — still inside cwd
 *  • absolute / $HOME / marker paths are cd-unaffected
 *  • `cd <existing-dir>` is allowlisted navigation (one extra approved segment)
 *  • the credential scan is raw-text — the prefix adds no credential text
 *  • any cd INSIDE the original command still overrides the prefix
 *
 * Any divergence is a real finding: either the gate reads the cd prefix
 * differently from bash, or the base row encodes cwd-relative behavior.
 * EXCEPTIONS below are known-legitimate: the prefix changes the command's
 * actual bash semantics (not merely its spelling).
 */
import path from "node:path";
import os from "node:os";
import fs from "node:fs";
import { describe, expect, it, beforeAll, afterAll } from "vitest";
import {decide} from "../decide/engine";
import { createStore } from "../gate/store";
import { cases } from "./cases-data";

// The contract suite's cwd (~/Projects) is a bare string in its rows; here the
// prefix must name a REAL existing subdir — `cd <nonexistent> &&` short-circuits
// (resolveCdTarget stats the target) and would auto-allow every row.
const SUB = "sub";
let cwd: string;

beforeAll(() => {
  cwd = fs.mkdtempSync(path.join(os.tmpdir(), "halter-metamorphic-"));
  fs.mkdirSync(path.join(cwd, SUB));
});
afterAll(() => {
  fs.rmSync(cwd, { recursive: true, force: true });
});

// Known-legitimate divergences (cmd → why the prefix changes semantics).
const EXCEPTIONS: Record<string, string> = {
  // `cd sub && ls || cat a || echo ok` = `((cd sub && ls) || cat a) || echo ok`:
  // a cd now sits LEFT of `||`, so `cat a`'s runtime cwd is genuinely
  // ambiguous (old dir if cd/ls failed, sub if ls failed). Halter's ||-model
  // makes such a base unknown → prompt. Conservative, not a bypass — the
  // base row (no cd anywhere) keeps a known base and allows.
  "ls || cat a || echo ok": "cd left of || makes the branch cwd genuinely ambiguous (unknown base → prompt)",
};

describe(`metamorphic: cd ${SUB} && <cmd> keeps the decision kind`, () => {
  it.each(cases.filter((c) => c.decision))("%s", async (c) => {
    const base = await decide({ type: "bash", command: c.cmd, cwd }, createStore());
    const prefixed = await decide({ type: "bash", command: `cd ${SUB} && ${c.cmd}`, cwd }, createStore());
    const baseWhy = "reason" in base ? base.reason : "";
    const prefWhy = "reason" in prefixed ? prefixed.reason : "";
    const ctx = `cd ${SUB} && ${JSON.stringify(c.cmd)}\n  base:     ${base.kind} ${baseWhy}\n  prefixed: ${prefixed.kind} ${prefWhy}`;
    if (EXCEPTIONS[c.cmd]) {
      // Divergence must go toward prompt (more conservative), never allow.
      expect(base.kind, ctx).toBe("auto-allow");
      expect(prefixed.kind, `${ctx}\n  why: ${EXCEPTIONS[c.cmd]}`).toBe("prompt");
    } else {
      expect(prefixed.kind, ctx).toBe(base.kind);
    }
  });
});
