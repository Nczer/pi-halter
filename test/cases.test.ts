/**
 * Comprehensive test cases for the halter extension.
 *
 * Agreed principles:
 *   1. Write → prompt (mkdir/touch are safe creation, auto-allow)
 *   2. Read inside cwd → auto-allow
 *   3. Code execution → prompt (unless trusted script)
 *   4. Outside cwd → prompt (first time), remembered → auto-allow
 *   5. Unsafe patterns → always prompt (DSP bypasses)
 */

import path from "node:path";
import os from "node:os";
import fs from "node:fs";
import { describe, expect, it, beforeAll, afterAll } from "vitest";
import { analyzeCommand } from "../analysis/command-analysis";
import {decide} from "../decide/engine";
import { createStore } from "../gate/store";
import { cases } from "./cases-data";
import { createContractCwd, removeContractCwd } from "./hermetic-cwd";

let cwd: string;

beforeAll(() => {
  cwd = createContractCwd();
});
afterAll(() => removeContractCwd(cwd));


// Bare-name symlink escaping cwd → prompt (the checkBareSymlinkTokens `warned`
// path — pinned end-to-end; perm #645 class). Uses a real tmpdir fixture so
// the lstat probe in the gate sees the actual link.
describe("bare-token symlink escape (end-to-end decision)", () => {
  let tmp: string;
  beforeAll(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "halter-e2e-sym-"));
    fs.symlinkSync("/etc/hostname", path.join(tmp, "etc-link"));
  });
  afterAll(() => {
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  it("cat <bare symlink → outside cwd> prompts (never silently allows)", async () => {
    const decision = await decide({ type: "bash", command: "cat etc-link", cwd: tmp }, createStore());
    expect(decision.kind).toBe("prompt");
  });

  it("regular bare file inside cwd still auto-allows", async () => {
    fs.writeFileSync(path.join(tmp, "plain.txt"), "x");
    const decision = await decide({ type: "bash", command: "cat plain.txt", cwd: tmp }, createStore());
    expect(decision.kind).toBe("auto-allow");
  });

  it("cat <glob> reaching a bare escaping symlink prompts (never silently allows)", async () => {
    // The shipped-symlink attack through a natural glob: the repo carries a
    // benign-named link to an outside file and the agent's `cat l*` would
    // read the target (glob expansion happens at bash runtime, so the name
    // decode check alone cannot see it).
    fs.writeFileSync(path.join(tmp, "readme.md"), "x");
    fs.symlinkSync("/etc/hostname", path.join(tmp, "lnk-benign"));
    const decision = await decide({ type: "bash", command: "cat l*", cwd: tmp }, createStore());
    expect(decision.kind).toBe("prompt");
  });
});

// Loop in-list under an allowed root (/tmp): the values are statically
// inside only if EVERY glob match really lives under the root (realpath-
// verified). This row uses a PRIVATE tmpdir instead of the shared /tmp top
// level: the static row globbed /tmp/* while the other ~44 test files create
// and delete tmpdirs there in parallel, fs.globSync raced a mid-scan
// deletion (ENOENT), the verification — correctly — failed closed, and the
// auto-allow flipped to prompt (intermittent suite flake, 2026-08-31).
describe("loop in-list under allowed root (hermetic fixture)", () => {
  let tmp: string;
  beforeAll(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "halter-allowed-root-"));
    fs.mkdirSync(path.join(tmp, "a"));
    fs.mkdirSync(path.join(tmp, "b"));
  });
  afterAll(() => {
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  it("glob in-list under the allowed root stays auto-allow (values statically inside — log FP)", async () => {
    const cmd = `for d in ${tmp}/*/; do echo "== $d"; ls "$d" | head -5; done`;
    const store = createStore();
    const analysis = await analyzeCommand(cmd, cwd);
    const decision = await decide({ type: "bash", command: cmd, cwd }, store);
    expect(analysis.safety.isSimple).toBe(true);
    expect(analysis.safety.hasUnsafePattern).toBe(false);
    expect(decision.kind).toBe("auto-allow");
  });
});

// ─── Run tests ───

describe.each(cases)("$desc", ({ cmd, simple: expSimple, unsafe: expUnsafe, decision: expDecision }) => {
  it(`simple=${expSimple}, unsafe=${expUnsafe}${expDecision ? `, decision=${expDecision}` : ""}`, async () => {
    const store = createStore();
    const analysis = await analyzeCommand(cmd, cwd);
    const decision = await decide({ type: "bash", command: cmd, cwd }, store);

    expect(analysis.safety.isSimple).toBe(expSimple);
    expect(analysis.safety.hasUnsafePattern).toBe(expUnsafe);
    if (expDecision) {
      expect(decision.kind).toBe(expDecision);
    }
  });
});
