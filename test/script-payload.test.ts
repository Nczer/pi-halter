/**
 * script-payload.ts — identification of the local script a command
 * executes: interpreter/direct-exec forms, effective-cwd resolution, and
 * the exclusions (trusted skill scripts, computed paths, non-script
 * extensions, missing files).
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it, beforeAll, afterAll, beforeEach } from "vitest";
import { findExecutedScript } from "../analysis/script-payload";
import { analyzeCommand } from "../analysis/command-analysis";

let tmp: string;
beforeAll(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "script-payload-"));
});
afterAll(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});
beforeEach(() => {
  for (const f of fs.readdirSync(tmp)) {
    fs.rmSync(path.join(tmp, f), { recursive: true, force: true });
  }
});

describe("findExecutedScript", () => {
  async function analyze(command: string, cwd = tmp) {
    return analyzeCommand(command, cwd);
  }

  it("includes an interpreter-run local script", async () => {
    fs.writeFileSync(path.join(tmp, "job.py"), "print('hello from job')\n");
    const s = findExecutedScript(await analyze("python3 job.py"), tmp);
    expect(s?.path).toBe(path.join(tmp, "job.py"));
    expect(s?.content).toContain("hello from job");
  });

  it("includes a directly-executed local script", async () => {
    fs.writeFileSync(path.join(tmp, "job.sh"), "#!/bin/sh\necho hi\n");
    const s = findExecutedScript(await analyze("./job.sh"), tmp);
    expect(s?.path).toBe(path.join(tmp, "job.sh"));
    expect(s?.content).toContain("echo hi");
  });

  it("resolves the script against the effective cwd after a cd", async () => {
    const sub = path.join(tmp, "sub");
    fs.mkdirSync(sub);
    fs.writeFileSync(path.join(sub, "job.py"), "print('nested')\n");
    const s = findExecutedScript(await analyze(`cd ${sub} && python3 job.py`), tmp);
    expect(s?.path).toBe(path.join(sub, "job.py"));
  });

  it("returns null for bash -c (no resolvable file)", async () => {
    expect(findExecutedScript(await analyze("bash -c 'echo hi'"), tmp)).toBeNull();
  });

  it("returns null for computed script paths", async () => {
    expect(findExecutedScript(await analyze("python3 $SCRIPT"), tmp)).toBeNull();
  });

  it("returns null for executables without a script extension", async () => {
    fs.writeFileSync(path.join(tmp, "tool"), "not a script\n");
    expect(findExecutedScript(await analyze("./tool"), tmp)).toBeNull();
  });

  it("returns null when the file does not exist", async () => {
    expect(findExecutedScript(await analyze("python3 missing.py"), tmp)).toBeNull();
  });
});
