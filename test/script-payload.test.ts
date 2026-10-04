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
import {
  findExecutedScript,
  scriptFilePathInSegment,
  executedScriptPaths,
} from "../analysis/script-payload";
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

  // 2026-10-04 judge.jsonl: `…/node_modules/.bin/vite-node /tmp/hprobe.mts`
  // identified no script, so the packet carried no content and the judge had
  // nothing to judge (defer twice, prompt on a command the floor also could
  // not see the payload of).
  it("identifies the script behind a path-like launcher", async () => {
    fs.writeFileSync(path.join(tmp, "probe.mts"), "console.log('mts payload')\n");
    const s = findExecutedScript(
      await analyze('./node_modules/.bin/vite-node probe.mts "x"'), tmp);
    expect(s?.path).toBe(path.join(tmp, "probe.mts"));
    expect(s?.content).toContain("mts payload");
  });

  it("a Node .mts payload is a script (the extension list must cover it)", async () => {
    fs.writeFileSync(path.join(tmp, "x.mts"), "console.log(1)\n");
    expect(findExecutedScript(await analyze("node x.mts"), tmp)?.path)
      .toBe(path.join(tmp, "x.mts"));
  });
});

describe("scriptFilePathInSegment (D19 — pure, no file read)", () => {
  it("interpreter-run and direct-exec forms resolve against the base", () => {
    expect(scriptFilePathInSegment("python3 job.py", tmp)).toBe(path.join(tmp, "job.py"));
    expect(scriptFilePathInSegment("./job.sh", tmp)).toBe(path.join(tmp, "job.sh"));
    expect(scriptFilePathInSegment("/abs/dir/job.py", tmp)).toBe("/abs/dir/job.py");
  });

  it("flags and non-script tokens are skipped or stop the scan", () => {
    expect(scriptFilePathInSegment("python3 -u job.py", tmp)).toBe(path.join(tmp, "job.py"));
    expect(scriptFilePathInSegment("python3 -m x", tmp)).toBeNull();
    expect(scriptFilePathInSegment("python3 -c 'print(1)'", tmp)).toBeNull();
  });

  it("a path-like launcher does not end the scan; an interpreter's non-script token still does", () => {
    // A path-like first token with no script extension reads as a LAUNCHER,
    // so the payload one token later is identified. The misread direction (a
    // reader invoked by absolute path — `/bin/cat job.py`) costs scrutiny,
    // never grants: the payload is fenced for the judge and D19 only converts
    // an auto-allow into a prompt.
    expect(scriptFilePathInSegment("./node_modules/.bin/vite-node probe.mts", tmp))
      .toBe(path.join(tmp, "probe.mts"));
    expect(scriptFilePathInSegment("./tool run.py", tmp)).toBe(path.join(tmp, "run.py"));
    expect(scriptFilePathInSegment("python3 -m x", tmp)).toBeNull();
  });

  it("computed paths, bare commands, and trusted skill scripts are null", () => {
    expect(scriptFilePathInSegment("python3 $SCRIPT", tmp)).toBeNull();
    expect(scriptFilePathInSegment("ls job.py", tmp)).toBeNull();
    const skill = path.join(os.homedir(), ".pi", "agent", "skills");
    expect(scriptFilePathInSegment(`python3 ${skill}/foo/job.py`, tmp)).toBeNull();
  });
});

describe("executedScriptPaths (D13 floor knowledge)", () => {
  async function analyze(command: string, cwd = tmp) {
    return analyzeCommand(command, cwd);
  }

  it("includes trusted skill scripts — the floor saw them when it trusted them", async () => {
    const skill = path.join(os.homedir(), ".pi", "agent", "skills");
    const a = await analyze(`bash ${skill}/doc-search/scripts/q.sh -P x`);
    expect(executedScriptPaths(a, tmp)).toEqual([`${skill}/doc-search/scripts/q.sh`]);
    // …while the payload view stays null (trusted scripts are never payloads).
    expect(findExecutedScript(a, tmp)).toBeNull();
  });

  it("includes non-trusted scripts and dedupes", async () => {
    const a = await analyze("python3 job.py && python3 job.py");
    expect(executedScriptPaths(a, tmp)).toEqual([path.join(tmp, "job.py")]);
  });

  it("bash -c and computed paths yield nothing", async () => {
    expect(executedScriptPaths(await analyze("bash -c 'echo hi'"), tmp)).toEqual([]);
    expect(executedScriptPaths(await analyze("python3 $SCRIPT"), tmp)).toEqual([]);
  });
});
