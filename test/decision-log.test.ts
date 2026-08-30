/**
 * JSONL decision log (decision-log.ts, wired into gate()).
 *
 * The log is the blast-radius measurement: one line per gated tool call.
 * Tests run against an env-redirected path (logging is off by default via
 * ~/.pi/agent/settings-ext.json, which the tests never touch — the toggle state is
 * driven through setDecisionLogEnabled with a tmp settings file); the
 * off-by-default toggle, settings round-trip, rotation, and the never-throw
 * guarantee are pinned here.
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it, beforeAll, afterAll, beforeEach, afterEach } from "vitest";
import { gate } from "../gate";
import { createStore } from "../store";
import {
  logDecision,
  resolveLogPath,
  readToggleSetting,
  writeToggleSetting,
  setDecisionLogEnabled,
  isDecisionLogEnabled,
  logUnresolved,
  MAX_LOG_BYTES,
  DEFAULT_LOG_FILE,
  type DecisionLogEntry,
} from "../decision-log";
import { DECISION_LOG_ENABLED } from "../config/logging";
import type { BashRequest, Decision, FileRequest, McpRequest } from "../decision-engine";

const noUiCtx = { hasUI: false } as never;
const noReject = (() => {
  throw new Error("onReject should not be called with hasUI=false");
}) as never;

function lines(file: string): DecisionLogEntry[] {
  return fs
    .readFileSync(file, "utf8")
    .trim()
    .split("\n")
    .filter(Boolean)
    .map((l) => JSON.parse(l));
}

describe("decision log", () => {
  let tmp: string;
  let logFile: string;
  let settingsFile: string;
  const savedEnv = process.env.HALTER_DECISION_LOG;

  beforeAll(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "halter-log-"));
    logFile = path.join(tmp, "decisions.jsonl");
    settingsFile = path.join(tmp, "halter.json");
  });
  afterAll(() => {
    fs.rmSync(tmp, { recursive: true, force: true });
  });
  beforeEach(() => {
    process.env.HALTER_DECISION_LOG = logFile;
  });
  afterEach(() => {
    if (savedEnv === undefined) delete process.env.HALTER_DECISION_LOG;
    else process.env.HALTER_DECISION_LOG = savedEnv;
    for (const f of [logFile, logFile + ".1"]) {
      try {
        fs.unlinkSync(f);
      } catch {
        /* not created */
      }
    }
  });

  it("logs an auto-allow bash decision", async () => {
    const result = await gate({ type: "bash", command: "ls", cwd: tmp } as BashRequest, noUiCtx, createStore(), noReject);
    expect(result).toBeUndefined();
    const [entry] = lines(logFile);
    expect(entry).toMatchObject({ tool: "bash", kind: "auto-allow", reason: null, target: "ls", cwd: tmp });
    expect(new Date(entry.ts).toString()).not.toBe("Invalid Date");
  });

  it("writes the dsp mode tag when passed; untagged lines carry no mode key", () => {
    // The dspa judge auto-allow line shape (gate.ts): auto-allow + audit reason + tag.
    logDecision(
      { type: "bash", command: "make test", cwd: tmp } as BashRequest,
      { kind: "auto-allow", reason: "dspa: judge approved (m-test)" },
      "dspa",
    );
    logDecision({ type: "bash", command: "pwd", cwd: tmp } as BashRequest, { kind: "auto-allow" });
    const [tagged, plain] = lines(logFile);
    expect(tagged).toMatchObject({ kind: "auto-allow", mode: "dspa", reason: "dspa: judge approved (m-test)" });
    expect(plain.mode).toBeUndefined();
    expect("mode" in plain).toBe(false);
  });

  it("writes the dspa stop-tag on prompt fall-throughs; absent when omitted", () => {
    const filePrompt = {
      kind: "prompt",
      promptData: {
        type: "file",
        action: "Write",
        filePath: "x.txt",
        resolved: "/x/x.txt",
        cwd: tmp,
        outsideDir: null,
        isWriteOp: true,
        warnedRule: null,
        symlinkHint: null,
        exists: false,
      },
    } as Decision;
    logDecision(
      { type: "bash", command: "make test", cwd: tmp } as BashRequest,
      filePrompt,
      "dspa",
      "gate: unsafe pattern (obfuscation/subshell/redirect)",
    );
    logDecision(
      { type: "bash", command: "make test", cwd: tmp } as BashRequest,
      filePrompt,
      "dspa",
      "judge: declined",
    );
    logDecision({ type: "bash", command: "pwd", cwd: tmp } as BashRequest, { kind: "auto-allow" });
    const [gateStop, judgeStop, plain] = lines(logFile);
    expect(gateStop).toMatchObject({
      kind: "prompt",
      mode: "dspa",
      dspa: "gate: unsafe pattern (obfuscation/subshell/redirect)",
    });
    expect(judgeStop.dspa).toBe("judge: declined");
    expect(plain.dspa).toBeUndefined();
    expect("dspa" in plain).toBe(false);
  });

  it("logs the LLM reject explanation as judgeDeny; absent when omitted", () => {
    const filePrompt = {
      kind: "prompt",
      promptData: {
        type: "file",
        action: "Write",
        filePath: "x.txt",
        resolved: "/x/x.txt",
        cwd: tmp,
        outsideDir: null,
        isWriteOp: true,
        warnedRule: null,
        symlinkHint: null,
        exists: false,
      },
    } as Decision;
    logDecision(
      { type: "bash", command: "make test", cwd: tmp } as BashRequest,
      filePrompt,
      "dspa",
      "judge: declined (stage 2)",
      "wipes the build output the user asked to keep",
    );
    logDecision(
      { type: "bash", command: "make test", cwd: tmp } as BashRequest,
      filePrompt,
      "dspa",
      "judge: declined (stage 2)",
    );
    const [withDeny, withoutDeny] = lines(logFile);
    expect(withDeny).toMatchObject({
      kind: "prompt",
      mode: "dspa",
      dspa: "judge: declined (stage 2)",
      judgeDeny: "wipes the build output the user asked to keep",
    });
    expect(withoutDeny.judgeDeny).toBeUndefined();
    expect("judgeDeny" in withoutDeny).toBe(false);
  });

  it("logs the prompted directory for file prompts (path-resolver debug)", async () => {
    // Inside cwd: the "Always (path)" dir is the resolved path's parent.
    await gate(
      { type: "file", toolName: "write", filePath: "src/a/b.txt", cwd: "/home/u/project", resolvedPath: "/home/u/project/src/a/b.txt" } as FileRequest,
      noUiCtx, createStore(), noReject,
    );
    // Outside cwd: the outside dir (also the resolved path's parent).
    await gate({ type: "file", toolName: "read", filePath: "/etc/passwd", cwd: tmp } as FileRequest, noUiCtx, createStore(), noReject);
    // Root file: the prompt offers the file, not a dir → no promptDir.
    await gate({ type: "file", toolName: "write", filePath: "/top.txt", cwd: tmp } as FileRequest, noUiCtx, createStore(), noReject);
    const [inside, outside, root] = lines(logFile);
    expect(inside).toMatchObject({ tool: "file", kind: "prompt", promptDir: "/home/u/project/src/a" });
    expect(outside).toMatchObject({ tool: "file", kind: "prompt", promptDir: "/etc" });
    expect(root.promptDir).toBeUndefined();
    expect("promptDir" in root).toBe(false);
  });

  it("logs a block decision with the reason", async () => {
    await gate({ type: "bash", command: "cat .ssh/id_rsa", cwd: tmp } as BashRequest, noUiCtx, createStore(), noReject);
    const [entry] = lines(logFile);
    expect(entry.kind).toBe("block");
    expect(entry.reason).toContain(".ssh");
  });

  it("logs a prompt decision with a one-line why (and gate blocks without UI)", async () => {
    const result = await gate({ type: "bash", command: "cat /etc/passwd", cwd: tmp } as BashRequest, noUiCtx, createStore(), noReject);
    expect(result).toMatchObject({ block: true });
    const [entry] = lines(logFile);
    expect(entry.kind).toBe("prompt");
    expect(typeof entry.reason).toBe("string");
    expect(entry.reason?.length).toBeGreaterThan(0);
  });

  it("names the cwd-bound identity for relative tools with empty signatures", async () => {
    // Real log shape: a relative tool whose basename IS allowlisted (tsc —
    // so no prompt signature) + a pipe (needsCmd) + outside base (the
    // prompt actually fires on the path, command approval has no sig).
    await gate({ type: "bash", command: "cd /etc && ./node_modules/.bin/tsc --noEmit index.ts | head", cwd: tmp } as BashRequest, noUiCtx, createStore(), noReject);
    const [entry] = lines(logFile);
    expect(entry.kind).toBe("prompt");
    expect(entry.reason).toContain("./node_modules/.bin/tsc");
    expect(entry.reason).toContain("(unlisted)");
  });

  it("logs file and mcp decisions with their target shapes", async () => {
    await gate({ type: "file", toolName: "read", filePath: "/etc/passwd", cwd: tmp } as FileRequest, noUiCtx, createStore(), noReject);
    const req: McpRequest = { type: "mcp", server: "exa", tool: "search" };
    await gate(req, noUiCtx, createStore(), noReject);
    const [fileEntry, mcpEntry] = lines(logFile);
    expect(fileEntry).toMatchObject({ tool: "file", target: "/etc/passwd", cwd: tmp });
    expect(mcpEntry).toMatchObject({ tool: "mcp", target: "exa/search", kind: "prompt", reason: "mcp call" });
    expect(mcpEntry.cwd).toBeUndefined();
  });

  it("truncates long bash commands", async () => {
    const cmd = "echo " + "x".repeat(2000);
    await gate({ type: "bash", command: cmd, cwd: tmp } as BashRequest, noUiCtx, createStore(), noReject);
    const [entry] = lines(logFile);
    expect(entry.target.length).toBeLessThanOrEqual(1000);
  });

  it("HALTER_DECISION_LOG=off writes nothing", async () => {
    process.env.HALTER_DECISION_LOG = "off";
    await gate({ type: "bash", command: "ls", cwd: tmp } as BashRequest, noUiCtx, createStore(), noReject);
    expect(fs.existsSync(logFile)).toBe(false);
  });

  it("no env override: resolution follows the persisted toggle state", () => {
    delete process.env.HALTER_DECISION_LOG;
    expect(DEFAULT_LOG_FILE).toContain(path.join("halter", ".log"));
    const orig = isDecisionLogEnabled();
    try {
      setDecisionLogEnabled(false, settingsFile);
      expect(resolveLogPath()).toBeNull();
      setDecisionLogEnabled(true, settingsFile);
      expect(resolveLogPath()).toBe(DEFAULT_LOG_FILE);
    } finally {
      setDecisionLogEnabled(orig, settingsFile);
    }
  });

  it("env path override enables logging even with the toggle off", () => {
    process.env.HALTER_DECISION_LOG = logFile;
    expect(resolveLogPath()).toBe(logFile);
  });

  it("settings round-trip: write → read, merge with other keys, missing file → default", () => {
    fs.writeFileSync(settingsFile, JSON.stringify({ halter: { otherHalterKey: 1 } }) + "\n");
    writeToggleSetting(true, settingsFile);
    expect(readToggleSetting(settingsFile)).toBe(true);
    const saved = JSON.parse(fs.readFileSync(settingsFile, "utf-8"));
    expect(saved.halter.otherHalterKey).toBe(1);
    expect(saved.halter.decisionLog).toBe(true);
    expect(readToggleSetting(path.join(tmp, "missing.json"))).toBe(DECISION_LOG_ENABLED);
  });

  it("never throws when the log path is impossible", () => {
    const blocker = path.join(tmp, "blocker");
    fs.writeFileSync(blocker, "i am a file");
    process.env.HALTER_DECISION_LOG = path.join(blocker, "sub", "decisions.jsonl");
    expect(() =>
      logDecision({ type: "bash", command: "ls", cwd: tmp } as BashRequest, { kind: "auto-allow" }),
    ).not.toThrow();
  });

  it("rotates to .1 when the size limit is exceeded", async () => {
    fs.writeFileSync(logFile, "y".repeat(MAX_LOG_BYTES));
    await gate({ type: "bash", command: "ls", cwd: tmp } as BashRequest, noUiCtx, createStore(), noReject);
    expect(fs.existsSync(logFile + ".1")).toBe(true);
    expect(fs.statSync(logFile + ".1").size).toBe(MAX_LOG_BYTES);
    const [entry] = lines(logFile);
    expect(entry.kind).toBe("auto-allow");
  });
});

describe("unresolved-token log (logUnresolved)", () => {
  let tmp: string;
  let unresolvedFile: string;
  let settingsFile: string;
  const savedEnv = process.env.HALTER_UNRESOLVED_LOG;

  beforeAll(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "halter-unres-"));
    unresolvedFile = path.join(tmp, "unresolved.jsonl");
    settingsFile = path.join(tmp, "halter.json");
  });
  afterAll(() => {
    fs.rmSync(tmp, { recursive: true, force: true });
  });
  beforeEach(() => {
    process.env.HALTER_UNRESOLVED_LOG = unresolvedFile;
    // Anything but "off" — the decision log is redirected to a scratch path
    // so the hermeticity guard does not disable the unresolved log.
    process.env.HALTER_DECISION_LOG = path.join(tmp, "decisions.jsonl");
    setDecisionLogEnabled(true, settingsFile);
  });
  afterEach(() => {
    setDecisionLogEnabled(false, settingsFile);
    if (savedEnv === undefined) delete process.env.HALTER_UNRESOLVED_LOG;
    else process.env.HALTER_UNRESOLVED_LOG = savedEnv;
    process.env.HALTER_DECISION_LOG = "off";
    for (const f of [unresolvedFile, unresolvedFile + ".1"]) {
      try {
        fs.unlinkSync(f);
      } catch {
        /* not created */
      }
    }
  });

  it("writes one entry per call (ts, full token, cmd truncated to 200)", () => {
    logUnresolved({
      cmd: "x".repeat(300),
      cwd: "/c",
      token: "/x/$e/f",
      llm: ["/a"],
      persisted: true,
      outcome: "prompted",
      decision: "yes",
    });
    const [entry] = fs.readFileSync(unresolvedFile, "utf8").trim().split("\n").map((l) => JSON.parse(l));
    expect(entry).toMatchObject({
      cmd: "x".repeat(200),
      cwd: "/c",
      token: "/x/$e/f",
      llm: ["/a"],
      persisted: true,
      outcome: "prompted",
      decision: "yes",
    });
    expect(new Date(entry.ts).toString()).not.toBe("Invalid Date");
  });

  it("omits the llm key when the resolver found nothing", () => {
    logUnresolved({ cmd: "ls", cwd: "/c", token: "$FOO", persisted: false, outcome: "gate-stop" });
    const entry = JSON.parse(fs.readFileSync(unresolvedFile, "utf8").trim());
    expect("llm" in entry).toBe(false);
    expect(entry.outcome).toBe("gate-stop");
  });

  it("stays silent when the toggle is off", () => {
    setDecisionLogEnabled(false, settingsFile);
    logUnresolved({ cmd: "ls", cwd: "/c", token: "$FOO", persisted: false, outcome: "prompted" });
    expect(fs.existsSync(unresolvedFile)).toBe(false);
  });

  it("stays silent under HALTER_DECISION_LOG=off (test hermeticity guard)", () => {
    process.env.HALTER_DECISION_LOG = "off";
    logUnresolved({ cmd: "ls", cwd: "/c", token: "$FOO", persisted: false, outcome: "prompted" });
    expect(fs.existsSync(unresolvedFile)).toBe(false);
  });

  it("never throws when the log path is impossible", () => {
    const blocker = path.join(tmp, "blocker");
    fs.writeFileSync(blocker, "i am a file");
    process.env.HALTER_UNRESOLVED_LOG = path.join(blocker, "sub", "unresolved.jsonl");
    expect(() =>
      logUnresolved({ cmd: "ls", cwd: "/c", token: "$FOO", persisted: false, outcome: "auto-allowed" }),
    ).not.toThrow();
  });
});
