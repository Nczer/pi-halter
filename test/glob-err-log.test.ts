/**
 * Glob-verify error ledger (config/logging.ts) — on by default, on-signal
 * only (a healthy run writes nothing). Pinned here: the line shape, the
 * shared /halter-ledger-log toggle (persisted like the decision log, module
 * state driven through setLedgerLogEnabled with a tmp settings file), and
 * the HALTER_GLOBERR_LOG seam (wins over the toggle; vitest hermeticity).
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it, beforeAll, afterAll, beforeEach, afterEach } from "vitest";
import {
  logGlobVerifyError,
  isLedgerLogEnabled,
  setLedgerLogEnabled,
  resolveGlobErrLogPath,
  LEDGER_LOG_ENABLED,
} from "../config/logging";

describe("glob-err ledger (logGlobVerifyError)", () => {
  let tmp: string;
  let logFile: string;
  let settingsFile: string;
  const savedEnv = process.env.HALTER_GLOBERR_LOG;

  beforeAll(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "halter-globerr-"));
    logFile = path.join(tmp, "glob-err.jsonl");
    settingsFile = path.join(tmp, "halter.json");
  });
  afterAll(() => {
    fs.rmSync(tmp, { recursive: true, force: true });
  });
  beforeEach(() => {
    process.env.HALTER_GLOBERR_LOG = logFile;
  });
  afterEach(() => {
    setLedgerLogEnabled(true, settingsFile); // restore the on-by-default module state
    if (savedEnv === undefined) delete process.env.HALTER_GLOBERR_LOG;
    else process.env.HALTER_GLOBERR_LOG = savedEnv;
    try {
      fs.unlinkSync(logFile);
    } catch {
      /* not created */
    }
  });

  it("writes one line per failed probe (ts, pattern, error name+message, cwd)", () => {
    logGlobVerifyError("a/*.ts", new Error("boom"), "/c");
    const [e] = fs.readFileSync(logFile, "utf8").trim().split("\n").map((l) => JSON.parse(l));
    expect(e).toMatchObject({ pattern: "a/*.ts", name: "Error", message: "boom", cwd: "/c" });
    expect(new Date(e.ts).toString()).not.toBe("Invalid Date");
  });

  it("truncates pattern/message/cwd to 200 (log economy)", () => {
    logGlobVerifyError("x".repeat(300), new Error("y".repeat(300)), "z".repeat(300));
    const [e] = fs.readFileSync(logFile, "utf8").trim().split("\n").map((l) => JSON.parse(l));
    expect(e.pattern).toHaveLength(200);
    expect(e.message).toHaveLength(200);
    expect(e.cwd).toHaveLength(200);
  });

  it("never throws when the log path is impossible", () => {
    const blocker = path.join(tmp, "blocker");
    fs.writeFileSync(blocker, "i am a file");
    process.env.HALTER_GLOBERR_LOG = path.join(blocker, "sub", "glob-err.jsonl");
    expect(() => logGlobVerifyError("a/*.ts", new Error("boom"), "/c")).not.toThrow();
  });

  it("resolveGlobErrLogPath: toggle off → null (no env), on → default file, seam wins", () => {
    const orig = process.env.HALTER_GLOBERR_LOG;
    try {
      delete process.env.HALTER_GLOBERR_LOG;
      setLedgerLogEnabled(false, settingsFile);
      expect(isLedgerLogEnabled()).toBe(false);
      expect(resolveGlobErrLogPath()).toBeNull();
      logGlobVerifyError("a/*.ts", new Error("boom"), "/c"); // must write nowhere
      setLedgerLogEnabled(true, settingsFile);
      expect(resolveGlobErrLogPath()).toContain(path.join("halter", ".log", "glob-err.jsonl"));
      // env seam still wins with the toggle off (test hermeticity)
      process.env.HALTER_GLOBERR_LOG = logFile;
      setLedgerLogEnabled(false, settingsFile);
      logGlobVerifyError("a/*.ts", new Error("boom"), "/c");
      expect(fs.existsSync(logFile)).toBe(true);
    } finally {
      if (orig === undefined) delete process.env.HALTER_GLOBERR_LOG;
      else process.env.HALTER_GLOBERR_LOG = orig;
    }
  });

  it("stays silent under HALTER_GLOBERR_LOG=off (test hermeticity guard)", () => {
    process.env.HALTER_GLOBERR_LOG = "off";
    setLedgerLogEnabled(true, settingsFile);
    logGlobVerifyError("a/*.ts", new Error("boom"), "/c");
    expect(fs.existsSync(logFile)).toBe(false);
  });

  it("missing settings key falls back to the compile-time default (on)", () => {
    expect(LEDGER_LOG_ENABLED).toBe(true);
  });
});
