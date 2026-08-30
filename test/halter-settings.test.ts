import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import {
  readSettingsFile,
  writeSettings,
  resetSettingsCache,
  HALTER_DEFAULTS,
} from "../halter-settings";

/**
 * halter-settings: single owner of the `halter` namespace in
 * ~/.pi/agent/settings-ext.json (the shared extension settings file).
 * One corrupt policy (backup + defaults), one read path (stat-cached),
 * namespace-scoped merge writes that preserve other extensions' namespaces
 * (the judge section and the decision-log toggle share the namespace).
 * Missing keys are materialized back into the file on first read.
 */
describe("halter-settings", () => {
  let tmp: string;
  let file: string;

  beforeAll(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "halter-settings-"));
    file = path.join(tmp, "settings-ext.json");
  });

  afterAll(() => {
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  beforeEach(() => {
    resetSettingsCache();
    for (const f of [file, file + ".bak"]) {
      try {
        fs.unlinkSync(f);
      } catch {
        /* not created */
      }
    }
  });

  it("missing file → defaults, materialized into the file", () => {
    expect(readSettingsFile(file)).toEqual(HALTER_DEFAULTS);
    const raw = JSON.parse(fs.readFileSync(file, "utf-8"));
    expect(raw.halter).toEqual(HALTER_DEFAULTS);
  });

  it("per-key merge: partial judge object fills in defaults", () => {
    fs.writeFileSync(file, JSON.stringify({ halter: { judge: { thinking: "high" } } }));
    expect(readSettingsFile(file)).toEqual({
      decisionLog: false,
      judge: { enabled: true, provider: null, model: null, thinking: "high", timeoutMs: 8000 },
    });
  });

  it("writeSettings merges a namespace patch and preserves other namespaces", () => {
    fs.writeFileSync(file, JSON.stringify({
      halter: { decisionLog: true, judge: { thinking: "high" } },
      tps: { enabled: false },
    }));
    const out = writeSettings({ decisionLog: false }, file);
    expect(out).toEqual({
      decisionLog: false,
      judge: { enabled: true, provider: null, model: null, thinking: "high", timeoutMs: 8000 },
    });
    const saved = JSON.parse(fs.readFileSync(file, "utf-8"));
    // The judge section survived the toggle write, and so did another
    // extension's namespace.
    expect(saved.halter.judge.thinking).toBe("high");
    expect(saved.tps).toEqual({ enabled: false });
    writeSettings({ judge: { enabled: true } }, file);
    expect(readSettingsFile(file).decisionLog).toBe(false);
  });

  it("unknown namespace keys are preserved (never dropped on materialization)", () => {
    fs.writeFileSync(file, JSON.stringify({ halter: { otherHalterKey: 1 } }));
    expect(readSettingsFile(file).otherHalterKey).toBe(1);
    expect(JSON.parse(fs.readFileSync(file, "utf-8")).halter.otherHalterKey).toBe(1);
  });

  it("corrupt file → defaults + one .bak backup", () => {
    fs.writeFileSync(file, "not json {");
    expect(readSettingsFile(file)).toEqual(HALTER_DEFAULTS);
    expect(fs.existsSync(file + ".bak")).toBe(true);
    expect(fs.readFileSync(file + ".bak", "utf-8")).toBe("not json {");
    // Repeated reads stay stable (the cache prevents re-reading a corrupt file).
    expect(readSettingsFile(file)).toEqual(HALTER_DEFAULTS);
  });

  it("non-object top level is corrupt too", () => {
    fs.writeFileSync(file, JSON.stringify([1, 2, 3]));
    expect(readSettingsFile(file)).toEqual(HALTER_DEFAULTS);
    expect(fs.existsSync(file + ".bak")).toBe(true);
  });

  it("external modification is picked up (stat-keyed invalidation)", () => {
    fs.writeFileSync(file, JSON.stringify({ halter: { decisionLog: true } }));
    expect(readSettingsFile(file).decisionLog).toBe(true);
    fs.writeFileSync(file, JSON.stringify({ halter: { decisionLog: false } }));
    expect(readSettingsFile(file).decisionLog).toBe(false);
  });

  it("read after write sees the merged object without re-reading (cache refreshed)", () => {
    writeSettings({ judge: { enabled: false } }, file);
    // Cache must agree with the write even if mtime granularity is coarse.
    const ns = readSettingsFile(file);
    expect((ns.judge as Record<string, unknown>).enabled).toBe(false);
    expect(ns.decisionLog).toBe(false);
  });
});
