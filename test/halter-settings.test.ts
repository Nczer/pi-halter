import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import {
  readSettingsFile,
  writeSettings,
  resetSettingsCache,
} from "../halter-settings";

/**
 * halter-settings: single owner of ~/.pi/agent/halter.json.
 * One corrupt policy (backup + defaults), one read path (stat-cached),
 * top-level merge writes that preserve unrelated keys (the judge section
 * and the decision-log toggle share the file).
 */
describe("halter-settings", () => {
  let tmp: string;
  let file: string;

  beforeAll(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "halter-settings-"));
    file = path.join(tmp, "halter.json");
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

  it("missing file → {}", () => {
    expect(readSettingsFile(file)).toEqual({});
  });

  it("writeSettings merges a top-level patch and preserves unrelated keys", () => {
    fs.writeFileSync(file, JSON.stringify({ decisionLogEnabled: true, judge: { thinking: "high" } }));
    const out = writeSettings({ decisionLogEnabled: false }, file);
    expect(out).toEqual({ decisionLogEnabled: false, judge: { thinking: "high" } });
    // The judge section survived the toggle write (and vice versa).
    expect(readSettingsFile(file)).toEqual(out);
    writeSettings({ judge: { enabled: true } }, file);
    expect(readSettingsFile(file).decisionLogEnabled).toBe(false);
  });

  it("corrupt file → {} + one .bak backup", () => {
    fs.writeFileSync(file, "not json {");
    expect(readSettingsFile(file)).toEqual({});
    expect(fs.existsSync(file + ".bak")).toBe(true);
    expect(fs.readFileSync(file + ".bak", "utf-8")).toBe("not json {");
    // Repeated reads stay stable (the cache prevents re-reading a corrupt file).
    expect(readSettingsFile(file)).toEqual({});
  });

  it("non-object top level is corrupt too", () => {
    fs.writeFileSync(file, JSON.stringify([1, 2, 3]));
    expect(readSettingsFile(file)).toEqual({});
    expect(fs.existsSync(file + ".bak")).toBe(true);
  });

  it("external modification is picked up (stat-keyed invalidation)", () => {
    fs.writeFileSync(file, JSON.stringify({ a: 1 }));
    expect(readSettingsFile(file)).toEqual({ a: 1 });
    fs.writeFileSync(file, JSON.stringify({ a: 2, b: 3 }));
    expect(readSettingsFile(file)).toEqual({ a: 2, b: 3 });
  });

  it("read after write sees the merged object without re-reading (cache refreshed)", () => {
    fs.writeFileSync(file, JSON.stringify({ a: 1 }));
    writeSettings({ b: 2 }, file);
    // Cache must agree with the write even if mtime granularity is coarse.
    expect(readSettingsFile(file)).toEqual({ a: 1, b: 2 });
  });
});
