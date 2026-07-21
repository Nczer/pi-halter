import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import { handleFile } from "../handlers";
import { store } from "../store";

const cwd = process.cwd();

function makeEditEvent(filePath: string, oldText = "foo", newText = "bar") {
  return {
    toolName: "edit",
    input: { path: filePath, edits: [{ oldText, newText }] },
  } as any;
}

function makeCtx() {
  return { cwd } as any;
}

/**
 * Regression: edit pre-validation must NOT read file content for credential paths
 * (denied/warned) before the permission gate decides. Reading secrets before the
 * gate is an ordering bug in a halter extension.
 */
describe("handleFile edit pre-validation security", () => {
  let readSpy: ReturnType<typeof vi.spyOn>;
  let existsSpy: ReturnType<typeof vi.spyOn>;
  let statSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    // Isolate from any state left by other tests.
    store.reset();
    existsSpy = vi.spyOn(fs, "existsSync").mockReturnValue(true);
    statSpy = vi.spyOn(fs, "statSync").mockReturnValue({ size: 100 } as fs.Stats);
    readSpy = vi.spyOn(fs, "readFileSync").mockReturnValue("some content that has no match");
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("does not read a denied path (~/.ssh) before the gate", async () => {
    const result = await handleFile(makeEditEvent("~/.ssh/id_rsa"), makeCtx());
    // No file content read prior to the permission decision.
    expect(readSpy).not.toHaveBeenCalled();
    expect(existsSpy).not.toHaveBeenCalled();
    // Gate hard-blocks denied paths without UI.
    expect(result).toEqual({ block: true, reason: expect.stringContaining("denied path") });
  });

  it("does not read a warned path (.env) before the gate", async () => {
    const result = await handleFile(makeEditEvent(".env"), makeCtx());
    expect(readSpy).not.toHaveBeenCalled();
    expect(existsSpy).not.toHaveBeenCalled();
    // No UI → gate auto-blocks the prompt for the warned path. No read happened first.
    expect(result).toEqual({ block: true, reason: expect.stringContaining("no UI") });
  });

  it("still pre-validates ordinary inside-cwd paths (reads to check edit viability)", async () => {
    // A normal project file: pre-validation reads it to decide whether to skip a
    // useless prompt. This confirms the guard only suppresses credential paths.
    await handleFile(makeEditEvent("src/index.ts"), makeCtx());
    expect(readSpy).toHaveBeenCalled();
  });

  it("skips prompt when oldText === newText (no-op edit will fail)", async () => {
    readSpy.mockReturnValue("hello world");
    const result = await handleFile(
      makeEditEvent("src/index.ts", "world", "world"),
      makeCtx(),
    );
    // Should return undefined (skip prompt) because edit is a no-op
    expect(result).toBeUndefined();
  });

  it("skips prompt when oldText has zero matches in file", async () => {
    readSpy.mockReturnValue("hello world");
    const result = await handleFile(
      makeEditEvent("src/index.ts", "nonexistent", "replacement"),
      makeCtx(),
    );
    expect(result).toBeUndefined();
  });

  it("skips prompt when oldText has multiple matches in file", async () => {
    readSpy.mockReturnValue("foo bar foo baz foo");
    const result = await handleFile(
      makeEditEvent("src/index.ts", "foo", "qux"),
      makeCtx(),
    );
    expect(result).toBeUndefined();
  });

  it("skips prompt when edits array is empty", async () => {
    const event = {
      toolName: "edit",
      input: { path: "src/index.ts", edits: [] },
    } as any;
    const result = await handleFile(event, makeCtx());
    expect(result).toBeUndefined();
  });

  it("skips prompt when edits array is null/undefined", async () => {
    const event = {
      toolName: "edit",
      input: { path: "src/index.ts", edits: null },
    } as any;
    const result = await handleFile(event, makeCtx());
    expect(result).toBeUndefined();
  });

  it("skips prompt when edits have invalid entries (missing oldText)", async () => {
    const event = {
      toolName: "edit",
      input: { path: "src/index.ts", edits: [{ newText: "bar" }] },
    } as any;
    const result = await handleFile(event, makeCtx());
    expect(result).toBeUndefined();
  });

  it("skips prompt when file does not exist", async () => {
    // statSync throws ENOENT for missing files → handler catches and returns early
    // before ever reading content.
    statSpy.mockImplementation(() => { throw new Error("ENOENT"); });
    const result = await handleFile(
      makeEditEvent("src/missing.ts"),
      makeCtx(),
    );
    expect(result).toBeUndefined();
    expect(readSpy).not.toHaveBeenCalled();
  });

  it("skips pre-validation for files larger than 1 MB (still prompts via gate)", async () => {
    // Large file: size cap avoids a full blocking read; the edit proceeds to the
    // gate instead of being pre-validated. No UI in this ctx → gate auto-blocks.
    statSpy.mockReturnValue({ size: 2 * 1024 * 1024 } as fs.Stats);
    const result = await handleFile(
      makeEditEvent("src/big.ts"),
      makeCtx(),
    );
    expect(readSpy).not.toHaveBeenCalled();
    expect(result).toEqual({ block: true, reason: expect.stringContaining("no UI") });
  });

  it("skips prompt when file read throws", async () => {
    existsSpy.mockReturnValue(true);
    readSpy.mockImplementation(() => { throw new Error("Permission denied"); });
    const result = await handleFile(
      makeEditEvent("src/index.ts"),
      makeCtx(),
    );
    expect(result).toBeUndefined();
  });
});
