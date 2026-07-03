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

  beforeEach(() => {
    // Isolate from any state left by other tests.
    store.reset();
    existsSpy = vi.spyOn(fs, "existsSync").mockReturnValue(true);
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
    expect(existsSpy).toHaveBeenCalled();
    expect(readSpy).toHaveBeenCalled();
  });
});
