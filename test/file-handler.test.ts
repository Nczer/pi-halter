import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { handleFile, buildEditAfterView } from "../handlers";
import { store, createStore } from "../gate/store";
import { decideFile } from "../decide/file-policy";

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

  it("pre-validates inside-cwd edits (prompt decision): skips prompt when the edit will fail", async () => {
    // Inside-cwd write decisions are prompts, but a guaranteed-fail edit
    // (no oldText match) must not prompt — it passes through and the agent
    // gets the normal tool error.
    readSpy.mockReturnValue("hello world");
    const result = await handleFile(
      makeEditEvent("src/index.ts", "nonexistent", "replacement"),
      makeCtx(),
    );
    expect(readSpy).toHaveBeenCalled();
    expect(result).toBeUndefined();
  });

  it("still prompts inside-cwd edits when the edit would succeed", async () => {
    readSpy.mockReturnValue("hello world");
    const result = await handleFile(
      makeEditEvent("src/index.ts", "world", "there"),
      makeCtx(),
    );
    expect(readSpy).toHaveBeenCalled();
    // No UI → gate auto-blocks the prompt.
    expect(result).toEqual({ block: true, reason: expect.stringContaining("no UI") });
  });

  it("skips prompt for outside-cwd edits that will fail", async () => {
    // The user-reported case: an edit to an outside-cwd file whose oldText
    // can't match must not prompt — the tool call just fails with an error.
    readSpy.mockReturnValue("line one\nline two");
    const result = await handleFile(
      makeEditEvent("/some/outside/project/file.ts", "nope", "bar"),
      makeCtx(),
    );
    expect(readSpy).toHaveBeenCalled();
    expect(result).toBeUndefined();
  });

  it("does NOT pre-validate warned paths (.env) even when the edit will fail", async () => {
    // A content oracle on a secret must not exist: prompt-vs-silent-failure
    // would reveal whether the guessed oldText occurs exactly once in the file.
    const result = await handleFile(makeEditEvent(".env", "nope", "bar"), makeCtx());
    expect(readSpy).not.toHaveBeenCalled();
    // No UI → gate auto-blocks the prompt. No read happened first.
    expect(result).toEqual({ block: true, reason: expect.stringContaining("no UI") });
  });

  it("pre-validates edits to auto-allow paths (e.g. /tmp)", async () => {
    // /tmp is an allowed write path → the edit decision is auto-allow →
    // pre-validation may read it to skip a useless prompt.
    const result = await handleFile(makeEditEvent("/tmp/out.ts"), makeCtx());
    expect(readSpy).toHaveBeenCalled();
    expect(result).toBeUndefined();
  });

  it("skips prompt when oldText === newText (no-op edit will fail)", async () => {
    readSpy.mockReturnValue("hello world");
    const result = await handleFile(
      makeEditEvent("/tmp/out.ts", "world", "world"),
      makeCtx(),
    );
    // Should return undefined (skip prompt) because edit is a no-op
    expect(result).toBeUndefined();
  });

  it("skips prompt when oldText has zero matches in file", async () => {
    readSpy.mockReturnValue("hello world");
    const result = await handleFile(
      makeEditEvent("/tmp/out.ts", "nonexistent", "replacement"),
      makeCtx(),
    );
    expect(result).toBeUndefined();
  });

  it("skips prompt when oldText has multiple matches in file", async () => {
    readSpy.mockReturnValue("foo bar foo baz foo");
    const result = await handleFile(
      makeEditEvent("/tmp/out.ts", "foo", "qux"),
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
    // before ever reading content. /tmp is auto-allowed so pre-validation runs.
    statSpy.mockImplementation(() => { throw new Error("ENOENT"); });
    const result = await handleFile(
      makeEditEvent("/tmp/missing.ts"),
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
      makeEditEvent("/tmp/out.ts"),
      makeCtx(),
    );
    expect(result).toBeUndefined();
  });
});

// ── Judge content threading ──

import * as decisionEngine from "../decide/engine";
import { resetDspa } from "../modes/dspa-mode";

describe("handleFile content threading (judge input)", () => {
  let decideSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    store.reset();
    resetDspa(); // never let a judge call fire in these tests
    decideSpy = vi
      .spyOn(decisionEngine, "decide")
      .mockResolvedValue({
        kind: "prompt",
        promptData: {
          type: "file",
          action: "Write",
          filePath: "x",
          resolved: `${cwd}/x`,
          cwd,
          outsideDir: null,
          isWriteOp: true,
          warnedRule: null,
          symlinkHint: null,
          exists: false,
        },
      });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("write: request carries the new content", async () => {
    const event = { toolName: "write", input: { path: `${cwd}/out.txt`, content: "line1\nline2" } } as any;
    await handleFile(event, makeCtx());
    expect(decideSpy).toHaveBeenCalled();
    const req = decideSpy.mock.calls[0][0] as any;
    expect(req.type).toBe("file");
    expect(req.content).toBe("line1\nline2");
  });

  it("edit: request carries the joined newText blocks", async () => {
    const event = {
      toolName: "edit",
      input: { path: `${cwd}/f.ts`, edits: [{ oldText: "a", newText: "b" }, { oldText: "c", newText: "d" }] },
    } as any;
    await handleFile(event, makeCtx());
    const req = decideSpy.mock.calls[0][0] as any;
    expect(req.content).toBe("b\n…\nd");
  });

  it("read: request has no content", async () => {
    const event = { toolName: "read", input: { path: `${cwd}/f.ts` } } as any;
    await handleFile(event, makeCtx());
    const req = decideSpy.mock.calls[0][0] as any;
    expect(req.content).toBeUndefined();
  });

  it("edit that would succeed: the judge input becomes the after-edit file view", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "halter-editview-"));
    try {
      const file = path.join(dir, "app.ts");
      const content = ["l1", "l2", "l3", "l4", "l5"].join("\n");
      fs.writeFileSync(file, content);
      const promptData: any = {
        type: "file",
        action: "Edit",
        filePath: file,
        resolved: file,
        cwd,
        outsideDir: null,
        isWriteOp: true,
        warnedRule: null,
        symlinkHint: null,
        exists: true,
        content: "L3-new",
      };
      decideSpy.mockResolvedValue({ kind: "prompt", promptData });
      await handleFile(
        { toolName: "edit", input: { path: file, edits: [{ oldText: "l3", newText: "L3-new" }] } } as any,
        makeCtx(),
      );
      expect(promptData.contentHeading).toBe("File after this edit");
      expect(promptData.content).toBe(
        buildEditAfterView(content, [{ oldText: "l3", newText: "L3-new" }]),
      );
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

// ── decideFile: exists flag (judge input) ──

describe("decideFile: exists for write ops", () => {
  afterEach(() => vi.restoreAllMocks());

  it("edit prompt carries exists: true when the file is on disk", () => {
    vi.spyOn(fs, "existsSync").mockReturnValue(true);
    const d = decideFile(
      {
        type: "file",
        toolName: "edit",
        filePath: "/some/outside/app.ts",
        cwd,
        resolvedPath: "/some/outside/app.ts",
        content: "b",
      },
      createStore(),
    );
    expect(d.kind).toBe("prompt");
    if (d.kind !== "prompt") return;
    expect(d.promptData.type).toBe("file");
    if (d.promptData.type !== "file") return;
    expect(d.promptData.exists).toBe(true);
  });

  it("edit prompt carries exists: false when the file is absent", () => {
    vi.spyOn(fs, "existsSync").mockReturnValue(false);
    const d = decideFile(
      {
        type: "file",
        toolName: "edit",
        filePath: "/some/outside/app.ts",
        cwd,
        resolvedPath: "/some/outside/app.ts",
        content: "b",
      },
      createStore(),
    );
    expect(d.kind).toBe("prompt");
    if (d.kind !== "prompt") return;
    expect(d.promptData.type).toBe("file");
    if (d.promptData.type !== "file") return;
    expect(d.promptData.exists).toBe(false);
  });

  it("write prompt behavior unchanged (exists: true on overwrite)", () => {
    vi.spyOn(fs, "existsSync").mockReturnValue(true);
    const d = decideFile(
      {
        type: "file",
        toolName: "write",
        filePath: "/some/outside/app.ts",
        cwd,
        resolvedPath: "/some/outside/app.ts",
        content: "hello",
      },
      createStore(),
    );
    expect(d.kind).toBe("prompt");
    if (d.kind !== "prompt") return;
    expect(d.promptData.type).toBe("file");
    if (d.promptData.type !== "file") return;
    expect(d.promptData.exists).toBe(true);
  });
});

// ── buildEditAfterView (judge input for edits) ──

function fileOf(n: number): string {
  return Array.from({ length: n }, (_, i) => `line ${i + 1}`).join("\n");
}

describe("buildEditAfterView", () => {
  // Anchored: <line number> <marker> <content> — padding-agnostic.
  const shown = (n: number, marker: ">" | "·", text: string): RegExp =>
    new RegExp(`(^|\n)\\s*${n} ${marker} ${text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}$`, "m");

  it("single replacement: line numbers, '>' marks, context, ellipses", () => {
    const file = fileOf(30);
    const view = buildEditAfterView(file, [{ oldText: "line 15", newText: "NEW 15" }]);
    expect(view).not.toBeNull();
    expect(view!.split("\n")[0]).toBe(
      "30 lines total · 1 replacement · 10-line context · '>' = line set by the edit, '·' = context",
    );
    // Context window: lines 5–25 shown; the edit line is '>', the rest '·'.
    expect(view!).toMatch(shown(5, "·", "line 5"));
    expect(view!).toMatch(shown(14, "·", "line 14"));
    expect(view!).toMatch(shown(15, ">", "NEW 15"));
    expect(view!).toMatch(shown(16, "·", "line 16"));
    expect(view!).toMatch(shown(25, "·", "line 25"));
    expect(view!.split("\n").filter((l) => l === "…").length).toBe(2); // head + tail
    expect(view!).not.toMatch(shown(1, "·", "line 1")); // outside the window
  });

  it("small file (≤ 2×context + 1): whole file shown, no ellipses", () => {
    const file = fileOf(5);
    const view = buildEditAfterView(file, [{ oldText: "line 3", newText: "NEW 3" }]);
    expect(view!).toMatch(shown(1, "·", "line 1"));
    expect(view!).toMatch(shown(3, ">", "NEW 3"));
    expect(view!).toMatch(shown(5, "·", "line 5"));
    expect(view!).not.toContain("…");
  });

  it("two distant blocks: two intervals separated by a single ellipsis", () => {
    const file = fileOf(60);
    const view = buildEditAfterView(file, [
      { oldText: "line 10", newText: "NEW 10" },
      { oldText: "line 50", newText: "NEW 50" },
    ]);
    expect(view!).toContain("2 replacements");
    expect(view!).toMatch(shown(10, ">", "NEW 10"));
    expect(view!).toMatch(shown(50, ">", "NEW 50"));
    // Windows 1–19 and 40–60 (the second reaches EOF) → exactly one gap.
    expect(view!.split("\n").filter((l) => l === "…").length).toBe(1);
  });

  it("adjacent blocks merge into one interval", () => {
    const file = fileOf(40);
    const view = buildEditAfterView(file, [
      { oldText: "line 10", newText: "NEW 10" },
      { oldText: "line 18", newText: "NEW 18" },
    ]);
    // Windows 1–19 and 8–28 overlap (±10) → merged 1–28, one trailing gap only.
    expect(view!).toMatch(shown(10, ">", "NEW 10"));
    expect(view!).toMatch(shown(18, ">", "NEW 18"));
    expect(view!.split("\n").filter((l) => l === "…").length).toBe(1);
  });

  it("blocks apply sequentially — the second matches the post-first content", () => {
    const file = fileOf(20);
    const view = buildEditAfterView(file, [
      { oldText: "line 5", newText: "line 5\ninserted A\ninserted B" },
      { oldText: "line 10", newText: "NEW 10" },
    ]);
    // After the first block (2 inserted lines) old "line 10" sits on line 12.
    // The inserted lines are part of the newText → marked '>'.
    expect(view!).toMatch(shown(7, ">", "inserted B"));
    expect(view!).toMatch(shown(12, ">", "NEW 10"));
    expect(view!).toContain("22 lines total");
  });

  it("deletion (empty newText): noted in the header, line count drops", () => {
    const file = fileOf(30);
    const view = buildEditAfterView(file, [{ oldText: "line 15\n", newText: "" }]);
    expect(view!).toContain("1 replacement (1 deletion)");
    expect(view!).toContain("29 lines total");
  });

  it("mid-line replacement: the joined line is shown and marked", () => {
    const file = "aa bb cc\nmid line\nzz";
    const view = buildEditAfterView(file, [{ oldText: "bb", newText: "BB" }]);
    expect(view!).toMatch(shown(1, ">", "aa BB cc"));
    expect(view!).toContain("3 lines total");
  });

  it("returns null when a block matches twice (or never)", () => {
    const file = "x\nx";
    expect(buildEditAfterView(file, [{ oldText: "x", newText: "y" }])).toBeNull();
    expect(buildEditAfterView(file, [{ oldText: "nope", newText: "y" }])).toBeNull();
  });

  it("no trailing newline: last line still numbered", () => {
    const file = "a\nb\nc"; // no final newline
    const view = buildEditAfterView(file, [{ oldText: "c", newText: "C" }]);
    expect(view!).toMatch(shown(3, ">", "C"));
    expect(view!).toContain("3 lines total");
  });
});
