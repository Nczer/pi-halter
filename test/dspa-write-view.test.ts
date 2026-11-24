/**
 * The after-edit view for a write the D3 probe converts.
 *
 * A write into a session-granted or project dir is a manual AUTO-ALLOW, which
 * /dspa converts into a judged prompt by re-deciding the same request
 * (gate/conversions.ts). The judge packet's content therefore comes from the
 * REQUEST, not from the first decision — the handler has to put the after-edit
 * file view there, or the judge reviews bare newText blocks with no context.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const { judgeStatusMock } = vi.hoisted(() => ({
  judgeStatusMock: vi.fn<() => { state: string; modelLabel: string | null; reason: string | null }>(),
}));
vi.mock("../judge/verdict", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../judge/verdict")>()),
  judgeStatus: judgeStatusMock,
}));

import { handleFile, buildEditAfterView } from "../handlers";
import * as decisionEngine from "../decide/engine";
import { decideFile } from "../decide/file-policy";
import { createStore } from "../gate/store";
import { resetDspa, setDspaActive } from "../modes/dspa-mode";

const ORIGINAL = ["l1", "l2", "l3", "l4", "l5"].join("\n");
const EDITS = [{ oldText: "l3", newText: "L3-new" }];

function makeCtx() {
  return { cwd: process.cwd(), hasUI: true } as any;
}

function makeEditEvent(filePath: string) {
  return { toolName: "edit", input: { path: filePath, edits: EDITS } } as any;
}

describe("handleFile: after-edit view on the D3 write-probe request", () => {
  let dir: string;
  let file: string;
  let decideSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "halter-writeview-"));
    file = path.join(dir, "app.ts");
    fs.writeFileSync(file, ORIGINAL);
    resetDspa();
    judgeStatusMock.mockReset();
    judgeStatusMock.mockReturnValue({ state: "ok", modelLabel: "test/model (session)", reason: null });
    // The manual decision for a write into a granted dir: auto-allow.
    decideSpy = vi.spyOn(decisionEngine, "decide").mockResolvedValue({ kind: "auto-allow" } as any);
  });

  afterEach(() => {
    vi.restoreAllMocks();
    resetDspa();
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("dspa + judge available: the re-decided request carries the view", async () => {
    setDspaActive(true);
    await handleFile(makeEditEvent(file), makeCtx());
    // First decide (manual shape) and the D3 re-decide run over ONE request
    // object — the view has to be on it, not on the first decision.
    expect(decideSpy.mock.calls.length).toBeGreaterThanOrEqual(2);
    const first = decideSpy.mock.calls[0][0] as any;
    const probed = decideSpy.mock.calls[1][0] as any;
    expect(probed).toBe(first);
    expect(probed.content).toBe(buildEditAfterView(ORIGINAL, EDITS));
    expect(probed.contentHeading).toBe("File after this edit");
  });

  it("dspa off: no view is built for an auto-allow (no judge will read it)", async () => {
    await handleFile(makeEditEvent(file), makeCtx());
    expect(decideSpy.mock.calls.length).toBe(1);
    const req = decideSpy.mock.calls[0][0] as any;
    expect(req.content).toBe("L3-new");
    expect(req.contentHeading).toBeUndefined();
  });

  it("judge unavailable: no conversion, so no view", async () => {
    setDspaActive(true);
    judgeStatusMock.mockReturnValue({ state: "off", modelLabel: null, reason: null });
    await handleFile(makeEditEvent(file), makeCtx());
    expect(decideSpy.mock.calls.length).toBe(1);
    expect((decideSpy.mock.calls[0][0] as any).content).toBe("L3-new");
  });
});

describe("decideFile: contentHeading reaches the judge packet", () => {
  it("edit prompt copies content and contentHeading from the request", () => {
    const d = decideFile(
      {
        type: "file",
        toolName: "edit",
        filePath: "/some/outside/app.ts",
        cwd: process.cwd(),
        resolvedPath: "/some/outside/app.ts",
        content: "## view",
        contentHeading: "File after this edit",
      },
      createStore(),
    );
    expect(d.kind).toBe("prompt");
    if (d.kind !== "prompt" || d.promptData.type !== "file") return;
    expect(d.promptData.content).toBe("## view");
    expect(d.promptData.contentHeading).toBe("File after this edit");
  });

  it("an edit prompt with no heading keeps the packet's default section", () => {
    const d = decideFile(
      {
        type: "file",
        toolName: "edit",
        filePath: "/some/outside/app.ts",
        cwd: process.cwd(),
        resolvedPath: "/some/outside/app.ts",
        content: "b\n\u2026\nd",
      },
      createStore(),
    );
    expect(d.kind).toBe("prompt");
    if (d.kind !== "prompt" || d.promptData.type !== "file") return;
    expect(d.promptData.content).toBe("b\n\u2026\nd");
    expect(d.promptData.contentHeading).toBeUndefined();
  });
});
