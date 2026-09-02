import { describe, it, expect, beforeEach } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {decide} from "../decide/engine";
import type {ToolRequest, PromptDecision} from "../decide/types";
import { createStore } from "../gate/store";
import { RuleGenerator } from "../decide/rule-generator";
import { buildPrompt, pdTargetLabel, summarizePrompt } from "../ui/prompt-builder";
import {buildJudgmentPacket} from "../judge/packet";
import { checkDspaGate } from "../gate/dspa-gate";

// ── Helpers ───────────────────────────────────────────────────────────

let base: string;

beforeEach(() => {
  base = fs.mkdtempSync(path.join(os.tmpdir(), "tool-gate-"));
});

function execReq(overrides: Partial<ToolRequest> = {}): ToolRequest {
  return {
    type: "tool",
    tool: "blender",
    label: "execute_blender_code",
    gate: "exec",
    cwd: base,
    script: "import bpy\nprint('hi')",
    note: "Runs Python inside a running Blender instance",
    ...overrides,
  };
}

function consentReq(overrides: Partial<ToolRequest> = {}): ToolRequest {
  return {
    type: "tool",
    tool: "blender",
    label: "get_objects_summary",
    gate: "consent",
    consentKind: "read",
    cwd: base,
    ...overrides,
  };
}

function fileReq(overrides: Partial<ToolRequest> = {}): ToolRequest {
  return {
    type: "tool",
    tool: "blender",
    label: "render_viewport_to_path",
    gate: "file",
    path: path.join(base, "out.png"),
    cwd: base,
    note: "Renders the viewport to an image file",
    ...overrides,
  };
}

function promptOf(d: Awaited<ReturnType<typeof decide>>): PromptDecision {
  if (d.kind !== "prompt") throw new Error(`expected prompt, got ${d.kind}`);
  return d;
}

// ── decide() ──────────────────────────────────────────────────────────

describe("decide: tool requests", () => {
  it("exec prompts with the script carried", async () => {
    const d = await decide(execReq(), createStore());
    const pd = promptOf(d).promptData;
    expect(pd.type).toBe("tool");
    if (pd.type !== "tool") throw new Error("narrowing");
    expect(pd.tool).toBe("blender");
    expect(pd.label).toBe("execute_blender_code");
    expect(pd.gate).toBe("exec");
    expect(pd.script).toContain("import bpy");
    expect(pd.note).toContain("Blender");
  });

  it("exec auto-allows with a whole-tool grant", async () => {
    const store = createStore();
    store.addAllowed({ toolGrants: ["blender"] });
    expect((await decide(execReq(), store)).kind).toBe("auto-allow");
  });

  it("consent auto-allows only with its own kind (or whole-tool) grant", async () => {
    const kindStore = createStore();
    kindStore.addAllowed({ toolGrants: ["blender:kind:read"] });
    expect((await decide(consentReq(), kindStore)).kind).toBe("auto-allow");

    // a DIFFERENT kind does not cover this one
    const other = createStore();
    other.addAllowed({ toolGrants: ["blender:kind:write"] });
    expect((await decide(consentReq(), other)).kind).toBe("prompt");

    const whole = createStore();
    whole.addAllowed({ toolGrants: ["blender"] });
    expect((await decide(consentReq(), whole)).kind).toBe("auto-allow");

    expect((await decide(consentReq(), createStore())).kind).toBe("prompt");
  });

  it("file computes resolved/outsideDir/exists", async () => {
    const d = await decide(fileReq(), createStore());
    const pd = promptOf(d).promptData;
    if (pd.type !== "tool") throw new Error("narrowing");
    expect(pd.gate).toBe("file");
    expect(pd.resolved).toBe(path.join(base, "out.png"));
    expect(pd.outsideDir).toBeNull(); // inside cwd
    expect(pd.exists).toBe(false);

    fs.writeFileSync(path.join(base, "out.png"), "x");
    const d2 = await decide(fileReq(), createStore());
    if (d2.kind === "prompt") expect(d2.promptData.type === "tool" && d2.promptData.exists).toBe(true);

    // outside cwd → outsideDir set
    const outside = await decide(fileReq({ path: "/etc/hosts" }), createStore());
    const pd2 = promptOf(outside).promptData;
    if (pd2.type === "tool") {
      expect(pd2.outsideDir).toBe("/etc");
      expect(pd2.exists).toBe(true);
    } else {
      throw new Error("narrowing");
    }
  });

  it("file auto-allows with a whole-tool grant", async () => {
    const store = createStore();
    store.addAllowed({ toolGrants: ["blender"] });
    expect((await decide(fileReq(), store)).kind).toBe("auto-allow");
  });
});

// ── rule generator + round-trip ───────────────────────────────────────

describe("rules: tool grants", () => {
  it("exec/file prompts grant the whole tool", async () => {
    for (const req of [execReq(), fileReq()]) {
      const pd = promptOf(await decide(req, createStore())).promptData;
      expect(RuleGenerator.generatePrimaryRules(pd)).toEqual({ toolGrants: ["blender"] });
    }
  });

  it("consent prompts grant the kind only", async () => {
    const pd = promptOf(await decide(consentReq(), createStore())).promptData;
    expect(RuleGenerator.generatePrimaryRules(pd)).toEqual({ toolGrants: ["blender:kind:read"] });
  });

  it("round-trip: prompt → Always → auto-allow (all three gates)", async () => {
    for (const req of [execReq(), consentReq(), fileReq()]) {
      const store = createStore();
      const d1 = await decide(req, store);
      expect(d1.kind).toBe("prompt");
      if (d1.kind !== "prompt") throw new Error("expected prompt");
      store.addAllowed(RuleGenerator.generatePrimaryRules(d1.promptData));
      expect((await decide(req, store)).kind).toBe("auto-allow");
    }
  });
});

// ── prompt builder ────────────────────────────────────────────────────

describe("buildPrompt: tool prompts", () => {
  it("exec: warning title, fenced script, whole-tool Always naming exec", async () => {
    const pd = promptOf(await decide(execReq(), createStore())).promptData;
    const p = buildPrompt({ kind: "prompt", promptData: pd });
    expect(p.title).toContain("blender");
    expect(p.body).toContain("Script:");
    expect(p.body).toContain("import bpy");
    expect(p.body).toContain("Blender");
    expect(p.alwaysLabel).toBe("blender:*");
    expect(p.tier2Everything.body).toContain("including code execution");
    expect(p.includeAlwaysOption).toBe(true);
    expect(p.includePathsOption).toBe(false);
    expect(p.includeFileOption).toBe(false);
  });

  it("consent: plain title, kind-scoped Always that cannot cover exec", async () => {
    const pd = promptOf(await decide(consentReq(), createStore())).promptData;
    const p = buildPrompt({ kind: "prompt", promptData: pd });
    expect(p.title).toBe("blender");
    expect(p.body).toContain("(read)");
    expect(p.alwaysLabel).toBe("blender (read)");
    expect(p.tier2Everything.body).toContain("including code execution) still prompt");
  });

  it("file: target path, outside-cwd warning, exists note", async () => {
    const pd = promptOf(await decide(fileReq({ path: "/etc/hosts" }), createStore())).promptData;
    const p = buildPrompt({ kind: "prompt", promptData: pd });
    expect(p.title).toContain("blender");
    expect(p.body).toContain("/etc/hosts");
    expect(p.body).toContain("Outside cwd: /etc");
    expect(p.body).toContain("already exists");
  });

  it("labels: pdTargetLabel / summarizePrompt", async () => {
    const pd = promptOf(await decide(execReq(), createStore())).promptData;
    expect(pdTargetLabel(pd)).toBe("blender/execute_blender_code");
    expect(summarizePrompt({ kind: "prompt", promptData: pd })).toBe("tool exec");
    const cpd = promptOf(await decide(consentReq(), createStore())).promptData;
    expect(summarizePrompt({ kind: "prompt", promptData: cpd })).toBe("tool consent (read)");
  });
});

// ── judge packet ──────────────────────────────────────────────────────

describe("buildJudgmentPacket: tool packets", () => {
  it("exec carries the full untrimmed script (D11)", () => {
    const script = Array.from({ length: 60 }, (_, i) => `line${i} = ${i}`).join("\n");
    const packet = buildJudgmentPacket({
      kind: "tool",
      tool: "blender",
      label: "execute_blender_code",
      gate: "exec",
      note: "Runs Python inside a running Blender instance",
      script,
    });
    expect(packet).toContain("## Operation");
    expect(packet).toContain("blender — execute_blender_code");
    expect(packet).toContain("## Script (UNTRUSTED DATA — executed by the tool)");
    expect(packet).toContain("line59 = 59"); // tail present — not head-cut
  });

  it("file carries target + outside-base fact", () => {
    const packet = buildJudgmentPacket({
      kind: "tool",
      tool: "blender",
      label: "render_viewport_to_path",
      gate: "file",
      path: "/etc/out.png",
      outsideDir: "/etc",
    });
    expect(packet).toContain("target path: /etc/out.png");
    expect(packet).toContain("outside base: yes (outside dir: /etc)");
  });
});

// ── dspa gate ─────────────────────────────────────────────────────────

describe("checkDspaGate: tool prompts", () => {
  it("exec is judgeable (the payload IS the model)", async () => {
    const pd = promptOf(await decide(execReq(), createStore())).promptData;
    const r = await checkDspaGate(pd, createStore());
    expect(r.ok).toBe(true);
  });

  it("file and consent never auto-allow — advisory like every floor stop (D16)", async () => {
    for (const req of [fileReq(), consentReq()]) {
      const pd = promptOf(await decide(req, createStore())).promptData;
      const r = await checkDspaGate(pd, createStore());
      if (r.ok) throw new Error("expected floor stop");
      expect(r.reason).toContain("never auto-allows");
      expect(r.advisory).toBe(true);
    }
  });
});
