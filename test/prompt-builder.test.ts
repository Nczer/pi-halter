import { describe, expect, it } from "vitest";
import { buildPrompt } from "../prompt-builder";
import type { PromptDecision } from "../decision-engine";

function bashDecision(overrides: Partial<PromptDecision["promptData"]> & { includePathsOption?: boolean } = {}): PromptDecision {
  return {
    kind: "prompt",
    promptData: {
      type: "bash",
      command: "ls -la",
      cwd: "/home/user/project",
      outsideDirs: [],
      segments: ["ls -la"],
      signatures: ["ls"],
      nonAllowedSegmentIndices: [],
      riskDangerous: false,
      riskSeverity: null,
      riskReasons: [],
      needsCommandApproval: false,
      needsPathApproval: false,
      ...overrides,
    },
    allowRules: {},
    includePathsOption: overrides.includePathsOption ?? false,
  };
}

function fileDecision(overrides: Partial<PromptDecision["promptData"]> = {}): PromptDecision {
  return {
    kind: "prompt",
    promptData: {
      type: "file",
      action: "Read",
      filePath: "src/index.ts",
      resolved: "/home/user/project/src/index.ts",
      cwd: "/home/user/project",
      outsideDir: null,
      isWriteOp: false,
      deniedRule: null,
      symlinkHint: null,
      ...overrides,
    },
    allowRules: {},
  };
}

function mcpDecision(overrides: Partial<PromptDecision["promptData"]> = {}): PromptDecision {
  return {
    kind: "prompt",
    promptData: {
      type: "mcp",
      server: "exa",
      tool: "exa_web_search",
      op: "call",
      ...overrides,
    },
    allowRules: { mcpServers: ["exa"] },
  };
}

describe("buildPrompt: bash", () => {
  it("produces title for simple bash command", () => {
    const decision = bashDecision({ needsCommandApproval: true });
    const prompt = buildPrompt(decision);
    expect(prompt.title).toBe("Bash");
    expect(prompt.body).toContain("ls -la");
  });

  it("adds warning emoji for high risk", () => {
    const decision = bashDecision({ riskSeverity: "high", riskDangerous: true, riskReasons: ["sudo"] });
    const prompt = buildPrompt(decision);
    expect(prompt.title).toContain("⚠");
  });

  it("includes danger flags when present", () => {
    const decision = bashDecision({ riskDangerous: true, riskSeverity: "high", riskReasons: ["sudo (elevated privileges)"] });
    const prompt = buildPrompt(decision);
    expect(prompt.body).toContain("sudo (elevated privileges)");
  });

  it("includes paths outside cwd", () => {
    const decision = bashDecision({ outsideDirs: ["/etc"], needsPathApproval: true });
    const prompt = buildPrompt(decision);
    expect(prompt.body).toContain("/etc");
  });

  it("shows both command and path sections when both need approval", () => {
    const decision = bashDecision({ outsideDirs: ["/etc"], needsCommandApproval: true, needsPathApproval: true, includePathsOption: true });
    const prompt = buildPrompt(decision);
    expect(prompt.title).toBe("Bash + Path");
    expect(prompt.includePathsOption).toBe(true);
  });

  it("truncates long commands", () => {
    const longCmd = Array.from({ length: 25 }, (_, i) => `echo line ${i}`).join("\n");
    const decision = bashDecision({ command: longCmd });
    const prompt = buildPrompt(decision);
    expect(prompt.body).toContain("(+");
    expect(prompt.body).toContain("more lines");
  });

  it("lists multiple segments with warning markers", () => {
    const decision = bashDecision({ segments: ["ls", "rm -rf /"], nonAllowedSegmentIndices: [1] });
    const prompt = buildPrompt(decision);
    expect(prompt.body).toContain("1.");
    expect(prompt.body).toContain("2.");
  });

  it("generates tier2 confirmation for commands only", () => {
    const decision = bashDecision({ signatures: ["ls -la"], needsPathApproval: false });
    const prompt = buildPrompt(decision);
    expect(prompt.tier2Everything.body).toContain("ls -la");
    expect(prompt.tier2Paths).toBeUndefined();
  });

  it("generates tier2 confirmation for paths only", () => {
    const decision = bashDecision({ outsideDirs: ["/etc"], needsPathApproval: true, needsCommandApproval: false });
    const prompt = buildPrompt(decision);
    expect(prompt.tier2Everything.body).toContain("/etc");
  });

  it("generates tier2 paths option when both command and path approval needed", () => {
    const decision = bashDecision({ outsideDirs: ["/etc"], signatures: ["rm"], needsCommandApproval: true, needsPathApproval: true, includePathsOption: true });
    const prompt = buildPrompt(decision);
    expect(prompt.tier2Paths).toBeDefined();
    expect(prompt.tier2Paths!.body).toContain("/etc");
  });
});

describe("buildPrompt: file", () => {
  it("produces title for read inside cwd", () => {
    const decision = fileDecision({ type: "file", action: "Read", outsideDir: null });
    const prompt = buildPrompt(decision);
    expect(prompt.title).toBe("Read");
    expect(prompt.body).toContain("src/index.ts");
  });

  it("shows outside cwd warning", () => {
    const decision = fileDecision({ type: "file", action: "Write", outsideDir: "/etc", isWriteOp: true, resolved: "/etc/config.conf" });
    const prompt = buildPrompt(decision);
    expect(prompt.title).toContain("⚠");
    expect(prompt.title).toContain("outside cwd");
    expect(prompt.body).toContain("/etc");
  });

  it("shows symlink hint", () => {
    const decision = fileDecision({ type: "file", action: "Read", outsideDir: "/mnt/data", symlinkHint: "/home/user/link → /mnt/data" });
    const prompt = buildPrompt(decision);
    expect(prompt.body).toContain("symlink");
    expect(prompt.body).toContain("/home/user/link");
  });

  it("shows denied rule match", () => {
    const decision = fileDecision({ type: "file", action: "Read", deniedRule: ".env" });
    const prompt = buildPrompt(decision);
    expect(prompt.body).toContain(".env");
  });

  it("generates tier2 file option for outside cwd", () => {
    const decision = fileDecision({ type: "file", action: "Read", outsideDir: "/etc", resolved: "/etc/hosts" });
    const prompt = buildPrompt(decision);
    expect(prompt.includeFileOption).toBe(true);
    expect(prompt.tier2File).toBeDefined();
    expect(prompt.tier2File!.body).toContain("/etc/hosts");
  });
});

describe("buildPrompt: mcp", () => {
  it("produces title with warning emoji", () => {
    const decision = mcpDecision();
    const prompt = buildPrompt(decision);
    expect(prompt.title).toBe("\u26a0\ufe0f MCP");
  });

  it("shows server, tool, and operation", () => {
    const decision = mcpDecision({ server: "exa", tool: "exa_web_search", op: "call" });
    const prompt = buildPrompt(decision);
    expect(prompt.body).toContain("exa");
    expect(prompt.body).toContain("exa_web_search");
    expect(prompt.body).toContain("call");
  });

  it("shows args preview when provided", () => {
    const decision = mcpDecision({ argsPreview: '{\n  "query": "hello"\n}' });
    const prompt = buildPrompt(decision);
    expect(prompt.body).toContain("query");
    expect(prompt.body).toContain("hello");
  });

  it("generates server-level tier2 confirmation", () => {
    const decision = mcpDecision({ server: "exa" });
    const prompt = buildPrompt(decision);
    expect(prompt.tier2Everything.body).toContain("exa:*");
  });
});

describe("buildPrompt: edge cases", () => {
  it("handles empty allowRules gracefully", () => {
    const decision: PromptDecision = {
      kind: "prompt",
      promptData: { type: "bash", command: "ls", cwd: "/tmp", outsideDirs: [], segments: ["ls"], signatures: ["ls"], nonAllowedSegmentIndices: [], riskDangerous: false, riskSeverity: null, riskReasons: [], needsCommandApproval: false, needsPathApproval: false },
      allowRules: {},
    };
    expect(() => buildPrompt(decision)).not.toThrow();
  });

  it("handles empty command", () => {
    const decision = bashDecision({ command: "" });
    const prompt = buildPrompt(decision);
    expect(prompt.body).toContain("Command:");
  });
});
