import { describe, expect, it } from "vitest";
import { buildPrompt } from "../prompt-builder";
import type { PromptDecision } from "../decision-engine";

// ── Helpers ────────────────────────────────────────────────────────────────

function bashDecision(overrides: Partial<PromptDecision["promptData"]> & { includePathsOption?: boolean; includeBroaderOption?: boolean } = {}): PromptDecision {
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
      hasUnsafePattern: false,
      needsCommandApproval: false,
      needsPathApproval: false,
      ...overrides,
    },
    allowRules: {},
    includePathsOption: overrides.includePathsOption ?? false,
    includeBroaderOption: overrides.includeBroaderOption ?? false,
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
      warnedRule: null,
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
      argsPreview: undefined,
      ...overrides,
    },
    allowRules: { mcpServers: ["exa"] },
  };
}

// ── Bash: body content ─────────────────────────────────────────────────────

describe("bash body content", () => {
  it("shows command in body", () => {
    const prompt = buildPrompt(bashDecision({ needsCommandApproval: true }));
    expect(prompt.body).toContain("ls -la");
  });

  it("title is Bash when only command needs approval", () => {
    const prompt = buildPrompt(bashDecision({ needsCommandApproval: true }));
    expect(prompt.title).toBe("Bash");
  });

  it("title is Path when only path needs approval", () => {
    const prompt = buildPrompt(bashDecision({ outsideDirs: ["/etc"], needsPathApproval: true, needsCommandApproval: false }));
    expect(prompt.title).toBe("Path");
  });

  it("title is Bash + Path when both need approval", () => {
    const prompt = buildPrompt(bashDecision({ outsideDirs: ["/etc"], signatures: ["rm"], needsCommandApproval: true, needsPathApproval: true, includePathsOption: true }));
    expect(prompt.title).toBe("Bash + Path");
  });

  it("adds warning emoji for high risk", () => {
    const prompt = buildPrompt(bashDecision({ riskSeverity: "high", riskDangerous: true, riskReasons: ["sudo"] }));
    expect(prompt.title).toContain("⚠");
  });

  it("includes danger flags in body", () => {
    const prompt = buildPrompt(bashDecision({ riskDangerous: true, riskSeverity: "high", riskReasons: ["sudo (elevated privileges)"] }));
    expect(prompt.body).toContain("sudo (elevated privileges)");
  });

  it("includes paths outside cwd in body", () => {
    const prompt = buildPrompt(bashDecision({ outsideDirs: ["/etc"], needsPathApproval: true }));
    expect(prompt.body).toContain("/etc");
  });

  it("truncates long multiline commands", () => {
    const longCmd = Array.from({ length: 25 }, (_, i) => `echo line ${i}`).join("\n");
    const prompt = buildPrompt(bashDecision({ command: longCmd }));
    expect(prompt.body).toContain("(+");
    expect(prompt.body).toContain("more lines");
  });

  it("lists segments with numbered indices", () => {
    const prompt = buildPrompt(bashDecision({ segments: ["ls", "rm -rf /"], nonAllowedSegmentIndices: [1] }));
    expect(prompt.body).toContain("1.");
    expect(prompt.body).toContain("2.");
    expect(prompt.body).toContain("2 commands");
  });

  it("marks non-allowed segments with warning emoji", () => {
    const prompt = buildPrompt(bashDecision({ segments: ["ls", "rm -rf /"], nonAllowedSegmentIndices: [1] }));
    // Segment 2 (index 1) should have ⚠, segment 1 should not
    const segmentLines = prompt.body.split("\n").filter(l => l.includes("."));
    expect(segmentLines[0]).not.toContain("⚠");
    expect(segmentLines[1]).toContain("⚠");
  });

  it("shows hasUnsafePattern warning text", () => {
    const prompt = buildPrompt(bashDecision({ needsCommandApproval: true, hasUnsafePattern: true }));
    expect(prompt.body).toContain("danger patterns always prompt");
  });
});

// ── Bash: labels ───────────────────────────────────────────────────────────

describe("bash labels", () => {
  it("alwaysLabel shows command sig when only command needs approval", () => {
    const prompt = buildPrompt(bashDecision({ signatures: ["rm -rf"], needsCommandApproval: true, needsPathApproval: false }));
    expect(prompt.alwaysLabel).toBe("rm -rf *");
  });

  it("alwaysLabel shows path text when only path needs approval (command trusted)", () => {
    const prompt = buildPrompt(bashDecision({ outsideDirs: ["/mnt/data"], signatures: ["uv run"], needsPathApproval: true, needsCommandApproval: false }));
    expect(prompt.alwaysLabel).toBe("Read /mnt/data/*");
    expect(prompt.alwaysLabel).not.toContain("uv run");
  });

  it("alwaysLabel shows command sig when both need approval", () => {
    const prompt = buildPrompt(bashDecision({ outsideDirs: ["/etc"], signatures: ["rm"], needsCommandApproval: true, needsPathApproval: true, includePathsOption: true }));
    expect(prompt.alwaysLabel).toBe("rm *");
  });

  it("alwaysPathsLabel shows path text when both need approval", () => {
    const prompt = buildPrompt(bashDecision({ outsideDirs: ["/etc"], signatures: ["rm"], needsCommandApproval: true, needsPathApproval: true, includePathsOption: true }));
    expect(prompt.alwaysPathsLabel).toBe("Read /etc/*");
  });

  it("alwaysPathsLabel is undefined when only command needs approval", () => {
    const prompt = buildPrompt(bashDecision({ signatures: ["rm"], needsCommandApproval: true, needsPathApproval: false }));
    expect(prompt.alwaysPathsLabel).toBeUndefined();
  });

  it("alwaysBroaderLabel shows parent command when broader option enabled", () => {
    const prompt = buildPrompt(bashDecision({ command: "npm test", signatures: ["npm test"], needsCommandApproval: true, includeBroaderOption: true }));
    expect(prompt.alwaysBroaderLabel).toBe("npm *");
  });

  it("alwaysBroaderLabel is undefined when broader option disabled", () => {
    const prompt = buildPrompt(bashDecision({ signatures: ["rm"], needsCommandApproval: true, includeBroaderOption: false }));
    expect(prompt.alwaysBroaderLabel).toBeUndefined();
  });

  it("permanentAllowExamples includes sig and broader for command-only", () => {
    const prompt = buildPrompt(bashDecision({ command: "npm test", signatures: ["npm test"], needsCommandApproval: true, needsPathApproval: false }));
    expect(prompt.permanentAllowExamples).toContain("npm test *");
    expect(prompt.permanentAllowExamples).toContain("npm *");
  });

  it("permanentAllowExamples includes path rule when path approval needed", () => {
    const prompt = buildPrompt(bashDecision({ outsideDirs: ["/etc"], signatures: ["ls"], needsCommandApproval: true, needsPathApproval: true }));
    expect(prompt.permanentAllowExamples).toContain("/etc/*");
  });
});

// ── Bash: tier2 confirmations ──────────────────────────────────────────────

describe("bash tier2 confirmations", () => {
  it("tier2 everything shows commands only when only command needs approval", () => {
    const prompt = buildPrompt(bashDecision({ signatures: ["ls -la"], needsCommandApproval: true, needsPathApproval: false }));
    expect(prompt.tier2Everything.body).toContain("ls -la");
    expect(prompt.tier2Paths).toBeUndefined();
  });

  it("tier2 everything shows paths only when only path needs approval", () => {
    const prompt = buildPrompt(bashDecision({ outsideDirs: ["/etc"], needsPathApproval: true, needsCommandApproval: false }));
    expect(prompt.tier2Everything.body).toContain("/etc");
  });

  it("tier2 everything includes both commands and paths when both need approval", () => {
    const prompt = buildPrompt(bashDecision({ outsideDirs: ["/etc"], signatures: ["rm"], needsCommandApproval: true, needsPathApproval: true, includePathsOption: true }));
    expect(prompt.tier2Everything.body).toContain("rm *");
    expect(prompt.tier2Everything.body).toContain("/etc/*");
  });

  it("tier2 paths option exists when both command and path approval needed", () => {
    const prompt = buildPrompt(bashDecision({ outsideDirs: ["/etc"], signatures: ["rm"], needsCommandApproval: true, needsPathApproval: true, includePathsOption: true }));
    expect(prompt.tier2Paths).toBeDefined();
    expect(prompt.tier2Paths!.body).toContain("/etc");
    expect(prompt.tier2Paths!.body).toContain("will still prompt");
  });

  it("tier2 paths option is undefined when only path needs approval", () => {
    const prompt = buildPrompt(bashDecision({ outsideDirs: ["/etc"], needsPathApproval: true, needsCommandApproval: false }));
    expect(prompt.tier2Paths).toBeUndefined();
  });
});

// ── File: body content ─────────────────────────────────────────────────────

describe("file body content", () => {
  it("produces title for read inside cwd", () => {
    const prompt = buildPrompt(fileDecision({ outsideDir: null }));
    expect(prompt.title).toBe("Read");
    expect(prompt.body).toContain("src/index.ts");
  });

  it("shows outside cwd warning with emoji", () => {
    const prompt = buildPrompt(fileDecision({ action: "Write", outsideDir: "/etc", isWriteOp: true, resolved: "/etc/config.conf" }));
    expect(prompt.title).toContain("⚠");
    expect(prompt.title).toContain("outside cwd");
    expect(prompt.body).toContain("/etc");
  });

  it("shows symlink hint", () => {
    const prompt = buildPrompt(fileDecision({ outsideDir: "/mnt/data", symlinkHint: "/home/user/link → /mnt/data" }));
    expect(prompt.body).toContain("symlink");
    expect(prompt.body).toContain("/home/user/link");
  });

  it("shows denied rule match", () => {
    const prompt = buildPrompt(fileDecision({ deniedRule: ".env" }));
    expect(prompt.body).toContain(".env");
  });

  it("shows warned rule match", () => {
    const prompt = buildPrompt(fileDecision({ warnedRule: ".env.*" }));
    expect(prompt.body).toContain(".env.*");
  });
});

// ── File: labels and tier2 ─────────────────────────────────────────────────

describe("file labels and tier2", () => {
  it("alwaysLabel shows read path for outside cwd read", () => {
    const prompt = buildPrompt(fileDecision({ action: "Read", outsideDir: "/etc", resolved: "/etc/hosts" }));
    expect(prompt.alwaysLabel).toBe("Read /etc/*");
  });

  it("alwaysLabel shows write path for outside cwd write", () => {
    const prompt = buildPrompt(fileDecision({ action: "Write", outsideDir: "/etc", isWriteOp: true, resolved: "/etc/config.conf" }));
    expect(prompt.alwaysLabel).toBe("Write /etc/*");
  });

  it("alwaysLabel shows file name for inside cwd read", () => {
    const prompt = buildPrompt(fileDecision({ action: "Read", outsideDir: null }));
    expect(prompt.alwaysLabel).toContain("index.ts");
  });

  it("alwaysBroaderLabel shows directory for inside cwd", () => {
    const prompt = buildPrompt(fileDecision({ action: "Read", outsideDir: null }));
    expect(prompt.alwaysBroaderLabel).toContain("src");
    expect(prompt.alwaysBroaderLabel).toContain("/*");
  });

  it("generates tier2 file option for outside cwd", () => {
    const prompt = buildPrompt(fileDecision({ action: "Read", outsideDir: "/etc", resolved: "/etc/hosts" }));
    expect(prompt.includeFileOption).toBe(true);
    expect(prompt.tier2File).toBeDefined();
    expect(prompt.tier2File!.body).toContain("/etc/hosts");
  });

  it("generates tier2 broader option for inside cwd", () => {
    const prompt = buildPrompt(fileDecision({ action: "Read", outsideDir: null }));
    expect(prompt.includeBroaderOption).toBe(true);
    expect(prompt.tier2Broader).toBeDefined();
  });

  it("permanentAllowExamples includes file name and directory", () => {
    const prompt = buildPrompt(fileDecision({ action: "Read", outsideDir: "/etc", resolved: "/etc/hosts" }));
    expect(prompt.permanentAllowExamples).toContain("hosts");
    expect(prompt.permanentAllowExamples).toContain("/etc/*");
  });
});

// ── MCP ────────────────────────────────────────────────────────────────────

describe("mcp", () => {
  it("produces title with warning emoji", () => {
    const prompt = buildPrompt(mcpDecision());
    expect(prompt.title).toBe("\u26a0\ufe0f MCP");
  });

  it("shows server, tool, and operation", () => {
    const prompt = buildPrompt(mcpDecision({ server: "exa", tool: "exa_web_search", op: "call" }));
    expect(prompt.body).toContain("exa");
    expect(prompt.body).toContain("exa_web_search");
    expect(prompt.body).toContain("call");
  });

  it("shows args preview when provided", () => {
    const prompt = buildPrompt(mcpDecision({ argsPreview: '{\n  "query": "hello"\n}' }));
    expect(prompt.body).toContain("query");
    expect(prompt.body).toContain("hello");
  });

  it("generates server-level tier2 confirmation", () => {
    const prompt = buildPrompt(mcpDecision({ server: "exa" }));
    expect(prompt.tier2Everything.body).toContain("exa:*");
  });

  it("alwaysLabel shows server wildcard", () => {
    const prompt = buildPrompt(mcpDecision({ server: "exa" }));
    expect(prompt.alwaysLabel).toBe("exa:*");
  });
});

// ── Edge cases ─────────────────────────────────────────────────────────────

describe("edge cases", () => {
  it("handles empty allowRules gracefully", () => {
    const decision: PromptDecision = {
      kind: "prompt",
      promptData: { type: "bash", command: "ls", cwd: "/tmp", outsideDirs: [], segments: ["ls"], signatures: ["ls"], nonAllowedSegmentIndices: [], riskDangerous: false, riskSeverity: null, riskReasons: [], hasUnsafePattern: false, needsCommandApproval: false, needsPathApproval: false },
      allowRules: {},
    };
    expect(() => buildPrompt(decision)).not.toThrow();
  });

  it("handles empty command", () => {
    const prompt = buildPrompt(bashDecision({ command: "" }));
    expect(prompt.body).toContain("Command:");
  });
});
