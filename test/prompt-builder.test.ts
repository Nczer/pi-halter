import { describe, expect, it } from "vitest";
import { buildPrompt } from "../prompt-builder";
import type { PromptDecision } from "../decision-engine";

// ── Helpers ────────────────────────────────────────────────────────────────

function bashDecision(overrides: Partial<PromptDecision["promptData"]> = {}): PromptDecision {
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
      warnedRule: null,
      symlinkHint: null,
      exists: false,
      ...overrides,
    },
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
    const prompt = buildPrompt(bashDecision({ riskDangerous: true, riskSeverity: "high", riskReasons: ["[System] sudo (privilege escalation)"] }));
    expect(prompt.body).toContain("[System]  sudo (privilege escalation)");
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

  it("shows formatted breakdown with numbered segments for tmux chains", () => {
    // Breakdown format used when at least one segment is a tmux command
    const segments = ["mkdir -p /tmp/foo", "tmux -f /dev/null -S $SOCKET new -d -s foo", "sleep 1"];
    const cmd = segments.join("; ");
    const prompt = buildPrompt(bashDecision({ command: cmd, segments, nonAllowedSegmentIndices: [1] }));
    expect(prompt.body).toContain("Segments:");
    expect(prompt.body).toContain("1.");
    expect(prompt.body).toContain("2.");
    expect(prompt.body).toContain("3.");
  });

  it("marks non-allowed segments with warning in formatted tmux output", () => {
    const segments = ["mkdir -p /tmp/foo", "tmux -f /dev/null -S $SOCKET new -d -s foo", "sleep 1"];
    const cmd = segments.join("; ");
    const prompt = buildPrompt(bashDecision({ command: cmd, segments, nonAllowedSegmentIndices: [1] }));
    const segmentLines = prompt.body.split("\n").filter(l => l.includes("2."));
    expect(segmentLines.some(l => l.includes("⚠"))).toBe(true);
  });

  it("shows raw command for non-tmux chains", () => {
    // Non-tmux chains keep raw command display + chain list
    const cmd = "ls && rm -rf /";
    const prompt = buildPrompt(bashDecision({ command: cmd, segments: ["ls", "rm -rf /"], nonAllowedSegmentIndices: [1] }));
    expect(prompt.body).toContain("  ls && rm -rf /");
    expect(prompt.body).not.toContain("bash (");
    expect(prompt.body).toContain("This chains 2 commands");
  });

  it("marks non-allowed segments with warning emoji in chain list", () => {
    const prompt = buildPrompt(bashDecision({ command: "ls && rm -rf /", segments: ["ls", "rm -rf /"], nonAllowedSegmentIndices: [1] }));
    const segmentLines = prompt.body.split("\n").filter(l => l.includes("."));
    expect(segmentLines.find(l => l.includes("1."))!).not.toContain("⚠");
    expect(segmentLines.find(l => l.includes("2."))!).toContain("⚠");
  });

  it("shows formatted breakdown even when tmux command has no boilerplate", () => {
    // Multi-segment tmux commands always get the structured "bash (N segments)" format
    const segments = ["tmux list-sessions", "sleep 1"];
    const cmd = segments.join("; ");
    const prompt = buildPrompt(bashDecision({ command: cmd, segments, nonAllowedSegmentIndices: [0] }));
    expect(prompt.body).toContain("Segments:");
    expect(prompt.body).toContain("bash (2 segments)");
    // ⚠ marker on segment 1 (index 0)
    const lines = prompt.body.split("\n");
    const line1 = lines.find(l => l.includes("1."));
    expect(line1).toContain("⚠");
  });

  it("compresses multi-line segments in non-tmux chain list", () => {
    // Non-tmux chains use plain numbered list with multi-line compression
    const multiLine = "cat <<'EOF'\nline1\nline2\nline3\nEOF";
    const prompt = buildPrompt(bashDecision({
      command: `ls && ${multiLine}`,
      segments: ["ls", multiLine],
      nonAllowedSegmentIndices: [1],
    }));
    expect(prompt.body).toContain("This chains 2 commands");
    expect(prompt.body).toContain("(5 lines)"); // heredoc has 5 lines including EOF markers
    // Chain list segment 2 shows compressed form (raw command above still shows full heredoc)
    const chainLines = prompt.body.split("\n").filter(l => l.includes("2."));
    expect(chainLines[0]).toContain("cat <<'EOF'");
    expect(chainLines[0]).toContain("(5 lines)");
    expect(chainLines[0]).not.toContain("line2");
  });

  it("truncates long segment display in chain list", () => {
    const longSegment = "a".repeat(100);
    const prompt = buildPrompt(bashDecision({
      command: `ls && ${longSegment}`,
      segments: ["ls", longSegment],
      nonAllowedSegmentIndices: [],
    }));
    expect(prompt.body).toContain("This chains 2 commands");
    // Segment display should be truncated to 80 chars
    const segLines = prompt.body.split("\n").filter(l => l.includes("2."));
    expect(segLines[0]).toContain("...");
    expect(segLines[0].length).toBeLessThanOrEqual(80 + 5); // "  2. " prefix = 5 chars
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

// ── Bash: includeAlwaysOption logic ────────────────────────────────────────

describe("bash includeAlwaysOption logic", () => {
  it("hasUnsafePattern=true disables Always option", () => {
    const prompt = buildPrompt(bashDecision({
      signatures: ["rm"], needsCommandApproval: true, hasUnsafePattern: true,
    }));
    expect(prompt.includeAlwaysOption).toBe(false);
  });

  it("credentialRule non-null disables Always option", () => {
    const prompt = buildPrompt(bashDecision({
      signatures: ["cat"], needsCommandApproval: true, credentialRule: ".env",
    }));
    expect(prompt.includeAlwaysOption).toBe(false);
  });

  it("hasUnsafePattern AND credentialRule disables Always option", () => {
    const prompt = buildPrompt(bashDecision({
      signatures: ["rm"], needsCommandApproval: true, hasUnsafePattern: true, credentialRule: ".env",
    }));
    expect(prompt.includeAlwaysOption).toBe(false);
  });

  it("no signatures + no outside dirs disables Always option (degenerate case)", () => {
    const prompt = buildPrompt(bashDecision({
      signatures: [], outsideDirs: [], needsCommandApproval: false, needsPathApproval: false,
    }));
    expect(prompt.includeAlwaysOption).toBe(false);
  });

  it("hasUnsafePattern=false + credentialRule=null + has sigs enables Always", () => {
    const prompt = buildPrompt(bashDecision({
      signatures: ["npm test"], needsCommandApproval: true,
    }));
    expect(prompt.includeAlwaysOption).toBe(true);
  });

  it("hasUnsafePattern=false + credentialRule=null + has outside dirs enables Always", () => {
    const prompt = buildPrompt(bashDecision({
      outsideDirs: ["/mnt/data"], needsPathApproval: true, needsCommandApproval: false,
    }));
    expect(prompt.includeAlwaysOption).toBe(true);
  });

  it("no unsafe pattern + only path approval: Always shows path label not command", () => {
    const prompt = buildPrompt(bashDecision({
      outsideDirs: ["/mnt/data"], signatures: ["uv run"],
      needsPathApproval: true, needsCommandApproval: false,
    }));
    expect(prompt.alwaysLabel).toContain("Read /mnt/data/*");
    expect(prompt.alwaysLabel).not.toContain("uv run");
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

  it("blocked paths never reach prompt builder (deniedRule field removed)", () => {
    // deniedRule was removed from FilePromptData — denied paths are blocked before prompt.
    // Warned paths still appear as expected.
    const prompt = buildPrompt(fileDecision({ warnedRule: ".env" }));
    expect(prompt.body).toContain(".env");
  });

  it("shows warned rule match", () => {
    const prompt = buildPrompt(fileDecision({ warnedRule: ".env.*" }));
    expect(prompt.body).toContain(".env.*");
  });

  it("shows warned rule outside cwd", () => {
    const prompt = buildPrompt(fileDecision({ warnedRule: ".aws", outsideDir: "/home/user" }));
    expect(prompt.body).toContain(".aws");
  });

  it("inside-cwd write has no outside-dir warning", () => {
    const prompt = buildPrompt(fileDecision({ action: "Write", isWriteOp: true, outsideDir: null }));
    expect(prompt.title).toBe("Write");
    expect(prompt.body).not.toContain("Outside cwd");
  });

  it("inside-cwd write with credential warn still shows warning", () => {
    const prompt = buildPrompt(fileDecision({ action: "Edit", isWriteOp: true, outsideDir: null, warnedRule: ".env" }));
    expect(prompt.title).toBe("Edit");
    expect(prompt.body).toContain(".env");
    expect(prompt.body).not.toContain("Outside cwd");
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

  it("generates broaderPaths for outside cwd (parents of outsideDir)", () => {
    const prompt = buildPrompt(fileDecision({ action: "Read", outsideDir: "/etc", resolved: "/etc/hosts" }));
    expect(prompt.broaderPaths).toBeDefined();
    // parent of /etc is /
    expect(prompt.broaderPaths!.map(p => p.dir)).toEqual(["/"]);
  });

  it("broaderPaths for outside cwd includes up to 3 levels above outsideDir", () => {
    const prompt = buildPrompt(fileDecision({
      action: "Write",
      isWriteOp: true,
      outsideDir: "/home/user/project/a/b",
      resolved: "/home/user/project/a/b/file.ts",
    }));
    expect(prompt.broaderPaths).toBeDefined();
    expect(prompt.broaderPaths!.map(p => p.dir)).toEqual([
      "/home/user/project/a",
      "/home/user/project",
      "/home/user",
    ]);
    // all labels use path.join so no double slashes
    expect(prompt.broaderPaths![0].label).toBe("Write /home/user/project/a/*");
  });

  it("outside cwd broader paths includeBroaderOption is true when parents exist", () => {
    const prompt = buildPrompt(fileDecision({
      action: "Read",
      outsideDir: "/mnt/data",
      resolved: "/mnt/data/file.txt",
    }));
    expect(prompt.includeBroaderOption).toBe(true);
  });

  it("outside cwd excludes root as broader path (loops stops at root)", () => {
    const prompt = buildPrompt(fileDecision({ action: "Read", outsideDir: "/", resolved: "/hosts" }));
    // When outsideDir is /, no parent beyond root exists → broaderPaths undefined
    expect(prompt.broaderPaths).toBeUndefined();
    expect(prompt.includeBroaderOption).toBe(false);
  });

  it("generates broaderPaths for inside cwd with immediate parent at index 0", () => {
    const prompt = buildPrompt(fileDecision({
      action: "Read",
      outsideDir: null,
      filePath: "analysis/file.ts",
      resolved: "/home/user/project/analysis/file.ts",
    }));
    expect(prompt.broaderPaths).toBeDefined();
    expect(prompt.broaderPaths!.length).toBeGreaterThanOrEqual(1);
    expect(prompt.broaderPaths![0].dir).toBe("/home/user/project/analysis");
    expect(prompt.broaderPaths![0].label).toBe("Read /home/user/project/analysis/*");
  });

  it("broaderPaths includes up to 3 parent levels above immediate parent", () => {
    const prompt = buildPrompt(fileDecision({
      action: "Read",
      outsideDir: null,
      filePath: "a/b/file.ts",
      resolved: "/home/user/project/a/b/file.ts",
    }));
    expect(prompt.broaderPaths).toBeDefined();
    // immediate: /home/user/project/a/b
    // level 1:   /home/user/project/a
    // level 2:   /home/user/project
    // level 3:   /home/user
    expect(prompt.broaderPaths!.map(p => p.dir)).toEqual([
      "/home/user/project/a/b",
      "/home/user/project/a",
      "/home/user/project",
      "/home/user",
    ]);
  });

  it("broaderPaths stops at root", () => {
    const prompt = buildPrompt(fileDecision({
      action: "Read",
      outsideDir: null,
      filePath: "file.ts",
      resolved: "/etc/file.ts",
    }));
    expect(prompt.broaderPaths).toBeDefined();
    // immediate: /etc, then / (root) — stops because dirname(/) === /
    expect(prompt.broaderPaths!.map(p => p.dir)).toEqual([
      "/etc",
      "/",
    ]);
    // labels use path.join so no double slashes
    expect(prompt.broaderPaths!.map(p => p.label)).toEqual([
      "Read /etc/*",
      "Read /*",
    ]);
  });

  it("broaderPaths labels use the action (Read/Write/Edit)", () => {
    const prompt = buildPrompt(fileDecision({
      action: "Write",
      outsideDir: null,
      isWriteOp: true,
      filePath: "src/index.ts",
      resolved: "/home/user/project/src/index.ts",
    }));
    expect(prompt.broaderPaths).toBeDefined();
    for (const bp of prompt.broaderPaths!) {
      expect(bp.label).toMatch(/^Write /);
    }
  });

  it("broaderPaths dir values are absolute paths", () => {
    const prompt = buildPrompt(fileDecision({
      action: "Read",
      outsideDir: null,
      filePath: "src/index.ts",
      resolved: "/home/user/project/src/index.ts",
    }));
    expect(prompt.broaderPaths).toBeDefined();
    for (const bp of prompt.broaderPaths!) {
      expect(bp.dir).toMatch(/^\//);
    }
  });
});

// ── MCP ────────────────────────────────────────────────────────────────────

describe("mcp", () => {
  it("produces title with warning emoji", () => {
    const prompt = buildPrompt(mcpDecision());
    expect(prompt.title).toBe("\u26a0\ufe0f MCP");
  });

  it("shows server, tool, and operation", () => {
    const prompt = buildPrompt(mcpDecision({ server: "exa", tool: "exa_web_search" }));
    expect(prompt.body).toContain("exa");
    expect(prompt.body).toContain("exa_web_search");
    expect(prompt.body).toContain("Calling");
  });

  it("shows args preview when provided", () => {
    const prompt = buildPrompt(mcpDecision({ argsPreview: '{\n  "query": "hello"\n}' }));
    expect(prompt.body).toContain("query");
    expect(prompt.body).toContain("hello");
  });

  it("preserves indent on first args key after stripping braces", () => {
    const prompt = buildPrompt(mcpDecision({ argsPreview: '{\n  "query": "test",\n  "numResults": 10\n}' }));
    const argsSection = prompt.body.split("Arguments:")[1]?.split("\n⚠")[0] ?? "";
    expect(argsSection).toContain('  "query"');
    expect(argsSection).toContain('  "numResults"');
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
  it("handles minimal prompt data gracefully", () => {
    const decision: PromptDecision = {
      kind: "prompt",
      promptData: { type: "bash", command: "ls", cwd: "/tmp", outsideDirs: [], segments: ["ls"], signatures: ["ls"], nonAllowedSegmentIndices: [], riskDangerous: false, riskSeverity: null, riskReasons: [], hasUnsafePattern: false, needsCommandApproval: false, needsPathApproval: false },
    };
    expect(() => buildPrompt(decision)).not.toThrow();
  });

  it("handles empty command", () => {
    const prompt = buildPrompt(bashDecision({ command: "" }));
    expect(prompt.body).toContain("Command:");
  });
});
