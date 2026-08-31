import { describe, expect, it } from "vitest";
import { buildPrompt, pdTargetLabel, summarizePrompt } from "../prompt-builder";
import type { PromptDecision, BashPromptData, FilePromptData } from "../decision-engine";

// ── Helpers ────────────────────────────────────────────────────────────────

function bashDecision(overrides: Partial<BashPromptData> = {}): PromptDecision {
  return {
    kind: "prompt",
    promptData: {
      type: "bash",
      command: "ls -la",
      cwd: "/home/user/project",
      outsideDirs: [],
      segments: ["ls -la"],
      signatures: ["ls"],
      relativeToolIds: [],
      nonAllowedSegmentIndices: [],
      riskDangerous: false,
      riskSeverity: null,
      riskReasons: [],
      hasUnsafePattern: false,
      credentialRule: null,
      needsCommandApproval: false,
      needsPathApproval: false,
      ...overrides,
    },
  };
}

function fileDecision(overrides: Partial<FilePromptData> = {}): PromptDecision {
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

  it("root-only path prompt offers no dir Always tier (never grant /)", () => {
    const prompt = buildPrompt(bashDecision({
      command: "find / -name tty.js",
      signatures: [],
      outsideDirs: ["/"],
      needsPathApproval: true,
      needsCommandApproval: false,
    }));
    expect(prompt.includeAlwaysOption).toBe(false);
    expect(prompt.includePathsOption).toBe(false);
    expect(prompt.alwaysLabel).toBe("");
  });

  it("mixed root+dir path prompt grants only the dir, never the root", () => {
    const prompt = buildPrompt(bashDecision({
      command: "ls / /etc",
      outsideDirs: ["/", "/etc"],
      needsPathApproval: true,
      needsCommandApproval: false,
    }));
    expect(prompt.includeAlwaysOption).toBe(true);
    expect(prompt.alwaysLabel).toBe("Read /etc/*");
  });

  it("title is Bash + Path when both need approval", () => {
    const prompt = buildPrompt(bashDecision({ outsideDirs: ["/etc"], signatures: ["rm"], needsCommandApproval: true, needsPathApproval: true }));
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

  it("caps long chain listings to the flagged segments (no off-screen prompts)", () => {
    const segs = Array.from({ length: 30 }, (_, i) => `echo part ${i}`);
    segs[9] = 'head -30 ~/.config/joplin-desktop/userchrome.css';
    const prompt = buildPrompt(bashDecision({
      command: segs.join("\n"),
      segments: segs,
      nonAllowedSegmentIndices: [9],
      needsPathApproval: true,
      outsideDirs: ["/home/nczer/.config/joplin-desktop"],
    }));
    expect(prompt.body).toContain("This chains 30 commands");
    expect(prompt.body).toContain("10. ⚠️ head -30 ~/.config/joplin-desktop/userchrome.css");
    expect(prompt.body).toContain("29 unflagged segments omitted");
    expect(prompt.body).not.toContain("1. echo part 0");
    expect(prompt.body).not.toContain("30. echo part 29");
  });

  it("long unflagged chain shows a head/tail sample", () => {
    const segs = Array.from({ length: 12 }, (_, i) => `echo part ${i}`);
    const prompt = buildPrompt(bashDecision({
      command: segs.join("\n"),
      segments: segs,
      nonAllowedSegmentIndices: [],
      needsPathApproval: true,
      outsideDirs: ["/etc"],
    }));
    expect(prompt.body).toContain("This chains 12 commands");
    expect(prompt.body).toContain("1. echo part 0");
    expect(prompt.body).toContain("4. echo part 3");
    expect(prompt.body).toContain("(+6 more)");
    expect(prompt.body).toContain("11. echo part 10");
    expect(prompt.body).toContain("12. echo part 11");
    expect(prompt.body).not.toContain("5. echo part 4");
  });

  it("short chains (≤8) still list every segment", () => {
    const segs = Array.from({ length: 8 }, (_, i) => `echo part ${i}`);
    const prompt = buildPrompt(bashDecision({
      command: segs.join("\n"),
      segments: segs,
      nonAllowedSegmentIndices: [3],
    }));
    expect(prompt.body).toContain("This chains 8 commands");
    expect(prompt.body).toContain("1. echo part 0");
    expect(prompt.body).toContain("4. ⚠️ echo part 3");
    expect(prompt.body).toContain("8. echo part 7");
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
    const prompt = buildPrompt(bashDecision({ outsideDirs: ["/etc"], signatures: ["rm"], needsCommandApproval: true, needsPathApproval: true }));
    expect(prompt.alwaysLabel).toBe("rm *");
  });

  it("alwaysPathsLabel shows path text when both need approval", () => {
    const prompt = buildPrompt(bashDecision({ outsideDirs: ["/etc"], signatures: ["rm"], needsCommandApproval: true, needsPathApproval: true }));
    expect(prompt.alwaysPathsLabel).toBe("Read /etc/*");
  });

  it("alwaysPathsLabel is undefined when only command needs approval", () => {
    const prompt = buildPrompt(bashDecision({ signatures: ["rm"], needsCommandApproval: true, needsPathApproval: false }));
    expect(prompt.alwaysPathsLabel).toBeUndefined();
  });

  it("alwaysBroaderLabel shows parent command when broader option enabled", () => {
    const prompt = buildPrompt(bashDecision({ command: "npm test", signatures: ["npm test"], needsCommandApproval: true }));
    expect(prompt.alwaysBroaderLabel).toBe("npm *");
  });

  it("alwaysBroaderLabel is undefined when broader option disabled", () => {
    const prompt = buildPrompt(bashDecision({ signatures: ["rm"], needsCommandApproval: true }));
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
    const prompt = buildPrompt(bashDecision({ outsideDirs: ["/etc"], signatures: ["rm"], needsCommandApproval: true, needsPathApproval: true }));
    expect(prompt.tier2Everything.body).toContain("rm *");
    expect(prompt.tier2Everything.body).toContain("/etc/*");
  });

  it("tier2 paths option exists when both command and path approval needed", () => {
    const prompt = buildPrompt(bashDecision({ outsideDirs: ["/etc"], signatures: ["rm"], needsCommandApproval: true, needsPathApproval: true }));
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

  it("hasUnsafePattern disables command tier but keeps paths tier (decoupled)", () => {
    // The heredoc-to-interpreter class: unsafe command + outside-base dir.
    // A dir grant can never auto-allow the unsafe command, so the paths-only
    // tier stays offerable even though the command tier is suppressed.
    const prompt = buildPrompt(bashDecision({
      command: "uv run --with pymupdf python - <<'EOF'\n...\nEOF",
      signatures: ["uv run"], needsCommandApproval: true, hasUnsafePattern: true,
      outsideDirs: ["/mnt/Ndr/Samples/Handbook"], needsPathApproval: true,
    }));
    expect(prompt.includeAlwaysOption).toBe(false);
    expect(prompt.includePathsOption).toBe(true);
    expect(prompt.alwaysPathsLabel).toBe("Read /mnt/Ndr/Samples/Handbook/*");
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

  it("outside cwd: no broader option when the only parent is the root", () => {
    // parent of /etc is / — a root grant is never offered (one click must
    // not hand out the whole disk); the file-level tiers remain.
    const prompt = buildPrompt(fileDecision({ action: "Read", outsideDir: "/etc", resolved: "/etc/hosts" }));
    expect(prompt.broaderPaths).toBeUndefined();
    expect(prompt.includeBroaderOption).toBe(false);
    expect(prompt.includeFileOption).toBe(true);
    expect(prompt.includeAlwaysOption).toBe(true);
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

  it("a file directly under root offers file-level tiers only (never a root grant)", () => {
    const prompt = buildPrompt(fileDecision({ action: "Write", isWriteOp: true, outsideDir: "/", resolved: "/hosts" }));
    // primary label is the file, not "Write /*" (the rule is sanitized too)
    expect(prompt.alwaysLabel).toBe("Write hosts");
    expect(prompt.tier2Everything.body).toContain("/hosts");
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

  it("broaderPaths stops before the root", () => {
    const prompt = buildPrompt(fileDecision({
      action: "Read",
      outsideDir: null,
      filePath: "file.ts",
      resolved: "/etc/file.ts",
    }));
    expect(prompt.broaderPaths).toBeDefined();
    // immediate: /etc — then root, which is never offered
    expect(prompt.broaderPaths!.map(p => p.dir)).toEqual([
      "/etc",
    ]);
    // labels use path.join so no double slashes
    expect(prompt.broaderPaths!.map(p => p.label)).toEqual([
      "Read /etc/*",
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

// ── Edge cases ─────────────────────────────────────────────────────────────

describe("edge cases", () => {
  it("handles minimal prompt data gracefully", () => {
    const decision: PromptDecision = {
      kind: "prompt",
      promptData: { type: "bash", command: "ls", cwd: "/tmp", outsideDirs: [], segments: ["ls"], signatures: ["ls"], relativeToolIds: [], nonAllowedSegmentIndices: [], riskDangerous: false, riskSeverity: null, riskReasons: [], hasUnsafePattern: false, credentialRule: null, needsCommandApproval: false, needsPathApproval: false },
    };
    expect(() => buildPrompt(decision)).not.toThrow();
  });

  it("handles empty command", () => {
    const prompt = buildPrompt(bashDecision({ command: "" }));
    expect(prompt.body).toContain("Command:");
  });
});

describe("cwd-bound relative tool grants in the prompt", () => {
  it("offers Always when only a relative-tool identity exists (empty signatures)", () => {
    const prompt = buildPrompt(bashDecision({
      signatures: [],
      relativeToolIds: [{ sig: "./node_modules/.bin/tsc --noEmit", base: "/home/user/project" }],
      needsCommandApproval: true,
    }));
    expect(prompt.includeAlwaysOption).toBe(true);
    expect(prompt.alwaysLabel).toContain("./node_modules/.bin/tsc --noEmit");
    expect(prompt.alwaysLabel).toContain("(this cwd)");
  });

  it("lists relative tools in the tier-2 body, deduped against signatures", () => {
    const prompt = buildPrompt(bashDecision({
      signatures: ["./node_modules/.bin/unknown-tool", "rm"],
      relativeToolIds: [
        { sig: "./node_modules/.bin/unknown-tool", base: "/home/user/project" },
        { sig: "./node_modules/.bin/tsc --noEmit", base: "/home/user/project" },
      ],
      needsCommandApproval: true,
    }));
    const tier2 = prompt.tier2Everything;
    expect(tier2).toBeDefined();
    if (tier2) {
      expect(tier2.body).toContain("rm *");
      expect(tier2.body).toContain("./node_modules/.bin/unknown-tool *");
      expect(tier2.body).toContain("./node_modules/.bin/tsc --noEmit (this cwd)");
      // deduped: unknown-tool is already a sig bullet — not repeated cwd-bound
      expect(tier2.body.match(/unknown-tool/g)?.length).toBe(1);
      expect(tier2.body.match(/tsc --noEmit/g)?.length).toBe(1);
    }
  });
});

// ── pdTargetLabel / summarizePrompt (prompt-shaped labels) ──

describe("pdTargetLabel", () => {
  it("one label shape per prompt type (widgets + audit + dspat stats)", () => {
    const bash = bashDecision();
    expect(pdTargetLabel(bash.promptData)).toBe("ls -la");
    const file = {
      kind: "prompt" as const,
      promptData: {
        type: "file" as const,
        action: "Write",
        filePath: "a.md",
        resolved: "/home/u/p/a.md",
        cwd: "/home/u/p",
        outsideDir: null,
        isWriteOp: true,
        warnedRule: null,
        symlinkHint: null,
        exists: false,
      },
    };
    expect(pdTargetLabel(file.promptData)).toBe("Write /home/u/p/a.md");
  });
});

describe("summarizePrompt", () => {
  it("names the cwd-bound grant identity for relative tools (unlisted)", () => {
    // signatures empty + relativeToolIds set = the unlisted case (no segment
    // carries a namable sig, e.g. relative binary with allowlisted basename).
    const d = bashDecision({
      signatures: [],
      relativeToolIds: [{ sig: "./node_modules/.bin/unknown-tool", base: "/home/user/project" }],
      needsCommandApproval: true,
    });
    expect(summarizePrompt(d)).toBe("cmd ./node_modules/.bin/unknown-tool (unlisted)");
  });

  it("file prompts name outsideDir as the location, not the thing the file is outside of", () => {
    const d = fileDecision({
      action: "Write",
      isWriteOp: true,
      filePath: "x.ts",
      resolved: "/etc/config/x.ts",
      outsideDir: "/etc/config",
    });
    expect(summarizePrompt(d)).toBe("file write outside cwd (/etc/config)");
  });
});

describe("buildPrompt: unresolved references", () => {
  it("lists the tokens that could not be statically bound", () => {
    const d = bashDecision({
      outsideDirs: ["/etc"],
      needsPathApproval: true,
      relativeToolIds: [],
      unresolved: [{ token: "$f", reason: "var" }, { token: "$x/sub", reason: "base" }],
    });
    const b = buildPrompt(d);
    expect(b.body).toContain("Unresolved references");
    expect(b.body).toContain("  \u2022 $f\n");
    expect(b.body).toContain("$x/sub \u2014 working directory not statically known");
  });

  it("omits the section when everything resolved", () => {
    const d = bashDecision({ outsideDirs: ["/etc"], needsPathApproval: true, relativeToolIds: [] });
    expect(buildPrompt(d).body).not.toContain("Unresolved references");
  });

  it("never offers a sentinel dir in the Always grant label", () => {
    const d = bashDecision({
      outsideDirs: ["/etc", "<unresolved-cwd>"],
      needsPathApproval: true,
      relativeToolIds: [],
    });
    const b = buildPrompt(d);
    // The marker stays visible in the body (a base the cd chain could not
    // resolve), but the grant covers only the real dir.
    expect(b.body).toContain("<unresolved-cwd>");
    expect(b.alwaysLabel).toBe("Read /etc/*");
    expect(b.alwaysLabel).not.toContain("<");
  });
});

describe("bash prompt: LLM/confirmed token resolutions", () => {
  const token = "/home/u/ext/$e/*.ts";

  it("renders a `→ LLM:` line under a resolved token (first 3 dirs + N more)", () => {
    const prompt = buildPrompt(
      bashDecision({
        needsPathApproval: true,
        outsideDirs: ["/home/u/ext/$e"],
        unresolved: [{ token, reason: "var" }],
      }),
      new Map([[token, ["/home/u/ext/a", "/home/u/ext/b", "/home/u/ext/c", "/home/u/ext/d", "/home/u/ext/e"]]]),
    );
    expect(prompt.body).toContain("→ LLM: /home/u/ext/a, /home/u/ext/b, /home/u/ext/c (+2 more)");
  });

  it("renders `→ confirmed:` for user-confirmed resolutions", () => {
    const prompt = buildPrompt(
      bashDecision({
        needsPathApproval: true,
        outsideDirs: ["/home/u/ext/$e"],
        unresolved: [{ token, reason: "var" }],
      }),
      new Map([[token, ["/home/u/ext/a"]]]),
      new Set([token]),
    );
    expect(prompt.body).toContain("→ confirmed: /home/u/ext/a");
    expect(prompt.body).not.toContain("→ LLM:");
  });

  it("unresolved tokens render shortened when long", () => {
    const long = "/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q/r/s/t/u/v/w/x/y/z/$e/file.txt";
    const prompt = buildPrompt(
      bashDecision({
        needsPathApproval: true,
        outsideDirs: [],
        unresolved: [{ token: long, reason: "var" }],
      }),
    );
    expect(prompt.body).toContain(long.slice(0, 59) + "…");
    expect(prompt.body).not.toContain(long);
  });

  it("resolver dirs join the paths grant (pathGrantDirs, labels, option)", () => {
    const prompt = buildPrompt(
      bashDecision({
        needsCommandApproval: true,
        needsPathApproval: true,
        signatures: ["grep"],
        outsideDirs: ["/home/u/ext/$e"],
        unresolved: [{ token, reason: "var" }],
      }),
      new Map([[token, ["/home/u/ext/a", "/home/u/ext/b"]]]),
    );
    expect(prompt.pathGrantDirs).toEqual(["/home/u/ext/$e", "/home/u/ext/a", "/home/u/ext/b"]);
    expect(prompt.resolverDirs).toEqual(["/home/u/ext/a", "/home/u/ext/b"]);
    expect(prompt.includePathsOption).toBe(true);
    expect(prompt.alwaysPathsLabel).toContain("Read /home/u/ext/a/*");
    expect(prompt.alwaysPathsLabel).toContain("Read /home/u/ext/b/*");
    expect(prompt.tier2Paths?.body).toContain("/home/u/ext/a/*");
  });

  it("resolver dirs alone enable the paths option (no concrete dirs)", () => {
    const prompt = buildPrompt(
      bashDecision({
        needsCommandApproval: true,
        needsPathApproval: true,
        signatures: ["grep"],
        outsideDirs: [],
        unresolved: [{ token, reason: "var" }],
      }),
      new Map([[token, ["/home/u/ext/a"]]]),
    );
    expect(prompt.pathGrantDirs).toEqual(["/home/u/ext/a"]);
    expect(prompt.includePathsOption).toBe(true);
    // Without resolutions the same prompt has nothing to grant.
    const bare = buildPrompt(
      bashDecision({
        needsCommandApproval: true,
        needsPathApproval: true,
        signatures: ["grep"],
        outsideDirs: [],
        unresolved: [{ token, reason: "var" }],
      }),
    );
    expect(bare.pathGrantDirs).toEqual([]);
    expect(bare.includePathsOption).toBe(false);
  });

  it("filters root and sentinel dirs from resolutions", () => {
    const prompt = buildPrompt(
      bashDecision({
        needsPathApproval: true,
        outsideDirs: [],
        unresolved: [{ token, reason: "var" }],
      }),
      new Map([[token, ["/", "<unresolved-cwd>", "/ok/dir"]]]),
    );
    expect(prompt.pathGrantDirs).toEqual(["/ok/dir"]);
    expect(prompt.resolverDirs).toEqual(["/ok/dir"]);
  });

  it("summarizePrompt shortens unresolved tokens", () => {
    const long = "/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q/r/s/t/u/v/w/x/y/z/$e/file.txt";
    const decision = bashDecision({
      needsPathApproval: true,
      outsideDirs: ["/x"],
      unresolved: [{ token: long, reason: "var" }],
    });
    const s = summarizePrompt(decision);
    expect(s).toContain(long.slice(0, 59) + "…");
    expect(s).not.toContain(long);
  });
});
