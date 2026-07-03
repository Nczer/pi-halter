import { describe, it, expect, vi, beforeEach } from "vitest";
import { rejectBash, rejectFile, rejectMcp } from "../gate";
import { createStore } from "../store";
import type { Decision } from "../decision-engine";

// ── Helpers ───────────────────────────────────────────────────────────

function fakeResult(allowed: boolean, reason?: string) {
  return { allowed, reason };
}

function fakeCtx() {
  return { ui: { notify: vi.fn() } } as any;
}

function bashPrompt(overrides: Partial<Extract<Extract<Decision, { kind: "prompt" }>["promptData"], { type: "bash" }>> = {}): Decision {
  return {
    kind: "prompt",
    promptData: {
      type: "bash",
      command: "rm -rf /tmp/test",
      cwd: "/home/user/project",
      outsideDirs: [],
      segments: ["rm -rf /tmp/test"],
      signatures: ["rm"],
      nonAllowedSegmentIndices: [0],
      riskDangerous: true,
      riskSeverity: "high",
      riskReasons: ["[System] destructive delete"],
      hasUnsafePattern: true,
      credentialRule: null,
      needsCommandApproval: true,
      needsPathApproval: false,
      ...overrides,
    },
  };
}

function filePrompt(overrides: Partial<Extract<Extract<Decision, { kind: "prompt" }>["promptData"], { type: "file" }>> = {}): Decision {
  return {
    kind: "prompt",
    promptData: {
      type: "file",
      action: "Read",
      filePath: "/etc/hosts",
      resolved: "/etc/hosts",
      cwd: "/home/user/project",
      outsideDir: "/etc",
      isWriteOp: false,
      deniedRule: null,
      warnedRule: null,
      symlinkHint: null,
      ...overrides,
    },
  };
}

function mcpPrompt(overrides: Partial<Extract<Extract<Decision, { kind: "prompt" }>["promptData"], { type: "mcp" }>> = {}): Decision {
  return {
    kind: "prompt",
    promptData: {
      type: "mcp",
      server: "exa",
      tool: "exa_web_search",
      op: "call",
      ...overrides,
    },
  };
}

// ── rejectBash ─────────────────────────────────────────────────────────

describe("rejectBash", () => {
  it("records abort in store", () => {
    const store = createStore();
    const ctx = fakeCtx();
    const result = rejectBash(bashPrompt(), fakeResult(false), store, ctx);
    expect(store.getLastAbort("rm -rf /tmp/test")).toBeTruthy();
    expect(result.block).toBe(true);
  });

  it("sends error notification", () => {
    const store = createStore();
    const ctx = fakeCtx();
    rejectBash(bashPrompt(), fakeResult(false), store, ctx);
    expect(ctx.ui.notify).toHaveBeenCalledWith(
      expect.stringContaining("Permission denied"),
      "error",
    );
  });

  it("includes danger flags in reason for dangerous commands", () => {
    const store = createStore();
    const ctx = fakeCtx();
    const result = rejectBash(bashPrompt({ riskDangerous: true }), fakeResult(false), store, ctx);
    expect(result.reason).toContain("Danger flags");
  });

  it("omits danger flags for non-dangerous commands", () => {
    const store = createStore();
    const ctx = fakeCtx();
    const result = rejectBash(
      bashPrompt({ riskDangerous: false, riskReasons: [], riskSeverity: null }),
      fakeResult(false),
      store,
      ctx,
    );
    expect(result.reason).not.toContain("Danger flags");
  });

  it("includes user-provided reason when available", () => {
    const store = createStore();
    const ctx = fakeCtx();
    const result = rejectBash(bashPrompt(), fakeResult(false, "Too scary"), store, ctx);
    expect(result.reason).toContain("Reason: Too scary");
  });

  it("truncates long commands in reason", () => {
    const store = createStore();
    const ctx = fakeCtx();
    const longCmd = "x".repeat(200);
    const result = rejectBash(
      bashPrompt({ command: longCmd }),
      fakeResult(false),
      store,
      ctx,
    );
    expect(result.reason).toContain(longCmd.slice(0, 120));
    expect(result.reason.length).toBeLessThan(longCmd.length + 100);
  });

  it("returns block for non-prompt decision (defensive)", () => {
    const store = createStore();
    const ctx = fakeCtx();
    const result = rejectBash(
      { kind: "auto-allow" } as Decision,
      fakeResult(false),
      store,
      ctx,
    );
    expect(result.block).toBe(true);
    expect(result.reason).toBe("Permission denied");
  });

  it("returns block for non-bash prompt data (defensive)", () => {
    const store = createStore();
    const ctx = fakeCtx();
    const result = rejectBash(
      mcpPrompt(),
      fakeResult(false),
      store,
      ctx,
    );
    expect(result.block).toBe(true);
    expect(result.reason).toBe("Permission denied");
  });
});

// ── rejectFile ─────────────────────────────────────────────────────────

describe("rejectFile", () => {
  it("does NOT record abort (file accesses are deterministic)", () => {
    const store = createStore();
    const ctx = fakeCtx();
    rejectFile(filePrompt(), fakeResult(false), ctx);
    // Store has no file-specific abort tracking — nothing to assert besides
    // that we don't call recordAbort. Verified by no side effects on store.
    expect(store.getLastAbort("/etc/hosts")).toBeNull();
  });

  it("sends error notification with file name", () => {
    const ctx = fakeCtx();
    rejectFile(filePrompt(), fakeResult(false), ctx);
    expect(ctx.ui.notify).toHaveBeenCalledWith(
      expect.stringContaining("hosts"),
      "error",
    );
  });

  it("includes action label in notification", () => {
    const ctx = fakeCtx();
    rejectFile(filePrompt({ action: "Write" }), fakeResult(false), ctx);
    expect(ctx.ui.notify).toHaveBeenCalledWith(
      expect.stringContaining("write"),
      "error",
    );
  });

  it("includes resolved path in reason", () => {
    const ctx = fakeCtx();
    const result = rejectFile(
      filePrompt({ resolved: "/etc/hosts", filePath: "/etc/hosts" }),
      fakeResult(false),
      ctx,
    );
    expect(result.reason).toContain("/etc/hosts");
  });

  it("includes user-provided reason", () => {
    const ctx = fakeCtx();
    const result = rejectFile(
      filePrompt(),
      fakeResult(false, "Outside project scope"),
      ctx,
    );
    expect(result.reason).toContain("Outside project scope");
  });

  it("returns block for non-prompt decision (defensive)", () => {
    const ctx = fakeCtx();
    const result = rejectFile(
      { kind: "auto-allow" } as Decision,
      fakeResult(false),
      ctx,
    );
    expect(result.block).toBe(true);
    expect(result.reason).toBe("Permission denied");
  });

  it("returns block for non-file prompt data (defensive)", () => {
    const ctx = fakeCtx();
    const result = rejectFile(
      bashPrompt() as any,
      fakeResult(false),
      ctx,
    );
    expect(result.block).toBe(true);
    expect(result.reason).toBe("Permission denied");
  });
});

// ── rejectMcp ──────────────────────────────────────────────────────────

describe("rejectMcp", () => {
  it("sends error notification with tool name", () => {
    const ctx = fakeCtx();
    rejectMcp(mcpPrompt(), fakeResult(false), ctx);
    expect(ctx.ui.notify).toHaveBeenCalledWith(
      expect.stringContaining("exa_web_search"),
      "error",
    );
  });

  it("includes server name in reason", () => {
    const ctx = fakeCtx();
    const result = rejectMcp(
      mcpPrompt({ server: "context7", tool: "resolve-library-id" }),
      fakeResult(false),
      ctx,
    );
    expect(result.reason).toContain("context7");
    expect(result.reason).toContain("resolve-library-id");
  });

  it("includes user-provided reason", () => {
    const ctx = fakeCtx();
    const result = rejectMcp(
      mcpPrompt(),
      fakeResult(false, "Don't trust this server"),
      ctx,
    );
    expect(result.reason).toContain("Don't trust this server");
  });

  it("returns block for non-prompt decision (defensive)", () => {
    const ctx = fakeCtx();
    const result = rejectMcp(
      { kind: "auto-allow" } as Decision,
      fakeResult(false),
      ctx,
    );
    expect(result.block).toBe(true);
    expect(result.reason).toBe("Permission denied");
  });

  it("returns block for non-mcp prompt data (defensive)", () => {
    const ctx = fakeCtx();
    const result = rejectMcp(
      bashPrompt() as any,
      fakeResult(false),
      ctx,
    );
    expect(result.block).toBe(true);
    expect(result.reason).toBe("Permission denied");
  });
});
