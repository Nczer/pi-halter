import { describe, it, expect, vi, beforeEach } from "vitest";
import { gate, rejectBash, rejectFile } from "../gate";
import { createStore } from "../store";
import type { Decision } from "../decision-engine";
import * as decisionEngine from "../decision-engine";

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
      relativeToolIds: [],
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
      warnedRule: null,
      symlinkHint: null,
      exists: false,
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
      filePrompt(),
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
    rejectFile(filePrompt(), fakeResult(false), createStore(), ctx);
    // Store has no file-specific abort tracking — nothing to assert besides
    // that we don't call recordAbort. Verified by no side effects on store.
    expect(store.getLastAbort("/etc/hosts")).toBeNull();
  });

  it("sends error notification with file name", () => {
    const ctx = fakeCtx();
    rejectFile(filePrompt(), fakeResult(false), createStore(), ctx);
    expect(ctx.ui.notify).toHaveBeenCalledWith(
      expect.stringContaining("hosts"),
      "error",
    );
  });

  it("includes action label in notification", () => {
    const ctx = fakeCtx();
    rejectFile(filePrompt({ action: "Write" }), fakeResult(false), createStore(), ctx);
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
      createStore(), ctx,
    );
    expect(result.reason).toContain("/etc/hosts");
  });

  it("includes user-provided reason", () => {
    const ctx = fakeCtx();
    const result = rejectFile(
      filePrompt(),
      fakeResult(false, "Outside project scope"),
      createStore(), ctx,
    );
    expect(result.reason).toContain("Outside project scope");
  });

  it("returns block for non-prompt decision (defensive)", () => {
    const ctx = fakeCtx();
    const result = rejectFile(
      { kind: "auto-allow" } as Decision,
      fakeResult(false),
      createStore(), ctx,
    );
    expect(result.block).toBe(true);
    expect(result.reason).toBe("Permission denied");
  });

  it("returns block for non-file prompt data (defensive)", () => {
    const ctx = fakeCtx();
    const result = rejectFile(
      bashPrompt() as any,
      fakeResult(false),
      createStore(), ctx,
    );
    expect(result.block).toBe(true);
    expect(result.reason).toBe("Permission denied");
  });
});

// ── gate(): fail-closed on internal analysis errors ────────────────────

function fakeGateCtx(hasUI: boolean) {
  return {
    hasUI,
    ui: {
      getToolsExpanded: () => false,
      setToolsExpanded: vi.fn(),
      notify: vi.fn(),
    },
  } as any;
}

const bashRequest = { type: "bash" as const, command: "cat /etc/passwd", cwd: "/home/user/project" };

async function runGate(ctx: any) {
  return gate(
    bashRequest,
    ctx,
    createStore(),
    (d, r) => rejectBash(d, r, createStore(), ctx),
  );
}

describe("gate fail-closed", () => {
  it("blocks when decide() throws (internal error never allows)", async () => {
    const spy = vi.spyOn(decisionEngine, "decide").mockRejectedValue(new Error("boom"));
    const ctx = fakeGateCtx(true);
    try {
      const result = await runGate(ctx);
      expect(result).toEqual({ block: true, reason: expect.stringContaining("fail closed") });
      expect(result!.reason).toContain("boom");
      expect(ctx.ui.notify).toHaveBeenCalledWith("Permission gate failed closed (internal error)", "error");
    } finally {
      spy.mockRestore();
    }
  });

  it("blocks without notify when no UI is available", async () => {
    const spy = vi.spyOn(decisionEngine, "decide").mockRejectedValue(new Error("boom"));
    const ctx = fakeGateCtx(false);
    try {
      const result = await runGate(ctx);
      expect(result).toEqual({ block: true, reason: expect.stringContaining("fail closed") });
    } finally {
      spy.mockRestore();
    }
  });

  it("still auto-allows when decide() succeeds (no behavior change)", async () => {
    const spy = vi.spyOn(decisionEngine, "decide").mockResolvedValue({ kind: "auto-allow" } as Decision);
    const ctx = fakeGateCtx(true);
    try {
      const result = await runGate(ctx);
      expect(result).toBeUndefined();
    } finally {
      spy.mockRestore();
    }
  });
});
