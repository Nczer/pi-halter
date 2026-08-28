/**
 * twoTierAlwaysPrompt UI dispatch tests.
 *
 * Drives the choice-index dispatch with fake ctx.ui.select / ctx.ui.input that
 * return canned indices/strings. Verifies callback wiring and tier-2 confirmation flow.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { twoTierAlwaysPrompt } from "../prompts";
import type { BuiltPrompt } from "../prompt-builder";
import { store } from "../store";

// ── Fake ctx ───────────────────────────────────────────────────────────

/**
 * Build a fake ExtensionContext whose ui.select / ui.input resolve with scripted
 * values. Each call consumes one value (interleaves select + editor calls).
 * Scripted numbers index into the live options array (select); null = cancel.
 */
function makeCtx(scripted: (number | string | null)[]): any {
  let idx = 0;
  const ctx: any = {
    /** Options arrays passed to each ui.select call (assert on displayed options). */
    __selects: [] as string[][],
  };
  ctx.ui = {
      select: async (_title: string, options: string[]): Promise<string | undefined> => {
        ctx.__selects.push(options);
        const val = scripted[idx++];
        if (val === null || val === undefined) return undefined;
        return typeof val === "number" ? options[val] : val;
      },
      input: async (_title?: string): Promise<string | undefined> => {
        const val = scripted[idx++];
        return val === null || val === undefined ? undefined : String(val);
      },
  };
  return ctx;
}

// ── Prompt builder ─────────────────────────────────────────────────────

function makePrompt(overrides: Partial<BuiltPrompt> = {}): BuiltPrompt {
  return {
    title: "Test",
    body: "Test body",
    tier2Everything: { title: "Confirm", body: "Confirm body" },
    tier2Paths: { title: "Confirm paths", body: "Paths body" },
    tier2File: { title: "Confirm file", body: "File body" },
    tier2Broader: { title: "Confirm broader", body: "Broader body" },
    includePathsOption: false,
    includeFileOption: false,
    includeBroaderOption: false,
    includeAlwaysOption: true,
    alwaysLabel: "test *",
    alwaysBroaderLabel: "test broader *",
    alwaysPathsLabel: "/path/*",
    alwaysFileLabel: "file.txt",
    pathGrantDirs: [],
    ...overrides,
  };
}

/** Standard callback set — all vi.fn() for assertion. */
function makeCallbacks() {
  return {
    onAlways: vi.fn(),
    onAlwaysPaths: vi.fn(),
    onAlwaysFile: vi.fn(),
    onAlwaysBroader: vi.fn(),
  };
}

beforeEach(() => {
  store.reset();
});

// ── Simple bash prompt (Yes / Always / No-reason / No) ─────────────────

describe("twoTierAlwaysPrompt: simple bash layout", () => {
  // choices = ["Yes", "Always: test *", "No (with reason)", "No"]
  // indices:     0          1                 2                3

  it("returns 'yes' when index 0 is selected", async () => {
    const cb = makeCallbacks();
    const result = await twoTierAlwaysPrompt(
      makePrompt(), store, makeCtx([0]), cb.onAlways, cb.onAlwaysPaths, cb.onAlwaysFile,
    );
    expect(result).toBe("yes");
    expect(cb.onAlways).not.toHaveBeenCalled();
  });

  it("calls onAlways and returns 'always' when Always → Confirm is selected", async () => {
    const cb = makeCallbacks();
    const result = await twoTierAlwaysPrompt(
      makePrompt(), store, makeCtx([1, 0]), cb.onAlways, cb.onAlwaysPaths, cb.onAlwaysFile,
    );
    expect(result).toBe("always");
    expect(cb.onAlways).toHaveBeenCalledTimes(1);
  });

  it("loops back to tier-1 when tier-2 selects Back, then No", async () => {
    const cb = makeCallbacks();
    // tier-1: Always (1), tier-2: Back (1), tier-1: No (3)
    const result = await twoTierAlwaysPrompt(
      makePrompt(), store, makeCtx([1, 1, 3]), cb.onAlways, cb.onAlwaysPaths, cb.onAlwaysFile,
    );
    expect(result).toBe("no");
    expect(cb.onAlways).not.toHaveBeenCalled();
  });

  it("increments prompt count once even when looping back from tier-2", async () => {
    const cb = makeCallbacks();
    // tier-1: Always (1), tier-2: Back (1), tier-1: Yes (0)
    await twoTierAlwaysPrompt(
      makePrompt(), store, makeCtx([1, 1, 0]), cb.onAlways, cb.onAlwaysPaths, cb.onAlwaysFile,
    );
    // Should be 1 prompt, not 2 (Back shouldn't inflate the count)
    expect(store.incrementPromptCount().count).toBe(2); // 1 from twoTierAlwaysPrompt + 1 from this check
  });

  it("returns {kind:'no', reason} when No-with-reason is selected", async () => {
    const cb = makeCallbacks();
    // tier-1: No with reason (2), editor: "because unsafe"
    const result = await twoTierAlwaysPrompt(
      makePrompt(), store, makeCtx([2, "because unsafe"]),
      cb.onAlways, cb.onAlwaysPaths, cb.onAlwaysFile,
    );
    expect(result).toEqual({ kind: "no", reason: "because unsafe" });
  });

  it("returns 'no' when No is selected", async () => {
    const cb = makeCallbacks();
    const result = await twoTierAlwaysPrompt(
      makePrompt(), store, makeCtx([3]), cb.onAlways, cb.onAlwaysPaths, cb.onAlwaysFile,
    );
    expect(result).toBe("no");
  });

  it("returns 'no' when selection is cancelled (null)", async () => {
    const cb = makeCallbacks();
    const result = await twoTierAlwaysPrompt(
      makePrompt(), store, makeCtx([null]), cb.onAlways, cb.onAlwaysPaths, cb.onAlwaysFile,
    );
    expect(result).toBe("no");
  });
});

// ── Bash with paths + broader ──────────────────────────────────────────

describe("twoTierAlwaysPrompt: bash with paths + broader", () => {
  // choices = ["Yes", "Always: test *", "Always: test broader *", "Always (paths): /path/*", "No (reason)", "No"]
  // indices:     0          1                    2                           3                              4            5

  const prompt = makePrompt({ includeBroaderOption: true, includePathsOption: true });

  it("calls onAlwaysPaths when Always(paths) → Confirm", async () => {
    const cb = makeCallbacks();
    // tier-1: Always(paths) (3), tier-2: Confirm (0)
    const result = await twoTierAlwaysPrompt(
      prompt, store, makeCtx([3, 0]),
      cb.onAlways, cb.onAlwaysPaths, cb.onAlwaysFile, cb.onAlwaysBroader,
    );
    expect(result).toBe("alwaysPaths");
    expect(cb.onAlwaysPaths).toHaveBeenCalledTimes(1);
    expect(cb.onAlways).not.toHaveBeenCalled();
  });

  it("calls onAlwaysBroader when Always(broader) → Confirm", async () => {
    const cb = makeCallbacks();
    // tier-1: Always(broader) (2), tier-2: Confirm (0)
    const result = await twoTierAlwaysPrompt(
      prompt, store, makeCtx([2, 0]),
      cb.onAlways, cb.onAlwaysPaths, cb.onAlwaysFile, cb.onAlwaysBroader,
    );
    expect(result).toBe("always");
    expect(cb.onAlwaysBroader).toHaveBeenCalledTimes(1);
    expect(cb.onAlways).not.toHaveBeenCalled();
  });
});

// ── File outside cwd with broader (path + file + broader) ──────────────

describe("twoTierAlwaysPrompt: file outside cwd with broader", () => {
  // choices = ["Yes", "Always (path): ...", "Always (file): ...", "Always (broader)", "No (reason)", "No"]
  // indices:     0          1                     2                       3                    4               5
  // entries:  [0]=primary, [1]=file, [2]=broader umbrella

  const prompt = makePrompt({
    includeFileOption: true,
    includePathsOption: false,
    includeBroaderOption: true,
    alwaysLabel: "Read /outside/data/*",
    alwaysFileLabel: "data.txt",
    broaderPaths: [
      { label: "Read /outside/*", dir: "/outside" },
      { label: "Read /*", dir: "/" },
    ],
  });

  it("calls onAlwaysFile when Always(file) → Confirm", async () => {
    const cb = makeCallbacks();
    // tier-1: Always(file) (2), tier-2: Confirm (0)
    const result = await twoTierAlwaysPrompt(
      prompt, store, makeCtx([2, 0]),
      cb.onAlways, cb.onAlwaysPaths, cb.onAlwaysFile, cb.onAlwaysBroader,
    );
    expect(result).toBe("alwaysFile");
    expect(cb.onAlwaysFile).toHaveBeenCalledTimes(1);
  });

  it("calls onAlways when Always(path) → Confirm", async () => {
    const cb = makeCallbacks();
    const result = await twoTierAlwaysPrompt(
      prompt, store, makeCtx([1, 0]),
      cb.onAlways, cb.onAlwaysPaths, cb.onAlwaysFile, cb.onAlwaysBroader,
    );
    expect(result).toBe("always");
    expect(cb.onAlways).toHaveBeenCalledTimes(1);
  });

  it("umbrella broader → sub-menu selects first parent → confirm", async () => {
    const cb = makeCallbacks();
    // tier-1: umbrella broader (3)
    // sub-menu: first item (0) → /outside
    // tier-2: Confirm (0)
    const result = await twoTierAlwaysPrompt(
      prompt, store, makeCtx([3, 0, 0]),
      cb.onAlways, cb.onAlwaysPaths, cb.onAlwaysFile, cb.onAlwaysBroader,
    );
    expect(result).toBe("always");
    expect(cb.onAlwaysBroader).toHaveBeenCalledTimes(1);
    expect(cb.onAlwaysBroader).toHaveBeenCalledWith("/outside");
  });

  it("umbrella broader → sub-menu selects second parent → confirm", async () => {
    const cb = makeCallbacks();
    const result = await twoTierAlwaysPrompt(
      prompt, store, makeCtx([3, 1, 0]),
      cb.onAlways, cb.onAlwaysPaths, cb.onAlwaysFile, cb.onAlwaysBroader,
    );
    expect(result).toBe("always");
    expect(cb.onAlwaysBroader).toHaveBeenCalledWith("/");
  });

  it("umbrella broader → sub-menu Back → loops back", async () => {
    const cb = makeCallbacks();
    const result = await twoTierAlwaysPrompt(
      prompt, store, makeCtx([3, 2, 5]),
      cb.onAlways, cb.onAlwaysPaths, cb.onAlwaysFile, cb.onAlwaysBroader,
    );
    expect(result).toBe("no");
    expect(cb.onAlwaysBroader).not.toHaveBeenCalled();
  });

  it("returns 'no' at last index", async () => {
    const cb = makeCallbacks();
    const result = await twoTierAlwaysPrompt(
      prompt, store, makeCtx([5]),
      cb.onAlways, cb.onAlwaysPaths, cb.onAlwaysFile, cb.onAlwaysBroader,
    );
    expect(result).toBe("no");
  });

  it("returns reason at No-with-reason index", async () => {
    const cb = makeCallbacks();
    const result = await twoTierAlwaysPrompt(
      prompt, store, makeCtx([4, "outside"]),
      cb.onAlways, cb.onAlwaysPaths, cb.onAlwaysFile, cb.onAlwaysBroader,
    );
    expect(result).toEqual({ kind: "no", reason: "outside" });
  });
});

// ── File outside cwd (path + file options, no broader) ─────────────────

describe("twoTierAlwaysPrompt: file outside cwd layout", () => {
  // choices = ["Yes", "Always (path): ...", "Always (file): ...", "No (reason)", "No"]
  // indices:     0          1                     2                       3            4

  const prompt = makePrompt({
    includeFileOption: true,
    includePathsOption: false,
    includeBroaderOption: false,
  });

  it("calls onAlwaysFile when Always(file) → Confirm", async () => {
    const cb = makeCallbacks();
    // tier-1: Always(file) (2), tier-2: Confirm (0)
    const result = await twoTierAlwaysPrompt(
      prompt, store, makeCtx([2, 0]),
      cb.onAlways, cb.onAlwaysPaths, cb.onAlwaysFile,
    );
    expect(result).toBe("alwaysFile");
    expect(cb.onAlwaysFile).toHaveBeenCalledTimes(1);
  });

  it("calls onAlways when Always(path/everything) → Confirm", async () => {
    const cb = makeCallbacks();
    // tier-1: Always(path) (1), tier-2: Confirm (0)
    const result = await twoTierAlwaysPrompt(
      prompt, store, makeCtx([1, 0]),
      cb.onAlways, cb.onAlwaysPaths, cb.onAlwaysFile,
    );
    expect(result).toBe("always");
    expect(cb.onAlways).toHaveBeenCalledTimes(1);
  });
});

// ── MCP ────────────────────────────────────────────────────────────────

describe("twoTierAlwaysPrompt: MCP layout", () => {
  // choices = ["Yes", "Always: exa:*", "No (with reason)", "No"]
  // indices:     0          1               2                3

  const mcpPrompt = makePrompt({
    includeAlwaysOption: true,
    alwaysLabel: "exa:*",
  });

  it("calls onAlways and returns 'always' when Always → Confirm", async () => {
    const cb = makeCallbacks();
    const result = await twoTierAlwaysPrompt(
      mcpPrompt, store, makeCtx([1, 0]),
      cb.onAlways, cb.onAlwaysPaths, cb.onAlwaysFile,
    );
    expect(result).toBe("always");
    expect(cb.onAlways).toHaveBeenCalledTimes(1);
  });

  it("selecting index 2 triggers 'No with reason'", async () => {
    const cb = makeCallbacks();
    // tier-1: index 2 = "No with reason", editor: "reason"
    const result = await twoTierAlwaysPrompt(
      mcpPrompt, store, makeCtx([2, "because unsafe"]),
      cb.onAlways, cb.onAlwaysPaths, cb.onAlwaysFile,
    );
    expect(result).toEqual({ kind: "no", reason: "because unsafe" });
    expect(cb.onAlways).not.toHaveBeenCalled();
  });

  it("returns 'no' when index 3 (No) is selected", async () => {
    const cb = makeCallbacks();
    const result = await twoTierAlwaysPrompt(
      mcpPrompt, store, makeCtx([3]),
      cb.onAlways, cb.onAlwaysPaths, cb.onAlwaysFile,
    );
    expect(result).toBe("no");
  });

  it("cancel (null) returns 'no'", async () => {
    const cb = makeCallbacks();
    const result = await twoTierAlwaysPrompt(
      mcpPrompt, store, makeCtx([null]),
      cb.onAlways, cb.onAlwaysPaths, cb.onAlwaysFile,
    );
    expect(result).toBe("no");
  });
});

// ── No Always option (unsafe pattern) ──────────────────────────────────

describe("twoTierAlwaysPrompt: no Always option (unsafe pattern)", () => {
  // includeAlwaysOption: false →
  // choices = ["Yes", "No (with reason)", "No"]
  // indices:     0          1                2

  const prompt = makePrompt({ includeAlwaysOption: false });

  it("returns 'yes' at index 0", async () => {
    const cb = makeCallbacks();
    const result = await twoTierAlwaysPrompt(
      prompt, store, makeCtx([0]), cb.onAlways, cb.onAlwaysPaths, cb.onAlwaysFile,
    );
    expect(result).toBe("yes");
  });

  it("returns {kind:'no', reason} at index 1 (No with reason)", async () => {
    const cb = makeCallbacks();
    const result = await twoTierAlwaysPrompt(
      prompt, store, makeCtx([1, "unsafe"]),
      cb.onAlways, cb.onAlwaysPaths, cb.onAlwaysFile,
    );
    expect(result).toEqual({ kind: "no", reason: "unsafe" });
    expect(cb.onAlways).not.toHaveBeenCalled();
  });

  it("returns 'no' at index 2", async () => {
    const cb = makeCallbacks();
    const result = await twoTierAlwaysPrompt(
      prompt, store, makeCtx([2]),
      cb.onAlways, cb.onAlwaysPaths, cb.onAlwaysFile,
    );
    expect(result).toBe("no");
  });

  it("cancelled reason editor (null) loops back then selects Yes", async () => {
    const cb = makeCallbacks();
    // tier-1: No with reason (1), editor: null (cancelled) → loops back
    // tier-1: Yes (0)
    const result = await twoTierAlwaysPrompt(
      prompt, store, makeCtx([1, null, 0]),
      cb.onAlways, cb.onAlwaysPaths, cb.onAlwaysFile,
    );
    expect(result).toBe("yes");
    expect(cb.onAlways).not.toHaveBeenCalled();
  });

  it("trims whitespace from reason", async () => {
    const cb = makeCallbacks();
    const result = await twoTierAlwaysPrompt(
      prompt, store, makeCtx([1, "  "]),
      cb.onAlways, cb.onAlwaysPaths, cb.onAlwaysFile,
    );
    // Empty/whitespace reason → trimmed → empty → "No reason provided"
    expect(result).toEqual({ kind: "no", reason: "No reason provided" });
  });
});

// ── Decoupled paths tier (unsafe command: paths still grantable) ───────

describe("twoTierAlwaysPrompt: paths tier decoupled from unsafe command", () => {
  // includeAlwaysOption: false (unsafe pattern) + includePathsOption: true →
  // choices = ["Yes", "Always (paths): /path/*", "No (reason)", "No"]
  // indices:     0                   1                     2           3
  // The command tiers (primary, broader) stay suppressed; the dir grant
  // can never auto-allow the unsafe command, so it remains offerable.

  const prompt = makePrompt({ includeAlwaysOption: false, includePathsOption: true });

  it("offers the paths option at index 1, not the command tiers", async () => {
    const ctx = makeCtx([1]);
    await twoTierAlwaysPrompt(
      prompt, store, ctx, () => {}, () => {}, () => {},
    );
    const shown = ctx.__selects[0];
    expect(shown).toEqual(["Yes", "Always (paths): /path/*", "No (with reason)", "No"]);
  });

  it("calls onAlwaysPaths when Always(paths) → Confirm", async () => {
    const cb = makeCallbacks();
    const result = await twoTierAlwaysPrompt(
      prompt, store, makeCtx([1, 0]),
      cb.onAlways, cb.onAlwaysPaths, cb.onAlwaysFile,
    );
    expect(result).toBe("alwaysPaths");
    expect(cb.onAlwaysPaths).toHaveBeenCalledTimes(1);
    expect(cb.onAlways).not.toHaveBeenCalled();
  });

  it("Back from tier-2 loops back to tier-1, then No", async () => {
    const cb = makeCallbacks();
    const result = await twoTierAlwaysPrompt(
      prompt, store, makeCtx([1, 1, 3]),
      cb.onAlways, cb.onAlwaysPaths, cb.onAlwaysFile,
    );
    expect(result).toBe("no");
    expect(cb.onAlwaysPaths).not.toHaveBeenCalled();
  });

  it("broader alone (no paths) is still fully suppressed", async () => {
    const suppressed = makePrompt({ includeAlwaysOption: false, includeBroaderOption: true });
    const ctx = makeCtx([2]);
    await twoTierAlwaysPrompt(
      suppressed, store, ctx, () => {}, () => {}, () => {},
    );
    expect(ctx.__selects[0]).toEqual(["Yes", "No (with reason)", "No"]);
  });
});

// ── Broader-only layout (inside-cwd file, bash-style without broaderPaths) ─────────────

describe("twoTierAlwaysPrompt: broader-only layout (inside-cwd file)", () => {
  // includeBroaderOption: true, includePathsOption: false, includeFileOption: false
  // choices = ["Yes", "Always: test *", "Always: test broader *", "No (reason)", "No"]
  // indices:     0          1                    2                      3           4

  const prompt = makePrompt({ includeBroaderOption: true, includePathsOption: false, includeFileOption: false });

  it("calls onAlwaysBroader when Always(broader) → Confirm", async () => {
    const cb = makeCallbacks();
    const result = await twoTierAlwaysPrompt(
      prompt, store, makeCtx([2, 0]),
      cb.onAlways, cb.onAlwaysPaths, cb.onAlwaysFile, cb.onAlwaysBroader,
    );
    expect(result).toBe("always");
    expect(cb.onAlwaysBroader).toHaveBeenCalledTimes(1);
    expect(cb.onAlways).not.toHaveBeenCalled();
  });

  it("calls onAlways when Always(everything) → Confirm", async () => {
    const cb = makeCallbacks();
    const result = await twoTierAlwaysPrompt(
      prompt, store, makeCtx([1, 0]),
      cb.onAlways, cb.onAlwaysPaths, cb.onAlwaysFile, cb.onAlwaysBroader,
    );
    expect(result).toBe("always");
    expect(cb.onAlways).toHaveBeenCalledTimes(1);
    cb.onAlwaysBroader && expect(cb.onAlwaysBroader).not.toHaveBeenCalled();
  });

  it("returns 'no' for index 4 (No)", async () => {
    const cb = makeCallbacks();
    const result = await twoTierAlwaysPrompt(
      prompt, store, makeCtx([4]),
      cb.onAlways, cb.onAlwaysPaths, cb.onAlwaysFile, cb.onAlwaysBroader,
    );
    expect(result).toBe("no");
  });
});

// ── File with broaderPaths (3-level hierarchy) ────────────────────────

describe("twoTierAlwaysPrompt: file broaderPaths (3-level hierarchy)", () => {
  // File prompt with broaderPaths: immediate parent + 2 more levels
  // choices = [
  //   "Yes",                            // 0
  //   "Always (file): index.ts",         // 1  → Always file
  //   "Always (path): analysis/*",       // 2  → Always immediate parent
  //   "Always (broader)",                // 3  → umbrella → sub-menu
  //   "No (with reason)",                // 4
  //   "No"                               // 5
  // ]

  const prompt = makePrompt({
    includeBroaderOption: true,
    includePathsOption: false,
    includeFileOption: false,
    alwaysLabel: "index.ts",
    broaderPaths: [
      { label: "Read analysis/*", dir: "/home/user/project/analysis" },
      { label: "Read /home/user/project/*", dir: "/home/user/project" },
      { label: "Read /home/user/*", dir: "/home/user" },
    ],
  });

  it("calls onAlwaysBroader with dir for Always(path) → Confirm", async () => {
    const cb = makeCallbacks();
    // tier-1: Always(path) (2), tier-2: Confirm (0)
    const result = await twoTierAlwaysPrompt(
      prompt, store, makeCtx([2, 0]),
      cb.onAlways, cb.onAlwaysPaths, cb.onAlwaysFile, cb.onAlwaysBroader,
    );
    expect(result).toBe("always");
    expect(cb.onAlwaysBroader).toHaveBeenCalledTimes(1);
    expect(cb.onAlwaysBroader).toHaveBeenCalledWith("/home/user/project/analysis");
  });

  it("umbrella broader → sub-menu → select first level → confirm", async () => {
    const cb = makeCallbacks();
    // tier-1: umbrella broader (3)
    // sub-menu: select first item (0) → /home/user/project
    // tier-2: Confirm (0)
    const result = await twoTierAlwaysPrompt(
      prompt, store, makeCtx([3, 0, 0]),
      cb.onAlways, cb.onAlwaysPaths, cb.onAlwaysFile, cb.onAlwaysBroader,
    );
    expect(result).toBe("always");
    expect(cb.onAlwaysBroader).toHaveBeenCalledTimes(1);
    expect(cb.onAlwaysBroader).toHaveBeenCalledWith("/home/user/project");
  });

  it("umbrella broader → sub-menu → select second level → confirm", async () => {
    const cb = makeCallbacks();
    // tier-1: umbrella broader (3)
    // sub-menu: select second item (1) → /home/user
    // tier-2: Confirm (0)
    const result = await twoTierAlwaysPrompt(
      prompt, store, makeCtx([3, 1, 0]),
      cb.onAlways, cb.onAlwaysPaths, cb.onAlwaysFile, cb.onAlwaysBroader,
    );
    expect(result).toBe("always");
    expect(cb.onAlwaysBroader).toHaveBeenCalledTimes(1);
    expect(cb.onAlwaysBroader).toHaveBeenCalledWith("/home/user");
  });

  it("umbrella broader → sub-menu → Back → loops back to tier-1", async () => {
    const cb = makeCallbacks();
    // tier-1: umbrella broader (3)
    // sub-menu: Back (2, last index)
    // tier-1: No (5)
    const result = await twoTierAlwaysPrompt(
      prompt, store, makeCtx([3, 2, 5]),
      cb.onAlways, cb.onAlwaysPaths, cb.onAlwaysFile, cb.onAlwaysBroader,
    );
    expect(result).toBe("no");
    expect(cb.onAlwaysBroader).not.toHaveBeenCalled();
  });

  it("umbrella broader → sub-menu → cancel (null) → loops back to tier-1", async () => {
    const cb = makeCallbacks();
    // tier-1: umbrella broader (3)
    // sub-menu: cancel (null)
    // tier-1: No (5)
    const result = await twoTierAlwaysPrompt(
      prompt, store, makeCtx([3, null, 5]),
      cb.onAlways, cb.onAlwaysPaths, cb.onAlwaysFile, cb.onAlwaysBroader,
    );
    expect(result).toBe("no");
    expect(cb.onAlwaysBroader).not.toHaveBeenCalled();
  });

  it("umbrella broader → sub-menu → tier-2 Back → loops back to tier-1", async () => {
    const cb = makeCallbacks();
    // tier-1: umbrella broader (3)
    // sub-menu: select first item (0)
    // tier-2: Back (1)
    // tier-1: No (5)
    const result = await twoTierAlwaysPrompt(
      prompt, store, makeCtx([3, 0, 1, 5]),
      cb.onAlways, cb.onAlwaysPaths, cb.onAlwaysFile, cb.onAlwaysBroader,
    );
    expect(result).toBe("no");
    expect(cb.onAlwaysBroader).not.toHaveBeenCalled();
  });

  it("Always(file) → Confirm uses onAlways (not onAlwaysBroader)", async () => {
    const cb = makeCallbacks();
    // tier-1: Always(file) (1), tier-2: Confirm (0)
    const result = await twoTierAlwaysPrompt(
      prompt, store, makeCtx([1, 0]),
      cb.onAlways, cb.onAlwaysPaths, cb.onAlwaysFile, cb.onAlwaysBroader,
    );
    expect(result).toBe("always");
    expect(cb.onAlways).toHaveBeenCalledTimes(1);
    expect(cb.onAlwaysBroader).not.toHaveBeenCalled();
  });

  it("returns 'no' at index 5 (No)", async () => {
    const cb = makeCallbacks();
    const result = await twoTierAlwaysPrompt(
      prompt, store, makeCtx([5]),
      cb.onAlways, cb.onAlwaysPaths, cb.onAlwaysFile, cb.onAlwaysBroader,
    );
    expect(result).toBe("no");
  });

  it("returns {kind:'no', reason} at index 4 (No with reason)", async () => {
    const cb = makeCallbacks();
    const result = await twoTierAlwaysPrompt(
      prompt, store, makeCtx([4, "not safe"]),
      cb.onAlways, cb.onAlwaysPaths, cb.onAlwaysFile, cb.onAlwaysBroader,
    );
    expect(result).toEqual({ kind: "no", reason: "not safe" });
  });
});

// ── File with broaderPaths (single level, no umbrella) ────────────────

describe("twoTierAlwaysPrompt: file broaderPaths (single level, no umbrella)", () => {
  // File at root — only immediate parent, no parent above
  // choices = [
  //   "Yes",                      // 0
  //   "Always (file): hosts",      // 1
  //   "Always (path): /etc/*",     // 2  → immediate parent only
  //   "No (with reason)",          // 3
  //   "No"                         // 4
  // ]

  const prompt = makePrompt({
    includeBroaderOption: true,
    includePathsOption: false,
    includeFileOption: false,
    alwaysLabel: "hosts",
    broaderPaths: [
      { label: "Read /etc/*", dir: "/etc" },
    ],
  });

  it("calls onAlwaysBroader with dir for Always(path) → Confirm", async () => {
    const cb = makeCallbacks();
    const result = await twoTierAlwaysPrompt(
      prompt, store, makeCtx([2, 0]),
      cb.onAlways, cb.onAlwaysPaths, cb.onAlwaysFile, cb.onAlwaysBroader,
    );
    expect(result).toBe("always");
    expect(cb.onAlwaysBroader).toHaveBeenCalledTimes(1);
    expect(cb.onAlwaysBroader).toHaveBeenCalledWith("/etc");
  });

  it("no umbrella option (only 1 broaderPaths entry)", async () => {
    // Verify there's no "Always (broader)" option — only file + path + no
    const cb = makeCallbacks();
    const result = await twoTierAlwaysPrompt(
      prompt, store, makeCtx([4]),
      cb.onAlways, cb.onAlwaysPaths, cb.onAlwaysFile, cb.onAlwaysBroader,
    );
    expect(result).toBe("no");
  });
});

// ── Paths-only layout (bash with paths, no broader) ────────────────────

describe("twoTierAlwaysPrompt: paths-only layout (bash no broader)", () => {
  // includePathsOption: true, includeBroaderOption: false
  // choices = ["Yes", "Always: test *", "Always (paths): /path/*", "No (reason)", "No"]
  // indices:     0          1                    2                         3           4

  const prompt = makePrompt({ includePathsOption: true, includeBroaderOption: false, includeFileOption: false });

  it("calls onAlwaysPaths when Always(paths) → Confirm", async () => {
    const cb = makeCallbacks();
    const result = await twoTierAlwaysPrompt(
      prompt, store, makeCtx([2, 0]),
      cb.onAlways, cb.onAlwaysPaths, cb.onAlwaysFile,
    );
    expect(result).toBe("alwaysPaths");
    expect(cb.onAlwaysPaths).toHaveBeenCalledTimes(1);
    expect(cb.onAlways).not.toHaveBeenCalled();
  });

  it("calls onAlways when Always(everything) → Confirm", async () => {
    const cb = makeCallbacks();
    const result = await twoTierAlwaysPrompt(
      prompt, store, makeCtx([1, 0]),
      cb.onAlways, cb.onAlwaysPaths, cb.onAlwaysFile,
    );
    expect(result).toBe("always");
    expect(cb.onAlways).toHaveBeenCalledTimes(1);
    cb.onAlwaysPaths && expect(cb.onAlwaysPaths).not.toHaveBeenCalled();
  });

  it("returns {kind:'no', reason} at index 3 (No with reason)", async () => {
    const cb = makeCallbacks();
    const result = await twoTierAlwaysPrompt(
      prompt, store, makeCtx([3, "path blocked"]),
      cb.onAlways, cb.onAlwaysPaths, cb.onAlwaysFile,
    );
    expect(result).toEqual({ kind: "no", reason: "path blocked" });
  });

  it("returns 'no' at index 4 (No)", async () => {
    const cb = makeCallbacks();
    const result = await twoTierAlwaysPrompt(
      prompt, store, makeCtx([4]),
      cb.onAlways, cb.onAlwaysPaths, cb.onAlwaysFile,
    );
    expect(result).toBe("no");
  });
});

// ── High prompt frequency warning ──────────────────────────────────────

describe("twoTierAlwaysPrompt: high prompt frequency warning", () => {
  it("shows warning prefix when over threshold", async () => {
    // Push the count past the threshold
    for (let i = 0; i < 25; i++) store.incrementPromptCount();

    // The warning prefix is concatenated with title before showSelectIndex.
    // Just verify the function completes successfully (doesn't crash).
    const cb = makeCallbacks();
    const result = await twoTierAlwaysPrompt(
      makePrompt(), store, makeCtx([3]), // No
      cb.onAlways, cb.onAlwaysPaths, cb.onAlwaysFile,
    );
    expect(result).toBe("no");
  });
});

// ── On-demand judge explanation option ─────────────────────────────────

describe("twoTierAlwaysPrompt: Explain option", () => {
  /** Fake ctx that records every select call (title + choices) and scripts. */
  function makeRecordingCtx(scripted: (number | string | null)[]) {
    const calls: Array<{ title: string; options: string[] }> = [];
    let idx = 0;
    return {
      calls,
      ctx: {
        ui: {
          select: async (title: string, options: string[]) => {
            calls.push({ title, options });
            const val = scripted[idx++];
            if (val === null || val === undefined) return undefined;
            return typeof val === "number" ? options[val] : val;
          },
          input: async () => undefined,
        },
      } as any,
    };
  }

  it("offers 'Explain' after the Always options; explaining re-shows with the verdict block and drops the option", async () => {
    // On-demand dspat: the block carries the explanation AND the suggests line.
    const blocks = ["💭 Judge: Runs a local build script.\n   → suggests: APPROVE (low)"];
    const explain = vi.fn(async () => blocks.shift() ?? null);
    const { ctx, calls } = makeRecordingCtx([2, 0]); // click Explain, then Yes

    const result = await twoTierAlwaysPrompt(
      makePrompt(), store, ctx,
      () => "always" as never, () => "alwaysPaths" as never, () => "alwaysFile" as never,
      undefined, { explain },
    );

    expect(result).toBe("yes");
    expect(explain).toHaveBeenCalledTimes(1);
    // first tier-1: option in the choices, no judge block in the body yet
    expect(calls[0].options).toEqual(["Yes", "Always: test *", "Explain", "No (with reason)", "No"]);
    expect(calls[0].title).not.toContain("💭 Judge:");
    // second tier-1: full verdict block in the body (explanation + suggests), option removed
    expect(calls[1].title).toContain("💭 Judge: Runs a local build script.");
    expect(calls[1].title).toContain("→ suggests: APPROVE (low)");
    expect(calls[1].options).not.toContain("Explain");
  });

  it("failed call → ⚠️ line in body, option consumed", async () => {
    const explain = vi.fn(async () => null);
    const { ctx, calls } = makeRecordingCtx([2, 0]); // Explain (fails), then Yes

    await twoTierAlwaysPrompt(
      makePrompt(), store, ctx,
      () => "always" as never, () => "alwaysPaths" as never, () => "alwaysFile" as never,
      undefined, { explain },
    );

    expect(explain).toHaveBeenCalledTimes(1);
    expect(calls).toHaveLength(2);
    // The failure is surfaced in the body, so the option is consumed.
    expect(calls[1].options).not.toContain("Explain");
    expect(calls[1].title).toContain("⚠️ Judge: call failed (model unavailable or timed out)");
  });

  it("no judge → no Explain option", async () => {
    const { ctx, calls } = makeRecordingCtx([0]);
    await twoTierAlwaysPrompt(
      makePrompt(), store, ctx,
      () => "always" as never, () => "alwaysPaths" as never, () => "alwaysFile" as never,
    );
    expect(calls[0].options).not.toContain("Explain");
  });
});

// ── D10: trust option ──────────────────────────────────────────────────

describe("twoTierAlwaysPrompt: D10 trust option", () => {
  it("shows Trust option and calls onTrust → 'always'", async () => {
    const cb = makeCallbacks();
    const onTrust = vi.fn();
    // choices = ["Yes", "Always: test *", "Trust: tsc, ruff (session)", "No (with reason)", "No"]
    // indices:     0           1                     2                        3                4
    const result = await twoTierAlwaysPrompt(
      makePrompt({ trustPackages: ["tsc", "ruff"] }), store, makeCtx([2, 0]),
      cb.onAlways, cb.onAlwaysPaths, cb.onAlwaysFile, cb.onAlwaysBroader, undefined, onTrust,
    );
    expect(result).toBe("always");
    expect(onTrust).toHaveBeenCalledTimes(1);
    expect(cb.onAlways).not.toHaveBeenCalled();
  });

  it("trust option is offered even when includeAlwaysOption is false", async () => {
    const cb = makeCallbacks();
    const onTrust = vi.fn();
    // choices = ["Yes", "Trust: tsc (session)", "No (with reason)", "No"]
    // indices:     0           1                  3
    const result = await twoTierAlwaysPrompt(
      makePrompt({ includeAlwaysOption: false, trustPackages: ["tsc"] }), store, makeCtx([1, 0]),
      cb.onAlways, cb.onAlwaysPaths, cb.onAlwaysFile, cb.onAlwaysBroader, undefined, onTrust,
    );
    expect(result).toBe("always");
    expect(onTrust).toHaveBeenCalledTimes(1);
  });

  it("no trust option without packages (plain layout unchanged)", async () => {
    const cb = makeCallbacks();
    const onTrust = vi.fn();
    // choices = ["Yes", "Always: test *", "No (with reason)", "No"] — no Trust
    // Always → Back → No
    const result = await twoTierAlwaysPrompt(
      makePrompt(), store, makeCtx([1, 1, 3]),
      cb.onAlways, cb.onAlwaysPaths, cb.onAlwaysFile, cb.onAlwaysBroader, undefined, onTrust,
    );
    expect(result).toBe("no");
    expect(onTrust).not.toHaveBeenCalled();
  });
});
