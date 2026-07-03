/**
 * twoTierAlwaysPrompt UI dispatch tests.
 *
 * Drives the choice-index dispatch with a fake ctx.ui.custom that returns
 * canned indices/strings. Verifies callback wiring, tier-2 confirmation flow,
 * and that the Permanent option is suppressed for MCP (includePermanentOption: false).
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { twoTierAlwaysPrompt } from "../prompts";
import type { BuiltPrompt } from "../prompt-builder";
import { store } from "../store";

// ── Fake ctx ───────────────────────────────────────────────────────────

/**
 * Build a fake ExtensionContext whose ui.custom resolves with scripted values.
 * Each ctx.ui.custom call consumes one value (interleaves select + editor calls).
 */
function makeCtx(scripted: (number | string | null)[]): any {
	let idx = 0;
	return {
		ui: {
			custom: <T>(callback: any): Promise<T> => {
				const val = scripted[idx++];
				// Call the callback for setup (harmless in tests; ignores the handler)
				callback(
					{ requestRender: () => {} },
					{ fg: (_c: string, t: string) => t },
					null,
					() => {},
				);
				return Promise.resolve(val as T);
			},
		},
	};
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
		includePermanentOption: true,
		alwaysLabel: "test *",
		alwaysBroaderLabel: "test broader *",
		alwaysPathsLabel: "/path/*",
		alwaysFileLabel: "file.txt",
		permanentAllowExamples: "Example: 'npm test *'",
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
		onCustomAlways: vi.fn().mockResolvedValue(undefined),
	};
}

beforeEach(() => {
	store.resetSessionState();
});

// ── Simple bash prompt (Yes / Always / Permanent / No-reason / No) ──────

describe("twoTierAlwaysPrompt: simple bash layout", () => {
	// choices = ["Yes", "Always: test *", "Permanent Always (config)", "No (with reason)", "No"]
	// indices:     0          1                    2                       3                  4

	it("returns 'yes' when index 0 is selected", async () => {
		const cb = makeCallbacks();
		const result = await twoTierAlwaysPrompt(
			makePrompt(), makeCtx([0]), cb.onAlways, cb.onAlwaysPaths, cb.onAlwaysFile,
		);
		expect(result).toBe("yes");
		expect(cb.onAlways).not.toHaveBeenCalled();
	});

	it("calls onAlways and returns 'always' when Always → Confirm is selected", async () => {
		const cb = makeCallbacks();
		const result = await twoTierAlwaysPrompt(
			makePrompt(), makeCtx([1, 0]), cb.onAlways, cb.onAlwaysPaths, cb.onAlwaysFile,
		);
		expect(result).toBe("always");
		expect(cb.onAlways).toHaveBeenCalledTimes(1);
	});

	it("loops back to tier-1 when tier-2 selects Back, then No", async () => {
		const cb = makeCallbacks();
		// tier-1: Always (1), tier-2: Back (1), tier-1: No (4)
		const result = await twoTierAlwaysPrompt(
			makePrompt(), makeCtx([1, 1, 4]), cb.onAlways, cb.onAlwaysPaths, cb.onAlwaysFile,
		);
		expect(result).toBe("no");
		expect(cb.onAlways).not.toHaveBeenCalled();
	});

	it("calls onCustomAlways with pattern when Permanent is selected", async () => {
		const cb = makeCallbacks();
		// tier-1: Permanent (2), editor: "npm test *"
		const result = await twoTierAlwaysPrompt(
			makePrompt(), makeCtx([2, "npm test *"]),
			cb.onAlways, cb.onAlwaysPaths, cb.onAlwaysFile, undefined, cb.onCustomAlways,
		);
		expect(result).toEqual({ kind: "custom", pattern: "npm test *" });
		expect(cb.onCustomAlways).toHaveBeenCalledWith("npm test *");
	});

	it("returns {kind:'no', reason} when No-with-reason is selected", async () => {
		const cb = makeCallbacks();
		// tier-1: No with reason (3), editor: "because unsafe"
		const result = await twoTierAlwaysPrompt(
			makePrompt(), makeCtx([3, "because unsafe"]),
			cb.onAlways, cb.onAlwaysPaths, cb.onAlwaysFile,
		);
		expect(result).toEqual({ kind: "no", reason: "because unsafe" });
	});

	it("returns 'no' when No is selected", async () => {
		const cb = makeCallbacks();
		const result = await twoTierAlwaysPrompt(
			makePrompt(), makeCtx([4]), cb.onAlways, cb.onAlwaysPaths, cb.onAlwaysFile,
		);
		expect(result).toBe("no");
	});

	it("returns 'no' when selection is cancelled (null)", async () => {
		const cb = makeCallbacks();
		const result = await twoTierAlwaysPrompt(
			makePrompt(), makeCtx([null]), cb.onAlways, cb.onAlwaysPaths, cb.onAlwaysFile,
		);
		expect(result).toBe("no");
	});

	it("loops when Permanent editor returns empty, then No", async () => {
		const cb = makeCallbacks();
		// tier-1: Permanent (2), editor: "" (empty → loop), tier-1: No (4)
		const result = await twoTierAlwaysPrompt(
			makePrompt(), makeCtx([2, "", 4]),
			cb.onAlways, cb.onAlwaysPaths, cb.onAlwaysFile, undefined, cb.onCustomAlways,
		);
		expect(result).toBe("no");
		expect(cb.onCustomAlways).not.toHaveBeenCalled();
	});
});

// ── Bash with paths + broader ──────────────────────────────────────────

describe("twoTierAlwaysPrompt: bash with paths + broader", () => {
	// choices = ["Yes", "Always: test *", "Always: test broader *", "Always (paths): /path/*", "Permanent", "No (reason)", "No"]
	// indices:     0          1                    2                           3                              4            5             6

	const prompt = makePrompt({ includeBroaderOption: true, includePathsOption: true });

	it("calls onAlwaysPaths when Always(paths) → Confirm", async () => {
		const cb = makeCallbacks();
		// tier-1: Always(paths) (3), tier-2: Confirm (0)
		const result = await twoTierAlwaysPrompt(
			prompt, makeCtx([3, 0]),
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
			prompt, makeCtx([2, 0]),
			cb.onAlways, cb.onAlwaysPaths, cb.onAlwaysFile, cb.onAlwaysBroader,
		);
		expect(result).toBe("always");
		expect(cb.onAlwaysBroader).toHaveBeenCalledTimes(1);
		expect(cb.onAlways).not.toHaveBeenCalled();
	});
});

// ── File outside cwd (path + file options) ─────────────────────────────

describe("twoTierAlwaysPrompt: file outside cwd layout", () => {
	// choices = ["Yes", "Always (path): ...", "Always (file): ...", "Permanent", "No (reason)", "No"]
	// indices:     0          1                     2                       3            4             5

	const prompt = makePrompt({
		includeFileOption: true,
		includePathsOption: false,
		includeBroaderOption: false,
	});

	it("calls onAlwaysFile when Always(file) → Confirm", async () => {
		const cb = makeCallbacks();
		// tier-1: Always(file) (2), tier-2: Confirm (0)
		const result = await twoTierAlwaysPrompt(
			prompt, makeCtx([2, 0]),
			cb.onAlways, cb.onAlwaysPaths, cb.onAlwaysFile,
		);
		expect(result).toBe("alwaysFile");
		expect(cb.onAlwaysFile).toHaveBeenCalledTimes(1);
	});

	it("calls onAlways when Always(path/everything) → Confirm", async () => {
		const cb = makeCallbacks();
		// tier-1: Always(path) (1), tier-2: Confirm (0)
		const result = await twoTierAlwaysPrompt(
			prompt, makeCtx([1, 0]),
			cb.onAlways, cb.onAlwaysPaths, cb.onAlwaysFile,
		);
		expect(result).toBe("always");
		expect(cb.onAlways).toHaveBeenCalledTimes(1);
	});
});

// ── MCP: permanent suppressed ──────────────────────────────────────────

describe("twoTierAlwaysPrompt: MCP layout (permanent suppressed)", () => {
	// includePermanentOption: false →
	// choices = ["Yes", "Always: exa:*", "No (with reason)", "No"]
	// indices:     0          1               2                3
	// NOTE: index 2 is "No (with reason)", NOT "Permanent" (which would be index 2 in bash layout)

	const mcpPrompt = makePrompt({
		includePermanentOption: false,
		includeAlwaysOption: true,
		alwaysLabel: "exa:*",
	});

	it("calls onAlways and returns 'always' when Always → Confirm", async () => {
		const cb = makeCallbacks();
		const result = await twoTierAlwaysPrompt(
			mcpPrompt, makeCtx([1, 0]),
			cb.onAlways, cb.onAlwaysPaths, cb.onAlwaysFile,
		);
		expect(result).toBe("always");
		expect(cb.onAlways).toHaveBeenCalledTimes(1);
	});

	it("selecting index 2 triggers 'No with reason', NOT permanent (P3 regression)", async () => {
		const cb = makeCallbacks();
		// tier-1: index 2, editor: "reason"
		// In bash layout, index 2 = Permanent → onCustomAlways.
		// In MCP layout, index 2 = "No with reason" → no onCustomAlways.
		const result = await twoTierAlwaysPrompt(
			mcpPrompt, makeCtx([2, "because unsafe"]),
			cb.onAlways, cb.onAlwaysPaths, cb.onAlwaysFile, undefined, cb.onCustomAlways,
		);
		expect(result).toEqual({ kind: "no", reason: "because unsafe" });
		expect(cb.onCustomAlways).not.toHaveBeenCalled();
	});

	it("returns 'no' when index 3 (No) is selected", async () => {
		const cb = makeCallbacks();
		const result = await twoTierAlwaysPrompt(
			mcpPrompt, makeCtx([3]),
			cb.onAlways, cb.onAlwaysPaths, cb.onAlwaysFile,
		);
		expect(result).toBe("no");
	});

	it("cancel (null) returns 'no'", async () => {
		const cb = makeCallbacks();
		const result = await twoTierAlwaysPrompt(
			mcpPrompt, makeCtx([null]),
			cb.onAlways, cb.onAlwaysPaths, cb.onAlwaysFile,
		);
		expect(result).toBe("no");
	});
});

// ── No Always option (unsafe pattern) ──────────────────────────────────

describe("twoTierAlwaysPrompt: no Always option (unsafe pattern)", () => {
	// includeAlwaysOption: false →
	// choices = ["Yes", "Permanent Always (config)", "No (with reason)", "No"]
	// indices:     0          1                            2                3

	const prompt = makePrompt({ includeAlwaysOption: false });

	it("returns 'yes' at index 0", async () => {
		const cb = makeCallbacks();
		const result = await twoTierAlwaysPrompt(
			prompt, makeCtx([0]), cb.onAlways, cb.onAlwaysPaths, cb.onAlwaysFile,
		);
		expect(result).toBe("yes");
	});

	it("triggers Permanent at index 1 (not Always, which is absent)", async () => {
		const cb = makeCallbacks();
		const result = await twoTierAlwaysPrompt(
			prompt, makeCtx([1, "rm *"]),
			cb.onAlways, cb.onAlwaysPaths, cb.onAlwaysFile, undefined, cb.onCustomAlways,
		);
		expect(result).toEqual({ kind: "custom", pattern: "rm *" });
		expect(cb.onCustomAlways).toHaveBeenCalledWith("rm *");
		expect(cb.onAlways).not.toHaveBeenCalled();
	});
});
