/**
 * Fail-closed boundary (index.ts tool_call handler).
 *
 * The gate's guarantee is: an internal error in ANY handler must block the
 * command, never let it run un-gated. The pi harness currently catches
 * handler throws (agent-loop prepareToolCall), but emitToolCall itself has no
 * try/catch (perm #452-A1) — this test pins halter's own boundary so a
 * harness change cannot silently turn a throw into a bypass.
 */
import { describe, expect, it, vi, beforeEach } from "vitest";

const handlersMock = vi.hoisted(() => ({
	handleMcp: vi.fn(),
	handleMcpDirectTool: vi.fn(),
	handleBash: vi.fn(),
	handleFile: vi.fn(),
}));
vi.mock("../handlers", () => handlersMock);

import halterExtension from "../index";

/** Minimal ExtensionAPI stub capturing registered event handlers. */
function makePi() {
	const events = new Map<string, unknown[]>();
	return {
		events,
		default: halterExtension,
		api: {
			on: (event: string, handler: unknown) => {
				if (!events.has(event)) events.set(event, []);
				events.get(event)!.push(handler);
			},
			registerCommand: () => {},
		},
	};
}

type ToolCallHandler = (e: unknown, c: unknown) => Promise<unknown>;

const event = {
	type: "tool_call" as const,
	toolName: "bash",
	toolCallId: "t1",
	input: { command: "ls" },
};

describe("tool_call fail-closed boundary", () => {
	beforeEach(() => {
		for (const fn of Object.values(handlersMock)) {
			fn.mockReset();
			fn.mockResolvedValue(undefined);
		}
	});

	it("a throwing handler blocks with a gate-error reason (never silent)", async () => {
		handlersMock.handleBash.mockRejectedValue(new Error("synthetic analysis crash"));
		const { api, events } = makePi();
		await halterExtension(api as never);
		const handler = (events.get("tool_call") as ToolCallHandler[])[0];
		const result = (await handler(event, {})) as { block?: boolean; reason?: string };
		expect(result?.block).toBe(true);
		expect(result?.reason).toMatch(/halter gate error: synthetic analysis crash/);
	});

	it("a non-Error throw is still blocked (stringified)", async () => {
		handlersMock.handleBash.mockRejectedValue("boom");
		const { api, events } = makePi();
		await halterExtension(api as never);
		const handler = (events.get("tool_call") as ToolCallHandler[])[0];
		const result = (await handler(event, {})) as { block?: boolean; reason?: string };
		expect(result?.block).toBe(true);
		expect(result?.reason).toMatch(/halter gate error: boom/);
	});

	it("a normal block result passes through unmodified", async () => {
		handlersMock.handleBash.mockResolvedValue({ block: true, reason: "Denied: credential" });
		const { api, events } = makePi();
		await halterExtension(api as never);
		const handler = (events.get("tool_call") as ToolCallHandler[])[0];
		const result = await handler(event, {});
		expect(result).toEqual({ block: true, reason: "Denied: credential" });
	});

	it("pass-through (all handlers undefined) stays undefined — no false block", async () => {
		const { api, events } = makePi();
		await halterExtension(api as never);
		const handler = (events.get("tool_call") as ToolCallHandler[])[0];
		expect(await handler(event, {})).toBeUndefined();
	});
});
