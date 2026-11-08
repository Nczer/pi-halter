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
  handleBash: vi.fn(),
  handleFile: vi.fn(),
  handleTool: vi.fn(),
}));
vi.mock("../handlers", () => handlersMock);

import halterExtension from "../index";
import { MAX_GATED_CALLS_PER_SCRIPT, resetScriptBudget } from "../gate/script-budget";

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

/**
 * The scripted-call budget is wired AHEAD of the handlers (gate/script-budget.ts):
 * a call past its script's ceiling must never reach a policy or the judge, so
 * the handler mocks below must stay untouched.
 */
describe("tool_call — scripted-call budget position", () => {
  const scripted = { ...event, toolCallId: "t1/7", parentToolCallId: "t1" };

  beforeEach(() => {
    resetScriptBudget();
    for (const fn of Object.values(handlersMock)) {
      fn.mockReset();
      fn.mockResolvedValue(undefined);
    }
  });

  it("a scripted call inside the budget still goes to the gate", async () => {
    const { api, events } = makePi();
    await halterExtension(api as never);
    const handler = (events.get("tool_call") as ToolCallHandler[])[0];
    expect(await handler(scripted, {})).toBeUndefined();
    expect(handlersMock.handleBash).toHaveBeenCalledTimes(1);
  });

  it("a scripted call past the budget blocks without reaching the gate", async () => {
    const { api, events } = makePi();
    await halterExtension(api as never);
    const handler = (events.get("tool_call") as ToolCallHandler[])[0];
    for (let i = 0; i < MAX_GATED_CALLS_PER_SCRIPT; i++) {
      await handler(scripted, {});
    }
    handlersMock.handleBash.mockClear();
    const result = (await handler(scripted, {})) as { block?: boolean; reason?: string };
    expect(result?.block).toBe(true);
    expect(result?.reason).toMatch(new RegExp(`at most ${MAX_GATED_CALLS_PER_SCRIPT} gated tool calls`));
    expect(handlersMock.handleBash).not.toHaveBeenCalled();
  });

  it("the model's own calls are never counted", async () => {
    const { api, events } = makePi();
    await halterExtension(api as never);
    const handler = (events.get("tool_call") as ToolCallHandler[])[0];
    for (let i = 0; i < MAX_GATED_CALLS_PER_SCRIPT + 5; i++) {
      await handler(event, {});
    }
    expect(handlersMock.handleBash).toHaveBeenCalledTimes(MAX_GATED_CALLS_PER_SCRIPT + 5);
  });
});
