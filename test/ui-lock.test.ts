/**
 * halter's permission prompts are tool-call UIs: pi runs the tool calls of one
 * assistant message concurrently, and every dialog is shown by clearing the
 * editor container. A consult dialog opening while a halter prompt is open
 * therefore cancels the halter prompt. Both chain on one mutex.
 */
import { describe, it, expect, beforeEach, vi } from "vitest";
import { withUILock as halterLock } from "../ui/ui-lock";
import { withUILock as consultLock } from "../../consult/index";
import { twoTierAlwaysPrompt } from "../ui/prompts";
import type { BuiltPrompt } from "../ui/prompt-builder";
import { store } from "../gate/store";

function makePrompt(): BuiltPrompt {
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
    alwaysPathsLabel: "/path/*",
    alwaysFileLabel: "file.txt",
    pathGrantDirs: [],
  };
}

beforeEach(() => {
  store.reset();
});

describe("shared UI lock (halter ↔ consult)", () => {
  it("halter uses the same globalThis mutex as consult", () => {
    expect((globalThis as any).__piSharedUiLock).toBeDefined();
  });

  it("a consult dialog cannot open while a halter permission prompt is open", async () => {
    const order: string[] = [];
    let releaseSelect: () => void;
    const ctx: any = {
      ui: {
        select: () =>
          new Promise<string>((resolve) => {
            order.push("halter prompt open");
            releaseSelect = () => resolve("Yes");
          }),
      },
    };

    const prompt = twoTierAlwaysPrompt(makePrompt(), store, ctx, vi.fn(), vi.fn(), vi.fn());
    await Promise.resolve();
    const consult = consultLock(async () => {
      order.push("consult open");
    });

    expect(order).toEqual(["halter prompt open"]); // consult must wait
    releaseSelect!();
    await prompt;
    await consult;
    expect(order).toEqual(["halter prompt open", "consult open"]);
  });

  it("a halter prompt cannot cut in front of a held consult dialog", async () => {
    const order: string[] = [];
    let releaseConsult: () => void;
    const gate = new Promise<void>((resolve) => {
      releaseConsult = resolve;
    });
    const consult = consultLock(async () => {
      order.push("consult open");
      await gate;
    });
    await Promise.resolve();

    const halter = halterLock(async () => {
      order.push("halter prompt open");
      return "Yes";
    });

    expect(order).toEqual(["consult open"]);
    releaseConsult!();
    await consult;
    await halter;
    expect(order).toEqual(["consult open", "halter prompt open"]);
  });

  it("the lock is released when the prompt select resolves with a cancel", async () => {
    const ctx: any = { ui: { select: async () => undefined } };
    const result = await twoTierAlwaysPrompt(makePrompt(), store, ctx, vi.fn(), vi.fn(), vi.fn());
    expect(result).toBe("no"); // cancel → reason-less No
    let ran = false;
    await halterLock(async () => {
      ran = true;
    });
    expect(ran).toBe(true);
  });
});
