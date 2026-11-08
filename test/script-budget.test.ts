import { describe, it, expect, beforeAll, beforeEach } from "vitest";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { checkScriptBudget, resetScriptBudget, scriptBudgetUsed, MAX_GATED_CALLS_PER_SCRIPT } from "../gate/script-budget";
import { loadPlugins, setLoadedPlugins } from "../plugins/loader";

const FIXTURE_ROOT = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "fixtures",
  "plugins",
);

// A nested call is one a script issued: pi marks it with parentToolCallId
// (harness-side; not in the pinned extension types, so the budget reads it
// defensively). These events cast like the budget module does.
function direct(toolName: string) {
  return { toolName, input: {} } as any;
}
function nested(toolName: string, parent: string) {
  return { toolName, input: {}, parentToolCallId: parent } as any;
}

describe("scripted-call budget", () => {
  beforeAll(async () => {
    setLoadedPlugins(await loadPlugins(FIXTURE_ROOT));
  });
  beforeEach(() => resetScriptBudget());

  it("never touches the model's own calls", () => {
    for (let i = 0; i < MAX_GATED_CALLS_PER_SCRIPT * 2; i++) {
      expect(checkScriptBudget(direct("bash"))).toBeUndefined();
    }
  });

  it("lets one script through up to the ceiling, then blocks fail-fast", () => {
    for (let i = 0; i < MAX_GATED_CALLS_PER_SCRIPT; i++) {
      expect(checkScriptBudget(nested("bash", "tc/1"))).toBeUndefined();
    }
    const r = checkScriptBudget(nested("bash", "tc/1"));
    expect(r?.block).toBe(true);
    if (!r) throw new Error("expected block");
    // the reason must be actionable: what the ceiling was, and what to do
    expect(r.reason).toContain(String(MAX_GATED_CALLS_PER_SCRIPT));
    expect(r.reason).toContain("split");
    expect(scriptBudgetUsed("tc/1")).toBe(MAX_GATED_CALLS_PER_SCRIPT); // blocked calls don't count
  });

  it("tracks each script separately", () => {
    for (let i = 0; i < MAX_GATED_CALLS_PER_SCRIPT; i++) {
      checkScriptBudget(nested("bash", "tc/a"));
    }
    expect(checkScriptBudget(nested("bash", "tc/a"))?.block).toBe(true);
    expect(checkScriptBudget(nested("bash", "tc/b"))).toBeUndefined();
    resetScriptBudget();
    expect(checkScriptBudget(nested("bash", "tc/a"))).toBeUndefined();
  });

  it("counts the surface halter evaluates, and only that", () => {
    for (const tool of ["bash", "read", "write", "edit", "good", "fakeglob__anything"]) {
      expect(checkScriptBudget(nested(tool, "tc/s")), tool).toBeUndefined();
    }
    expect(scriptBudgetUsed("tc/s")).toBe(6);
    // a call halter does not evaluate (no handler, no plugin slot) stays free
    for (let i = 0; i < MAX_GATED_CALLS_PER_SCRIPT * 2; i++) {
      expect(checkScriptBudget(nested("noplugin", "tc/s"))).toBeUndefined();
    }
    expect(scriptBudgetUsed("tc/s")).toBe(6);
  });

  it("tolerates a malformed event name (the handlers report that, not the budget)", () => {
    expect(checkScriptBudget({ toolName: 7, input: {}, parentToolCallId: "tc/x" } as any)).toBeUndefined();
    expect(checkScriptBudget({ toolName: "bash", input: {}, parentToolCallId: "" } as any)).toBeUndefined();
  });

  it("evicts the oldest script keys instead of growing forever", () => {
    for (let i = 0; i < 300; i++) checkScriptBudget(nested("bash", `tc/${i}`));
    expect(scriptBudgetUsed("tc/0")).toBe(0); // evicted
    expect(scriptBudgetUsed("tc/299")).toBe(1); // kept
  });
});
