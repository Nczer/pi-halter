import { describe, it, expect, vi, beforeEach, beforeAll } from "vitest";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { loadPlugins, setLoadedPlugins } from "../plugins/loader";
import { handleTool } from "../handlers/tool";
import { store } from "../store";

const FIXTURE_ROOT = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "fixtures",
  "plugins",
);

function fakeCtx() {
  return { cwd: "/tmp/halter-fixture", hasUI: false, ui: { notify: vi.fn() } } as any;
}

function fakeEvent(toolName: string, input: Record<string, unknown> = {}) {
  return { toolName, input } as any;
}

describe("plugin loader", () => {
  it("loads valid plugins, marks broken ones, skips exts without halter/", async () => {
    const slots = await loadPlugins(FIXTURE_ROOT);

    const good = slots.get("good");
    expect(good?.state).toBe("ok");
    if (good?.state === "ok") expect(good.plugin.name).toBe("good");

    const bad = slots.get("mismatch");
    expect(bad?.state).toBe("broken");
    if (bad?.state === "broken") expect(bad.error).toContain("must equal");

    const threw = slots.get("throws");
    expect(threw?.state).toBe("broken");
    if (threw?.state === "broken") expect(threw.error).toContain("boom");

    const thrower = slots.get("thrower");
    expect(thrower?.state).toBe("ok"); // valid contract — throws only at call time

    expect(slots.has("noplugin")).toBe(false);
  });
});

describe("handleTool dispatch", () => {
  let slots: Awaited<ReturnType<typeof loadPlugins>>;

  beforeAll(async () => {
    slots = await loadPlugins(FIXTURE_ROOT);
    setLoadedPlugins(slots);
  });

  beforeEach(() => store.reset());

  it("passes through tools without a plugin", async () => {
    expect(await handleTool(fakeEvent("bash"), fakeCtx())).toBeUndefined();
    expect(await handleTool(fakeEvent("noplugin"), fakeCtx())).toBeUndefined();
  });

  it("blocks tools whose plugin failed to load (fail closed)", async () => {
    const r = await handleTool(fakeEvent("mismatch"), fakeCtx());
    expect(r).toBeDefined();
    if (!r) throw new Error("expected block");
    expect(r.reason).toContain("failed to load");
  });

  it("blocks when buildRequest throws (fail closed)", async () => {
    const r = await handleTool(fakeEvent("thrower"), fakeCtx());
    expect(r).toBeDefined();
    if (!r) throw new Error("expected block");
    expect(r.reason).toContain("threw");
    expect(r.reason).toContain("classification exploded");
  });

  it("passes through null classifications (discovery/status)", async () => {
    expect(await handleTool(fakeEvent("good"), fakeCtx())).toBeUndefined();
    // goodbuild: non-`run` action → null → pass
    expect(await handleTool(fakeEvent("goodbuild", { action: "status" }), fakeCtx())).toBeUndefined();
  });

  it("gates classified calls through the gate (no UI → block)", async () => {
    const r = await handleTool(
      fakeEvent("goodbuild", { action: "run", code: "print(1)" }),
      fakeCtx(),
    );
    expect(r).toBeDefined();
    if (!r) throw new Error("expected block");
    // no-UI block from gate() — proof the exec request reached the gate
    expect(r.reason).toContain("no UI");
  });
});
