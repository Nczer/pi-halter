import { describe, it, expect, vi, beforeEach, beforeAll } from "vitest";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { loadPlugins, setLoadedPlugins, getPluginLoadError, globToRegExp, isGlobKey } from "../plugins/loader";
import { handleTool } from "../handlers/tool";
import { store } from "../gate/store";

const FIXTURE_ROOT = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "fixtures",
  "plugins",
);
// Separate root: holds a plugin whose dispatch key is `*` — loaded there so it
// cannot swallow the tool names the tests above use.
const GLOBERR_ROOT = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "fixtures",
  "plugins-globerr",
);

function fakeCtx() {
  return { cwd: "/tmp/halter-fixture", hasUI: false, ui: { notify: vi.fn() } } as any;
}

function fakeEvent(toolName: string, input: Record<string, unknown> = {}) {
  return { toolName, input } as any;
}

describe("plugin loader", () => {
  it("keys slots by the gated tool's name (multi-tool exts: tool ≠ dir)", async () => {
    const slots = await loadPlugins(FIXTURE_ROOT);

    const good = slots.get("good");
    expect(good?.state).toBe("ok");
    if (good?.state === "ok") expect(good.plugin.name).toBe("good");

    // a plugin may gate a tool whose name differs from its ext directory
    const cross = slots.get("othertool");
    expect(cross?.state).toBe("ok");
    if (cross?.state === "ok") expect(cross.plugin.name).toBe("othertool");
    expect(slots.has("crosstool")).toBe(false); // the dir name is not a slot

    const thrower = slots.get("thrower");
    expect(thrower?.state).toBe("ok"); // valid contract — throws only at call time

    expect(slots.has("noplugin")).toBe(false);
  });

  it("an unreadable extensions root is a load error, never a silent empty map", async () => {
    // The scan cannot prove which tools are gated: handlers/tool.ts blocks
    // instead of passing every gated tool through ungated (3.50.0).
    const missing = path.join(FIXTURE_ROOT, "does-not-exist");
    const slots = await loadPlugins(missing);
    expect(slots.size).toBe(0);
    expect(getPluginLoadError()).toBeTruthy();
    // A later successful scan clears it.
    await loadPlugins(FIXTURE_ROOT);
    expect(getPluginLoadError()).toBeNull();
  });

  it("marks broken plugins, keyed fail-closed (sniffed name, else ext dir)", async () => {
    const slots = await loadPlugins(FIXTURE_ROOT);

    const threw = slots.get("throws");
    expect(threw?.state).toBe("broken");
    if (threw?.state === "broken") expect(threw.error).toContain("boom");

    // import failure with a readable name literal → the REAL tool is blocked
    const serr = slots.get("serrtool");
    expect(serr?.state).toBe("broken");
    if (serr?.state === "broken") expect(serr.error.length).toBeGreaterThan(0);

    // no name literal (contract violation) → falls back to the ext dir name
    const noname = slots.get("noname");
    expect(noname?.state).toBe("broken");
    if (noname?.state === "broken") expect(noname.error).toContain("non-empty string");
  });
});

describe("glob (namespace) slots", () => {
  it("keys a glob plugin by its `match`, not its name or ext dir", async () => {
    const slots = await loadPlugins(FIXTURE_ROOT);
    expect(slots.get("fakeglob__*")?.state).toBe("ok");
    expect(slots.has("globhost")).toBe(false); // the plugin's name is not a slot
  });

  it("rejects glob syntax beyond `*` (`?`), keyed fail-closed by the sniffed match", async () => {
    const slots = await loadPlugins(FIXTURE_ROOT);
    const bad = slots.get("fake?bad__*");
    expect(bad?.state).toBe("broken");
    if (bad?.state === "broken") expect(bad.error).toContain("wildcard");
  });

  it("rejects a wildcard-only `match` (it would gate every tool)", async () => {
    const slots = await loadPlugins(GLOBERR_ROOT);
    const wild = slots.get("*");
    expect(wild?.state).toBe("broken");
    if (wild?.state === "broken") expect(wild.error).toContain("namespace");
  });

  it("globToRegExp: `*` spans anything, everything else is literal", () => {
    const re = globToRegExp("mcp__blender__*");
    expect(re.test("mcp__blender__get_scene"));
    expect(re.test("mcp__blender__")); // `*` matches the empty string too
    expect(re.test("mcp__other__x")).toBe(false);
    expect(isGlobKey("mcp__blender__*")).toBe(true);
    expect(isGlobKey("bash")).toBe(false);
    // regex metacharacters in the literal part stay literal
    expect(globToRegExp("a+b*").test("axb")).toBe(false);
    expect(globToRegExp("a+b*").test("a+b")).toBe(true);
  });
});

describe("handleTool dispatch — glob slots", () => {
  beforeEach(() => store.reset());

  it("routes any verb in the namespace through the gate", async () => {
    setLoadedPlugins(await loadPlugins(FIXTURE_ROOT));
    const r = await handleTool(fakeEvent("fakeglob__anything"), fakeCtx());
    expect(r).toBeDefined();
    if (!r) throw new Error("expected block");
    expect(r.reason).toContain("no UI"); // the glob plugin's exec request reached the gate
  });

  it("prefers an exact slot over a glob covering the same name", async () => {
    setLoadedPlugins(await loadPlugins(FIXTURE_ROOT));
    // globexact gates `fakeglob__exact` and classifies null → pass, even though
    // globexec's `fakeglob__*` also matches it.
    expect(await handleTool(fakeEvent("fakeglob__exact"), fakeCtx())).toBeUndefined();
  });

  it("blocks a concrete verb whose glob plugin failed to load, naming the pattern", async () => {
    setLoadedPlugins(await loadPlugins(FIXTURE_ROOT));
    const r = await handleTool(fakeEvent("fakebroken__read"), fakeCtx());
    expect(r).toBeDefined();
    if (!r) throw new Error("expected block");
    expect(r.reason).toContain("failed to load");
    expect(r.reason).toContain("fakebroken__*"); // fixable from the message alone
  });

  it("a rejected wildcard-only pattern still blocks (fail closed, key `*`)", async () => {
    setLoadedPlugins(await loadPlugins(GLOBERR_ROOT));
    try {
      const r = await handleTool(fakeEvent("bash"), fakeCtx());
      expect(r).toBeDefined();
      if (!r) throw new Error("expected block");
      expect(r.reason).toContain("failed to load");
    } finally {
      setLoadedPlugins(await loadPlugins(FIXTURE_ROOT)); // do not leak the `*` slot
    }
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
    // the ext dir of a cross-named plugin is not itself a gated tool
    expect(await handleTool(fakeEvent("crosstool"), fakeCtx())).toBeUndefined();
  });

  it("blocks tools whose plugin failed to load (fail closed)", async () => {
    const r = await handleTool(fakeEvent("noname"), fakeCtx());
    expect(r).toBeDefined();
    if (!r) throw new Error("expected block");
    expect(r.reason).toContain("failed to load");

    // import failure: the sniffed tool name is blocked, not just the ext dir
    const serr = await handleTool(fakeEvent("serrtool"), fakeCtx());
    expect(serr).toBeDefined();
    if (!serr) throw new Error("expected block");
    expect(serr.reason).toContain("failed to load");
  });

  it("forwards ctx to buildRequest", async () => {
    // ctxfwd throws if ctx is missing — a pass-through proves it arrived
    expect(await handleTool(fakeEvent("ctxfwd"), fakeCtx())).toBeUndefined();
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
    // othertool (gated from the crosstool dir) classifies null → pass
    expect(await handleTool(fakeEvent("othertool"), fakeCtx())).toBeUndefined();
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
