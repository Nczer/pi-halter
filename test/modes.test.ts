/**
 * Single-mode machine (index.ts): manual / dsp / dspa / dspat — enabling one
 * leaves the others off, and leaving a judge mode resets its session stats.
 * The command handlers are the only writers of mode state, so these tests
 * drive the production handlers through a stubbed ExtensionAPI.
 */
import { describe, expect, it, vi, beforeEach, afterAll } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { resetSettingsCache } from "../halter-settings";

const handlersMock = vi.hoisted(() => ({
  handleBash: vi.fn(),
  handleFile: vi.fn(),
}));
vi.mock("../handlers", () => handlersMock);
// Redirect halter's settings to a scratch file: the /dspa toggle PERSISTS
// (settings-ext.json) and the factory's session_start reads it back. The
// path is computed inside the (hoisted) mock factory and exposed as __file.
vi.mock("../halter-settings", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../halter-settings")>();
  const file = path.join(
    fs.mkdtempSync(path.join(os.tmpdir(), "halter-modes-")),
    "settings-ext.json",
  );
  return {
    ...actual,
    __file: file,
    readSettingsFile: (p?: string) => actual.readSettingsFile(p ?? file),
    writeSettings: (patch: Record<string, unknown>, p?: string) => actual.writeSettings(patch, p ?? file),
  };
});
import halterExtension from "../index";
import * as halterSettings from "../halter-settings";
const settingsPath: string = (halterSettings as { __file?: string }).__file ?? "";
import { isDspActive, setDspActive } from "../modes/dsp-mode";
import { isDspaActive, setDspaActive, resetDspa, recordDspaAutoAllowed, getDspaStats } from "../modes/dspa-mode";
import { isDspatActive, setDspatActive, resetDspat, recordDspatOutcome, getDspatStats } from "../modes/dspat-mode";

interface CommandDef {
  description: string;
  handler: (args?: string, ctx?: unknown) => Promise<void>;
}

type EventName = string;
type EventHandler = (event: unknown, ctx: unknown) => Promise<void>;

function makePi() {
  const commands = new Map<string, CommandDef>();
  const events = new Map<EventName, EventHandler[]>();
  return {
    api: {
      on: (name: EventName, handler: EventHandler) => {
        const list = events.get(name) ?? [];
        list.push(handler);
        events.set(name, list);
      },
      registerCommand: (name: string, def: CommandDef) => void commands.set(name, def),
    },
    commands,
    events,
  };
}

function makeCtx(confirmResult: boolean = true) {
  return {
    hasUI: true,
    ui: {
      confirm: vi.fn(async () => confirmResult),
      notify: vi.fn(),
      setWidget: vi.fn(),
    },
  } as any;
}

async function command(name: string, ctx: ReturnType<typeof makeCtx>): Promise<void> {
  const { api, commands } = makePi();
  await halterExtension(api as never);
  await commands.get(name)!.handler("", ctx);
}

/** Fresh factory + a session_start event (the restart/reload path). */
async function startSession(ctx: ReturnType<typeof makeCtx>): Promise<void> {
  const { api, events } = makePi();
  await halterExtension(api as never);
  for (const h of events.get("session_start") ?? []) {
    await h({ type: "session_start", reason: "startup" }, ctx);
  }
}

afterAll(() => {
  if (settingsPath) fs.rmSync(path.dirname(settingsPath), { recursive: true, force: true });
});

beforeEach(() => {
  setDspActive(false);
  resetDspa();
  resetDspat();
  // Fresh settings file per test (the /dspa toggle persists into it).
  try { fs.unlinkSync(settingsPath); } catch { /* first test */ }
  resetSettingsCache();
});

describe("single-mode machine", () => {
  it("enabling dspa while dspat is active switches; dspat state + stats are reset", async () => {
    setDspatActive(true);
    recordDspatOutcome("m1", true, true, "ls");
    expect(getDspatStats().total).toBe(1);
    const ctx = makeCtx();
    await command("dspa", ctx);
    expect(isDspaActive()).toBe(true);
    expect(isDspatActive()).toBe(false);
    expect(getDspatStats().total).toBe(0);
    expect(ctx.ui.notify).toHaveBeenCalledWith(expect.stringContaining("DSPA ON"), "info");
    expect(ctx.ui.notify).toHaveBeenCalledWith(expect.stringContaining("(DSPAT off)"), "info");
  });

  it("enabling dsp while dspa is active switches (confirmed); dspa state + stats are reset", async () => {
    setDspaActive(true);
    recordDspaAutoAllowed("m1", "ls");
    expect(getDspaStats().autoAllowed).toBe(1);
    const ctx = makeCtx(true);
    await command("dsp", ctx);
    expect(ctx.ui.confirm).toHaveBeenCalled();
    expect(isDspActive()).toBe(true);
    expect(isDspaActive()).toBe(false);
    expect(getDspaStats().autoAllowed).toBe(0);
    expect(ctx.ui.notify).toHaveBeenCalledWith(expect.stringContaining("(DSPA off)"), "warning");
  });

  it("a cancelled DSP confirmation keeps the current mode", async () => {
    setDspatActive(true);
    await command("dsp", makeCtx(false));
    expect(isDspActive()).toBe(false);
    expect(isDspatActive()).toBe(true);
  });

  it("toggling the active mode off returns to manual", async () => {
    await command("dspa", makeCtx());
    expect(isDspaActive()).toBe(true);
    const ctx = makeCtx();
    await command("dspa", ctx);
    expect(isDspaActive()).toBe(false);
    expect(isDspatActive()).toBe(false);
    expect(isDspActive()).toBe(false);
    expect(ctx.ui.notify).toHaveBeenCalledWith(expect.stringContaining("DSPA OFF"), "info");
  });
});

describe("dspa persistence (settings-ext.json, halter.mode)", () => {
  const raw = () => JSON.parse(fs.readFileSync(settingsPath, "utf-8"));

  it("/dspa on persists the startup mode; a new session restores it", async () => {
    await command("dspa", makeCtx());
    expect(raw().halter.mode).toBe("dspa");
    // Fresh module state (a restart re-loads the extension): session_start
    // restores dspa from the settings file.
    resetDspa();
    expect(isDspaActive()).toBe(false);
    const ctx = makeCtx();
    await startSession(ctx);
    expect(isDspaActive()).toBe(true);
    expect(ctx.ui.notify).toHaveBeenCalledWith(expect.stringContaining("DSPA ON"), "info");
  });

  it("/dspa off clears the persisted startup mode", async () => {
    await command("dspa", makeCtx());
    const ctx = makeCtx();
    await command("dspa", ctx);
    expect(raw().halter.mode).toBe("manual");
    resetDspa();
    await startSession(makeCtx());
    expect(isDspaActive()).toBe(false);
  });

  it("a fresh session with no persisted mode stays manual", async () => {
    await startSession(makeCtx());
    expect(isDspaActive()).toBe(false);
    expect(isDspActive()).toBe(false);
    expect(isDspatActive()).toBe(false);
  });

  it("/dsp and /dspat are session-scoped — they never touch the persisted mode", async () => {
    await command("dspa", makeCtx());
    await command("dspat", makeCtx()); // displaces dspa in this session
    expect(isDspatActive()).toBe(true);
    expect(raw().halter.mode).toBe("dspa"); // ...but the next session still starts in dspa
  });
});
