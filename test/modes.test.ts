/**
 * Single-mode machine (index.ts): manual / dsp / dspa / dspat — enabling one
 * leaves the others off, and leaving a judge mode resets its session stats.
 * The command handlers are the only writers of mode state, so these tests
 * drive the production handlers through a stubbed ExtensionAPI.
 */
import { describe, expect, it, vi, beforeEach } from "vitest";

const handlersMock = vi.hoisted(() => ({
  handleBash: vi.fn(),
  handleFile: vi.fn(),
}));
vi.mock("../handlers", () => handlersMock);
import halterExtension from "../index";
import { isDspActive, setDspActive } from "../modes/dsp-mode";
import { isDspaActive, setDspaActive, resetDspa, recordDspaAutoAllowed, getDspaStats } from "../modes/dspa-mode";
import { isDspatActive, setDspatActive, resetDspat, recordDspatOutcome, getDspatStats } from "../modes/dspat-mode";

interface CommandDef {
  description: string;
  handler: (args?: string, ctx?: unknown) => Promise<void>;
}

function makePi() {
  const commands = new Map<string, CommandDef>();
  return {
    api: {
      on: () => {},
      registerCommand: (name: string, def: CommandDef) => void commands.set(name, def),
    },
    commands,
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

beforeEach(() => {
  setDspActive(false);
  resetDspa();
  resetDspat();
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
    expect(ctx.ui.notify).toHaveBeenCalledWith("DSPA OFF — all prompts restored", "info");
  });
});
