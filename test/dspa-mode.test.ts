/**
 * dspa-mode.ts — auto-allow mode state, model-scoped session counters, status.
 */
import { describe, it, expect, beforeEach, beforeAll, afterAll, vi } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import { visibleWidth } from "@earendil-works/pi-tui";
import {
  isDspaActive,
  setDspaActive,
  resetDspa,
  recordDspaAutoAllowed,
  recordDspaStop,
  getDspaStats,
  updateDspaWidget,
  setDspaJudging,
  persistDspaMode,
  readPersistedMode,
} from "../modes/dspa-mode";
import { resetSettingsCache } from "../halter-settings";
import { onStatusChange } from "../modes/status-bus";
import { updateStatus } from "../ui/widget";

const { judgeStatusMock } = vi.hoisted(() => ({
  judgeStatusMock: vi.fn<() => { state: string; modelLabel: string | null; reason: string | null }>(),
}));
vi.mock("../judge/verdict", () => ({ judgeStatus: judgeStatusMock }));

beforeEach(() => {
  resetDspa();
  judgeStatusMock.mockReset();
  judgeStatusMock.mockReturnValue({ state: "off", modelLabel: null, reason: null });
  // Production wiring (index.ts): the unified status is the status-bus
  // listener — mode → bus → status → setStatus.
  onStatusChange(updateStatus);
});

describe("mode toggle", () => {
  it("off by default, toggles on/off", () => {
    expect(isDspaActive()).toBe(false);
    setDspaActive(true);
    expect(isDspaActive()).toBe(true);
    setDspaActive(false);
    expect(isDspaActive()).toBe(false);
  });

  it("disabling resets the counters (fresh stats when re-enabled)", () => {
    setDspaActive(true);
    recordDspaAutoAllowed("m1", "cargo build");
    setDspaActive(false);
    expect(getDspaStats().autoAllowed).toBe(0);
    setDspaActive(true);
    recordDspaAutoAllowed("m1", "cargo build");
    expect(getDspaStats().autoAllowed).toBe(1);
  });

  it("resetDspa clears mode and stats", () => {
    setDspaActive(true);
    recordDspaAutoAllowed("m1", "ls");
    resetDspa();
    expect(isDspaActive()).toBe(false);
    expect(getDspaStats()).toEqual({ model: null, autoAllowed: 0, lastTarget: null, gate: 0, deny: 0, declined: 0, defer: 0 });
  });
});

describe("counters", () => {
  it("records auto-allows with target", () => {
    recordDspaAutoAllowed("m1", "cargo build --release");
    expect(getDspaStats()).toEqual({
      model: "m1",
      autoAllowed: 1,
      lastTarget: "cargo build --release",
      gate: 0,
      deny: 0,
      declined: 0,
      defer: 0,
    });
  });

  it("a model change resets the counters", () => {
    recordDspaAutoAllowed("m1", "a");
    recordDspaAutoAllowed("m1", "b");
    recordDspaAutoAllowed("m2", "c");
    expect(getDspaStats()).toEqual({ model: "m2", autoAllowed: 1, lastTarget: "c", gate: 0, deny: 0, declined: 0, defer: 0 });
  });

  it("stop counters: each kind increments its own bucket", () => {
    // The first NON-NULL model establishes the model scope (a prior null-
    // model stop would have been reset by it — covered below).
    recordDspaStop("gate", "m1");
    recordDspaStop("gate", null); // null model: counted, no reset
    recordDspaStop("deny", "m1");
    recordDspaStop("declined", "m1");
    recordDspaStop("defer", "m1");
    recordDspaStop("defer", null);
    expect(getDspaStats()).toMatchObject({ model: "m1", gate: 2, deny: 1, declined: 1, defer: 2 });
  });

  it("a stop with a NEW model resets all counters (model-scoped)", () => {
    recordDspaAutoAllowed("m1", "a");
    recordDspaStop("deny", "m1");
    recordDspaStop("gate", "m2");
    expect(getDspaStats()).toEqual({ model: "m2", autoAllowed: 0, lastTarget: null, gate: 1, deny: 0, declined: 0, defer: 0 });
  });

  it("a gate stop with no verdict (model null) never resets the counters", () => {
    recordDspaAutoAllowed("m1", "a");
    recordDspaStop("gate", null);
    expect(getDspaStats().autoAllowed).toBe(1);
    expect(getDspaStats().model).toBe("m1");
    expect(getDspaStats().gate).toBe(1);
  });

  it("truncates long targets", () => {
    recordDspaAutoAllowed("m1", "x".repeat(200));
    expect(getDspaStats().lastTarget).toHaveLength(80);
  });

  it("flattens newlines in multi-line targets (one widget element = one screen row)", () => {
    // Regression: a multi-line python3 -c command auto-allowed under /dspa
    // stored a raw \n in lastTarget; the widget line wrapped mid-row and
    // desynced the TUI diff renderer.
    recordDspaAutoAllowed("m1", 'cd /tmp/x && python3 -c "\na = 1\nb = 2\n"');
    const t = getDspaStats().lastTarget;
    expect(t).not.toMatch(/[\r\n]/);
    expect(t).toBe('cd /tmp/x && python3 -c " a = 1 b = 2 "');
  });
});

describe("status (unified halter status — see widget.ts)", () => {
  function makeCtx(hasUI = true) {
    let status: unknown;
    const theme = { fg: (_c: string, s: string) => s, bold: (s: string) => s };
    const ctx = {
      hasUI,
      ui: {
        setStatus: (_id: string, v?: unknown) => {
          status = v;
        },
        setWidget: () => {}, // legacy id clears
        theme,
      },
    } as unknown as ExtensionContext;
    return { ctx, status: () => status };
  }

  it("carries the counter + judge tag (no last-target — dropped in the migration)", () => {
    judgeStatusMock.mockReturnValue({
      state: "ok",
      modelLabel: "llama-cpp/Qwen3.8-27B (session)",
      reason: null,
    });
    setDspaActive(true);
    recordDspaAutoAllowed("llama-cpp/Qwen3.8-27B", "cargo build");
    const { ctx, status } = makeCtx();
    updateDspaWidget(ctx);
    // No session model in this ctx → the judge model shows its short name.
    expect(status()).toBe("» DSPA (Qwen3.8-27B): 1a");
    expect(String(status())).not.toContain("last:");
  });

  it("renders stop counts compactly, non-zero only (a g r c d order)", () => {
    judgeStatusMock.mockReturnValue({ state: "ok", modelLabel: null, reason: null });
    setDspaActive(true);
    recordDspaAutoAllowed("m1", "cargo build");
    recordDspaAutoAllowed("m1", "ls");
    recordDspaStop("gate", null);
    recordDspaStop("deny", "m1");
    recordDspaStop("defer", "m1");
    // declined stays hidden (zero)
    const { ctx, status } = makeCtx();
    updateDspaWidget(ctx);
    // exact count run — a non-zero declined would break this ("…1r 1c 1d…");
    // no session model in this ctx → the model tag shows.
    expect(status()).toBe("» DSPA (m1): 2a 1g 1r 1d");
  });

  it("stays within the fixed budget regardless of target length", () => {
    setDspaActive(true);
    recordDspaAutoAllowed("llama-cpp/Qwen3.8-27B", "x".repeat(120));
    const { ctx, status } = makeCtx();
    updateDspaWidget(ctx);
    expect(visibleWidth(String(status()))).toBeLessThanOrEqual(40);
    expect(status()).toContain("» DSPA");
  });

  it("judging transitions refresh the status and paint the stage inline", () => {
    judgeStatusMock.mockReturnValue({
      state: "ok",
      modelLabel: "llama-cpp/Qwen3.8-27B (session)",
      reason: null,
    });
    setDspaActive(true);
    recordDspaAutoAllowed("llama-cpp/Qwen3.8-27B", "cargo build");
    const { ctx, status } = makeCtx();
    updateDspaWidget(ctx);
    const before = status();
    setDspaJudging(1, ctx); // transition — the stage paints inline
    expect(status()).toBe(before + " — judging stage 1…");
    setDspaJudging(2, ctx); // stage switch — the painted stage follows
    expect(status()).toBe(before + " — judging stage 2…");
    setDspaJudging(null, ctx); // cleared — counts-only line returns
    expect(status()).toBe(before);
  });

  it("clears while the judge is invalid, reappears when it is ok again", () => {
    judgeStatusMock.mockReturnValue({
      state: "invalid",
      modelLabel: null,
      reason: "session model not resolvable",
    });
    setDspaActive(true);
    const { ctx, status } = makeCtx();
    updateDspaWidget(ctx);
    expect(status()).toBeUndefined(); // no rules either → nothing shown
    judgeStatusMock.mockReturnValue({
      state: "ok",
      modelLabel: "llama-cpp/Qwen3.8-27B (session)",
      reason: null,
    });
    updateDspaWidget(ctx);
    expect(status()).toBe("» DSPA"); // bare name pre-first-op
  });

  it("clears when inactive", () => {
    const { ctx, status } = makeCtx();
    updateDspaWidget(ctx);
    expect(status()).toBeUndefined();
  });

  it("no-op without UI", () => {
    const { ctx, status } = makeCtx(false);
    setDspaActive(true);
    updateDspaWidget(ctx);
    expect(status()).toBeUndefined();
  });
});

describe("persistent startup mode (settings-ext.json, halter.mode)", () => {
  let tmp: string;
  let file: string;

  beforeAll(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "dspa-persist-"));
    file = path.join(tmp, "settings-ext.json");
  });
  afterAll(() => {
    fs.rmSync(tmp, { recursive: true, force: true });
  });
  beforeEach(() => {
    resetSettingsCache();
    try { fs.unlinkSync(file); } catch { /* not created */ }
  });

  it("persist + read round-trip", () => {
    persistDspaMode(true, file);
    expect(readPersistedMode(file)).toBe("dspa");
    persistDspaMode(false, file);
    expect(readPersistedMode(file)).toBe("manual");
  });

  it("missing file → manual (fail-closed)", () => {
    expect(readPersistedMode(file)).toBe("manual");
  });

  it("corrupt file → manual (fail-closed, never dspa)", () => {
    fs.writeFileSync(file, "not json {");
    expect(readPersistedMode(file)).toBe("manual");
  });

  it("a non-dspa mode value (e.g. hand-written \"dsp\") → manual", () => {
    fs.writeFileSync(file, JSON.stringify({ halter: { mode: "dsp" } }));
    expect(readPersistedMode(file)).toBe("manual");
  });
});
