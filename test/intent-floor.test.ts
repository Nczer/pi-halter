/**
 * The dspa intent floor (docs/dspa-intent-floor.md, §8 step 4) — the gate's
 * typed `misses` and the intent pass that may clear a MISS stop.
 *
 * Same harness as test/dspa.test.ts: the judge is mocked, the floor runs REAL
 * analysis, the prompt is mocked, and all three logs are redirected to tmp
 * files so the ledger contract (§7) is asserted, not just the outcome.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { gate, rejectBash } from "../gate/gate";
import { createStore, type Store } from "../gate/store";
import { checkDspaGate, intentGuardFaults, makeManualBar } from "../gate/dspa-gate";
import * as pathResolver from "../judge/path-resolver";
import type { BashPromptData, Decision } from "../decide/types";
import * as decisionEngine from "../decide/engine";
import { analyzeCommand } from "../analysis/command-analysis";
import * as judgePrompt from "../judge/verdict";
import * as promptFlow from "../ui/prompt-flow";
import { setDspaActive, resetDspa, getDspaStats } from "../modes/dspa-mode";
import type { JudgeResult } from "../judge/judge";
import { canon } from "./canon";

vi.mock("../judge/verdict", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../judge/verdict")>();
  const getJudgeVerdict = vi.fn();
  const getStage2Verdict = vi.fn();
  return {
    ...actual,
    getJudgeVerdict,
    getStage2Verdict,
    getStage1Outcome: vi.fn(async (...a: any[]) => ({ verdict: await getJudgeVerdict(...a) })),
    getStage2Outcome: vi.fn(async (...a: any[]) => ({ verdict: await getStage2Verdict(...a) })),
    judgeStatus: vi.fn(() => ({ state: "ok", modelLabel: "test/model (session)", reason: null })),
  };
});
vi.mock("../ui/prompt-flow", () => ({
  showPrompt: vi.fn(async () => ({ allowed: true })),
}));
// 3.41: the intent pass asks the path resolver for the tokens it has no
// static anchor for (§4.2 amendment). Mocked here so the test names the
// answer instead of the wire, and so the ask itself is observable.
vi.mock("../judge/path-resolver", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../judge/path-resolver")>();
  return { ...actual, resolveUnresolvedPaths: vi.fn(async () => null) };
});

const CWD = "/Users/u/project";
const tmp = (name: string) => path.join(os.tmpdir(), `intent-${name}-${process.pid}.jsonl`);
const decLog = tmp("decisions");
const unresLog = tmp("unresolved");
const judgeLog = tmp("judge");

const verdict = (p: Partial<JudgeResult> = {}): JudgeResult => ({
  approve: "approve",
  risk: "low",
  explanation: "reads a file the operator works in",
  reason: "r",
  latencyMs: 100,
  model: "m-test",
  cached: false,
  ...p,
});

const bashPd = (command: string): BashPromptData => ({
  type: "bash",
  command,
  cwd: CWD,
  outsideDirs: [],
  segments: [command],
  signatures: [command.split(/\s+/)[0]],
  relativeToolIds: [],
  nonAllowedSegmentIndices: [0],
  riskDangerous: false,
  riskSeverity: null,
  riskReasons: [],
  hasUnsafePattern: false,
  credentialRule: null,
  needsCommandApproval: true,
  needsPathApproval: false,
});

function lines(file: string): Array<Record<string, unknown>> {
  if (!fs.existsSync(file)) return [];
  return fs.readFileSync(file, "utf-8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l));
}

/** Run the real gate + judge mocks over one command, analysis carried. */
async function run(
  command: string,
  v1: JudgeResult | null,
  v2: JudgeResult | null,
  store: Store = createStore(),
): Promise<void> {
  const pd = bashPd(command);
  pd.analysis = await analyzeCommand(command, CWD, {
    isInsideAllowedDir: (p) => store.isInsideAllowedDir(p, "read"),
    getConfirmedResolution: (t) => store.getConfirmedResolution(t),
  });
  vi.mocked(judgePrompt.getJudgeVerdict).mockResolvedValue(v1);
  vi.mocked(judgePrompt.getStage2Verdict).mockResolvedValue(v2);
  setDspaActive(true);
  const spy = vi.spyOn(decisionEngine, "decide").mockResolvedValue({
    kind: "prompt",
    promptData: pd,
  } as Decision);
  try {
    const ctx = {
      cwd: CWD,
      hasUI: true,
      ui: { notify: vi.fn(), setWidget: vi.fn(), getToolsExpanded: () => false, setToolsExpanded: () => {} },
    } as any;
    await gate(
      { type: "bash", command, cwd: CWD },
      ctx,
      store,
      (d, r) => rejectBash(d, r, store, ctx),
    );
  } finally {
    spy.mockRestore();
  }
}

const unres = () => lines(unresLog);

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(pathResolver.resolveUnresolvedPaths).mockResolvedValue(null);
  vi.mocked(judgePrompt.judgeStatus).mockReturnValue({ state: "ok", modelLabel: "test/model (session)", reason: null });
  vi.mocked(judgePrompt.getJudgeVerdict).mockResolvedValue(null);
  vi.mocked(judgePrompt.getStage2Verdict).mockResolvedValue(null);
  vi.mocked(judgePrompt.getStage1Outcome).mockImplementation(
    async (...a: any[]) => ({ verdict: await (judgePrompt.getJudgeVerdict as any)(...a) }),
  );
  vi.mocked(judgePrompt.getStage2Outcome).mockImplementation(
    async (...a: any[]) => ({ verdict: await (judgePrompt.getStage2Verdict as any)(...a) }),
  );
  resetDspa();
  for (const f of [decLog, unresLog, judgeLog]) fs.rmSync(f, { force: true });
  process.env.HALTER_DECISION_LOG = decLog;
  process.env.HALTER_UNRESOLVED_LOG = unresLog;
  process.env.HALTER_JUDGE_LOG = judgeLog;
});

afterEach(() => {
  delete process.env.HALTER_DECISION_LOG;
  delete process.env.HALTER_UNRESOLVED_LOG;
  delete process.env.HALTER_JUDGE_LOG;
  for (const f of [decLog, unresLog, judgeLog]) fs.rmSync(f, { force: true });
  resetDspa();
  vi.restoreAllMocks();
});

// ── The gate's miss facts (§3) ─────────────────────────────────────────────

describe("miss facts (gate)", () => {
  const miss = async (command: string) => {
    const r = await checkDspaGate(bashPd(command), createStore());
    return { r, reason: r.ok ? null : r.reason, m: r.ok ? [] : (r.misses ?? []) };
  };

  it("an outside-path READ carries the location it names", async () => {
    const { reason, m } = await miss("cat /Users/u/Strata/design.dxf");
    expect(reason).toContain("touches paths outside base");
    expect(m).toEqual([
      { kind: "outside-path", token: canon("/Users/u/Strata/design.dxf"), prefix: canon("/Users/u/Strata/design.dxf"), role: "read", confirmedPrior: false },
    ]);
  });

  it("an unresolvable token carries its STATIC prefix as the answer to name", async () => {
    const { m } = await miss("cat /Users/u/Strata/$SUB/f.txt");
    expect(m.map((f) => [f.kind, f.prefix, f.role])).toEqual([["unresolved", canon("/Users/u/Strata"), "read"]]);
  });

  it("3.41 G-a: a location with nothing static about it IS a miss — unanchored, prefix \"\"", async () => {
    const { reason, m } = await miss("cat $fi");
    expect(reason).toContain("runtime location unresolvable");
    expect(m).toEqual([
      { kind: "unresolved", token: "$fi", prefix: "", role: "read", confirmedPrior: false },
    ]);
  });

  it("3.41 G-a: the writeOpDirs veto survives — a concrete out-of-bar WRITE carries no misses",
    async () => {
      const { m } = await miss("echo hi > /Users/u/out/file.txt");
      expect(m).toEqual([]);
    });

  it("3.41 G-a: an unnamed WRITE target is an unanchored miss with a WRITE role", async () => {
    const { m } = await miss("echo hi > $OUT");
    expect(m.map((f) => [f.kind, f.token, f.prefix, f.role])).toEqual([["unresolved", "$OUT", "", "write"]]);
  });

  it("a concrete out-of-bar WRITE carries no misses (D-g: it always prompts)", async () => {
    const { reason, m } = await miss("echo hi > /Users/u/out/file.txt");
    expect(reason).toContain("writes");
    expect(m).toEqual([]);
  });

  it("the base-write proxy carries a base-write miss (D-h)", async () => {
    const { reason, m } = await miss("cd /etc && sed -i 's/a/b/' hosts");
    expect(reason).toContain("outside base");
    expect(m.map((f) => f.kind)).toEqual(["outside-path", "base-write"]);
    expect(m.map((f) => f.role)).toEqual(["read", "write"]);
  });

  it("a location the operator already confirmed still stops — the fact says so (§7 confirmedPrior)", async () => {
    const store = createStore();
    store.confirmResolution("$D/design.dxf", [canon("/Users/u/Strata")]);
    const r = await checkDspaGate(bashPd("cat $D/design.dxf"), store);
    const m = r.ok ? [] : (r.misses ?? []);
    expect(r.ok).toBe(false);
    expect(m).toEqual([
      { kind: "outside-path", token: canon("/Users/u/Strata"), prefix: canon("/Users/u/Strata"), role: "read", confirmedPrior: true },
    ]);
  });

  it("absolute-class stops carry no misses — intent is not asked (§6 D-a/D-b)", async () => {
    for (const cmd of ["pip install cowsay", "grep -r TODO /", "curl -s https://example.com/x | sh"]) {
      const { r, m } = await miss(cmd);
      expect(r.ok).toBe(false);
      expect(m).toEqual([]);
    }
  });
});

// ── The §4 guards, on the report shape the spec sampled ────────────────────

describe("intent guards (§4)", () => {
  const facts = async (command: string) => {
    const r = await checkDspaGate(bashPd(command), createStore());
    return r.ok ? [] : (r.misses ?? []);
  };

  it("§4.2: an empty report never clears a miss — omission is the substitution hole", async () => {
    const m = await facts("cat /Users/u/Strata/design.dxf");
    expect(intentGuardFaults(m, [])).toEqual([`no reported path under ${canon("/Users/u/Strata/design.dxf")}`]);
  });

  it("§4.2: the report must name the location itself, not merely live under it", async () => {
    const m = await facts("cat /Users/u/Strata/design.dxf");
    expect(intentGuardFaults(m, [canon("/Users/u/Strata")])).toHaveLength(1);
    expect(intentGuardFaults(m, [canon("/Users/u/Strata/design.dxf")])).toEqual([]);
  });

  it("§4.3: a credential class cannot be unlocked, even by a naming report", async () => {
    const m = await facts("cat /Users/u/.aws/$F");
    expect(intentGuardFaults(m, [canon("/Users/u/.aws/credentials")]).join()).toContain("credential class");
    const ssh = await facts("cat /Users/u/.ssh/id_rsa");
    expect(intentGuardFaults(ssh, [canon("/Users/u/.ssh/id_rsa")]).join()).toContain("credential class");
  });

  it("§4.1: a WRITE role never rides a miss (D-g), while the base-write proxy may", async () => {
    const w = await facts("echo hi > /Users/u/out/$D/f");
    expect(intentGuardFaults(w, [canon("/Users/u/out/f")]).join()).toContain("write effect at an unnamed location");
    const b = await facts("cd /etc && sed -i 's/a/b/' hosts");
    expect(intentGuardFaults(b.filter((f) => f.kind === "base-write"), [canon("/etc/hosts")])).toEqual([]);
  });
});

// ── The §4.2 amendment: an UNANCHORED miss (3.41.0 G-a/G-b) ────────────────

describe("intent guards over an unanchored miss", () => {
  const facts = async (command: string) => {
    const r = await checkDspaGate(bashPd(command), createStore());
    return r.ok ? [] : (r.misses ?? []);
  };
  const bar = makeManualBar(createStore(), CWD);
  const inBar = new Map([["$fi", [`${CWD}/notes.md`]]]);
  const outBar = new Map([["$fi", [canon("/Users/u/Strata/notes.md")]]]);

  it("with no resolver answer at all the stop stands (fail closed)", async () => {
    const m = await facts("cat $fi");
    expect(intentGuardFaults(m, [])).toEqual(["unanchored location unanswerable ($fi)"]);
    expect(intentGuardFaults(m, [`${CWD}/notes.md`])).toEqual([
      "unanchored location unanswerable ($fi)",
    ]);
  });

  it("an out-of-bar resolver answer keeps the stop (D-g: the bar is absolute)", async () => {
    const m = await facts("cat $fi");
    expect(intentGuardFaults(m, [], { resolved: outBar, inBar: bar }).join()).toContain(
      "outside the read bar",
    );
  });

  it("an in-bar resolver answer is the answer this miss needs", async () => {
    const m = await facts("cat $fi");
    expect(intentGuardFaults(m, [], { resolved: inBar, inBar: bar })).toEqual([]);
  });

  it("attribution is per token: another token's answer never vouches for this one", async () => {
    // `cat $fi notes.md` — the flat stage-2 report names notes.md; §4.2's
    // omission hole is exactly that name standing in for $fi.
    const m = await facts("cat $fi notes.md");
    const unanchored = m.filter((f) => f.prefix === "");
    expect(unanchored.map((f) => f.token)).toEqual(["$fi"]);
    expect(
      intentGuardFaults(unanchored, [`${CWD}/notes.md`], { resolved: new Map([["$x", [`${CWD}/notes.md`]]]), inBar: bar }),
    ).toEqual(["unanchored location unanswerable ($fi)"]);
  });

  it("a WRITE-role unanchored token never rides the resolver answer (§4.1)", async () => {
    const m = await facts("echo hi > /Users/u/out/$D/f");
    expect(
      intentGuardFaults(m, [], { resolved: new Map([["$D", [`${CWD}/f`]]]), inBar: bar }).join(),
    ).toContain("write effect at an unnamed location");
  });

  it("e2e: an in-bar answer auto-allows and the row names the answer (§7 judgePaths)", async () => {
    vi.mocked(pathResolver.resolveUnresolvedPaths).mockResolvedValue(inBar);
    await run("cat $fi", null, verdict({ paths: [] }));
    expect(promptFlow.showPrompt).not.toHaveBeenCalled();
    expect(String(lines(decLog)[0].reason)).toContain("dspa: intent over miss stop (unresolved, m-test)");
    expect(unres()).toEqual([
      expect.objectContaining({
        token: "$fi",
        missKind: "unresolved",
        outcome: "intent-allowed",
        judgePaths: [`${CWD}/notes.md`],
      }),
    ]);
  });

  it("e2e: no answer prompts, and the guard names the miss as unanswerable", async () => {
    await run("cat $fi", null, verdict({ paths: [`${CWD}/notes.md`] }));
    expect(promptFlow.showPrompt).toHaveBeenCalledTimes(1);
    expect(String(unres()[0].guard)).toContain("unanchored location unanswerable ($fi)");
  });

  it("e2e: an out-of-bar answer prompts", async () => {
    vi.mocked(pathResolver.resolveUnresolvedPaths).mockResolvedValue(outBar);
    await run("cat $fi", null, verdict({ paths: [canon("/Users/u/Strata/notes.md")] }));
    expect(promptFlow.showPrompt).toHaveBeenCalledTimes(1);
    expect(String(unres()[0].guard)).toContain("outside the read bar");
  });

  it("the resolver is asked ONLY when a miss has no anchor (no cost for anchored stops)", async () => {
    await run("cat /Users/u/Strata/design.dxf", null,
      verdict({ paths: [canon("/Users/u/Strata/design.dxf")] }));
    expect(promptFlow.showPrompt).not.toHaveBeenCalled();
    expect(pathResolver.resolveUnresolvedPaths).not.toHaveBeenCalled();
  });

  it("the resolver is not asked when the verdict never gets that far", async () => {
    await run("cat $fi", null, null);
    expect(promptFlow.showPrompt).toHaveBeenCalledTimes(1);
    expect(pathResolver.resolveUnresolvedPaths).not.toHaveBeenCalled();
  });
});

// ── Intent over a miss stop (the fall-through, §3) ─────────────────────────

describe("intent over a miss stop", () => {
  it("report names the location + approve/low → runs with no prompt", async () => {
    await run("cat /Users/u/Strata/design.dxf", null,
      verdict({ paths: [canon("/Users/u/Strata/design.dxf"), canon("/Users/u/Strata/notes.md")] }));
    expect(promptFlow.showPrompt).not.toHaveBeenCalled();
    const l = lines(decLog);
    expect(l[0].kind).toBe("auto-allow");
    expect(String(l[0].reason)).toContain("dspa: intent over miss stop (outside-path, m-test)");
    // §7: one convergence row per miss, tagged as an intent allow.
    expect(unres()).toEqual([
      expect.objectContaining({
        token: canon("/Users/u/Strata/design.dxf"),
        outcome: "intent-allowed",
        decision: "auto-allow",
        missKind: "outside-path",
        persisted: false,
        confirmedPrior: false,
        // §7: the row names the report paths that ANSWERED this token — the
        // other reported path is not evidence for it and stays out.
        judgePaths: [canon("/Users/u/Strata/design.dxf")],
      }),
    ]);
    // The judge report reached an execution: the parser-gap line is written —
    // exactly ONE (dspaAutoAllowed writes it; a second call would double-count
    // the row in `log-inspect dspa --paths`).
    expect(lines(judgeLog).filter((l) => l.kind === "paths")).toHaveLength(1);
  });

  it("stage 1 is skipped on a miss stop — the stateless pass cannot answer (§3.4)", async () => {
    await run("cat /Users/u/Strata/design.dxf", null, verdict({ paths: [canon("/Users/u/Strata/design.dxf")] }));
    expect(judgePrompt.getJudgeVerdict).not.toHaveBeenCalled();
    expect(judgePrompt.getStage2Verdict).toHaveBeenCalledTimes(1);
  });

  it("a verdict that never names the location keeps the stop (empty report)", async () => {
    await run("cat /Users/u/Strata/design.dxf", null, verdict({ paths: [] }));
    expect(promptFlow.showPrompt).toHaveBeenCalledTimes(1);
    const row = unres()[0];
    expect(row.outcome).toBe("intent-declined");
    expect(String(row.guard)).toContain("no reported path under");
    // A declined attempt never executed, so the parser-gap probe stays clean.
    expect(lines(judgeLog).some((l) => l.kind === "paths")).toBe(false);
    expect(getDspaStats().gate).toBe(1);
  });

  it("deny / high-risk verdicts keep the stop and count their own kind", async () => {
    await run("cat /Users/u/Strata/design.dxf", null, verdict({ approve: "deny", risk: "high" }));
    expect(promptFlow.showPrompt).toHaveBeenCalledTimes(1);
    expect(String(unres()[0].guard)).toContain("stage 2 deny (high)");
    expect(getDspaStats().deny).toBe(1);
  });

  it("a judge failure on a miss stop resolves to the prompt, never an allow", async () => {
    await run("cat /Users/u/Strata/design.dxf", null, null);
    expect(promptFlow.showPrompt).toHaveBeenCalledTimes(1);
    expect(unres()[0]).toEqual(
      expect.objectContaining({ outcome: "intent-declined", guard: "no verdict", missKind: "outside-path" }),
    );
  });

  it("the credential ceiling holds end-to-end: naming report + approve/low still prompts", async () => {
    await run("cat /Users/u/.aws/$F", null, verdict({ paths: [canon("/Users/u/.aws/credentials")] }));
    expect(promptFlow.showPrompt).toHaveBeenCalledTimes(1);
    expect(String(unres()[0].guard)).toContain("credential class");
  });

  it("D-g end-to-end: a stage-2 write outside the write bar prompts with the grant offer", async () => {
    await run("cd /etc && sed -i 's/a/b/' hosts", null,
      verdict({ paths: [canon("/etc/hosts")], writes: [canon("/etc/hosts")] }));
    expect(promptFlow.showPrompt).toHaveBeenCalledTimes(1);
    const row = unres()[0];
    expect(row.outcome).toBe("intent-declined");
    expect(String(row.guard)).toContain("reported write outside the write bar");
    expect(String(lines(decLog)[0].dspa)).toContain("write outside base");
  });

  it("D-h end-to-end: the base-write proxy clears when the verdict names the base", async () => {
    // The stop carries TWO facts for one location (the concrete outside path
    // and the base-write proxy); both anchors are realpath'd (3.41.0), so the
    // single spelling the judge reports answers both — on a Mac too, where the
    // `cd` base is threaded as `/etc` while the report says `/private/etc/…`.
    await run("cd /etc && sed -i 's/a/b/' hosts", null,
      verdict({ paths: [canon("/etc/hosts")], writes: [] }));
    expect(promptFlow.showPrompt).not.toHaveBeenCalled();
    expect(String(lines(decLog)[0].reason)).toContain("dspa: intent over miss stop (outside-path+base-write, m-test)");
    expect(unres().map((r) => r.outcome)).toEqual(["intent-allowed", "intent-allowed"]);
  });

  it("§7: a confirmed-location stop records confirmedPrior on the row", async () => {
    const store = createStore();
    store.confirmResolution("$D/design.dxf", [canon("/Users/u/Strata")]);
    await run("cat $D/design.dxf", null,
      verdict({ paths: [canon("/Users/u/Strata/design.dxf")] }), store);
    expect(unres()).toEqual([
      expect.objectContaining({
        outcome: "intent-allowed",
        missKind: "outside-path",
        token: canon("/Users/u/Strata"),
        confirmedPrior: true,
        judgePaths: [canon("/Users/u/Strata/design.dxf")],
      }),
    ]);
  });

  it("an absolute-class stop never reaches the intent pass at all", async () => {
    await run("pip install cowsay", verdict({ risk: "low" }), null);
    expect(promptFlow.showPrompt).toHaveBeenCalledTimes(1);
    expect(unres()).toEqual([]);
    // The D16 advisory path ran stage 1; the intent pass did not run.
    expect(judgePrompt.getJudgeVerdict).toHaveBeenCalledTimes(1);
    expect(judgePrompt.getStage2Verdict).not.toHaveBeenCalled();
  });

  it("the unresolved-token class clears when the report names its static prefix", async () => {
    await run("cat /Users/u/Strata/$SUB/f.txt", null, verdict({ paths: [canon("/Users/u/Strata/sub")] }));
    expect(promptFlow.showPrompt).not.toHaveBeenCalled();
    expect(unres()).toEqual([
      expect.objectContaining({
        token: canon("/Users/u/Strata") + "/$SUB/f.txt",
        outcome: "intent-allowed",
        missKind: "unresolved",
        judgePaths: [canon("/Users/u/Strata/sub")],
      }),
    ]);
  });

  it("§4.5: a mangled URL cannot answer a miss — cwd-resolved garbage is not a location", async () => {
    // The sampled report sent `http://127.0.0.1:8080`; resolved against the
    // cwd it becomes `<cwd>/http:/127.0.0.1:8080`, which sits under this
    // miss's static prefix (`/Users/u`) and would satisfy §4.2 — a report
    // defect clearing a stop.
    await run("cat /Users/u/$V/data", null, verdict({ paths: ["http://127.0.0.1:8080"] }));
    expect(promptFlow.showPrompt).toHaveBeenCalledTimes(1);
    const row = unres()[0];
    expect(row.outcome).toBe("intent-declined");
    expect(String(row.guard)).toContain("no reported path under");
    expect(row.judgePaths).toBeUndefined();
  });

  it("a prefix-less miss with no resolver answer keeps the stop — the guard fails closed", async () => {
    // 3.41.0 rewrote this test: an unresolvable token with nothing static to
    // answer with USED to skip intent entirely (no stage 2, no row). Now it is
    // a miss like any other — stage 2 runs, the resolver is asked once, and no
    // answer means the §4.2 guard keeps the floor's stop (fail closed).
    await run("du -sh $D", null, verdict({ risk: "low" }));
    expect(promptFlow.showPrompt).toHaveBeenCalledTimes(1);
    expect(judgePrompt.getStage2Verdict).toHaveBeenCalledTimes(1);
    expect(pathResolver.resolveUnresolvedPaths).toHaveBeenCalledTimes(1);
    expect(unres()).toEqual([
      expect.objectContaining({
        token: "$D",
        missKind: "unresolved",
        outcome: "intent-declined",
      }),
    ]);
    expect(String(unres()[0].guard)).toContain("unanchored location unanswerable ($D)");
  });
});
