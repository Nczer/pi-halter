/**
 * Goldens for the 2026-12-28 corpus audit (Part 1 of the review): a loop's `cd`
 * binding, the brace group a `cd` leaves behind, and a shell-escaped quote.
 *
 * Loop bindings live in the floor's `cd` bounds, not in the per-segment base
 * (a loop body is one segment whose base is unknown), so these run the real
 * two-stage flow and assert the outcome the operator sees: "clear" = allowed
 * (manual auto-allow, or a prompt the deterministic floor cleared), "stop:…" =
 * the prompt the operator gets, with its class.
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it, beforeAll, afterAll } from "vitest";
import { analyzeCommand } from "../analysis/command-analysis";
import { decide } from "../decide/engine";
import { checkDspaGate } from "../gate/dspa-gate";
import { createStore } from "../gate/store";

let ROOT: string;
beforeAll(() => {
  ROOT = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "halter-loop-")));
  for (const d of ["halter", "gallop", "sub", "a", "b"]) {
    fs.mkdirSync(path.join(ROOT, d), { recursive: true });
  }
});
afterAll(() => fs.rmSync(ROOT, { recursive: true, force: true }));

/** What the operator ends up seeing for this command, under `cwd`. */
async function outcome(command: string, cwd = ROOT): Promise<string> {
  const store = createStore();
  const d = await decide({ type: "bash", command, cwd } as never, store);
  if (d.kind !== "prompt") return "clear";
  const g = await checkDspaGate(d.promptData as never, store);
  return g.ok ? "clear" : `stop:${g.stopClass}`;
}

describe("a loop's `cd` binds the loop variable — and unbinds when it cannot be trusted", () => {
  it("a list the parse can read costs the operator nothing", async () => {
    for (const cmd of [
      "for d in halter gallop; do cd $d; cat x; done",
      'for d in halter gallop; do cd "$d"; cat x; done',
      'for d in halter gallop; do cd "$d"; ls ./{a,b}/x; done',
      // A variable the binder never relied on: reassigning another name is not
      // a reason to distrust the loop.
      "for d in halter gallop; do e=/etc; cd \"$d\"; cat x; done",
    ]) {
      expect(await outcome(cmd), cmd).toBe("clear");
    }
  });

  it("a list that names places outside still stops, and names them", async () => {
    for (const [cmd, place] of [
      ["for d in /etc /var; do cd \"$d\"; cat passwd; done", "/etc"],
      ["for d in halter gallop; do cd \"$d\"; cd /etc; cat passwd; done", "/etc"],
      ['for d in halter ../..; do cd "$d"; cat x; done', "/"],
    ] as const) {
      const store = createStore();
      const d = await decide({ type: "bash", command: cmd, cwd: ROOT } as never, store);
      if (d.kind !== "prompt") throw new Error(`not a prompt: ${cmd}`);
      const g = await checkDspaGate(d.promptData as never, store);
      expect(g.ok, cmd).toBe(false);
      if (!g.ok) expect(g.reason, cmd).toContain(place);
    }
  });

  it("the loop's own base does not excuse a deletion at scale", async () => {
    // Binding the base is not the same as excusing the verb: this one stops on
    // its delete count exactly as it did before the loop knew where it ran.
    expect(await outcome('for d in halter gallop; do cd "$d"; rm x; done')).toBe("stop:delete-scale");
  });

  it("a loop variable the body moves voids the binding (was: auto-allow outside the base)", async () => {
    // At HEAD the single-iteration form read `<ROOT>/halter` while the shell
    // read `/etc` — the binder trusted a variable the body had overwritten.
    for (const cmd of [
      'for d in halter; do cd "$d"; d=/etc; cd "$d"; cat x; done',
      'for d in halter gallop; do cd "$d"; d=/etc; cd "$d"; cat x; done',
      'for d in halter gallop; do cd "$d"; cd "$d"; cat x; done',
      "for d in halter gallop; do IFS= read -r d <<< /etc; cd \"$d\"; cat x; done",
      "for d in halter gallop; do for d in ../..; do cd \"$d\"; cat x; done; done",
      'for d in halter gallop; do cd "$d"; cd sub; cat x; done',
    ]) {
      expect(await outcome(cmd), cmd).not.toBe("clear");
    }
  });
});

describe("a brace group resolves under the `cd` the shell already performed", () => {
  it("names only the candidates — no phantom pair at the parse-time cwd", async () => {
    const a = await analyzeCommand(`cd ${ROOT} && ls ./{a,b}/x`, ROOT);
    expect([...new Set(a.paths)].sort()).toEqual(
      [path.join(ROOT, "a/x"), path.join(ROOT, "b/x")].sort(),
    );
  });

  it("stays single-location when the word is quoted", async () => {
    const a = await analyzeCommand(`cd ${ROOT} && ls "./{a,b}/x"`, ROOT);
    expect(a.paths.some((p) => p.includes("{") || p.includes("}")), JSON.stringify(a.paths)).toBe(true);
  });
});

describe("a shell-escaped quote is one word, not two", () => {
  it("\\' inside single quotes keeps the quoted text joined", async () => {
    // `'/etc/pa'\\''sswd'` is the shell's way of spelling `/etc/pa'sswd`. Split
    // at the escape, the residue fed a credential glob the command never typed.
    const a = await analyzeCommand(String.raw`cat '/etc/pa'\'sswd'`, ROOT);
    expect(a.paths).toContain("/etc/pa'sswd");
    expect(a.risk.reasons.filter((r) => r.startsWith("glob-unverified"))).toEqual([]);
  });
});
