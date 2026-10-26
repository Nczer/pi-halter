/**
 * The corpus replay (docs/dspa-intent-floor.md §9 build order): every command
 * the ledgers recorded, plus a fixed set of probes for the seams the location
 * model moves, run through the floor with an EMPTY session (no grants, no
 * confirmed resolutions).
 *
 * Two uses:
 *  - It asserts an invariant: no real command makes the path model throw. A
 *    containment verb that refuses to answer (under()) fails closed in the
 *    gate, so a missed call site looks like a blocked command in production —
 *    here it looks like a failed test.
 *  - It is the per-step proof of the build order, as a DIFF rather than an
 *    assertion. Run it once on the working tree and once with the step
 *    stashed, then diff the two files line by line:
 *      FLOOR_OUT=/tmp/after.txt FLOOR_LOG=/tmp/log-snap npx vitest run test/floor-replay.test.ts
 *      git stash && FLOOR_OUT=/tmp/before.txt FLOOR_LOG=/tmp/log-snap npx vitest run test/floor-replay.test.ts && git stash pop
 *      diff <(sort /tmp/before.txt) <(sort /tmp/after.txt)
 *    A step that moves no stop differs ONLY where it intends to. Point FLOOR_LOG
 *    at a frozen copy of .log while the extension is live: the gate logs the
 *    very commands the two passes run, so an unfrozen corpus gains rows between
 *    passes and fakes a flip. Lists are sorted, because their order is
 *    display-only.
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { analyzeCommand } from "../analysis/command-analysis";
import { decide } from "../decide/engine";
import { createStore } from "../gate/store";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const LOG_DIR = process.env.FLOOR_LOG || path.join(HERE, "..", ".log");
const OUT = process.env.FLOOR_OUT || "";

/**
 * Probes for the seams step 1 moved, on a fixed tree under /tmp: one word per
 * top-level folder (the root case), brace groups at the leaf, mid-word and
 * nested, globs, unbound vars and command substitutions, relative words, a
 * symlink and a symlink-plus-escape, the root delete and its `..` twin.
 */
const SYNTH_CWD = "/tmp/floor-replay-probes";
const SYNTH: string[] = [
  "ls /optfoo && ls /opt",
  "rm -rf /",
  "rm -rf /halt-pfx-nonexistent/y",
  "cat /etc/hosts",
  `ls ${SYNTH_CWD}/{a,b}`,
  "cat /tmp/{a,b}/x",
  `ls ${SYNTH_CWD}/{a,b}/x > ${SYNTH_CWD}/{c,d}/y`,
  `ls ${SYNTH_CWD}/{a,b}/{c,d}`,
  `tee ${SYNTH_CWD}/{a,b}/log`,
  `rm -rf ${SYNTH_CWD}/{a,b}`,
  "ls $FOO/*",
  "rm -rf $FOO/bar",
  "ls ${UNSET}/x",
  "cat $(echo /etc/hosts)",
  "ls ~/nonexistentdir/x",
  "ls ~root/x",
  "ls .",
  "cat notes/todo.md",
  "echo hi > out.txt",
  `echo hi > ${SYNTH_CWD}/deep/out.txt`,
  `rm -rf ${SYNTH_CWD}/other/*`,
  `ls ${SYNTH_CWD}/link/x`,
  `ls ${SYNTH_CWD}/link/../other`,
  `ls ${SYNTH_CWD}/../${path.basename(SYNTH_CWD)}/deep`,
  `ls ${SYNTH_CWD}/deep/../deep`,
  `cd ${SYNTH_CWD} && cat deep/out.txt`,
  `cp ${SYNTH_CWD}/deep/a ${SYNTH_CWD}/other/b`,
  `chmod 700 ${SYNTH_CWD}/deep`,
  "rm -rf ./",
  "rm -rf ..",
  `grep -r TODO ${SYNTH_CWD} | head`,
  `find ${SYNTH_CWD} -name '*.ts' | xargs rm`,
  `sed -i 's/a/b/' ${SYNTH_CWD}/other/f.txt`,
  `ln -s ${SYNTH_CWD}/deep ${SYNTH_CWD}/other/l`,
];

function ensureProbeTree(): void {
  fs.mkdirSync(path.join(SYNTH_CWD, "deep", "nested"), { recursive: true });
  fs.mkdirSync(path.join(SYNTH_CWD, "other"), { recursive: true });
  const leaf = path.join(SYNTH_CWD, "deep", "a");
  if (!fs.existsSync(leaf)) fs.writeFileSync(leaf, "a\n");
  const link = path.join(SYNTH_CWD, "link");
  if (!fs.lstatSync(link, { throwIfNoEntry: false })) fs.symlinkSync(path.join(SYNTH_CWD, "deep"), link);
}

function ledgerRows(): Array<{ cmd: string; cwd: string }> {
  const rows: Array<{ cmd: string; cwd: string }> = [];
  const seen = new Set<string>();
  if (fs.existsSync(LOG_DIR)) {
    for (const f of fs.readdirSync(LOG_DIR).filter((x) => x.endsWith(".jsonl"))) {
      const text = fs.readFileSync(path.join(LOG_DIR, f), "utf8").trim();
      for (const line of text.split("\n").filter(Boolean)) {
        let e: Record<string, unknown>;
        try {
          e = JSON.parse(line) as Record<string, unknown>;
        } catch {
          continue;
        }
        if (typeof e.cmd !== "string" || !e.cmd) continue;
        const cwd = typeof e.cwd === "string" && e.cwd ? e.cwd : process.cwd();
        const key = `${cwd}\u0000${e.cmd}`;
        if (seen.has(key)) continue;
        seen.add(key);
        rows.push({ cmd: e.cmd, cwd });
      }
    }
  }
  return rows;
}

const sorted = (xs: readonly string[] | undefined) => (xs ? [...xs].sort() : null);

async function signature(cmd: string, cwd: string): Promise<string> {
  const a = await analyzeCommand(cmd, cwd, {
    isInsideAllowedDir: () => false,
    isInsideAllowedWriteDir: () => false,
    getConfirmedResolution: () => null,
  });
  const d = await decide({ type: "bash", command: cmd, cwd }, createStore());
  const pd = d.kind === "prompt" && d.promptData.type === "bash" ? d.promptData : null;
  const decided = pd
    ? {
          kind: "prompt",
          outsideDirs: sorted(pd.outsideDirs),
          outsideWriteDirs: sorted(pd.outsideWriteDirs),
          needsPath: pd.needsPathApproval,
          needsWrite: pd.needsWriteApproval ?? null,
        }
    : { kind: d.kind, reason: d.kind === "block" ? d.reason : null };
  return JSON.stringify({
    cwd,
    cmd,
    paths: sorted(a.paths),
    prompt: {
      outsidePaths: sorted(a.prompt.outsidePaths),
      outsideDirs: sorted(a.prompt.outsideDirs),
      outsideWritePaths: sorted(a.prompt.outsideWritePaths),
      outsideWriteDirs: sorted(a.prompt.outsideWriteDirs),
      needsPathApproval: a.prompt.needsPathApproval ?? null,
      needsWriteApproval: a.prompt.needsWriteApproval ?? null,
    },
    decided,
  });
}

describe("corpus replay — the floor answers every recorded command", () => {
  ensureProbeTree();
  const rows = [...ledgerRows(), ...SYNTH.map((cmd) => ({ cmd, cwd: SYNTH_CWD }))];

  it("no ledger or probe command makes the path model throw", async () => {
    const out: string[] = [];
    const thrown: string[] = [];
    for (const { cmd, cwd } of rows) {
      try {
        out.push(await signature(cmd, cwd));
      } catch (err) {
        thrown.push(`${cmd} :: ${err instanceof Error ? err.message : String(err)}`);
      }
    }
    expect(thrown).toEqual([]);
    expect(out.length).toBe(rows.length);
    if (OUT) fs.writeFileSync(OUT, out.join("\n") + "\n");
  }, 180000);
});
