/**
 * bench.mts — measure decide() runtime + per-syscall cost.
 *
 * usage: npx tsx tools/bench.mts [rounds]
 *
 * Runs every bash contract case (test/cases-data.ts) through decide() with a
 * fresh store (first-encounter decisions), N rounds (default 3, round 0 is a
 * warmup that also loads the tree-sitter WASM). Reports total time per round
 * and a per-fs-method table (count + cumulative ms). No source changes —
 * the fs methods are wrapped in-process.
 */
import fs from "node:fs";
import { performance } from "node:perf_hooks";
import { decide } from "../decide/engine";
import { createStore } from "../gate/store";
import { cases } from "../test/cases-data";

const CWD = "/mnt/Ndr/Projects";
const rounds = Math.max(1, Number(process.argv[2] ?? 3));

// ── instrument sync fs methods ──────────────────────────────────────────
const METHODS = [
  "realpathSync", "lstatSync", "statSync", "existsSync", "readlinkSync",
  "readdirSync", "globSync", "opendirSync", "readFileSync", "writeFileSync",
  "appendFileSync", "mkdirSync", "renameSync", "accessSync", "closeSync",
];
const stats = new Map<string, { n: number; ms: number }>();
for (const m of METHODS) {
  const orig = (fs as any)[m];
  if (typeof orig !== "function") continue;
  (fs as any)[m] = function (this: unknown, ...args: unknown[]) {
    const t0 = performance.now();
    try {
      return orig.apply(this, args);
    } finally {
      const s = stats.get(m) ?? { n: 0, ms: 0 };
      s.n += 1;
      s.ms += performance.now() - t0;
      stats.set(m, s);
    }
  };
}

const bashCases = cases.filter((c) => c.cmd && !c.cmd.includes("\0"));
console.log(`cases: ${bashCases.length} bash commands, ${rounds} rounds`);

// ── warmup (WASM + caches) ──────────────────────────────────────────────
{
  const t0 = performance.now();
  for (let i = 0; i < 50; i++) {
    await decide({ type: "bash", command: bashCases[i % bashCases.length].cmd, cwd: CWD }, createStore());
  }
  console.log(`warmup: ${(performance.now() - t0).toFixed(0)}ms`);
}

// ── timed rounds ────────────────────────────────────────────────────────
const totals: number[] = [];
const perCase: { ms: number; cmd: string }[] = [];
for (let r = 0; r < rounds; r++) {
  const t0 = performance.now();
  for (const c of bashCases) {
    const ts = performance.now();
    await decide({ type: "bash", command: c.cmd, cwd: CWD }, createStore());
    perCase.push({ ms: performance.now() - ts, cmd: c.cmd });
  }
  totals.push(performance.now() - t0);
}

const timed = totals.slice(1);
const avg = timed.reduce((a, b) => a + b, 0) / timed.length;
console.log(`rounds(ms): ${totals.map((t) => t.toFixed(0)).join("  ")}  avg=${avg.toFixed(0)}ms  per-case=${(avg / bashCases.length).toFixed(2)}ms`);

// fs table (timed rounds only — stats accumulate, but the warmup is one-shot
// dominated by WASM; subtract by snapshotting)
// (simplest: report all-time; warmup contribution is negligible after WASM load
//  except first-use realpath caches — noted in output)
const rows = [...stats.entries()].sort((a, b) => b[1].ms - a[1].ms);
let nAll = 0, msAll = 0;
console.log("\nfs method          calls        total-ms");
for (const [m, s] of rows) {
  if (s.ms < 0.05 && s.n < 3) continue;
  nAll += s.n;
  msAll += s.ms;
  console.log(`${m.padEnd(17)}${String(s.n).padStart(8)}  ${s.ms.toFixed(1).padStart(10)}`);
}
console.log(`${"ALL".padEnd(17)}${String(nAll).padStart(8)}  ${msAll.toFixed(1).padStart(10)}`);

perCase.sort((a, b) => b.ms - a.ms);
console.log("\nslowest cases:");
for (const p of perCase.slice(0, 8)) {
  console.log(`  ${p.ms.toFixed(2)}ms  ${p.cmd.slice(0, 70)}`);
}
