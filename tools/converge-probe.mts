/**
 * D12 convergence probe (docs/dspa-redesign.md) — verify that a command with an
 * unbound path token reaches a deterministic steady state across three runs:
 *
 *   run1  fresh store, no confirmed resolution
 *         → PROMPT + gate stop "runtime location unresolvable (<token>)"
 *         (the LLM path resolver suggests dirs; the user grants or one-shot yes)
 *
 *   run2  fresh store, token confirmed to ALL-in-bar dirs
 *         → AUTO-ALLOW (the token leaves the approval bar; no LLM, no prompt)
 *
 *   run3  fresh store, token confirmed to one OUT-of-bar dir
 *         → PROMPT + gate stop "touches paths outside base (<dir>)" carrying
 *           confirmedOutside — the manual bar's "Always (paths)" grants
 *           exactly <dir>, so one click converges the token (next run = run2).
 *
 * The raw token is discovered from run1's analysis (no hardcoding). Both dirs
 * default to fresh temp dirs under $HOME (the tests' hermetic pattern): cwd is
 * the manual bar, outsidePrefix is a sibling dir outside it.
 *
 * usage: npx tsx tools/converge-probe.mts [outsidePrefix] [cwd]
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { decide } from "../decision-engine";
import { checkDspaGate } from "../dspa-gate";
import { createStore } from "../store";

const outsidePrefixArg = process.argv[2];
const cwdArg = process.argv[3];
const outsidePrefix = outsidePrefixArg ?? fs.mkdtempSync(path.join(os.homedir(), ".halter-cv-"));
const cwd = cwdArg ?? fs.mkdtempSync(path.join(os.homedir(), ".halter-cv-"));
// An unbound loop var over the outside prefix → an unresolved token whose static
// prefix is OUT of the bar (Tier 0 only drops in-bar prefixes, so this survives).
const command = `for e in a b; do grep -rn x ${outsidePrefix}/$e/*.ts; done`;

const inBar = [`${cwd}/.a`, `${cwd}/.b`]; // under cwd → inside the manual bar
const outOfBar = outsidePrefix; // sibling dir → outside the manual bar

async function run(label: string, confirmed: Array<[string, string[]]> | null) {
  const store = createStore();
  for (const [token, dirs] of confirmed ?? []) store.confirmResolution(token, dirs);
  const d = await decide({ type: "bash", command, cwd }, store);
  if (d.kind !== "prompt") {
    console.log(`${label}: ${d.kind.toUpperCase()}`);
    return { kind: d.kind } as const;
  }
  const gate = await checkDspaGate(d.promptData, store);
  console.log(`${label}: PROMPT`);
  console.log(`  gate: ${JSON.stringify(gate)}`);
  return { kind: "prompt" as const, token: d.promptData.unresolved?.[0]?.token ?? null };
}

try {
  console.log(`bar (cwd)       = ${cwd}`);
  console.log(`outside prefix  = ${outsidePrefix}`);
  console.log(`command         = ${command}\n`);

  const r1 = await run("run1 (unconfirmed)", null);
  if (r1.kind !== "prompt" || !r1.token) {
    console.log("ERROR: run1 did not prompt on an unresolved token — is the prefix really out of the bar?");
    process.exit(1);
  }
  const token = r1.token;
  console.log(`token           = ${token}\n`);

  await run("run2 (confirmed all-in-bar)", [[token, inBar]]);
  await run("run3 (confirmed one-out-of-bar)", [[token, [...inBar, outOfBar]]]);
} finally {
  // Remove only the temp dirs the probe created itself — never a dir the
  // caller passed explicitly.
  if (!outsidePrefixArg) fs.rmSync(outsidePrefix, { recursive: true, force: true });
  if (!cwdArg) fs.rmSync(cwd, { recursive: true, force: true });
}
