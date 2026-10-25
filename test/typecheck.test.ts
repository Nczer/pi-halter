import { createRequire } from "node:module";
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

/**
 * The README puts `npm run typecheck` in the prove step, but nothing ran it
 * unless someone remembered: halter's strict tsc sat red on a wrong type
 * annotation while the suite stayed green. The gate moves into the suite, so a
 * type slip fails a run that already happens.
 *
 * tsc runs through node, not npx: halter keeps no local node_modules (deps
 * hoist to the extensions workspace), and npx would go looking for a package it
 * is not told is already installed.
 */
const repoRoot = dirname(dirname(fileURLToPath(import.meta.url)));

describe("typecheck", () => {
  it("tsc --noEmit is clean over source and tests", () => {
    const tsc = createRequire(import.meta.url).resolve("typescript/bin/tsc");
    const run = spawnSync(process.execPath, [tsc, "--noEmit", "-p", join(repoRoot, "tsconfig.json")], {
      encoding: "utf8",
    });
    const output = `${run.stdout}${run.stderr}`.trim();
    expect(output, `tsc --noEmit:\n${output}`).toBe("");
  }, 60_000);
});
