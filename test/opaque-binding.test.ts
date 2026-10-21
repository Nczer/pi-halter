/**
 * Deterministic binding of opaque tokens in path position (3.41.0).
 *
 * G-c — a shell parameter whose expansion provably cannot contain `/` (the
 *   numeric/special parameters) is a NAME, so a path-position use of it is
 *   relative to the effective base: the same shape `n=5; cat "$n"` already
 *   has. Nothing is asked of the model; the token stops being a miss.
 * G-d — an in-list word written with `~` was invisible to the allowed-root
 *   proof (`isAllowedRootToken` tests the literal text), so a loop over a
 *   root-pinned glob stayed an unresolvable sentinel. The proof now runs on
 *   the tilde-expanded word; the proof itself is unchanged (realpath'd
 *   literals, glob-expanded matches, fail closed on a symlink escape).
 */
import { describe, expect, it, beforeAll, afterAll } from "vitest";
import path from "node:path";
import os from "node:os";
import { analyzeCommand } from "../analysis/command-analysis";
import { parseCommand } from "../analysis/bash-parser";
import { createContractCwd, removeContractCwd } from "./hermetic-cwd";

let CWD: string;
beforeAll(() => {
  CWD = createContractCwd();
});
afterAll(() => removeContractCwd(CWD));

const analyze = (cmd: string) =>
  analyzeCommand(cmd, CWD, {
    isInsideAllowedDir: () => false,
    getConfirmedResolution: () => null,
  });

describe("special parameters in path position bind to the base (G-c)", () => {
  it("an exit-status parameter carried in a variable binds under the base", async () => {
    const a = await analyze('rc=$?; tail -5 "$rc"');
    expect(a.prompt.unresolved).toEqual([]);
  });

  it("the parameter standing alone in path position binds too", async () => {
    for (const tok of ["$?", "$!", "$$", "$#", "$SECONDS", "$LINENO", "$RANDOM", "$pipestatus"]) {
      const a = await analyze(`cat "${tok}"`);
      expect(a.prompt.unresolved, tok).toEqual([]);
    }
  });

  it("fail closed: a positional parameter and $OPTARG may BE paths", async () => {
    for (const tok of ["$1", "$OPTARG"]) {
      const a = await analyze(`cat "${tok}"`);
      expect(a.prompt.unresolved.map((u) => u.token), tok).toEqual([tok]);
    }
  });

  it("fail closed: an assignment to a special name wins over the special binding", async () => {
    const a = await analyze('RANDOM=/Users/u/outside/x; cat "$RANDOM"');
    expect(a.prompt.unresolved).toEqual([]);
    expect((a.prompt.outsidePaths ?? []).some((p) => p.endsWith("/outside/x"))).toBe(true);
  });

  it("fail closed: a special parameter glued into a literal path stays unresolved", async () => {
    // Not the var-resolution path at all — the token itself is a path token
    // with a dynamic segment, so its location is unknowable.
    const a = await analyze('cat "/var/log/$?"');
    expect(a.prompt.unresolved.map((u) => u.token)).toEqual(["/var/log/$?"]);
  });
});

describe("loop in-lists: the ~ spelling of an allowed root (G-d)", () => {
  it("a root-pinned glob written with ~ is exempt, like its absolute spelling", async () => {
    const r = await parseCommand("for f in ~/.pi/*.log; do tail -5 \"$f\"; done", CWD);
    expect(r.opaque).toEqual([]);
  });

  it("a ~/-rooted in-list outside every root stays opaque (fail closed)", async () => {
    const r = await parseCommand("for f in ~/not-a-root-9k3x/*.log; do tail -5 \"$f\"; done", CWD);
    expect(r.opaque.map((o) => o.kind)).toEqual(["opaque"]);
  });

  it("an absolute glob in-list outside every root still stays opaque (unchanged)", async () => {
    const r = await parseCommand("for f in /a/*/x; do cat \"$f\"; done", CWD);
    expect(r.opaque.map((o) => o.kind)).toEqual(["opaque"]);
  });

  it("the ~ spelling resolves to the SAME classification as the absolute spelling", async () => {
    const abs = await parseCommand(`for f in ${path.join(os.homedir(), ".pi", "*.log")}; do tail -5 "$f"; done`, CWD);
    const tilde = await parseCommand("for f in ~/.pi/*.log; do tail -5 \"$f\"; done", CWD);
    expect(tilde.opaque).toEqual(abs.opaque);
  });
});
