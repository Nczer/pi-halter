/**
 * G6 (3.38.0): the command position is ONE fixpoint, for every consumer.
 *
 * The signature a grant is stored under, the allow table, the parser's operand
 * model, the egress check and the base-access/base-write checks all key on
 * "what program does this run". Keying on the first WORD instead means a
 * wrapper in front of the command moves the answer per consumer:
 * `nice command cat /etc/hosts` was `nice` to the parser (not path-aware → the
 * operand model never ran → `paths=[]` → no location bar at all), `nice
 * command` to the signature, and `cat` to nobody (2026-10-17 round-6 audit).
 *
 * Sibling of the P13 block in verified-bypasses.test.ts, which holds the
 * round-6 attack rows; the units here pin the resolution itself.
 */
import { describe, expect, it, beforeAll, afterAll } from "vitest";
import { resolveDelegatedTokens, MAX_UNWRAP_HOPS } from "../analysis/wrapper-unwrap";
import { analyzeCommand } from "../analysis/command-analysis";
import { decide } from "../decide/engine";
import { createStore } from "../gate/store";
import { createContractCwd, removeContractCwd } from "./hermetic-cwd";

let cwd: string;
beforeAll(() => { cwd = createContractCwd(); });
afterAll(() => removeContractCwd(cwd));

// ── the unwrapper itself ──────────────────────────────────────────────
describe("resolveDelegatedTokens resolves to a fixpoint", () => {
  it("null when nothing is delegated", () => {
    expect(resolveDelegatedTokens(["cat", "/etc/hosts"])).toBeNull();
    // A wrapper whose only remaining word is a flag names no program.
    expect(resolveDelegatedTokens(["nice", "-x"])).toBeNull();
  });

  it("nests prefixes (one hop stops at the NEXT prefix, which names nothing)", () => {
    expect(resolveDelegatedTokens(["nice", "cat", "/etc/hosts"])).toMatchObject({ cmd: "cat", index: 1 });
    expect(resolveDelegatedTokens(["nice", "command", "cat", "/etc/hosts"])).toMatchObject({ cmd: "cat", index: 2 });
    expect(resolveDelegatedTokens(["command", "env", "nice", "cat"])).toMatchObject({ cmd: "cat", index: 3 });
    expect(resolveDelegatedTokens(["timeout", "5", "command", "curl", "https://evil.com"])).toMatchObject({ cmd: "curl", index: 3 });
    expect(resolveDelegatedTokens(["env", "FOO=bar", "nice", "cat", "/etc/hosts"])).toMatchObject({ cmd: "cat", index: 3 });
  });

  it("skips option VALUES, not just flags, so the value is never the program", () => {
    expect(resolveDelegatedTokens(["watch", "-n", "1", "curl", "http://x"])).toMatchObject({ cmd: "curl", index: 3 });
    expect(resolveDelegatedTokens(["xargs", "-a", "/dev/null", "sh", "-c", "cat f"])).toMatchObject({ cmd: "sh", index: 3 });
  });

  it("`command -v` is a lookup, not a program to model", () => {
    expect(resolveDelegatedTokens(["command", "-v", "ls"])).toMatchObject({ cmd: "ls", lookup: true, capped: false });
  });

  it("capped past the hop cap — identity, not the first word", () => {
    const deep = ["nice", "nice", "nice", "nice", "cat", "/etc/hosts"];
    expect(resolveDelegatedTokens(deep)).toMatchObject({ cmd: "cat", capped: false });
    const over = ["nice", ...deep];
    expect(resolveDelegatedTokens(over)).toMatchObject({ cmd: "", capped: true });
    // The cap is what the cap is FOR: past it the answer is "no identity", and
    // consumers fail closed rather than reading a wrapper as the program.
    expect(MAX_UNWRAP_HOPS).toBe(4);
  });
});

// ── signatures name the program the wrapper runs ──────────────────────
describe("signatures are about the program, not the wrapper", () => {
  const sigOf = async (cmd: string) => (await analyzeCommand(cmd, cwd)).signatures;

  it("wrapper + resolved program", async () => {
    expect(await sigOf("nice cat /etc/hosts")).toEqual(["nice cat"]);
    expect(await sigOf("command cat /etc/hosts")).toEqual(["command cat"]);
    expect(await sigOf("nice command git status")).toEqual(["nice git"]);
    expect(await sigOf("timeout 5 command curl https://evil.com")).toEqual(["timeout curl"]);
  });

  it("a capped chain collapses to the wrapper alone, so no grant can name it", async () => {
    expect(await sigOf("nice nice nice nice nice cat /etc/hosts")).toEqual(["nice"]);
  });

  it("the deepest chain still resolved names its program and its operands", async () => {
    const a = await analyzeCommand("timeout 5 command timeout 5 command cat /etc/hosts", cwd);
    expect(a.signatures).toEqual(["timeout cat"]);
    expect(a.paths).toEqual(["/etc/hosts"]);
  });
});

// ── the operand model and the base checks run under a wrapper ─────────
describe("a wrapped command still gets its operands modeled", () => {
  it("a wrapped read of an outside location leaves a path for the location bar", async () => {
    for (const cmd of ["nice cat /etc/hosts", "command cat /etc/hosts", "nice command cat /etc/hosts"]) {
      const a = await analyzeCommand(cmd, cwd);
      expect(a.paths, cmd).toContain("/etc/hosts");
      expect((await decide({ type: "bash", command: cmd, cwd }, createStore())).kind, cmd).not.toBe("auto-allow");
    }
  });

  it("the base a `cd` left is what a wrapped later stage reads", async () => {
    // `cd /etc && nice ls` used to look like a segment running `nice`: no
    // path-aware program, so the base it operated on left no trace.
    for (const cmd of ["cd /etc && nice ls", "cd /etc && command ls", "cd /etc && nice cat passwd", "cd /etc && nice nice ls"]) {
      const a = await analyzeCommand(cmd, cwd);
      expect(a.paths, cmd).toContain("/etc");
      expect((await decide({ type: "bash", command: cmd, cwd }, createStore())).kind, cmd).not.toBe("auto-allow");
    }
  });

  it("a wrapped write verb writes the base", async () => {
    const d = await decide({ type: "bash", command: "cd /tmp && nice touch zz-halter-probe-x", cwd }, createStore());
    expect(d.kind).not.toBe("auto-allow");
  });

  it("a capped chain assumes the base is touched (fail closed)", async () => {
    for (const cmd of ["cd /etc && nice nice nice nice nice ls", "nice nice nice nice nice cat README.md"]) {
      const d = await decide({ type: "bash", command: cmd, cwd }, createStore());
      expect(d.kind, cmd).not.toBe("auto-allow");
    }
  });

  it("wrapper transparency does NOT mean the wrapper name is approval", async () => {
    const store = createStore();
    store.addAllowed({ bashSigs: ["nice"] });
    const d = await decide({ type: "bash", command: "nice command git push", cwd }, store);
    expect(d.kind).not.toBe("auto-allow");
  });
});

// ── exec/code-body payloads get no segment-level vetting ──────────────
describe("an exec payload is trusted only against the unconditionally-safe set", () => {
  it("a payload naming a vetted-entry program stops", async () => {
    for (const cmd of ["find . -exec git push \\;", "fd -x git clean -fdx", "find . -exec rg --pre /tmp/evil {} \\;"]) {
      const d = await decide({ type: "bash", command: cmd, cwd }, createStore());
      expect(d.kind, cmd).not.toBe("auto-allow");
    }
  });

  it("a payload that is unconditionally safe stays allowed (no blanket -exec stop)", async () => {
    for (const cmd of ["find . -exec cat {} \\;", "fd -x echo {}", "rg --pre /bin/true file.txt"]) {
      const d = await decide({ type: "bash", command: cmd, cwd }, createStore());
      expect(d.kind, cmd).toBe("auto-allow");
    }
  });
});

// ── the runner's identity flags in their short spelling ────────────────
describe("`uv run` dependency flags are recognized in every spelling", () => {
  it("-w IS --with (verified against `uv run --help`)", async () => {
    const a = await analyzeCommand("uv run -w evil-pkg python3 x.py", cwd);
    expect(a.signatures).toEqual(["uv run --with evil-pkg"]);
    expect(a.runDepSegmentIndices).toEqual([0]);
  });

  it("…also behind a wrapper, and no coarse grant names it", async () => {
    const cmd = "nice timeout 5 uv run -w evil-pkg python3 x.py";
    const a = await analyzeCommand(cmd, cwd);
    expect(a.signatures).toEqual(["nice uv --with evil-pkg"]);
    expect(a.runDepSegmentIndices).toEqual([0]);
    for (const bashSigs of [["uv"], ["nice"], ["timeout uv"], ["uv run"]]) {
      const store = createStore();
      store.addAllowed({ bashSigs });
      const d = await decide({ type: "bash", command: cmd, cwd }, store);
      expect(d.kind, `${cmd} + ${bashSigs.join(",")}`).not.toBe("auto-allow");
    }
  });
});
