/**
 * G4 — argv0 location semantics (docs/dspa-redesign.md §6 item 4).
 *
 * `ls` and `~/Downloads/ls` were the same word to the analysis: a basename
 * lookup against the allow table, with NO path minted for the program itself,
 * so the read bar never saw the binary the shell execs (2026-10-17 round-6
 * corpus: `bin/ls`, `scripts/cat README.md`, `~/Downloads/ls`,
 * `/tmp/evil/git status`, `node_modules/.bin/tsc` all auto-allowed).
 *
 * The rule these tests pin: a program the system does not own is a PATH
 * OPERAND — its own location joins the path set, and it matches only an exact,
 * base-bound grant. Only argv0 under a package-manager-owned dir (`/bin`,
 * `/usr/bin`, `/sbin`, `/usr/sbin`) keeps bare-name semantics.
 */

import path from "node:path";
import os from "node:os";
import fs from "node:fs";
import { describe, expect, it, beforeAll, afterAll } from "vitest";
import { classifyArgv0, classifyStageArgv0 } from "../analysis/argv0-path";
import { getCommandSignature } from "../analysis/segment-helpers";
import { analyzeCommand } from "../analysis/command-analysis";
import { decide } from "../decide/engine";
import { createStore } from "../gate/store";
import { RuleGenerator } from "../decide/rule-generator";
import { createContractCwd, removeContractCwd } from "./hermetic-cwd";

const base = "/home/user/project";

describe("the argv0 location class", () => {
  it("a bare name is bare — PATH is checked separately", () => {
    for (const word of ["ls", "git", "python3", "ssh"]) {
      expect(classifyArgv0(word, base), word).toBe("bare");
    }
  });

  it("a program the distro owns keeps bare-name semantics", () => {
    for (const word of ["/usr/bin/ls", "/bin/cat", "/sbin/ip", "/usr/sbin/nologin"]) {
      expect(classifyArgv0(word, base), word).toBe("system");
    }
    // Base-aware: a relative form under a system dir is that same program.
    expect(classifyArgv0("./ls", "/usr/bin")).toBe("system");
    expect(classifyArgv0("bin/ls", "/")).toBe("system");
  });

  it("any other path-qualified invocation is qualified", () => {
    for (const word of ["./ls", "../tools/ls", "bin/ls", "scripts/cat", "node_modules/.bin/tsc", "~/Downloads/ls", "/tmp/evil/git"]) {
      expect(classifyArgv0(word, base), word).toBe("qualified");
    }
    // Documented deviation: /usr/local/bin and /opt/homebrew/bin are
    // admin/homebrew-writable — the exact class this rule targets — so they are
    // NOT system dirs; such a call prompts once, then a location or exact grant
    // covers it.
    expect(classifyArgv0("/usr/local/bin/mytool", base)).toBe("qualified");
  });

  it("an unresolvable base classifies qualified (fail closed)", () => {
    // A relative program whose base is unknown cannot be SHOWN to be a system
    // program, so it does not get the system-dir exemption either.
    expect(classifyArgv0("bin/ls", null)).toBe("qualified");
    expect(classifyArgv0("/usr/bin/ls", null)).toBe("qualified");
    expect(classifyArgv0("ls", null)).toBe("bare");
  });

  it("a lookup executes nothing, so its argument stays bare", () => {
    for (const stage of ["command -v /tmp/evil/x", "command -V ./x", "type /tmp/x"]) {
      expect(classifyStageArgv0(stage, base), stage).toBe("bare");
    }
  });

  it("env prefixes and wrapper chains do not move the answer", () => {
    // The class is the command position's, and the command position is the one
    // unwrapper's answer — a prefix cannot step between the rule and the word.
    for (const stage of ["FOO=/tmp/x /tmp/y", "nice bin/ls", "env PATH=/x bin/ls", "command ~/Downloads/ls", "env FOO=bar nice bin/ls"]) {
      expect(classifyStageArgv0(stage, base), stage).toBe("qualified");
    }
    for (const stage of ["FOO=/tmp/x ls", "env PATH=/x ls", "command ls"]) {
      expect(classifyStageArgv0(stage, base), stage).toBe("bare");
    }
    // A wrapper over a system program is still a system program.
    expect(classifyStageArgv0("nice /usr/bin/ls", base)).toBe("system");
    // A stage with no path form at all never pays for the scan.
    expect(classifyStageArgv0("ls -la", base)).toBe("bare");
  });
});

describe("a qualified argv0 is part of the grant identity", () => {
  it("the signature names the location the wrapper branch used to collapse", () => {
    // Before G4 the wrapper branch basenamed the delegate (`nice bin/ls` →
    // "nice ls") and an env-assignment prefix hid argv0 entirely
    // (`FOO=/tmp/x /tmp/y` → "foo=/tmp/x"), so the grant that came back named a
    // program the command did not run.
    expect(getCommandSignature("nice bin/ls", base)).toBe("nice bin/ls");
    expect(getCommandSignature("env ./x --flag", base)).toBe("env ./x");
    expect(getCommandSignature("timeout 5 bin/tool --go", base)).toBe("timeout bin/tool");
    expect(getCommandSignature("FOO=/tmp/x /tmp/y", base)).toBe("foo=/tmp/x /tmp/y");
    // A path is not a name: the identity keeps its case, or one grant would
    // cover two different files.
    expect(getCommandSignature("/tmp/Evil/Git status", base)).toBe("/tmp/Evil/Git");
    // A package manager reached by path keeps its subcommand AND its location.
    expect(getCommandSignature("./node_modules/.bin/npm run build", base)).toBe("./node_modules/.bin/npm run");
  });

  it("a system program is still named by the word the user typed", () => {
    // The exemption is about what a grant has to PROVE, not about rewriting the
    // identity: `/usr/bin/ls` was always its own signature.
    expect(getCommandSignature("/usr/bin/ls -la", base)).toBe("/usr/bin/ls -la");
    expect(getCommandSignature("nice /usr/bin/ls", base)).toBe("nice ls");
  });
});

describe("a qualified argv0 faces the path bar and binds its grant", () => {
  let cwd: string;
  let elsewhere: string;
  let outsideProgDir: string;

  beforeAll(() => {
    cwd = createContractCwd();
    elsewhere = fs.mkdtempSync(path.join(os.tmpdir(), "halter-g4-elsewhere-"));
    // Under HOME, not /tmp: /tmp is an allowed-read dir here, so the bar would
    // legitimately stay quiet and the test would prove nothing.
    outsideProgDir = fs.mkdtempSync(path.join(os.homedir(), "halter-g4-prog-"));
    fs.writeFileSync(path.join(outsideProgDir, "Git"), "#!/bin/sh\necho evil\n");
  });
  afterAll(() => {
    removeContractCwd(cwd);
    fs.rmSync(elsewhere, { recursive: true, force: true });
    fs.rmSync(outsideProgDir, { recursive: true, force: true });
  });

  it("the program's own location is a path operand", async () => {
    const prog = path.join(outsideProgDir, "Git");
    const a = await analyzeCommand(`${prog} status`, cwd);
    expect(a.paths).toContain(prog);
    const d = await decide({ type: "bash", command: `${prog} status`, cwd }, createStore());
    expect(d.kind).toBe("prompt");
    if (d.kind === "prompt" && d.promptData.type === "bash") {
      expect(d.promptData.outsideDirs).toEqual([outsideProgDir]);
      expect(d.promptData.needsPathApproval).toBe(true);
    }
  });

  it("a name the allow table knows does not cover its qualified form", async () => {
    // The bypass: `ls` is table-allowed, so `bin/ls` auto-allowed with nothing
    // recorded about the file in ./bin that the shell execs.
    const store = createStore();
    store.addAllowed({ bashSigs: ["ls"] });
    expect((await decide({ type: "bash", command: "ls", cwd }, store)).kind).toBe("auto-allow");
    for (const cmd of ["bin/ls", "./ls", "nice bin/ls", "node_modules/.bin/tsc"]) {
      const d = await decide({ type: "bash", command: cmd, cwd }, store);
      expect(d.kind, cmd).not.toBe("auto-allow");
    }
    // Nor does the same bare name held as a cwd-bound grant.
    const store2 = createStore();
    store2.addAllowed({ bashSigCwds: [{ sig: "ls", cwd }] });
    expect((await decide({ type: "bash", command: "bin/ls", cwd }, store2)).kind).not.toBe("auto-allow");
  });

  it("Always on a qualified program stores an exact base-bound grant", async () => {
    const store = createStore();
    const d1 = await decide({ type: "bash", command: "bin/ls", cwd }, store);
    expect(d1.kind).toBe("prompt");
    if (d1.kind !== "prompt" || d1.promptData.type !== "bash") throw new Error("expected prompt");
    // The prompt offers the base-bound identity, never the bare name.
    expect(d1.promptData.relativeToolIds).toEqual([{ sig: "bin/ls", base: cwd }]);
    expect(d1.promptData.signatures).not.toContain("ls");
    store.addAllowed(RuleGenerator.generatePrimaryRules(d1.promptData));
    expect((await decide({ type: "bash", command: "bin/ls", cwd }, store)).kind).toBe("auto-allow");
  });

  it("the grant is exact: another base, another program, another flag set", async () => {
    const store = createStore();
    const d1 = await decide({ type: "bash", command: "bin/ls", cwd }, store);
    if (d1.kind !== "prompt") throw new Error("expected prompt");
    store.addAllowed(RuleGenerator.generatePrimaryRules(d1.promptData));
    // Another base — the same relative form is a different program.
    expect((await decide({ type: "bash", command: "bin/ls", cwd: elsewhere }, store)).kind).not.toBe("auto-allow");
    // A sibling program in the same dir, and the same program under new flags.
    expect((await decide({ type: "bash", command: "bin/cat x", cwd }, store)).kind).not.toBe("auto-allow");
    expect((await decide({ type: "bash", command: "bin/ls -la", cwd }, store)).kind).not.toBe("auto-allow");
    // The qualified form does not leak back onto the bare name either.
    expect((await decide({ type: "bash", command: "ls", cwd }, store)).kind).toBe("auto-allow");
  });

  it("a system-dir program keeps auto-allowing", async () => {
    // The cost side of the rule: the table's programs still run unimpeded.
    for (const cmd of ["ls", "/usr/bin/ls", "/bin/ls", "/usr/bin/ls -la", "nice /bin/ls", "command -v /tmp/evil/x"]) {
      const d = await decide({ type: "bash", command: cmd, cwd }, createStore());
      expect(d.kind, cmd).toBe("auto-allow");
    }
  });
});
