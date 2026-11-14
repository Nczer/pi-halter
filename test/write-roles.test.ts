/**
 * G3 — write-role operands (docs/dspa-redesign.md §6 item 3).
 *
 * Manual bash mode asked one location question — may this path be READ? — and
 * every verb answered it identically. `~/.pi` is read-allowed (skills,
 * extensions), so `mkdir ~/.pi/agent/pwned-dir` and `touch ~/.pi/agent/pwned-file`
 * auto-allowed: nothing separated the operand a command WRITES from one it
 * reads, and no write grant could ever have been offered.
 *
 * The rule these tests pin: for every command on the closed set, the operand
 * position that is a write target is minted into `analysis.writePaths` — always
 * a subset of `analysis.paths` — and that set is checked against the WRITE
 * allow set alone (cwd ∪ config write dirs ∪ write grants). A READ grant never
 * satisfies a write. A command off the set contributes no write operand: no
 * new looseness, it just cannot be location-scoped.
 */

import path from "node:path";
import os from "node:os";
import { describe, expect, it } from "vitest";
import { writeOperandIndices } from "../analysis/write-roles";
import { gitOperandRoles } from "../config";
import { parseCommand } from "../analysis/bash-parser";

/** args are the parser's arguments AFTER the command word, so index 0 of the
 *  array is the first operand the parser sees. */
const idx = (cmd: string, args: string[], skip: number[] = []) =>
  [...writeOperandIndices(cmd, args, new Set(skip))].sort((a, b) => a - b);

describe("writeOperandIndices: the position table", () => {
  it("verbs that mutate what they name: every location operand", () => {
    expect(idx("mkdir", ["a", "b"])).toEqual([0, 1]);
    expect(idx("rm", ["-rf", "build", "dist"])).toEqual([1, 2]);
    expect(idx("truncate", ["-s", "0", "f"])).toEqual([2]);
    expect(idx("chmod", ["777", "f", "g"])).toEqual([1, 2]);
    expect(idx("touch", ["new"])).toEqual([0]);
    // gzip's operand is named; the .gz lands beside it, which is the location
    // at risk — naming the operand is how the bar sees the derived target.
    expect(idx("gzip", ["a", "b"])).toEqual([0, 1]);
    expect(idx("xz", ["-9", "a"])).toEqual([1]);
  });

  it("verbs whose destination is the LAST location operand", () => {
    expect(idx("mv", ["a", "b", "dir"])).toEqual([2]);
    expect(idx("cp", ["a", "b"])).toEqual([1]);
    expect(idx("install", ["-m", "755", "src", "dst"])).toEqual([3]);
    expect(idx("split", ["big", "pre"])).toEqual([1]);
    // `ln` LAST, not ALL: the first operand is a name the link points at, and
    // the command never writes it. Marking it a write would demand write
    // access to a file `ln -s ~/.pi/…/SKILL.md ./S.md` does not touch.
    expect(idx("ln", ["-s", "/etc/passwd", "link"])).toEqual([2]);
    expect(idx("ln", ["-s", "~/.pi/agent/skills/pdf/SKILL.md", "./S.md"])).toEqual([2]);
    // One operand alone states no destination pair: nothing is claimed.
    expect(idx("mv", ["dir"])).toEqual([]);
    // `-t DIR` states the destination, so no positional is one.
    expect(idx("cp", ["-t", "dir", "src1", "src2"])).toEqual([1]);
    expect(idx("mv", ["--target-directory=dir", "src"])).toEqual([0]);
  });

  it("verbs whose destination is the FIRST location operand", () => {
    expect(idx("zip", ["a.zip", "f1", "f2"])).toEqual([0]);
    // A lone operand IS the target: `patch f < diff` reads the diff on stdin.
    expect(idx("patch", ["f"])).toEqual([0]);
    expect(idx("patch", ["f", "-p1"])).toEqual([0]);
  });

  it("in-place flag decides it for sed/perl — otherwise the operand is read", () => {
    // The script argument is DATA at the operand position: the parser's skip
    // set (nonFileArgIndices) is what keeps it out, same as `-name x` above.
    expect(idx("sed", ["-i", "s/a/b/", "f"], [1])).toEqual([2]);
    expect(idx("sed", ["-i.bak", "s/a/b/", "f"], [1])).toEqual([2]);
    expect(idx("sed", ["-ni", "s/a/b/", "f"], [1])).toEqual([2]);
    expect(idx("sed", ["-n", "e", "f"], [1])).toEqual([]);
    expect(idx("sed", ["s/a/b/", "f"], [1])).toEqual([]);
    expect(idx("sed", ["--in-place", "s/a/b/", "f"], [1])).toEqual([2]);
    expect(idx("perl", ["-i", "-pe", "s/a/b/", "f"], [2])).toEqual([3]);
    expect(idx("perl", ["-ne", "print", "f"], [1])).toEqual([]);
  });

  it("flag VALUES are writes, per command — never the same flag everywhere", () => {
    expect(idx("sort", ["-o", "out", "in1", "in2"])).toEqual([1]);
    expect(idx("sort", ["--output=out", "in"])).toEqual([0]);
    expect(idx("sort", ["in", "-o", "out"])).toEqual([2]);
    // grep -o prints matches; it writes nothing.
    expect(idx("grep", ["-o", "pat", "f"])).toEqual([]);
    expect(idx("cp", ["-t", "dir", "src1", "src2"])).toEqual([1]);
    expect(idx("mv", ["--target-directory=dir", "src"])).toEqual([0]);
    expect(idx("unzip", ["-d", "outdir", "a.zip"])).toEqual([1]);
    expect(idx("patch", ["-o", "out", "-p1"])).toEqual([1]);
    expect(idx("find", [".", "-name", "x", "-fprint", "log"])).toEqual([4]);
    expect(idx("find", ["/d", "-fprintf", "/tmp/f", "%p"])).toEqual([2]);
  });

  it("`find -delete` empties the directories it walks", () => {
    // The `-name` VALUE is data, not a location: the parser's skip set is what
    // keeps it out of the all-operands rule, same as everywhere else.
    expect(idx("find", ["/d", "-name", "x", "-delete"], [2])).toEqual([0]);
    expect(idx("find", ["/d", "/e", "-delete"])).toEqual([0, 1]);
    expect(idx("find", ["/d", "-name", "x"])).toEqual([]);
  });

  it("tar writes the archive in a create mode, never in a read mode", () => {
    expect(idx("tar", ["cf", "out.tar", "."])).toEqual([1]);
    expect(idx("tar", ["-cf", "out.tar", "."])).toEqual([1]);
    expect(idx("tar", ["-czf", "out.tar.gz", "."])).toEqual([1]);
    expect(idx("tar", ["-c", "-f", "out.tar", "."])).toEqual([2]);
    expect(idx("tar", ["--file=out.tar", "-c", "."])).toEqual([0]);
    expect(idx("tar", ["--create", "out.tar", "."])).toEqual([1]);
    // A dashless bundle is anchored to a mode letter: `config` is an operand.
    expect(idx("tar", ["cf", "out.tar", "config"])).toEqual([1]);
    expect(idx("tar", ["xf", "in.tar"])).toEqual([]);
    expect(idx("tar", ["-tzf", "in.tar.gz"])).toEqual([]);
    expect(idx("tar", ["--list", "--file=in.tar"])).toEqual([]);
  });

  it("the parser's non-operand indices are never writes", () => {
    // A grep pattern is data; even a write verb's flag value at that index
    // (skipArgs) is not claimed as a destination.
    expect(idx("sort", ["-o", "out", "in"], [1])).toEqual([]);
  });

  it("closed world: a verb with no entry claims nothing", () => {
    expect(idx("whatchamacallit", ["a", "b"])).toEqual([]);
    expect(idx("echo", ["x", ">/dev/null"])).toEqual([]);
    expect(idx("", ["a"])).toEqual([]);
  });
});

describe("parseCommand: writePaths is the write-role subset", () => {
  const home = os.homedir();
  const abs = (p: string) => (p.startsWith("~") ? path.join(home, p.slice(2)) : p);

  const writesFor = async (command: string) => {
    const r = await parseCommand(command, "/work");
    const w = [...r.writePaths];
    // The invariant the whole design rests on: same mint sites, same dedup
    // filter, so a write is always a path the read bar already saw.
    for (const p of w) expect(r.paths, `${command}: ${p}`).toContain(p);
    return w;
  };

  it("a `>` destination is a write, a `<` source is not", async () => {
    expect(await writesFor("echo x > ~/Downloads/out.txt")).toEqual([abs("~/Downloads/out.txt")]);
    expect(await writesFor("cat < ~/Downloads/in.txt")).toEqual([]);
    expect(await writesFor("echo x >> ~/Downloads/log")).toEqual([abs("~/Downloads/log")]);
    expect(await writesFor("echo x >| ~/Downloads/f")).toEqual([abs("~/Downloads/f")]);
  });

  it("only the write-role operand of a command is marked", async () => {
    expect(await writesFor("sort -o ~/Downloads/x ~/Downloads/y")).toEqual([abs("~/Downloads/x")]);
    expect(await writesFor("cp ~/Downloads/a ~/Downloads/b")).toEqual([abs("~/Downloads/b")]);
    expect(await writesFor("ln -s ~/.pi/agent/skills/pdf/SKILL.md ./S.md")).toEqual(["/work/S.md"]);
    expect(await writesFor("tar cf ~/Downloads/a.tar config")).toEqual([abs("~/Downloads/a.tar")]);
    expect(await writesFor("unzip -d ~/Downloads ~/Downloads/z.zip")).toEqual([abs("~/Downloads")]);
    expect(await writesFor("cp -t ~/Downloads ~/Downloads/a ~/Downloads/b")).toEqual([abs("~/Downloads")]);
  });

  it("`dd` names its if= / of= operands even though they are k=v tokens", async () => {
    expect(await writesFor("dd if=/dev/zero of=~/Downloads/x")).toEqual([abs("~/Downloads/x")]);
    expect(await writesFor("dd if=~/Downloads/x of=/dev/null")).toEqual([]);
  });

  it("a short-option cluster carries the write target too (sort -ox)", async () => {
    expect(await writesFor("sort -o~/Downloads/x ~/Downloads/y")).toEqual([abs("~/Downloads/x")]);
  });

  it("a write-capable code body makes its own operands writes", async () => {
    expect(await writesFor("python3 -c 'open(\"~/.pi/agent/x\",\"w\")'")).toEqual([abs("~/.pi/agent/x")]);
    expect(await writesFor("node -e 'require(\"fs\").writeFileSync(\"~/.pi/agent/x\", 1)'")).toEqual([abs("~/.pi/agent/x")]);
    // A body that only reads contributes reads — the write set stays empty.
    expect(await writesFor("python3 -c 'print(open(\"~/.pi/agent/x\").read())'")).toEqual([]);
  });

  it("in-cwd writes stay writes — the bar, not the mint, decides them", async () => {
    expect(await writesFor("mkdir ./new-dir")).toEqual(["/work/new-dir"]);
    // At PARSE level every operand resolves against the parse cwd; the re-base
    // after `cd` is the analysis layer's job (threadCwdPaths), pinned in
    // test/verified-bypasses (P15).
    expect(await writesFor("cd ~/.pi/agent && mkdir ./pwned")).toEqual(["/work/pwned"]);
  });
});

// ── round 7 (3.53.0): mode-dependent roles — tar's destination, git's verb ──
//
// Two programs whose operand roles depend on something OUTSIDE the operand
// position. `tar -C DIR` is a destination while extracting and a read location
// while creating (`tar cf out.tar -C DIR .`), so a flag-wide table entry had to
// go mode-dependent (2026-11-13: `tar xf a.tgz -C /outside` minted no write at
// all). git's verb is its SUBCOMMAND, and it stayed out of the position table
// entirely because its arguments are revisions (`origin/main`); the cost was
// that NOTHING was minted — `git apply /var/x.patch` auto-allowed.

describe("tar: the -C destination is a write only while extracting", () => {
  it("extracting writes the -C directory, and not the archive it reads", () => {
    expect(idx("tar", ["xf", "a.tgz", "-C", "/d"])).toEqual([3]);
    expect(idx("tar", ["x", "a.tgz", "-C", "/d"])).toEqual([3]);
    expect(idx("tar", ["-zxvf", "a.tgz", "-C", "/d"])).toEqual([3]);
    expect(idx("tar", ["--extract", "--file", "a.tgz", "--directory", "/d"])).toEqual([4]);
    // The mode may come after the flag — the destination is still the write.
    expect(idx("tar", ["--directory", "/d", "-xf", "a.tgz"])).toEqual([1]);
  });

  it("creating writes the archive, and -C only says where to read from", () => {
    expect(idx("tar", ["cf", "a.tgz", "-C", "/d", "out"])).toEqual([1]);
    expect(idx("tar", ["rf", "a.tar", "-C", "/d", "out"])).toEqual([1]);
  });

  it("listing claims no destination", () => {
    expect(idx("tar", ["tf", "a.tgz", "-C", "/d"])).toEqual([1]);
    expect(idx("tar", ["--list", "-f", "a.tgz", "-C", "/d"])).toEqual([]);
  });

  it("a positional operand is never read as the mode", () => {
    // `tar cf out.tar x` — a file named `x` is not an extract mode, and an
    // operand-shaped match would claim `-C`'s read location as a write.
    expect(idx("tar", ["cf", "out.tar", "x"])).toEqual([1]);
  });
});

describe("gitOperandRoles: the subcommand decides what an operand means", () => {
  const roles = (args: string[]) => gitOperandRoles(args);

  it("a working-tree rewrite reads its patch and writes the repository", () => {
    expect(roles(["apply", "/var/p.patch"])).toEqual({
      sub: "apply", repoIdx: -1, writesRepo: true, reads: [1],
    });
    expect(roles(["am", "/box/1.mbox"])).toMatchObject({ sub: "am", writesRepo: true, reads: [1] });
    // Its own options all carry the value inline, so the first bare word is the patch.
    expect(roles(["-C", "/repo", "apply", "--index", "-p2", "rel.patch"])).toEqual({
      sub: "apply", repoIdx: 1, writesRepo: true, reads: [5],
    });
  });

  it("the location flags name the repository; --git-dir does not (it is not the tree)", () => {
    expect(roles(["--work-tree=/repo", "apply", "p"])).toMatchObject({ repoIdx: 0, writesRepo: true });
    expect(roles(["--git-dir", "/g", "apply", "/p"])).toMatchObject({ repoIdx: -1, reads: [3] });
  });

  it("a message file is a read, and only commit declares such flags", () => {
    expect(roles(["commit", "-q", "-F", "/m/msg.txt"])).toEqual({
      sub: "commit", repoIdx: -1, writesRepo: false, reads: [3],
    });
    expect(roles(["commit", "-Fmsg.txt"])).toMatchObject({ reads: [1] }); // the glued spelling
    expect(roles(["commit", "--file=/m/msg.txt"])).toMatchObject({ reads: [1] });
    // A subcommand that declares read-flags answers with an empty set rather
    // than null: nothing is minted, and the caller cannot confuse "no opinion"
    // with "opinion: nothing".
    expect(roles(["commit", "-m", "text"])).toEqual({
      sub: "commit", repoIdx: -1, writesRepo: false, reads: [],
    });
  });

  it("global flags are walked past; a subcommand with no location operand says nothing", () => {
    expect(roles(["-c", "k=v", "am", "/box/1"])).toMatchObject({ sub: "am", repoIdx: -1, reads: [3] });
    expect(roles(["status"])).toBeNull();
    expect(roles(["log", "origin/main..HEAD"])).toBeNull();
    expect(roles(["diff", "HEAD~2"])).toBeNull();
    // A repository named without a tree-writing subcommand is still a read.
    expect(roles(["-C", "/repo", "status"])).toEqual({
      sub: "status", repoIdx: 1, writesRepo: false, reads: [],
    });
  });
});
