/**
 * Variable resolution: cwd-local substitution classification, assignment
 * dataflow binding, loop in-list classification (bare / cwd-local / pinned /
 * opaque), and worst-case candidate resolution — the replacement for the old
 * `<unresolved-var>` marker (2026-09-21 hardening).
 */
import path from "node:path";
import os from "node:os";
import fs from "node:fs";
import { describe, expect, it, beforeAll, afterAll } from "vitest";
import { parseCommand } from "../analysis/bash-parser";
import { resolveOpaqueRefs } from "../analysis/var-resolution";
import { trackEffectiveCwd } from "../analysis/cwd-tracking";
import { isCwdLocalSubstitution, isCwdLocalWord } from "../analysis/cwd-local";
import { decide } from "../decision-engine";
import { createStore } from "../store";

const CWD = "/home/u/project";
const home = os.homedir();
const sessionCwd = path.join(home, "Projects");

/** Strict base predicate: only the session cwd counts as inside. */
const strictInside = (p: string) => p === CWD || p.startsWith(CWD + "/");

/** Parse + resolve with the strict base predicate (deterministic, no config). */
async function resolve(cmd: string) {
  const p = await parseCommand(cmd, CWD);
  return resolveOpaqueRefs(
    p.opaque,
    p.segments,
    trackEffectiveCwd(p.segments, CWD),
    p.assignments,
    CWD,
    strictInside,
  );
}

describe("isCwdLocalSubstitution", () => {
  const accepted = [
    "find .",
    "find . -name '*.ts'",
    "find . -maxdepth 2 -type f",
    "find . | head",
    "find . -name x | head -5",
    "find . -name x | head -n 5",
    "find . | sort -r",
    "find . -name x | uniq -c",
    "find . | xargs grep -l pat",
    "find . -name x | xargs grep -l -e pat",
  ];
  const rejected = [
    "find /abs",
    "find ..",
    "find ../x",
    "find ./*",
    "find . -exec ls {} \\;",
    "find . -ok sh -c 'ls {}' \\;",
    "find . | awk '{print $1}'",
    "find . | sed s/a/b/",
    "find . | wc -l",
    "find . | sort 5",
    "find . | grep -l pat",
    "find . | xargs grep pat",
    "find . | xargs grep -l p1 p2",
    "find . ; echo hi",
    "find . & ls",
    "find $x",
    "find . -name \"$x\"",
    "ls .",
    "",
  ];

  for (const s of accepted) {
    it(`accepts: ${s}`, () => expect(isCwdLocalSubstitution(s)).toBe(true));
  }
  for (const s of rejected) {
    it(`rejects: ${s || "(empty)"}`, () => expect(isCwdLocalSubstitution(s)).toBe(false));
  }
});

describe("isCwdLocalWord", () => {
  it("accepts a whole-word substitution", () => expect(isCwdLocalWord("$(find .)")).toBe(true));
  it("accepts single-quoted", () => expect(isCwdLocalWord("'$(find .)'")).toBe(true));
  it("rejects double-quoted (runtime expansion)", () => expect(isCwdLocalWord('"$(find .)"')).toBe(false));
  it("rejects literal glue", () => expect(isCwdLocalWord("$(find .) extra")).toBe(false));
  it("rejects a second command", () => expect(isCwdLocalWord("$(find . ; echo hi)")).toBe(false));
  it("rejects escaping find", () => expect(isCwdLocalWord("$(find ..)")).toBe(false));
  it("rejects a plain var", () => expect(isCwdLocalWord("$x")).toBe(false));
  it("rejects absolute find", () => expect(isCwdLocalWord("$(find /)")).toBe(false));
});

describe("assignment binding", () => {
  it("relative value resolves under the segment base → inside", async () => {
    const r = await resolve('f=./x.jsonl; cat "$f"');
    expect(r.paths).toEqual([]);
    expect(r.unresolved).toEqual([]);
  });

  it("absolute value resolves to the concrete outside path", async () => {
    const r = await resolve("f=/etc/passwd; cat \"$f\"");
    expect(r.paths).toEqual(["/etc/passwd"]);
    expect(r.unresolved).toEqual([]);
  });

  it("unbound ref stays a sentinel (reason var)", async () => {
    const r = await resolve("f=$g; cat $f");
    expect(r.paths).toEqual([]);
    expect(r.unresolved.map(u => u.token)).toEqual(["$f"]);
    expect(r.unresolved[0].reason).toBe("var");
  });

  it("reassigned ref is ambiguous → sentinel", async () => {
    const r = await resolve("f=a; f=b; cat $f");
    expect(r.unresolved.map(u => u.token)).toEqual(["$f"]);
  });

  it("subshell-local assignment does not leak to the parent", async () => {
    const r = await resolve("(f=/etc/x; cat $f); cat $f");
    expect(r.unresolved.map(u => u.token)).toEqual(["$f", "$f"]);
  });

  it("subshell inherits the parent assignment", async () => {
    const r = await resolve("f=/etc/x; (cat $f)");
    expect(r.paths).toEqual(["/etc/x"]);
    expect(r.unresolved).toEqual([]);
  });

  it("export form binds (declaration_command)", async () => {
    const r = await resolve("export f=/etc/x; cat $f");
    expect(r.paths).toEqual(["/etc/x"]);
  });

  it("export form with a relative value resolves inside", async () => {
    const r = await resolve("export f=./x; cat $f");
    expect(r.paths).toEqual([]);
  });

  it("a bare `export f` re-exports the earlier assignment", async () => {
    const r = await resolve("f=/etc/x; export f; cat $f");
    expect(r.paths).toEqual(["/etc/x"]);
  });

  it("an exec form in the value stays opaque", async () => {
    const r = await resolve('f=$(find . -exec ls {} \\;); cat $f');
    expect(r.unresolved.map(u => u.token)).toEqual(["$f"]);
  });

  it("a cwd-local find value resolves against the base", async () => {
    const r = await resolve('f=$(find . -name \'*.log\' | head); cat "$f"');
    expect(r.paths).toEqual([]);
    expect(r.unresolved).toEqual([]);
  });

  it("a cwd-local find value after a cd resolves against the cd base", async () => {
    const r = await resolve('f=$(find . -name \'*.log\' | head); cd /etc && cat "$f"');
    expect(r.paths).toEqual(["/etc"]);
  });

  it("a default chain resolves through the unbound vars", async () => {
    const r = await resolve('d=${PI_TMUX_SOCKET_DIR:-${TMPDIR:-/tmp}/sockets}; mkdir -p "$d"');
    expect(r.paths).toEqual(["/tmp/sockets"]);
  });

  it("an env prefix does not bind (command child, not statement position)", async () => {
    const r = await resolve('f=/etc/x cat $f');
    expect(r.unresolved.map(u => u.token)).toEqual(["$f"]);
  });

  it("a backgrounded assignment does not bind", async () => {
    const r = await resolve("f=/etc/x & cat $f");
    expect(r.unresolved.map(u => u.token)).toEqual(["$f"]);
  });

  it("a ref after a later reassignment sees only the earlier value", async () => {
    const r = await resolve("f=/etc/x; cat $f; f=./y");
    expect(r.paths).toEqual(["/etc/x"]);
  });
});

describe("loop in-list classification (decide level, session cwd)", () => {
  it("bare in-list with a cd outside cwd → prompt (the <unresolved-cwd> hole, closed)", async () => {
    const d = await decide({ type: "bash", command: "cd /etc && for f in a b; do cat $f; done", cwd: sessionCwd }, createStore());
    expect(d.kind).toBe("prompt");
  });

  it("bare in-list under the session cwd → auto-allow (the log false positive, gone)", async () => {
    const d = await decide({ type: "bash", command: "for f in a.txt b.txt; do cat $f; done", cwd: sessionCwd }, createStore());
    expect(d.kind).toBe("auto-allow");
  });

  it("a subshell in a command argument: worst-case candidate resolution keeps it auto-allow", async () => {
    const d = await decide({ type: "bash", command: 'for f in a.txt b.txt; do echo "$(cat $f)"; done', cwd: sessionCwd }, createStore());
    expect(d.kind).toBe("auto-allow");
  });

  it("the 2026-09-21 log shape (wc probe in an echo argument) → auto-allow", async () => {
    const d = await decide(
      { type: "bash", command: 'for f in a.txt b.txt; do echo "=== $f ($(wc -c < $f) chars) ==="; done', cwd: sessionCwd },
      createStore(),
    );
    expect(d.kind).toBe("auto-allow");
  });
});

describe("pinned in-lists (trailing static prefix)", () => {
  let base: string;
  beforeAll(() => {
    base = fs.mkdtempSync(path.join(os.tmpdir(), "halter-pin-"));
    fs.mkdirSync(path.join(base, "sess", "0123abc"), { recursive: true });
  });
  afterAll(() => {
    fs.rmSync(base, { recursive: true, force: true });
  });

  it("classifies a bounded in-list with a known-root prefix as pinned", async () => {
    const r = await parseCommand(`for d in 0123abc*; do ls ${base}/sess/$d; done`, CWD);
    expect(r.opaque).toEqual([
      { raw: `${base}/sess/$d`, segIdx: 0, kind: "pinned", prefixDir: fs.realpathSync(path.join(base, "sess")) },
    ]);
  });

  it("a pinned prefix outside the base is named, not sentinel-prompted", async () => {
    const r = await resolve(`for d in 0123abc*; do ls ${base}/sess/$d; done`);
    expect(r.paths).toEqual([fs.realpathSync(path.join(base, "sess"))]);
    expect(r.unresolved).toEqual([]);
  });

  it("an in-list word with $ stays opaque (pinned proof fails)", async () => {
    const r = await parseCommand(`for d in ${base}/sess/$d; do ls "$d"; done`, CWD);
    expect(r.opaque.every(o => o.kind === "opaque")).toBe(true);
  });
});
