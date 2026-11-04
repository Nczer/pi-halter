/**
 * The command position is read once, as the shell resolves it (3.50.0).
 *
 * Before this suite, three spellings of the same program each hid it from the
 * verb-keyed layer, and the grant identity inherited the mistake:
 *
 *   FOO=1 rm -rf x   → signature "foo=1 -rf",   no [Pattern] rm, Always offered
 *   "rm" -rf x       → signature "__str__ -rf", no [Pattern] rm, Always offered
 *   \rm -rf x        → signature "\rm -rf",     no [Pattern] rm, Always offered
 *
 * Because grants prefix-match, an Always minted from one spelling then covered
 * a different program behind the same prefix (`foo=1` covered `FOO=1 git
 * push`; `__str__` covered every quoted command, including
 * `"cat" /etc/passwd`, whose operands the parser never minted either).
 *
 * Every row below is a verified bypass from the review; each must keep its
 * prompt, its program-named identity, and its narrow grant.
 */
import { describe, expect, it, beforeAll, afterAll } from "vitest";
import { decide } from "../decide/engine";
import { analyzeCommand } from "../analysis/command-analysis";
import { getCommandSignature, hasInlineAssignment } from "../analysis/segment-helpers";
import { createStore } from "../gate/store";
import { buildPrompt } from "../ui/prompt-builder";
import type { Decision } from "../decide/types";
import { createContractCwd, removeContractCwd } from "./hermetic-cwd";

let cwd: string;

beforeAll(() => {
  cwd = createContractCwd();
});
afterAll(() => removeContractCwd(cwd));

const decideBash = (command: string, store = createStore()): Promise<Decision> =>
  decide({ type: "bash", command, cwd }, store);

async function promptOf(command: string, store = createStore()) {
  const d = await decideBash(command, store);
  if (d.kind !== "prompt" || d.promptData.type !== "bash") {
    throw new Error(`${command}: expected a bash prompt, got ${d.kind}`);
  }
  return d;
}

const alwaysOffered = (d: Decision): boolean => d.kind === "prompt" && buildPrompt(d).includeAlwaysOption === true;

describe("the program is read past the spelling", () => {
  it("an inline assignment, quotes and a backslash all name the program they run", () => {
    expect(getCommandSignature("FOO=1 ls", cwd)).toBe("foo=1 ls");
    expect(getCommandSignature("FOO=1 /bin/ls", cwd)).toBe("foo=1 /bin/ls");
    expect(getCommandSignature("FOO=1 /bin/ls -la", cwd)).toBe("foo=1 /bin/ls -la");
    expect(getCommandSignature('"cat" notes.txt', cwd)).toBe("cat");
    expect(getCommandSignature("'cat' notes.txt", cwd)).toBe("cat");
    expect(getCommandSignature("$'cat' notes.txt", cwd)).toBe("cat");
    expect(getCommandSignature("\\cat notes.txt", cwd)).toBe("cat");
    // The pre-existing qualified-prefix identity, unchanged.
    expect(getCommandSignature("FOO=/tmp/x /tmp/y", cwd)).toBe("foo=/tmp/x /tmp/y");
    // Wrapper/package/run-form identities are untouched.
    expect(getCommandSignature("nice bin/ls", cwd)).toBe("nice bin/ls");
    expect(getCommandSignature("timeout 5 curl http://x", cwd)).toBe("timeout curl");
    expect(getCommandSignature("npm test", cwd)).toBe("npm test");
    expect(getCommandSignature("FOO=1 npm test", cwd)).toBe("foo=1 npm test");
    expect(getCommandSignature("uv run --with pandas x.py", cwd)).toBe("uv run --with pandas");
    expect(getCommandSignature("FOO=1 uv run --with pandas x.py", cwd)).toBe("foo=1 uv run --with pandas");
  });

  it("no identity carries the quoted-argument marker", () => {
    for (const cmd of ['"rm" -rf x', '"git" push', "$'cat' x", '"npm" test']) {
      expect(getCommandSignature(cmd, cwd)).not.toContain("__str__");
    }
  });

  it("hasInlineAssignment answers for the shell's assignment words only", () => {
    expect(hasInlineAssignment("FOO=1 ls")).toBe(true);
    expect(hasInlineAssignment("A=1 B=2 ls")).toBe(true);
    expect(hasInlineAssignment("ls FOO=1")).toBe(false);
    expect(hasInlineAssignment('"cat" x')).toBe(false);
    expect(hasInlineAssignment("\\cat x")).toBe(false);
  });
});

describe("the danger tables see the program behind the spelling", () => {
  const rows = [
    "FOO=1 rm -rf child",
    '"rm" -rf child',
    "'rm' -rf child",
    "$'rm' -rf child",
    "\\rm -rf child",
    "FOO=1 git push",
    "FOO=1 python3 -c 'print(1)'",
    "FOO=1 find . -delete",
  ];

  it("every spelling prompts as dangerous and offers no Always", async () => {
    for (const cmd of rows) {
      const d = await promptOf(cmd);
      expect(d.promptData, cmd).toMatchObject({ hasUnsafePattern: true, riskDangerous: true });
      expect(alwaysOffered(d), cmd).toBe(false);
    }
  });

  it("a quoted/escaped dangerous program is the same row as the bare one", async () => {
    for (const cmd of ['"git" push', "\\git push", '"rm" -rf x']) {
      const pd = (await promptOf(cmd)).promptData;
      if (pd.type !== "bash") throw new Error("bash");
      expect(pd.riskReasons.length, cmd).toBeGreaterThan(0);
    }
  });
});

describe("quoted and escaped program names are path-aware", () => {
  it("their operands join the path set, so the read bar sees them", async () => {
    for (const cmd of ['"cat" /etc/passwd', "\\cat /etc/passwd", '"head" /etc/passwd']) {
      const a = await analyzeCommand(cmd, cwd, { isInsideAllowedDir: () => false });
      expect(a.paths, cmd).toContain("/etc/passwd");
      const d = await promptOf(cmd);
      expect(d.promptData, cmd).toMatchObject({ needsPathApproval: true });
      if (d.promptData.type === "bash") expect(d.promptData.outsideDirs).toContain("/etc");
    }
  });

  it("an in-cwd read spelled with quotes or a backslash auto-allows", async () => {
    for (const cmd of ['"cat" notes.txt', "\\cat notes.txt", '"ls" -la', "\\ls"]) {
      expect((await decideBash(cmd)).kind, cmd).toBe("auto-allow");
    }
  });
});

describe("a grant names the program, so it cannot cover another one", () => {
  it("the exact assignment-aware identity covers its own flag variants", async () => {
    const store = createStore();
    store.addAllowed({ bashSigs: ["foo=1 ls"] });
    expect((await decideBash("FOO=1 ls", store)).kind).toBe("auto-allow");
    expect((await decideBash("FOO=1 ls -la", store)).kind).toBe("auto-allow");
    // A different program behind the same assignment, or a different value.
    expect((await decideBash("FOO=1 rm -rf /tmp/x", store)).kind).toBe("prompt");
    expect((await decideBash("FOO=1 git push", store)).kind).toBe("prompt");
    expect((await decideBash("FOO=2 ls", store)).kind).toBe("prompt");
  });

  it("an assignment-only grant covers nothing behind it", async () => {
    // The pre-3.50.0 identity: an Always on `FOO=1 ls` stored `foo=1`.
    const store = createStore();
    store.addAllowed({ bashSigs: ["foo=1"] });
    expect((await decideBash("FOO=1 ls", store)).kind).toBe("prompt");
    expect((await decideBash("FOO=1 rm -rf /tmp/x", store)).kind).toBe("prompt");
  });

  it("the quoted-command marker is not a shared identity", async () => {
    const store = createStore();
    store.addAllowed({ bashSigs: ["__str__"] });
    for (const cmd of ['"rm" -rf /tmp/x', '"python3" -c \'print(1)\'', '"cat" /etc/passwd']) {
      expect((await decideBash(cmd, store)).kind, cmd).toBe("prompt");
    }
    // A grant on the real program still works for the quoted spelling, and
    // the path bar still stops the outside read.
    const catStore = createStore();
    catStore.addAllowed({ bashSigs: ["cat"] });
    expect((await decideBash('"cat" notes.txt', catStore)).kind).toBe("auto-allow");
    expect((await decideBash('"cat" /etc/passwd', catStore)).kind).toBe("prompt");
  });
});

describe("assignment-prefixed commands are prompt-first, not wildcards", () => {
  it("the prompt offers the exact spelling (so it can be silenced in one click)", async () => {
    const d = await promptOf("FOO=1 ls");
    if (d.promptData.type !== "bash") throw new Error("bash");
    expect(d.promptData.signatures).toEqual(["foo=1 ls"]);
    expect(d.promptData.hasUnsafePattern).toBe(false);
    expect(alwaysOffered(d)).toBe(true);
  });

  it("the trusted script and trusted package paths keep working behind an assignment", async () => {
    // D8/Bash-trust: the assignment sets the environment, the trusted script
    // is what runs — the pre-3.50.0 behaviour this fix must not lose.
    expect((await decideBash("DEBUG=1 python3 ~/.pi/agent/skills/test.py")).kind).toBe("auto-allow");
    const store = createStore();
    store.trustPackage("tsc");
    expect((await decideBash("FOO=bar npx tsc", store)).kind).toBe("auto-allow");
    // ...and an untrusted package behind the same prefix still prompts.
    expect((await decideBash("FOO=bar npx evil", store)).kind).toBe("prompt");
  });
});
