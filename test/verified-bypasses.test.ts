/**
 * Regression tests for verified auto-allow bypasses (handoff /tmp/handoff-h1QLa6.md
 * + the user-reported `timeout npx vitest` wrapper gap).
 *
 * Each test verifies a specific attack vector that must NOT auto-allow.
 */

import path from "node:path";
import os from "node:os";
import { describe, expect, it } from "vitest";
import { decide } from "../decision-engine";
import { createStore } from "../store";

const home = os.homedir();
const cwd = path.join(home, "Projects");

// ──────────────────────────────────────────────────────────────────────
// P0: `cd` target amplification — cd was not path-aware, so its argument
// was never checked against outside-cwd or credential rules.
// ──────────────────────────────────────────────────────────────────────
describe("P0: cd path-awareness", () => {
  it("cd ~ && sort -o .bashrc x → prompts (write primitive after cd)", async () => {
    const d = await decide({ type: "bash", command: "cd ~ && sort -o .bashrc x", cwd }, createStore());
    expect(d.kind).not.toBe("auto-allow");
  });

  it("cd /etc && sort -o passwd /dev/null → prompts (outside cwd + write)", async () => {
    const d = await decide({ type: "bash", command: "cd /etc && sort -o passwd /dev/null", cwd }, createStore());
    expect(d.kind).not.toBe("auto-allow");
  });

  it("cd ~/.s?sh && cat id_rsa → prompts (glob-encoded dir, cd now path-aware)", async () => {
    // NOTE: `?` matches exactly one char, so ~/.s?sh cannot glob-match .ssh —
    // cd fails at runtime. The point is it must never auto-allow.
    const d = await decide({ type: "bash", command: "cd ~/.s?sh && cat id_rsa", cwd }, createStore());
    expect(d.kind).not.toBe("auto-allow");
  });

  it("cat ~/.s?sh/id_rsa → prompts (glob-encoded dir in path)", async () => {
    const d = await decide({ type: "bash", command: "cat ~/.s?sh/id_rsa", cwd }, createStore());
    expect(d.kind).not.toBe("auto-allow");
  });

  it("cd ~/.s*sh && cat id_rsa → BLOCKED (* matches zero chars → real .ssh)", async () => {
    // `*` matches the empty string: ~/.s*sh globs to ~/.ssh at runtime — this
    // is the real cd-amplified credential bypass.
    const d = await decide({ type: "bash", command: "cd ~/.s*sh && cat id_rsa", cwd }, createStore());
    expect(d.kind).toBe("block");
  });

  it("cat ~/.s*sh/id_ed25519 → BLOCKED (star-encoded .ssh)", async () => {
    const d = await decide({ type: "bash", command: "cat ~/.s*sh/id_ed25519", cwd }, createStore());
    expect(d.kind).toBe("block");
  });

  it("control: cd /tmp stays auto-allow (allowed write path)", async () => {
    const d = await decide({ type: "bash", command: "cd /tmp", cwd }, createStore());
    expect(d.kind).toBe("auto-allow");
  });
});

// ──────────────────────────────────────────────────────────────────────
// P1: `git -c` inline config executes code — isGitDangerous skipped -c values.
// ──────────────────────────────────────────────────────────────────────
describe("P1: git -c inline config (code execution)", () => {
  it("git -c alias.st=!rm st → prompts (shell alias)", async () => {
    const d = await decide({ type: "bash", command: "git -c alias.st=!rm st", cwd }, createStore());
    expect(d.kind).not.toBe("auto-allow");
  });

  it("git -c core.pager=/tmp/x diff → prompts", async () => {
    const d = await decide({ type: "bash", command: "git -c core.pager=/tmp/x diff", cwd }, createStore());
    expect(d.kind).not.toBe("auto-allow");
  });

  it("git --config core.fsmonitor=/tmp/x status → prompts (long form)", async () => {
    const d = await decide({ type: "bash", command: "git --config core.fsmonitor=/tmp/x status", cwd }, createStore());
    expect(d.kind).not.toBe("auto-allow");
  });

  it("git -ccore.editor=evil status → prompts (attached form)", async () => {
    const d = await decide({ type: "bash", command: "git -ccore.editor=evil status", cwd }, createStore());
    expect(d.kind).not.toBe("auto-allow");
  });

  it("control: git status stays auto-allow", async () => {
    const d = await decide({ type: "bash", command: "git status", cwd }, createStore());
    expect(d.kind).toBe("auto-allow");
  });

  it("control: benign -c config stays auto-allow", async () => {
    const d = await decide({ type: "bash", command: "git -c core.quotePath=false status", cwd }, createStore());
    expect(d.kind).toBe("auto-allow");
  });
});

// ──────────────────────────────────────────────────────────────────────
// P1: `sort -o` / `--output=` is a write primitive that auto-allowed.
// ──────────────────────────────────────────────────────────────────────
describe("P1: sort -o write primitive", () => {
  it("sort -o package.json /dev/null → prompts (truncate project file)", async () => {
    const d = await decide({ type: "bash", command: "sort -o package.json /dev/null", cwd }, createStore());
    expect(d.kind).not.toBe("auto-allow");
  });

  it("sort --output=out.txt in.txt → prompts", async () => {
    const d = await decide({ type: "bash", command: "sort --output=out.txt in.txt", cwd }, createStore());
    expect(d.kind).not.toBe("auto-allow");
  });

  it("sort -o /tmp/x in.txt → prompts", async () => {
    const d = await decide({ type: "bash", command: "sort -o /tmp/x in.txt", cwd }, createStore());
    expect(d.kind).not.toBe("auto-allow");
  });

  it("control: sort without -o stays auto-allow", async () => {
    const d = await decide({ type: "bash", command: "sort -k 2 in.txt", cwd }, createStore());
    expect(d.kind).toBe("auto-allow");
  });
});

// ──────────────────────────────────────────────────────────────────────
// P1: npx under a wrapper — wrapper delegation only checked write-ness,
// and npx was missing from the write-capable package-manager set.
// (User-reported: `timeout 600 npx vitest run 2>&1 | tail -15` auto-allowed.)
// ──────────────────────────────────────────────────────────────────────
describe("P1: npx under wrapper (user-reported)", () => {
  it("timeout 600 npx vitest run → prompts", async () => {
    const d = await decide({ type: "bash", command: "timeout 600 npx vitest run", cwd }, createStore());
    expect(d.kind).not.toBe("auto-allow");
  });

  it("timeout 5 npx --yes cowsay hi → prompts", async () => {
    const d = await decide({ type: "bash", command: "timeout 5 npx --yes cowsay hi", cwd }, createStore());
    expect(d.kind).not.toBe("auto-allow");
  });

  it("control: timeout 5 ls stays auto-allow", async () => {
    const d = await decide({ type: "bash", command: "timeout 5 ls", cwd }, createStore());
    expect(d.kind).toBe("auto-allow");
  });
});

// ──────────────────────────────────────────────────────────────────────
// P2: credential coverage gaps — standalone keyfiles, *.pem, .envrc,
// printenv env dump.
// ──────────────────────────────────────────────────────────────────────
describe("P2: credential coverage gaps", () => {
  it("cat id_rsa → prompts (standalone keyfile)", async () => {
    const d = await decide({ type: "bash", command: "cat id_rsa", cwd }, createStore());
    expect(d.kind).not.toBe("auto-allow");
  });

  it("cat server.pem → prompts (*.pem suffix)", async () => {
    const d = await decide({ type: "bash", command: "cat server.pem", cwd }, createStore());
    expect(d.kind).not.toBe("auto-allow");
  });

  it("cat .envrc → prompts", async () => {
    const d = await decide({ type: "bash", command: "cat .envrc", cwd }, createStore());
    expect(d.kind).not.toBe("auto-allow");
  });

  it("cat id_rs? → prompts (glob-encoded keyfile)", async () => {
    const d = await decide({ type: "bash", command: "cat id_rs?", cwd }, createStore());
    expect(d.kind).not.toBe("auto-allow");
  });

  it("printenv OPENAI_API_KEY → prompts (env secret dump)", async () => {
    const d = await decide({ type: "bash", command: "printenv OPENAI_API_KEY", cwd }, createStore());
    expect(d.kind).not.toBe("auto-allow");
  });

  it("bare printenv → prompts (dumps ALL env vars)", async () => {
    const d = await decide({ type: "bash", command: "printenv", cwd }, createStore());
    expect(d.kind).not.toBe("auto-allow");
  });

  it("control: cat package.json stays auto-allow", async () => {
    const d = await decide({ type: "bash", command: "cat package.json", cwd }, createStore());
    expect(d.kind).toBe("auto-allow");
  });
});

// ──────────────────────────────────────────────────────────────────────
// P2: relative-path executables must not inherit bare-name grants.
// ──────────────────────────────────────────────────────────────────────
describe("P2: relative-path grant isolation", () => {
  it("./node_modules/.bin/npm test does NOT auto-allow after `npm` grant", async () => {
    const store = createStore();
    store.addAllowed({ bashSigs: ["npm"] });
    const d = await decide({ type: "bash", command: "./node_modules/.bin/npm test", cwd }, store);
    expect(d.kind).not.toBe("auto-allow");
  });

  it("control: npm test auto-allows after `npm` grant", async () => {
    const store = createStore();
    store.addAllowed({ bashSigs: ["npm"] });
    const d = await decide({ type: "bash", command: "npm test", cwd }, store);
    expect(d.kind).toBe("auto-allow");
  });
});

// ──────────────────────────────────────────────────────────────────────
// P2: tree-sitter parse errors must never auto-allow (parser divergence).
// ──────────────────────────────────────────────────────────────────────
describe("P2: parse errors block auto-allow", () => {
  it("ls $( → prompts (unterminated substitution)", async () => {
    const d = await decide({ type: "bash", command: "ls $(", cwd }, createStore());
    expect(d.kind).not.toBe("auto-allow");
  });

  it("echo $( → prompts", async () => {
    const d = await decide({ type: "bash", command: "echo $(", cwd }, createStore());
    expect(d.kind).not.toBe("auto-allow");
  });
});

// ──────────────────────────────────────────────────────────────────────
// P3: terminal escape sequences in echo/printf (OSC 52 clipboard write,
// screen spoofing).
// ──────────────────────────────────────────────────────────────────────
describe("P3: terminal escape sequences", () => {
  it("printf '\\033]52;c;AAAA' → prompts (OSC 52 clipboard)", async () => {
    const d = await decide({ type: "bash", command: "printf '\\033]52;c;AAAA'", cwd }, createStore());
    expect(d.kind).not.toBe("auto-allow");
  });

  it("echo -e '\\033[2J' → prompts (screen clear/spoof)", async () => {
    const d = await decide({ type: "bash", command: "echo -e '\\033[2J'", cwd }, createStore());
    expect(d.kind).not.toBe("auto-allow");
  });

  it("echo $'\\033[31m' → prompts (ANSI-C quoting)", async () => {
    const d = await decide({ type: "bash", command: "echo $'\\033[31m'", cwd }, createStore());
    expect(d.kind).not.toBe("auto-allow");
  });

  it("control: echo hello stays auto-allow", async () => {
    const d = await decide({ type: "bash", command: "echo hello", cwd }, createStore());
    expect(d.kind).toBe("auto-allow");
  });

  it("control: echo -e 'a\\nb' stays auto-allow (no ESC)", async () => {
    const d = await decide({ type: "bash", command: "echo -e 'a\\nb'", cwd }, createStore());
    expect(d.kind).toBe("auto-allow");
  });

  it("control: printf 'hello %s\\n' world stays auto-allow", async () => {
    const d = await decide({ type: "bash", command: "printf 'hello %s\\n' world", cwd }, createStore());
    expect(d.kind).toBe("auto-allow");
  });
});

// ──────────────────────────────────────────────────────────────────────
// Glob sanity — globs in benign commands must not false-positive.
// ──────────────────────────────────────────────────────────────────────
describe("glob sanity (no false positives)", () => {
  it("cat * stays auto-allow", async () => {
    const d = await decide({ type: "bash", command: "cat *", cwd }, createStore());
    expect(d.kind).toBe("auto-allow");
  });

  it("ls *.ts stays auto-allow", async () => {
    const d = await decide({ type: "bash", command: "ls *.ts", cwd }, createStore());
    expect(d.kind).toBe("auto-allow");
  });

  it("ls ? stays auto-allow", async () => {
    const d = await decide({ type: "bash", command: "ls ?", cwd }, createStore());
    expect(d.kind).toBe("auto-allow");
  });
});
