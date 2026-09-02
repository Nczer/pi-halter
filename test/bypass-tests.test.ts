/**
 * Security bypass regression tests — FastAllow/wrapper/tmux/sed attack
 * vectors.
 *
 * Sibling of verified-bypasses.test.ts (the handoff-verified P0–P5 vectors);
 * together the two files cover the known bypass classes. Each test verifies
 * a specific attack vector that should NOT auto-allow.
 */

import path from "node:path";
import os from "node:os";
import { describe, expect, it, beforeAll, afterAll } from "vitest";
import {decide} from "../decide/engine";
import { createStore } from "../gate/store";
import { createContractCwd, removeContractCwd } from "./hermetic-cwd";

let cwd: string;

beforeAll(() => {
  cwd = createContractCwd();
});
afterAll(() => removeContractCwd(cwd));

// ──────────────────────────────────────────────────────────────────────
// 🔴 CRITICAL: FastAllowRule — newline command injection
// ──────────────────────────────────────────────────────────────────────
describe("CRITICAL: FastAllowRule newline injection", () => {
  it("blocks: ls\\nrm -rf / (newline after safe command)", async () => {
    const store = createStore();
    const d = await decide({ type: "bash", command: "ls\nrm -rf /", cwd }, store);
    expect(d.kind).not.toBe("auto-allow");
  });

  it("blocks: echo ok\\nrm -rf / (newline after echo)", async () => {
    const store = createStore();
    const d = await decide({ type: "bash", command: "echo ok\nrm -rf /", cwd }, store);
    expect(d.kind).not.toBe("auto-allow");
  });

  it("blocks: cat x\\ncat /etc/passwd (newline after cat)", async () => {
    const store = createStore();
    const d = await decide({ type: "bash", command: "cat x\ncat /etc/passwd", cwd }, store);
    expect(d.kind).not.toBe("auto-allow");
  });

  it("blocks: ls\\r\\nrm -rf / (CRLF after safe command)", async () => {
    const store = createStore();
    const d = await decide({ type: "bash", command: "ls\r\nrm -rf /", cwd }, store);
    expect(d.kind).not.toBe("auto-allow");
  });

  it("blocks: ls\\npython evil.py (newline + interpreter)", async () => {
    const store = createStore();
    const d = await decide({ type: "bash", command: "ls\npython evil.py", cwd }, store);
    expect(d.kind).not.toBe("auto-allow");
  });
});

// ──────────────────────────────────────────────────────────────────────
// 🔴 CRITICAL: Wrapper + interpreter auto-allow bypass
// ──────────────────────────────────────────────────────────────────────
describe("CRITICAL: wrapper + interpreter bypass", () => {
  it("timeout python → prompts (not auto-allowed)", async () => {
    const store = createStore();
    const d = await decide({ type: "bash", command: "timeout 10 python evil.py", cwd }, store);
    expect(d.kind).not.toBe("auto-allow");
  });

  it("timeout node → prompts (not auto-allowed)", async () => {
    const store = createStore();
    const d = await decide({ type: "bash", command: "timeout 10 node exploit.js", cwd }, store);
    expect(d.kind).not.toBe("auto-allow");
  });

  it("watch python → prompts (not auto-allowed)", async () => {
    const store = createStore();
    const d = await decide({ type: "bash", command: "watch python evil.py", cwd }, store);
    expect(d.kind).not.toBe("auto-allow");
  });

  it("watch node → prompts (not auto-allowed)", async () => {
    const store = createStore();
    const d = await decide({ type: "bash", command: "watch node exploit.js", cwd }, store);
    expect(d.kind).not.toBe("auto-allow");
  });

  it("nice python → prompts (not auto-allowed)", async () => {
    const store = createStore();
    const d = await decide({ type: "bash", command: "nice python evil.py", cwd }, store);
    expect(d.kind).not.toBe("auto-allow");
  });

  it("xargs python → prompts (not auto-allowed)", async () => {
    const store = createStore();
    const d = await decide({ type: "bash", command: "xargs python", cwd }, store);
    expect(d.kind).not.toBe("auto-allow");
  });

  it("parallel python → prompts (not auto-allowed)", async () => {
    const store = createStore();
    const d = await decide({ type: "bash", command: "parallel python", cwd }, store);
    expect(d.kind).not.toBe("auto-allow");
  });

  it("env python → prompts (not auto-allowed)", async () => {
    const store = createStore();
    const d = await decide({ type: "bash", command: "env python evil.py", cwd }, store);
    expect(d.kind).not.toBe("auto-allow");
  });

  it("timeout ruby → prompts (not auto-allowed)", async () => {
    const store = createStore();
    const d = await decide({ type: "bash", command: "timeout 10 ruby attack.rb", cwd }, store);
    expect(d.kind).not.toBe("auto-allow");
  });

  it("timeout php → prompts (not auto-allowed)", async () => {
    const store = createStore();
    const d = await decide({ type: "bash", command: "timeout 10 php attack.php", cwd }, store);
    expect(d.kind).not.toBe("auto-allow");
  });

  it("timeout lua → prompts (not auto-allowed)", async () => {
    const store = createStore();
    const d = await decide({ type: "bash", command: "timeout 10 lua attack.lua", cwd }, store);
    expect(d.kind).not.toBe("auto-allow");
  });

  it("timeout deno → prompts (not auto-allowed)", async () => {
    const store = createStore();
    const d = await decide({ type: "bash", command: "timeout 10 deno run attack.ts", cwd }, store);
    expect(d.kind).not.toBe("auto-allow");
  });

  it("timeout bun → prompts (not auto-allowed)", async () => {
    const store = createStore();
    const d = await decide({ type: "bash", command: "timeout 10 bun run attack.ts", cwd }, store);
    expect(d.kind).not.toBe("auto-allow");
  });

  it("timeout perl → prompts (not auto-allowed)", async () => {
    const store = createStore();
    const d = await decide({ type: "bash", command: "timeout 10 perl evil.pl", cwd }, store);
    expect(d.kind).not.toBe("auto-allow");
  });

  // Verify existing safe wrapper patterns still work
  it("timeout ls → auto-allows (safe inner command)", async () => {
    const store = createStore();
    const d = await decide({ type: "bash", command: "timeout 30 ls -la", cwd }, store);
    expect(d.kind).toBe("auto-allow");
  });

  it("watch cat → auto-allows (safe inner command)", async () => {
    const store = createStore();
    const d = await decide({ type: "bash", command: "watch cat file.txt", cwd }, store);
    expect(d.kind).toBe("auto-allow");
  });
});

// ──────────────────────────────────────────────────────────────────────
// 🔴 CRITICAL: tmux send-keys chained command bypass
// ──────────────────────────────────────────────────────────────────────
describe("CRITICAL: tmux send-keys chained command bypass", () => {
  // The payload is typed into a pane's shell: analyzeTmuxSendKeysPayload
  // splits it on Enter and every chunk must meet the SAME auto-allow bar
  // as a direct command. These tests run the full pipeline end-to-end
  // (the old raw-text isTmuxSendKeysSafe heuristic is gone).
  const sendKeys = (payload: string) =>
    decide({ type: "bash", command: `tmux send-keys -t foo '${payload}' Enter`, cwd }, createStore());

  it("ls ; rm -rf . → prompts (semicolon chain)", async () => {
    expect((await sendKeys("ls ; rm -rf .")).kind).not.toBe("auto-allow");
  });

  it("ls && rm -rf . → prompts (&& chain)", async () => {
    expect((await sendKeys("ls && rm -rf .")).kind).not.toBe("auto-allow");
  });

  it("cat x | bash → prompts (pipe to interpreter)", async () => {
    expect((await sendKeys("cat x | bash")).kind).not.toBe("auto-allow");
  });

  it("cat x | sh → prompts (pipe to interpreter)", async () => {
    expect((await sendKeys("cat x | sh")).kind).not.toBe("auto-allow");
  });

  it("echo ok > file → prompts (write redirect)", async () => {
    expect((await sendKeys("echo ok > file")).kind).not.toBe("auto-allow");
  });

  it("ls || rm -rf . → prompts (|| chain)", async () => {
    expect((await sendKeys("ls || rm -rf .")).kind).not.toBe("auto-allow");
  });

  it("ls & → auto-allow (trailing & is a background suffix — direct 'ls &' auto-allows too, so the payload inherits the same verdict)", async () => {
    expect((await sendKeys("ls &")).kind).toBe("auto-allow");
  });

  it("ls; cat x → auto-allow (chaining ONLY safe commands inherits the direct-command bar — direct 'ls; cat x' auto-allows too)", async () => {
    expect((await sendKeys("ls; cat x")).kind).toBe("auto-allow");
  });

  // Verify existing safe send-keys patterns still work
  it("ls -la → auto-allow (single allowed command)", async () => {
    expect((await sendKeys("ls -la")).kind).toBe("auto-allow");
  });

  it("cat file.txt → auto-allow (single allowed command)", async () => {
    expect((await sendKeys("cat file.txt")).kind).toBe("auto-allow");
  });

  it("grep pattern file → auto-allow (single allowed command)", async () => {
    expect((await sendKeys("grep pattern file")).kind).toBe("auto-allow");
  });
});

// ──────────────────────────────────────────────────────────────────────
// 🟠 HIGH: sed -ni — combined flag bypass
// ──────────────────────────────────────────────────────────────────────
describe("HIGH: sed combined flag bypass", () => {
  it("sed -ni → prompts (combined flag = in-place)", async () => {
    const store = createStore();
    const d = await decide({ type: "bash", command: "sed -ni 's/a/b/' file.txt", cwd }, store);
    expect(d.kind).not.toBe("auto-allow");
  });

  it("sed -npi → prompts (combined flag = in-place)", async () => {
    const store = createStore();
    const d = await decide({ type: "bash", command: "sed -npi 's/a/b/' file.txt", cwd }, store);
    expect(d.kind).not.toBe("auto-allow");
  });

  it("sed -in → prompts (-i with 'n' backup suffix = in-place, GNU sed verified)", async () => {
    const store = createStore();
    const d = await decide({ type: "bash", command: "sed -in 's/foo/bar/' file.txt", cwd }, store);
    expect(d.kind).toBe("prompt");
  });

  it("sed -in == sed -ni (same flags, different order → same decision)", async () => {
    const store = createStore();
    const dNi = await decide({ type: "bash", command: "sed -ni 's/a/b/' file.txt", cwd }, store);
    const dIn = await decide({ type: "bash", command: "sed -in 's/a/b/' file.txt", cwd }, store);
    expect(dNi.kind).toBe(dIn.kind);
    expect(dIn.kind).toBe("prompt");
  });

  it("sed -i → prompts (in-place)", async () => {
    const store = createStore();
    const d = await decide({ type: "bash", command: "sed -i 's/a/b/' file.txt", cwd }, store);
    expect(d.kind).not.toBe("auto-allow");
  });

  it("sed -i.bak → prompts (in-place with backup)", async () => {
    const store = createStore();
    const d = await decide({ type: "bash", command: "sed -i.bak 's/a/b/' file.txt", cwd }, store);
    expect(d.kind).not.toBe("auto-allow");
  });
});

// ──────────────────────────────────────────────────────────────────────
// 🟠 HIGH: git -C / global flag bypass
// ──────────────────────────────────────────────────────────────────────
describe("HIGH: git global flag bypass", () => {
  it("git -C repo reset --hard → prompts (global flag bypass)", async () => {
    const store = createStore();
    const d = await decide({ type: "bash", command: "git -C repo reset --hard HEAD", cwd }, store);
    expect(d.kind).not.toBe("auto-allow");
  });

  it("git --git-dir=x push -f → prompts (global flag bypass)", async () => {
    const store = createStore();
    const d = await decide({ type: "bash", command: "git --git-dir=x push -f", cwd }, store);
    expect(d.kind).not.toBe("auto-allow");
  });

  it("git -c core.editor=vim push --force → prompts (global flag bypass)", async () => {
    const store = createStore();
    const d = await decide({ type: "bash", command: "git -c core.editor=vim push --force", cwd }, store);
    expect(d.kind).not.toBe("auto-allow");
  });

  it("git --no-pager clean -f → prompts (global flag bypass)", async () => {
    const store = createStore();
    const d = await decide({ type: "bash", command: "git --no-pager clean -f", cwd }, store);
    expect(d.kind).not.toBe("auto-allow");
  });

  it("git -C repo clean -fd → prompts (global flag bypass)", async () => {
    const store = createStore();
    const d = await decide({ type: "bash", command: "git -C repo clean -fd", cwd }, store);
    expect(d.kind).not.toBe("auto-allow");
  });

  // Verify existing safe git patterns still work
  it("git status → auto-allows (safe)", async () => {
    const store = createStore();
    const d = await decide({ type: "bash", command: "git status", cwd }, store);
    expect(d.kind).toBe("auto-allow");
  });

  it("git log → auto-allows (safe)", async () => {
    const store = createStore();
    const d = await decide({ type: "bash", command: "git log --oneline", cwd }, store);
    expect(d.kind).toBe("auto-allow");
  });

  it("git -C repo status → auto-allows (safe with global flag)", async () => {
    const store = createStore();
    const d = await decide({ type: "bash", command: "git -C repo status", cwd }, store);
    expect(d.kind).toBe("auto-allow");
  });
});

// ──────────────────────────────────────────────────────────────────────
// 🟠 HIGH: git clean -nfd — combined flag evasion
// ──────────────────────────────────────────────────────────────────────
describe("HIGH: git clean combined flag evasion", () => {
  it("git clean -nfd → prompts (combined flag = force+dirs)", async () => {
    const store = createStore();
    const d = await decide({ type: "bash", command: "git clean -nfd", cwd }, store);
    expect(d.kind).not.toBe("auto-allow");
  });

  it("git clean -ndx → prompts (combined flag = dirs+exclude)", async () => {
    const store = createStore();
    const d = await decide({ type: "bash", command: "git clean -ndx", cwd }, store);
    expect(d.kind).not.toBe("auto-allow");
  });

  it("git clean -fdx → prompts (combined flag = force+dirs+exclude)", async () => {
    const store = createStore();
    const d = await decide({ type: "bash", command: "git clean -fdx", cwd }, store);
    expect(d.kind).not.toBe("auto-allow");
  });

  it("git clean -n → auto-allows (dry-run only, safe)", async () => {
    const store = createStore();
    const d = await decide({ type: "bash", command: "git clean -n", cwd }, store);
    expect(d.kind).toBe("auto-allow");
  });
});

// ──────────────────────────────────────────────────────────────────────
// 🟠 HIGH: find -fprint / -fprintf / -fls — undetected write flags
// ──────────────────────────────────────────────────────────────────────
describe("HIGH: find write-to-file flags", () => {
  it("find -fprint → prompts (write to file)", async () => {
    const store = createStore();
    const d = await decide({ type: "bash", command: "find . -fprint /tmp/output.txt", cwd }, store);
    expect(d.kind).not.toBe("auto-allow");
  });

  it("find -fprintf → prompts (write formatted to file)", async () => {
    const store = createStore();
    const d = await decide({ type: "bash", command: "find . -fprintf /tmp/output.txt '%p\\n'", cwd }, store);
    expect(d.kind).not.toBe("auto-allow");
  });

  it("find -fls → prompts (list to file)", async () => {
    const store = createStore();
    const d = await decide({ type: "bash", command: "find . -fls /tmp/output.txt", cwd }, store);
    expect(d.kind).not.toBe("auto-allow");
  });

  it("find -name → auto-allows (read-only)", async () => {
    const store = createStore();
    const d = await decide({ type: "bash", command: "find . -name '*.txt'", cwd }, store);
    expect(d.kind).toBe("auto-allow");
  });
});

// ──────────────────────────────────────────────────────────────────────
// 🟡 MEDIUM: perl -npi — combined flag evasion
// ──────────────────────────────────────────────────────────────────────
describe("MEDIUM: perl combined flag evasion", () => {
  it("perl -npi → prompts (combined flag = in-place)", async () => {
    const store = createStore();
    const d = await decide({ type: "bash", command: "perl -npi -e 's/a/b/' file.txt", cwd }, store);
    expect(d.kind).not.toBe("auto-allow");
  });

  it("perl -npiw → prompts (combined flag = in-place)", async () => {
    const store = createStore();
    const d = await decide({ type: "bash", command: "perl -npiw -e 's/a/b/' file.txt", cwd }, store);
    expect(d.kind).not.toBe("auto-allow");
  });

  it("perl -pi → prompts (in-place, existing test)", async () => {
    const store = createStore();
    const d = await decide({ type: "bash", command: "perl -pi -e 's/a/b/' file.txt", cwd }, store);
    expect(d.kind).not.toBe("auto-allow");
  });
});

// ──────────────────────────────────────────────────────────────────────
// 🟡 MEDIUM: awk -i — in-place extension missed
// ──────────────────────────────────────────────────────────────────────
describe("MEDIUM: awk in-place", () => {
  it("awk -i inplace → prompts (gawk in-place extension)", async () => {
    const store = createStore();
    const d = await decide({ type: "bash", command: "awk -i inplace '{print}' file.txt", cwd }, store);
    expect(d.kind).not.toBe("auto-allow");
  });

  it("awk '{print}' → prompts (awk not in allowlist, prompts by design)", async () => {
    const store = createStore();
    const d = await decide({ type: "bash", command: "awk '{print}' file.txt", cwd }, store);
    expect(d.kind).toBe("prompt");
  });
});

// ──────────────────────────────────────────────────────────────────────
// 🟡 MEDIUM: truncate + glob wildcard
// ──────────────────────────────────────────────────────────────────────
describe("MEDIUM: truncate wildcard", () => {
  it("truncate -s 0 *.log → prompts (truncate + glob = destructive)", async () => {
    const store = createStore();
    const d = await decide({ type: "bash", command: "truncate -s 0 *.log", cwd }, store);
    expect(d.kind).not.toBe("auto-allow");
  });

  it("truncate -s 0 file.log → prompts (truncate single file)", async () => {
    const store = createStore();
    const d = await decide({ type: "bash", command: "truncate -s 0 file.log", cwd }, store);
    expect(d.kind).not.toBe("auto-allow");
  });
});

// ──────────────────────────────────────────────────────────────────────
// 🟡 MEDIUM: chmod u+s (SUID bit) missed
// ──────────────────────────────────────────────────────────────────────
describe("MEDIUM: chmod SUID", () => {
  it("chmod u+s → prompts (SUID bit)", async () => {
    const store = createStore();
    const d = await decide({ type: "bash", command: "chmod u+s script.sh", cwd }, store);
    expect(d.kind).not.toBe("auto-allow");
  });

  it("chmod 4755 → prompts (SUID numeric)", async () => {
    const store = createStore();
    const d = await decide({ type: "bash", command: "chmod 4755 script.sh", cwd }, store);
    expect(d.kind).not.toBe("auto-allow");
  });

  it("chmod 2755 → prompts (SGID numeric)", async () => {
    const store = createStore();
    const d = await decide({ type: "bash", command: "chmod 2755 script.sh", cwd }, store);
    expect(d.kind).not.toBe("auto-allow");
  });

  it("chmod 755 → prompts (chmod is write command, prompts by design)", async () => {
    const store = createStore();
    const d = await decide({ type: "bash", command: "chmod 755 script.sh", cwd }, store);
    expect(d.kind).toBe("prompt");
  });
});
