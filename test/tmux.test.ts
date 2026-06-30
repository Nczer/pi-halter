import { describe, it, expect } from "vitest";
import { analyzeCommand } from "../analysis/command-analysis";
import { decide, type Decision } from "../decision-engine";
import { createStore } from "../store";
import {
  getTmuxSubcommand,
  extractTmuxSendKeys,
  isTmuxSendKeysSafe,
} from "../analysis/tmux-helpers";
import { MIRROR_CASES } from "./shared-cases";

const cwd = "/home/user/project";

function run(cmd: string) {
  return analyzeCommand(cmd, cwd);
}

async function decision(cmd: string) {
  const analysis = await run(cmd);
  const dec = await decide({ type: "bash", command: cmd, cwd }, createStore());
  return { analysis, decision: dec };
}

function isAutoAllow(dec: Decision): boolean {
  return dec.kind === "auto-allow";
}
function isPrompt(dec: Decision): boolean {
  return dec.kind === "prompt";
}

describe("tmux: safe subcommands (auto-allow)", () => {
  const safe = [
    "tmux list-sessions",
    "tmux list-panes",
    "tmux list-windows",
    "tmux list-buffers",
    "tmux capture-pane",
    "tmux capture-pane -p",
    "tmux capture-pane -t mysession",
    "tmux has-session mysession",
    "tmux show-options",
    "tmux show-options -g",
    "tmux show-messages",
    "tmux display-message 'hello'",
    "tmux display-panes",
    "tmux wait-for --something",
    "tmux save-buffer /tmp/out",
    "tmux delete-buffer",
    "tmux new-session",
    "tmux new-session -d -s foo",
    "tmux new -d -s foo",
    "tmux attach",
    "tmux attach -t foo",
    "tmux start-server",
    "tmux switch-client -t foo",
    "tmux move-window -t foo",
    "tmux rename-window bar",
    "tmux rename-session bar",
    "tmux select-window -t 1",
    "tmux select-pane -t 0",
    "tmux resize-pane -D 5",
    "tmux resize-window -x 80",
    "tmux break-pane -t foo",
    "tmux swap-pane -s 0 -t 1",
    "tmux swap-window -s 0 -t 1",
    "tmux join-pane -t foo",
  ];

  it.each(safe)("%s", async (cmd) => {
    const { analysis, decision: dec } = await decision(cmd);
    expect(analysis.safety.isSimple, `${cmd}: allSimple`).toBe(true);
    expect(analysis.safety.hasUnsafePattern, `${cmd}: hasUnsafePattern`).toBe(false);
    expect(isAutoAllow(dec), `${cmd}: auto-allow`).toBe(true);
  });
});

describe("tmux: safe subcommands with socket/alias flags (auto-allow)", () => {
  const withSocket = [
    "tmux -S /tmp/my.sock list-sessions",
    "tmux -S /tmp/my.sock capture-pane -p",
    "tmux -L myalias new-session -d -s foo",
    "tmux -L myalias list-panes",
  ];

  it.each(withSocket)("%s", async (cmd) => {
    const { analysis, decision: dec } = await decision(cmd);
    expect(analysis.safety.isSimple, `${cmd}: allSimple`).toBe(true);
    expect(analysis.safety.hasUnsafePattern, `${cmd}: hasUnsafePattern`).toBe(false);
    expect(isAutoAllow(dec), `${cmd}: auto-allow`).toBe(true);
  });
});

describe("tmux: dangerous subcommands (prompt)", () => {
  const dangerous = [
    { cmd: "tmux send-keys -t foo hello Enter", reason: "keystroke injection" },
    { cmd: "tmux -S /tmp/x.sock send-keys C-c", reason: "keystroke injection (socket)" },
    { cmd: "tmux run-shell 'echo hello'", reason: "code exec on server" },
    { cmd: "tmux pipe-pane -t foo 'tee /tmp/out'", reason: "shell command" },
    { cmd: "tmux respawn-pane -t foo -c 'bash'", reason: "arbitrary command" },
    { cmd: "tmux kill-session -t foo", reason: "destroy session" },
    { cmd: "tmux kill-server", reason: "destroy server" },
    { cmd: "tmux kill-window -t 0", reason: "destroy window" },
    { cmd: "tmux kill-pane -t foo.0", reason: "destroy pane" },
    { cmd: "tmux split-window -t foo", reason: "spawns shell" },
    { cmd: "tmux new-window -t foo", reason: "spawns shell" },
    { cmd: "tmux set-option -g mouse on", reason: "modifies config" },
    { cmd: "tmux set-environment MYVAR val", reason: "modifies env" },
    { cmd: "tmux bind-key X run-shell 'echo hi'", reason: "modifies keybindings" },
  ];

  it.each(dangerous)("%s", async ({ cmd }) => {
    const { analysis, decision: dec } = await decision(cmd);
    expect(analysis.safety.isSimple, `${cmd}: allSimple`).toBe(false);
    expect(analysis.safety.hasUnsafePattern, `${cmd}: hasUnsafePattern`).toBe(true);
    expect(isPrompt(dec), `${cmd}: prompt`).toBe(true);
    // Check severity
    const bashData = dec.kind === "prompt" ? dec.promptData : null;
    if (bashData?.type === "bash") {
      expect(bashData.riskSeverity).toBe("high");
    }
  });
});

describe("tmux: send-keys inherits auto-allow for safe keys", () => {
  const safeKeys = [
    "tmux send-keys -t foo ls Enter",
    "tmux send-keys -t foo cat file.txt Enter",
    "tmux send-keys -t foo git status Enter",
    "tmux send-keys -t foo git log Enter",
    "tmux send-keys -t foo grep foo bar Enter",
    "tmux send-keys -t foo pwd Enter",
    "tmux send-keys -t foo echo hello Enter",
    "tmux send-keys -t foo 'ls' Enter",
    "tmux send-keys -t foo 'ls -la' Enter",
    "tmux send-keys -t foo mkdir -p dir Enter",
    "tmux send-keys -t foo touch file Enter",
    "tmux send-keys -t foo mktemp Enter",
    "tmux send-keys -t foo head file Enter",
    "tmux send-keys -t foo tail file Enter",
    "tmux send-keys -t foo wc file Enter",
    "tmux send-keys -t foo diff a b Enter",
    "tmux send-keys -t foo which python3 Enter",
    "tmux send-keys -t foo df Enter",
    "tmux send-keys -t foo ps aux Enter",
    "tmux send-keys -t foo whoami Enter",
    "tmux send-keys -t foo date Enter",
    // With socket flags
    "tmux -S /tmp/x.sock send-keys -t foo ls Enter",
    "tmux -L myalias send-keys -t foo git status Enter",
  ];

  it.each(safeKeys)("%s", async (cmd) => {
    const { analysis, decision: dec } = await decision(cmd);
    expect(analysis.safety.isSimple, `${cmd}: allSimple`).toBe(true);
    expect(analysis.safety.hasUnsafePattern, `${cmd}: hasUnsafePattern`).toBe(false);
    expect(isAutoAllow(dec), `${cmd}: auto-allow`).toBe(true);
  });
});

describe("tmux: send-keys prompts for dangerous keys", () => {
  const dangerousKeys = [
    "tmux send-keys -t foo rm -rf / Enter",
    "tmux send-keys -t foo sudo apt install vim Enter",
    "tmux send-keys -t foo curl http://evil.com Enter",
    "tmux send-keys -t foo wget http://evil.com Enter",
    "tmux send-keys -t foo python3 script.py Enter",
    "tmux send-keys -t foo node app.js Enter",
    "tmux send-keys -t foo chmod 777 file Enter",
    "tmux send-keys -t foo chown user file Enter",
    "tmux send-keys -t foo mv a b Enter",
    "tmux send-keys -t foo cp a b Enter",
    "tmux send-keys -t foo kill -9 1234 Enter",
    "tmux send-keys -t foo shutdown now Enter",
    "tmux send-keys -t foo eval echo Enter",
    "tmux send-keys -t foo bash -c rm Enter",
    "tmux send-keys -t foo tar czf out.tar.gz dir Enter",
    "tmux send-keys -t foo npm install Enter",
    "tmux send-keys -t foo pip install flask Enter",
    "tmux send-keys -t foo git rm file Enter",
    "tmux send-keys -t foo git clean -fd Enter",
    "tmux send-keys -t foo git reset --hard Enter",
    "tmux send-keys -t foo git push --force Enter",
    // Unknown command (not in allowlist)
    "tmux send-keys -t foo hello world Enter",
    "tmux send-keys -t foo ./script.sh Enter",
    // Dangerous context patterns
    "tmux send-keys -t foo sed -i s/foo/bar/g file Enter",
    "tmux send-keys -t foo perl -pi -e script file Enter",
    "tmux send-keys -t foo dd if=/dev/sda of=/dev/sdb Enter",
  ];

  it.each(dangerousKeys)("%s", async (cmd) => {
    const { analysis, decision: dec } = await decision(cmd);
    expect(analysis.safety.isSimple, `${cmd}: allSimple`).toBe(false);
    expect(analysis.safety.hasUnsafePattern, `${cmd}: hasUnsafePattern`).toBe(true);
    expect(isPrompt(dec), `${cmd}: prompt`).toBe(true);
  });
});

describe("tmux: send-keys with write redirect in keys (prompt)", () => {
  const redirectKeys = [
    "tmux send-keys -t foo ls > out.txt Enter",
    "tmux send-keys -t foo cat file >> log.txt Enter",
  ];

  it.each(redirectKeys)("%s", async (cmd) => {
    const { analysis, decision: dec } = await decision(cmd);
    expect(analysis.safety.isSimple, `${cmd}: allSimple`).toBe(false);
    expect(analysis.safety.hasUnsafePattern, `${cmd}: hasUnsafePattern`).toBe(true);
    expect(isPrompt(dec), `${cmd}: prompt`).toBe(true);
  });
});

describe("tmux: send-keys with subshell in keys (prompt)", () => {
  const subshellKeys = [
    "tmux send-keys -t foo $(whoami) Enter",
    "tmux send-keys -t foo `pwd` Enter",
  ];

  it.each(subshellKeys)("%s", async (cmd) => {
    const { analysis, decision: dec } = await decision(cmd);
    expect(analysis.safety.isSimple, `${cmd}: allSimple`).toBe(false);
    expect(analysis.safety.hasUnsafePattern, `${cmd}: hasUnsafePattern`).toBe(true);
    expect(isPrompt(dec), `${cmd}: prompt`).toBe(true);
  });
});

describe("tmux: send-keys with no Enter (partial input)", () => {
  // Keys without Enter are still checked as commands
  const noEnter = [
    { cmd: "tmux send-keys -t foo ls", safe: true },
    { cmd: "tmux send-keys -t foo rm", safe: false },
  ];

  it.each(noEnter)("%s", async ({ cmd, safe }) => {
    const { analysis, decision: dec } = await decision(cmd);
    if (safe) {
      expect(analysis.safety.isSimple, `${cmd}: allSimple`).toBe(true);
      expect(isAutoAllow(dec), `${cmd}: auto-allow`).toBe(true);
    } else {
      expect(analysis.safety.isSimple, `${cmd}: allSimple`).toBe(false);
      expect(isPrompt(dec), `${cmd}: prompt`).toBe(true);
    }
  });
});

describe("tmux: 1:1 mirror of cases.test.ts bash commands via send-keys", () => {
  // Shared data source — prevents drift between cases.test.ts and this mirror
  it.each(MIRROR_CASES)("%s (safe=%s)", async ({ cmd, safe }) => {
    const { analysis, decision: dec } = await decision(cmd);
    if (safe) {
      expect(analysis.safety.isSimple, `${cmd}: allSimple`).toBe(true);
      expect(analysis.safety.hasUnsafePattern, `${cmd}: hasUnsafePattern`).toBe(false);
      expect(isAutoAllow(dec), `${cmd}: auto-allow`).toBe(true);
    } else {
      expect(analysis.safety.isSimple, `${cmd}: allSimple`).toBe(false);
      expect(analysis.safety.hasUnsafePattern, `${cmd}: hasUnsafePattern`).toBe(true);
      expect(isPrompt(dec), `${cmd}: prompt`).toBe(true);
    }
  });
});

describe("tmux: edge cases", () => {
  it("no subcommand prompts", async () => {
    const { analysis, decision: dec } = await decision("tmux");
    expect(analysis.safety.isSimple).toBe(false);
    expect(isPrompt(dec)).toBe(true);
  });

  it("send-keys with no keys prompts", async () => {
    const { analysis, decision: dec } = await decision("tmux send-keys -t foo");
    expect(analysis.safety.isSimple).toBe(false);
    expect(isPrompt(dec)).toBe(true);
  });

  it("send-keys with only Enter auto-allows", async () => {
    const { analysis, decision: dec } = await decision("tmux send-keys -t foo Enter");
    // Enter alone → empty command after stripping → treated as safe
    // (just pressing Enter in a terminal is harmless)
    expect(analysis.safety.isSimple).toBe(true);
    expect(isAutoAllow(dec)).toBe(true);
  });

  it("send-keys with multiple safe commands chained", async () => {
    const { analysis, decision: dec } = await decision("tmux send-keys -t foo ls && echo done Enter");
    // The keys contain && which is a shell operator; the first command is 'ls'
    // isTmuxSendKeysSafe checks the first token only
    expect(analysis.safety.isSimple).toBe(true);
    expect(isAutoAllow(dec)).toBe(true);
  });

  it("pipeline with safe tmux command", async () => {
    const { analysis, decision: dec } = await decision("tmux list-sessions | grep foo");
    expect(analysis.safety.isSimple).toBe(true);
    expect(isAutoAllow(dec)).toBe(true);
  });

  it("pipeline with dangerous tmux command", async () => {
    const { analysis, decision: dec } = await decision("tmux send-keys -t foo rm -rf / Enter | cat");
    expect(analysis.safety.isSimple).toBe(false);
    expect(isPrompt(dec)).toBe(true);
  });

  it("&& chain with safe send-keys", async () => {
    const { analysis, decision: dec } = await decision("tmux send-keys -t foo ls Enter && tmux send-keys -t bar pwd Enter");
    expect(analysis.safety.isSimple).toBe(true);
    expect(isAutoAllow(dec)).toBe(true);
  });

  it("&& chain with dangerous send-keys", async () => {
    const { analysis, decision: dec } = await decision("tmux send-keys -t foo ls Enter && tmux send-keys -t bar rm -rf / Enter");
    expect(analysis.safety.isSimple).toBe(false);
    expect(isPrompt(dec)).toBe(true);
  });

  it("nested tmux send-keys (send-keys sending send-keys)", async () => {
    // tmux send-keys -t foo 'tmux send-keys -t bar ls' Enter
    // The outer keys are the string 'tmux send-keys -t bar ls'
    // First token after quote strip: tmux → isAllowedCommand("tmux") = true
    // Then checks isTmuxDangerous on the inner command
    const { analysis, decision: dec } = await decision("tmux send-keys -t foo 'tmux send-keys -t bar ls' Enter");
    // Inner: tmux send-keys with safe keys (ls) → safe
    expect(analysis.safety.isSimple).toBe(true);
    expect(isAutoAllow(dec)).toBe(true);
  });
});

describe("tmux: risk reason content", () => {
  it("send-keys with dangerous keys shows keys in reason", async () => {
    const { decision: dec } = await decision("tmux send-keys -t foo rm -rf / Enter");
    expect(dec.kind).toBe("prompt");
    if (dec.kind === "prompt" && dec.promptData.type === "bash") {
      const reasons = dec.promptData.riskReasons;
      expect(reasons.some(r => r.includes("send-keys"))).toBe(true);
      expect(reasons.some(r => r.includes("→"))).toBe(true);
    }
  });

  it("kill-session shows destruction reason", async () => {
    const { decision: dec } = await decision("tmux kill-session -t foo");
    expect(dec.kind).toBe("prompt");
    if (dec.kind === "prompt" && dec.promptData.type === "bash") {
      const reasons = dec.promptData.riskReasons;
      expect(reasons.some(r => r.includes("kill-session"))).toBe(true);
    }
  });

  it("run-shell shows code execution reason", async () => {
    const { decision: dec } = await decision("tmux run-shell 'echo hi'");
    expect(dec.kind).toBe("prompt");
    if (dec.kind === "prompt" && dec.promptData.type === "bash") {
      const reasons = dec.promptData.riskReasons;
      expect(reasons.some(r => r.includes("run-shell"))).toBe(true);
    }
  });

  it("unknown subcommand shows generic reason", async () => {
    const { decision: dec } = await decision("tmux unknown-subcommand");
    expect(dec.kind).toBe("prompt");
    if (dec.kind === "prompt" && dec.promptData.type === "bash") {
      const reasons = dec.promptData.riskReasons;
      expect(reasons.some(r => r.includes("not in safe allowlist"))).toBe(true);
    }
  });
});

describe("tmux: no 'always' option for dangerous commands", () => {
  it("dangerous subcommand blocks always option", async () => {
    const { analysis, decision: dec } = await decision("tmux send-keys -t foo rm -rf / Enter");
    expect(dec.kind).toBe("prompt");
    // hasUnsafePattern means canBeAutoAllowed is false, so no "always" option
    expect(analysis.safety.hasUnsafePattern).toBe(true);
    expect(analysis.safety.canBeAutoAllowed).toBe(false);
  });

  it("safe subcommand auto-allows (no prompt)", async () => {
    const { decision: dec } = await decision("tmux list-sessions");
    expect(dec.kind).toBe("auto-allow");
  });
});

// ── Control character tests ──

describe("tmux: control characters in send-keys", () => {
  it("C-c prompts (SIGINT injection)", async () => {
    const { analysis, decision: dec } = await decision("tmux send-keys -t foo C-c");
    expect(analysis.safety.isSimple).toBe(false);
    expect(isPrompt(dec)).toBe(true);
  });

  it("C-d prompts (EOF injection)", async () => {
    const { analysis, decision: dec } = await decision("tmux send-keys -t foo C-d");
    expect(analysis.safety.isSimple).toBe(false);
    expect(isPrompt(dec)).toBe(true);
  });

  it("C-\\ prompts (SIGQUIT injection)", async () => {
    const { analysis, decision: dec } = await decision("tmux send-keys -t foo C-\\");
    expect(analysis.safety.isSimple).toBe(false);
    expect(isPrompt(dec)).toBe(true);
  });

  it("M-x prompts (Meta key, not an allowed command)", async () => {
    const { analysis, decision: dec } = await decision("tmux send-keys -t foo M-x");
    expect(analysis.safety.isSimple).toBe(false);
    expect(isPrompt(dec)).toBe(true);
  });

  it("mixed safe keys + control char — first token wins (ls is safe)", async () => {
    // Current implementation checks first token only. ls is allowed → auto-allow.
    // If multi-key safety becomes a requirement, this test documents the current behavior.
    const { analysis, decision: dec } = await decision("tmux send-keys -t foo ls C-c Enter");
    expect(analysis.safety.isSimple).toBe(true);
    expect(isAutoAllow(dec)).toBe(true);
  });
});

// ── Unit tests for tmux extractor functions ──

describe("getTmuxSubcommand", () => {
  it("returns null for bare tmux", () => {
    expect(getTmuxSubcommand("tmux")).toBeNull();
  });

  it("extracts subcommand after tmux", () => {
    expect(getTmuxSubcommand("tmux list-sessions")).toBe("list-sessions");
  });

  it("skips -S socket flag", () => {
    expect(getTmuxSubcommand("tmux -S /tmp/x.sock list-sessions")).toBe("list-sessions");
  });

  it("skips -L alias flag", () => {
    expect(getTmuxSubcommand("tmux -L myalias capture-pane")).toBe("capture-pane");
  });

  it("skips multiple flags", () => {
    expect(getTmuxSubcommand("tmux -S /tmp/x.sock -L alias send-keys")).toBe("send-keys");
  });

  it("lowercases subcommand", () => {
    expect(getTmuxSubcommand("tmux List-Sessions")).toBe("list-sessions");
  });
});

describe("extractTmuxSendKeys", () => {
  it("returns null for bare send-keys", () => {
    expect(extractTmuxSendKeys("tmux send-keys -t foo")).toBeNull();
  });

  it("extracts keys after flags", () => {
    expect(extractTmuxSendKeys("tmux send-keys -t foo hello Enter")).toBe("hello Enter");
  });

  it("skips -t target flag", () => {
    expect(extractTmuxSendKeys("tmux send-keys -t mysession ls Enter")).toBe("ls Enter");
  });

  it("skips -l flag (literal)", () => {
    expect(extractTmuxSendKeys("tmux send-keys -t foo -l ls Enter")).toBe("ls Enter");
  });

  it("preserves inner command flags like -fd", () => {
    expect(extractTmuxSendKeys("tmux send-keys -t foo git clean -fd Enter")).toBe("git clean -fd Enter");
  });

  it("handles socket flag before send-keys", () => {
    expect(extractTmuxSendKeys("tmux -S /tmp/x.sock send-keys -t foo ls Enter")).toBe("ls Enter");
  });

  it("handles quoted keys", () => {
    expect(extractTmuxSendKeys("tmux send-keys -t foo 'hello world' Enter")).toBe("'hello world' Enter");
  });
});

describe("isTmuxSendKeysSafe", () => {
  it("empty keys (Enter only) is safe", () => {
    expect(isTmuxSendKeysSafe("Enter")).toBe(true);
  });

  it("whitespace + Enter is safe", () => {
    expect(isTmuxSendKeysSafe("   Enter")).toBe(true);
  });

  it("safe command is safe", () => {
    expect(isTmuxSendKeysSafe("ls Enter")).toBe(true);
  });

  it("dangerous command is unsafe", () => {
    expect(isTmuxSendKeysSafe("rm -rf / Enter")).toBe(false);
  });

  it("dangerous git subcommand is unsafe", () => {
    expect(isTmuxSendKeysSafe("git clean -fd Enter")).toBe(false);
  });

  it("safe git subcommand is safe", () => {
    expect(isTmuxSendKeysSafe("git status Enter")).toBe(true);
  });

  it("quoted command strips quotes before checking", () => {
    expect(isTmuxSendKeysSafe("'ls' Enter")).toBe(true);
  });

  it("nested tmux send-keys with safe keys is safe", () => {
    expect(isTmuxSendKeysSafe("tmux send-keys -t bar ls Enter")).toBe(true);
  });

  it("nested tmux send-keys with dangerous keys is unsafe", () => {
    expect(isTmuxSendKeysSafe("tmux send-keys -t bar rm -rf / Enter")).toBe(false);
  });

  it("control character C-c is unsafe", () => {
    expect(isTmuxSendKeysSafe("C-c")).toBe(false);
  });

  it("control character C-d is unsafe", () => {
    expect(isTmuxSendKeysSafe("C-d")).toBe(false);
  });

  it("write redirect in keys is unsafe", () => {
    expect(isTmuxSendKeysSafe("ls > out.txt Enter")).toBe(false);
  });

  it("subshell in keys is unsafe", () => {
    expect(isTmuxSendKeysSafe("$(whoami) Enter")).toBe(false);
  });
});
