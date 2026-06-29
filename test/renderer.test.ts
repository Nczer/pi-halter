import { describe, it, expect } from "vitest";
import {
  parseTmuxFlags,
  formatTmuxSegment,
  formatSegment,
  formatBashCommand,
  splitIntoSegments,
  splitOnPipe,
} from "../renderers/tmux";

// ── parseTmuxFlags ──

describe("parseTmuxFlags: subcommand extraction", () => {
  it("extracts subcommand after tmux", () => {
    const r = parseTmuxFlags("tmux list-sessions");
    expect(r.subcommand).toBe("list-sessions");
  });

  it("skips -S socket flag", () => {
    const r = parseTmuxFlags("tmux -S /tmp/pi.sock list-sessions");
    expect(r.subcommand).toBe("list-sessions");
  });

  it("skips -L alias flag", () => {
    const r = parseTmuxFlags("tmux -L myalias capture-pane");
    expect(r.subcommand).toBe("capture-pane");
  });

  it("skips -f config flag", () => {
    const r = parseTmuxFlags("tmux -f /dev/null new-session");
    expect(r.subcommand).toBe("new-session");
  });

  it("handles new alias", () => {
    const r = parseTmuxFlags("tmux new -d -s foo");
    expect(r.subcommand).toBe("new-session");
  });

  it("returns null for bare tmux", () => {
    const r = parseTmuxFlags("tmux");
    expect(r.subcommand).toBeNull();
  });

  it("returns null for non-tmux command", () => {
    const r = parseTmuxFlags("mkdir -p /tmp/foo");
    expect(r.subcommand).toBeNull();
  });
});

describe("parseTmuxFlags: boilerplate stripping", () => {
  it("strips -f /dev/null", () => {
    const r = parseTmuxFlags("tmux -f /dev/null list-sessions");
    expect(r.flags).not.toContainEqual(expect.objectContaining({ short: "-f" }));
  });

  it("strips -S socket", () => {
    const r = parseTmuxFlags("tmux -S /tmp/pi.sock list-sessions");
    expect(r.flags).not.toContainEqual(expect.objectContaining({ short: "-S" }));
  });

  it("strips both boilerplate flags", () => {
    const r = parseTmuxFlags("tmux -f /dev/null -S /tmp/pi.sock send-keys -t foo ls Enter");
    expect(r.subcommand).toBe("send-keys");
    expect(r.flags).not.toContainEqual(expect.objectContaining({ short: "-f" }));
    expect(r.flags).not.toContainEqual(expect.objectContaining({ short: "-S" }));
  });

  it("keeps -S when used as capture-pane start line", () => {
    // capture-pane -S -200 means start from line -200
    const r = parseTmuxFlags("tmux capture-pane -p -S -200");
    const startFlag = r.flags.find(f => f.name === "start");
    expect(startFlag).toBeDefined();
    expect(startFlag?.value).toBe("-200");
  });
});

describe("parseTmuxFlags: flag mapping", () => {
  it("maps -t to target", () => {
    const r = parseTmuxFlags("tmux send-keys -t mysession:0.0 ls Enter");
    const flag = r.flags.find(f => f.name === "target");
    expect(flag?.value).toBe("mysession:0.0");
  });

  it("maps -d to detached (boolean)", () => {
    const r = parseTmuxFlags("tmux new-session -d -s foo");
    const flag = r.flags.find(f => f.name === "detached");
    expect(flag).toBeDefined();
    expect(flag?.value).toBeNull(); // boolean flag, no value
  });

  it("maps -s to session", () => {
    const r = parseTmuxFlags("tmux new-session -d -s foo");
    const flag = r.flags.find(f => f.name === "session");
    expect(flag?.value).toBe("foo");
  });

  it("maps -n to window", () => {
    const r = parseTmuxFlags("tmux new-session -d -s foo -n shell");
    const flag = r.flags.find(f => f.name === "window");
    expect(flag?.value).toBe("shell");
  });

  it("maps -p to print for capture-pane", () => {
    const r = parseTmuxFlags("tmux capture-pane -p -t foo");
    const flag = r.flags.find(f => f.name === "print");
    expect(flag).toBeDefined();
  });

  it("maps -J to join for capture-pane", () => {
    const r = parseTmuxFlags("tmux capture-pane -p -J -t foo");
    const flag = r.flags.find(f => f.name === "join");
    expect(flag).toBeDefined();
  });

  it("maps -l to literal for send-keys", () => {
    const r = parseTmuxFlags("tmux send-keys -t foo -l -- 'code' Enter");
    const flag = r.flags.find(f => f.name === "literal");
    expect(flag).toBeDefined();
  });

  it("maps -F to format", () => {
    const r = parseTmuxFlags("tmux list-panes -t foo -F '#{pane_index}'");
    const flag = r.flags.find(f => f.name === "format");
    expect(flag?.value).toBe("'#{pane_index}'");
  });

  it("keeps unmapped flags as raw", () => {
    const r = parseTmuxFlags("tmux resize-pane -D 5 -t foo");
    const raw = r.flags.find(f => f.raw === "-D 5");
    expect(raw).toBeDefined();
  });
});

describe("parseTmuxFlags: send-keys keys extraction", () => {
  it("extracts keys from send-keys", () => {
    const r = parseTmuxFlags("tmux send-keys -t foo ls Enter");
    expect(r.keys).toBe("ls Enter");
  });

  it("extracts keys with -l flag", () => {
    const r = parseTmuxFlags("tmux send-keys -t foo -l -- 'python3 -q'");
    expect(r.keys).toBe("'python3 -q'");
  });

  it("extracts keys with Enter sent separately", () => {
    const r = parseTmuxFlags("tmux send-keys -t foo Enter");
    expect(r.keys).toBe("Enter");
  });

  it("returns null keys for non-send-keys", () => {
    const r = parseTmuxFlags("tmux list-sessions");
    expect(r.keys).toBeNull();
  });
});

// ── formatTmuxSegment ──

describe("formatTmuxSegment: basic commands", () => {
  it("formats list-sessions", () => {
    expect(formatTmuxSegment("tmux -f /dev/null -S /tmp/pi.sock list-sessions")).toBe(
      "tmux list-sessions",
    );
  });

  it("formats capture-pane with named params", () => {
    expect(formatTmuxSegment("tmux -f /dev/null -S $SOCKET capture-pane -p -J -t target -S -200")).toBe(
      "tmux capture-pane  print join target=target start=-200",
    );
  });

  it("formats new-session with detached and session", () => {
    expect(formatTmuxSegment("tmux -f /dev/null -S $SOCKET new -d -s pi-shell -n shell")).toBe(
      "tmux new-session  detached session=pi-shell window=shell",
    );
  });

  it("formats send-keys with arrow", () => {
    expect(formatTmuxSegment("tmux -f /dev/null -S $SOCKET send-keys -t pi-shell:0.0 -- 'python3 -q' Enter")).toBe(
      "tmux send-keys  target=pi-shell:0.0 → 'python3 -q' Enter",
    );
  });

  it("formats send-keys with -l flag", () => {
    expect(formatTmuxSegment("tmux send-keys -t foo -l -- 'code'")).toBe(
      "tmux send-keys  target=foo literal → 'code'",
    );
  });

  it("formats list-panes with format", () => {
    expect(formatTmuxSegment("tmux list-panes -t foo -F '#{window_index}.#{pane_index}'")).toBe(
      "tmux list-panes  target=foo format='#{window_index}.#{pane_index}'",
    );
  });

  it("formats kill-session", () => {
    expect(formatTmuxSegment("tmux kill-session -t foo")).toBe(
      "tmux kill-session  target=foo",
    );
  });

  it("formats bare tmux (no subcommand)", () => {
    expect(formatTmuxSegment("tmux")).toBe("tmux");
  });
});

describe("formatTmuxSegment: boilerplate stripped", () => {
  it("removes -f /dev/null from output", () => {
    const result = formatTmuxSegment("tmux -f /dev/null -S /tmp/pi.sock send-keys -t foo ls Enter");
    expect(result).not.toContain("-f");
    expect(result).not.toContain("/dev/null");
    expect(result).not.toContain("-S");
    expect(result).not.toContain("/tmp/pi.sock");
  });

  it("removes -L alias from output", () => {
    const result = formatTmuxSegment("tmux -L myalias list-sessions");
    expect(result).not.toContain("-L");
    expect(result).not.toContain("myalias");
  });
});

// ── formatSegment ──

describe("formatSegment: tmux vs non-tmux", () => {
  it("formats tmux commands with structure", () => {
    expect(formatSegment("tmux -f /dev/null -S $SOCKET new -d -s foo")).toBe(
      "tmux new-session  detached session=foo",
    );
  });

  it("passes through non-tmux commands as-is (trimmed)", () => {
    expect(formatSegment("mkdir -p /tmp/foo")).toBe("mkdir -p /tmp/foo");
  });

  it("passes through variable assignments as-is", () => {
    expect(formatSegment("SOCKET_DIR=${TMPDIR:-/tmp}/pi-tmux-sockets")).toBe(
      "SOCKET_DIR=${TMPDIR:-/tmp}/pi-tmux-sockets",
    );
  });

  it("passes through variable assignment with subshell", () => {
    expect(formatSegment("TARGET=$(tmux list-panes -t foo -F '#{pane_index}' | head -1)").trim()).toMatch(
      /TARGET=\$\(tmux list-panes/,
    );
  });

  it("trims whitespace", () => {
    expect(formatSegment("  sleep 2  ")).toBe("sleep 2");
  });
});

// ── formatBashCommand ──

describe("formatBashCommand: single command", () => {
  it("formats a single tmux command", () => {
    const result = formatBashCommand("tmux -f /dev/null -S $SOCKET list-sessions");
    expect(result).toBe("$ tmux list-sessions");
  });

  it("returns raw command for single non-tmux command", () => {
    const result = formatBashCommand("mkdir -p /tmp/foo");
    expect(result).toBe("mkdir -p /tmp/foo");
  });
});

describe("formatBashCommand: chained commands", () => {
  it("formats a chain of mixed commands", () => {
    const cmd = "SOCKET_DIR=${TMPDIR:-/tmp}/pi-tmux-sockets; mkdir -p \"$SOCKET_DIR\"; tmux -f /dev/null -S $SOCKET new -d -s pi-shell";
    const result = formatBashCommand(cmd);
    expect(result).toContain("bash");
    expect(result).toContain("3"); // segment count
    expect(result).toContain("SOCKET_DIR=${TMPDIR:-/tmp}/pi-tmux-sockets");
    expect(result).toContain("mkdir -p");
    expect(result).toContain("tmux new-session");
  });

  it("formats && chain", () => {
    const cmd = "tmux -f /dev/null -S $SOCKET new -d -s foo && tmux -f /dev/null -S $SOCKET send-keys -t foo ls Enter";
    const result = formatBashCommand(cmd);
    expect(result).toContain("2"); // segment count
    expect(result).toContain("tmux new-session");
    expect(result).toContain("tmux send-keys");
  });

  it("formats || chain", () => {
    const cmd = "tmux has-session foo || tmux new -d -s foo";
    const result = formatBashCommand(cmd);
    expect(result).toContain("2");
    expect(result).toContain("tmux has-session");
    expect(result).toContain("tmux new-session");
  });

  it("keeps raw command for non-tmux chains", () => {
    const cmd = "ls -la && cat file.txt";
    const result = formatBashCommand(cmd);
    expect(result).toBe("ls -la && cat file.txt");
  });
});

describe("formatBashCommand: pipe within segment", () => {
  it("formats pipe chain on one line", () => {
    const cmd = "tmux list-panes -t foo -F '#{pane_index}' | head -1";
    const result = formatBashCommand(cmd);
    expect(result).toBe("$ tmux list-panes  target=foo format='#{pane_index}' | head -1");
  });
});

describe("formatBashCommand: edge cases", () => {
  it("handles empty command", () => {
    expect(formatBashCommand("")).toBe("");
  });

  it("handles command with only whitespace", () => {
    expect(formatBashCommand("   ")).toBe("");
  });

  it("preserves unicode in commands", () => {
    const result = formatBashCommand("tmux display-message 'こんにちは'");
    expect(result).toContain("こんにちは");
  });

  it("splits on semicolon without eating next character", () => {
    const cmd = "tmux list-sessions; echo done; tmux new -d -s foo";
    const result = formatBashCommand(cmd);
    // Each segment should start correctly — semicolon should not eat first char
    expect(result).toContain("tmux list-sessions");
    expect(result).toContain("2. echo done");
    expect(result).toContain("3. tmux new-session");
    // If ; ate the next char, segments would be "cho done" and "mux new"
    expect(result).not.toContain("2. cho");
    expect(result).not.toContain("3. mux");
  });

  it("marks non-allowed segments with warning emoji", () => {
    const cmd = "tmux new -d -s foo; tmux send-keys -t foo rm -rf / Enter";
    const result = formatBashCommand(cmd, new Set([1]));
    expect(result).toContain("1.");
    expect(result).toContain("2.");
    const lines = result.split("\n");
    const line2 = lines.find(l => l.includes("2."));
    expect(line2).toContain("⚠");
    const line1 = lines.find(l => l.includes("1."));
    expect(line1).not.toContain("⚠");
  });
});

describe("formatBashCommand: full tmux skill example", () => {
  it("renders the quickstart pattern", () => {
    const cmd = [
      "SOCKET_DIR=${TMPDIR:-/tmp}/pi-tmux-sockets",
      "mkdir -p \"$SOCKET_DIR\"",
      "SOCKET=\"$SOCKET_DIR/pi.sock\"",
      "tmux -f /dev/null -S \"$SOCKET\" new -d -s pi-shell -n shell",
    ].join("; ");
    const result = formatBashCommand(cmd);

    expect(result).toContain("bash");
    expect(result).toContain("4"); // 4 segments
    // Segment 1: variable assignment
    expect(result).toContain("1.");
    expect(result).toContain("SOCKET_DIR=");
    // Segment 2: mkdir
    expect(result).toContain("2.");
    expect(result).toContain("mkdir -p");
    // Segment 3: variable assignment
    expect(result).toContain("3.");
    expect(result).toContain("SOCKET=");
    // Segment 4: tmux new-session
    expect(result).toContain("4.");
    expect(result).toContain("tmux new-session");
    expect(result).toContain("detached");
    expect(result).toContain("session=pi-shell");
    expect(result).toContain("window=shell");
    // No boilerplate
    expect(result).not.toContain("-f /dev/null");
    expect(result).not.toContain("-S \"");
  });
});

// ── splitIntoSegments ──

describe("splitIntoSegments", () => {
  it("splits on &&", () => {
    expect(splitIntoSegments("ls && echo hi")).toEqual(["ls", "echo hi"]);
  });

  it("splits on ||", () => {
    expect(splitIntoSegments("false || echo hi")).toEqual(["false", "echo hi"]);
  });

  it("splits on ;", () => {
    expect(splitIntoSegments("cd /tmp; ls")).toEqual(["cd /tmp", "ls"]);
  });

  it("does not split on ;= (edge case)", () => {
    // Semicolon followed by = should not be treated as a separator
    expect(splitIntoSegments("echo a;=b; echo c")).toEqual(["echo a;=b", "echo c"]);
  });

  it("does not split pipes — keeps within segment", () => {
    expect(splitIntoSegments("cat file | grep foo")).toEqual(["cat file | grep foo"]);
  });

  it("handles empty input", () => {
    expect(splitIntoSegments("")).toEqual([]);
  });

  it("handles single command with no operators", () => {
    expect(splitIntoSegments("ls -la")).toEqual(["ls -la"]);
  });

  it("respects single quotes around operators", () => {
    expect(splitIntoSegments("echo 'foo && bar'")).toEqual(["echo 'foo && bar'"]);
  });

  it("respects double quotes around operators", () => {
    expect(splitIntoSegments('echo "foo; bar"')).toEqual(['echo "foo; bar"']);
  });

  it("splits mixed chain with different operators", () => {
    expect(splitIntoSegments("cd /tmp && ls; echo done")).toEqual(["cd /tmp", "ls", "echo done"]);
  });
});

// ── splitOnPipe ──

describe("splitOnPipe", () => {
  it("splits on single pipe", () => {
    expect(splitOnPipe("ls | grep foo")).toEqual(["ls", "grep foo"]);
  });

  it("does not split on double pipe (||)", () => {
    expect(splitOnPipe("false || echo hi")).toEqual(["false || echo hi"]);
  });

  it("handles multiple pipes", () => {
    expect(splitOnPipe("a | b | c")).toEqual(["a", "b", "c"]);
  });

  it("respects single quotes around pipe", () => {
    expect(splitOnPipe("echo 'a | b'")).toEqual(["echo 'a | b'"]);
  });

  it("respects double quotes around pipe", () => {
    expect(splitOnPipe('echo "a | b"')).toEqual(['echo "a | b"']);
  });

  it("handles empty input", () => {
    expect(splitOnPipe("")).toEqual([]);
  });

  it("handles single token with no pipe", () => {
    expect(splitOnPipe("ls -la")).toEqual(["ls -la"]);
  });

  it("trims whitespace from pipe parts", () => {
    expect(splitOnPipe("a  |  b")).toEqual(["a", "b"]);
  });
});

describe("formatBashCommand: pre-parsed segments", () => {
  it("uses pre-parsed segments when provided", () => {
    const cmd = "mkdir -p /tmp/foo; tmux list-sessions";
    const segments = ["mkdir -p /tmp/foo", "tmux list-sessions"];
    const result = formatBashCommand(cmd, new Set(), segments);
    expect(result).toContain("bash (2 segments)");
    expect(result).toContain("1. mkdir -p /tmp/foo");
    expect(result).toContain("2. tmux list-sessions");
  });

  it("falls back to internal split when segments not provided", () => {
    const cmd = "mkdir -p /tmp/foo; tmux list-sessions";
    const result = formatBashCommand(cmd);
    expect(result).toContain("bash (2 segments)");
    expect(result).toContain("tmux list-sessions");
  });

  it("respects non-allowed indices with pre-parsed segments", () => {
    const cmd = "ls; tmux new -d -s foo";
    const segments = ["ls", "tmux new -d -s foo"];
    const result = formatBashCommand(cmd, new Set([1]), segments);
    expect(result).toContain("1. ls");
    const lines = result.split("\n");
    const line2 = lines.find(l => l.includes("2."));
    expect(line2).toContain("⚠");
  });
});
