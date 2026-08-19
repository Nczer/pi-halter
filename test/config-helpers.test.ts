import { describe, expect, it } from "vitest";
import { isWriteOperation, isTrustedScriptCommand } from "../config";
import { analyzeCommand } from "../analysis/command-analysis";

// ── isWriteOperation (from config) ──

describe("isWriteOperation", () => {
  it("detects always-write commands", () => {
    expect(isWriteOperation("rm", "/some/path")).toBe(true);
    expect(isWriteOperation("mv", "/src /dst")).toBe(true);
    expect(isWriteOperation("cp", "/src /dst")).toBe(true);
    expect(isWriteOperation("chmod", "755 file")).toBe(true);
    expect(isWriteOperation("touch", "file.txt")).toBe(true);
    expect(isWriteOperation("mkdir", "dir")).toBe(true);
  });

  it("detects archive/pkg commands as write", () => {
    expect(isWriteOperation("tar", "-cf archive.tar files/")).toBe(true);
    expect(isWriteOperation("zip", "archive.zip file.txt")).toBe(true);
    expect(isWriteOperation("pip", "install requests")).toBe(true);
    expect(isWriteOperation("npm", "install lodash")).toBe(true);
  });

  it("detects sed -i as write", () => {
    expect(isWriteOperation("sed", "sed -i 's/foo/bar/g' file.txt")).toBe(true);
  });

  it("does not flag sed without -i as write", () => {
    expect(isWriteOperation("sed", "sed 's/foo/bar/g' file.txt")).toBe(false);
    // Regression: unanchored -i pattern matched "-session.ts" inside a path
    expect(isWriteOperation("sed", "sed -n '95,115p' packages/coding-agent/src/core/agent-session.ts")).toBe(false);
  });

  it("detects perl as write (script interpreter = arbitrary code execution)", () => {
    expect(isWriteOperation("perl", "perl -pi -e 's/foo/bar/g' file.txt")).toBe(true);
    expect(isWriteOperation("perl", "perl -e 'print 42'")).toBe(true);
    expect(isWriteOperation("perl", "perl script.pl")).toBe(true);
  });

  it("detects tee as write", () => {
    expect(isWriteOperation("tee", "tee /tmp/out.txt")).toBe(true);
  });

  it("detects shell interpreters as write", () => {
    expect(isWriteOperation("sh", "sh -c 'some command'")).toBe(true);
    expect(isWriteOperation("bash", "bash script.sh")).toBe(true);
  });

  it("returns false for unknown commands", () => {
    expect(isWriteOperation("ls", "ls -la")).toBe(false);
    expect(isWriteOperation("grep", "grep foo bar")).toBe(false);
    expect(isWriteOperation("cat", "cat file.txt")).toBe(false);
  });
});

// ── isTrustedScriptCommand (from config) ──

describe("isTrustedScriptCommand", () => {
  it("detects trusted script in skills dir", () => {
    expect(isTrustedScriptCommand("python3 ~/.pi/agent/skills/my-script.py", "/tmp")).toBe(true);
  });

  it("rejects scripts outside skills dir", () => {
    expect(isTrustedScriptCommand("python3 /tmp/random.py", "/tmp")).toBe(false);
  });

  it("returns false for non-interpreter commands", () => {
    expect(isTrustedScriptCommand("ls -la", "/tmp")).toBe(false);
  });

  it("returns false for single-word commands", () => {
    expect(isTrustedScriptCommand("python3", "/tmp")).toBe(false);
  });

  it("detects uv run with trusted script", () => {
    expect(isTrustedScriptCommand("uv run python ~/.pi/agent/skills/my-script.py", "/tmp")).toBe(true);
  });

  it("detects uv run --with deps and trusted script", () => {
    expect(isTrustedScriptCommand("uv run --with pymupdf python ~/.pi/agent/skills/my-script.py", "/tmp")).toBe(true);
  });

  it("detects uv run --with=deps (equals form) and trusted script", () => {
    expect(isTrustedScriptCommand("uv run --with=pymupdf python ~/.pi/agent/skills/my-script.py", "/tmp")).toBe(true);
  });

  it("rejects uv run --with-editable outside trusted dirs (supply chain defense)", () => {
    expect(isTrustedScriptCommand("uv run --with-editable ./pkg python ~/.pi/agent/skills/my-script.py", "/tmp")).toBe(false);
    expect(isTrustedScriptCommand("uv run --with-editable=/tmp/evil-dir python ~/.pi/agent/skills/my-script.py", "/tmp")).toBe(false);
  });

  it("allows uv run --with-editable inside trusted dirs", () => {
    expect(isTrustedScriptCommand("uv run --with-editable ~/.pi/agent/skills/pkg python ~/.pi/agent/skills/my-script.py", "/tmp")).toBe(true);
    expect(isTrustedScriptCommand("uv run --with-editable=~/.pi/agent/skills/pkg python ~/.pi/agent/skills/my-script.py", "/tmp")).toBe(true);
  });

  it("rejects uv run --with-requirements outside trusted dirs (supply chain defense)", () => {
    expect(isTrustedScriptCommand("uv run --with-requirements /tmp/evil.txt python ~/.pi/agent/skills/my-script.py", "/tmp")).toBe(false);
    expect(isTrustedScriptCommand("uv run --with-requirements=/tmp/evil.txt python ~/.pi/agent/skills/my-script.py", "/tmp")).toBe(false);
  });

  it("allows uv run --with-requirements inside trusted dirs", () => {
    expect(isTrustedScriptCommand("uv run --with-requirements ~/.pi/agent/skills/reqs.txt python ~/.pi/agent/skills/my-script.py", "/tmp")).toBe(true);
  });

  it("rejects uv run with script outside skills dir", () => {
    expect(isTrustedScriptCommand("uv run python /tmp/random.py", "/tmp")).toBe(false);
  });

  it("rejects uv run with non-trusted script even with --with", () => {
    expect(isTrustedScriptCommand("uv run --with pymupdf python /tmp/random.py", "/tmp")).toBe(false);
  });

  it("rejects uv run with unknown --with package", () => {
    expect(isTrustedScriptCommand("uv run --with evil-package python ~/.pi/agent/skills/my-script.py", "/tmp")).toBe(false);
  });

  it("rejects uv run with mixed known/unknown --with packages", () => {
    expect(isTrustedScriptCommand("uv run --with pymupdf,evil-package python ~/.pi/agent/skills/my-script.py", "/tmp")).toBe(false);
  });

  it("allows uv run with comma-separated known packages", () => {
    expect(isTrustedScriptCommand("uv run --with pypdf,reportlab python ~/.pi/agent/skills/my-script.py", "/tmp")).toBe(true);
  });

  it("allows uv run with package extras syntax", () => {
    expect(isTrustedScriptCommand('uv run --with "markitdown[pptx]" python ~/.pi/agent/skills/my-script.py', "/tmp")).toBe(true);
  });

  it("rejects uv run with unknown package in extras form", () => {
    expect(isTrustedScriptCommand('uv run --with "evil[payload]" python ~/.pi/agent/skills/my-script.py', "/tmp")).toBe(false);
  });

  // ── Shell scripts (direct exec + shell interpreter) ──

  it("trusts direct exec of a .sh inside skills dir (~ form)", () => {
    expect(isTrustedScriptCommand("~/.pi/agent/skills/doc-search/scripts/q.sh /corpus query", "/tmp")).toBe(true);
  });

  it("trusts direct exec of a .sh inside skills dir (relative ./ form, cwd in skill dir)", () => {
    expect(isTrustedScriptCommand("./scripts/find-sessions.sh -S /tmp/sock", "~/.pi/agent/skills/tmux")).toBe(true);
  });

  it("trusts direct exec of a .py inside skills dir (shebang exec)", () => {
    expect(isTrustedScriptCommand(`~/.pi/agent/skills/docx/scripts/comment.py file.docx`, "/tmp")).toBe(true);
  });

  it("rejects direct exec of a script outside skills dir", () => {
    expect(isTrustedScriptCommand("/tmp/evil.sh", "/tmp")).toBe(false);
    expect(isTrustedScriptCommand("./scripts/foo.sh", "/tmp/project")).toBe(false);
  });

  it("trusts bash/sh running a script from skills dir", () => {
    expect(isTrustedScriptCommand("bash ~/.pi/agent/skills/doc-search/scripts/q.sh /corpus query", "/tmp")).toBe(true);
    expect(isTrustedScriptCommand("sh ~/.pi/agent/skills/tmux/scripts/wait-for-text.sh -t a:0.0 -p done", "/tmp")).toBe(true);
    expect(isTrustedScriptCommand("bash -u ./scripts/q.sh /corpus query", "~/.pi/agent/skills/doc-search")).toBe(true);
  });

  it("rejects bash/sh running a script outside skills dir", () => {
    expect(isTrustedScriptCommand("bash /tmp/evil.sh", "/tmp")).toBe(false);
    expect(isTrustedScriptCommand("bash ./scripts/foo.sh", "/tmp/project")).toBe(false);
  });

  it("never trusts shell -c/--command forms (command strings are opaque)", () => {
    expect(isTrustedScriptCommand("bash -c '~/skills/doc-search/scripts/q.sh /corpus query'", "/tmp")).toBe(false);
    expect(isTrustedScriptCommand("bash -c '~/skills/doc-search/scripts/q.sh /corpus; rm -rf /'", "/tmp")).toBe(false);
    expect(isTrustedScriptCommand("bash -c '~/skills/doc-search/scripts/q.sh; rm -rf /'", "/tmp")).toBe(false);
    expect(isTrustedScriptCommand("sh --command 'ls'", "/tmp")).toBe(false);
    expect(isTrustedScriptCommand("bash -c 'rm -rf /'", "/tmp")).toBe(false);
  });

  it("rejects bare shell interpreters with no script file", () => {
    expect(isTrustedScriptCommand("bash", "/tmp")).toBe(false);
    expect(isTrustedScriptCommand("bash --norc", "/tmp")).toBe(false);
    expect(isTrustedScriptCommand("bash -e", "/tmp")).toBe(false);
  });
});

// ── Obfuscation false positive defenses (via analyzeCommand) ──

async function isUnsafe(cmd: string): Promise<boolean> {
  const result = await analyzeCommand(cmd, "/home/user/project");
  return result.safety.hasUnsafePattern;
}

describe("detectObfuscation: false positive defenses", () => {
  it("does not flag $PATH as obfuscation", async () => {
    expect(await isUnsafe("echo $PATH")).toBe(false);
  });

  it("does not flag normal env var usage as obfuscation", async () => {
    expect(await isUnsafe("echo $HOME")).toBe(false);
    expect(await isUnsafe("echo $USER")).toBe(false);
  });

  it("still flags variable indirection ${!...}", async () => {
    expect(await isUnsafe("echo ${!P@}")).toBe(true);
  });

  it("flags variable holding command pattern", async () => {
    expect(await isUnsafe("CMD=rm; $CMD file")).toBe(true);
  });
});

// ── Heredoc to interpreter (via analyzeCommand) ──

describe("heredoc to interpreter detection", () => {
  it("detects python3 heredoc as unsafe", async () => {
    expect(await isUnsafe("python3 << 'EOF'\nprint(1)\nEOF")).toBe(true);
  });

  it("detects node heredoc as unsafe", async () => {
    expect(await isUnsafe("node << 'EOF'\nconsole.log(1)\nEOF")).toBe(true);
  });

  it("detects bash heredoc as unsafe", async () => {
    expect(await isUnsafe("bash << 'EOF'\nrm -rf /\nEOF")).toBe(true);
  });

  it("does not flag cat heredoc as unsafe (data, not code)", async () => {
    expect(await isUnsafe("cat << 'EOF'\nrm -rf /\nEOF")).toBe(false);
  });
});
