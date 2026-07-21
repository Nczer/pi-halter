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

  it("detects uv run --with-editable and trusted script", () => {
    expect(isTrustedScriptCommand("uv run --with-editable ./pkg python ~/.pi/agent/skills/my-script.py", "/tmp")).toBe(true);
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
