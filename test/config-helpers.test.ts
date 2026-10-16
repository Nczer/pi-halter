import { describe, expect, it } from "vitest";
import { findNetworkEgress, isWriteOperation, isTrustedScriptCommand, registryRunDeps, uvRunFlags, resolveDepSource } from "../config";
import { tokenizeSegmentQuoted } from "../analysis/tokenizer";
import { dangerousPerlFlags } from "../config/bash-patterns";
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

  // The perl -i cases now prompt for a second reason (script execution), so
  // the anchoring regression is pinned on the flag itself: an unanchored
  // pattern reads "-session.txt" as an in-place flag token.
  it("dangerousPerlFlags stays anchored to real flag tokens", () => {
    expect(dangerousPerlFlags.test("perl -ne 'print' foo-session.txt")).toBe(false);
    expect(dangerousPerlFlags.test("perl -npi -e 's/a/b/' file.txt")).toBe(true);
    expect(dangerousPerlFlags.test("perl -i.bak -pe 's/a/b/' file.txt")).toBe(true);
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

  // The option walk must scan uv's WHOLE leading option region. It used to stop
  // at the first token that was not a dependency flag, so any uv flag placed
  // before --with hid the entire install set: `uv run --frozen --with evil …`
  // read as "no dependencies" and the trusted-script bypass then vouched for an
  // unvetted registry fetch (or an untrusted requirements file).
  it("a uv option before --with does not hide the dependency set (3.31.0 trust defect)", () => {
    for (const pre of ["--frozen", "--quiet", "--isolated", "--no-sync", "--offline", "--no-project"]) {
      expect(isTrustedScriptCommand(`uv run ${pre} --with evil-package python ~/.pi/agent/skills/my-script.py`, "/tmp"), pre).toBe(false);
    }
  });

  it("a uv option before --with-requirements does not hide the source", () => {
    expect(isTrustedScriptCommand("uv run --isolated --with-requirements /tmp/evil.txt python ~/.pi/agent/skills/my-script.py", "/tmp")).toBe(false);
  });

  it("an unknown uv option is assumed to take a value", () => {
    // Skipped as a flag, `pymupdf` would become the runner and the scan would
    // stop before --with; assumed to take a value, the scan stays narrow but
    // sees the dependency set (fail closed either way for trust).
    expect(uvRunFlags(tokenizeSegmentQuoted("uv run --some-new-uv-flag pymupdf --with evil-package python x.py"))!.deps)
      .toEqual([{ flag: "--with", value: "evil-package", opaque: false }]);
  });

  it("uv options after the dependency flags are still walked", () => {
    expect(uvRunFlags(tokenizeSegmentQuoted("uv run --with pandas --frozen -p 3.12 python x.py")))
      .toMatchObject({ uvFlags: ["--frozen"], pythonValues: ["3.12"] }); // -p is a value flag, not a bare option
  });

  it("inline values, -p shorthand and the equals form are walked", () => {
    expect(uvRunFlags(tokenizeSegmentQuoted("uv run -p3.11 --with=pandas python x.py")))
      .toMatchObject({ deps: [{ flag: "--with", value: "pandas" }], pythonValues: ["3.11"] });
    expect(isTrustedScriptCommand("uv run --frozen -p3.11 --with pymupdf python ~/.pi/agent/skills/my-script.py", "/tmp")).toBe(true);
    expect(isTrustedScriptCommand("uv run --frozen --with=evil-package python ~/.pi/agent/skills/my-script.py", "/tmp")).toBe(false);
  });

  it("a dangling dependency flag names nothing at all", () => {
    expect(uvRunFlags(tokenizeSegmentQuoted("uv run --with-requirements"))!.danglingSource).toBe(true);
    expect(isTrustedScriptCommand("uv run --with-requirements python ~/.pi/agent/skills/my-script.py", "/tmp")).toBe(false);
  });

  it("a run-time dependency value is marked opaque, not trusted", () => {
    expect(uvRunFlags(tokenizeSegmentQuoted('uv run --with "$PKG" python x.py'))!.deps[0].opaque).toBe(true);
    expect(uvRunFlags(tokenizeSegmentQuoted("uv run --with pkg*.txt python x.py"))!.deps[0].opaque).toBe(true);
    expect(uvRunFlags(tokenizeSegmentQuoted('uv run --with "pandas>=2.0" python x.py'))!.deps[0]).toEqual({ flag: "--with", value: "pandas>=2.0", opaque: false });
  });

  it("registryRunDeps reports deps hidden behind other uv options", () => {
    expect(registryRunDeps(["uv run --frozen --with pymupdf,evil-package python x.py"])).toEqual([
      { name: "pymupdf", allowlisted: true },
      { name: "evil-package", allowlisted: false },
    ]);
  });

  it("resolveDepSource anchors a relative source to the run-time cwd", () => {
    expect(resolveDepSource("req.txt", "/work")).toBe("/work/req.txt");
    expect(resolveDepSource("./sub/req.txt", "/work")).toBe("/work/sub/req.txt");
    expect(resolveDepSource("/abs/req.txt", "/work")).toBe("/abs/req.txt");
    expect(resolveDepSource("~/req.txt", "/work")).toContain("req.txt");
  });

  // The wrapper walk (2026-10-14) gained the judge CONTENT for wrapped runs;
  // the skills-dir bypass stays exactly as wide as it was. Trust answers
  // "may this script run unreviewed", and that decision was made about the
  // bare interpreter form — not about a trusted script fan-outed over
  // stdin-provided args, nor about a package fetched from the registry.
  it("trust is not transitive through pass-through wrappers or fetch runners", () => {
    expect(isTrustedScriptCommand("timeout 60 python3 ~/.pi/agent/skills/my-script.py", "/tmp")).toBe(false);
    expect(isTrustedScriptCommand("xargs python3 ~/.pi/agent/skills/my-script.py", "/tmp")).toBe(false);
    expect(isTrustedScriptCommand("watch -n 5 python3 ~/.pi/agent/skills/my-script.py", "/tmp")).toBe(false);
    expect(isTrustedScriptCommand("npx tsx ~/.pi/agent/skills/tool.mts", "/tmp")).toBe(false);
    expect(isTrustedScriptCommand("uvx python ~/.pi/agent/skills/my-script.py", "/tmp")).toBe(false);
  });

  it("an env-assignment prefix stays transparent for trust (as elsewhere in the floor)", () => {
    expect(isTrustedScriptCommand("DEBUG=1 python3 ~/.pi/agent/skills/my-script.py", "/tmp")).toBe(true);
  });

  it("allows uv run with comma-separated known packages", () => {
    expect(isTrustedScriptCommand("uv run --with pypdf,reportlab python ~/.pi/agent/skills/my-script.py", "/tmp")).toBe(true);
  });

  it("allows uv run with doc-extract packages (pandas,openpyxl,xlrd)", () => {
    expect(isTrustedScriptCommand("uv run --with pandas,openpyxl,xlrd python3 ~/.pi/agent/skills/doc-extract/scripts/extract.py", "/tmp")).toBe(true);
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

// ── registryRunDeps — the uv --with packages the judge packet names ──

describe("registryRunDeps", () => {
  it("names the --with packages, marked against the operator allowlist", () => {
    expect(registryRunDeps(["uv run --with pandas,openpyxl python3 job.py"])).toEqual([
      { name: "pandas", allowlisted: true },
      { name: "openpyxl", allowlisted: true },
    ]);
    expect(registryRunDeps(["uv run --with pdfplumber python3 job.py"])).toEqual([
      { name: "pdfplumber", allowlisted: false },
    ]);
  });

  it("reads the same forms trust reads (inline value, extras, env prefix, quotes)", () => {
    expect(registryRunDeps(["uv run --with=pymupdf python3 job.py"])).toEqual([
      { name: "pymupdf", allowlisted: true },
    ]);
    expect(registryRunDeps(['uv run --with "markitdown[pptx]" python3 job.py'])).toEqual([
      { name: "markitdown", allowlisted: true },
    ]);
    expect(registryRunDeps(["DEBUG=1 uv run --with requests python3 job.py"])).toEqual([
      { name: "requests", allowlisted: false },
    ]);
    // An unallowlisted dep in one segment still surfaces when another runs a
    // trusted form (the packet names what any segment fetches).
    expect(registryRunDeps([
      "uv run --with pandas python3 a.py",
      "uv run --with evil python3 b.py",
    ])).toEqual([
      { name: "pandas", allowlisted: true },
      { name: "evil", allowlisted: false },
    ]);
  });

  it("names no packages for anything that is not a uv run form", () => {
    expect(registryRunDeps(["python3 job.py"])).toEqual([]);
    expect(registryRunDeps(["uvx pymupdf -c 1"])).toEqual([]);
    expect(registryRunDeps(["npm install pandas"])).toEqual([]);
    // --with-editable/--with-requirements are local PATHS (the floor's path
    // checks own them), not registry fetches — not named here.
    expect(registryRunDeps(["uv run --with-editable ./pkg python3 job.py"])).toEqual([]);
  });

  it("dedupes a package repeated across segments", () => {
    expect(registryRunDeps(["uv run --with pandas python3 a.py", "uv run --with pandas python3 b.py"])).toHaveLength(1);
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

// ── findNetworkEgress (single collector for gate + judge packet) ──

describe("findNetworkEgress", () => {
  it("collects per-segment network first words, deduped in order", () => {
    const { commands } = findNetworkEgress(
      "curl a && wget b && curl c",
      ["curl a", "wget b", "curl c"],
    );
    expect(commands).toEqual(["curl", "wget"]);
  });

  it("matches git remote subcommands only", () => {
    expect(findNetworkEgress("git push origin", ["git push origin"]).commands).toEqual(["git push"]);
    expect(findNetworkEgress("git status", ["git status"]).commands).toEqual([]);
  });

  it("collects all URLs in order, deduped", () => {
    const { urls } = findNetworkEgress(
      "echo https://a.example and https://b.example and https://a.example",
      ["echo x"],
    );
    expect(urls).toEqual(["https://a.example", "https://b.example"]);
  });

  it("finds nothing for offline commands", () => {
    expect(findNetworkEgress("ls -la", ["ls -la"])).toEqual({ commands: [], urls: [] });
  });

  it("annotates explicit go/cargo fetch forms (D8 class) and nothing else", () => {
    expect(findNetworkEgress("cargo fetch", ["cargo fetch"]).commands).toEqual(["cargo fetch"]);
    expect(findNetworkEgress("go mod download", ["go mod download"]).commands).toEqual(["go mod download"]);
    expect(findNetworkEgress("go get x", ["go get x"]).commands).toEqual(["go get"]);
    // non-fetch forms stay clean (D1-judgeable)
    expect(findNetworkEgress("cargo build", ["cargo build"]).commands).toEqual([]);
    expect(findNetworkEgress("go run main.go", ["go run main.go"]).commands).toEqual([]);
  });
});
