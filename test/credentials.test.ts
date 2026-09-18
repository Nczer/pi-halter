import path from "node:path";
import os from "node:os";
import fs from "node:fs";
import { describe, expect, it, beforeAll, afterAll, afterEach, vi } from "vitest";
import {
  checkCommandForCredentialPaths,
  checkBareRelativeTokens,
  stripHeredocBodies,
  stripShellComments,
  GLOB_UNVERIFIED_PREFIX,
  isGlobUnverified,
  globUnverifiedToken,
} from "../analysis/credentials";
import { tokenizeSegmentQuoted, type QuotedToken } from "../analysis/tokenizer";
import { createContractCwd, removeContractCwd } from "./hermetic-cwd";

const tmpdir = os.tmpdir();
let cwd: string;

beforeAll(() => {
  cwd = createContractCwd();
});
afterAll(() => removeContractCwd(cwd));

describe("checkCommandForCredentialPaths", () => {
  const flaggedCases: [string, string][] = [
    ["cat .ssh/id_rsa", ".ssh"],
    ["cat .gnupg/private.key", ".gnupg"],
    ["cat .gpg/key", ".gpg"],
    ["cat .vault/token", ".vault"],
    ["cat .secret", ".secret"],
    ["cat .secrets/db", ".secrets"],
    ["ls .ssh", ".ssh"],
    ["cat '.ssh/id_rsa'", ".ssh"],
    ['cat ".ssh/id_rsa"', ".ssh"],
    // Shell operators stuck to the token (whitespace-only tokenization):
    ["cat .ssh; ls", ".ssh"],
    ["cat .ssh&& ls", ".ssh"],
    ["cat .ssh|grep id", ".ssh"],
    ["cat .ssh>/tmp/copy", ".ssh"],
    ["echo $(cat .ssh)", ".ssh"],
    // Env-var indirection: the assignment value is the credential path.
    ["export X=.ssh && ls $X", ".ssh"],
    ["X=.ssh; ls $X", ".ssh"],
    ["declare X=.ssh", ".ssh"],
    ["export X=$HOME/.ssh && ls $X", ".ssh"],
  ];
  for (const [cmd, rule] of flaggedCases) {
    it(`flags credential dir: ${cmd}`, () => {
      const result = checkCommandForCredentialPaths(cmd, cwd);
      expect(result).toBe(rule);
    });
  }

  const warnCases: [string, string][] = [
    ["cat .env", ".env"],
    ["cat .aws/credentials", ".aws"],
    ["cat .env.production", ".env.*"],
    ["cat .npmrc", ".npmrc"],
    ["cat .netrc", ".netrc"],
    ["cat .pypirc", ".pypirc"],
    ["cat .docker/config.json", ".docker/config.json"],
    ["grep PASS .env", ".env"],
    ["cat '.env'", ".env"],
    ['cat ".env"', ".env"],
    ["cat .env|grep x", ".env"],
    ["export X=.env && cat $X", ".env"],
  ];
  for (const [cmd, rule] of warnCases) {
    it(`flags credential file: ${cmd}`, () => {
      const result = checkCommandForCredentialPaths(cmd, cwd);
      expect(result).toBe(rule);
    });
  }

  const safeCases = [
    "cat regular.txt",
    "ls -la",
    "grep -r pattern .",
    "echo hello",
    "cat src/index.ts",
    "git status",
    "cat .gitignore",
    "cat .git/HEAD",
    // Harmless env assignments (non-credential values) must not flag:
    "export FOO=bar && ls",
    "FOO=/tmp/data; ls",
    "export PATH=$PATH:/usr/local/bin",
  ];
  for (const cmd of safeCases) {
    it(`safe: ${cmd}`, () => {
      const result = checkCommandForCredentialPaths(cmd, cwd);
      expect(result).toBeNull();
      expect(result).toBeNull();
    });
  }

  // Heredoc bodies are stdin DATA — credential names in the body are not
  // path operands and must not false-positive (FP regression: the agent's
  // own probe commands writing test files got blocked on this).
  it("heredoc body with denied credential name is data (no match)", () => {
    const result = checkCommandForCredentialPaths("cat > out.txt <<'EOF'\n.ssh/id_rsa\nEOF", cwd);
    expect(result).toBeNull();
    expect(result).toBeNull();
  });

  it("heredoc body with warned credential name is data (no match)", () => {
    const result = checkCommandForCredentialPaths("wc -l x <<EOF\n.env\nEOF", cwd);
    expect(result).toBeNull();
    expect(result).toBeNull();
  });

  it("credential in the command line beside a heredoc still matches", () => {
    const result = checkCommandForCredentialPaths("cat .ssh/id_rsa <<EOF\nbody\nEOF", cwd);
    expect(result).toBe(".ssh");
  });

  it("redirect target credential still matches with heredoc present", () => {
    const result = checkCommandForCredentialPaths("cat <<EOF > .ssh/id_rsa\nbody\nEOF", cwd);
    expect(result).toBe(".ssh");
  });

  it("quoted pseudo-heredoc mid-line does not strip following lines", () => {
    const result = checkCommandForCredentialPaths('echo "fake <<EOF text" && cat .env', cwd);
    expect(result).toBe(".env");
  });

  it("unterminated heredoc stays fail-closed (body still scanned)", () => {
    const result = checkCommandForCredentialPaths("cat <<EOF\n.ssh/id_rsa", cwd);
    expect(result).toBe(".ssh");
  });

  it("multiple heredocs on one line: bodies until both terminators", () => {
    const result = checkCommandForCredentialPaths("cmd <<A <<B\na-body.ssh\nA\nb-body.env\nB", cwd);
    expect(result).toBeNull();
    expect(result).toBeNull();
  });

  // Bypass regression: a FALSE heredoc start (operator text bash does not
  // actually parse as a redirect) must not put the scanner in body mode —
  // that would drop live command lines from the credential scan.
  it("line comment ending in <<EOF does not hide a live credential line (bypass)", () => {
    const result = checkCommandForCredentialPaths("# usage: tool <<EOF\ncat .ssh/id_rsa\nEOF", cwd);
    expect(result).toBe(".ssh");
  });

  it("semicolon-comment <<EOF does not hide a live credential line (bypass)", () => {
    const result = checkCommandForCredentialPaths("echo hi;# c <<EOF\ncat .ssh/id_rsa\nEOF", cwd);
    expect(result).toBe(".ssh");
  });

  it("glued x<<EOF (literal word, not a redirect) does not hide a live credential line (bypass)", () => {
    const result = checkCommandForCredentialPaths("echo foo<<EOF\ncat .ssh/id_rsa\nEOF", cwd);
    expect(result).toBe(".ssh");
  });

  it("string closed before a live credential line is not hidden (false start in unterminated string)", () => {
    // line 0: operator text inside an unterminated string (no bash redirect);
    // the string closes on line 1, so line 2 is a LIVE command
    const result = checkCommandForCredentialPaths(
      'x="docs: <<EOF\nend of docs"\ncat .ssh/id_rsa\nEOF',
      cwd,
    );
    expect(result).toBe(".ssh");
  });

  it("real heredoc with a comment AFTER the operator still strips the body", () => {
    const result = checkCommandForCredentialPaths("cat <<EOF # c\n.ssh/id_rsa\nEOF", cwd);
    expect(result).toBeNull();
    expect(result).toBeNull();
  });

  // ── Shell comments are data, not path operands (2026-08) ──
  it("line comment naming a denied path does not block", () => {
    const result = checkCommandForCredentialPaths("# check the .ssh directory\nls", cwd);
    expect(result).toBeNull();
    expect(result).toBeNull();
  });

  it("inline trailing comment naming a warned path does not prompt", () => {
    const result = checkCommandForCredentialPaths("ls # todo: rotate .env", cwd);
    expect(result).toBeNull();
    expect(result).toBeNull();
  });

  it("comment swallows chained credential text to end of line", () => {
    const result = checkCommandForCredentialPaths("ls # .ssh && rm -rf .", cwd);
    expect(result).toBeNull();
    expect(result).toBeNull();
  });

  it("a comment does not hide a LIVE credential on the next line", () => {
    const result = checkCommandForCredentialPaths("# see docs\ncat .ssh/id_rsa", cwd);
    expect(result).toBe(".ssh");
  });

  it("a real credential operand is still denied with a trailing comment", () => {
    const result = checkCommandForCredentialPaths("cat .ssh/id_rsa # see docs", cwd);
    expect(result).toBe(".ssh");
  });

  it("mid-word # is literal — foo#.ssh is a benign filename, live text after operators is still checked", () => {
    expect(checkCommandForCredentialPaths("cat foo#.ssh", cwd)).toBeNull();
    const result = checkCommandForCredentialPaths("cat foo#.ssh; cat .env", cwd);
    expect(result).toBe(".env");
  });
});

describe("stripShellComments", () => {
  it("masks a whole-line comment, preserving length and newlines", () => {
    expect(stripShellComments("# c\nls")).toBe("   \nls");
  });

  it("masks an inline trailing comment only", () => {
    expect(stripShellComments("ls # .env note")).toBe("ls            ");
    expect(stripShellComments("ls # .env note\necho ok")).toBe("ls            \necho ok");
  });

  it("keeps mid-word # (word content, not a comment)", () => {
    expect(stripShellComments("cat foo#.ssh")).toBe("cat foo#.ssh");
    expect(stripShellComments("${v#pat}")).toBe("${v#pat}");
    expect(stripShellComments("VAR=#x")).toBe("VAR=#x");
    expect(stripShellComments('echo "a"# b')).toBe('echo "a"# b');
  });

  it("keeps # inside quotes (including multi-line strings)", () => {
    expect(stripShellComments(`echo 'a # .env b' x`)).toBe(`echo 'a # .env b' x`);
    const q = 'echo "a # .env b" # real comment';
    const qMasked = stripShellComments(q);
    expect(qMasked).toBe(q.slice(0, q.length - 14) + " ".repeat(14));
    expect(qMasked).toContain('"a # .env b"');
    expect(qMasked).not.toContain("real comment");
    expect(stripShellComments("x='a\n# .ssh'\nls")).toBe("x='a\n# .ssh'\nls");
  });

  it("keeps a backslash-escaped #", () => {
    expect(stripShellComments("echo \\# .ssh")).toBe("echo \\# .ssh");
  });

  it("line splice joins for the word-start check", () => {
    // `foo \\<nl># x` splices to `foo # x` → comment (backslash+newline kept)
    expect(stripShellComments("foo \\\n# .ssh")).toBe("foo \\\n" + " ".repeat(6));
    // `foo\<nl># x` splices to `foo# x` → literal word content
    expect(stripShellComments("foo\\# .ssh\nls")).toBe("foo\\# .ssh\nls");
  });

  it("a comment ends at its physical line even when it ends in backslash", () => {
    expect(stripShellComments("# c \\\nrm -rf /tmp/x")).toBe("     \nrm -rf /tmp/x");
  });

  it("comments after shell operators start a comment", () => {
    expect(stripShellComments("ls;# c .ssh")).toBe("ls;" + " ".repeat(8));
    expect(stripShellComments("(# c")).toBe("(   ");
  });
});

describe("stripHeredocBodies", () => {
  it("strips a terminated heredoc body only", () => {
    expect(stripHeredocBodies("cat > out.txt <<'EOF'\nline1\nline2\nEOF\necho done"))
      .toBe("cat > out.txt <<'EOF'\nEOF\necho done");
  });

  it("keeps the command text for non-heredoc commands", () => {
    expect(stripHeredocBodies("ls -la && cat x")).toBe("ls -la && cat x");
  });

  it("keeps everything when the heredoc is unterminated", () => {
    expect(stripHeredocBodies("cat <<EOF\nbody")).toBe("cat <<EOF\nbody");
  });

  it("does not treat here-strings (<<<) as heredocs", () => {
    expect(stripHeredocBodies("read x <<< .ssh/id_rsa")).toBe("read x <<< .ssh/id_rsa");
  });

  it("handles <<-'EOF' (tab-trimmed, quoted) delimiters", () => {
    expect(stripHeredocBodies("cat <<-\u0027EOF\'\n\tbody\n\tEOF\ndone")).toBe("cat <<-'EOF'\n\tEOF\ndone");
  });

  // False-start declines: bash parses none of these as heredoc starts, so
  // the following lines must stay in the text (never enter body mode).
  it("keeps text when <<EOF sits inside a line comment", () => {
    expect(stripHeredocBodies("# c <<EOF\nbody\nEOF")).toBe("# c <<EOF\nbody\nEOF");
  });

  it("keeps text when <<EOF follows a semicolon comment", () => {
    expect(stripHeredocBodies("echo hi;# c <<EOF\nbody\nEOF")).toBe("echo hi;# c <<EOF\nbody\nEOF");
  });

  it("keeps text when <<EOF is glued to a preceding word", () => {
    expect(stripHeredocBodies("echo foo<<EOF\nbody\nEOF")).toBe("echo foo<<EOF\nbody\nEOF");
  });

  it("keeps text when <<EOF sits in an unterminated double-quoted string", () => {
    expect(stripHeredocBodies('x="s <<EOF\nbody\nEOF')).toBe('x="s <<EOF\nbody\nEOF');
  });
});

describe("checkCommandForCredentialPaths: quoted glob tokens", () => {
  // 3.26.0 false-positive regressions. Two defects made ordinary commands
  // look like credential reads: (1) a QUOTED word was operator-split, so a
  // sed/awk program body (`s|/[0-9]*|/N|`) became fake path operands; (2) a
  // wildcard-only component (`[0-9]*`, `.*`) was compiled into a
  // near-universal regex and compared against credential NAMES. Quoted text
  // never expands and never splits, so all of these are data.
  it.each([
    'grep ".*" file.txt',
    "sed 's/.*/x/' file.txt",
    "sed '/.*/d' file.txt",
    'grep -r "a.*b" .',
    "sed 's|/[0-9]*|/N|g' notes.md",
    "sed -i -e 's|.*/x|y|' f",
    "rg -no '\\b[A-Z]{2,4}/[0-9]+\\b' spec.md",
    "awk '{print $2}' f",
    "tr a-z A-Z",
    "echo .*",
    "rg 'x.*' f",
  ])("%s → clean", (cmd) => {
    expect(checkCommandForCredentialPaths(cmd, cwd)).toBeNull();
  });

  // A glob that spells a credential name (letters typed out) is flagged from
  // the spelling alone — an unquoted `s*sh` can expand to the ssh directory.
  it.each([
    "ls .s*sh",
    "cat .s*e*",
    "ls id_rs?",
  ])("%s → flagged (glob spells a credential name)", (cmd) => {
    expect(checkCommandForCredentialPaths(cmd, cwd)).not.toBeNull();
  });

  // A wildcard-ONLY spelling carries no name, so it is answered by the
  // filesystem instead: the expansion is probed, and a credential path that is
  // really there is flagged.
  it("an unquoted glob expands onto a credential path — flagged", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "halter-glob-"));
    try {
      fs.mkdirSync(path.join(dir, ".secrets"));
      fs.writeFileSync(path.join(dir, ".secrets", "blob"), "x");
      fs.writeFileSync(path.join(dir, "file.txt"), "x");
      expect(checkCommandForCredentialPaths("cat .*/blob", dir)).toBe(".secrets");
      expect(checkCommandForCredentialPaths("grep .* file.txt", dir)).toBe(".secrets");
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("the same wildcard glob is clean where nothing credential-shaped is present", () => {
    expect(checkCommandForCredentialPaths("cat .*/blob", cwd)).toBeNull();
  });

  it("a quoted occurrence does not shield an unquoted one", () => {
    expect(checkCommandForCredentialPaths('echo ".s*sh" && cat .s*sh', cwd)).not.toBeNull();
  });

  it("literal credential names inside quotes are still flagged", () => {
    expect(checkCommandForCredentialPaths('grep "\\.ssh" README.md', cwd)).not.toBeNull();
  });

  // Brace alternation spells names too; a brace group with no comma is a
  // regex quantifier and stays literal text.
  it("brace alternation naming a credential path is flagged", () => {
    expect(checkCommandForCredentialPaths("ls {a,.}ssh/x", cwd)).toBe(".ssh");
  });

  it("a brace quantifier is not an alternation", () => {
    expect(checkCommandForCredentialPaths("rg [a-z]{2,4} f", cwd)).toBeNull();
  });
});

describe("checkBareRelativeTokens", () => {
  const home = os.homedir();
  let tmp: string;
  beforeAll(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "halter-sym-"));
    fs.writeFileSync(path.join(tmp, "data.txt"), "hi\n");
    fs.symlinkSync(path.join(home, ".ssh"), path.join(tmp, "ssh-link"));
    fs.symlinkSync("/etc/hostname", path.join(tmp, "etc-link"));
    fs.symlinkSync("data.txt", path.join(tmp, "inner-link"));
    fs.symlinkSync("/etc/hostname", path.join(tmp, "lnk-out"));
    fs.symlinkSync("data.txt", path.join(tmp, "lnk-in"));
  });
  afterAll(() => {
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  it("flags a symlink whose target matches a credential pattern", () => {
    expect(checkBareRelativeTokens(["cat", "ssh-link"], tmp)).toBe(".ssh");
  });

  it("flags a symlink escaping cwd (non-credential target)", () => {
    const r = checkBareRelativeTokens(["cat", "etc-link"], tmp);
    expect(r).toBe("/etc/hostname");
  });

  it("allows a symlink staying inside cwd", () => {
    const r = checkBareRelativeTokens(["cat", "inner-link"], tmp);
    expect(r).toBeNull();
  });

  it("skips regular files and flags", () => {
    expect(checkBareRelativeTokens(["cat", "data.txt"], tmp)).toBeNull();
    expect(checkBareRelativeTokens(["grep", "-r", "foo", "data.txt"], tmp)).toBeNull();
  });

  it("expands bare relative globs and probes every match for symlink escapes", () => {
    // The attack shape: the repo ships a benign-looking symlink; a natural
    // `cat ln*` reaches it although no credential text is on the command line.
    expect(checkBareRelativeTokens(["cat", "ln*"], tmp)).toBe("/etc/hostname");
  });

  it("denies a glob whose match targets a deny pattern", () => {
    expect(checkBareRelativeTokens(["cat", "ssh-*"], tmp)).not.toBeNull();
  });

  it("keeps globs matching only regular files or in-cwd symlinks clean", () => {
    expect(checkBareRelativeTokens(["cat", "da*"], tmp)).toBeNull();
    expect(checkBareRelativeTokens(["cat", "inner-*"], tmp)).toBeNull();
    expect(checkBareRelativeTokens(["cat", ".s*sh"], tmp)).toBeNull(); // no match
  });

  it("probes relative globs below cwd (subdir symlinks)", () => {
    fs.mkdirSync(path.join(tmp, "sub"));
    fs.symlinkSync("/etc/hostname", path.join(tmp, "sub", "ln"));
    expect(checkBareRelativeTokens(["cat", "sub/ln*"], tmp)).toBe("/etc/hostname");
  });

  it("skips globs with runtime expansions (path layer keeps them opaque)", () => {
    expect(checkBareRelativeTokens(["cat", "$x*"], tmp)).toBeNull();
  });

  it("skips non-bare tokens (slashes, env assignments, command name)", () => {
    expect(checkBareRelativeTokens(["cat", path.join(home, ".ssh", "id_rsa")], tmp)).toBeNull();
    expect(checkBareRelativeTokens(["X=ssh-link", "cat"], tmp)).toBeNull();
    expect(checkBareRelativeTokens(["ssh-link", "arg"], tmp)).toBeNull();
  });

  it("sees tokens glued to shell operators", () => {
    expect(checkBareRelativeTokens(["cat", "ssh-link;ls"], tmp)).not.toBeNull();
    expect(checkBareRelativeTokens(["cat", "ssh-link>x"], tmp)).not.toBeNull();
  });
});

// ── Quoting facts (tokenizeSegmentQuoted) ───────────────────────────────────

describe("tokenizeSegmentQuoted: quoting facts", () => {
  it("a single-quoted script body is one quoted word (no operator split, no glob)", () => {
    const t = tokenizeSegmentQuoted("node -e 'a; b* && c | d'")[2]; // 0=node 1=-e 2=body
    expect(t.text).toBe("a; b* && c | d");
    expect(t.quoted).toBe(true);
    expect(t.unquotedGlob).toBe(false);
  });

  it("a double-quoted glob is quoted (never expands at runtime)", () => {
    const t = tokenizeSegmentQuoted('cat "l*"')[1]; // 0=cat 1="l*"
    expect(t.text).toBe("l*");
    expect(t.quoted).toBe(true);
    expect(t.unquotedGlob).toBe(false);
  });

  it("a glob char outside the quoted span keeps the expansion flag", () => {
    const t = tokenizeSegmentQuoted("cat a*b'c'")[1]; // 0=cat 1=mixed word
    // Quotes are syntax, not content: the expansion pattern is the stripped word.
    expect(t.text).toBe("a*bc");
    expect(t.unquotedGlob).toBe(true);
  });

  it("plain unquoted tokens are unquoted", () => {
    const t = tokenizeSegmentQuoted("cat judge/*.ts")[1]; // 0=cat 1=glob
    expect(t.quoted).toBe(false);
    expect(t.unquotedGlob).toBe(true);
  });

  it("text output is identical to tokenizeSegment for mixed quoting", () => {
    expect(tokenizeSegmentQuoted("node -e 'a; b* && c' | grep x").map((t) => t.text))
      .toEqual(["node", "-e", "a; b* && c", "|", "grep", "x"]);
  });
});

// ── Quoted-token probe semantics (3.22.0 field false-positive fix) ──────────

describe("checkBareRelativeTokens: quoted tokens", () => {
  let tmp: string;
  const q = (text: string): QuotedToken => ({ text, quoted: true, unquotedGlob: false, quotedWhole: true });
  beforeAll(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "halter-symq-"));
    fs.writeFileSync(path.join(tmp, "data.txt"), "hi\n");
    fs.symlinkSync("/etc/hostname", path.join(tmp, "lnk-out"));
    fs.symlinkSync("data.txt", path.join(tmp, "lnk-in"));
    fs.symlinkSync("/etc/hostname", path.join(tmp, "lit*")); // literally named lit*
  });
  afterAll(() => {
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  it("a quoted literal name still follows symlinks (quoting does not stop it)", () => {
    expect(checkBareRelativeTokens(["cat", q("lnk-out")], tmp)).toBe("/etc/hostname");
  });

  it("a quoted glob never expands — cat \"l*\" is the literal name l*", () => {
    expect(checkBareRelativeTokens(["cat", q("ln*")], tmp)).toBeNull();
  });

  it("a quoted word that IS a literal glob-named symlink is still probed", () => {
    expect(checkBareRelativeTokens(["cat", q("lit*")], tmp)).toBe("/etc/hostname");
  });

  it("a quoted word is never operator-split (internal ; && | are data)", () => {
    expect(checkBareRelativeTokens(["cat", q("lnk-out; ls && lnk-out")], tmp)).toBeNull();
    // Contrast: the same text UNQUOTED is a chain and reaches the symlink.
    expect(checkBareRelativeTokens(["cat", "lnk-out; ls"], tmp)).toBe("/etc/hostname");
  });

  it("a glob char outside the quoted span still expands and probes matches", () => {
    expect(checkBareRelativeTokens(["cat", { text: "lnk-out*", quoted: true, unquotedGlob: true, quotedWhole: false }], tmp))
      .toBe("/etc/hostname");
  });
});

// ── globSync failure semantics (honest marker + static-prefix guard) ────────

describe("checkBareRelativeTokens: glob-verify failures", () => {
  let tmp: string;
  beforeAll(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "halter-symg-"));
    fs.mkdirSync(path.join(tmp, "exist-dir"));
  });
  afterAll(() => {
    fs.rmSync(tmp, { recursive: true, force: true });
  });
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("a missing static prefix is provably empty — no prompt even when globSync throws", () => {
    // Field shape (Bun): every no-match glob threw → failed closed. The
    // prefix is gone ⇒ the expansion is empty ⇒ nothing to verify.
    vi.spyOn(fs, "globSync").mockImplementation(() => {
      throw new Error("simulated no-match throw");
    });
    expect(checkBareRelativeTokens(["grep", "x", "missing-dir/*.ts"], tmp)).toBeNull();
  });

  it("an existing prefix with an unverifiable expansion fails closed, marked honestly", () => {
    vi.spyOn(fs, "globSync").mockImplementation(() => {
      throw new Error("simulated");
    });
    expect(checkBareRelativeTokens(["grep", "x", "exist-dir/*.zzz"], tmp)).toBe(GLOB_UNVERIFIED_PREFIX + "exist-dir/*.zzz");
  });

  it("marker helpers round-trip", () => {
    expect(isGlobUnverified(GLOB_UNVERIFIED_PREFIX + "x/*.ts")).toBe(true);
    expect(isGlobUnverified(".env")).toBe(false);
    expect(isGlobUnverified(null)).toBe(false);
    expect(globUnverifiedToken(GLOB_UNVERIFIED_PREFIX + "x/*.ts")).toBe("x/*.ts");
  });
});

// ── Entry-point regression: quoted script bodies are not probed as chains ──

describe("checkCommandForCredentialPaths: quoted bodies (field regression)", () => {
  it("does not operator-split a quoted node -e body (no bogus fragments)", () => {
    const r = checkCommandForCredentialPaths("node -e 'const p = \"*.ts\"; a; b && c | d'", cwd);
    expect(r).toBeNull();
  });

  it("the field repro: grep over missing-prefix globs no longer prompts", () => {
    // This exact command spammed the gate (Bun globSync throw on no-match +
    // operator-split garbage). Missing static prefixes ⇒ provably empty.
    const r = checkCommandForCredentialPaths(
      'cd ~/.pi/agent/extensions/halter && grep -n "misses" judge/*.ts gate/*.ts analysis/*.ts | head -30',
      cwd,
    );
    expect(r).toBeNull();
  });
});
