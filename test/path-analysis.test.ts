import path from "node:path";
import os from "node:os";
import fs from "node:fs";
import { describe, expect, it, beforeAll, afterAll } from "vitest";
import {
	expandTilde,
	resolvePathReal,
	isInsideCwd,
	isAllowedReadPath,
	getOutsideCwdPaths,
	isProjectPiPathResolved,
	isPathDeniedResolved,
	isPathWarnedResolved,
	checkCommandForCredentialPaths,
	checkBareSymlinkTokens,
	stripHeredocBodies,
} from "../analysis/path-analysis";

const home = os.homedir();
const tmpdir = os.tmpdir();
const cwd = path.join(home, "Projects");

describe("expandTilde", () => {
	it("expands ~/foo", () => {
		expect(expandTilde("~/foo")).toBe(path.join(home, "foo"));
	});

	it("expands ~", () => {
		expect(expandTilde("~")).toBe(home);
	});

	it("leaves absolute paths alone", () => {
		expect(expandTilde("/absolute")).toBe("/absolute");
	});

	it("leaves relative paths alone", () => {
		expect(expandTilde("relative")).toBe("relative");
	});
});

describe("resolvePathReal", () => {
	it("resolves relative path", () => {
		expect(resolvePathReal("src/index.ts", cwd)).toBe(path.join(cwd, "src/index.ts"));
	});

	it("resolves absolute path (follows symlinks)", () => {
		// macOS: /etc/hosts → /private/etc/hosts, Linux: stays /etc/hosts
		const expected = require("fs").realpathSync("/etc/hosts");
		expect(resolvePathReal("/etc/hosts", cwd)).toBe(expected);
	});

	it("handles non-existent path gracefully", () => {
		// macOS: /tmp → /private/tmp, so resolved path reflects the symlink target
		const tmpReal = require("fs").realpathSync("/tmp", "utf8");
		expect(resolvePathReal("/tmp/nonexistent/deep/file.txt", cwd)).toBe(
			path.join(tmpReal, "nonexistent/deep/file.txt")
		);
	});
});

describe("isInsideCwd", () => {
	it("cwd is inside itself", () => {
		expect(isInsideCwd(cwd, cwd)).toBe(true);
	});

	it("subdir is inside cwd", () => {
		expect(isInsideCwd(`${cwd}/src`, cwd)).toBe(true);
	});

	it("file in subdir is inside cwd", () => {
		expect(isInsideCwd(`${cwd}/src/index.ts`, cwd)).toBe(true);
	});

	it("/etc is outside cwd", () => {
		expect(isInsideCwd("/etc/hosts", cwd)).toBe(false);
	});

	it("sibling dir is outside cwd", () => {
		expect(isInsideCwd(path.join(home, "Other"), cwd)).toBe(false);
	});

	it("parent dir is outside cwd", () => {
		expect(isInsideCwd(home, cwd)).toBe(false);
	});
});

describe("isAllowedReadPath", () => {
	it("tmpdir is allowed read path", () => {
		expect(isAllowedReadPath(path.join(tmpdir, "foo"))).toBe(true);
	});

	it(".pi is allowed read path", () => {
		expect(isAllowedReadPath(path.join(home, ".pi/agent/foo"))).toBe(true);
	});

	it("/etc is not allowed read path", () => {
		expect(isAllowedReadPath("/etc/hosts")).toBe(false);
	});
});

describe("getOutsideCwdPaths", () => {
	it("returns empty when all paths inside cwd", () => {
		expect(getOutsideCwdPaths([`${cwd}/a`, `${cwd}/b`], cwd)).toHaveLength(0);
	});

	it("filters to outside paths only", () => {
		const outside = getOutsideCwdPaths([`${cwd}/a`, "/etc/hosts"], cwd);
		expect(outside).toEqual(["/etc/hosts"]);
	});

	it("excludes auto-allowed dirs", () => {
		const autoRead = new Set(["/opt"]);
		const isInside = (p: string) => autoRead.has(p) || [...autoRead].some(d => p.startsWith(d + "/"));
		const outside = getOutsideCwdPaths([`${cwd}/a`, "/opt/pi", "/etc/hosts"], cwd, isInside);
		expect(outside).toEqual(["/etc/hosts"]);
	});

	it("excludes allowed read paths", () => {
		const outside = getOutsideCwdPaths([`${cwd}/a`, path.join(tmpdir, "foo"), "/etc/hosts"], cwd);
		expect(outside).toEqual(["/etc/hosts"]);
	});
});

describe("resolved-path variants (hot-path optimization)", () => {
	// The *Resolved variants take a pre-resolved real path so decideFile can skip
	// redundant realpathSync calls. These pin the exact values the file policy
	// relies on.
	const resolved = (filePath: string) => resolvePathReal(expandTilde(filePath), cwd);

	const deniedCases: [string, boolean, string | null][] = [
		[".pi/agent/foo", false, null],
		["~/other/.pi/foo", false, null],
		["src/index.ts", false, null],
		["~/.ssh/id_rsa", true, ".ssh"],
		[".env.production", false, null],
		["~/.aws/credentials", false, null],
	];
	for (const [filePath, denied, matchedRule] of deniedCases) {
		it(`isPathDeniedResolved: ${filePath}`, () => {
			expect(isPathDeniedResolved(filePath, resolved(filePath))).toEqual({ denied, matchedRule });
		});
	}

	const warnedCases: [string, boolean, string | null][] = [
		[".pi/agent/foo", false, null],
		["~/other/.pi/foo", false, null],
		["src/index.ts", false, null],
		["~/.ssh/id_rsa", true, "id_rsa"],
		[".env.production", true, ".env.*"],
		["~/.aws/credentials", true, ".aws"],
	];
	for (const [filePath, warned, matchedRule] of warnedCases) {
		it(`isPathWarnedResolved: ${filePath}`, () => {
			expect(isPathWarnedResolved(filePath, resolved(filePath))).toEqual({ warned, matchedRule });
		});
	}

	const projectPiCases: [string, boolean][] = [
		[".pi/agent/foo", true],
		["~/other/.pi/foo", false],
		["src/index.ts", false],
		["~/.ssh/id_rsa", false],
		[".env.production", false],
		["~/.aws/credentials", false],
	];
	for (const [filePath, inside] of projectPiCases) {
		it(`isProjectPiPathResolved: ${filePath}`, () => {
			expect(isProjectPiPathResolved(resolved(filePath), cwd)).toBe(inside);
		});
	}
});

describe("checkCommandForCredentialPaths", () => {
	const deniedCases: [string, string][] = [
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
	for (const [cmd, rule] of deniedCases) {
		it(`denies: ${cmd}`, () => {
			const result = checkCommandForCredentialPaths(cmd, cwd);
			expect(result.denied).toBe(rule);
		});
	}

	const warnedCases: [string, string][] = [
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
	for (const [cmd, rule] of warnedCases) {
		it(`warns: ${cmd}`, () => {
			const result = checkCommandForCredentialPaths(cmd, cwd);
			expect(result.warned).toBe(rule);
			expect(result.denied).toBeNull();
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
			expect(result.denied).toBeNull();
			expect(result.warned).toBeNull();
		});
	}

	// Heredoc bodies are stdin DATA — credential names in the body are not
	// path operands and must not false-positive (FP regression: the agent's
	// own probe commands writing test files got blocked on this).
	it("heredoc body with denied credential name is data (no match)", () => {
		const result = checkCommandForCredentialPaths("cat > out.txt <<'EOF'\n.ssh/id_rsa\nEOF", cwd);
		expect(result.denied).toBeNull();
		expect(result.warned).toBeNull();
	});

	it("heredoc body with warned credential name is data (no match)", () => {
		const result = checkCommandForCredentialPaths("wc -l x <<EOF\n.env\nEOF", cwd);
		expect(result.denied).toBeNull();
		expect(result.warned).toBeNull();
	});

	it("credential in the command line beside a heredoc still matches", () => {
		const result = checkCommandForCredentialPaths("cat .ssh/id_rsa <<EOF\nbody\nEOF", cwd);
		expect(result.denied).toBe(".ssh");
	});

	it("redirect target credential still matches with heredoc present", () => {
		const result = checkCommandForCredentialPaths("cat <<EOF > .ssh/id_rsa\nbody\nEOF", cwd);
		expect(result.denied).toBe(".ssh");
	});

	it("quoted pseudo-heredoc mid-line does not strip following lines", () => {
		const result = checkCommandForCredentialPaths('echo "fake <<EOF text" && cat .env', cwd);
		expect(result.warned).toBe(".env");
	});

	it("unterminated heredoc stays fail-closed (body still scanned)", () => {
		const result = checkCommandForCredentialPaths("cat <<EOF\n.ssh/id_rsa", cwd);
		expect(result.denied).toBe(".ssh");
	});

	it("multiple heredocs on one line: bodies until both terminators", () => {
		const result = checkCommandForCredentialPaths("cmd <<A <<B\na-body.ssh\nA\nb-body.env\nB", cwd);
		expect(result.denied).toBeNull();
		expect(result.warned).toBeNull();
	});

	// Bypass regression: a FALSE heredoc start (operator text bash does not
	// actually parse as a redirect) must not put the scanner in body mode —
	// that would drop live command lines from the credential scan.
	it("line comment ending in <<EOF does not hide a live credential line (bypass)", () => {
		const result = checkCommandForCredentialPaths("# usage: tool <<EOF\ncat .ssh/id_rsa\nEOF", cwd);
		expect(result.denied).toBe(".ssh");
	});

	it("semicolon-comment <<EOF does not hide a live credential line (bypass)", () => {
		const result = checkCommandForCredentialPaths("echo hi;# c <<EOF\ncat .ssh/id_rsa\nEOF", cwd);
		expect(result.denied).toBe(".ssh");
	});

	it("glued x<<EOF (literal word, not a redirect) does not hide a live credential line (bypass)", () => {
		const result = checkCommandForCredentialPaths("echo foo<<EOF\ncat .ssh/id_rsa\nEOF", cwd);
		expect(result.denied).toBe(".ssh");
	});

	it("string closed before a live credential line is not hidden (false start in unterminated string)", () => {
		// line 0: operator text inside an unterminated string (no bash redirect);
		// the string closes on line 1, so line 2 is a LIVE command
		const result = checkCommandForCredentialPaths(
			'x="docs: <<EOF\nend of docs"\ncat .ssh/id_rsa\nEOF',
			cwd,
		);
		expect(result.denied).toBe(".ssh");
	});

	it("real heredoc with a comment AFTER the operator still strips the body", () => {
		const result = checkCommandForCredentialPaths("cat <<EOF # c\n.ssh/id_rsa\nEOF", cwd);
		expect(result.denied).toBeNull();
		expect(result.warned).toBeNull();
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
	// Quoted text is never glob-expanded by bash, so a quoted ".*" is a regex
	// pattern (or a literal name), not a glob reaching .ssh at runtime.
	it.each([
		'grep ".*" file.txt',
		"sed 's/.*/x/' file.txt",
		"sed '/.*/d' file.txt",
		'grep -r "a.*b" .',
	])("%s → clean (quoted, cannot expand)", (cmd) => {
		expect(checkCommandForCredentialPaths(cmd, cwd)).toEqual({ denied: null, warned: null });
	});

	// Unquoted globs keep the full check (runtime-verified: they DO expand).
	it.each([
		"cat .*/id_rsa",
		"grep .* file.txt",
		"ls .s*sh",
	])("%s → denied (unquoted glob expands)", (cmd) => {
		expect(checkCommandForCredentialPaths(cmd, cwd).denied).not.toBeNull();
	});

	it("a quoted occurrence does not shield an unquoted one", () => {
		expect(checkCommandForCredentialPaths('echo ".s*sh" && cat .s*sh', cwd).denied).not.toBeNull();
	});

	it("literal credential names inside quotes are still denied", () => {
		expect(checkCommandForCredentialPaths('grep "\\.ssh" README.md', cwd).denied).not.toBeNull();
	});
});

describe("checkBareSymlinkTokens", () => {
	const home = os.homedir();
	let tmp: string;
	beforeAll(() => {
		tmp = fs.mkdtempSync(path.join(os.tmpdir(), "halter-sym-"));
		fs.writeFileSync(path.join(tmp, "data.txt"), "hi\n");
		fs.symlinkSync(path.join(home, ".ssh"), path.join(tmp, "ssh-link"));
		fs.symlinkSync("/etc/hostname", path.join(tmp, "etc-link"));
		fs.symlinkSync("data.txt", path.join(tmp, "inner-link"));
	});
	afterAll(() => {
		fs.rmSync(tmp, { recursive: true, force: true });
	});

	it("denies a symlink whose target matches a deny pattern", () => {
		const r = checkBareSymlinkTokens(["cat", "ssh-link"], tmp);
		expect(r.denied).not.toBeNull();
	});

	it("warns on a symlink escaping cwd (non-credential target)", () => {
		const r = checkBareSymlinkTokens(["cat", "etc-link"], tmp);
		expect(r.denied).toBeNull();
		expect(r.warned).toBe("/etc/hostname");
	});

	it("allows a symlink staying inside cwd", () => {
		const r = checkBareSymlinkTokens(["cat", "inner-link"], tmp);
		expect(r).toEqual({ denied: null, warned: null });
	});

	it("skips regular files, flags, and globs", () => {
		expect(checkBareSymlinkTokens(["cat", "data.txt"], tmp)).toEqual({ denied: null, warned: null });
		expect(checkBareSymlinkTokens(["grep", "-r", "foo", "data.txt"], tmp)).toEqual({ denied: null, warned: null });
		expect(checkBareSymlinkTokens(["cat", ".s*sh"], tmp)).toEqual({ denied: null, warned: null });
	});

	it("skips non-bare tokens (slashes, env assignments, command name)", () => {
		expect(checkBareSymlinkTokens(["cat", path.join(home, ".ssh", "id_rsa")], tmp)).toEqual({ denied: null, warned: null });
		expect(checkBareSymlinkTokens(["X=ssh-link", "cat"], tmp)).toEqual({ denied: null, warned: null });
		expect(checkBareSymlinkTokens(["ssh-link", "arg"], tmp)).toEqual({ denied: null, warned: null });
	});

	it("sees tokens glued to shell operators", () => {
		expect(checkBareSymlinkTokens(["cat", "ssh-link;ls"], tmp).denied).not.toBeNull();
		expect(checkBareSymlinkTokens(["cat", "ssh-link>x"], tmp).denied).not.toBeNull();
	});
});
