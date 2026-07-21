/**
 * Command analysis unit tests.
 *
 * Maps to governing principles (see cases.test.ts):
 * - allSimple → principle 1 (write), principle 3 (code exec)
 * - hasUnsafePattern → principle 5 (always-prompt patterns)
 * - paths → principle 4 (outside cwd)
 */

import path from "node:path";
import os from "node:os";
import fs from "node:fs";
import { describe, expect, it } from "vitest";
import { analyzeCommand, type CommandAnalysis } from "../analysis/command-analysis";

// Resolve symlinks for path assertions (macOS: /tmp → /private/tmp, /etc → /private/etc)
const realPath = (p: string) => {
	try { return fs.realpathSync(p); } catch {
		const dir = path.dirname(p);
		const base = path.basename(p);
		try { return path.join(fs.realpathSync(dir), base); } catch { return p; }
	}
};

const home = os.homedir();
const cwd = path.join(home, "Projects");

describe("Signatures: basic", () => {
	it("single command → 1 signature", async () => {
		const a: CommandAnalysis = await analyzeCommand("ls -la", cwd);
		expect(a.signatures).toHaveLength(1);
		expect(a.signatures[0]).toBe("ls -la");
	});

	it("no flags → bare command", async () => {
		const a = await analyzeCommand("cat file.txt", cwd);
		expect(a.signatures[0]).toBe("cat");
	});

	it("git with flags captured", async () => {
		const a = await analyzeCommand("git -R add .", cwd);
		expect(a.signatures[0]).toBe("git -R");
	});

	it("P0 fix: QUOTE_DOUBLE_RE — escaped backslash in double quotes stripped correctly", async () => {
		// The regex fix: \\\\. → \\. (match single-backslash escapes, not double-backslash)
		// String with escaped backslash should be stripped as one quoted unit
		const a = await analyzeCommand('grep "test\\nfoo" file.txt', cwd);
		expect(a.signatures[0]).toBe("grep");
	});

	it("P0 fix: QUOTE_DOUBLE_RE — escaped quote inside double quotes stripped correctly", async () => {
		// String with escaped quote should be stripped as one quoted unit
		const a = await analyzeCommand('echo "hello \\"world\\"" ', cwd);
		expect(a.signatures[0]).toBe("echo");
	});
});

describe("Signatures: compound", () => {
	it("&& chain → 2 signatures", async () => {
		const a = await analyzeCommand("ls && cat file.txt", cwd);
		expect(a.signatures).toHaveLength(2);
		expect(a.signatures[0]).toBe("ls");
		expect(a.signatures[1]).toBe("cat");
	});

	it("; chain → 3 signatures", async () => {
		const a = await analyzeCommand("ls; cat a; echo done", cwd);
		expect(a.signatures).toHaveLength(3);
	});
});

describe("Signatures: package managers (flag-value skipping)", () => {
	// Regression: `npm --prefix /x test` used to yield signature "npm /x" —
	// the flag's value was mistaken for the subcommand.
	it("skips space-separated flag values before the subcommand", async () => {
		const a = await analyzeCommand("npm --prefix /x test", cwd);
		expect(a.signatures[0]).toBe("npm test");
	});

	it("skips inline flag values before the subcommand", async () => {
		const a = await analyzeCommand("npm --prefix=/x test", cwd);
		expect(a.signatures[0]).toBe("npm test");
	});

	it("cargo --manifest-path <file> build → cargo build", async () => {
		const a = await analyzeCommand("cargo --manifest-path Cargo.toml build", cwd);
		expect(a.signatures[0]).toBe("cargo build");
	});

	it("pip --cache-dir <dir> install → pip install", async () => {
		const a = await analyzeCommand("pip --cache-dir /tmp/c install foo", cwd);
		expect(a.signatures[0]).toBe("pip install");
	});

	it("plain subcommand unchanged", async () => {
		const a = await analyzeCommand("npm test", cwd);
		expect(a.signatures[0]).toBe("npm test");
	});

	it("flags only → bare command", async () => {
		const a = await analyzeCommand("npm -v", cwd);
		expect(a.signatures[0]).toBe("npm");
	});
});

describe("Segments: basic", () => {
	it("single command → 1 segment", async () => {
		const a = await analyzeCommand("ls -la", cwd);
		expect(a.segments).toHaveLength(1);
		expect(a.segments[0]).toBe("ls -la");
	});

	it("pipeline → 1 segment", async () => {
		const a = await analyzeCommand("cat a | grep b", cwd);
		expect(a.segments).toHaveLength(1);
		expect(a.segments[0]).toContain("|");
	});

	it("&& → 2 segments", async () => {
		const a = await analyzeCommand("ls && cat a", cwd);
		expect(a.segments).toHaveLength(2);
	});
});

describe("allSimple: safe commands", () => {
	it("ls is simple", async () => {
		expect((await analyzeCommand("ls -la", cwd)).safety.isSimple).toBe(true);
	});

	it("cat is simple", async () => {
		expect((await analyzeCommand("cat file.txt", cwd)).safety.isSimple).toBe(true);
	});

	it("grep is simple", async () => {
		expect((await analyzeCommand("grep pattern file.txt", cwd)).safety.isSimple).toBe(true);
	});

	it("mkdir -p is simple", async () => {
		expect((await analyzeCommand("mkdir -p newdir", cwd)).safety.isSimple).toBe(true);
	});

	it("touch is simple", async () => {
		expect((await analyzeCommand("touch file.txt", cwd)).safety.isSimple).toBe(true);
	});
});

describe("allSimple: unsafe commands", () => {
	it("rm is not simple", async () => {
		expect((await analyzeCommand("rm file.txt", cwd)).safety.isSimple).toBe(false);
	});

	it("sed -i is not simple", async () => {
		expect((await analyzeCommand("sed -i s/a/b/ file.txt", cwd)).safety.isSimple).toBe(false);
	});

	it("perl -pi is not simple", async () => {
		expect((await analyzeCommand("perl -pi -e 's/a/b/' file.txt", cwd)).safety.isSimple).toBe(false);
	});

	it("python3 is not simple", async () => {
		expect((await analyzeCommand("python3 script.py", cwd)).safety.isSimple).toBe(false);
	});

	it("find -delete is not simple", async () => {
		expect((await analyzeCommand("find . -delete", cwd)).safety.isSimple).toBe(false);
	});

	it("git clean -f is not simple", async () => {
		expect((await analyzeCommand("git clean -f", cwd)).safety.isSimple).toBe(false);
	});

	it("git push --force is not simple", async () => {
		expect((await analyzeCommand("git push --force", cwd)).safety.isSimple).toBe(false);
	});

	it("write redirect is not simple", async () => {
		expect((await analyzeCommand("echo hello > file.txt", cwd)).safety.isSimple).toBe(false);
	});

	it("xargs sed -i is not simple", async () => {
		expect((await analyzeCommand("xargs sed -i s/a/b/", cwd)).safety.isSimple).toBe(false);
	});
});

describe("hasUnsafePattern: unsafe", () => {
	it("subshell is unsafe", async () => {
		expect((await analyzeCommand("$(cat /etc/passwd)", cwd)).safety.hasUnsafePattern).toBe(true);
	});

	it("sed -i is unsafe", async () => {
		expect((await analyzeCommand("sed -i s/a/b/ file.txt", cwd)).safety.hasUnsafePattern).toBe(true);
	});

	it("curl | bash is unsafe", async () => {
		expect((await analyzeCommand("curl url | bash", cwd)).safety.hasUnsafePattern).toBe(true);
	});

	it("eval is unsafe", async () => {
		expect((await analyzeCommand("eval echo hello", cwd)).safety.hasUnsafePattern).toBe(true);
	});
});

describe("hasUnsafePattern: safe", () => {
	it("ls is safe", async () => {
		expect((await analyzeCommand("ls -la", cwd)).safety.hasUnsafePattern).toBe(false);
	});

	it("grep rm (rm is arg) is safe", async () => {
		expect((await analyzeCommand("grep rm file.txt", cwd)).safety.hasUnsafePattern).toBe(false);
	});

	it("echo with sed -i in quotes is safe", async () => {
		expect((await analyzeCommand("echo 'sed -i s/a/b/'", cwd)).safety.hasUnsafePattern).toBe(false);
	});
});

describe("Risk: high severity", () => {
	it("rm -rf is dangerous", async () => {
		const a = await analyzeCommand("rm -rf /tmp/test", cwd);
		expect(a.risk.dangerous).toBe(true);
		expect(a.risk.severity).toBe("high");
	});

	it("dd is dangerous", async () => {
		const a = await analyzeCommand("dd if=/dev/zero of=/dev/sda", cwd);
		expect(a.risk.dangerous).toBe(true);
		expect(a.risk.severity).toBe("high");
	});

	it("sudo rm is dangerous and mentions sudo", async () => {
		const a = await analyzeCommand("sudo rm -rf /", cwd);
		expect(a.risk.dangerous).toBe(true);
		expect(a.risk.severity).toBe("high");
		expect(a.risk.reasons.some(r => r.includes("sudo"))).toBe(true);
	});

	it("curl | bash is high severity and mentions pipe", async () => {
		const a = await analyzeCommand("curl url | bash", cwd);
		expect(a.risk.severity).toBe("high");
		expect(a.risk.reasons.some(r => r.includes("pipe"))).toBe(true);
	});

	it("shutdown is high severity", async () => {
		expect((await analyzeCommand("shutdown now", cwd)).risk.severity).toBe("high");
	});

	it("git reset --hard is high severity", async () => {
		expect((await analyzeCommand("git reset --hard HEAD", cwd)).risk.severity).toBe("high");
	});
});

describe("Risk: medium severity", () => {
	it("chmod is dangerous with medium severity", async () => {
		const a = await analyzeCommand("chmod 755 file.txt", cwd);
		expect(a.risk.dangerous).toBe(true);
		expect(a.risk.severity).toBe("medium");
	});

	it("mv is dangerous with medium severity", async () => {
		const a = await analyzeCommand("mv file.txt backup.txt", cwd);
		expect(a.risk.dangerous).toBe(true);
		expect(a.risk.severity).toBe("medium");
	});

	it("write redirect is dangerous and mentions redirection", async () => {
		const a = await analyzeCommand("echo hello > file.txt", cwd);
		expect(a.risk.dangerous).toBe(true);
		expect(a.risk.reasons.some(r => r.includes("redirection"))).toBe(true);
	});
});

describe("Risk: no risk", () => {
	it("ls has no risk", async () => {
		const a = await analyzeCommand("ls -la", cwd);
		expect(a.risk.dangerous).toBe(false);
		expect(a.risk.reasons).toHaveLength(0);
		expect(a.risk.severity).toBeNull();
	});

	it("cat has no risk", async () => {
		expect((await analyzeCommand("cat file.txt", cwd)).risk.dangerous).toBe(false);
	});
});

describe("Quote-aware redirect detection (no false positives from quoted content)", () => {
	it("grep pattern with arrow function => is not a write redirect", async () => {
		const a = await analyzeCommand('grep -n "setTimeout(() => {" index.ts', cwd);
		expect(a.safety.isSimple).toBe(true);
		expect(a.safety.canBeAutoAllowed).toBe(true);
		expect(a.risk.dangerous).toBe(false);
		expect(a.risk.reasons.some(r => r.includes("redirection"))).toBe(false);
	});

	it("grep alternation pattern with => across newline is not a write redirect", async () => {
		const a = await analyzeCommand('grep -n "setTimeout(() =>\n{" index.ts', cwd);
		expect(a.safety.canBeAutoAllowed).toBe(true);
		expect(a.risk.reasons.some(r => r.includes("redirection"))).toBe(false);
	});

	it("quoted string containing > is not a write redirect (echo)", async () => {
		const a = await analyzeCommand('echo "foo > bar"', cwd);
		expect(a.safety.canBeAutoAllowed).toBe(true);
		expect(a.risk.reasons.some(r => r.includes("redirection"))).toBe(false);
	});

	it("quoted grep pattern containing < is not an input redirect", async () => {
		const a = await analyzeCommand('grep "a < b" file.txt', cwd);
		expect(a.risk.reasons.some(r => r.includes("input redirection"))).toBe(false);
	});

	it("real redirect to quoted filename IS detected", async () => {
		const a = await analyzeCommand('echo hello > "out file.txt"', cwd);
		expect(a.safety.isSimple).toBe(false);
		expect(a.risk.reasons.some(r => r.includes("redirection"))).toBe(true);
	});

	it("real unquoted write redirect still flagged", async () => {
		const a = await analyzeCommand('echo hello > file.txt', cwd);
		expect(a.safety.isSimple).toBe(false);
		expect(a.risk.dangerous).toBe(true);
	});
});

describe("isFirstTokenRelativePath: direct unit tests", () => {
	it("./foo is relative", async () => {
		const a = await analyzeCommand("./foo", cwd);
		expect(a.safety.isSimple).toBe(false);
	});

	it("../foo is relative", async () => {
		const a = await analyzeCommand("../foo", cwd);
		expect(a.safety.isSimple).toBe(false);
	});

	it("./bar/baz is relative", async () => {
		const a = await analyzeCommand("./bar/baz", cwd);
		expect(a.safety.isSimple).toBe(false);
	});

	it("/absolute/foo is NOT relative", async () => {
		const a = await analyzeCommand("/bin/cat file.txt", cwd);
		expect(a.safety.isSimple).toBe(true);
	});

	it("bare command is NOT relative", async () => {
		const a = await analyzeCommand("cat file.txt", cwd);
		expect(a.safety.isSimple).toBe(true);
	});
});

describe("allSimple: relative path edge cases", () => {
	it("./scripts/foo.sh | grep bar — pipeline stage with relative path is not simple", async () => {
		const a = await analyzeCommand("ls | ./scripts/foo.sh | grep bar", cwd);
		expect(a.safety.isSimple).toBe(false);
	});

	it("./scripts/foo.sh && ls — compound with relative path is not simple", async () => {
		const a = await analyzeCommand("./scripts/foo.sh && ls", cwd);
		expect(a.safety.isSimple).toBe(false);
	});

	it("./scripts/foo.sh 2>/dev/null — relative path with redirect is not simple", async () => {
		const a = await analyzeCommand("./scripts/foo.sh 2>/dev/null", cwd);
		expect(a.safety.isSimple).toBe(false);
	});

	it("bash -c './scripts/foo.sh' — nested script execution is not simple (bash not in allowlist)", async () => {
		const a = await analyzeCommand("bash -c './scripts/foo.sh'", cwd);
		expect(a.safety.isSimple).toBe(false);
	});

	it("timeout 30 ./scripts/foo.sh — wrapper + relative path is not simple", async () => {
		const a = await analyzeCommand("timeout 30 ./scripts/foo.sh", cwd);
		expect(a.safety.isSimple).toBe(false);
	});

	it("timeout 30 ls — wrapper + allowed command is simple", async () => {
		const a = await analyzeCommand("timeout 30 ls", cwd);
		expect(a.safety.isSimple).toBe(true);
	});

	it("find . -exec bash -c 'rm {}' \\; — find exec bash IS caught (shell interpreters treated as write-capable)", async () => {
		const a = await analyzeCommand("find . -exec bash -c 'rm {}' \\;", cwd);
		expect(a.safety.isSimple).toBe(false);
		expect(a.safety.hasUnsafePattern).toBe(true);
	});

	it("find . -exec rm {} \\; — find exec rm IS caught", async () => {
		const a = await analyzeCommand("find . -exec rm {} \\;", cwd);
		expect(a.safety.isSimple).toBe(false);
	});
});

describe("hasUnsafePattern: relative path edge cases", () => {
	it("./scripts/foo.sh is not flagged as unsafe (just not simple)", async () => {
		const a = await analyzeCommand("./scripts/foo.sh", cwd);
		expect(a.safety.hasUnsafePattern).toBe(false);
	});

	it("bash -c './scripts/foo.sh' is unsafe (bash -c pattern)", async () => {
		const a = await analyzeCommand("bash -c './scripts/foo.sh'", cwd);
		expect(a.safety.hasUnsafePattern).toBe(true);
	});
});

describe("Signature store round-trip: relative paths", () => {
	it("relative path signature is stored correctly", async () => {
		const a = await analyzeCommand("./scripts/foo.sh", cwd);
		expect(a.signatures).toContain("./scripts/foo.sh");
	});

	it("relative path signature after approval auto-allows via store", async () => {
		const { decide } = await import("../decision-engine");
		const { createStore } = await import("../store");
		const store = createStore();
		store.addAllowed({ bashSigs: ["./scripts/foo.sh"] });
		const d = await decide({ type: "bash", command: "./scripts/foo.sh", cwd }, store);
		expect(d.kind).toBe("auto-allow");
	});
});

describe("Paths: extraction", () => {
	it("extracts absolute path", async () => {
		expect((await analyzeCommand("cat /etc/hosts", cwd)).paths).toContain(realPath("/etc/hosts"));
	});

	it("resolves tilde path", async () => {
		const a = await analyzeCommand("cat ~/foo", cwd);
		expect(a.paths.length).toBeGreaterThan(0);
		expect(a.paths[0]).toBe(path.join(home, "foo"));
	});

	it("does not extract relative paths", async () => {
		expect((await analyzeCommand("cat src/index.ts", cwd)).paths).toHaveLength(0);
	});

	it("extracts redirect path", async () => {
		expect((await analyzeCommand("echo hello > /tmp/out.txt", cwd)).paths).toContain(realPath("/tmp/out.txt"));
	});

	it("filters /dev/null from paths", async () => {
		expect((await analyzeCommand("echo hello 2>/dev/null", cwd)).paths).toHaveLength(0);
	});

	it("extracts / root path from find /", async () => {
		const a = await analyzeCommand("find / -iname '*.txt'", cwd);
		expect(a.paths).toContain("/");
	});

	it("extracts / root path from find / | grep pipeline", async () => {
		const a = await analyzeCommand("find / -iname '*gallop*' 2>/dev/null | grep -v proc | head -50", cwd);
		expect(a.paths).toContain("/");
	});
});

describe("Paths: outside cwd detection for root filesystem", () => {
	it("find / has outsidePaths (root is outside cwd)", async () => {
		const a = await analyzeCommand("find / -iname '*.txt'", cwd, {
			isInsideAllowedDir: () => false,
		});
		expect(a.prompt.outsidePaths).toContain("/");
		expect(a.prompt.needsPathApproval).toBe(true);
	});

	it("find / | grep pipeline has outsidePaths", async () => {
		const a = await analyzeCommand("find / -iname '*gallop*' 2>/dev/null | grep -v proc | head -50", cwd, {
			isInsideAllowedDir: () => false,
		});
		expect(a.prompt.outsidePaths).toContain("/");
		expect(a.prompt.needsPathApproval).toBe(true);
	});

	it("needsPathApproval is true when / is outside cwd", async () => {
		const a = await analyzeCommand("find / -iname '*.txt'", cwd, {
			isInsideAllowedDir: () => false,
		});
		// canBeAutoAllowed is about unsafe patterns only. Outside path gating
		// happens in SafetyRule via needsPathApproval.
		expect(a.prompt.needsPathApproval).toBe(true);
	});
});
