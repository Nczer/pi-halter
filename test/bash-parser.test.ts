import path from "node:path";
import os from "node:os";
import fs from "node:fs";
import { describe, expect, it } from "vitest";
import { parseCommand } from "../analysis/bash-parser";

// Resolve symlinks for path assertions (macOS: /tmp → /private/tmp, /etc → /private/etc)
const realPath = (p: string) => {
	try { return fs.realpathSync(p); } catch {
		// For non-existent paths, resolve the parent and re-append
		const dir = path.dirname(p);
		const base = path.basename(p);
		try { return path.join(fs.realpathSync(dir), base); } catch { return p; }
	}
};

const home = os.homedir();
const cwd = path.join(home, "Projects");

describe("parseCommand: segments", () => {
	it("single command → 1 segment", async () => {
		const r = await parseCommand("ls -la", cwd);
		expect(r.segments).toHaveLength(1);
		expect(r.segments[0].text).toBe("ls -la");
	});

	it("pipeline → 1 segment", async () => {
		const r = await parseCommand("cat a | grep b", cwd);
		expect(r.segments).toHaveLength(1);
		expect(r.segments[0].ops).toContain("|");
	});

	it("&& → 2 segments", async () => {
		const r = await parseCommand("ls && cat file.txt", cwd);
		expect(r.segments).toHaveLength(2);
	});

	it("triple && → 3 segments", async () => {
		const r = await parseCommand("ls && cat a && echo done", cwd);
		expect(r.segments).toHaveLength(3);
	});

	it("redirected statement → 1 segment", async () => {
		const r = await parseCommand("tr 'a-z' 'A-Z' < file.txt", cwd);
		expect(r.segments).toHaveLength(1);
	});

	it("pipeline with redirect → 1 segment", async () => {
		const r = await parseCommand("cat a | grep b 2>/dev/null", cwd);
		expect(r.segments).toHaveLength(1);
	});

	it("for loop with redirect → segments extracted", async () => {
		const r = await parseCommand("for f in a b; do rm $f; done 2>/dev/null", cwd);
		expect(r.segments.length).toBeGreaterThanOrEqual(1);
	});

	it("subshell in pipeline → segments", async () => {
		const r = await parseCommand("(rm a && ls b) | cat", cwd);
		expect(r.segments.length).toBeGreaterThanOrEqual(1);
	});

	it("|| → 2 segments", async () => {
		const r = await parseCommand("ls || echo not found", cwd);
		expect(r.segments).toHaveLength(2);
	});

	it("; → 2 segments", async () => {
		const r = await parseCommand("ls; cat file.txt", cwd);
		expect(r.segments).toHaveLength(2);
	});

	it("backgrounding stripped", async () => {
		const r = await parseCommand("sleep 10 &", cwd);
		expect(r.segments).toHaveLength(1);
		expect(r.segments[0].text).toBe("sleep 10");
	});

	it("comment stripped", async () => {
		const r = await parseCommand("ls # comment", cwd);
		expect(r.segments).toHaveLength(1);
	});
});

describe("parseCommand: paths", () => {
	it("keeps absolute paths", async () => {
		const r = await parseCommand("cat /etc/hosts", cwd);
		expect(r.paths).toContain(realPath("/etc/hosts"));
	});

	it("expands tilde", async () => {
		const r = await parseCommand("ls ~/foo", cwd);
		expect(r.paths.length).toBeGreaterThan(0);
		expect(r.paths[0]).toBe(path.join(home, "foo"));
	});

	it("does not extract relative paths", async () => {
		const r = await parseCommand("cat src/index.ts", cwd);
		expect(r.paths).toHaveLength(0);
	});

	it("extracts redirect destination", async () => {
		const r = await parseCommand("cat file.txt > /tmp/out.txt", cwd);
		expect(r.paths).toContain(realPath("/tmp/out.txt"));
	});

	it("extracts input redirect", async () => {
		const r = await parseCommand("cat < /tmp/in.txt", cwd);
		expect(r.paths).toContain(realPath("/tmp/in.txt"));
	});

	it("filters /dev/null", async () => {
		const r = await parseCommand("echo hello 2>/dev/null", cwd);
		expect(r.paths).toHaveLength(0);
	});

	it("handles single-quoted paths", async () => {
		const r = await parseCommand("cat '/tmp/file with spaces.txt'", cwd);
		expect(r.paths).toContain(realPath("/tmp/file with spaces.txt"));
	});

	it("handles double-quoted paths", async () => {
		const r = await parseCommand('cat "/tmp/file with spaces.txt"', cwd);
		expect(r.paths).toContain(realPath("/tmp/file with spaces.txt"));
	});

	it("does not extract heredoc body as path", async () => {
		const r = await parseCommand("cat << 'EOF'\n/etc/passwd\nEOF", cwd);
		expect(r.paths).toHaveLength(0);
	});

	it("does not extract commented paths", async () => {
		const r = await parseCommand("ls # /etc/hosts", cwd);
		expect(r.paths).toHaveLength(0);
	});

	it("non-path-aware commands have no paths", async () => {
		const r = await parseCommand("echo /etc/hosts", cwd);
		expect(r.paths).toHaveLength(0);
	});

	it("does not extract URLs as paths", async () => {
		const r = await parseCommand("cat https://example.com", cwd);
		expect(r.paths).toHaveLength(0);
	});
});

describe("parseCommand: hasSubshell", () => {
	it("detects subshell in command", async () => {
		const r = await parseCommand("cat $(echo /etc/hosts)", cwd);
		expect(r.hasSubshell).toBe(true);
	});

	it("no subshell on simple command", async () => {
		const r = await parseCommand("ls -la", cwd);
		expect(r.hasSubshell).toBe(false);
	});
});

describe("parseCommand: command substitution", () => {
	it("detects $()", async () => {
		const r = await parseCommand("$(cat /etc/passwd)", cwd);
		expect(r.hasSubshell).toBe(true);
	});

	it("detects backticks", async () => {
		const r = await parseCommand("`whoami`", cwd);
		expect(r.hasSubshell).toBe(true);
	});

	it("detects process substitution", async () => {
		const r = await parseCommand("cat <(ls)", cwd);
		expect(r.hasSubshell).toBe(true);
	});
});

describe("parseCommand: no subshell", () => {
	it("simple command has no subshell", async () => {
		const r = await parseCommand("ls -la", cwd);
		expect(r.hasSubshell).toBe(false);
	});

	it("pipeline has no subshell", async () => {
		const r = await parseCommand("cat file.txt | grep pattern", cwd);
		expect(r.hasSubshell).toBe(false);
	});

	it("single-quoted $() not flagged (literal string)", async () => {
		const r = await parseCommand("echo 'hello $(world)'", cwd);
		expect(r.hasSubshell).toBe(false);
	});
});

describe("parseCommand: edge cases", () => {
	it("empty string has no subshell", async () => {
		const r = await parseCommand("", cwd);
		expect(r.hasSubshell).toBe(false);
	});

	it("echo has no subshell", async () => {
		const r = await parseCommand("echo hello", cwd);
		expect(r.hasSubshell).toBe(false);
	});
});

describe("parseCommand: pipeline with compound children (split on &&, no commands dropped)", () => {
	it("subshell with && chain inside pipeline → && splits into separate segments, none dropped", async () => {
		const r = await parseCommand("(rm a && ls b) | cat", cwd);
		// handlePipeline keeps control-operator splits as top-level segments — only the
		// last newly-added segment joins the pipeline. History: an early version dropped
		// "rm a" entirely; the "merge all" band-aid fixed the drop but folded both commands
		// into one blob led by the first command's signature, hiding the second command
		// from the approval gate (e.g. "(ls && npx evil) | cat" auto-allowed via "ls").
		expect(r.segments.length).toBe(2);
		expect(r.segments[0].text).toBe("rm a");
		expect(r.segments[1].text).toBe("ls b | cat");
		expect(r.segments[1].ops).toContain("|");
	});

	it("subshell with triple && chain inside pipeline → all three commands present across segments", async () => {
		const r = await parseCommand("(echo a && echo b && echo c) | grep x", cwd);
		expect(r.segments.length).toBe(3);
		expect(r.segments[0].text).toBe("echo a");
		expect(r.segments[1].text).toBe("echo b");
		expect(r.segments[2].text).toBe("echo c | grep x");
	});

	// — bypass fix: && / ; / || chains feeding a pipe —
	it("cd && npx 2>&1 | grep → cd splits off, npx joins pipe", async () => {
		const r = await parseCommand("cd /tmp && npx vitest 2>&1 | grep FAIL", cwd);
		expect(r.segments.length).toBe(2);
		expect(r.segments[0].text).toBe("cd /tmp");
		expect(r.segments[1].text).toContain("npx vitest");
		expect(r.segments[1].text).toContain("| grep FAIL");
		expect(r.segments[1].ops).toContain("|");
	});

	it("cd ; npx 2>&1 | cat → ; chain, npx joins pipe", async () => {
		const r = await parseCommand("cd /tmp ; npx somepkg 2>&1 | cat", cwd);
		expect(r.segments.length).toBe(2);
		expect(r.segments[0].text).toBe("cd /tmp");
		expect(r.segments[1].text).toContain("npx somepkg");
		expect(r.segments[1].ops).toContain("|");
	});

	it("cd || npx 2>&1 | cat → || chain, npx joins pipe", async () => {
		const r = await parseCommand("cd /tmp || npx somepkg 2>&1 | cat", cwd);
		expect(r.segments.length).toBe(2);
		expect(r.segments[0].text).toBe("cd /tmp");
		expect(r.segments[1].text).toContain("npx somepkg");
		expect(r.segments[1].ops).toContain("|");
	});

	it("{ ls && npx } | cat → brace group, npx joins pipe", async () => {
		const r = await parseCommand("{ ls && npx somepkg } | cat", cwd);
		expect(r.segments.length).toBe(2);
		expect(r.segments[0].text).toBe("ls");
		expect(r.segments[1].text).toContain("npx somepkg");
		expect(r.segments[1].ops).toContain("|");
	});

	it("cd && ls && npx 2>&1 | cat → triple &&, npx joins pipe", async () => {
		const r = await parseCommand("cd /tmp && ls && npx somepkg 2>&1 | cat", cwd);
		expect(r.segments.length).toBe(3);
		expect(r.segments[0].text).toBe("cd /tmp");
		expect(r.segments[1].text).toBe("ls");
		expect(r.segments[2].text).toContain("npx somepkg");
		expect(r.segments[2].ops).toContain("|");
	});

	it("ls | grep && npx → pipe then &&, npx separate", async () => {
		const r = await parseCommand("ls | grep foo && npx somepkg", cwd);
		expect(r.segments.length).toBe(2);
		expect(r.segments[0].text).toContain("ls");
		expect(r.segments[0].text).toContain("| grep foo");
		expect(r.segments[0].ops).toContain("|");
		expect(r.segments[1].text).toBe("npx somepkg");
	});

	it("(cd ; npx) | cat → subshell with ;, npx joins pipe", async () => {
		const r = await parseCommand("(cd /tmp ; npx somepkg) | cat", cwd);
		expect(r.segments.length).toBe(2);
		expect(r.segments[0].text).toBe("cd /tmp");
		expect(r.segments[1].text).toContain("npx somepkg");
		expect(r.segments[1].ops).toContain("|");
	});

	it("(cd || npx) | cat → subshell with ||, npx joins pipe", async () => {
		const r = await parseCommand("(cd /tmp || npx somepkg) | cat", cwd);
		expect(r.segments.length).toBe(2);
		expect(r.segments[0].text).toBe("cd /tmp");
		expect(r.segments[1].text).toContain("npx somepkg");
		expect(r.segments[1].ops).toContain("|");
	});

	it("(ls && echo && npx) | cat → subshell triple &&, npx joins pipe", async () => {
		const r = await parseCommand("(ls && echo ok && npx somepkg) | cat", cwd);
		expect(r.segments.length).toBe(3);
		expect(r.segments[0].text).toBe("ls");
		expect(r.segments[1].text).toBe("echo ok");
		expect(r.segments[2].text).toContain("npx somepkg");
		expect(r.segments[2].ops).toContain("|");
	});

	// — safe chains should still split correctly (auto-allow path) —
	it("cd && ls 2>&1 | grep → safe chain, 2 segments", async () => {
		const r = await parseCommand("cd /tmp && ls 2>&1 | grep foo", cwd);
		expect(r.segments.length).toBe(2);
		expect(r.segments[0].text).toBe("cd /tmp");
		expect(r.segments[1].text).toContain("ls");
		expect(r.segments[1].ops).toContain("|");
	});

	it("cd && ls && cat 2>&1 | grep → triple safe chain, 3 segments", async () => {
		const r = await parseCommand("cd /tmp && ls && cat file 2>&1 | grep foo", cwd);
		expect(r.segments.length).toBe(3);
		expect(r.segments[0].text).toBe("cd /tmp");
		expect(r.segments[1].text).toBe("ls");
		expect(r.segments[2].text).toContain("cat file");
		expect(r.segments[2].ops).toContain("|");
	});
});

describe("parseCommand: bare / root path", () => {
	it("extracts / as a path from find /", async () => {
		const r = await parseCommand("find / -iname '*.txt'", cwd);
		expect(r.paths).toContain("/");
	});

	it("extracts / as a path from find / -iname with pipe", async () => {
		const r = await parseCommand("find / -iname '*gallop*' 2>/dev/null | grep -v proc | head -50", cwd);
		expect(r.paths).toContain("/");
	});

	it("extracts / as a path from grep -r /", async () => {
		const r = await parseCommand("grep -r pattern /", cwd);
		expect(r.paths).toContain("/");
	});

	it("extracts / as a path from ls /", async () => {
		const r = await parseCommand("ls /", cwd);
		expect(r.paths).toContain("/");
	});

	it("still filters // (double slash noise)", async () => {
		const r = await parseCommand("echo //", cwd);
		expect(r.paths).toHaveLength(0);
	});
});

describe("parseCommand: ./ relative paths (P1 fix: isPathCandidate)", () => {
	it("extracts ./ relative path from path-aware command", async () => {
		const r = await parseCommand("cat ./src/index.ts", cwd);
		expect(r.paths.length).toBeGreaterThan(0);
		expect(r.paths[0]).toContain("src/index.ts");
	});

	it("extracts ./ relative path from redirect", async () => {
		const r = await parseCommand("echo hello > ./output.txt", cwd);
		expect(r.paths.length).toBeGreaterThan(0);
		expect(r.paths[0]).toContain("output.txt");
	});

	it("does not extract bare relative paths (no ./ prefix)", async () => {
		const r = await parseCommand("cat src/index.ts", cwd);
		expect(r.paths).toHaveLength(0);
	});
});
