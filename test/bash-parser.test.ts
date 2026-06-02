import path from "node:path";
import os from "node:os";
import { describe, expect, it } from "vitest";
import { parseCommand, hasSubshell } from "../bash-parser";

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
		expect(r.paths).toContain("/etc/hosts");
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
		expect(r.paths).toContain("/tmp/out.txt");
	});

	it("extracts input redirect", async () => {
		const r = await parseCommand("cat < /tmp/in.txt", cwd);
		expect(r.paths).toContain("/tmp/in.txt");
	});

	it("filters /dev/null", async () => {
		const r = await parseCommand("echo hello 2>/dev/null", cwd);
		expect(r.paths).toHaveLength(0);
	});

	it("handles single-quoted paths", async () => {
		const r = await parseCommand("cat '/tmp/file with spaces.txt'", cwd);
		expect(r.paths).toContain("/tmp/file with spaces.txt");
	});

	it("handles double-quoted paths", async () => {
		const r = await parseCommand('cat "/tmp/file with spaces.txt"', cwd);
		expect(r.paths).toContain("/tmp/file with spaces.txt");
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

describe("hasSubshell: command substitution", () => {
	it("detects $()", async () => {
		expect(await hasSubshell("$(cat /etc/passwd)")).toBe(true);
	});

	it("detects backticks", async () => {
		expect(await hasSubshell("`whoami`")).toBe(true);
	});

	it("detects process substitution", async () => {
		expect(await hasSubshell("cat <(ls)")).toBe(true);
	});
});

describe("hasSubshell: no subshell", () => {
	it("simple command has no subshell", async () => {
		expect(await hasSubshell("ls -la")).toBe(false);
	});

	it("pipeline has no subshell", async () => {
		expect(await hasSubshell("cat file.txt | grep pattern")).toBe(false);
	});

	it("single-quoted $() not flagged (literal string)", async () => {
		expect(await hasSubshell("echo 'hello $(world)'")).toBe(false);
	});
});

describe("hasSubshell: edge cases", () => {
	it("empty string has no subshell", async () => {
		expect(await hasSubshell("")).toBe(false);
	});

	it("echo has no subshell", async () => {
		expect(await hasSubshell("echo hello")).toBe(false);
	});
});
