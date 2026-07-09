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

	describe("parseCommand: backslash-escaped paths", () => {
		it("strips backslash before space (\\) in path", async () => {
			// find /tmp/foo\ bar → resolved path should not contain backslash
			const r = await parseCommand("find /tmp/foo\\ bar -type f", cwd);
			expect(r.paths.length).toBeGreaterThan(0);
			const p = r.paths[0];
			expect(p).not.toContain("\\");
			expect(p).toContain("/tmp/foo bar");
		});

		it("strips backslash before bracket (\[) in path", async () => {
			const r = await parseCommand("cat /tmp/\\[test\\].txt", cwd);
			expect(r.paths.length).toBeGreaterThan(0);
			const p = r.paths[0];
			expect(p).not.toContain("\\");
			expect(p).toContain("/tmp/[test].txt");
		});

		it("strips backslash before space and bracket in complex path (find)", async () => {
			// Simulating: find /path/[dir]\ name/file
			const r = await parseCommand("find /tmp/\\[dir\\]\\ name/file -type f", cwd);
			expect(r.paths.length).toBeGreaterThan(0);
			const p = r.paths[0];
			expect(p).not.toContain("\\");
			expect(p).toContain("/tmp/[dir] name/file");
		});

		it("preserves double-backslash (\\) as literal backslash", async () => {
			// \\ → \ (single literal backslash)
			const r = await parseCommand("cat /tmp/foo\\\\bar", cwd);
			expect(r.paths.length).toBeGreaterThan(0);
			const p = r.paths[0];
			expect(p).toContain("foo\\bar");
			expect(p).not.toContain("\\\\");
		});

		it("preserves unescaped path without backslashes", async () => {
			const r = await parseCommand("cat /tmp/normal_path.txt", cwd);
			expect(r.paths.length).toBeGreaterThan(0);
			const p = r.paths[0];
			expect(p).toContain("/tmp/normal_path.txt");
			expect(p).not.toContain("\\");
		});
	});
});

describe("parseCommand: per-segment hasSubshell", () => {
	it("detects subshell in command", async () => {
		const r = await parseCommand("cat $(echo /etc/hosts)", cwd);
		expect(r.segments.some(s => s.hasSubshell)).toBe(true);
	});

	it("no subshell on simple command", async () => {
		const r = await parseCommand("ls -la", cwd);
		expect(r.segments.some(s => s.hasSubshell)).toBe(false);
	});
});

describe("parseCommand: command substitution", () => {
	it("detects $", async () => {
		const r = await parseCommand("$(cat /etc/passwd)", cwd);
		expect(r.segments.some(s => s.hasSubshell)).toBe(true);
	});

	it("detects backticks", async () => {
		const r = await parseCommand("`whoami`", cwd);
		expect(r.segments.some(s => s.hasSubshell)).toBe(true);
	});

	it("detects process substitution", async () => {
		const r = await parseCommand("cat <(ls)", cwd);
		expect(r.segments.some(s => s.hasSubshell)).toBe(true);
	});
});

describe("parseCommand: subshellTexts extraction", () => {
	it("basename in $() extracts inner text", async () => {
		const r = await parseCommand('echo "$(basename /path/to/file)"', cwd);
		const seg = r.segments.find(s => s.hasSubshell);
		expect(seg?.subshellTexts).toBeDefined();
		expect(seg!.subshellTexts!).toContain("basename /path/to/file");
	});

	it("backtick substitution extracts inner text", async () => {
		const r = await parseCommand("echo `echo hello`", cwd);
		const seg = r.segments.find(s => s.hasSubshell);
		expect(seg?.subshellTexts).toBeDefined();
		expect(seg!.subshellTexts!).toContain("echo hello");
	});

	it("multiple subshells extract all inner texts", async () => {
		const r = await parseCommand("echo \"$(basename a) $(dirname b)\"", cwd);
		const seg = r.segments.find(s => s.hasSubshell);
		expect(seg?.subshellTexts).toBeDefined();
		expect(seg!.subshellTexts!.length).toBe(2);
		expect(seg!.subshellTexts!).toContain("basename a");
		expect(seg!.subshellTexts!).toContain("dirname b");
	});

	it("no subshell returns empty subshellTexts", async () => {
		const r = await parseCommand("ls -la", cwd);
		const seg = r.segments[0];
		expect(seg.subshellTexts).toBeDefined();
		expect(seg.subshellTexts!.length).toBe(0);
	});

	it("process substitution extracts inner text", async () => {
		const r = await parseCommand("cat <(echo hi)", cwd);
		const seg = r.segments.find(s => s.hasSubshell);
		expect(seg?.subshellTexts).toBeDefined();
		expect(seg!.subshellTexts!).toContain("echo hi");
	});
});

describe("parseCommand: no subshell", () => {
	it("simple command has no subshell", async () => {
		const r = await parseCommand("ls -la", cwd);
		expect(r.segments.some(s => s.hasSubshell)).toBe(false);
	});

	it("pipeline has no subshell", async () => {
		const r = await parseCommand("cat file.txt | grep pattern", cwd);
		expect(r.segments.some(s => s.hasSubshell)).toBe(false);
	});

	it("single-quoted $() not flagged (literal string)", async () => {
		const r = await parseCommand("echo 'hello $(world)'", cwd);
		expect(r.segments.some(s => s.hasSubshell)).toBe(false);
	});
});

describe("parseCommand: edge cases", () => {
	it("empty string has no subshell", async () => {
		const r = await parseCommand("", cwd);
		expect(r.segments.length).toBe(0);
	});

	it("echo has no subshell", async () => {
		const r = await parseCommand("echo hello", cwd);
		expect(r.segments.some(s => s.hasSubshell)).toBe(false);
	});
});

describe("parseCommand: redirect fallback for empty compound", () => {
	it("empty subshell with write redirect produces a redirect-only segment", async () => {
		// Bug 4: () > out had its redirect silently dropped because the compound
		// child walk produced zero segments. The redirect should survive.
		const r = await parseCommand("() > /tmp/out.txt", cwd);
		expect(r.segments.length).toBeGreaterThanOrEqual(1);
		// The segment should contain the redirect text
		const segText = r.segments.map(s => s.text).join(" ");
		expect(segText).toContain("/tmp/out.txt");
	});

	it("empty subshell with multiple redirects", async () => {
		const r = await parseCommand("() > /tmp/out.txt 2>/tmp/err.txt", cwd);
		expect(r.segments.length).toBeGreaterThanOrEqual(1);
		const segText = r.segments.map(s => s.text).join(" ");
		expect(segText).toContain("/tmp/out.txt");
		expect(segText).toContain("/tmp/err.txt");
	});

	it("non-empty subshell with redirect still works normally", async () => {
		const r = await parseCommand("(echo hi) > /tmp/out.txt", cwd);
		expect(r.segments.length).toBeGreaterThanOrEqual(1);
		const segText = r.segments.map(s => s.text).join(" ");
		expect(segText).toContain("echo hi");
		expect(segText).toContain("/tmp/out.txt");
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

describe("parseCommand: && + || precedence mixed chains", () => {
	it("ls && cat a || echo fallback → 3 segments", async () => {
		const r = await parseCommand("ls && cat a || echo fallback", cwd);
		expect(r.segments).toHaveLength(3);
		expect(r.segments[0].text).toBe("ls");
		expect(r.segments[1].text).toBe("cat a");
		expect(r.segments[2].text).toBe("echo fallback");
	});

	it("ls || cat a && rm b → 3 segments", async () => {
		const r = await parseCommand("ls || cat a && rm b", cwd);
		expect(r.segments).toHaveLength(3);
		expect(r.segments[0].text).toBe("ls");
		expect(r.segments[1].text).toBe("cat a");
		expect(r.segments[2].text).toBe("rm b");
	});

	it("ls && cat a && rm b && echo ok → 4 segments", async () => {
		const r = await parseCommand("ls && cat a && rm b && echo ok", cwd);
		expect(r.segments).toHaveLength(4);
	});

	it("ls || cat a || rm b || echo ok → 4 segments", async () => {
		const r = await parseCommand("ls || cat a || rm b || echo ok", cwd);
		expect(r.segments).toHaveLength(4);
	});

	it("ls && cat a || rm b && echo ok → 4 segments", async () => {
		const r = await parseCommand("ls && cat a || rm b && echo ok", cwd);
		expect(r.segments).toHaveLength(4);
	});

	it("ls || cat a && rm b || echo ok → 4 segments", async () => {
		const r = await parseCommand("ls || cat a && rm b || echo ok", cwd);
		expect(r.segments).toHaveLength(4);
	});
});

describe("parseCommand: trailing & on compound commands", () => {
	it("ls && cat & → 2 segments, backgrounding stripped", async () => {
		const r = await parseCommand("ls && cat &", cwd);
		expect(r.segments).toHaveLength(2);
		expect(r.segments[0].text).toBe("ls");
		expect(r.segments[1].text).toBe("cat");
	});

	it("rm a && cat b & → 2 segments, backgrounding stripped", async () => {
		const r = await parseCommand("rm a && cat b &", cwd);
		expect(r.segments).toHaveLength(2);
		expect(r.segments[0].text).toBe("rm a");
		expect(r.segments[1].text).toBe("cat b");
	});

	it("(ls && cat) & → subshell segments extracted, & stripped", async () => {
		const r = await parseCommand("(ls && cat) &", cwd);
		expect(r.segments.length).toBeGreaterThanOrEqual(2);
	});

	it("{ ls ; cat } & → brace segments extracted, & stripped", async () => {
		const r = await parseCommand("{ ls ; cat } &", cwd);
		expect(r.segments.length).toBeGreaterThanOrEqual(2);
	});

	it("ls | grep foo & → 1 segment with pipe, & stripped", async () => {
		const r = await parseCommand("ls | grep foo &", cwd);
		expect(r.segments).toHaveLength(1);
		expect(r.segments[0].ops).toContain("|");
	});
});

describe("parseCommand: multiple pipes with mixed safe/unsafe", () => {
	it("cat a | grep b | head → 1 segment (triple pipe)", async () => {
		const r = await parseCommand("cat a | grep b | head", cwd);
		expect(r.segments).toHaveLength(1);
		expect(r.segments[0].text).toContain("cat a");
		expect(r.segments[0].text).toContain("grep b");
		expect(r.segments[0].text).toContain("head");
	});

	it("cat a | sed -i s/x/y/ | head → 1 segment", async () => {
		const r = await parseCommand("cat a | sed -i s/x/y/ | head", cwd);
		expect(r.segments).toHaveLength(1);
	});

	it("echo foo | xargs rm | cat → 1 segment", async () => {
		const r = await parseCommand("echo foo | xargs rm | cat", cwd);
		expect(r.segments).toHaveLength(1);
	});

	it("cat a | grep b | wc | sed -i s/x/y/ → 1 segment (4 pipes)", async () => {
		const r = await parseCommand("cat a | grep b | wc | sed -i s/x/y/", cwd);
		expect(r.segments).toHaveLength(1);
	});
});

describe("parseCommand: empty compound bodies", () => {
	it("() → 1 segment (empty text)", async () => {
		const r = await parseCommand("()", cwd);
		expect(r.segments).toHaveLength(1);
		expect(r.segments[0].text).toBe("");
	});

	it("() && ls → 2 segments (empty + ls)", async () => {
		const r = await parseCommand("() && ls", cwd);
		expect(r.segments).toHaveLength(2);
		expect(r.segments[0].text).toBe("");
		expect(r.segments[1].text).toBe("ls");
	});

	it("ls && () → 2 segments (ls + empty)", async () => {
		const r = await parseCommand("ls && ()", cwd);
		expect(r.segments).toHaveLength(2);
		expect(r.segments[0].text).toBe("ls");
	});

	it("() | cat → 1 segment (subshell in pipeline)", async () => {
		const r = await parseCommand("() | cat", cwd);
		expect(r.segments.length).toBeGreaterThanOrEqual(1);
	});

	it("() > out.txt → 1 segment with redirect", async () => {
		const r = await parseCommand("() > out.txt", cwd);
		expect(r.segments.length).toBeGreaterThanOrEqual(1);
		const segText = r.segments.map(s => s.text).join(" ");
		expect(segText).toContain("out.txt");
	});

	it("{ } → 0 segments (empty brace group)", async () => {
		const r = await parseCommand("{ }", cwd);
		expect(r.segments).toHaveLength(0);
	});

	it("{ } && ls → 1 segment (empty brace dropped)", async () => {
		const r = await parseCommand("{ } && ls", cwd);
		expect(r.segments).toHaveLength(1);
		expect(r.segments[0].text).toBe("ls");
	});

	it("{ } | cat → 1 segment (brace in pipeline)", async () => {
		const r = await parseCommand("{ } | cat", cwd);
		expect(r.segments.length).toBeGreaterThanOrEqual(1);
	});
});

describe("parseCommand: heredoc inside compound", () => {
	it("if + cat heredoc → segment contains cat", async () => {
		const r = await parseCommand("if true; then cat << 'EOF'\nline1\nEOF; fi", cwd);
		expect(r.segments.length).toBeGreaterThanOrEqual(1);
		const segText = r.segments.map(s => s.text).join(" ");
		expect(segText).toContain("cat");
	});

	it("if + python3 heredoc → segment contains python3", async () => {
		const r = await parseCommand("if true; then python3 << 'PYEOF'\nimport os\nPYEOF; fi", cwd);
		expect(r.segments.length).toBeGreaterThanOrEqual(1);
		const segText = r.segments.map(s => s.text).join(" ");
		expect(segText).toContain("python3");
	});

	it("for + cat heredoc → segments extracted from loop body", async () => {
		const r = await parseCommand("for f in a b; do cat << EOF\n$f\nEOF; done", cwd);
		expect(r.segments.length).toBeGreaterThanOrEqual(1);
	});

	it("for + bash heredoc → segments extracted from loop body", async () => {
		const r = await parseCommand("for f in a b; do bash << EOF\nrm $f\nEOF; done", cwd);
		expect(r.segments.length).toBeGreaterThanOrEqual(1);
	});

	it("brace group + cat heredoc → segments extracted", async () => {
		const r = await parseCommand("{ cat << 'EOF'\nhello\nEOF; }", cwd);
		expect(r.segments.length).toBeGreaterThanOrEqual(1);
	});

	it("subshell + cat heredoc → segments extracted", async () => {
		const r = await parseCommand("(cat << 'EOF'\ndata\nEOF)", cwd);
		expect(r.segments.length).toBeGreaterThanOrEqual(1);
	});
});
