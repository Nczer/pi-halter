import { describe, expect, it } from "vitest";
import { extractPathsFromBash, extractSegments, hasSubshell } from "../bash-parser";

const cwd = "/home/nczer/Projects";

describe("extractPathsFromBash: basic paths", () => {
	it("does not extract relative paths (always inside cwd)", async () => {
		const paths = await extractPathsFromBash("cat src/index.ts", cwd);
		expect(paths).toHaveLength(0);
	});

	it("keeps absolute paths", async () => {
		const paths = await extractPathsFromBash("cat /etc/hosts", cwd);
		expect(paths).toContain("/etc/hosts");
	});

	it("expands tilde", async () => {
		const paths = await extractPathsFromBash("ls ~/foo", cwd);
		expect(paths.length).toBeGreaterThan(0);
		expect(paths[0]).toMatch(/^\/home\//);
	});

	it("flags-only command has no paths", async () => {
		const paths = await extractPathsFromBash("ls -la", cwd);
		expect(paths).toHaveLength(0);
	});
});

describe("extractPathsFromBash: redirects", () => {
	it("extracts redirect destination", async () => {
		const paths = await extractPathsFromBash("cat file.txt > /tmp/out.txt", cwd);
		expect(paths).toContain("/tmp/out.txt");
	});

	it("filters /dev/null", async () => {
		const paths = await extractPathsFromBash("echo hello 2>/dev/null", cwd);
		expect(paths).toHaveLength(0);
	});

	it("extracts input redirect", async () => {
		const paths = await extractPathsFromBash("cat < /tmp/in.txt", cwd);
		expect(paths).toContain("/tmp/in.txt");
	});
});

describe("extractPathsFromBash: quotes", () => {
	it("handles single quotes with absolute path", async () => {
		const paths = await extractPathsFromBash("cat '/tmp/file with spaces.txt'", cwd);
		expect(paths).toContain("/tmp/file with spaces.txt");
	});

	it("handles double quotes with absolute path", async () => {
		const paths = await extractPathsFromBash('cat "/tmp/file with spaces.txt"', cwd);
		expect(paths).toContain("/tmp/file with spaces.txt");
	});
});

describe("extractPathsFromBash: heredocs", () => {
	it("does not extract heredoc body as path", async () => {
		const paths = await extractPathsFromBash("cat << 'EOF'\n/etc/passwd\nEOF", cwd);
		expect(paths).toHaveLength(0);
	});
});

describe("extractPathsFromBash: comments", () => {
	it("does not extract commented paths", async () => {
		const paths = await extractPathsFromBash("ls # /etc/hosts", cwd);
		expect(paths).toHaveLength(0);
	});
});

describe("extractPathsFromBash: subshells", () => {
	it("does not crash on subshell", async () => {
		const paths = await extractPathsFromBash("cat $(echo /etc/hosts)", cwd);
		expect(Array.isArray(paths)).toBe(true);
	});
});

describe("extractPathsFromBash: non-path-aware commands", () => {
	it("echo is not path-aware", async () => {
		const paths = await extractPathsFromBash("echo /etc/hosts", cwd);
		expect(paths).toHaveLength(0);
	});
});

describe("extractPathsFromBash: URL filtering", () => {
	it("does not extract URLs as paths", async () => {
		const paths = await extractPathsFromBash("cat https://example.com", cwd);
		expect(paths).toHaveLength(0);
	});
});

describe("extractSegments: simple commands", () => {
	it("single command → 1 segment", async () => {
		const segs = await extractSegments("ls -la");
		expect(segs).toHaveLength(1);
		expect(segs[0].text).toBe("ls -la");
	});
});

describe("extractSegments: pipelines", () => {
	it("pipeline → 1 segment", async () => {
		const segs = await extractSegments("cat a | grep b");
		expect(segs).toHaveLength(1);
		expect(segs[0].ops).toContain("|");
	});

	it("multi-pipe → 1 segment", async () => {
		const segs = await extractSegments("cat a | grep b | wc -l");
		expect(segs).toHaveLength(1);
		expect(segs[0].ops).toContain("|");
	});
});

describe("extractSegments: && chains", () => {
	it("&& → 2 segments", async () => {
		const segs = await extractSegments("ls && cat file.txt");
		expect(segs).toHaveLength(2);
		expect(segs[0].text).toContain("ls");
		expect(segs[1].text).toContain("cat");
	});

	it("triple && → 3 segments", async () => {
		const segs = await extractSegments("ls && cat a && echo done");
		expect(segs).toHaveLength(3);
	});
});

describe("extractSegments: || chains", () => {
	it("|| → 2 segments", async () => {
		const segs = await extractSegments("ls || echo not found");
		expect(segs).toHaveLength(2);
	});
});

describe("extractSegments: ; chains", () => {
	it("; → 2 segments", async () => {
		const segs = await extractSegments("ls; cat file.txt");
		expect(segs).toHaveLength(2);
	});
});

describe("extractSegments: backgrounding", () => {
	it("backgrounding → 1 segment (& stripped)", async () => {
		const segs = await extractSegments("sleep 10 &");
		expect(segs).toHaveLength(1);
		expect(segs[0].text).toBe("sleep 10");
	});
});

describe("extractSegments: redirected_statement", () => {
	it("redirected command → 1 segment", async () => {
		const segs = await extractSegments("tr 'a-z' 'A-Z' < file.txt");
		expect(segs).toHaveLength(1);
		expect(segs[0].text).toContain("tr");
		expect(segs[0].text).toContain("file.txt");
	});

	it("&& chain with redirect → 2 segments", async () => {
		const segs = await extractSegments("rm a && ls b 2>/dev/null");
		expect(segs).toHaveLength(2);
		expect(segs[0].text).toBe("rm a");
		expect(segs[1].text).toContain("ls b");
		expect(segs[1].text).toContain("2>/dev/null");
	});
});

describe("extractSegments: compound + redirect", () => {
	it("pipeline with redirect → 1 segment", async () => {
		const segs = await extractSegments("cat a | grep b 2>/dev/null");
		expect(segs).toHaveLength(1);
	});

	it("for loop with redirect → segments extracted", async () => {
		const segs = await extractSegments("for f in a b; do rm $f; done 2>/dev/null");
		expect(segs.length).toBeGreaterThanOrEqual(1);
	});
});

describe("extractSegments: subshells", () => {
	it("subshell in pipeline → segments", async () => {
		const segs = await extractSegments("(rm a && ls b) | cat");
		expect(segs.length).toBeGreaterThanOrEqual(1);
	});
});

describe("extractSegments: heredocs", () => {
	it("heredoc does not crash segmentation", async () => {
		const segs = await extractSegments("cat << 'EOF'\nhello world\nEOF\n");
		expect(Array.isArray(segs)).toBe(true);
	});
});

describe("extractSegments: comments", () => {
	it("comment stripped from segment", async () => {
		const segs = await extractSegments("ls # comment");
		expect(segs).toHaveLength(1);
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
