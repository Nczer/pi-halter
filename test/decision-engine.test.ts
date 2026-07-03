/**
 * Decision engine tests — file and MCP requests.
 *
 * Governing principles (see cases.test.ts for full bash matrix):
 *   1. Write → prompt (mkdir/touch are safe creation, auto-allow)
 *   2. Read inside cwd → auto-allow
 *   3. Code execution → prompt (unless trusted script)
 *   4. Outside cwd → prompt first time, remembered → auto-allow
 *   5. Unsafe patterns → always prompt (DSP bypasses)
 */

import path from "node:path";
import os from "node:os";
import fs from "node:fs";
import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { decide, FileRequest, McpRequest } from "../decision-engine";
import { createStore } from "../store";
import { buildPrompt } from "../prompt-builder";
import { RuleGenerator } from "../rule-generator";

// Resolve symlinks for path assertions (macOS: /tmp → /private/tmp, /var → /private/var)
const realPath = (p: string) => {
	try { return fs.realpathSync(p); } catch {
		const dir = path.dirname(p);
		const base = path.basename(p);
		try { return path.join(fs.realpathSync(dir), base); } catch { return p; }
	}
};

const home = os.homedir();
const cwd = path.join(home, "Projects");

describe("File: Read inside cwd", () => {
	it("auto-allowed", async () => {
		const store = createStore();
		const req: FileRequest = { type: "file", toolName: "read", filePath: "src/index.ts", cwd };
		const d = await decide(req, store);
		expect(d.kind).toBe("auto-allow");
	});
});

describe("File: Read outside cwd", () => {
	it("prompts on first time", async () => {
		const store = createStore();
		const req: FileRequest = { type: "file", toolName: "read", filePath: "/etc/hosts", cwd };
		const d = await decide(req, store);
		expect(d.kind).toBe("prompt");
		if (d.kind === "prompt") {
			expect(d.promptData.type).toBe("file");
			expect(d.promptData.isWriteOp).toBe(false);
			expect(d.promptData.outsideDir).not.toBeNull();
		}
	});

	it("auto-allowed after adding dir", async () => {
		const store = createStore();
		// Add the resolved realpath of /etc (macOS: /private/etc)
		store.addAllowed({ readDirs: [realPath("/etc")] });
		const req: FileRequest = { type: "file", toolName: "read", filePath: "/etc/hosts", cwd };
		const d = await decide(req, store);
		expect(d.kind).toBe("auto-allow");
	});
});

describe("File: Write inside cwd", () => {
	it("prompts on first time", async () => {
		const store = createStore();
		const req: FileRequest = { type: "file", toolName: "write", filePath: "src/output.txt", cwd };
		const d = await decide(req, store);
		expect(d.kind).toBe("prompt");
		if (d.kind === "prompt") {
			expect(d.promptData.isWriteOp).toBe(true);
			expect(d.promptData.outsideDir).toBeNull();
		}
	});
});

describe("File: Write outside cwd", () => {
	it("prompts with write op and outside dir", async () => {
		const store = createStore();
		const req: FileRequest = { type: "file", toolName: "write", filePath: "/var/log/out.txt", cwd };
		const d = await decide(req, store);
		expect(d.kind).toBe("prompt");
		if (d.kind === "prompt") {
			expect(d.promptData.isWriteOp).toBe(true);
			// macOS: /var/log resolves to /private/var/log
			expect(d.promptData.outsideDir).toBe(realPath("/var/log"));
		}
	});
});

describe("File: Edit inside cwd", () => {
	it("prompts as write op", async () => {
		const store = createStore();
		const req: FileRequest = { type: "file", toolName: "edit", filePath: "src/index.ts", cwd };
		const d = await decide(req, store);
		expect(d.kind).toBe("prompt");
		if (d.kind === "prompt") {
			expect(d.promptData.isWriteOp).toBe(true);
		}
	});
});

describe("File: Denied paths (inside cwd)", () => {
	it("blocks .ssh/id_rsa", async () => {
		const store = createStore();
		const req: FileRequest = { type: "file", toolName: "read", filePath: "~/.ssh/id_rsa", cwd };
		const d = await decide(req, store);
		expect(d.kind).toBe("block");
		if (d.kind === "block") {
			expect(d.reason).toContain(".ssh");
		}
	});
});

describe("File: Warned paths (inside cwd)", () => {
	it("prompts for .env with credential warning", async () => {
		const store = createStore();
		const req: FileRequest = { type: "file", toolName: "read", filePath: ".env", cwd };
		const d = await decide(req, store);
		expect(d.kind).toBe("prompt");
		if (d.kind === "prompt") {
			expect(d.promptData.type).toBe("file");
			expect(d.promptData.warnedRule).toBe(".env");
		}
	});

	it("prompts for .env.local", async () => {
		const store = createStore();
		const req: FileRequest = { type: "file", toolName: "read", filePath: ".env.local", cwd };
		const d = await decide(req, store);
		expect(d.kind).toBe("prompt");
	});

	it("prompts for .env.production (glob match)", async () => {
		const store = createStore();
		const req: FileRequest = { type: "file", toolName: "read", filePath: ".env.production", cwd };
		const d = await decide(req, store);
		expect(d.kind).toBe("prompt");
		if (d.kind === "prompt") {
			expect(d.promptData.warnedRule).toBe(".env.*");
		}
	});
});

describe("File: node_modules allowed", () => {
	it("auto-allows node_modules/package.json (inside cwd)", async () => {
		const store = createStore();
		const req: FileRequest = { type: "file", toolName: "read", filePath: "node_modules/package.json", cwd };
		const d = await decide(req, store);
		expect(d.kind).toBe("auto-allow");
	});
});

describe("File: Write allowed after adding path", () => {
	it("auto-allows specific write path", async () => {
		const store = createStore();
		store.addAllowed({ writePaths: [`${cwd}/src/output.txt`] });
		const req: FileRequest = { type: "file", toolName: "write", filePath: "src/output.txt", cwd };
		const d = await decide(req, store);
		expect(d.kind).toBe("auto-allow");
	});
});

describe("File: rules", () => {
	it("inside cwd uses writePaths not writeDirs", async () => {
		const store = createStore();
		const req: FileRequest = { type: "file", toolName: "write", filePath: "src/out.txt", cwd };
		const d = await decide(req, store);
		if (d.kind === "prompt") {
			const rules = RuleGenerator.generatePrimaryRules(d.promptData);
			expect(rules.writeDirs).toBeUndefined();
			expect(Array.isArray(rules.writePaths)).toBe(true);
		}
	});

	it("outside cwd has file-only rules targeting specific file", async () => {
		const store = createStore();
		const req: FileRequest = { type: "file", toolName: "write", filePath: "/var/log/out.txt", cwd };
		const d = await decide(req, store);
		if (d.kind === "prompt") {
			const fileOnlyRules = RuleGenerator.generateFileOnlyRules(d.promptData);
			expect(fileOnlyRules).toBeDefined();
			if (fileOnlyRules) {
				// macOS: /var/log/out.txt resolves to /private/var/log/out.txt
				expect(fileOnlyRules.writePaths?.[0]).toBe(realPath("/var/log/out.txt"));
			}
		}
	});
});

describe("MCP: First time", () => {
	it("prompts on first use", async () => {
		const store = createStore();
		const req: McpRequest = { type: "mcp", server: "context7", tool: "resolve-library-id" };
		const d = await decide(req, store);
		expect(d.kind).toBe("prompt");
		if (d.kind === "prompt") {
			expect(d.promptData.type).toBe("mcp");
			expect(d.promptData.server).toBe("context7");
			expect(d.promptData.tool).toBe("resolve-library-id");
		}
	});
});

describe("MCP: Auto-allow after approval", () => {
	it("auto-allows approved server", async () => {
		const store = createStore();
		store.addAllowed({ mcpServers: ["context7"] });
		const req: McpRequest = { type: "mcp", server: "context7", tool: "resolve-library-id" };
		const d = await decide(req, store);
		expect(d.kind).toBe("auto-allow");
	});
});

describe("MCP: With argsPreview", () => {
	it("passes through argsPreview", async () => {
		const store = createStore();
		const req: McpRequest = {
			type: "mcp",
			server: "exa",
			tool: "web_search",
			argsPreview: "how to build a tree",
		};
		const d = await decide(req, store);
		if (d.kind === "prompt") {
			expect(d.promptData.argsPreview).toBe("how to build a tree");
		}
	});
});

describe("MCP: Server extraction from tool name", () => {
	it("extracts server from tool name", async () => {
		const store = createStore();
		const req: McpRequest = { type: "mcp", server: "", tool: "joplin:get_notes" };
		const d = await decide(req, store);
		if (d.kind === "prompt") {
			expect(d.promptData.server).toBe("joplin");
		}
	});
});

describe("MCP: rules", () => {
	it("includes server in rules", async () => {
		const store = createStore();
		const req: McpRequest = { type: "mcp", server: "blender", tool: "render" };
		const d = await decide(req, store);
		if (d.kind === "prompt") {
			const rules = RuleGenerator.generatePrimaryRules(d.promptData);
			expect(rules.mcpServers?.[0]).toBe("blender");
		}
	});
});

describe("MCP: unknown server blocked", () => {
	it("blocks unknown server", async () => {
		const store = createStore();
		const req: McpRequest = { type: "mcp", server: "unknown", tool: "some_tool" };
		const d = await decide(req, store);
		expect(d.kind).toBe("block");
		if (d.kind === "block") {
			expect(d.reason).toContain("unresolvable");
		}
	});
});

describe("Bash: empty segments guard", () => {
	it("does not auto-allow command with zero segments (heredoc to interpreter)", async () => {
		const store = createStore();
		const d = await decide(
			{ type: "bash", command: "python3 << 'PYEOF'\nimport os\nPYEOF", cwd },
			store,
		);
		// Even if parser produces zero segments, should NOT vacuously auto-allow
		expect(d.kind).toBe("prompt");
	});

	it("does not auto-allow bash heredoc with zero segments", async () => {
		const store = createStore();
		const d = await decide(
			{ type: "bash", command: "bash << 'EOF'\nrm -rf /\nEOF", cwd },
			store,
		);
		expect(d.kind).toBe("prompt");
	});
});

describe("Bash: safe subcommands", () => {
	it("auto-allows npm ls (read-only)", async () => {
		const store = createStore();
		const d = await decide({ type: "bash", command: "npm ls", cwd }, store);
		expect(d.kind).toBe("auto-allow");
	});

	it("auto-allows tsc", async () => {
		const store = createStore();
		const d = await decide({ type: "bash", command: "tsc", cwd }, store);
		expect(d.kind).toBe("auto-allow");
	});

	it("auto-allows tsc --noEmit", async () => {
		const store = createStore();
		const d = await decide({ type: "bash", command: "tsc --noEmit", cwd }, store);
		expect(d.kind).toBe("auto-allow");
	});

	it("prompts for npm test (arbitrary script)", async () => {
		const store = createStore();
		const d = await decide({ type: "bash", command: "npm test", cwd }, store);
		expect(d.kind).toBe("prompt");
	});

	it("prompts for npm run build (arbitrary script)", async () => {
		const store = createStore();
		const d = await decide({ type: "bash", command: "npm run build", cwd }, store);
		expect(d.kind).toBe("prompt");
	});

	it("prompts for npm install (not a safe subcommand)", async () => {
		const store = createStore();
		const d = await decide({ type: "bash", command: "npm install", cwd }, store);
		expect(d.kind).toBe("prompt");
	});

	it("prompts for npm publish", async () => {
		const store = createStore();
		const d = await decide({ type: "bash", command: "npm publish", cwd }, store);
		expect(d.kind).toBe("prompt");
	});
});

describe("Bash: granular allow (subcommand vs broader)", () => {
	it("npm test signature is 'npm test', not 'npm'", async () => {
		const store = createStore();
		const d = await decide({ type: "bash", command: "npm test", cwd }, store);
		if (d.kind === "prompt") {
			expect(d.promptData.signatures).toContain("npm test");
		}
	});

	it("npm install signature is 'npm install', not 'npm'", async () => {
		const store = createStore();
		const d = await decide({ type: "bash", command: "npm install", cwd }, store);
		if (d.kind === "prompt") {
			expect(d.promptData.signatures).toContain("npm install");
		}
	});

	it("rules have specific sigs, broader rules have parent command", async () => {
		const store = createStore();
		const d = await decide({ type: "bash", command: "npm test", cwd }, store);
		if (d.kind === "prompt") {
			const rules = RuleGenerator.generatePrimaryRules(d.promptData);
			expect(rules.bashSigs).toContain("npm test");
			const broaderRules = RuleGenerator.generateBroaderRules(d.promptData);
			expect(broaderRules).toBeDefined();
			expect(broaderRules!.bashSigs).toContain("npm");
		}
	});

	it("allowing 'npm test' does not auto-allow 'npm install'", async () => {
		const store = createStore();
		store.addAllowed({ bashSigs: ["npm test"] });
		const dTest = await decide({ type: "bash", command: "npm test", cwd }, store);
		expect(dTest.kind).toBe("auto-allow");

		const dInstall = await decide({ type: "bash", command: "npm install", cwd }, store);
		expect(dInstall.kind).toBe("prompt");
	});

	it("allowing 'npm' auto-allows all npm commands", async () => {
		const store = createStore();
		store.addAllowed({ bashSigs: ["npm"] });
		const dTest = await decide({ type: "bash", command: "npm test", cwd }, store);
		expect(dTest.kind).toBe("auto-allow");
	});

	it("non-package-manager commands do not get broader option", async () => {
		const store = createStore();
		const d = await decide({ type: "bash", command: "sed -i 's/foo/bar/' file.txt", cwd }, store);
		if (d.kind === "prompt") {
			// sed is not a package manager — no broader option
			const broaderRules = RuleGenerator.generateBroaderRules(d.promptData);
			expect(broaderRules).toBeUndefined();
		}
	});
});

describe("Integration: decide → buildPrompt", () => {
	it("trusted script with outside path: alwaysLabel shows path not command", async () => {
		const store = createStore();
		const d = await decide(
			{ type: "bash", command: `uv run --with pymupdf python ${home}/.pi/agent/skills/pdf/scripts/pdf_extract.py /mnt/data/file.pdf`, cwd },
			store,
		);
		expect(d.kind).toBe("prompt");
		if (d.kind === "prompt") {
			expect(d.promptData.needsPathApproval).toBe(true);
			expect(d.promptData.needsCommandApproval).toBe(false);
			const prompt = buildPrompt(d);
			expect(prompt.title).toBe("Path");
			expect(prompt.alwaysLabel).toContain("Read /mnt/data/*");
			expect(prompt.alwaysLabel).not.toContain("uv run");
		}
	});

	it("trusted script with outside path: tier2 confirms path only", async () => {
		const store = createStore();
		const d = await decide(
			{ type: "bash", command: `uv run --with pymupdf python ${home}/.pi/agent/skills/pdf/scripts/pdf_extract.py /mnt/data/file.pdf`, cwd },
			store,
		);
		if (d.kind === "prompt") {
			const prompt = buildPrompt(d);
			expect(prompt.tier2Everything.body).toContain("/mnt/data/*");
			expect(prompt.tier2Everything.body).not.toContain("uv run");
			expect(prompt.tier2Paths).toBeUndefined();
		}
	});

	it("untrusted command with outside path: alwaysLabel shows command sig", async () => {
		const store = createStore();
		const d = await decide(
			{ type: "bash", command: "npm test /mnt/data/file.txt", cwd },
			store,
		);
		if (d.kind === "prompt") {
			const prompt = buildPrompt(d);
			expect(prompt.alwaysLabel).toContain("npm test *");
		}
	});

	it("untrusted package in --with: prompts for command approval", async () => {
		const store = createStore();
		const d = await decide(
			{ type: "bash", command: `uv run --with evil-pkg python ${home}/.pi/agent/skills/pdf/scripts/pdf_extract.py /tmp/file.pdf`, cwd },
			store,
		);
		expect(d.kind).toBe("prompt");
		if (d.kind === "prompt") {
			// Script is trusted but package is not → command is not simple
			expect(d.promptData.needsCommandApproval).toBe(true);
		}
	});
});

// ── Retry-loop prevention (RetryLoopRule through decide pipeline) ───────

describe("Bash: retry-loop prevention", () => {
	let clock: number;
	let dateNowSpy: ReturnType<typeof vi.spyOn>;

	beforeEach(() => {
		clock = 1_000_000; // non-zero so getLastAbort returns a truthy timestamp
		dateNowSpy = vi.spyOn(Date, "now").mockImplementation(() => clock);
	});

	afterEach(() => {
		dateNowSpy.mockRestore();
	});

	it("blocks a command aborted within ABORT_REMEMBER_MS", async () => {
		const store = createStore(() => clock);
		store.recordAbort("rm -rf /tmp");
		clock = 1_000_000 + 30_000; // 30s later, within 60s threshold
		const d = await decide({ type: "bash", command: "rm -rf /tmp", cwd }, store);
		expect(d.kind).toBe("block");
		if (d.kind === "block") {
			expect(d.reason).toContain("aborted");
		}
	});

	it("does not block after ABORT_REMEMBER_MS threshold", async () => {
		const store = createStore(() => clock);
		store.recordAbort("rm -rf /tmp");
		clock = 1_000_000 + 61_000; // 61s later, past 60s threshold
		const d = await decide({ type: "bash", command: "rm -rf /tmp", cwd }, store);
		expect(d.kind).not.toBe("block");
		// rm is unsafe + /tmp is outside cwd → should prompt
		expect(d.kind).toBe("prompt");
	});

	it("only blocks the exact aborted command, not others", async () => {
		const store = createStore(() => clock);
		store.recordAbort("rm -rf /tmp");
		clock = 1_000_000 + 10_000;
		const d = await decide({ type: "bash", command: "ls", cwd }, store);
		expect(d.kind).toBe("auto-allow");
	});
});

// ── FastAllow path-token guard ─────────────────────────────────────────

describe("Bash: FastAllow path-token guard", () => {
	// FastAllowRule auto-allows trivial commands (cat, ls, ...) UNLESS a token
	// starts with /, ~/, ./, or ../ — those must go through analysis for path checks.

	it("auto-allows 'cat x' (plain, no path token)", async () => {
		const store = createStore();
		const d = await decide({ type: "bash", command: "cat x", cwd }, store);
		expect(d.kind).toBe("auto-allow");
	});

	it("prompts for 'cat ~/x' (~/ skips FastAllow, analysis catches outside cwd)", async () => {
		const store = createStore();
		const d = await decide({ type: "bash", command: "cat ~/x", cwd }, store);
		// Without the guard, cat ~/x would fast-allow and skip the outside-path check.
		expect(d.kind).toBe("prompt");
	});

	it("prompts for 'cat /etc/passwd' (/ skips FastAllow, analysis catches outside cwd)", async () => {
		const store = createStore();
		const d = await decide({ type: "bash", command: "cat /etc/passwd", cwd }, store);
		expect(d.kind).toBe("prompt");
	});

	it("prompts for 'ls /var/log' (/ skips FastAllow, outside cwd)", async () => {
		const store = createStore();
		const d = await decide({ type: "bash", command: "ls /var/log", cwd }, store);
		expect(d.kind).toBe("prompt");
	});
});
