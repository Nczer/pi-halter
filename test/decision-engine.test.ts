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
import { describe, expect, it } from "vitest";
import { decide, FileRequest, McpRequest } from "../decision-engine";
import { createStore } from "../store";

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
		store.addAllowed({ readDirs: ["/etc"] });
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
			expect(d.promptData.outsideDir).toBe("/var/log");
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

describe("File: allowRules", () => {
	it("inside cwd uses writePaths not writeDirs", async () => {
		const store = createStore();
		const req: FileRequest = { type: "file", toolName: "write", filePath: "src/out.txt", cwd };
		const d = await decide(req, store);
		if (d.kind === "prompt") {
			expect(d.allowRules.writeDirs).toBeUndefined();
			expect(Array.isArray(d.allowRules.writePaths)).toBe(true);
		}
	});

	it("outside cwd has allowFileRules targeting specific file", async () => {
		const store = createStore();
		const req: FileRequest = { type: "file", toolName: "write", filePath: "/var/log/out.txt", cwd };
		const d = await decide(req, store);
		if (d.kind === "prompt") {
			expect(d.allowFileRules).toBeDefined();
			if (d.allowFileRules) {
				expect(d.allowFileRules.writePaths?.[0]).toBe("/var/log/out.txt");
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

describe("MCP: allowRules", () => {
	it("includes server in allowRules", async () => {
		const store = createStore();
		const req: McpRequest = { type: "mcp", server: "blender", tool: "render" };
		const d = await decide(req, store);
		if (d.kind === "prompt") {
			expect(d.allowRules.mcpServers?.[0]).toBe("blender");
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

	it("allowRules has specific sigs, allowBroaderRules has parent command", async () => {
		const store = createStore();
		const d = await decide({ type: "bash", command: "npm test", cwd }, store);
		if (d.kind === "prompt") {
			expect(d.allowRules.bashSigs).toContain("npm test");
			expect(d.allowBroaderRules).toBeDefined();
			expect(d.allowBroaderRules!.bashSigs).toContain("npm");
			expect(d.includeBroaderOption).toBe(true);
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
});
