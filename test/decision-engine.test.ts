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

import { describe, expect, it } from "vitest";
import { decide, FileRequest, McpRequest } from "../decision-engine";
import { createStore } from "../store";

const cwd = "/home/nczer/Projects";

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
	it("blocks .env", async () => {
		const store = createStore();
		const req: FileRequest = { type: "file", toolName: "read", filePath: ".env", cwd };
		const d = await decide(req, store);
		expect(d.kind).toBe("block");
		if (d.kind === "block") {
			expect(d.reason).toContain(".env");
		}
	});

	it("blocks .env.local", async () => {
		const store = createStore();
		const req: FileRequest = { type: "file", toolName: "read", filePath: ".env.local", cwd };
		const d = await decide(req, store);
		expect(d.kind).toBe("block");
	});

	it("blocks .env.production (glob match)", async () => {
		const store = createStore();
		const req: FileRequest = { type: "file", toolName: "read", filePath: ".env.production", cwd };
		const d = await decide(req, store);
		expect(d.kind).toBe("block");
	});

	it("blocks .ssh/id_rsa", async () => {
		const store = createStore();
		const req: FileRequest = { type: "file", toolName: "read", filePath: "~/.ssh/id_rsa", cwd };
		const d = await decide(req, store);
		expect(d.kind).toBe("block");
		if (d.kind === "block") {
			expect(d.reason).toContain(".ssh");
		}
	});

	it("blocks node_modules/package.json", async () => {
		const store = createStore();
		const req: FileRequest = { type: "file", toolName: "read", filePath: "node_modules/package.json", cwd };
		const d = await decide(req, store);
		expect(d.kind).toBe("block");
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
