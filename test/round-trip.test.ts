/**
 * Round-trip tests: prompt → allowRules → addAllowed → auto-allow.
 *
 * Verifies that the allowRules returned by a prompt decision, when fed back
 * into store.addAllowed(), actually produce auto-allow on the next request.
 *
 * Governing principles (see cases.test.ts for full bash matrix):
 *   1. Write → prompt (mkdir/touch are safe creation, auto-allow)
 *   2. Read inside cwd → auto-allow
 *   3. Code execution → prompt (unless trusted script)
 *   4. Outside cwd → prompt first time, remembered → auto-allow
 *   5. Unsafe patterns → always prompt (DSP bypasses, never auto-allowed after approval)
 */

import { describe, expect, it } from "vitest";
import { decide, BashRequest, FileRequest, McpRequest } from "../decision-engine";
import { createStore } from "../store";

const cwd = "/home/nczer/Projects";

// ─── Bash: unsafe commands never auto-allow (principle 5) ───
// Unsafe patterns → always prompt, even after "approval".
// The allowRules are still stored, but hasUnsafePattern blocks the signature-approval path.

describe("Round-trip: Bash unsafe commands never auto-allow", () => {
	it("rm → prompt → allowRules → still prompts (unsafe)", async () => {
		const store = createStore();

		const req: BashRequest = { type: "bash", command: "rm file.txt", cwd };
		const d1 = await decide(req, store);
		expect(d1.kind).toBe("prompt");

		if (d1.kind !== "prompt") throw new Error("expected prompt");
		store.addAllowed(d1.allowRules);

		const d2 = await decide(req, store);
		expect(d2.kind).toBe("prompt");
	});

	it("sed -i → prompt → allowRules → still prompts (unsafe)", async () => {
		const store = createStore();

		const req: BashRequest = { type: "bash", command: "sed -i s/a/b/ file.txt", cwd };
		const d1 = await decide(req, store);
		expect(d1.kind).toBe("prompt");

		if (d1.kind !== "prompt") throw new Error("expected prompt");
		store.addAllowed(d1.allowRules);

		const d2 = await decide(req, store);
		expect(d2.kind).toBe("prompt");
	});

	it("&& chain with unsafe → prompt → allowRules → still prompts (unsafe)", async () => {
		const store = createStore();

		const req: BashRequest = { type: "bash", command: "ls && rm file.txt", cwd };
		const d1 = await decide(req, store);
		expect(d1.kind).toBe("prompt");

		if (d1.kind !== "prompt") throw new Error("expected prompt");
		store.addAllowed(d1.allowRules);

		const d2 = await decide(req, store);
		expect(d2.kind).toBe("prompt");
	});

	it("chmod → prompt → allowRules → still prompts (unsafe)", async () => {
		const store = createStore();

		const req: BashRequest = { type: "bash", command: "chmod 755 file.txt", cwd };
		const d1 = await decide(req, store);
		expect(d1.kind).toBe("prompt");

		if (d1.kind !== "prompt") throw new Error("expected prompt");
		store.addAllowed(d1.allowRules);

		const d2 = await decide(req, store);
		expect(d2.kind).toBe("prompt");
	});
});

// ─── Bash: command + outside paths (dual approval) ───

describe("Round-trip: Bash command + outside paths", () => {
	it("sed -i outside cwd → prompt → allowRules (both) → still prompts (unsafe)", async () => {
		const store = createStore();

		const req: BashRequest = { type: "bash", command: "sed -i s/a/b/ /etc/hosts", cwd };
		const d1 = await decide(req, store);
		expect(d1.kind).toBe("prompt");
		if (d1.kind !== "prompt") throw new Error("expected prompt");
		expect(d1.includePathsOption).toBe(true);

		// "Always (everything)" — both command and paths stored, but unsafe → still prompts
		store.addAllowed(d1.allowRules);
		const d2 = await decide(req, store);
		expect(d2.kind).toBe("prompt");
	});

	it("sed -i outside cwd → prompt → allowPathsRules (paths only) → still prompts on command", async () => {
		const store = createStore();

		const req: BashRequest = { type: "bash", command: "sed -i s/a/b/ /etc/hosts", cwd };
		const d1 = await decide(req, store);
		expect(d1.kind).toBe("prompt");
		if (d1.kind !== "prompt") throw new Error("expected prompt");

		// "Always (paths only)" — paths approved, command still needs approval
		if (d1.allowPathsRules) {
			store.addAllowed(d1.allowPathsRules);
			const d2 = await decide(req, store);
			expect(d2.kind).toBe("prompt");
			if (d2.kind === "prompt") {
				// Path approval is gone (already approved), only command remains
				expect(d2.promptData.needsPathApproval).toBe(false);
				expect(d2.promptData.needsCommandApproval).toBe(true);
			}
		}
	});

	it("cat outside cwd → prompt → allowRules (paths) → auto-allow", async () => {
		const store = createStore();

		const req: BashRequest = { type: "bash", command: "cat /etc/hosts", cwd };
		const d1 = await decide(req, store);
		expect(d1.kind).toBe("prompt");
		if (d1.kind !== "prompt") throw new Error("expected prompt");

		store.addAllowed(d1.allowRules);
		const d2 = await decide(req, store);
		expect(d2.kind).toBe("auto-allow");
	});
});

// ─── File: read outside cwd ───

describe("Round-trip: File read outside cwd", () => {
	it("read /etc/hosts → prompt → allowRules (readDirs) → auto-allow", async () => {
		const store = createStore();

		const req: FileRequest = { type: "file", toolName: "read", filePath: "/etc/hosts", cwd };
		const d1 = await decide(req, store);
		expect(d1.kind).toBe("prompt");
		if (d1.kind !== "prompt") throw new Error("expected prompt");

		store.addAllowed(d1.allowRules);
		const d2 = await decide(req, store);
		expect(d2.kind).toBe("auto-allow");
	});

	it("read /etc/hosts → prompt → allowFileRules (readPaths) → auto-allow specific file only", async () => {
		const store = createStore();

		const req: FileRequest = { type: "file", toolName: "read", filePath: "/etc/hosts", cwd };
		const d1 = await decide(req, store);
		expect(d1.kind).toBe("prompt");
		if (d1.kind !== "prompt") throw new Error("expected prompt");

		if (d1.allowFileRules) {
			store.addAllowed(d1.allowFileRules);

			// Same file → auto-allow
			const d2 = await decide(req, store);
			expect(d2.kind).toBe("auto-allow");

			// Different file in same dir → still prompts
			const req2: FileRequest = { type: "file", toolName: "read", filePath: "/etc/resolv.conf", cwd };
			const d3 = await decide(req2, store);
			expect(d3.kind).toBe("prompt");
		}
	});
});

// ─── File: write inside cwd ───

describe("Round-trip: File write inside cwd", () => {
	it("write inside cwd → prompt → allowRules (writePaths) → auto-allow", async () => {
		const store = createStore();

		const req: FileRequest = { type: "file", toolName: "write", filePath: "src/output.txt", cwd };
		const d1 = await decide(req, store);
		expect(d1.kind).toBe("prompt");
		if (d1.kind !== "prompt") throw new Error("expected prompt");

		store.addAllowed(d1.allowRules);
		const d2 = await decide(req, store);
		expect(d2.kind).toBe("auto-allow");
	});

	it("edit inside cwd → prompt → allowRules (writePaths) → auto-allow", async () => {
		const store = createStore();

		const req: FileRequest = { type: "file", toolName: "edit", filePath: "src/index.ts", cwd };
		const d1 = await decide(req, store);
		expect(d1.kind).toBe("prompt");
		if (d1.kind !== "prompt") throw new Error("expected prompt");

		store.addAllowed(d1.allowRules);
		const d2 = await decide(req, store);
		expect(d2.kind).toBe("auto-allow");
	});
});

// ─── File: write outside cwd ───

describe("Round-trip: File write outside cwd", () => {
	it("write /var/log/out.txt → prompt → allowRules (writeDirs) → auto-allow", async () => {
		const store = createStore();

		const req: FileRequest = { type: "file", toolName: "write", filePath: "/var/log/out.txt", cwd };
		const d1 = await decide(req, store);
		expect(d1.kind).toBe("prompt");
		if (d1.kind !== "prompt") throw new Error("expected prompt");

		store.addAllowed(d1.allowRules);
		const d2 = await decide(req, store);
		expect(d2.kind).toBe("auto-allow");
	});

	it("write /var/log/out.txt → prompt → allowFileRules (writePaths) → auto-allow specific file only", async () => {
		const store = createStore();

		const req: FileRequest = { type: "file", toolName: "write", filePath: "/var/log/out.txt", cwd };
		const d1 = await decide(req, store);
		expect(d1.kind).toBe("prompt");
		if (d1.kind !== "prompt") throw new Error("expected prompt");

		if (d1.allowFileRules) {
			store.addAllowed(d1.allowFileRules);

			// Same file → auto-allow
			const d2 = await decide(req, store);
			expect(d2.kind).toBe("auto-allow");

			// Different file in same dir → still prompts
			const req2: FileRequest = { type: "file", toolName: "write", filePath: "/var/log/other.txt", cwd };
			const d3 = await decide(req2, store);
			expect(d3.kind).toBe("prompt");
		}
	});
});

// ─── MCP round-trip ───

describe("Round-trip: MCP server approval", () => {
	it("context7 → prompt → allowRules → auto-allow", async () => {
		const store = createStore();

		const req: McpRequest = { type: "mcp", server: "context7", tool: "resolve-library-id" };
		const d1 = await decide(req, store);
		expect(d1.kind).toBe("prompt");
		if (d1.kind !== "prompt") throw new Error("expected prompt");

		store.addAllowed(d1.allowRules);
		const d2 = await decide(req, store);
		expect(d2.kind).toBe("auto-allow");
	});

	it("server approval covers all tools on that server", async () => {
		const store = createStore();

		const req1: McpRequest = { type: "mcp", server: "blender", tool: "render" };
		const d1 = await decide(req1, store);
		expect(d1.kind).toBe("prompt");
		if (d1.kind !== "prompt") throw new Error("expected prompt");

		store.addAllowed(d1.allowRules);

		// Different tool, same server → auto-allow
		const req2: McpRequest = { type: "mcp", server: "blender", tool: "scene_objects" };
		const d2 = await decide(req2, store);
		expect(d2.kind).toBe("auto-allow");
	});

	it("server extraction from tool name → allowRules → auto-allow", async () => {
		const store = createStore();

		const req: McpRequest = { type: "mcp", server: "", tool: "joplin:get_notes" };
		const d1 = await decide(req, store);
		expect(d1.kind).toBe("prompt");
		if (d1.kind !== "prompt") throw new Error("expected prompt");

		store.addAllowed(d1.allowRules);

		// Same server via explicit field → auto-allow
		const req2: McpRequest = { type: "mcp", server: "joplin", tool: "get_notes" };
		const d2 = await decide(req2, store);
		expect(d2.kind).toBe("auto-allow");
	});
});

// ─── Multi-request accumulation ───

describe("Round-trip: Multi-request accumulation", () => {
	it("two different unsafe bash commands still prompt after approval", async () => {
		const store = createStore();

		const req1: BashRequest = { type: "bash", command: "rm file.txt", cwd };
		const d1 = await decide(req1, store);
		expect(d1.kind).toBe("prompt");
		if (d1.kind !== "prompt") throw new Error("expected prompt");
		store.addAllowed(d1.allowRules);

		const req2: BashRequest = { type: "bash", command: "chmod 755 file.txt", cwd };
		const d2 = await decide(req2, store);
		expect(d2.kind).toBe("prompt");
		if (d2.kind !== "prompt") throw new Error("expected prompt");
		store.addAllowed(d2.allowRules);

		// Both still prompt — unsafe commands never auto-allow
		expect((await decide(req1, store)).kind).toBe("prompt");
		expect((await decide(req2, store)).kind).toBe("prompt");
	});

	it("safe bash command with outside path → prompt → allowRules → auto-allow", async () => {
		const store = createStore();

		const req1: BashRequest = { type: "bash", command: "cat /etc/hosts", cwd };
		const d1 = await decide(req1, store);
		expect(d1.kind).toBe("prompt");
		if (d1.kind !== "prompt") throw new Error("expected prompt");
		store.addAllowed(d1.allowRules);

		const req2: BashRequest = { type: "bash", command: "ls /var/log", cwd };
		const d2 = await decide(req2, store);
		expect(d2.kind).toBe("prompt");
		if (d2.kind !== "prompt") throw new Error("expected prompt");
		store.addAllowed(d2.allowRules);

		// Both auto-allow — safe commands + approved paths
		expect((await decide(req1, store)).kind).toBe("auto-allow");
		expect((await decide(req2, store)).kind).toBe("auto-allow");
	});

	it("read and write approvals are independent", async () => {
		const store = createStore();

		const readReq: FileRequest = { type: "file", toolName: "read", filePath: "/etc/hosts", cwd };
		const d1 = await decide(readReq, store);
		expect(d1.kind).toBe("prompt");
		if (d1.kind !== "prompt") throw new Error("expected prompt");
		store.addAllowed(d1.allowRules);

		// Read auto-allows
		expect((await decide(readReq, store)).kind).toBe("auto-allow");

		// Write to same dir still prompts (readDirs ≠ writeDirs)
		const writeReq: FileRequest = { type: "file", toolName: "write", filePath: "/etc/out.txt", cwd };
		expect((await decide(writeReq, store)).kind).toBe("prompt");
	});
});
