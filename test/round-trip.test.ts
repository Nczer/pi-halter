/**
 * Round-trip tests: prompt → RuleGenerator → addAllowed → auto-allow.
 *
 * Verifies that rules generated from a prompt decision's promptData,
 * when fed into store.addAllowed(), actually produce auto-allow on the next request.
 *
 * Governing principles (see cases.test.ts for full bash matrix):
 *   1. Write → prompt (mkdir/touch are safe creation, auto-allow)
 *   2. Read inside cwd → auto-allow
 *   3. Code execution → prompt (unless trusted script)
 *   4. Outside cwd → prompt first time, remembered → auto-allow
 *   5. Unsafe patterns → always prompt (DSP bypasses, never auto-allowed after approval)
 */

import path from "node:path";
import os from "node:os";
import { describe, expect, it } from "vitest";
import { decide, BashRequest, FileRequest, McpRequest } from "../decision-engine";
import { createStore } from "../store";
import { RuleGenerator } from "../rule-generator";

const home = os.homedir();
const cwd = path.join(home, "Projects");

// ─── Bash: unsafe commands never auto-allow (principle 5) ───
// Unsafe patterns → always prompt, even after "approval".
// Rules can be generated, but hasUnsafePattern blocks the signature-approval path.

describe("Round-trip: Bash unsafe commands never auto-allow", () => {
	it("rm → prompt → rules → still prompts (unsafe)", async () => {
		const store = createStore();

		const req: BashRequest = { type: "bash", command: "rm file.txt", cwd };
		const d1 = await decide(req, store);
		expect(d1.kind).toBe("prompt");

		if (d1.kind !== "prompt") throw new Error("expected prompt");
		store.addAllowed(RuleGenerator.generatePrimaryRules(d1.promptData));

		const d2 = await decide(req, store);
		expect(d2.kind).toBe("prompt");
	});

	it("sed -i → prompt → rules → still prompts (unsafe)", async () => {
		const store = createStore();

		const req: BashRequest = { type: "bash", command: "sed -i s/a/b/ file.txt", cwd };
		const d1 = await decide(req, store);
		expect(d1.kind).toBe("prompt");

		if (d1.kind !== "prompt") throw new Error("expected prompt");
		store.addAllowed(RuleGenerator.generatePrimaryRules(d1.promptData));

		const d2 = await decide(req, store);
		expect(d2.kind).toBe("prompt");
	});

	it("&& chain with unsafe → prompt → rules → still prompts (unsafe)", async () => {
		const store = createStore();

		const req: BashRequest = { type: "bash", command: "ls && rm file.txt", cwd };
		const d1 = await decide(req, store);
		expect(d1.kind).toBe("prompt");

		if (d1.kind !== "prompt") throw new Error("expected prompt");
		store.addAllowed(RuleGenerator.generatePrimaryRules(d1.promptData));

		const d2 = await decide(req, store);
		expect(d2.kind).toBe("prompt");
	});

	it("chmod → prompt → rules → still prompts (unsafe)", async () => {
		const store = createStore();

		const req: BashRequest = { type: "bash", command: "chmod 755 file.txt", cwd };
		const d1 = await decide(req, store);
		expect(d1.kind).toBe("prompt");

		if (d1.kind !== "prompt") throw new Error("expected prompt");
		store.addAllowed(RuleGenerator.generatePrimaryRules(d1.promptData));

		const d2 = await decide(req, store);
		expect(d2.kind).toBe("prompt");
	});
});

// ─── Bash: command + outside paths (dual approval) ───

describe("Round-trip: Bash command + outside paths", () => {
	it("sed -i outside cwd → prompt → rules (both) → still prompts (unsafe)", async () => {
		const store = createStore();

		const req: BashRequest = { type: "bash", command: "sed -i s/a/b/ /etc/hosts", cwd };
		const d1 = await decide(req, store);
		expect(d1.kind).toBe("prompt");
		if (d1.kind !== "prompt") throw new Error("expected prompt");

		// "Always (everything)" — both command and paths stored, but unsafe → still prompts
		store.addAllowed(RuleGenerator.generatePrimaryRules(d1.promptData));
		const d2 = await decide(req, store);
		expect(d2.kind).toBe("prompt");
	});

	it("sed -i outside cwd → prompt → paths-only rules → still prompts on command", async () => {
		const store = createStore();

		const req: BashRequest = { type: "bash", command: "sed -i s/a/b/ /etc/hosts", cwd };
		const d1 = await decide(req, store);
		expect(d1.kind).toBe("prompt");
		if (d1.kind !== "prompt") throw new Error("expected prompt");

		// "Always (paths only)" — paths approved, command still needs approval
		const pathsRules = RuleGenerator.generatePathsOnlyRules(d1.promptData);
		if (pathsRules) {
			store.addAllowed(pathsRules);
			const d2 = await decide(req, store);
			expect(d2.kind).toBe("prompt");
			if (d2.kind === "prompt") {
				// Path approval is gone (already approved), only command remains
				expect(d2.promptData.needsPathApproval).toBe(false);
				expect(d2.promptData.needsCommandApproval).toBe(true);
			}
		}
	});

	it("cat outside cwd → prompt → rules (paths) → auto-allow", async () => {
		const store = createStore();

		const req: BashRequest = { type: "bash", command: "cat /etc/hosts", cwd };
		const d1 = await decide(req, store);
		expect(d1.kind).toBe("prompt");
		if (d1.kind !== "prompt") throw new Error("expected prompt");

		store.addAllowed(RuleGenerator.generatePrimaryRules(d1.promptData));
		const d2 = await decide(req, store);
		expect(d2.kind).toBe("auto-allow");
	});
});

// ─── File: read outside cwd ───

describe("Round-trip: File read outside cwd", () => {
	it("read /etc/hosts → prompt → rules (readDirs) → auto-allow", async () => {
		const store = createStore();

		const req: FileRequest = { type: "file", toolName: "read", filePath: "/etc/hosts", cwd };
		const d1 = await decide(req, store);
		expect(d1.kind).toBe("prompt");
		if (d1.kind !== "prompt") throw new Error("expected prompt");

		store.addAllowed(RuleGenerator.generatePrimaryRules(d1.promptData));
		const d2 = await decide(req, store);
		expect(d2.kind).toBe("auto-allow");
	});

	it("read /etc/hosts → prompt → file-only rules (readPaths) → auto-allow specific file only", async () => {
		const store = createStore();

		const req: FileRequest = { type: "file", toolName: "read", filePath: "/etc/hosts", cwd };
		const d1 = await decide(req, store);
		expect(d1.kind).toBe("prompt");
		if (d1.kind !== "prompt") throw new Error("expected prompt");

		const fileOnlyRules = RuleGenerator.generateFileOnlyRules(d1.promptData);
		if (fileOnlyRules) {
			store.addAllowed(fileOnlyRules);

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
	it("write inside cwd → prompt → rules (writePaths) → auto-allow", async () => {
		const store = createStore();

		const req: FileRequest = { type: "file", toolName: "write", filePath: "src/output.txt", cwd };
		const d1 = await decide(req, store);
		expect(d1.kind).toBe("prompt");
		if (d1.kind !== "prompt") throw new Error("expected prompt");

		store.addAllowed(RuleGenerator.generatePrimaryRules(d1.promptData));
		const d2 = await decide(req, store);
		expect(d2.kind).toBe("auto-allow");
	});

	it("edit inside cwd → prompt → rules (writePaths) → auto-allow", async () => {
		const store = createStore();

		const req: FileRequest = { type: "file", toolName: "edit", filePath: "src/index.ts", cwd };
		const d1 = await decide(req, store);
		expect(d1.kind).toBe("prompt");
		if (d1.kind !== "prompt") throw new Error("expected prompt");

		store.addAllowed(RuleGenerator.generatePrimaryRules(d1.promptData));
		const d2 = await decide(req, store);
		expect(d2.kind).toBe("auto-allow");
	});
});

// ─── File: write outside cwd ───

describe("Round-trip: File write outside cwd", () => {
	it("write /var/log/out.txt → prompt → rules (writeDirs) → auto-allow", async () => {
		const store = createStore();

		const req: FileRequest = { type: "file", toolName: "write", filePath: "/var/log/out.txt", cwd };
		const d1 = await decide(req, store);
		expect(d1.kind).toBe("prompt");
		if (d1.kind !== "prompt") throw new Error("expected prompt");

		store.addAllowed(RuleGenerator.generatePrimaryRules(d1.promptData));
		const d2 = await decide(req, store);
		expect(d2.kind).toBe("auto-allow");
	});

	it("write /var/log/out.txt → prompt → file-only rules (writePaths) → auto-allow specific file only", async () => {
		const store = createStore();

		const req: FileRequest = { type: "file", toolName: "write", filePath: "/var/log/out.txt", cwd };
		const d1 = await decide(req, store);
		expect(d1.kind).toBe("prompt");
		if (d1.kind !== "prompt") throw new Error("expected prompt");

		const fileOnlyRules = RuleGenerator.generateFileOnlyRules(d1.promptData);
		if (fileOnlyRules) {
			store.addAllowed(fileOnlyRules);

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
	it("context7 → prompt → rules → auto-allow", async () => {
		const store = createStore();

		const req: McpRequest = { type: "mcp", server: "context7", tool: "resolve-library-id" };
		const d1 = await decide(req, store);
		expect(d1.kind).toBe("prompt");
		if (d1.kind !== "prompt") throw new Error("expected prompt");

		store.addAllowed(RuleGenerator.generatePrimaryRules(d1.promptData));
		const d2 = await decide(req, store);
		expect(d2.kind).toBe("auto-allow");
	});

	it("server approval covers all tools on that server", async () => {
		const store = createStore();

		const req1: McpRequest = { type: "mcp", server: "blender", tool: "render" };
		const d1 = await decide(req1, store);
		expect(d1.kind).toBe("prompt");
		if (d1.kind !== "prompt") throw new Error("expected prompt");

		store.addAllowed(RuleGenerator.generatePrimaryRules(d1.promptData));

		// Different tool, same server → auto-allow
		const req2: McpRequest = { type: "mcp", server: "blender", tool: "scene_objects" };
		const d2 = await decide(req2, store);
		expect(d2.kind).toBe("auto-allow");
	});

	it("server approval → rules → auto-allow", async () => {
		const store = createStore();

		const req: McpRequest = { type: "mcp", server: "joplin", tool: "joplin:get_notes" };
		const d1 = await decide(req, store);
		expect(d1.kind).toBe("prompt");
		if (d1.kind !== "prompt") throw new Error("expected prompt");

		store.addAllowed(RuleGenerator.generatePrimaryRules(d1.promptData));

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
		store.addAllowed(RuleGenerator.generatePrimaryRules(d1.promptData));

		const req2: BashRequest = { type: "bash", command: "chmod 755 file.txt", cwd };
		const d2 = await decide(req2, store);
		expect(d2.kind).toBe("prompt");
		if (d2.kind !== "prompt") throw new Error("expected prompt");
		store.addAllowed(RuleGenerator.generatePrimaryRules(d2.promptData));

		// Both still prompt — unsafe commands never auto-allow
		expect((await decide(req1, store)).kind).toBe("prompt");
		expect((await decide(req2, store)).kind).toBe("prompt");
	});

	it("safe bash command with outside path → prompt → rules → auto-allow", async () => {
		const store = createStore();

		const req1: BashRequest = { type: "bash", command: "cat /etc/hosts", cwd };
		const d1 = await decide(req1, store);
		expect(d1.kind).toBe("prompt");
		if (d1.kind !== "prompt") throw new Error("expected prompt");
		store.addAllowed(RuleGenerator.generatePrimaryRules(d1.promptData));

		const req2: BashRequest = { type: "bash", command: "ls /var/log", cwd };
		const d2 = await decide(req2, store);
		expect(d2.kind).toBe("prompt");
		if (d2.kind !== "prompt") throw new Error("expected prompt");
		store.addAllowed(RuleGenerator.generatePrimaryRules(d2.promptData));

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
		store.addAllowed(RuleGenerator.generatePrimaryRules(d1.promptData));

		// Read auto-allows
		expect((await decide(readReq, store)).kind).toBe("auto-allow");

		// Write to same dir still prompts (readDirs ≠ writeDirs)
		const writeReq: FileRequest = { type: "file", toolName: "write", filePath: "/etc/out.txt", cwd };
		expect((await decide(writeReq, store)).kind).toBe("prompt");
	});
});
