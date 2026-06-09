import { describe, expect, it, beforeAll, afterAll, beforeEach } from "vitest";
import { decide } from "../decision-engine";
import { createStore } from "../store";
import { setPersistencePath } from "../store";
import path from "node:path";
import os from "node:os";
import fs from "node:fs/promises";

const home = os.homedir();
const cwd = path.join(home, "Projects");
const TEST_CONFIG_PATH = path.join(os.tmpdir(), `pi-perms-test-${Date.now()}.json`);

beforeAll(() => {
  setPersistencePath(TEST_CONFIG_PATH);
});

beforeEach(async () => {
  // Clear config file between tests for isolation
  try {
    await fs.unlink(TEST_CONFIG_PATH);
  } catch {}
});

afterAll(async () => {
  try {
    await fs.unlink(TEST_CONFIG_PATH);
  } catch {}
});

describe("User Rules Safety Invariants", () => {
	it("user allow on simple command bypasses safety heuristics", async () => {
		const store = createStore();
		await store.init();
		await store.addUserRule("bash", { pattern: "rm *", action: "allow" });

		// rm -rf is dangerous but user explicitly allowed it -> auto-allow
		const decision = await decide({ type: "bash", command: "rm -rf /tmp/data", cwd }, store);
		expect(decision.kind).toBe("auto-allow");
	});

	it("ls * does NOT match compound command ls x && rm -rf y", async () => {
		const store = createStore();
		await store.init();
		await store.addUserRule("bash", { pattern: "ls *", action: "allow" });

		// Simple ls -> auto-allow
		const decision1 = await decide({ type: "bash", command: "ls -la", cwd }, store);
		expect(decision1.kind).toBe("auto-allow");

		// Compound: ls * matches "ls /tmp" segment but NOT "rm -rf /tmp/data" -> prompt
		const decision2 = await decide({ type: "bash", command: "ls /tmp && rm -rf /tmp/data", cwd }, store);
		expect(decision2.kind).toBe("prompt");
	});

	it("user deny on simple command blocks even with other allow rules", async () => {
		const store = createStore();
		await store.init();
		await store.addUserRule("bash", { pattern: "rm -rf *", action: "deny" });
		await store.addUserRule("bash", { pattern: "rm *", action: "allow" });

		// First rule wins: rm -rf * deny matches before rm * allow
		const decision = await decide({ type: "bash", command: "rm -rf /tmp/data", cwd }, store);
		expect(decision.kind).toBe("block");
		expect(decision.reason).toContain("Blocked by user rule");
	});

	it("should NOT auto-allow denied paths even if they match a user allow rule", async () => {
		const store = createStore();
		await store.init();
		await store.addUserRule("read", { pattern: "*", action: "allow" });

		// Case 1: normal file -> auto-allow
		const decision1 = await decide({ type: "file", toolName: "read", filePath: "readme.md", cwd }, store);
		expect(decision1.kind).toBe("auto-allow");

		// Case 2: .ssh (denied path) -> MUST block regardless of user allow rule
		const decision2 = await decide({ type: "file", toolName: "read", filePath: ".ssh", cwd }, store);
		expect(decision2.kind).toBe("block");
		expect(decision2.reason).toContain("denied path");
	});

	it("should still allow user deny rules to take priority", async () => {
		const store = createStore();
		await store.init();
		await store.addUserRule("bash", { pattern: "rm *", action: "deny" });

		const decision = await decide({ type: "bash", command: "rm file.txt", cwd }, store);
		expect(decision.kind).toBe("block");
		expect(decision.reason).toContain("Blocked by user rule");
	});
});

describe("User Rules: Trailing wildcard stripping", () => {
	it("npm test * matches signature npm test (no args)", async () => {
		const store = createStore();
		await store.init();
		await store.addUserRule("bash", { pattern: "npm test *", action: "allow" });

		// Full command with args
		expect(store.getUserRuleAction("bash", "npm test -- --coverage")).toBe("allow");
		// Signature without args — trailing * is optional
		expect(store.getUserRuleAction("bash", "npm test")).toBe("allow");
	});

	it("npm test * does not match npm (too short)", async () => {
		const store = createStore();
		await store.init();
		await store.addUserRule("bash", { pattern: "npm test *", action: "allow" });

		expect(store.getUserRuleAction("bash", "npm")).toBeNull();
		expect(store.getUserRuleAction("bash", "npm install")).toBeNull();
	});

	it("trailing strip works for signature-level auto-allow in decideBash", async () => {
		const store = createStore();
		await store.init();
		// Pattern with trailing * — should match "npm test" signature
		await store.addUserRule("bash", { pattern: "npm test *", action: "allow" });

		// Command whose signature is "npm test" (no extra args)
		const decision = await decide({ type: "bash", command: "npm test", cwd }, store);
		expect(decision.kind).toBe("auto-allow");
	});
});
