import { describe, expect, it } from "vitest";
import { createStore } from "../store";

describe("Store: Fresh state", () => {
	it("starts with no allowances", () => {
		const store = createStore();
		expect(store.hasAllowedBash("ls")).toBe(false);
		expect(store.hasAllowedReadPath("/foo")).toBe(false);
		expect(store.hasAllowedWritePath("/foo")).toBe(false);
		expect(store.hasAllowedMcpServer("exa")).toBe(false);
		expect(store.getLastAbort("ls")).toBeNull();
	});
});

describe("Store: addAllowed", () => {
	it("adds bash signatures", () => {
		const store = createStore();
		store.addAllowed({ bashSigs: ["ls -la", "cat"] });
		expect(store.hasAllowedBash("ls -la")).toBe(true);
		expect(store.hasAllowedBash("cat")).toBe(true);
		expect(store.hasAllowedBash("rm")).toBe(false);
	});

	it("adds read dirs", () => {
		const store = createStore();
		store.addAllowed({ readDirs: ["/opt", "/var/log"] });
		const dirs = store.listAllowedReadDirs();
		expect(dirs).toContain("/opt");
		expect(dirs).toContain("/var/log");
		expect(dirs.size).toBe(2);
	});

	it("adds write dirs", () => {
		const store = createStore();
		store.addAllowed({ writeDirs: ["/tmp"] });
		expect(store.listAllowedWriteDirs()).toContain("/tmp");
		expect(store.listAllowedWriteDirs().size).toBe(1);
	});

	it("adds read paths", () => {
		const store = createStore();
		store.addAllowed({ readPaths: ["/etc/hosts", "/etc/resolv.conf"] });
		expect(store.hasAllowedReadPath("/etc/hosts")).toBe(true);
		expect(store.hasAllowedReadPath("/etc/resolv.conf")).toBe(true);
		expect(store.hasAllowedReadPath("/etc/passwd")).toBe(false);
	});

	it("adds write paths", () => {
		const store = createStore();
		store.addAllowed({ writePaths: ["/tmp/out.txt"] });
		expect(store.hasAllowedWritePath("/tmp/out.txt")).toBe(true);
		expect(store.hasAllowedWritePath("/tmp/other.txt")).toBe(false);
	});

	it("adds MCP servers", () => {
		const store = createStore();
		store.addAllowed({ mcpServers: ["exa", "context7"] });
		expect(store.hasAllowedMcpServer("exa")).toBe(true);
		expect(store.hasAllowedMcpServer("context7")).toBe(true);
		expect(store.hasAllowedMcpServer("blender")).toBe(false);
	});

	it("adds all categories at once", () => {
		const store = createStore();
		store.addAllowed({
			bashSigs: ["ls"],
			readDirs: ["/opt"],
			writeDirs: ["/tmp"],
			readPaths: ["/a"],
			writePaths: ["/b"],
			mcpServers: ["exa"],
		});
		expect(store.hasAllowedBash("ls")).toBe(true);
		expect(store.listAllowedReadDirs()).toContain("/opt");
		expect(store.listAllowedWriteDirs()).toContain("/tmp");
		expect(store.hasAllowedReadPath("/a")).toBe(true);
		expect(store.hasAllowedWritePath("/b")).toBe(true);
		expect(store.hasAllowedMcpServer("exa")).toBe(true);
	});

	it("handles partial allowances", () => {
		const store = createStore();
		store.addAllowed({ bashSigs: ["ls"] });
		expect(store.hasAllowedBash("ls")).toBe(true);
	});
});

describe("Store: Abort tracking", () => {
	it("records and retrieves aborts", () => {
		const now = Date.now();
		const store = createStore(() => now);

		store.recordAbort("rm -rf /");
		expect(store.getLastAbort("rm -rf /")).toBe(now);
		expect(store.getLastAbort("ls")).toBeNull();
	});

	it("overwrites previous abort timestamps", () => {
		const store = createStore(() => 0);
		store.recordAbort("rm -rf /");
		const later = 1000;
		const store2 = createStore(() => later);
		store2.recordAbort("rm -rf /");
		expect(store2.getLastAbort("rm -rf /")).toBe(later);
	});

	it("lazy-cleans old aborts past threshold", () => {
		let currentTime = 0;
		const store = createStore(() => currentTime);

		for (let i = 0; i < 101; i++) {
			currentTime = i * 1000;
			store.recordAbort(`cmd-${i}`);
		}

		currentTime = 99000 + 1000;
		store.getLastAbort("cmd-99");

		expect(store.getLastAbort("cmd-0")).toBeNull();
		expect(store.getLastAbort("cmd-99")).not.toBeNull();
	});
});

describe("Store: Prompt counter", () => {
	it("increments and detects threshold", () => {
		const store = createStore();
		expect(store.incrementPromptCount().count).toBe(1);
		expect(store.incrementPromptCount().over).toBe(false);

		for (let i = 0; i < 20; i++) {
			store.incrementPromptCount();
		}
		const result = store.incrementPromptCount();
		expect(result.over).toBe(true);
		expect(result.count).toBe(23);
	});
});

describe("Store: Reset", () => {
	it("clears all state", () => {
		const store = createStore();
		store.addAllowed({ bashSigs: ["ls"], readDirs: ["/opt"] });
		store.recordAbort("rm");
		store.incrementPromptCount();

		store.reset();

		expect(store.hasAllowedBash("ls")).toBe(false);
		expect(store.listAllowedReadDirs().size).toBe(0);
		expect(store.listAllowedWriteDirs().size).toBe(0);
		expect(store.listAllowedReadPaths().size).toBe(0);
		expect(store.listAllowedWritePaths().size).toBe(0);
		expect(store.hasAllowedMcpServer("exa")).toBe(false);
		expect(store.getLastAbort("rm")).toBeNull();
		expect(store.incrementPromptCount().count).toBe(1);
	});
});

describe("Store: isInsideAllowedDir", () => {
	it("returns false for empty store", () => {
		const store = createStore();
		expect(store.isInsideAllowedDir("/opt/foo", "read")).toBe(false);
		expect(store.isInsideAllowedDir("/opt/foo", "write")).toBe(false);
	});

	it("checks read dirs for read kind", () => {
		const store = createStore();
		store.addAllowed({ readDirs: ["/opt"] });
		expect(store.isInsideAllowedDir("/opt", "read")).toBe(true);
		expect(store.isInsideAllowedDir("/opt/foo", "read")).toBe(true);
		expect(store.isInsideAllowedDir("/opt/foo/bar", "read")).toBe(true);
		expect(store.isInsideAllowedDir("/other", "read")).toBe(false);
		// read dirs don't grant write
		expect(store.isInsideAllowedDir("/opt", "write")).toBe(false);
	});

	it("checks write dirs for write kind", () => {
		const store = createStore();
		store.addAllowed({ writeDirs: ["/tmp/work"] });
		expect(store.isInsideAllowedDir("/tmp/work", "write")).toBe(true);
		expect(store.isInsideAllowedDir("/tmp/work/file.txt", "write")).toBe(true);
		expect(store.isInsideAllowedDir("/tmp/other", "write")).toBe(false);
	});

	it("write dirs imply read", () => {
		const store = createStore();
		store.addAllowed({ writeDirs: ["/tmp/work"] });
		expect(store.isInsideAllowedDir("/tmp/work", "read")).toBe(true);
		expect(store.isInsideAllowedDir("/tmp/work/file.txt", "read")).toBe(true);
	});

	it("read dirs do not imply write", () => {
		const store = createStore();
		store.addAllowed({ readDirs: ["/tmp/work"] });
		expect(store.isInsideAllowedDir("/tmp/work", "write")).toBe(false);
	});

	it("does not match partial path prefixes", () => {
		const store = createStore();
		store.addAllowed({ readDirs: ["/opt"] });
		// /optfoo should NOT match /opt
		expect(store.isInsideAllowedDir("/optfoo", "read")).toBe(false);
		expect(store.isInsideAllowedDir("/opt-foo", "read")).toBe(false);
	});
});
