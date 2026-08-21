/**
 * rm mass-deletion flag tests.
 *
 * `rm` always prompts (danger), but targets that wipe "a stupid amount of
 * stuff" — the whole home dir, a system dir, a directory with 100+ entries,
 * a `*` glob over a big directory, or many file arguments — get an explicit
 * mass-deletion reason in the prompt.
 *
 * Principles: flagging is fail-soft (fs errors skip the check, the generic
 * rm prompt still applies) and never auto-allows — these reasons only add
 * specificity to an already-mandatory prompt.
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { analyzeCommand } from "../analysis/command-analysis";

let tmp: string;
let bigDir: string;
let smallDir: string;

beforeAll(() => {
	tmp = fs.mkdtempSync(path.join(os.tmpdir(), "halter-rm-mass-"));
	bigDir = path.join(tmp, "big");
	fs.mkdirSync(bigDir);
	for (let i = 0; i < 120; i++) fs.writeFileSync(path.join(bigDir, `f${i}`), "");
	smallDir = path.join(tmp, "small");
	fs.mkdirSync(smallDir);
	for (let i = 0; i < 10; i++) fs.writeFileSync(path.join(smallDir, `f${i}`), "");
});

afterAll(() => {
	fs.rmSync(tmp, { recursive: true, force: true });
});

const reasons = async (cmd: string, cwd: string = tmp) =>
	(await analyzeCommand(cmd, cwd)).risk.reasons;
const has = (rs: string[], s: string) => rs.some(r => r.includes(s));

describe("rm mass-deletion: home directory", () => {
	it("rm -rf ~ → home directory flag", async () => {
		const rs = await reasons("rm -rf ~");
		expect(has(rs, "home directory")).toBe(true);
	});

	it("rm -rf \"$HOME\" → home directory flag (quoted)", async () => {
		const rs = await reasons('rm -rf "$HOME"');
		expect(has(rs, "home directory")).toBe(true);
	});

	it("rm -rf . under home → home directory flag (cwd-based)", async () => {
		const rs = await reasons("rm -rf .", os.homedir());
		expect(has(rs, "home directory")).toBe(true);
	});

	it("rm -rf ~/subdir → no home flag (subdir is not home)", async () => {
		const rs = await reasons("rm -rf ~/definitely-not-a-dir-xyz");
		expect(has(rs, "home directory")).toBe(false);
	});
});

describe("rm mass-deletion: system directories", () => {
	it("rm -rf / → system directory flag", async () => {
		const rs = await reasons("rm -rf /");
		expect(has(rs, "system directory")).toBe(true);
	});

	it("rm -rf /etc → system directory flag", async () => {
		const rs = await reasons("rm -rf /etc");
		expect(has(rs, "system directory")).toBe(true);
	});

	it("rm -rf /etc/foo → no system directory flag (content, not the dir)", async () => {
		const rs = await reasons("rm -rf /etc/foo");
		expect(has(rs, "system directory")).toBe(false);
	});

	it("cd $D && rm -rf . → unknown base is NOT resolved to /", async () => {
		const rs = await reasons("cd $D && rm -rf .");
		expect(has(rs, "system directory")).toBe(false);
		expect(has(rs, "home directory")).toBe(false);
	});
});

describe("rm mass-deletion: directory entry count", () => {
	it("rm -rf <dir with 120 entries> → mass deletion flag (count capped at threshold by early stop)", async () => {
		const rs = await reasons(`rm -rf ${bigDir}`);
		expect(has(rs, "mass deletion")).toBe(true);
		expect(has(rs, "100+ entries")).toBe(true);
	});

	it("rm -rf <dir with 10 entries> → no mass deletion flag", async () => {
		const rs = await reasons(`rm -rf ${smallDir}`);
		expect(has(rs, "mass deletion")).toBe(false);
	});

	it("rm <dir with 120 entries> (non-recursive) → no entry-count flag", async () => {
		const rs = await reasons(`rm ${bigDir}`);
		expect(has(rs, "mass deletion")).toBe(false);
	});

	it("rm <dir>/* → glob mass deletion flag", async () => {
		const rs = await reasons(`rm ${bigDir}/*`);
		expect(has(rs, "mass deletion")).toBe(true);
	});

	it("rm <smallDir>/* → no glob mass deletion flag", async () => {
		const rs = await reasons(`rm ${smallDir}/*`);
		expect(has(rs, "mass deletion")).toBe(false);
	});

	it("rm -rf /nonexistent-dir-xyz → no crash, no mass flag", async () => {
		const rs = await reasons("rm -rf /nonexistent-dir-xyz");
		expect(has(rs, "mass deletion")).toBe(false);
		expect(has(rs, "system directory")).toBe(false);
	});
});

describe("rm mass-deletion: many file arguments", () => {
	it("rm with 105 literal file args → mass deletion flag", async () => {
		const files = Array.from({ length: 105 }, (_, i) => `file${i}`);
		const rs = await reasons(`rm -f ${files.join(" ")}`);
		expect(has(rs, "mass deletion")).toBe(true);
	});

	it("rm with 3 file args → no mass deletion flag", async () => {
		const rs = await reasons("rm -f a b c");
		expect(has(rs, "mass deletion")).toBe(false);
	});
});

describe("rm mass-deletion: wrappers", () => {
	it("sudo rm -rf / → system directory flag (and sudo reason)", async () => {
		const a = await analyzeCommand("sudo rm -rf /", tmp);
		expect(has(a.risk.reasons, "system directory")).toBe(true);
		expect(has(a.risk.reasons, "sudo")).toBe(true);
	});

	it("timeout 30 rm -rf ~ → home directory flag (wrapper delegation)", async () => {
		const rs = await reasons("timeout 30 rm -rf ~");
		expect(has(rs, "home directory")).toBe(true);
	});
});

describe("rm baseline behavior unchanged", () => {
	it("plain rm still prompts as dangerous/high", async () => {
		const a = await analyzeCommand("rm -rf /tmp/whatever", tmp);
		expect(a.risk.dangerous).toBe(true);
		expect(a.risk.severity).toBe("high");
	});
});
