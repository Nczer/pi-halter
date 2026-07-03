import path from "node:path";
import os from "node:os";
import { describe, expect, it } from "vitest";
import {
	expandTilde,
	resolvePathReal,
	isInsideCwd,
	isInsideAutoAllowedDir,
	isAllowedReadPath,
	getOutsideCwdPaths,
	isProjectPiPath,
	isProjectPiPathResolved,
	isPathDenied,
	isPathDeniedResolved,
	isPathWarned,
	isPathWarnedResolved,
} from "../analysis/path-analysis";

const home = os.homedir();
const tmpdir = os.tmpdir();
const cwd = path.join(home, "Projects");

describe("expandTilde", () => {
	it("expands ~/foo", () => {
		expect(expandTilde("~/foo")).toBe(path.join(home, "foo"));
	});

	it("expands ~", () => {
		expect(expandTilde("~")).toBe(home);
	});

	it("leaves absolute paths alone", () => {
		expect(expandTilde("/absolute")).toBe("/absolute");
	});

	it("leaves relative paths alone", () => {
		expect(expandTilde("relative")).toBe("relative");
	});
});

describe("resolvePathReal", () => {
	it("resolves relative path", () => {
		expect(resolvePathReal("src/index.ts", cwd)).toBe(path.join(cwd, "src/index.ts"));
	});

	it("resolves absolute path (follows symlinks)", () => {
		// macOS: /etc/hosts → /private/etc/hosts, Linux: stays /etc/hosts
		const expected = require("fs").realpathSync("/etc/hosts");
		expect(resolvePathReal("/etc/hosts", cwd)).toBe(expected);
	});

	it("handles non-existent path gracefully", () => {
		// macOS: /tmp → /private/tmp, so resolved path reflects the symlink target
		const tmpReal = require("fs").realpathSync("/tmp", "utf8");
		expect(resolvePathReal("/tmp/nonexistent/deep/file.txt", cwd)).toBe(
			path.join(tmpReal, "nonexistent/deep/file.txt")
		);
	});
});

describe("isInsideCwd", () => {
	it("cwd is inside itself", () => {
		expect(isInsideCwd(cwd, cwd)).toBe(true);
	});

	it("subdir is inside cwd", () => {
		expect(isInsideCwd(`${cwd}/src`, cwd)).toBe(true);
	});

	it("file in subdir is inside cwd", () => {
		expect(isInsideCwd(`${cwd}/src/index.ts`, cwd)).toBe(true);
	});

	it("/etc is outside cwd", () => {
		expect(isInsideCwd("/etc/hosts", cwd)).toBe(false);
	});

	it("sibling dir is outside cwd", () => {
		expect(isInsideCwd(path.join(home, "Other"), cwd)).toBe(false);
	});

	it("parent dir is outside cwd", () => {
		expect(isInsideCwd(home, cwd)).toBe(false);
	});
});

describe("isInsideAutoAllowedDir", () => {
	it("matches exact dir", () => {
		const dirs = new Set(["/opt", "/var/log"]);
		expect(isInsideAutoAllowedDir("/opt", dirs)).toBe(true);
	});

	it("matches child of /opt", () => {
		const dirs = new Set(["/opt", "/var/log"]);
		expect(isInsideAutoAllowedDir("/opt/pi", dirs)).toBe(true);
	});

	it("matches deep child of /opt", () => {
		const dirs = new Set(["/opt", "/var/log"]);
		expect(isInsideAutoAllowedDir("/opt/pi/src", dirs)).toBe(true);
	});

	it("matches child of /var/log", () => {
		const dirs = new Set(["/opt", "/var/log"]);
		expect(isInsideAutoAllowedDir("/var/log/syslog", dirs)).toBe(true);
	});

	it("does not match unrelated dir", () => {
		const dirs = new Set(["/opt", "/var/log"]);
		expect(isInsideAutoAllowedDir("/etc/hosts", dirs)).toBe(false);
	});

	it("does not match prefix mismatch (/optical ≠ /opt)", () => {
		const dirs = new Set(["/opt", "/var/log"]);
		expect(isInsideAutoAllowedDir("/optical/disk", dirs)).toBe(false);
	});
});

describe("isAllowedReadPath", () => {
	it("tmpdir is allowed read path", () => {
		expect(isAllowedReadPath(path.join(tmpdir, "foo"))).toBe(true);
	});

	it(".pi is allowed read path", () => {
		expect(isAllowedReadPath(path.join(home, ".pi/agent/foo"))).toBe(true);
	});

	it("/etc is not allowed read path", () => {
		expect(isAllowedReadPath("/etc/hosts")).toBe(false);
	});
});

describe("getOutsideCwdPaths", () => {
	it("returns empty when all paths inside cwd", () => {
		expect(getOutsideCwdPaths([`${cwd}/a`, `${cwd}/b`], cwd, new Set(), new Set())).toHaveLength(0);
	});

	it("filters to outside paths only", () => {
		const outside = getOutsideCwdPaths([`${cwd}/a`, "/etc/hosts"], cwd, new Set(), new Set());
		expect(outside).toEqual(["/etc/hosts"]);
	});

	it("excludes auto-allowed dirs", () => {
		const autoRead = new Set(["/opt"]);
		const outside = getOutsideCwdPaths([`${cwd}/a`, "/opt/pi", "/etc/hosts"], cwd, autoRead, new Set());
		expect(outside).toEqual(["/etc/hosts"]);
	});

	it("excludes allowed read paths", () => {
		const outside = getOutsideCwdPaths([`${cwd}/a`, path.join(tmpdir, "foo"), "/etc/hosts"], cwd, new Set(), new Set());
		expect(outside).toEqual(["/etc/hosts"]);
	});
});

describe("isProjectPiPath", () => {
	it("matches .pi/agent/foo", () => {
		expect(isProjectPiPath(".pi/agent/foo", cwd)).toBe(true);
	});

	it("matches .pi/extensions/bar", () => {
		expect(isProjectPiPath(".pi/extensions/bar", cwd)).toBe(true);
	});

	it("does not match src/index.ts", () => {
		expect(isProjectPiPath("src/index.ts", cwd)).toBe(false);
	});

	it("does not match home .pi (~/other/.pi/foo)", () => {
		expect(isProjectPiPath("~/other/.pi/foo", cwd)).toBe(false);
	});
});

describe("isPathDenied", () => {
	it("denies .ssh", () => {
		expect(isPathDenied("~/.ssh/id_rsa", cwd).denied).toBe(true);
	});

	it("allows src/index.ts", () => {
		expect(isPathDenied("src/index.ts", cwd).denied).toBe(false);
	});

	it("allows README.md", () => {
		expect(isPathDenied("README.md", cwd).denied).toBe(false);
	});

	it("allows node_modules", () => {
		expect(isPathDenied("node_modules/pkg/index.js", cwd).denied).toBe(false);
	});
});

describe("isPathWarned", () => {
	it("warns .env", () => {
		const result = isPathWarned(".env", cwd);
		expect(result.warned).toBe(true);
		expect(result.matchedRule).toBe(".env");
	});

	it("warns .env.local", () => {
		expect(isPathWarned(".env.local", cwd).warned).toBe(true);
	});

	it("warns .env.production (glob match)", () => {
		const result = isPathWarned(".env.production", cwd);
		expect(result.warned).toBe(true);
		expect(result.matchedRule).toBe(".env.*");
	});

	it("warns .aws", () => {
		expect(isPathWarned("~/.aws/credentials", cwd).warned).toBe(true);
	});

	it("warns .netrc", () => {
		expect(isPathWarned("~/.netrc", cwd).warned).toBe(true);
	});

	it("warns .npmrc", () => {
		expect(isPathWarned("~/.npmrc", cwd).warned).toBe(true);
	});

	it("warns .docker/config.json", () => {
		expect(isPathWarned("~/.docker/config.json", cwd).warned).toBe(true);
	});

	it("does not warn src/index.ts", () => {
		expect(isPathWarned("src/index.ts", cwd).warned).toBe(false);
	});
});

describe("resolved-path variants (hot-path optimization)", () => {
	// The *Resolved variants take a pre-resolved real path so decideFile can skip
	// redundant realpathSync calls. They must match the public functions, which resolve
	// internally. This pins the contract the file policy relies on.
	const cases = [
		".pi/agent/foo",
		"~/other/.pi/foo",
		"src/index.ts",
		"~/.ssh/id_rsa",
		".env.production",
		"~/.aws/credentials",
	];

	for (const filePath of cases) {
		it(`isPathDeniedResolved matches isPathDenied for ${filePath}`, () => {
			const resolved = resolvePathReal(expandTilde(filePath), cwd);
			expect(isPathDeniedResolved(filePath, resolved)).toEqual(isPathDenied(filePath, cwd));
		});

		it(`isPathWarnedResolved matches isPathWarned for ${filePath}`, () => {
			const resolved = resolvePathReal(expandTilde(filePath), cwd);
			expect(isPathWarnedResolved(filePath, resolved)).toEqual(isPathWarned(filePath, cwd));
		});

		it(`isProjectPiPathResolved matches isProjectPiPath for ${filePath}`, () => {
			const resolved = resolvePathReal(expandTilde(filePath), cwd);
			expect(isProjectPiPathResolved(resolved, cwd)).toBe(isProjectPiPath(filePath, cwd));
		});
	}
});
