import path from "node:path";
import os from "node:os";
import fs from "node:fs";
import { describe, expect, it, beforeAll, afterAll } from "vitest";
import {
  expandTilde,
  resolvePathReal,
  isInsideCwd,
  isAllowedReadPath,
  getOutsideCwdPaths,
  isProjectPiPathResolved,
  isPathDeniedResolved,
  isPathWarnedResolved,
} from "../analysis/path-analysis";
import { createContractCwd, removeContractCwd } from "./hermetic-cwd";

const home = os.homedir();
const tmpdir = os.tmpdir();
let cwd: string;

beforeAll(() => {
  cwd = createContractCwd();
});
afterAll(() => removeContractCwd(cwd));

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
    expect(getOutsideCwdPaths([`${cwd}/a`, `${cwd}/b`], cwd)).toHaveLength(0);
  });

  it("filters to outside paths only", () => {
    const outside = getOutsideCwdPaths([`${cwd}/a`, "/etc/hosts"], cwd);
    expect(outside).toEqual(["/etc/hosts"]);
  });

  it("excludes auto-allowed dirs", () => {
    const autoRead = new Set(["/opt"]);
    const isInside = (p: string) => autoRead.has(p) || [...autoRead].some(d => p.startsWith(d + "/"));
    const outside = getOutsideCwdPaths([`${cwd}/a`, "/opt/pi", "/etc/hosts"], cwd, isInside);
    expect(outside).toEqual(["/etc/hosts"]);
  });

  it("excludes allowed read paths", () => {
    const outside = getOutsideCwdPaths([`${cwd}/a`, path.join(tmpdir, "foo"), "/etc/hosts"], cwd);
    expect(outside).toEqual(["/etc/hosts"]);
  });
});

describe("resolved-path variants (hot-path optimization)", () => {
  // The *Resolved variants take a pre-resolved real path so decideFile can skip
  // redundant realpathSync calls. These pin the exact values the file policy
  // relies on.
  const resolved = (filePath: string) => resolvePathReal(expandTilde(filePath), cwd);

  const deniedCases: [string, boolean, string | null][] = [
    [".pi/agent/foo", false, null],
    ["~/other/.pi/foo", false, null],
    ["src/index.ts", false, null],
    ["~/.ssh/id_rsa", true, ".ssh"],
    [".env.production", false, null],
    ["~/.aws/credentials", false, null],
  ];
  for (const [filePath, denied, matchedRule] of deniedCases) {
    it(`isPathDeniedResolved: ${filePath}`, () => {
      expect(isPathDeniedResolved(filePath, resolved(filePath))).toEqual({ denied, matchedRule });
    });
  }

  const warnedCases: [string, boolean, string | null][] = [
    [".pi/agent/foo", false, null],
    ["~/other/.pi/foo", false, null],
    ["src/index.ts", false, null],
    ["~/.ssh/id_rsa", true, "id_rsa"],
    [".env.production", true, ".env.*"],
    ["~/.aws/credentials", true, ".aws"],
  ];
  for (const [filePath, warned, matchedRule] of warnedCases) {
    it(`isPathWarnedResolved: ${filePath}`, () => {
      expect(isPathWarnedResolved(filePath, resolved(filePath))).toEqual({ warned, matchedRule });
    });
  }

  const projectPiCases: [string, boolean][] = [
    [".pi/agent/foo", true],
    ["~/other/.pi/foo", false],
    ["src/index.ts", false],
    ["~/.ssh/id_rsa", false],
    [".env.production", false],
    ["~/.aws/credentials", false],
  ];
  for (const [filePath, inside] of projectPiCases) {
    it(`isProjectPiPathResolved: ${filePath}`, () => {
      expect(isProjectPiPathResolved(resolved(filePath), cwd)).toBe(inside);
    });
  }
});

