/**
 * rule-generator.ts — Always-tier rule generation.
 *
 * The root-grant sanitization: one click on "Always" must never hand out
 * read/write of the filesystem root. A `find /` prompt used to offer
 * "Always (paths only): /" → readDirs ["/"], and an /etc file prompt's
 * broader umbrella reached up to `/` (write the whole disk). Root-touching
 * prompts still prompt; their Always tiers are file-level or root-free.
 */
import { describe, it, expect } from "vitest";
import { RuleGenerator } from "../rule-generator";
import type { BashPromptData, FilePromptData } from "../decision-engine";

const BASE = "/home/u/project";

function bashPd(overrides: Partial<BashPromptData> = {}): BashPromptData {
  return {
    type: "bash",
    command: "ls /",
    cwd: BASE,
    outsideDirs: ["/"],
    segments: ["ls /"],
    signatures: ["ls"],
    relativeToolIds: [],
    nonAllowedSegmentIndices: [0],
    riskDangerous: false,
    riskSeverity: null,
    riskReasons: [],
    hasUnsafePattern: false,
    credentialRule: null,
    needsCommandApproval: true,
    needsPathApproval: true,
    ...overrides,
  };
}

function filePd(overrides: Partial<FilePromptData> = {}): FilePromptData {
  return {
    type: "file",
    action: "Write",
    filePath: "hosts",
    resolved: "/hosts",
    cwd: BASE,
    outsideDir: "/",
    isWriteOp: true,
    warnedRule: null,
    symlinkHint: null,
    exists: false,
    ...overrides,
  };
}

describe("root grants are never generated", () => {
  it("bash primary: / is dropped from readDirs, other dirs kept", () => {
    const rules = RuleGenerator.generatePrimaryRules(bashPd({ command: "find / -name x" }));
    expect(rules.readDirs).toBeUndefined();
    const mixed = RuleGenerator.generatePrimaryRules(
      bashPd({ command: "ls / /etc", outsideDirs: ["/", "/etc"] }),
    );
    expect(mixed.readDirs).toEqual(["/etc"]);
    // the command signatures are unaffected
    expect(rules.bashSigs).toEqual(["ls"]);
  });

  it("bash paths-only: root-only outsideDirs produce no tier at all", () => {
    expect(RuleGenerator.generatePathsOnlyRules(bashPd())).toBeUndefined();
    const mixed = RuleGenerator.generatePathsOnlyRules(
      bashPd({ command: "ls / /etc", outsideDirs: ["/", "/etc"] }),
    );
    expect(mixed).toEqual({ readDirs: ["/etc"] });
  });

  it("file primary: a file directly under / gets a file-level grant, not a dir grant", () => {
    const rules = RuleGenerator.generatePrimaryRules(filePd());
    expect(rules).toEqual({ writePaths: ["/hosts"], readPaths: ["/hosts"] });
    // ordinary outside-cwd dirs still grant the dir
    const etc = RuleGenerator.generatePrimaryRules(
      filePd({ filePath: "/etc/hosts", resolved: "/etc/hosts", outsideDir: "/etc", isWriteOp: false, action: "Read" }),
    );
    expect(etc).toEqual({ readDirs: ["/etc"] });
  });

  it("file broader: / is refused", () => {
    expect(RuleGenerator.generateBroaderRules(filePd(), "/")).toBeUndefined();
    const etc = RuleGenerator.generateBroaderRules(
      filePd({ filePath: "x.md", resolved: `${BASE}/x.md`, outsideDir: null }),
      "/etc",
    );
    expect(etc).toEqual({ writeDirs: ["/etc"], readDirs: ["/etc"] });
  });
});
