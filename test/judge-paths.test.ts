/**
 * judge-paths.ts (D13) — sanitizing the stage-2 judge's path report and
 * cross-checking it against the floor's own knowledge. Pure functions, no
 * model, no disk.
 */
import { describe, expect, it } from "vitest";
import os from "node:os";
import {
  sanitizeJudgePaths,
  judgePathReport,
  type JudgePathFloor,
} from "../judge/paths";
import { OPAQUE_VAR_DIR } from "../analysis/bash-parser";
import { UNKNOWN_CWD_MARKER } from "../analysis/cwd-tracking";

const cwd = "/home/u/project";
const home = os.homedir();

describe("sanitizeJudgePaths", () => {
  it("resolves relatives against the cwd and expands ~", () => {
    expect(sanitizeJudgePaths(["target/x", "~/data"], cwd)).toEqual([
      "/home/u/project/target/x",
      `${home}/data`,
    ]);
  });

  it("keeps absolute paths, trims, dedupes", () => {
    expect(
      sanitizeJudgePaths(["  /a/b  ", "/a/b", "/a/c"], cwd),
    ).toEqual(["/a/b", "/a/c"]);
  });

  it("drops the floor's sentinel markers (model echo, not paths)", () => {
    const s = sanitizeJudgePaths(
      [`${OPAQUE_VAR_DIR}/base/$e/f`, `${UNKNOWN_CWD_MARKER}/x`, "/real"],
      cwd,
    );
    expect(s).toEqual(["/real"]);
  });

  it("caps at 8 and returns [] for nothing usable", () => {
    const many = Array.from({ length: 20 }, (_, i) => `/p${i}`);
    expect(sanitizeJudgePaths(many, cwd)).toHaveLength(8);
    expect(sanitizeJudgePaths(undefined, cwd)).toEqual([]);
    expect(sanitizeJudgePaths([], cwd)).toEqual([]);
    expect(sanitizeJudgePaths(["  "], cwd)).toEqual([]);
  });
});

describe("judgePathReport", () => {
  const floor: JudgePathFloor = {
    cwd,
    floorPaths: ["/home/u/project/target", "/home/u/project/data/*.log"],
    confirmedDirs: ["/granted/dir"],
  };

  it("covers: equal, under-a-floor-path, glob-ancestor, confirmed dir, cwd", () => {
    const r = judgePathReport(
      [
        "/home/u/project/target", // equal
        "/home/u/project/target/release", // under a floor path
        "/home/u/project/data/app.log", // under a GLOB floor path
        "/granted/dir/f", // confirmed dir
        cwd, // the cwd itself
      ],
      floor,
    );
    expect(r.paths).toHaveLength(5);
    expect(r.misses).toBeUndefined();
  });

  it("misses: unrelated paths (the parser-gap signal)", () => {
    const r = judgePathReport(["/etc/shadow", "/home/u/project/target"], {
      cwd,
      floorPaths: ["/home/u/project/target"],
    });
    expect(r.paths).toEqual(["/etc/shadow", "/home/u/project/target"]);
    expect(r.misses).toEqual(["/etc/shadow"]);
  });

  it("a literal floor path under the report is a miss (broader claim)", () => {
    // The floor saw /y/z; the judge claims the operation touches all of /y.
    const r = judgePathReport(["/y"], { cwd: "/x", floorPaths: ["/y/z"] });
    expect(r.misses).toEqual(["/y"]);
  });

  it("sentinels in the floor set are not knowledge", () => {
    const r = judgePathReport(["/a"], {
      cwd: "/x",
      floorPaths: [`${OPAQUE_VAR_DIR}/a`],
    });
    expect(r.misses).toEqual(["/a"]);
  });

  it("caps misses at 5; {} when the model reported nothing", () => {
    const r = judgePathReport(
      Array.from({ length: 8 }, (_, i) => `/m${i}`),
      { cwd, floorPaths: [] },
    );
    expect(r.misses).toHaveLength(5);
    expect(judgePathReport(undefined, { cwd, floorPaths: [] })).toEqual({});
    expect(judgePathReport([], { cwd, floorPaths: [] })).toEqual({});
  });
});
