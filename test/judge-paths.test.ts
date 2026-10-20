/**
 * judge-paths.ts (D13) — sanitizing the stage-2 judge's path report and
 * cross-checking it against the floor's own knowledge. Pure functions, no
 * model, no disk.
 */
import { describe, expect, it } from "vitest";
import os from "node:os";
import fs from "node:fs";
import path from "node:path";
import { canon } from "./canon";
import {
  sanitizeJudgePaths,
  judgePathReport,
  type JudgePathFloor,
} from "../judge/paths";
import { OPAQUE_VAR_DIR } from "../analysis/bash-parser";
import { UNKNOWN_CWD_MARKER } from "../analysis/cwd-tracking";

const cwd = "/Users/u/project";
const home = os.homedir();

describe("sanitizeJudgePaths", () => {
  it("resolves relatives against the cwd and expands ~", () => {
    expect(sanitizeJudgePaths(["target/x", "~/data"], cwd)).toEqual([
      "/Users/u/project/target/x",
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

  it("§4.5: URL-shaped tokens are dropped, never resolved against the cwd", () => {
    // The sampled report sent `http://127.0.0.1:8080`; resolving it made
    // `<cwd>/http:/127.0.0.1:8080`, a fake path under the operation's base.
    expect(
      sanitizeJudgePaths(["http://127.0.0.1:8080", "s3://bucket/key", "real/file"], cwd),
    ).toEqual([`${cwd}/real/file`]);
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
    floorPaths: ["/Users/u/project/target", "/Users/u/project/data/*.log"],
    confirmedDirs: ["/granted/dir"],
  };

  it("covers: equal, under-a-floor-path, glob-ancestor, confirmed dir, cwd", () => {
    const r = judgePathReport(
      [
        "/Users/u/project/target", // equal
        "/Users/u/project/target/release", // under a floor path
        "/Users/u/project/data/app.log", // under a GLOB floor path
        "/granted/dir/f", // confirmed dir
        cwd, // the cwd itself
      ],
      floor,
    );
    expect(r.paths).toHaveLength(5);
    expect(r.floorMisses).toBeUndefined();
  });

  it("floorMisses: unrelated paths (the parser-gap signal)", () => {
    const r = judgePathReport([canon("/etc/shadow"), "/Users/u/project/target"], {
      cwd,
      floorPaths: ["/Users/u/project/target"],
    });
    expect(r.paths).toEqual([canon("/etc/shadow"), "/Users/u/project/target"]);
    expect(r.floorMisses).toEqual([canon("/etc/shadow")]);
  });

  it("a literal floor path under the report is COVERED (2026-10-04, D23)", () => {
    // The floor saw /y/z; the judge named /y — the same location generalized
    // upward, not a place the gate never saw. A broader claim still escalates
    // where it matters (the write bar, dspa-gate.ts judgeWriteOutside, sees
    // the sanitized `writes` list directly); this is the diagnostic only.
    const r = judgePathReport(["/y"], { cwd: "/x", floorPaths: ["/y/z"] });
    expect(r.floorMisses).toBeUndefined();
  });

  it("contextMisses: a miss the judge only saw in the Session context section is split out, never suppressed", () => {
    const r = judgePathReport(["/seen/in/context", "/never/seen"], {
      cwd: "/x",
      floorPaths: ["/x"],
      contextPaths: ["/seen/in"],
    });
    expect(r.floorMisses).toEqual(["/never/seen"]);
    expect(r.contextMisses).toEqual(["/seen/in/context"]);
  });

  it("§4.4: with no concrete floor path the row stays a floorMiss, never context bleed", () => {
    // The floor named nothing of its own, so it cannot have been out-of-date
    // about a path it never derived — calling this context bleed hid a parser
    // gap (2026-10-18T03:02:28, the sweep.sh row).
    const r = judgePathReport(["/seen/in/context"], {
      cwd: "/x",
      floorPaths: [`${OPAQUE_VAR_DIR}/base`],
      contextPaths: ["/seen/in"],
    });
    expect(r.floorMisses).toEqual(["/seen/in/context"]);
    expect(r.contextMisses).toBeUndefined();
  });

  it("sentinels in the floor set are not knowledge", () => {
    const r = judgePathReport(["/a"], {
      cwd: "/x",
      floorPaths: [`${OPAQUE_VAR_DIR}/a`],
    });
    expect(r.floorMisses).toEqual(["/a"]);
  });

  it("a judge path reaching the floor's path through a symlink is covered (resolved both sides)", () => {
    const real = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "halter-jp-real-")));
    const linkRoot = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "halter-jp-link-")));
    try {
      const link = path.join(linkRoot, "link");
      fs.symlinkSync(real, link);
      const r = judgePathReport([path.join(link, "target")], {
        cwd: "/x",
        floorPaths: [path.join(real, "target")],
      });
      expect(r.floorMisses).toBeUndefined();
    } finally {
      fs.rmSync(real, { recursive: true, force: true });
      fs.rmSync(linkRoot, { recursive: true, force: true });
    }
  });

  it("caps floorMisses at 5; {} when the model reported nothing", () => {
    const r = judgePathReport(
      Array.from({ length: 8 }, (_, i) => `/m${i}`),
      { cwd, floorPaths: [] },
    );
    expect(r.floorMisses).toHaveLength(5);
    expect(judgePathReport(undefined, { cwd, floorPaths: [] })).toEqual({});
    expect(judgePathReport([], { cwd, floorPaths: [] })).toEqual({});
  });
});
