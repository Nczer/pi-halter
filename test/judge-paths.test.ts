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

  it("keeps the WHOLE report — the sanitizer is not capped (3.44.0)", () => {
    // The 8-path cap used to live here, so it also cut the INPUTS: the D19
    // write bar checked 8 of 12 reported writes, and §4.2's answer set hid
    // answers past #8. The cap is a row-writing concern (JUDGE_PATHS_MAX),
    // and a cut row records the remainder.
    const many = Array.from({ length: 20 }, (_, i) => `/p${i}`);
    expect(sanitizeJudgePaths(many, cwd)).toHaveLength(20);
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

  it("a dynamic floor path covers its ANCHOR dir — the gate's own rule (3.44.0)", () => {
    // The floor's `$e`/glob token cannot name a leaf but pins the directory:
    // the 2026-10-26 ledger burned 2 of 5 miss slots on /tmp/snap-x/exa and
    // /tmp/snap-x/gallop for a floor that had /tmp/snap-x/$e.
    const r = judgePathReport(
      ["/tmp/snap-x/exa", "/tmp/snap-x/gallop", "/tmp/snap-x/memory"],
      { cwd, floorPaths: ["/tmp/snap-x/$e", "/Users/u/project/data/*.log"] },
    );
    expect(r.floorMisses).toBeUndefined();
    // …and the anchor is a directory, not a free pass: an unrelated report
    // under no floor path is still a blind spot.
    const r2 = judgePathReport(["/tmp/elsewhere/x"], {
      cwd,
      floorPaths: ["/tmp/snap-x/$e"],
    });
    expect(r2.floorMisses).toEqual(["/tmp/elsewhere/x"]);
  });

  it("a floor path whose FIRST segment is dynamic gives the floor no anchor", () => {
    // `/[abc]/x` pins no directory — the whole first segment is unknown — so
    // the report stays a blind spot instead of being absorbed by a fake root.
    const r = judgePathReport(["/[abc]/y"], {
      cwd,
      floorPaths: ["/[abc]/x"],
    });
    expect(r.floorMisses).toEqual(["/[abc]/y"]);
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

/**
 * 3.43.0: the floor↔judge disagreement split by ROLE instead of location.
 * Both directions share one question — "does the command WRITE here" — and
 * are owned by opposite sides, so they must stay disjoint and separate.
 */
describe("judgePathReport — role disagreement", () => {
  it("roleFloorMisses: the judge reports a write the floor's write set does not cover", () => {
    // The floor derived /srv/data/app.db as an operand (so it is NOT a
    // floorMiss) but as a READ — `cp /srv/data/app.db ./copy`. The judge
    // says it writes there: the parser's role table is the gap to mine.
    const r = judgePathReport(["/srv/data/app.db"], {
      cwd,
      floorPaths: ["/srv/data/app.db"],
      floorWritePaths: ["/Users/u/project/copy"],
    }, ["/srv/data/app.db"]);
    expect(r.floorMisses).toBeUndefined();
    expect(r.roleFloorMisses).toEqual(["/srv/data/app.db"]);
    expect(r.roleJudgeMisses).toBeUndefined();
  });

  it("roleJudgeMisses: an out-of-cwd floor write the verdict never claims as a write", () => {
    // Variant A — the omission counts: a report that leaves `writes` empty
    // while the floor has an out-of-cwd write operand reasoned about a write
    // as if it were a read.
    const floor: JudgePathFloor = {
      cwd,
      floorPaths: ["/srv/data/app.db"],
      floorWritePaths: ["/srv/data/app.db"],
    };
    const r = judgePathReport(["/srv/data/app.db"], floor);
    expect(r.floorMisses).toBeUndefined();
    expect(r.roleJudgeMisses).toEqual(["/srv/data/app.db"]);
    expect(r.roleFloorMisses).toBeUndefined();
    // …and the same when a writes list exists but names somewhere else: the
    // floor operand is still unclaimed.
    const r2 = judgePathReport(["/srv/data/app.db", "/srv/other/x"], floor, ["/srv/other/x"]);
    expect(r2.roleJudgeMisses).toEqual(["/srv/data/app.db"]);
  });

  it("writes inside the session cwd are the working set — no role row either way", () => {
    const r = judgePathReport(["build/out.js"], {
      cwd,
      floorPaths: [`${cwd}/build/out.js`],
      floorWritePaths: [`${cwd}/build/other.js`],
    }, [`${cwd}/build/out.js`]);
    expect(r.roleFloorMisses).toBeUndefined();
    expect(r.roleJudgeMisses).toBeUndefined();
  });

  it("attribution stays disjoint: a location the floor never derived is only a floorMiss", () => {
    const r = judgePathReport(["/never/derived"], {
      cwd,
      floorPaths: [],
      floorWritePaths: [],
    }, ["/never/derived"]);
    expect(r.floorMisses).toEqual(["/never/derived"]);
    expect(r.roleFloorMisses).toBeUndefined();
  });

  it("ancestor-tolerant both ways (the gate's own writeRoleAt rule)", () => {
    // The judge names the directory, the floor has the file under it: the
    // same location, and the write bar sees the raw list regardless.
    const r = judgePathReport(["/srv/data"], {
      cwd,
      floorPaths: ["/srv/data/app.db"],
      floorWritePaths: ["/srv/data/app.db"],
    }, ["/srv/data"]);
    expect(r.floorMisses).toBeUndefined();
    expect(r.roleFloorMisses).toBeUndefined();
    expect(r.roleJudgeMisses).toBeUndefined();
  });

  it("no role comparison at all without both sides; sentinels are not write operands", () => {
    expect(judgePathReport([canon("/etc/shadow")], { cwd, floorPaths: [] }).roleJudgeMisses).toBeUndefined();
    const r = judgePathReport(["/srv/data/app.db"], {
      cwd,
      floorPaths: ["/srv/data/app.db"],
      floorWritePaths: [`${OPAQUE_VAR_DIR}/app.db`, `${UNKNOWN_CWD_MARKER}/app.db`],
    }, []);
    expect(r.roleJudgeMisses).toBeUndefined();
    expect(r.roleFloorMisses).toBeUndefined();
  });

  it("role lists cap at 5, like the set misses", () => {
    const writes = Array.from({ length: 8 }, (_, i) => `/w${i}`);
    const r = judgePathReport(writes, {
      cwd,
      floorPaths: writes,
      floorWritePaths: writes,
    }, []);
    expect(r.roleJudgeMisses).toHaveLength(5);
  });
});
