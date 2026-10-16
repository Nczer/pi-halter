import { describe, it, expect } from "vitest";
import os from "node:os";
import {
  combineCommonPaths,
  dirGrantLabel,
  dirListBody,
  filterSubPaths,
  pickCoveringDir,
  shortenHomePath,
} from "../ui/path-display";

describe("filterSubPaths", () => {
  it("removes sub-paths of parent directories", () => {
    expect(filterSubPaths(["/a/b/c", "/a"])).toEqual(["/a"]);
  });

  it("keeps sibling paths", () => {
    expect(filterSubPaths(["/a/b", "/a/c"])).toEqual(["/a/b", "/a/c"]);
  });

  it("handles trailing slashes", () => {
    expect(filterSubPaths(["/a/", "/a/b"])).toEqual(["/a/"]);
  });

  it("returns empty array for empty input", () => {
    expect(filterSubPaths([])).toEqual([]);
  });

  it("preserves order for non-overlapping paths", () => {
    expect(filterSubPaths(["/x", "/y", "/z"])).toEqual(["/x", "/y", "/z"]);
  });

  it("handles deeply nested sub-paths", () => {
    expect(filterSubPaths(["/a/b/c/d", "/a/b", "/a"])).toEqual(["/a"]);
  });
});

describe("shortenHomePath", () => {
  it("shortens $HOME-prefixed absolute paths to ~", () => {
    expect(shortenHomePath(`${os.homedir()}/pi/agent/file.ts`)).toBe("~/pi/agent/file.ts");
  });

  it("leaves other absolute and relative paths unchanged", () => {
    expect(shortenHomePath("/tmp/elsewhere/file.ts")).toBe("/tmp/elsewhere/file.ts");
    expect(shortenHomePath("relative/file.ts")).toBe("relative/file.ts");
  });

  it("does not shorten a sibling directory that shares the home prefix", () => {
    expect(shortenHomePath(`${os.homedir()}-other/file.ts`)).toBe(`${os.homedir()}-other/file.ts`);
  });
});

describe("combineCommonPaths", () => {
  it("combines siblings under a shared directory with &", () => {
    expect(combineCommonPaths(["a/b/x", "a/b/y"])).toBe("a/b/x & y");
  });

  it("keeps groups with unrelated paths separate", () => {
    expect(combineCommonPaths(["a/b/x", "a/b/y", "c/z"]).split(" ")).toContain("c/z");
    expect(combineCommonPaths(["a/b/x", "a/b/y", "c/z"])).toContain("a/b/x & y");
  });

  it("keeps nested remainders in the plain form when combining does not save", () => {
    // "a/b/c & bd/x" (12) vs "a/b/c a/bd/x" (12): no saving → plain join.
    expect(combineCommonPaths(["a/b/c", "a/bd/x"])).toBe("a/b/c a/bd/x");
  });

  it("does not combine top-level siblings (no shared directory)", () => {
    expect(combineCommonPaths(["/x", "/y"])).toBe("/x /y");
  });

  it("does not combine when the combination is not shorter", () => {
    // 2-char prefix: "a/b & c" (7) vs "a/b a/c" (7) — not strictly shorter.
    expect(combineCommonPaths(["a/b", "a/c"])).toBe("a/b a/c");
  });

  it("passes through single and empty lists", () => {
    expect(combineCommonPaths(["a/b/x"])).toBe("a/b/x");
    expect(combineCommonPaths([])).toBe("");
  });
});

describe("pickCoveringDir", () => {
  it("names the ancestor holding most of the dirs", () => {
    expect(
      pickCoveringDir(["/proj/a", "/proj/b", "/proj/c", "/elsewhere/d"]),
    ).toEqual({ covering: "/proj/", covered: 3, others: 1 });
  });

  it("covers the whole set when every dir hangs under one location", () => {
    expect(pickCoveringDir(["/proj/x/a", "/proj/x/b", "/proj/x/c", "/proj/x/d"])).toEqual({
      covering: "/proj/x/",
      covered: 4,
      others: 0,
    });
  });

  it("breaks ties to the deeper candidate (never claims more reach)", () => {
    // /p/ and /p/q/ both cover 2 entries — the deeper, more specific one wins.
    expect(pickCoveringDir(["/p/q/a", "/p/q/b", "/x", "/y"])).toEqual({
      covering: "/p/q/",
      covered: 2,
      others: 2,
    });
  });

  it("prefers the candidate covering more entries over a deeper one", () => {
    expect(pickCoveringDir(["/p/q/a", "/p/q/b", "/p/z", "/w"])).toEqual({
      covering: "/p/",
      covered: 3,
      others: 1,
    });
  });

  it("returns null for a list short enough to read in full", () => {
    expect(pickCoveringDir(["/proj/a", "/proj/b", "/proj/c"])).toBeNull();
  });

  it("returns null when nothing covers 2+ dirs (scattered set)", () => {
    expect(pickCoveringDir(["/vol1/a", "/vol2/b", "/vol3/c", "/vol4/d"])).toBeNull();
  });

  it("returns null when an unresolved marker dir is present (signal stays whole)", () => {
    expect(
      pickCoveringDir(["/proj/a", "/proj/b", "/proj/c", "<unresolved-cwd>"]),
    ).toBeNull();
  });

  it("never offers the filesystem root as the covering dir", () => {
    expect(pickCoveringDir(["/a", "/b", "/c", "/d"])).toBeNull();
  });

  it("shortens the covering dir under $HOME for display", () => {
    const s = pickCoveringDir([
      `${os.homedir()}/p/a`,
      `${os.homedir()}/p/b`,
      `${os.homedir()}/p/c`,
      "/elsewhere/d",
    ]);
    expect(s?.covering).toBe("~/p/");
  });
});

describe("dirListBody", () => {
  it("collapses to the granted parent when it is in the list (a/aa, a/ab, a → a)", () => {
    expect(dirListBody(["a/aa", "a/ab", "a"])).toBe("a");
    expect(dirListBody(["/a/aa", "/a/ab", "/a", "/x"])).toBe("/a, /x");
  });

  it("summarizes a set hanging under one dir with its count and the remainder", () => {
    expect(dirListBody(["/p/a", "/p/b", "/p/c", "/elsewhere/d"])).toBe(
      "/p/ (3 dirs under it) +1 others",
    );
  });

  it("drops the \"+N others\" tail when nothing sits elsewhere", () => {
    expect(dirListBody(["/p/a", "/p/b", "/p/c", "/p/sub/d"])).toBe("/p/ (4 dirs under it)");
  });

  it("leaves short lists in plain comma form", () => {
    expect(dirListBody(["/etc", "/mnt/Ndr/Download"])).toBe("/etc, /mnt/Ndr/Download");
  });

  it("combines scattered dirs for width instead of summarizing", () => {
    expect(dirListBody(["/vol1/share/x", "/vol2/y", "/vol3/z", "/tmp/w"])).toBe(
      "/tmp/w /vol1/share/x /vol2/y /vol3/z",
    );
  });
});

describe("dirGrantLabel", () => {
  it("names only the granted parent when it covers the rest", () => {
    expect(dirGrantLabel(["a/aa", "a/ab", "a"])).toBe("Read a/*");
  });

  it("counts the dirs instead of writing a dir/* rule for the covering dir", () => {
    // "/p/" is NOT granted — /p/a /p/b /p/c are; `Read /p/*` would overstate.
    expect(dirGrantLabel(["/p/a", "/p/b", "/p/c", "/elsewhere/d"])).toBe(
      "Read 3 dirs under /p/ +1 more",
    );
  });

  it("keeps the single-dir label in rule form (what Always actually mints)", () => {
    expect(dirGrantLabel(["/etc"])).toBe("Read /etc/*");
  });

  it("repeats Read per dir and caps scattered dirs at 3 entries plus an …+N tail", () => {
    expect(dirGrantLabel(["/v1/a", "/v2/b", "/v3/c", "/v4/d", "/v5/e"])).toBe(
      "Read /v1/a/*, Read /v2/b/*, Read /v3/c/* …+2 more dirs",
    );
  });

  it("stays under the label budget for a large scattered set", () => {
    const dirs = Array.from({ length: 40 }, (_, i) => `/vol${i}/leaf`);
    expect(dirGrantLabel(dirs).length).toBeLessThan(80);
  });

  it('returns "" for an empty tier (no dir Always option exists)', () => {
    expect(dirGrantLabel([])).toBe("");
  });
});
