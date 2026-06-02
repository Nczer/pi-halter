import { describe, it, expect } from "vitest";
import { filterSubPaths, groupCommandVariants } from "../widget";

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

describe("groupCommandVariants", () => {
  it("groups same command with different flags", () => {
    const result = groupCommandVariants(["git -m", "git -am"]);
    expect(result).toContain("git[git -am, git -m]");
  });

  it("shows single command without grouping", () => {
    expect(groupCommandVariants(["ls"])).toEqual(["ls"]);
  });

  it("shows command with single flag variant", () => {
    expect(groupCommandVariants(["git -m"])).toEqual(["git -m"]);
  });

  it("handles mixed flag/no-flag variants", () => {
    const result = groupCommandVariants(["git", "git -m"]);
    expect(result).toContain("git[git, git -m]");
  });

  it("handles multiple commands independently", () => {
    const result = groupCommandVariants(["ls", "git -m", "git -am"]);
    expect(result).toContain("ls");
    expect(result).toContain("git[git -am, git -m]");
  });

  it("returns empty array for empty input", () => {
    expect(groupCommandVariants([])).toEqual([]);
  });
});
