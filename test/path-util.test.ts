import { describe, expect, it } from "vitest";
import os from "node:os";
import path from "node:path";
import {
  under,
  rememberedDirOf,
  isUnresolvedPath,
  isUnresolvedMarker,
  staticPrefixOf,
  OPAQUE_VAR_DIR,
  UNKNOWN_CWD_MARKER,
} from "../analysis/path-util";

const home = os.homedir();

// Step 1 of the location model (docs/dspa-intent-floor.md §9 L4/L3): the one
// containment test, and the one rule for the folder an approval remembers.
// Before this, five copies of the containment answer existed and 18 call sites
// spelled it inline; two of those copies disagreed about the same token
// (3.44.0), which is what the strictness below makes impossible to repeat.

describe("under — containment, real-disk form on both sides", () => {
  it("a dir is inside itself", () => {
    expect(under("/a/b", "/a/b")).toBe(true);
  });

  it("a subdir and a deep file are inside", () => {
    expect(under("/a/b/c", "/a/b")).toBe(true);
    expect(under("/a/b/c/d.txt", "/a/b")).toBe(true);
  });

  it("a sibling sharing a name prefix is NOT inside (the prefix bug)", () => {
    expect(under("/a/bc", "/a/b")).toBe(false);
    expect(under("/optfoo", "/opt")).toBe(false);
  });

  it("the parent is not inside the child", () => {
    expect(under("/a", "/a/b")).toBe(false);
  });

  it("the root contains every absolute path", () => {
    expect(under("/etc/hosts", "/")).toBe(true);
    expect(under("/", "/")).toBe(true);
  });

  it("refuses a relative side instead of guessing", () => {
    expect(() => under("src/index.ts", home)).toThrow(/names no location/);
    expect(() => under(home, ".")).toThrow(/names no location/);
  });

  it("refuses either unnameable-location spelling", () => {
    expect(() => under(`${OPAQUE_VAR_DIR}/base/x`, home)).toThrow(/names no location/);
    expect(() => under(home, UNKNOWN_CWD_MARKER)).toThrow(/names no location/);
  });

  it("refuses a side that is not in real-disk form", () => {
    // A lexical `..` or `.` left in the text means the caller skipped
    // resolvePathReal: the answer would depend on spelling, not on where the
    // dir really is.
    expect(() => under("/a/b/../c", "/a")).toThrow(/real-disk form/);
    expect(() => under("/a//b", "/a")).toThrow(/real-disk form/);
    expect(() => under("/a/./b", "/a")).toThrow(/real-disk form/);
  });

  it("agrees with staticPrefixOf about an anchored word's folder", () => {
    const anchor = staticPrefixOf("/tmp/snap-x/$e");
    expect(under("/tmp/snap-x/exa", anchor)).toBe(true);
  });
});

describe("rememberedDirOf — the folder an approval can remember", () => {
  it("a named leaf remembers its containing dir", () => {
    expect(rememberedDirOf("/a/b/c.txt")).toBe("/a/b");
    expect(rememberedDirOf(`${home}/notes/todo.md`)).toBe(`${home}/notes`);
  });

  it("a wildcard leaf remembers the dir it globs in", () => {
    expect(rememberedDirOf(`${home}/notes/*`)).toBe(`${home}/notes`);
  });

  it("a group cut mid-word remembers the real dir above it, not the cut", () => {
    // The 3.44.0 dead-grant class: `/tmp/{a,b}/x` used to remember
    // `/tmp/{a,b`, which is no directory, so the command re-stopped after the
    // user had already allowed it.
    expect(rememberedDirOf("/tmp/{a,b}/x")).toBe("/tmp");
    expect(rememberedDirOf(`${home}/{notes,inbox}`)).toBe(home);
  });

  it("a word dynamic in its first segment pins no folder", () => {
    expect(rememberedDirOf("$X/*")).toBe("");
    expect(rememberedDirOf("$(pwd)/x")).toBe("");
  });

  it("a relative word pins no folder (it still needs a base)", () => {
    expect(rememberedDirOf("notes/todo.md")).toBe("");
  });

  it("expands ~ like the path model does", () => {
    expect(rememberedDirOf("~/notes/todo.md")).toBe(path.join(home, "notes"));
  });

  it("a word pinned only to the root pins no approvable folder", () => {
    expect(rememberedDirOf("/etc/hosts")).toBe("/etc");
    // `/etc` itself, and a word in a top-level folder that does not exist, are
    // pinned to `/` — a grant there is the bar switched off, so "" (the caller
    // keeps the word as the location and the stop still fires).
    expect(rememberedDirOf("/etc")).toBe("");
    expect(rememberedDirOf("/halt-pfx-nonexistent")).toBe("");
  });

  it("an opaque marker word names no grantable folder", () => {
    // Its static prefix IS nameable (`/tmp/snap-x`), but a var value can hold
    // `..`, so a grant of the prefix could never satisfy the marker that keeps
    // forcing approval — minting it would be a dead, misleading grant.
    expect(rememberedDirOf(`${OPAQUE_VAR_DIR}/tmp/snap-x/$e`)).toBe("");
  });
});

describe("isUnresolvedPath / isUnresolvedMarker", () => {
  it("a plain absolute path is resolved enough to compare", () => {
    expect(isUnresolvedPath(`${home}/notes/todo.md`)).toBe(false);
    expect(isUnresolvedMarker(`${home}/notes/todo.md`)).toBe(false);
  });

  it("relative words are unresolved for a comparison but fixable by a base", () => {
    expect(isUnresolvedPath("notes/todo.md")).toBe(true);
    expect(isUnresolvedMarker("notes/todo.md")).toBe(false);
  });

  it("both markers are unresolved anywhere in the word", () => {
    expect(isUnresolvedPath(`${home}/${UNKNOWN_CWD_MARKER}/x`)).toBe(true);
    expect(isUnresolvedMarker(`x/${OPAQUE_VAR_DIR}`)).toBe(true);
  });
});
