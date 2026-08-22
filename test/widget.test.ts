import { describe, it, expect, beforeEach } from "vitest";
import { filterSubPaths, groupCommandVariants, updateWidget } from "../widget";
import { store } from "../store";

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
    expect(result).toEqual(["git(-am, -m)"]);
  });

  it("shows single command without grouping", () => {
    expect(groupCommandVariants(["ls"])).toEqual(["ls"]);
  });

  it("shows command with single flag variant", () => {
    expect(groupCommandVariants(["git -m"])).toEqual(["git(-m)"]);
  });

  it("collapses bare cmd with variants to cmd(*)", () => {
    const result = groupCommandVariants(["git", "git -m"]);
    expect(result).toEqual(["git(*)"]);
  });

  it("handles multiple commands independently", () => {
    const result = groupCommandVariants(["ls", "git -m", "git -am"]);
    expect(result).toContain("ls");
    expect(result).toContain("git(-am, -m)");
  });

  it("collapses bare cmd + multiple variants to cmd(*)", () => {
    const result = groupCommandVariants(["git", "git -m", "git -am"]);
    expect(result).toEqual(["git(*)"]);
  });

  it("returns empty array for empty input", () => {
    expect(groupCommandVariants([])).toEqual([]);
  });
});

describe("updateWidget", () => {
  // The widget reads the module singleton store; tests in this file own it.
  let widgetFn: ((tui: unknown, theme: unknown) => { render: (w: number) => string[]; invalidate: () => void }) | null;
  let setWidgetCalled = false;
  const theme = { fg: (_style: string, text?: string) => text ?? "" };
  const ctx = {
    ui: {
      setWidget: (_id: string, fn: unknown) => {
        setWidgetCalled = true;
        widgetFn = (fn ?? null) as typeof widgetFn;
      },
    },
  } as never;

  beforeEach(() => {
    store.reset();
    widgetFn = null;
    setWidgetCalled = false;
  });

  it("cwd-bound grants render on their own Cwd line with the bound cwd", () => {
    store.addAllowed({ bashSigCwds: [{ sig: "./node_modules/.bin/mytool --do", cwd: "/home/u/proj1" }] });
    updateWidget(ctx);
    expect(widgetFn).not.toBeNull();
    const lines = widgetFn!(null, theme).render(200);
    expect(lines).toHaveLength(1);
    expect(lines[0]).toBe("Cwd: ./node_modules/.bin/mytool --do @ /home/u/proj1");
  });

  it("keeps unbound Bash sigs and cwd-bound grants on separate lines", () => {
    store.addAllowed({
      bashSigs: ["du"],
      bashSigCwds: [{ sig: "./node_modules/.bin/mytool --do", cwd: "/home/u/proj1" }],
    });
    updateWidget(ctx);
    const lines = widgetFn!(null, theme).render(200);
    expect(lines).toContain("Bash: du");
    expect(lines).toContain("Cwd: ./node_modules/.bin/mytool --do @ /home/u/proj1");
  });

  it("cwd-bound grants alone keep the widget visible", () => {
    store.addAllowed({ bashSigCwds: [{ sig: "./tool", cwd: "/a" }] });
    updateWidget(ctx);
    expect(widgetFn).not.toBeNull();
    expect(widgetFn!(null, theme).render(200)).toHaveLength(1);
  });

  it("hides the widget with no rules at all", () => {
    updateWidget(ctx);
    expect(setWidgetCalled).toBe(true);
    expect(widgetFn).toBeNull();
  });
});
