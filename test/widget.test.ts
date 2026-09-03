import { describe, it, expect, beforeEach, vi } from "vitest";
import os from "node:os";
import {
  combineCommonPaths,
  filterSubPaths,
  groupCommandVariants,
  renderRulesLine,
  shortenHomePath,
  updateWidget,
} from "../ui/widget";
import { store } from "../gate/store";
import { resetDspa, recordDspaAutoAllowed, setDspaActive } from "../modes/dspa-mode";

// The widget calls judgeStatus(ctx) per render; the real one reads the user's
// live settings + model registry — mock it so mode-line tests are hermetic.
vi.mock("../judge/verdict", async (importOriginal) => {
  const mod = await importOriginal<typeof import("../judge/verdict")>();
  return { ...mod, judgeStatus: vi.fn(() => ({ state: "ok", modelLabel: null, reason: null })) };
});

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
  const theme = { fg: (_style: string, text?: string) => text ?? "", bold: (t?: string) => t ?? "" };
  const ctx = {
    ui: {
      setWidget: (_id: string, fn: unknown) => {
        setWidgetCalled = true;
        widgetFn = (fn ?? null) as typeof widgetFn;
      },
    },
    // Session model for the DSPA tag comparison (provider/id ref).
    model: { provider: "llama-cpp", id: "Qwen3.8-27B" },
  } as never;

  beforeEach(() => {
    store.reset();
    resetDspa();
    widgetFn = null;
    setWidgetCalled = false;
  });

  it("cwd-bound grants render on the merged rules line with the bound cwd", () => {
    store.addAllowed({ bashSigCwds: [{ sig: "./node_modules/.bin/mytool --do", cwd: "/home/u/proj1" }] });
    updateWidget(ctx);
    expect(widgetFn).not.toBeNull();
    const lines = widgetFn!(null, theme).render(200);
    expect(lines).toHaveLength(1);
    expect(lines[0]).toBe("· Cwd: ./node_modules/.bin/mytool --do @ /home/u/proj1");
  });

  it("keeps unbound Bash sigs and cwd-bound grants on the one rules line", () => {
    store.addAllowed({
      bashSigs: ["du"],
      bashSigCwds: [{ sig: "./node_modules/.bin/mytool --do", cwd: "/home/u/proj1" }],
    });
    updateWidget(ctx);
    const lines = widgetFn!(null, theme).render(200);
    expect(lines).toHaveLength(1);
    expect(lines[0]).toBe("· Bash: du · Cwd: ./node_modules/.bin/mytool --do @ /home/u/proj1");
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

  it("merges rule categories onto one line in safety-priority order", () => {
    store.addAllowed({
      writePaths: ["/a/w"],
      readPaths: ["/a/r", "/a/w"],
      bashSigs: ["du"],
    });
    store.trustPackage("vitest");
    updateWidget(ctx);
    const lines = widgetFn!(null, theme).render(200);
    expect(lines).toHaveLength(1);
    // /a/w is a write path, so it drops out of the read-only list.
    expect(lines[0]).toBe("· R/W: /a/w · R: /a/r · Bash: du · Pkg: vitest");
  });

  it("caps path lists at 3 with a …+N tail and sibling-combines the shown ones", () => {
    const home = os.homedir();
    store.addAllowed({
      writePaths: [
        `${home}/pi/agent/extensions/filechanges`,
        `${home}/pi/agent/extensions/gallop`,
        `${home}/pi/agent/extensions/halter`,
        `${home}/pi/agent/extensions/memory`,
      ],
    });
    updateWidget(ctx);
    const lines = widgetFn!(null, theme).render(300);
    expect(lines[0]).toBe("· R/W: ~/pi/agent/extensions/filechanges & gallop & halter …+1");
  });

  it("drops whole low-priority segments behind one …+N marker on narrow widths", () => {
    store.addAllowed({
      writePaths: ["/a/w"],
      readPaths: ["/b/r"],
    });
    store.trustPackage("vitest");
    updateWidget(ctx);
    // Width fits only the R/W segment plus the …+N marker (17 cols), not the
    // R or Pkg segments (27 / 35) — they drop behind one marker.
    const lines = widgetFn!(null, theme).render(20);
    expect(lines[0]).toBe("· R/W: /a/w · …+2");
  });

  it("shows no model tag when the judge model is the session model", () => {
    setDspaActive(true);
    recordDspaAutoAllowed("llama-cpp/Qwen3.8-27B", `Edit ${os.homedir()}/x/f.ts`);
    updateWidget(ctx);
    const lines = widgetFn!(null, theme).render(200);
    expect(lines).toHaveLength(1);
    expect(lines[0]).toBe("» DSPA: 1a — last: Edit ~/x/f.ts");
  });

  it("shows the short model name when the judge model differs from the session model", () => {
    setDspaActive(true);
    recordDspaAutoAllowed("ollama/Other-9B", "Edit f.ts");
    updateWidget(ctx);
    const lines = widgetFn!(null, theme).render(200);
    expect(lines[0]).toBe("» DSPA (Other-9B): 1a — last: Edit f.ts");
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

describe("renderRulesLine", () => {
  const theme = { fg: (_style: string, text?: string) => text ?? "" };

  it("returns null for no segments", () => {
    expect(renderRulesLine(200, theme, [])).toBeNull();
  });

  it("joins segments with · and leads the line with · ", () => {
    expect(renderRulesLine(200, theme, [{ label: "R/W", text: "a" }, { label: "Pkg", text: "b" }])).toBe("· R/W: a · Pkg: b");
  });
});
