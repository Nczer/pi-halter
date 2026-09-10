import { describe, it, expect, beforeEach, vi } from "vitest";
import os from "node:os";
import {
  combineCommonPaths,
  filterSubPaths,
  groupCommandVariants,
  renderRulesLine,
  shortenHomePath,
  updateStatus,
} from "../ui/widget";
import { store } from "../gate/store";
import { resetDspa, recordDspaAutoAllowed, setDspaActive, setDspaJudging } from "../modes/dspa-mode";
import { setDspatActive, setDspatJudging } from "../modes/dspat-mode";

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

describe("updateStatus", () => {
  // The status reads the module singleton store; tests in this file own it.
  // The budget is FIXED (setStatus has no width parameter), so the string
  // trims itself — expectations below are exact strings.
  let status: string | undefined;
  const theme = { fg: (_style: string, text?: string) => text ?? "", bold: (t?: string) => t ?? "" };
  const ctx = {
    hasUI: true,
    ui: {
      setStatus: (_id: string, value?: string) => {
        status = value;
      },
      setWidget: () => {}, // legacy id clears
      theme,
    },
    // Session model for the DSPA tag comparison (provider/id ref).
    model: { provider: "llama-cpp", id: "Qwen3.8-27B" },
  } as never;

  beforeEach(() => {
    store.reset();
    resetDspa();
    status = undefined;
  });

  it("renders cwd-bound grants on the status line with the bound cwd", () => {
    store.addAllowed({ bashSigCwds: [{ sig: "./tool", cwd: "/a" }] });
    updateStatus(ctx);
    expect(status).toBe("· Cwd: ./tool @ /a");
  });

  it("keeps unbound Bash sigs and cwd-bound grants on the one line", () => {
    store.addAllowed({
      bashSigs: ["du"],
      bashSigCwds: [{ sig: "./tool", cwd: "/a" }],
    });
    updateStatus(ctx);
    expect(status).toBe("· Bash: du · Cwd: ./tool @ /a");
  });

  it("hides the status with no rules at all", () => {
    updateStatus(ctx);
    expect(status).toBeUndefined();
  });

  it("merges rule categories in safety-priority order (the budget trims the tail)", () => {
    store.addAllowed({
      writePaths: ["/a/w"],
      readPaths: ["/a/r", "/a/w"],
      bashSigs: ["du"],
    });
    store.trustPackage("vitest");
    updateStatus(ctx);
    // /a/w is a write path, so it drops out of the read-only list.
    expect(status).toBe("· R/W: /a/w · R: /a/r · Bash: du · Pkg: vitest");
  });

  it("caps path lists at 3 with a …+N tail and sibling-combines the shown ones", () => {
    store.addAllowed({
      writePaths: ["/a/x1", "/a/x2", "/a/x3", "/a/x4"],
    });
    updateStatus(ctx);
    expect(status).toBe("· R/W: /a/x1 & x2 & x3 …+1");
  });

  it("drops whole low-priority segments behind …+N when they outgrow the budget", () => {
    setDspaActive(true);
    recordDspaAutoAllowed("llama-cpp/Qwen3.8-27B", "ls");
    store.addAllowed({
      // Long enough that the Bash segment alone can't share the line with
      // the path segments (budget 120, main 10 → 109 for rules).
      writePaths: ["/mnt/Ndr/Projects/alpha/file1.ts", "/mnt/Ndr/Projects/beta/file2.ts"],
      readPaths: ["/mnt/Ndr/Projects/delta/file4.ts"],
      bashSigs: [
        "npm run build --watch",
        "npx vitest run --coverage",
        'git commit -am "work"',
      ],
    });
    store.trustPackage("vitest");
    updateStatus(ctx);
    // R/W + R fit; Bash + Pkg drop behind one marker (116 total ≤ 120).
    // (Sibling paths share the /mnt/Ndr/Projects prefix → combined.)
    expect(status).toBe(
      "» DSPA: 1a · R/W: /mnt/Ndr/Projects/alpha/file1.ts & beta/file2.ts"
        + " · R: /mnt/Ndr/Projects/delta/file4.ts · …+2",
    );
  });

  it("shows no model tag when the judge model is the session model", () => {
    setDspaActive(true);
    recordDspaAutoAllowed("llama-cpp/Qwen3.8-27B", `Edit ${os.homedir()}/x/f.ts`);
    updateStatus(ctx);
    // No "— last:" target; idle = no judging tail (counts only).
    expect(status).toBe("» DSPA: 1a");
  });

  it("shows the short model name when the judge model differs from the session model", () => {
    setDspaActive(true);
    recordDspaAutoAllowed("ollama/Other-9B", "Edit f.ts");
    updateStatus(ctx);
    expect(status).toBe("» DSPA (Other-9B): 1a");
  });

  it("paints the in-flight judging stage inline on the DSPA line (restored indicator)", () => {
    setDspaActive(true);
    recordDspaAutoAllowed("llama-cpp/Qwen3.8-27B", "ls");
    setDspaJudging(2, ctx);
    updateStatus(ctx);
    expect(status).toBe("» DSPA: 1a — judging stage 2…");
    setDspaJudging(null, ctx);
    updateStatus(ctx);
    expect(status).toBe("» DSPA: 1a");
  });

  it("paints the in-flight judging stage inline on the DSPAT line", () => {
    setDspatActive(true);
    setDspatJudging(1, ctx);
    updateStatus(ctx);
    expect(status).toBe("◎ DSPAT — judging stage 1…");
    setDspatJudging(null, ctx);
    updateStatus(ctx);
    expect(status).toBe("◎ DSPAT");
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
