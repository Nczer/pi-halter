/**
 * The brace arithmetic (analysis/brace.ts) — the one place a `{a,b}` group is
 * opened, for the location model (docs/dspa-intent-floor.md L2) and the
 * credential scan alike. These pins are the limits L2 set: what opens, what
 * stays a name, and where the walk stops and refuses.
 */
import { describe, expect, it } from "vitest";
import { braceVariants, openBraces } from "../analysis/brace";

const names = (n: number): string => `{${Array.from({ length: n }, (_, i) => `n${i}`).join(",")}}`;

describe("openBraces — what one word's braces do", () => {
  it("an alternation opens into the words it spells", () => {
    expect(openBraces("/x/{a,b}")).toEqual({ kind: "open", words: ["/x/a", "/x/b"] });
    expect(openBraces("/x/{a,}")).toEqual({ kind: "open", words: ["/x/a", "/x/"] });
  });

  it("a group spans directory levels", () => {
    expect(openBraces("a/{b/c,d}e")).toEqual({ kind: "open", words: ["a/b/ce", "a/de"] });
  });

  it("a branch may itself be a group: every name comes back whole", () => {
    expect(openBraces("{a,{b,c}}")).toEqual({ kind: "open", words: ["a", "b", "c"] });
    expect(openBraces("{a,{b,c}}/x")).toEqual({ kind: "open", words: ["a/x", "b/x", "c/x"] });
  });

  it("two groups multiply", () => {
    expect(openBraces("{a,b}x{c,d}")).toEqual({
      kind: "open",
      words: ["axc", "axd", "bxc", "bxd"],
    });
  });

  it("an unquoted brace that is not alternation is part of the name", () => {
    expect(openBraces("/x/{a}")).toEqual({ kind: "literal" });
    expect(openBraces("/x/{a,b")).toEqual({ kind: "literal" }); // unbalanced
    expect(openBraces("/x/\\{a,b\\}")).toEqual({ kind: "literal" }); // escaped
    expect(openBraces("/x/{a/b")).toEqual({ kind: "literal" });
  });

  it("a range is countable but is not a set of places", () => {
    expect(openBraces("/x/{1..200}")).toEqual({ kind: "range" });
    expect(openBraces("/x/{a..z}")).toEqual({ kind: "range" });
  });

  it("the caps: 16 words out of one token, nesting no deeper than 3", () => {
    expect(openBraces(`/x/${names(16)}`).kind).toBe("open");
    expect(openBraces(`/x/${names(17)}`).kind).toBe("tooMany");
    expect(openBraces("/x/{a,{b,{c,d}}}").kind).toBe("open"); // 3 levels, 4 words
    expect(openBraces("/x/{a,{b,{c,{d,e}}}}").kind).toBe("tooMany"); // 4 levels
  });

  it("an open never leaves a group inside a name", () => {
    const GROUP = /\{[^{}]*,[^{}]*\}/;
    for (const w of ["{a,{b,c}}", "{a,b}{c,d}", "/x/{a,{b,c}}/y", "{{a,b}"]) {
      const o = openBraces(w);
      expect(o.kind).toBe("open");
      if (o.kind === "open") expect(o.words.some((v) => GROUP.test(v))).toBe(false);
    }
  });
});

describe("braceVariants — the scan's wider cast", () => {
  it("the caller's limits are its own", () => {
    expect(braceVariants(names(20), 64, 4)?.length).toBe(20);
    expect(braceVariants(names(20), 16, 4)).toBeNull();
    expect(braceVariants("{a,{b,{c,{d,e}}}}", 64, 4)).toEqual(["a", "b", "c", "d", "e"]);
    expect(braceVariants("{a,{b,{c,{d,e}}}}", 64, 3)).toBeNull();
  });

  it("no group, one name", () => {
    expect(braceVariants("/x/y", 16, 3)).toEqual(["/x/y"]);
  });
});
