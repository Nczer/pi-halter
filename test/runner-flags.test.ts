/**
 * G7 — the runner's closed world: what a run form FETCHES, and which of its
 * options a grant can vouch for. Two tables decide both (bash-patterns
 * FETCH_PKG_SELECT/UV_VALUE_FLAGS and trusted-scripts' uv option classes), and
 * the same scan feeds the dspa floor's stop, the D10 trust gate, the grant
 * signature and the trusted-script umbrella. These rows are the unit layer of
 * that; the end-to-end pairs live in verified-bypasses.test.ts (P16).
 */
import { describe, expect, it } from "vitest";
import { fetchFormScan, uvRunFlags, uvFetchFormOk, isTrustedScriptCommand } from "../config";
import { tokenizeSegmentQuoted } from "../analysis/tokenizer";
import {
  segmentFetchPackage, segmentNamesRunOptions, segmentRunFormUngrantable,
  segmentFetchOptionsOk, uvRunSignature, getCommandSignature,
} from "../analysis/segment-helpers";

// ── the fetch set: every package a fetchable run form installs ──

describe("fetchFormScan — the fetch set, not the first word after the flags", () => {
  it("a package-select flag's value IS the fetch; the trailing word runs from inside it", () => {
    // The G7 hole: `npx --package=evil-pkg tsc` was vouched for by a grant for
    // `tsc`, a package the command never fetched.
    expect(fetchFormScan("npx", "npx --package=evil-pkg tsc".split(" "))).toEqual({ pkgs: ["evil-pkg"], opaque: false });
    expect(fetchFormScan("npx", "npx -p typescript tsc".split(" "))).toEqual({ pkgs: ["typescript"], opaque: false });
    expect(fetchFormScan("npx", "npx -p a -p b cmd".split(" "))).toEqual({ pkgs: ["a", "b"], opaque: false });
    expect(fetchFormScan("npm", "npm exec -p a -- cmd".split(" "))).toEqual({ pkgs: ["a"], opaque: false });
    expect(fetchFormScan("uvx", "uvx --from=evil-pkg tsc".split(" "))).toEqual({ pkgs: ["evil-pkg"], opaque: false });
    expect(fetchFormScan("bun", "bun x --package pkg cmd".split(" "))).toEqual({ pkgs: ["pkg"], opaque: false });
  });

  it("select flags are per family: uv's `-p` is an interpreter, not a package", () => {
    expect(fetchFormScan("uvx", "uvx --python 3.12 tsc".split(" "))).toEqual({ pkgs: ["tsc"], opaque: false });
    expect(fetchFormScan("uvx", "uvx -p /tmp/evil/python tsc".split(" "))).toEqual({ pkgs: ["tsc"], opaque: false });
    // …and an option the family does not model names its value as the package
    // (fail closed, and the honest limit documented in docs/dspa-redesign.md).
    expect(fetchFormScan("pnpm", "pnpm dlx --registry http://x tsc".split(" "))).toEqual({ pkgs: ["http://x"], opaque: false });
  });

  it("uv's two-word `tool run` is uvx and is gated like it", () => {
    expect(segmentFetchPackage("uv tool run evil-pkg tsc")).toEqual({ first: "uv", pkgs: ["evil-pkg"], opaque: false });
    expect(segmentFetchPackage("uv x tsc")).toEqual({ first: "uv", pkgs: ["tsc"], opaque: false });
  });

  it("trust keys are bare package names; prefixes and wrappers resolve first", () => {
    expect(segmentFetchPackage("npx tsc@5.0.0 --noEmit")!.pkgs).toEqual(["tsc"]);
    expect(segmentFetchPackage("npx @Org/Tool")!.pkgs).toEqual(["@Org/Tool"]); // case kept
    expect(segmentFetchPackage("FOO=bar npx evil")!.pkgs).toEqual(["evil"]);
    expect(segmentFetchPackage("timeout 5 uvx evil")!.pkgs).toEqual(["evil"]);
    // LOCAL run forms execute repo-visible code: never a fetch, never gated.
    expect(segmentFetchPackage("npm run build")).toBeNull();
    expect(segmentFetchPackage("uv run --with pandas python x.py")).toBeNull();
  });

  it("a select flag whose value the shell decides names nothing", () => {
    expect(fetchFormScan("npx", 'npx -p "$PKG" tsc'.split(" "))).toMatchObject({ opaque: true });
    expect(fetchFormScan("npx", ["npx", "-p"])).toMatchObject({ pkgs: [], opaque: true });
  });
});

// ── uv's option table: closed world, unknown is never benign ──

describe("uvRunFlags — the closed world over uv's four run forms", () => {
  it("all four spellings are scanned with the same option set", () => {
    for (const [cmd, runner] of [["uvx", "uvx"], ["uv x tsc", "uv x"], ["uv run x.py", "uv run"],
                                 ["uv tool run --from pkg cmd", "uv tool run"]] as const) {
      expect(uvRunFlags(tokenizeSegmentQuoted(cmd))!.runner).toBe(runner);
    }
  });

  it("behaviour switches join the identity; anything else lands in otherOptions", () => {
    const f = uvRunFlags(tokenizeSegmentQuoted("uv run --frozen --isolated --no-project python3 x.py"))!;
    expect(f).toMatchObject({ uvFlags: ["--frozen", "--isolated", "--no-project"], otherOptions: [], deps: [] });
    // Widening, redirecting or weakening options are not benign on purpose.
    expect(uvRunFlags(tokenizeSegmentQuoted("uv run --extra dev python x.py"))!.otherOptions)
      .toEqual([{ flag: "--extra", value: "dev", opaque: false }]);
    expect(uvRunFlags(tokenizeSegmentQuoted("uv run --group dev python x.py"))!.otherOptions)
      .toEqual([{ flag: "--group", value: "dev", opaque: false }]);
    expect(uvRunFlags(tokenizeSegmentQuoted("uv run --upgrade python x.py"))!.otherOptions)
      .toEqual([{ flag: "--upgrade", value: "python", opaque: false }]); // arity-unknown: value assumed
  });

  it("short options are case-sensitive: `-P` upgrades, `-p` selects the interpreter", () => {
    // Folding them read `uv run -P pandas python3 s.py` as `--python pandas` —
    // a vetted version string, umbrella intact, while uv installed an upgrade.
    expect(uvRunFlags(tokenizeSegmentQuoted("uvx -P pandas tsc"))).toMatchObject({
      pythonValues: [], otherOptions: [{ flag: "-P", value: "pandas", opaque: false }],
    });
    expect(uvRunFlags(tokenizeSegmentQuoted("uvx -p3.12 tsc"))!.pythonValues)
      .toEqual([{ flag: "--python", value: "3.12", opaque: false }]);
  });

  it("arity is known for every option uv's help lists with a value", () => {
    // `--color never`: the flag joins the identity, its value is skipped — the
    // scan that missed it read `never` as the script and lost the umbrella.
    expect(uvRunFlags(tokenizeSegmentQuoted("uv run --color never python x.py"))).toMatchObject({
      uvFlags: ["--color"], otherOptions: [],
    });
    expect(uvRunFlags(tokenizeSegmentQuoted("uv run --python=3.12 python x.py"))!.pythonValues)
      .toEqual([{ flag: "--python", value: "3.12", opaque: false }]);
    expect(uvRunFlags(tokenizeSegmentQuoted("uv run --python /tmp/evil/python python x.py"))!.pythonValues)
      .toEqual([{ flag: "--python", value: "/tmp/evil/python", opaque: false }]);
    // An option the tables do not know is ASSUMED to take a value: the skipped
    // word is the runner, so the scan can only get narrower.
    expect(uvRunFlags(tokenizeSegmentQuoted("uvx --some-unknown-flag tsc"))!.otherOptions)
      .toEqual([{ flag: "--some-unknown-flag", value: "tsc", opaque: false }]);
  });

  it("a value-taking option with no value is malformed, not empty", () => {
    expect(uvRunFlags(tokenizeSegmentQuoted("uv run --with"))!.danglingValue).toBe(true);
    expect(uvRunFlags(tokenizeSegmentQuoted('uvx --with "$PKG" tsc'))!.deps[0].opaque).toBe(true);
  });
});

// ── what those two tables answer on the trust path ──

describe("fetch trust and grant identity", () => {
  it("package trust covers a fetch form only where its options cannot change the code", () => {
    const ok = ["uvx tsc", "uvx --python 3.12 tsc", "uvx --frozen tsc", "npx tsc", "timeout 5 uvx --frozen tsc"];
    const not = ["uvx --with x tsc", "uvx -p /tmp/evil/python tsc", "uvx -f http://x tsc"];
    for (const c of ok) expect(segmentFetchOptionsOk(c, "/work"), c).toBe(true);
    for (const c of not) expect(segmentFetchOptionsOk(c, "/work"), c).toBe(false);
  });

  it("an option value that decides what runs joins the signature", () => {
    // The generic flag-name rule made `uvx -p /tmp/evil/python tsc`'s identity
    // `uvx -p`: an "Always" stored a grant for an interpreter that is a path.
    expect(getCommandSignature("uvx -p /tmp/evil/python tsc", "/work")).toBe("uvx --python /tmp/evil/python");
    expect(getCommandSignature("uvx --with x tsc", "/work")).toBe("uvx --with x");
    expect(getCommandSignature("uvx -f http://x tsc", "/work")).toBe("uvx -f http://x");
    expect(uvRunSignature("uv tool run --from evil-pkg tsc", "/work")).toBe("uv tool run --from evil-pkg");
    expect(getCommandSignature("uv run --color never --frozen python3 x.py", "/work")).toBe("uv run --color --frozen");
    // With nothing to name, the fetch form keeps the coarse runner signature
    // (its package tier is granted by Trust, not by this rule).
    expect(getCommandSignature("uvx tsc", "/work")).toBe("uvx");
    expect(segmentNamesRunOptions("uvx -p /tmp/evil/python tsc")).toBe(true);
    expect(segmentNamesRunOptions("uvx --frozen tsc")).toBe(false);
  });

  it("no grant can name a run-time value, so the form is ungrantable", () => {
    expect(segmentRunFormUngrantable('npx -p "$PKG" tsc', "/work")).toBe(true);
    expect(segmentRunFormUngrantable('uvx --with "$PKG" tsc', "/work")).toBe(true);
    // A path value with no knowable cwd would key the grant on a relative path.
    expect(segmentRunFormUngrantable("uvx -p ./venv/python tsc", null)).toBe(true);
    expect(segmentRunFormUngrantable("uvx -p ./venv/python tsc", "/work")).toBe(false);
  });

  it("the umbrella: benign options keep it, an unknown or widening one voids it", () => {
    const s = "python3 ~/.pi/agent/skills/pdf/scripts/extract.py";
    expect(isTrustedScriptCommand(`uv run --color never --frozen ${s}`, "/work")).toBe(true);
    expect(isTrustedScriptCommand(`uv run -P pandas ${s}`, "/work")).toBe(false);
    expect(uvFetchFormOk(uvRunFlags(tokenizeSegmentQuoted("uvx --python 3.12 tsc")), "/work")).toBe(true);
    expect(uvFetchFormOk(uvRunFlags(tokenizeSegmentQuoted("uvx -p /tmp/evil/python tsc")), "/work")).toBe(false);
  });
});
