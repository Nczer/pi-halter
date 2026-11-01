import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { parseCommand } from "../analysis/bash-parser";
import { analyzeCommand } from "../analysis/command-analysis";
import {
  barLocations,
  dirsOfLocations,
  kindOfWord,
  locationsOf,
  pathWord,
  type PathWord,
} from "../analysis/path-word";
import { OPAQUE_VAR_DIR, UNKNOWN_CWD_MARKER } from "../analysis/path-util";
import { canon } from "./canon";
import { createContractCwd, removeContractCwd } from "./hermetic-cwd";

/**
 * The PATH WORD record (analysis/path-word, docs/dspa-intent-floor.md §9 L1–L2).
 *
 * These tests pin the RECORD — the word as typed, its kind, its completeness,
 * the places it names — not the flat lists the bars read (those are pinned by
 * the command-analysis, cwd-threading and floor suites, and the replay diff is
 * the standing proof the view did not move).
 *
 * Fixtures use the anonymized `/Users/u` namespace (test/canon.ts) unless a
 * stat answer is under test, which needs a real directory or file: those live
 * in TREE, under $HOME, never under /tmp (config/path-rules.ts puts /tmp in
 * both bars, so a /tmp fixture would quietly flip approval rows).
 */
const U = "/Users/u";
let CWD: string;
let TREE: string;

beforeAll(() => {
  CWD = createContractCwd();
  TREE = fs.mkdtempSync(path.join(os.homedir(), ".halter-pw-"));
  fs.mkdirSync(path.join(TREE, "dir"));
  fs.mkdirSync(path.join(TREE, "sub"));
  fs.writeFileSync(path.join(TREE, "file.txt"), "x\n");
});
afterAll(() => {
  removeContractCwd(CWD);
  fs.rmSync(TREE, { recursive: true, force: true });
});

const wordsOf = async (cmd: string): Promise<PathWord[]> => (await parseCommand(cmd, CWD)).words;

/** Assert the command names exactly one path word and return it. */
async function oneWord(cmd: string): Promise<PathWord> {
  const words = await wordsOf(cmd);
  expect(words.map((w) => w.text)).toEqual([expect.any(String)]);
  return words[0];
}

/** `{n0,n1,…,n<count-1>}` — a group with `count` names, for the caps. */
const names = (count: number): string =>
  `{${Array.from({ length: count }, (_, i) => `n${i}`).join(",")}}`;

describe("kindOfWord — how the text names its location", () => {
  it("a literal word with a literal location is exact", () => {
    expect(kindOfWord(`${U}/notes.md`, `${U}/notes.md`)).toBe("exact");
  });
  it("a glob is a wildcard (its leaf set is a disk question)", () => {
    expect(kindOfWord(`${U}/*.md`, `${U}/*.md`)).toBe("wildcard");
    expect(kindOfWord(`${U}/[ab].md`, `${U}/[ab].md`)).toBe("wildcard");
  });
  it("a brace alternation is a group, a brace range is a range", () => {
    expect(kindOfWord(`${U}/{a,b}`, `${U}/{a,b}`)).toBe("group");
    expect(kindOfWord(`${U}/{a,}`, `${U}/{a,}`)).toBe("group");
    expect(kindOfWord(`${U}/{1..200}`, `${U}/{1..200}`)).toBe("range");
    // A brace with no comma and no range is literal text, not a group.
    expect(kindOfWord(`${U}/{a}`, `${U}/{a}`)).toBe("exact");
  });
  it("the sentinels win over the text — they say WHY nothing is named", () => {
    // An unbound ref's token may carry a glob (`$e/*.ts`) and still name no
    // place; its kind must not claim a wildcard prefix the disk was asked for.
    expect(kindOfWord("$e/*.ts", path.join(OPAQUE_VAR_DIR, "$e/*.ts"))).toBe("opaque-var");
    expect(kindOfWord("./x", `${UNKNOWN_CWD_MARKER}/./x`)).toBe("unknown-cwd");
    expect(kindOfWord("", OPAQUE_VAR_DIR)).toBe("opaque-var");
  });
});

describe("pathWord — minting", () => {
  it("a word that proved no place carries an empty list, not a guess", () => {
    expect(pathWord("$f", [])).toEqual({ text: "$f", kind: "exact", locations: [], complete: true });
  });
  it("only a single provable place is complete", () => {
    expect(pathWord(`${U}/a`, [`${U}/a`]).complete).toBe(true);
    expect(pathWord(`${U}/*`, [`${U}/*`]).complete).toBe(false);
    expect(pathWord(`${U}/{a,b}`, [`${U}/{a,b}`]).complete).toBe(false);
    expect(pathWord(`${U}/{1..9}`, [`${U}/{1..9}`]).complete).toBe(false);
    // A sentinel names no place either, but it is the whole answer: there is
    // exactly one stop and no hidden leaf set behind it.
    expect(pathWord("$f", [path.join(OPAQUE_VAR_DIR, "$f")]).complete).toBe(true);
  });
});

describe("the words a command names (parseCommand)", () => {
  it("an absolute operand: the word as typed, one location", async () => {
    const w = await oneWord(`cat ${U}/notes.md`);
    expect(w).toMatchObject({
      text: `${U}/notes.md`,
      kind: "exact",
      complete: true,
      locations: [canon(`${U}/notes.md`)],
    });
  });

  it("a tilde operand keeps the typed text and resolves the location", async () => {
    const w = await oneWord("cat ~/notes.md");
    expect(w).toMatchObject({
      text: "~/notes.md",
      kind: "exact",
      locations: [canon(path.join(os.homedir(), "notes.md"))],
    });
  });

  it("a relative operand keeps `./` in the text", async () => {
    const w = await oneWord("cat ./notes.md");
    expect(w).toMatchObject({
      text: "./notes.md",
      kind: "exact",
      locations: [canon(path.join(CWD, "notes.md"))],
    });
  });

  it("a flag value is the word, not the flag (`--file=/x`)", async () => {
    const w = await oneWord("grep --file=/Users/u/pat x");
    expect(w.text).toBe("/Users/u/pat");
  });

  it("a glob is one word, incomplete, and its location keeps the glob", async () => {
    const w = await oneWord(`ls ${U}/*.md`);
    expect(w).toMatchObject({ text: `${U}/*.md`, kind: "wildcard", complete: false });
    expect(w.locations).toEqual([canon(`${U}/*.md`)]);
  });

  it("a brace group opens into one record naming one place per branch (§9 S3/S5)", async () => {
    const w = await oneWord(`ls ${U}/{a,b}`);
    expect(w).toMatchObject({ text: `${U}/{a,b}`, kind: "group", complete: true });
    // The locations are the places a run can produce, never the typed string.
    expect(w.locations).toEqual([canon(`${U}/a`), canon(`${U}/b`)]);
    expect(w.anchor).toBeUndefined();
  });

  it("a group can span a level, nest inside a branch, and sit beside another", async () => {
    expect((await oneWord(`ls ${U}/{a/b,c}`)).locations)
      .toEqual([canon(`${U}/a/b`), canon(`${U}/c`)]);
    expect((await oneWord(`ls ${U}/{a,{b,c}}`)).locations)
      .toEqual([canon(`${U}/a`), canon(`${U}/b`), canon(`${U}/c`)]);
    expect((await oneWord(`ls ${U}/{a,b}/{c,d}`)).locations)
      .toEqual([canon(`${U}/a/c`), canon(`${U}/a/d`), canon(`${U}/b/c`), canon(`${U}/b/d`)]);
  });

  it("a branch that still globs opens, and the word is not complete", async () => {
    const w = await oneWord(`ls ${U}/{a,b}/*.md`);
    expect(w).toMatchObject({ kind: "group", complete: false });
    expect(w.locations).toEqual([canon(`${U}/a/*.md`), canon(`${U}/b/*.md`)]);
  });

  it("braces inside quotes are part of the name — nothing opens", async () => {
    const w = await oneWord(`cat '${U}/{a,b}/x'`);
    expect(w).toMatchObject({ text: `${U}/{a,b}/x`, kind: "exact", complete: true });
    expect(w.locations).toEqual([canon(`${U}/{a,b}/x`)]);
  });

  it("a group past the caps names no place and anchors on its folder", async () => {
    const w = await oneWord(`ls ${U}/${names(17)}`);
    expect(w).toMatchObject({ text: `${U}/${names(17)}`, kind: "group", complete: false });
    expect(w.locations).toEqual([]);
    expect(w.anchor).toBe(canon(U));
  });

  it("a brace range names no place and anchors on its folder", async () => {
    const w = await oneWord(`ls ${U}/{1..200}`);
    expect(w).toMatchObject({ text: `${U}/{1..200}`, kind: "range", complete: false });
    expect(w.locations).toEqual([]);
    expect(w.anchor).toBe(canon(U));
  });

  it("`sort -o` and `dd if=/of=` name their operands as words", async () => {
    const sort = await wordsOf(`sort -o ${TREE}/sorted.json ${TREE}/data.txt`);
    expect(sort.map((w) => w.text)).toEqual([`${TREE}/sorted.json`, `${TREE}/data.txt`]);
    const dd = await wordsOf(`dd if=${U}/a of=${U}/b`);
    expect(dd.map((w) => w.text)).toEqual([`${U}/a`, `${U}/b`]);
  });

  it("a redirect destination is a word", async () => {
    const w = await oneWord(`echo hi > ${U}/log.txt`);
    expect(w).toMatchObject({ text: `${U}/log.txt`, kind: "exact" });
  });

  it("a path inside a code body is a word", async () => {
    const words = await wordsOf(`python3 -c 'open("${U}/x", "w")'`);
    expect(words.map((w) => w.text)).toContain(`${U}/x`);
  });

  it("a word screened as a safe system path leaves no record", async () => {
    expect(await wordsOf("cat /dev/null")).toEqual([]);
  });

  it("a location is one place: a second word naming it adds no location", async () => {
    const words = await wordsOf(`cat ${U}/a ${U}/a`);
    expect(locationsOf(words)).toEqual([canon(`${U}/a`)]);
    expect(words).toHaveLength(1); // one stop, not two
  });

  it("`paths` is the flat view over the records, never an independent list", async () => {
    const cmd = `cat ${U}/a ${U}/*.md ~/{a,b} ./rel 2>${U}/err`;
    const r = await parseCommand(cmd, CWD);
    expect(r.paths).toEqual(barLocations(r.words));
    expect(r.writePaths.every((p) => r.paths.includes(p))).toBe(true);
  });

  it("`bodyWritePaths` says WHICH EVIDENCE made a location a write", async () => {
    // `writePaths` answers WHERE is written; this says the only evidence is a
    // code body's own text — what the intent floor uses to keep D-g's
    // absolute write rule for OPERANDS only (docs/dspa-intent-floor.md §4.1).
    const payload = await parseCommand(`python3 -c 'import json; open("${U}/out.json", "w").write("{}")'`, CWD);
    expect(payload.writePaths).toContain(canon(`${U}/out.json`));
    expect(payload.bodyWritePaths).toEqual([canon(`${U}/out.json`)]);

    // An operand slot is the other kind of evidence — the shell's own shape
    // named the write, so the floor keeps it absolute.
    for (const cmd of [`echo hi > ${U}/out.json`, `echo hi | tee ${U}/out.json`, `sed -i s/a/b/ ${U}/out.json`]) {
      const r = await parseCommand(cmd, CWD);
      expect(r.writePaths, cmd).toContain(canon(`${U}/out.json`));
      expect(r.bodyWritePaths, cmd).toEqual([]);
    }

    // Both kinds at one location: the operand wins — a payload cannot make a
    // stop the command's own shape minted relaxable.
    const both = await parseCommand(`python3 -c 'open("${U}/out.json", "w")' > ${U}/out.json`, CWD);
    expect(both.bodyWritePaths).toEqual([]);

    // A relative payload path is never minted at all — the body extractor
    // threads absolute-looking strings only. Filed gap: the base-write proxy
    // is what covers `cd D && python3 -c "open('f','w')"`.
    for (const cmd of [`python3 -c 'open("out.json", "w")'`, `python3 -c 'open("sub/out.json", "w")'`]) {
      const r = await parseCommand(cmd, CWD);
      expect(r.paths, cmd).toEqual([]);
      expect(r.bodyWritePaths, cmd).toEqual([]);
    }
    // `~/…` is threaded, because it names a place without a cwd to resolve.
    const tilde = await parseCommand(`python3 -c 'open("~/halter-tilde-probe/out.json", "w")'`, CWD);
    expect(tilde.bodyWritePaths).toEqual([canon(path.join(os.homedir(), "halter-tilde-probe", "out.json"))]);

    // A body the floor does not interpret (sh) mints no write paths at all.
    const sh = await parseCommand(`sh -c 'echo hi > ${U}/out.json'`, CWD);
    expect(sh.bodyWritePaths).toEqual([]);
  });
});

describe("the words the floor's own derivations mint (analyzeCommand)", () => {
  it("an unbound variable: the token is the word, its place is the sentinel", async () => {
    const a = await analyzeCommand("cat $HALTER_PW_UNBOUND", CWD);
    const w = a.words.find((x) => x.text === "$HALTER_PW_UNBOUND");
    expect(w).toMatchObject({ kind: "opaque-var", complete: true });
    expect(w?.locations).toEqual([path.join(OPAQUE_VAR_DIR, "$HALTER_PW_UNBOUND")]);
    expect(a.paths).toContain(path.join(OPAQUE_VAR_DIR, "$HALTER_PW_UNBOUND"));
  }, 15000);

  it("a base the cd chain cannot resolve: kind unknown-cwd, location the marker", async () => {
    const a = await analyzeCommand("cd $HALTER_PW_UNBOUND && cat ./x", CWD);
    const w = a.words.find((x) => x.locations.some((l) => l.includes(UNKNOWN_CWD_MARKER)));
    expect(w).toMatchObject({ text: "./x", kind: "unknown-cwd" });
  }, 15000);

  it("a bound variable names its concrete place", async () => {
    const a = await analyzeCommand(`f=${U}/x; cat $f`, CWD);
    const hit = a.words.find((w) => w.locations.includes(canon(`${U}/x`)));
    expect(hit?.kind).toBe("exact");
    // 2a mints this merge from the location — the TOKEN is known inside
    // var-resolution and rides out with the reference work (§9 step 3).
    expect(hit?.text).toBe(canon(`${U}/x`));
  }, 15000);
});

describe("barLocations — the view a bar tests", () => {
  it("a word's places, or its anchor when it names none, or nothing", () => {
    const opened = pathWord(`${U}/{a,b}`, [`${U}/a`, `${U}/b`], "opened");
    const refused = { ...pathWord(`${U}/{1..200}`, [], "range"), anchor: U };
    const screened = pathWord("$f", []);
    expect(barLocations([opened, refused, screened])).toEqual([`${U}/a`, `${U}/b`, U]);
  });
});

describe("dirsOfLocations — the folder an answer sits in, written once", () => {
  it("a directory names itself; a file or a non-existent path names its parent", async () => {
    const dirs = await dirsOfLocations([
      pathWord(`${TREE}/dir`, [`${TREE}/dir`]),
      pathWord(`${TREE}/file.txt`, [`${TREE}/file.txt`]),
      pathWord(`${TREE}/gone.txt`, [`${TREE}/gone.txt`]),
    ]);
    // the dir itself, and TREE twice over (the parent of the file and of the
    // path that does not exist) — deduped, sorted.
    expect(dirs).toEqual([TREE, `${TREE}/dir`]);
  });

  it("a marker location keeps its marker — a stat would degrade it", async () => {
    expect(await dirsOfLocations([pathWord("./x", [`${UNKNOWN_CWD_MARKER}/./x`])]))
      .toEqual([UNKNOWN_CWD_MARKER]);
  });

  it("an unbound token keeps the static prefix its own text pins", async () => {
    // The marker carries the token AS TYPED (`path.join(OPAQUE_VAR_DIR, raw)`),
    // so a `~/…` token keeps its prefix and pins a real dir — the corpus case
    // `<unresolved-var>/~/.pi/agent/extensions/$e/*.ts` (unresolved.jsonl).
    const tok = `~/${path.basename(TREE)}/sub/$f`;
    expect(await dirsOfLocations([pathWord(tok, [path.join(OPAQUE_VAR_DIR, tok)])]))
      .toEqual([`${TREE}/sub`]);
    // No static prefix → the bare sentinel (the prompt shows the token instead).
    expect(await dirsOfLocations([pathWord("$f", [path.join(OPAQUE_VAR_DIR, "$f")])]))
      .toEqual([OPAQUE_VAR_DIR]);
    // Known gap (unchanged from the function this replaced): an ABSOLUTE token
    // arrives with its leading `/` eaten by the join, so its prefix reads
    // relative and pins nothing. Filed with the reference work (§9 step 3).
    expect(await dirsOfLocations([pathWord(`${TREE}/sub/$f`, [path.join(OPAQUE_VAR_DIR, `${TREE}/sub/$f`)])]))
      .toEqual([OPAQUE_VAR_DIR]);
  });

  it("an opened group is asked at each branch — the folders the run really touches", async () => {
    const w = pathWord(`${TREE}/{dir,sub}`, [`${TREE}/dir`, `${TREE}/sub`], "opened");
    expect(await dirsOfLocations([w])).toEqual([`${TREE}/dir`, `${TREE}/sub`]);
  });

  it("a location carrying an unopened group answers at its static prefix, never inside the group", async () => {
    // 3.44.0's dead grant: `ls ~/{Applications,apps,bin,.local/bin}` offered
    // `$HOME/{Applications,apps,bin,.local` as an Always option no run could
    // match. The quoted word keeps its braces, so the answer is the folder the
    // whole group sits in — which is what the next run's bar can match.
    const w = pathWord(`${TREE}/{a,b}/x`, [`${TREE}/{a,b}/x`], "quoted");
    expect(await dirsOfLocations([w])).toEqual([TREE]);
  });

  it("a word the parser refused to open is asked at its anchor", async () => {
    const w: PathWord = { ...pathWord(`${TREE}/${names(17)}`, [], "tooMany"), anchor: TREE };
    expect(await dirsOfLocations([w])).toEqual([TREE]);
  });

  it("`only` answers for the locations a bar selected — and dedupes, and sorts", async () => {
    const words = [
      pathWord(`${TREE}/dir`, [`${TREE}/dir`]),
      pathWord(`${TREE}/file.txt`, [`${TREE}/file.txt`]),
      pathWord(`${TREE}/gone.txt`, [`${TREE}/gone.txt`]),
    ];
    expect(await dirsOfLocations(words, [`${TREE}/file.txt`, `${TREE}/dir`]))
      .toEqual([TREE, `${TREE}/dir`].sort());
    expect(await dirsOfLocations([
      pathWord("a", [`${TREE}/dir`]),
      pathWord("b", [`${TREE}/dir`]),
    ])).toEqual([`${TREE}/dir`]);
  });
});
