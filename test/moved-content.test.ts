/**
 * moved-content.ts (D26) — the bytes a copy moves are read for the judge.
 *
 * The gap this closes: `cp probe.test.ts test/` puts content at a path the
 * judge cannot see, so it approved copies it had never read (10 of 12 in one
 * session's ledger) or deferred them for "missing information". These rows pin
 * both halves of the fix — what gets read, and what is deliberately named
 * instead of read.
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it, beforeAll, afterAll, beforeEach } from "vitest";
import { findMovedContent, MAX_MOVED_FILE_BYTES } from "../analysis/moved-content";
import { analyzeCommand } from "../analysis/command-analysis";

let tmp: string;
beforeAll(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "moved-content-"));
});
afterAll(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});
beforeEach(() => {
  for (const f of fs.readdirSync(tmp)) fs.rmSync(path.join(tmp, f), { recursive: true, force: true });
});

function put(rel: string, content: string | Buffer): string {
  const p = path.join(tmp, rel);
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, content);
  return p;
}

async function moved(command: string, cwd = tmp) {
  return findMovedContent(await analyzeCommand(command, cwd), cwd);
}

/** The one file, with the noise unwrapped. */
function only(m: Awaited<ReturnType<typeof moved>>) {
  expect(m?.files).toHaveLength(1);
  return m!.files[0];
}

describe("findMovedContent — the copy verbs", () => {
  it("reads the file cp puts in place", async () => {
    put("probe.test.ts", "export const answer = 42;\n");
    const f = only(await moved("cp probe.test.ts probe.copy.test.ts"));
    expect(f.source).toBe(path.join(tmp, "probe.test.ts"));
    expect(f.dest).toBe(path.join(tmp, "probe.copy.test.ts"));
    expect(f.content).toBe("export const answer = 42;\n");
    expect(f.overwrites).toBe(false);
    expect(f.note).toBeNull();
  });

  it("says when the destination already holds a file", async () => {
    put("new.ts", "fresh\n");
    put("old.ts", "stale\n");
    const f = only(await moved("cp new.ts old.ts"));
    expect(f.overwrites).toBe(true);
    expect(f.content).toBe("fresh\n");
  });

  it("lands each source inside a directory destination, under its own name", async () => {
    put("a.txt", "A\n");
    put("b.txt", "B\n");
    fs.mkdirSync(path.join(tmp, "out"));
    const m = await moved("cp a.txt b.txt out/");
    expect(m?.files).toHaveLength(2);
    expect(m!.files.map((f) => f.dest)).toEqual([path.join(tmp, "out/a.txt"), path.join(tmp, "out/b.txt")]);
  });

  it("reads the directory from -t rather than the trailing operand", async () => {
    put("a.txt", "A\n");
    put("dest", "this is a FILE named dest, not the target dir\n");
    fs.mkdirSync(path.join(tmp, "dir"));
    const f = only(await moved("cp -t dir a.txt"));
    expect(f.dest).toBe(path.join(tmp, "dir/a.txt"));
  });

  it("follows mv as well as cp", async () => {
    put("job.sh", "#!/bin/sh\necho job\n");
    fs.mkdirSync(path.join(tmp, "bin"));
    const f = only(await moved("mv job.sh bin/"));
    expect(f.content).toContain("echo job");
    expect(f.dest).toBe(path.join(tmp, "bin/job.sh"));
  });

  it("reads install's source past its mode flags", async () => {
    put("rel", "#!/bin/sh\ntrue\n");
    const abs = path.join(tmp, "installed-tool");
    const f = only(await moved(`install -m 644 rel ${abs}`));
    expect(f.source).toBe(path.join(tmp, "rel"));
    expect(f.dest).toBe(abs);
    expect(f.content).toContain("#!/bin/sh");
  });

  it("leaves split's destination unnamed — it names its outputs by prefix", async () => {
    put("big.txt", "x".repeat(400));
    const f = only(await moved("split -b 100 big.txt big.part-"));
    expect(f.content).toHaveLength(400);
    expect(f.dest).toBeNull();
  });

  it("reads through a wrapper: timeout 60 cp … is still a copy", async () => {
    put("a.txt", "A\n");
    fs.mkdirSync(path.join(tmp, "out"));
    const f = only(await moved("timeout 60 cp a.txt out/"));
    expect(f.content).toBe("A\n");
    expect(f.dest).toBe(path.join(tmp, "out/a.txt"));
  });

  it("reads the right file when one pipeline copies and another moves", async () => {
    put("a.txt", "A\n");
    put("b.txt", "B\n");
    fs.mkdirSync(path.join(tmp, "out"));
    const m = await moved("cp a.txt out/ && mv b.txt out/b2.txt");
    expect(m?.files).toHaveLength(2);
    expect(m!.files.map((f) => f.content)).toEqual(["A\n", "B\n"]);
  });
});

describe("findMovedContent — dd and the redirect past", () => {
  it("reads dd if= and names dd of= as the destination", async () => {
    put("in.bin", "payload\n");
    const f = only(await moved("dd if=in.bin of=out.bin"));
    expect(f.source).toBe(path.join(tmp, "in.bin"));
    expect(f.dest).toBe(path.join(tmp, "out.bin"));
    expect(f.content).toBe("payload\n");
  });

  it("reads the file cat writes out through a redirect", async () => {
    put("in.txt", "cat me\n");
    const f = only(await moved("cat in.txt > out.txt"));
    expect(f.content).toBe("cat me\n");
    expect(f.dest).toBe(path.join(tmp, "out.txt"));
  });

  it("takes cat's source from `<` when it has no file operand", async () => {
    put("in.txt", "redirected in\n");
    const f = only(await moved("cat < in.txt > out.txt"));
    expect(f.content).toBe("redirected in\n");
  });
});

describe("findMovedContent — sources it names instead of reading", () => {
  it("expands a glob and shows each match's content", async () => {
    put("x1.txt", "one\n");
    put("x2.txt", "two\n");
    put("skip.md", "not a match\n");
    fs.mkdirSync(path.join(tmp, "out"));
    const m = await moved("cp *.txt out/");
    expect(m?.files).toHaveLength(2);
    expect(m!.files.map((f) => f.source).sort()).toEqual([path.join(tmp, "x1.txt"), path.join(tmp, "x2.txt")]);
    expect(m!.files.map((f) => f.content).sort()).toEqual(["one\n", "two\n"]);
  });

  it("says so when a glob matches nothing", async () => {
    const f = only(await moved("cp *.nope out/"));
    expect(f.content).toBeNull();
    expect(f.note).toContain("nothing matches");
  });

  it("names a source whose location the analysis cannot resolve", async () => {
    const f = only(await moved("cp $HOME/secret.txt out/"));
    expect(f.content).toBeNull();
    expect(f.note).toContain("path not resolvable");
  });

  it("names a folder by its file count, and reads nothing inside it", async () => {
    put("tree/a", "1\n");
    put("tree/b", "2\n");
    put("tree/c", "3\n");
    const f = only(await moved("cp -r tree backup"));
    expect(f.content).toBeNull();
    expect(f.note).toBe("folder — 3 files, contents not shown");
  });

  it("never reads a source the credential scan matches — and says which rule", async () => {
    put(".env", "API_KEY=sk-super-secret\n");
    const f = only(await moved("cp .env .env.bak"));
    expect(f.content).toBeNull();
    expect(f.note).toContain("credential file");
    expect(f.note).toContain(".env");
  });

  it("never reads /proc, /sys or /dev", async () => {
    const f = only(await moved("cp /proc/uptime up.txt"));
    expect(f.content).toBeNull();
    expect(f.note).toBe("device or pseudo-file — not read");
  });

  it("names a file over the size limit instead of reading it", async () => {
    put("huge.txt", Buffer.alloc(MAX_MOVED_FILE_BYTES + 1, 0x61));
    const f = only(await moved("cp huge.txt huge.copy"));
    expect(f.content).toBeNull();
    expect(f.note).toContain("over the 1 MB limit");
    expect(f.bytes).toBe(MAX_MOVED_FILE_BYTES + 1);
  });

  it("names a binary instead of pasting it", async () => {
    put("blob.bin", Buffer.from([0x89, 0x50, 0x00, 0x01, 0xff]));
    const f = only(await moved("cp blob.bin copy.bin"));
    expect(f.content).toBeNull();
    expect(f.note).toBe("binary — content not shown");
  });

  it("shows the first MAX_MOVED_FILES and counts the rest", async () => {
    for (let i = 0; i < 9; i++) put(`f${i}.txt`, `f${i}\n`);
    fs.mkdirSync(path.join(tmp, "out"));
    const m = await moved("cp f0.txt f1.txt f2.txt f3.txt f4.txt f5.txt f6.txt f7.txt f8.txt out/");
    expect(m?.files).toHaveLength(8);
    expect(m?.omitted).toBe(1);
  });

  it("says so when there is nothing at the source path", async () => {
    const f = only(await moved("cp absent.txt copy.txt"));
    expect(f.content).toBeNull();
    expect(f.note).toBe("nothing at this path");
  });
});

describe("findMovedContent — commands that move no file bytes", () => {
  // `tee`'s payload is already in the command text; `sed -i` and `patch`
  // COMPUTE bytes rather than relocating them; a link creates a name and moves
  // nothing. Reading for these would cost a verdict's time for no new fact.
  it.each([
    "echo hi | tee out.txt",
    "sed -i 's/a/b/' file.txt",
    "ln -s real.txt link.txt",
    "mkdir -p out/deep",
    "tar cf archive.tar .",
    "rm -f old.txt",
    "echo written > made-by-echo.txt",
    "grep -r needle .",
  ])("%s gets no content section", async (command) => {
    expect(await moved(command)).toBeNull();
  });

  it("says nothing it cannot place: a copy after an unresolvable cd", async () => {
    // Guessing the session cwd here would show the judge some other file's
    // bytes as this copy's payload, so the file is named and not read.
    put("a.txt", "A\n");
    const m = await moved("cd $SOMEDIR && cp a.txt out/", tmp);
    expect(m?.files).toHaveLength(1);
    expect(m!.files[0].content).toBeNull();
    expect(m!.files[0].note).toContain("directory this runs in is not known");
  });
});
