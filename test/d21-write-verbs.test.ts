/**
 * D21 — write-verb base access + clean judge packet (2026-09-13).
 *
 * Incident: `cd <corpus> && mkdir -p … && mv …` under /dspa prompted forever
 * with no "Allow writes" option — the judge packet showed
 * `effective base: … write: NOT granted` and the (small) judge model denied
 * on that, while D18's trigger classes (redirects, opaque code) never
 * covered mkdir/mv, so no floor stop ever carried the write option.
 *
 * The three store scenarios of the incident, run through the real gate:
 *  S1 base inside session cwd → working set: the floor never stops; the
 *     (now clean) judge decides.
 *  S2 base outside cwd, no grants → the read-bar stop now carries
 *     writeOutside (merged options: read + write in ONE prompt).
 *  S3 base outside cwd, read-granted (after a previous "Always (paths)"
 *     click) → the D18 write stop now fires deterministically (class 3),
 *     offering `Allow writes: B` — one click reaches steady state (S3b).
 */
import { describe, it, expect } from "vitest";
import { checkDspaGate } from "../gate/dspa-gate";
import { baseWriteAccess } from "../analysis/cwd-tracking";
import { createStore } from "../gate/store";
import type { BashPromptData } from "../decide/types";

const B = "/mnt/Ndr/Projects/MOSAC/Contract Document.corpus";
const CMD =
  `cd "/mnt/Ndr/Projects/MOSAC/Contract Document.corpus" && mkdir -p corpus-patches/patches && ` +
  `mv /tmp/ocrcheck/patch/*.txt corpus-patches/patches/ && mv /tmp/ocrcheck/findings.md corpus-patches/findings.md && ` +
  `ls corpus-patches/patches | wc -l`;

function bashPd(command: string, cwd: string): BashPromptData {
  return {
    type: "bash",
    command,
    cwd,
    outsideDirs: [],
    segments: [command],
    signatures: [command.split(/\s+/)[0]],
    relativeToolIds: [],
    nonAllowedSegmentIndices: [0],
    riskDangerous: false,
    riskSeverity: null,
    riskReasons: [],
    hasUnsafePattern: false,
    credentialRule: null,
    needsCommandApproval: true,
    needsPathApproval: false,
  };
}

describe("D21 gate scenarios (MOSAC incident)", () => {
  it("S1: base inside session cwd → floor passes (working set; judge decides)", async () => {
    const r = await checkDspaGate(bashPd(CMD, "/mnt/Ndr/Projects/MOSAC"), createStore());
    expect(r.ok).toBe(true);
  });

  it("S2: base outside cwd, no grants → read-bar stop carries writeOutside (merged options)", async () => {
    const r = await checkDspaGate(bashPd(CMD, "/home/nczer"), createStore());
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.reason).toContain(`outside base (${B}`);
      expect(r.writeOutside).toEqual([B]);
    }
  });

  it("S3: base outside cwd, read-granted → D18 write stop with the 'Allow writes' option (D21 class 3)", async () => {
    const store = createStore();
    store.addAllowed({ readDirs: [B] });
    const r = await checkDspaGate(bashPd(CMD, "/home/nczer"), store);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.reason).toBe(`write outside base (${B})`);
      expect(r.writeOutside).toEqual([B]);
    }
  });

  it("S3b: after the 'Allow writes' grant (write implies read) → floor passes", async () => {
    const store = createStore();
    store.addAllowed({ writeDirs: [B] });
    const r = await checkDspaGate(bashPd(CMD, "/home/nczer"), store);
    expect(r.ok).toBe(true);
  });
});

describe("D21 baseWriteAccess: write-verb class", () => {
  const seg = (text: string) => baseWriteAccess({ text, ops: [], hasSubshell: false });

  it("write verbs with a bare target write the base", () => {
    for (const text of [
      "mkdir -p corpus-patches/patches",
      "mv /tmp/ocrcheck/patch/*.txt corpus-patches/patches/",
      "mv /tmp/ocrcheck/findings.md corpus-patches/findings.md",
      "cp /tmp/x rel.txt",
      "touch rel.txt",
      "ln -s /abs/target rel-link",
      "chmod 755 rel.sh",
      "chown u:u rel.txt",
      "chgrp g rel.txt",
      "install -m 755 /tmp/bin rel-bin",
      "sed -i 's/x/y/' rel.txt",
      "sed -i.bak 's/x/y/' rel.txt",
      "sed --in-place 's/x/y/' rel.txt",
    ]) {
      expect(baseWriteAccess({ text, ops: [], hasSubshell: false }), text).toBe(true);
    }
  });

  it("a write verb in a LATER pipeline stage still counts (shared effective cwd)", () => {
    expect(baseWriteAccess({ text: "cat x | tee out.txt", ops: ["|"], hasSubshell: false })).toBe(true);
  });

  it("non-writing commands and resolvable-only targets do not", () => {
    for (const text of [
      "ls corpus-patches/patches",
      "ls corpus-patches/patches | wc -l",
      "git status",
      "git commit -m x",
      "sed 's/x/y/' rel.txt",          // not in-place: writes nothing
      "mkdir /abs/dir",                // resolvable: the path set covers it
      "mv /abs/a /abs/b",
      "cp /tmp/x /abs/y",
    ]) {
      expect(seg(text), text).toBe(false);
    }
  });

  it("classes 1-2 still fire independently (no regression)", () => {
    expect(baseWriteAccess({ text: "echo x > f", ops: [">"], hasSubshell: false })).toBe(true);
    expect(baseWriteAccess({ text: "python3 - <<'EOF'\nprint(1)\nEOF", ops: ["<<"], hasSubshell: false })).toBe(true);
    expect(baseWriteAccess({ text: "python3 -c 'import os'", ops: [], hasSubshell: false })).toBe(true);
    expect(baseWriteAccess({ text: "python3 fix.py", ops: [], hasSubshell: false })).toBe(false);
    expect(baseWriteAccess({ text: "ls rel", ops: [], hasSubshell: false })).toBe(false);
  });
});
