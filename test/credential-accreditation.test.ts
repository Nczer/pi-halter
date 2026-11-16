/**
 * The credential accreditation at the floor (docs/dspa-credential-vouch.md).
 *
 * These rows are the feature's safety contract, so every case names the guard
 * it pins. The two doors run the real analysis (no hand-written findings): a
 * grant that only worked because a test faked the scan would be worthless.
 */
import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { checkDspaGate } from "../gate/dspa-gate";
import { credentialAccreditation } from "../gate/accreditation";
import { analyzeCommand } from "../analysis/command-analysis";
import { createStore } from "../gate/store";
import type { BashPromptData, FilePromptData } from "../decide/types";

let ROOT: string;
let store: ReturnType<typeof createStore>;

beforeAll(() => {
  ROOT = fs.mkdtempSync(path.join(os.tmpdir(), "halter-accred-"));
  fs.mkdirSync(path.join(ROOT, "sub"));
  for (const f of ["ca.pem", "sub/intermediate.pem", "id_rsa.pem"]) fs.writeFileSync(path.join(ROOT, f), "x");
});
afterAll(() => fs.rmSync(ROOT, { recursive: true, force: true }));

beforeEach(() => {
  store = createStore();
});

function bashPd(command: string, cwd: string, overrides: Partial<BashPromptData> = {}): BashPromptData {
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
    ...overrides,
  };
}

function filePd(resolved: string, cwd: string, isWriteOp: boolean, rule: string | null): FilePromptData {
  return {
    type: "file",
    action: isWriteOp ? "Write" : "Read",
    filePath: path.basename(resolved),
    resolved,
    cwd,
    outsideDir: null,
    isWriteOp,
    warnedRule: rule,
    symlinkHint: null,
    exists: true,
  };
}

describe("credentialAccreditation (the policy)", () => {
  const cert = { path: "/srv/certs/ca.pem", rule: "*.pem" };
  const key = { path: "/srv/certs/sub/key.pem", rule: "*.pem" };

  it("names the dir an unaccredited command wants", () => {
    const r = credentialAccreditation({ paths: [cert], pathless: [] }, store);
    expect(r).toEqual({ cleared: false, offerDir: "/srv/certs" });
  });

  it("one accredited dir covers the subtree, so the answer is cleared", () => {
    store.accreditDir("/srv/certs");
    expect(credentialAccreditation({ paths: [cert, key], pathless: [] }, store).cleared).toBe(true);
  });

  it("an unaccredited path in a partly-accredited set keeps the stop and re-offers", () => {
    store.accreditDir("/srv/certs/sub");
    const r = credentialAccreditation({ paths: [cert, key], pathless: [] }, store);
    expect(r).toEqual({ cleared: false, offerDir: "/srv/certs" });
  });

  it("two unrelated dirs share nothing nameable — no clearance, no offer", () => {
    const r = credentialAccreditation(
      { paths: [cert, { path: "/home/u/other.pem", rule: "*.pem" }], pathless: [] },
      store,
    );
    expect(r).toEqual({ cleared: false, offerDir: null });
  });

  it("a pathless finding is not a grant (G4/G5)", () => {
    for (const pathless of [["glob-unverified:*.pem"], [".ssh"], ["/home/u/.ssh"]]) {
      expect(credentialAccreditation({ paths: [cert], pathless }, store)).toEqual({
        cleared: false,
        offerDir: null,
      });
    }
  });

  it("no findings at all (the scan matched text it could not resolve)", () => {
    expect(credentialAccreditation(undefined, store)).toEqual({ cleared: false, offerDir: null });
    expect(credentialAccreditation({ paths: [], pathless: [] }, store)).toEqual({
      cleared: false,
      offerDir: null,
    });
  });

  it("a write to the credential path is never covered (V-d/G2)", () => {
    const findings = { paths: [cert], pathless: [] };
    expect(credentialAccreditation(findings, store, ["/srv/certs/ca.pem"])).toEqual({
      cleared: false,
      offerDir: null,
    });
    // A write INTO a credential dir the scan named is also a write to it.
    expect(credentialAccreditation({ paths: [{ path: "/home/u/.ssh", rule: ".ssh" }], pathless: [] }, store, ["/home/u/.ssh/id_new"])).toEqual({
      cleared: false,
      offerDir: null,
    });
  });
});

/** A prompt decision as `decide` builds one: the analysis the decision was
 *  made from rides with it, and the credential rule comes from that analysis —
 *  a hand-set rule with no findings behind it is not a real decision. */
async function realPd(command: string, cwd: string): Promise<BashPromptData> {
  const analysis = await analyzeCommand(command, cwd);
  return bashPd(command, cwd, { credentialRule: analysis.credentialRule, analysis });
}

describe("bash door — the real scan, the real gate", () => {
  it("an unaccredited credential read stops and offers its dir", async () => {
    const r = await checkDspaGate(await realPd(`cat ${ROOT}/ca.pem`, ROOT), store);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.reason).toContain("credential");
      expect(r.accreditDir).toBe(ROOT);
    }
  });

  it("accredited (and readable) — no credential stop: the judge decides (G6)", async () => {
    store.accreditDir(ROOT);
    store.addAllowed({ readDirs: [ROOT] }); // V-d: the click records both grants
    const r = await checkDspaGate(await realPd(`cat ${ROOT}/ca.pem`, ROOT), store);
    if (!r.ok) expect(r.reason).not.toContain("credential");
  });

  it("a store path stops with nothing to offer, even under an accredited dir", async () => {
    const home = path.join(ROOT, "home");
    fs.mkdirSync(path.join(home, ".ssh"), { recursive: true });
    fs.writeFileSync(path.join(home, ".ssh", "id_ed25519"), "x");
    store.accreditDir(ROOT);
    const r = await checkDspaGate(await realPd(`cat ${home}/.ssh/id_ed25519`, ROOT), store);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.reason).toContain("credential");
      expect(r.accreditDir).toBeUndefined();
    }
  });

  it("a keyfile name stays absolute inside the accredited tree (V-c)", async () => {
    fs.writeFileSync(path.join(ROOT, "id_rsa"), "x");
    store.accreditDir(ROOT);
    store.addAllowed({ readDirs: [ROOT] });
    const r = await checkDspaGate(await realPd(`cat ${ROOT}/id_rsa`, ROOT), store);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.reason).toContain("credential");
      expect(r.accreditDir).toBeUndefined();
    }
  });

  it("an unverifiable glob is unchanged and offers nothing (G5)", async () => {
    const r = await checkDspaGate(
      bashPd("grep x foo/*.pem", ROOT, { credentialRule: "glob-unverified:foo/*.pem" }),
      store,
    );
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.reason).toContain("unverifiable glob");
      expect(r.accreditDir).toBeUndefined();
    }
  });

  it("a command that writes a credential path gets neither clearance nor offer", async () => {
    const r = await checkDspaGate(
      await realPd(`cp ${ROOT}/ca.pem ${ROOT}/sub/ca.pem`, ROOT),
      store,
    );
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.accreditDir).toBeUndefined();
  });
});

describe("file door — the same exemption, both spellings", () => {
  it("a warned read stops and offers the file's dir", async () => {
    const r = await checkDspaGate(filePd(`${ROOT}/ca.pem`, ROOT, false, "*.pem"), store);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.reason).toContain("credential");
      expect(r.accreditDir).toBe(ROOT);
    }
  });

  it("accredited — the read is judgeable (V-g)", async () => {
    store.accreditDir(ROOT);
    const r = await checkDspaGate(filePd(`${ROOT}/sub/intermediate.pem`, ROOT, false, "*.pem"), store);
    expect(r.ok).toBe(true);
  });

  it("a WRITE to an accredited credential file still stops (V-d/G2)", async () => {
    store.accreditDir(ROOT);
    store.addAllowed({ writeDirs: [ROOT] });
    const r = await checkDspaGate(filePd(`${ROOT}/ca.pem`, ROOT, true, "*.pem"), store);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.reason).toContain("credential");
      expect(r.accreditDir).toBeUndefined();
    }
  });

  it("a store path stops with nothing to offer", async () => {
    const r = await checkDspaGate(filePd("/home/u/.ssh/id_rsa", "/home/u", false, ".ssh"), store);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.accreditDir).toBeUndefined();
  });
});
