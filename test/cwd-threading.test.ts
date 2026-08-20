import { describe, expect, it } from "vitest";
import os from "node:os";
import path from "node:path";
import fs from "node:fs";
import {
  trackEffectiveCwd,
  reResolveCwdDependentPaths,
  UNKNOWN_CWD_MARKER,
} from "../analysis/cwd-tracking";
import { OPAQUE_VAR_DIR } from "../analysis/bash-parser";
import { analyzeCommand } from "../analysis/command-analysis";
import { decide } from "../decision-engine";
import { createStore } from "../store";
import type { BashSegment } from "../analysis/bash-parser";

const HOME = os.homedir();
const DOC_EXTRACT = path.join(HOME, ".pi", "agent", "skills", "doc-extract");
const SKILL_SCRIPT = path.join(DOC_EXTRACT, "scripts", "extract.py");
const BASE = "/mnt/projects";
const CWD = "/mnt/Ndr/Projects";

function seg(text: string, ops: string[] = [], hasSubshell = false): BashSegment {
  return { text, ops, hasSubshell };
}

describe("trackEffectiveCwd", () => {
  it("threads absolute cd to subsequent segments", () => {
    expect(trackEffectiveCwd([seg("cd /tmp"), seg("ls")], BASE)).toEqual([BASE, "/tmp"]);
  });

  it("threads sequential cds, relative ones against the current effective cwd", () => {
    expect(trackEffectiveCwd([seg("cd /tmp"), seg("cd /var"), seg("ls")], BASE)).toEqual([BASE, "/tmp", "/var"]);
    expect(trackEffectiveCwd([seg("cd ~"), seg("cd .pi"), seg("ls")], BASE)).toEqual([BASE, HOME, path.join(HOME, ".pi")]);
  });

  it("bare cd goes home", () => {
    expect(trackEffectiveCwd([seg("cd"), seg("ls")], BASE)).toEqual([BASE, HOME]);
  });

  it("handles -L / -P / -- flags and quoted paths", () => {
    expect(trackEffectiveCwd([seg("cd -P /tmp"), seg("ls")], BASE)).toEqual([BASE, "/tmp"]);
    expect(trackEffectiveCwd([seg("cd -- /tmp"), seg("ls")], BASE)).toEqual([BASE, "/tmp"]);
    expect(trackEffectiveCwd([seg('cd "/tmp"'), seg("ls")], BASE)).toEqual([BASE, "/tmp"]);
  });

  it("escaped spaces stay a residual (tokenizer splits the word) — base unchanged (fail closed)", () => {
    // bash would cd into "/var/tmp/halt space probe", but the tokenizer splits
    // the word at the escaped space → 3 target tokens in our view → no threading.
    expect(trackEffectiveCwd([seg("cd /var/tmp/halt\\ space probe"), seg("ls")], BASE)).toEqual([BASE, BASE]);
  });

  it("makes the base UNKNOWN for non-literal cds (cd -, globs, expansions) — sticky until recovery", () => {
    expect(trackEffectiveCwd([seg("cd -"), seg("ls")], BASE)).toEqual([BASE, null]);
    expect(trackEffectiveCwd([seg("cd /tmp/d*"), seg("ls")], BASE)).toEqual([BASE, null]);
    expect(trackEffectiveCwd([seg("cd $X"), seg("ls")], BASE)).toEqual([BASE, null]);
    expect(trackEffectiveCwd([seg("cd $(echo /tmp)"), seg("ls")], BASE)).toEqual([BASE, null]);
    // sticky across non-cd segments
    expect(trackEffectiveCwd([seg("cd $X"), seg("echo hi"), seg("ls")], BASE)).toEqual([BASE, null, null]);
  });

  it("absolute literal cd recovers an unknown base; relative literal does not", () => {
    expect(
      trackEffectiveCwd([seg("cd $X"), { ...seg("cd /var"), precedingOp: "&&" }, seg("ls")], BASE),
    ).toEqual([BASE, null, "/var"]);
    expect(
      trackEffectiveCwd([seg("cd $X"), { ...seg("cd sub"), precedingOp: "&&" }, seg("ls")], BASE),
    ).toEqual([BASE, null, null]);
  });

  it("does not change the base for cds that cannot succeed at runtime", () => {
    // bash errors: `cd: too many arguments` / unexpected flag → cd fails
    expect(trackEffectiveCwd([seg("cd /nonexistent-xyz /tmp"), seg("ls")], BASE)).toEqual([BASE, BASE]);
    expect(trackEffectiveCwd([seg("cd --weird /tmp"), seg("ls")], BASE)).toEqual([BASE, BASE]);
    // nonexistent literal: cd fails → under ; the cwd is untouched, under && the rest never runs
    expect(trackEffectiveCwd([seg("cd /nonexistent-dir-xyz"), seg("ls")], BASE)).toEqual([BASE, BASE]);
  });

  it("does not thread cd in pipeline stages or subshells (subshell cwd doesn't persist)", () => {
    expect(trackEffectiveCwd([seg("cd /tmp | wc -l", ["|"]), seg("ls")], BASE)).toEqual([BASE, BASE]);
    expect(trackEffectiveCwd([seg("cd /tmp |& tee x", ["|&"]), seg("ls")], BASE)).toEqual([BASE, BASE]);
    expect(trackEffectiveCwd([seg("cd /tmp", [], true), seg("ls")], BASE)).toEqual([BASE, BASE]);
  });

  it("ignores non-cd first words (cd inside arguments)", () => {
    expect(trackEffectiveCwd([seg("echo cd /tmp"), seg("ls")], BASE)).toEqual([BASE, BASE]);
  });

  it("the branch segment after || gets an UNKNOWN base (branch-dependent cwd)", () => {
    // (cd /tmp && echo hi) || (cd /var && ls): ls only runs in the branch where
    // cd /var ran — its base is unresolvable until that cd is resolved.
    expect(
      trackEffectiveCwd(
        [seg("cd /tmp"), { ...seg("echo hi"), precedingOp: "&&" }, { ...seg("cd /var"), precedingOp: "||" }, { ...seg("ls"), precedingOp: "&&" }],
        BASE,
      ),
    ).toEqual([BASE, "/tmp", null, "/var"]);
    // the branch segment's own absolute literal cd recovers immediately
    expect(
      trackEffectiveCwd(
        [seg("cd /tmp"), { ...seg("cd /var"), precedingOp: "||" }, { ...seg("cd /tmp"), precedingOp: "&&" }, seg("ls")],
        BASE,
      ),
    ).toEqual([BASE, null, "/var", "/tmp"]);
  });

  it("backgrounded segments do not change the base (subshell cwd doesn't persist)", () => {
    expect(
      trackEffectiveCwd([{ ...seg("cd /tmp"), backgrounded: true }, { ...seg("ls"), precedingOp: "&" }], BASE),
    ).toEqual([BASE, BASE]);
  });

  it("a cd FOLLOWING & (main shell) still threads", () => {
    expect(
      trackEffectiveCwd(
        [{ ...seg("sleep 1"), backgrounded: true }, { ...seg("cd /var"), precedingOp: "&" }, seg("ls")],
        BASE,
      ),
    ).toEqual([BASE, BASE, "/var"]);
  });
});

describe("parser operator metadata (precedingOp / backgrounded)", () => {
  it("attaches precedingOp in document order", async () => {
    const { parseCommand } = await import("../analysis/bash-parser");
    const p = await parseCommand("echo a && echo b || echo c; echo d", BASE);
    expect(p.segments.map(s => s.precedingOp)).toEqual([undefined, "&&", "||", ";"]);
  }, 15000);

  it("marks backgrounded segments and the & separator", async () => {
    const { parseCommand } = await import("../analysis/bash-parser");
    const p = await parseCommand("sleep 1 & echo b", BASE);
    expect(p.segments.map(s => s.precedingOp)).toEqual([undefined, "&"]);
    expect(p.segments[0].backgrounded).toBe(true);
    expect(p.segments[1].backgrounded).toBeFalsy();
  }, 15000);

  it("marks every segment of a backgrounded list", async () => {
    const { parseCommand } = await import("../analysis/bash-parser");
    const p = await parseCommand("cd /tmp && cd /var & echo b", BASE);
    expect(p.segments.slice(0, 2).every(s => s.backgrounded)).toBe(true);
    expect(p.segments[2].backgrounded).toBeFalsy();
    expect(p.segments.map(s => s.precedingOp)).toEqual([undefined, "&&", "&"]);
  }, 15000);

  it("cd after & is NOT backgrounded (only the & 's own sibling is)", async () => {
    const { parseCommand } = await import("../analysis/bash-parser");
    const p = await parseCommand("sleep 1 & cd /tmp && echo b", BASE);
    expect(p.segments.map(s => s.backgrounded)).toEqual([true, undefined, undefined]);
  }, 15000);
});

describe("reResolveCwdDependentPaths", () => {
  it("re-resolves ./ and ../ tokens against the effective cwd", () => {
    expect(reResolveCwdDependentPaths(seg("cat ./secret.txt"), "/tmp")).toEqual(["/tmp/secret.txt"]);
    expect(reResolveCwdDependentPaths(seg("cat ../x.txt"), "/tmp/a")).toEqual(["/tmp/x.txt"]);
  });

  it("re-resolves flag-embedded relative values", () => {
    expect(reResolveCwdDependentPaths(seg("sort -o ./out.txt in.txt"), "/tmp/a")).toEqual(["/tmp/a/out.txt"]);
    expect(reResolveCwdDependentPaths(seg("grep -r x --include=./y ."), "/tmp/a")).toEqual(["/tmp/a/y"]);
  });

  it("re-resolves $PWD / ${PWD} tokens against the effective cwd", () => {
    expect(reResolveCwdDependentPaths(seg("cat $PWD/secret.txt"), "/tmp")).toEqual(["/tmp/secret.txt"]);
    expect(reResolveCwdDependentPaths(seg("cat ${PWD}/secret.txt"), "/tmp")).toEqual(["/tmp/secret.txt"]);
    expect(reResolveCwdDependentPaths(seg("ls $PWD"), "/tmp/a")).toEqual(["/tmp/a"]);
    expect(reResolveCwdDependentPaths(seg("sort -o $PWD/out.txt in.txt"), "/tmp/a")).toEqual(["/tmp/a/out.txt"]);
  });

  it("resolves unknown-base tokens to the marker (forces path approval)", () => {
    expect(reResolveCwdDependentPaths(seg("cat ./secret.txt"), null)).toEqual([`${UNKNOWN_CWD_MARKER}/secret.txt`]);
    expect(reResolveCwdDependentPaths(seg("cat $PWD/secret.txt"), null)).toEqual([`${UNKNOWN_CWD_MARKER}/secret.txt`]);
    expect(reResolveCwdDependentPaths(seg("ls $PWD"), null)).toEqual([UNKNOWN_CWD_MARKER]);
  });

  it("skipDotPaths collects only $PWD tokens (./.. already resolved by the parser)", () => {
    expect(reResolveCwdDependentPaths(seg("cat ./x $PWD/y"), "/tmp", { skipDotPaths: true })).toEqual(["/tmp/y"]);
    expect(reResolveCwdDependentPaths(seg("cat ./x ../y"), "/tmp", { skipDotPaths: true })).toEqual([]);
  });

  it("ignores absolute, ~, bare non-path tokens, and other variables", () => {
    expect(reResolveCwdDependentPaths(seg("cat /abs.txt ~/x.txt foo.txt $D/x"), "/tmp/a")).toEqual([]);
  });
});

describe("$HOME expansion (parseCommand)", () => {
  it("resolves $HOME/… and ${HOME}/… against the home dir, base-independent", async () => {
    const { parseCommand } = await import("../analysis/bash-parser");
    const p = await parseCommand("cat $HOME/probe.txt ${HOME}/other/probe2.txt", CWD);
    expect(p.paths).toContain(path.join(HOME, "probe.txt"));
    expect(p.paths).toContain(path.join(HOME, "other", "probe2.txt"));
  }, 15000);

  it("does not treat $HOME-lookalike variables as $HOME (they stay opaque → markers)", async () => {
    const { parseCommand } = await import("../analysis/bash-parser");
    const p = await parseCommand("cat $HOMEDIR/x $HOME_DIR/x", CWD);
    expect(p.paths).toEqual([`${OPAQUE_VAR_DIR}/$HOMEDIR/x`, `${OPAQUE_VAR_DIR}/$HOME_DIR/x`]);
  }, 15000);
});

describe("cd threading integration (analyzeCommand)", () => {
  it.runIf(fs.existsSync(DOC_EXTRACT))(
    "auto-allows cd <skill-dir> && uv run --with pandas,openpyxl,xlrd python3 scripts/… (reported false positive)",
    async () => {
      const cmd = `cd ${DOC_EXTRACT} && uv run --with pandas,openpyxl,xlrd python3 scripts/extract.py --source /tmp/pnap --dry-run 2>&1 | tail -40`;
      const a = await analyzeCommand(cmd, CWD);
      expect(a.safety.hasUnsafePattern).toBe(false);
      expect(a.safety.isSimple).toBe(true);
      expect(a.safety.canBeAutoAllowed).toBe(true);
      expect(a.risk.severity).toBeNull();
    },
    15000,
  );

  it.runIf(fs.existsSync(DOC_EXTRACT))(
    "cd to a non-trusted dir does NOT grant trust to a relative script",
    async () => {
      // /tmp must exist for the cd to thread; scripts/evil.py is not in the skills dir
      const cmd = "cd /tmp && uv run --with pandas,openpyxl python3 scripts/evil.py --dry-run";
      const a = await analyzeCommand(cmd, CWD);
      expect(a.safety.hasUnsafePattern).toBe(true);
      expect(a.safety.canBeAutoAllowed).toBe(false);
    },
    15000,
  );

  it("re-resolves relative paths after cd against the runtime cwd", async () => {
    const a = await analyzeCommand("cd /tmp && cat ./secret.txt", CWD);
    expect(a.paths).toContain("/tmp/secret.txt");
  }, 15000);

  it("keeps session-cwd resolution when no cd is present", async () => {
    const a = await analyzeCommand("cat ./secret.txt", CWD);
    expect(a.paths).toContain(path.join(CWD, "secret.txt"));
  }, 15000);

  it("resolves $PWD against the session cwd even without a cd", async () => {
    const a = await analyzeCommand("cat $PWD/secret.txt", CWD);
    expect(a.paths).toContain(path.join(CWD, "secret.txt"));
  }, 15000);

  it("does not treat a pipeline-stage cd as persisting (relative stays session-cwd)", async () => {
    const a = await analyzeCommand("cat ./secret.txt | head", CWD);
    expect(a.paths).toContain(path.join(CWD, "secret.txt"));
  }, 15000);

  it.runIf(fs.existsSync(DOC_EXTRACT))(
    "cd A || cd <skill> && python3 scripts/… — the right branch only runs UNDER the skill dir (recovery, runtime-exact)",
    async () => {
      // `cd A || (cd skill && python3 …)`: python3 only runs if the right-side cd
      // succeeded, so the runtime cwd is exactly the (trusted) skill dir when it
      // runs. The unknown base at || is recovered by the absolute literal cd.
      const cmd = `cd ${HOME} || cd ${DOC_EXTRACT} && python3 scripts/evil.py`;
      const a = await analyzeCommand(cmd, CWD);
      expect(a.safety.canBeAutoAllowed).toBe(true);
    },
    15000,
  );

  it(
    "BYPASS (freeze hole): cd /nonexistent || cd /var/tmp && cat ./secret.txt prompts",
    async () => {
      // A literal left cd to a nonexistent dir FAILS at runtime, so the right branch
      // DOES run — freezing at the left dir (or the session cwd) would be a bypass.
      // The unknown base flags the relative token instead.
      const d = await decide({ type: "bash", command: "cd /nonexistent-dir-xyz || cd /var/tmp && cat ./secret.txt", cwd: CWD }, createStore());
      expect(d.kind).toBe("prompt");
    },
    15000,
  );

  it.runIf(fs.existsSync(DOC_EXTRACT))(
    "backgrounded cd does not persist (sleep 1 & cd /nope && python3 …) still prompts",
    async () => {
      const cmd = "sleep 1 & cd /nonexistent-dir-xyz && python3 scripts/evil.py";
      const a = await analyzeCommand(cmd, CWD);
      expect(a.safety.hasUnsafePattern).toBe(true);
      expect(a.safety.canBeAutoAllowed).toBe(false);
    },
    15000,
  );

  it.runIf(fs.existsSync(DOC_EXTRACT))(
    "cd after & runs in the MAIN shell — it threads (runtime really is under the skill dir)",
    async () => {
      const cmd = `sleep 1 & cd ${DOC_EXTRACT} && python3 scripts/extract.py`;
      const a = await analyzeCommand(cmd, CWD);
      expect(a.safety.hasUnsafePattern).toBe(false);
      expect(a.safety.canBeAutoAllowed).toBe(true);
    },
    15000,
  );

  it.runIf(fs.existsSync(DOC_EXTRACT))(
    "relative after || is analyzed under an unknown base (no false trust, prompt)",
    async () => {
      const cmd = `cd ${DOC_EXTRACT} && grep foo /nonexistent-file || python3 scripts/extract.py`;
      const a = await analyzeCommand(cmd, CWD);
      expect(a.safety.hasUnsafePattern).toBe(true);
      expect(a.safety.canBeAutoAllowed).toBe(false);
    },
    15000,
  );
});

describe("unknown-base integration (P1)", () => {
  it(
    "BYPASS: D=/var/tmp && cd $D && cat ./secret.txt prompts (relative after untrackable cd)",
    async () => {
      const d = await decide({ type: "bash", command: "D=/var/tmp && cd $D && cat ./secret.txt", cwd: CWD }, createStore());
      expect(d.kind).toBe("prompt");
    },
    15000,
  );

  it("marks relative tokens under an unknown cwd with the unresolved marker", async () => {
    const a = await analyzeCommand("D=/var/tmp && cd $D && cat ./secret.txt $PWD/other.txt", CWD);
    expect(a.paths).toContain(`${UNKNOWN_CWD_MARKER}/secret.txt`);
    expect(a.paths).toContain(`${UNKNOWN_CWD_MARKER}/other.txt`);
  }, 15000);

  it("absolute paths are still checked (and trusted) under an unknown base", async () => {
    const a = await analyzeCommand("cd $D && cat /var/tmp/halt-probe-abs.txt", CWD);
    expect(a.paths).toContain("/var/tmp/halt-probe-abs.txt");
    const d = await decide({ type: "bash", command: "cd $D && cat /var/tmp/halt-probe-abs.txt", cwd: CWD }, createStore());
    expect(d.kind).toBe("prompt");
  }, 15000);

  it.runIf(fs.existsSync(SKILL_SCRIPT))(
    "absolute trusted script under an unknown base still auto-allows (recovery via absolute path)",
    async () => {
      const d = await decide({ type: "bash", command: `cd $D && python3 ${SKILL_SCRIPT}`, cwd: CWD }, createStore());
      expect(d.kind).toBe("auto-allow");
    },
    15000,
  );

  it.runIf(fs.existsSync(DOC_EXTRACT))(
    "relative script under an unknown base is NOT trusted (prompts)",
    async () => {
      const d = await decide({ type: "bash", command: `cd $D && python3 scripts/extract.py`, cwd: CWD }, createStore());
      expect(d.kind).toBe("prompt");
    },
    15000,
  );

  it("cd $D && cat main.ts (bare token) stays an accepted residual — no marker for bare names", async () => {
    const a = await analyzeCommand("cd $D && cat main.ts", CWD);
    expect(a.paths.filter(p => p.startsWith(UNKNOWN_CWD_MARKER))).toEqual([]);
  }, 15000);
});

describe("$HOME expansion integration (P2)", () => {
  it("cat $HOME/<outside> prompts (resolves to the real home path)", async () => {
    const a = await analyzeCommand("cat $HOME/.halt-secret-probe.txt", CWD);
    expect(a.paths).toContain(path.join(HOME, ".halt-secret-probe.txt"));
    const d = await decide({ type: "bash", command: "cat $HOME/.halt-secret-probe.txt", cwd: CWD }, createStore());
    expect(d.kind).toBe("prompt");
  }, 15000);

  it("ls $HOME/.pi auto-allows (~/.pi is an allowed read dir — no over-flag)", async () => {
    const d = await decide({ type: "bash", command: "ls $HOME/.pi", cwd: CWD }, createStore());
    expect(d.kind).toBe("auto-allow");
  }, 15000);
});

describe("opaque variable expansions in path position", () => {
  it("cat $X prompts (computed path — marker outside every allowed dir)", async () => {
    const a = await analyzeCommand("cat $X", CWD);
    expect(a.paths).toContain(`${OPAQUE_VAR_DIR}/$X`);
    const d = await decide({ type: "bash", command: "cat $X", cwd: CWD }, createStore());
    expect(d.kind).toBe("prompt");
  }, 15000);

  it("X=/etc/shadow && cat $X prompts (same-command variable bypass)", async () => {
    const d = await decide({ type: "bash", command: "X=/etc/shadow && cat $X", cwd: CWD }, createStore());
    expect(d.kind).toBe("prompt");
  }, 15000);

  it("sort -o $X and redirect > $X prompt (write destinations)", async () => {
    const a1 = await analyzeCommand("sort -o $X in.txt", CWD);
    expect(a1.paths).toContain(`${OPAQUE_VAR_DIR}/$X`);
    const a2 = await analyzeCommand("echo hi > $X", CWD);
    expect(a2.paths).toContain(`${OPAQUE_VAR_DIR}/$X`);
    const d2 = await decide({ type: "bash", command: "echo hi > $X", cwd: CWD }, createStore());
    expect(d2.kind).toBe("prompt");
  }, 15000);

  it("flag-embedded opaque values prompt (-f=$X)", async () => {
    const d = await decide({ type: "bash", command: "head -f=$X in.txt", cwd: CWD }, createStore());
    const a = await analyzeCommand("head -f=$X in.txt", CWD);
    expect(a.paths.some(p => p.startsWith(OPAQUE_VAR_DIR))).toBe(true);
    expect(d.kind).toBe("prompt");
  }, 15000);

  it("$HOME stays closed-set (no marker, resolved normally)", async () => {
    const a = await analyzeCommand("cat $HOME/x.txt ${HOME}/y.txt", CWD);
    expect(a.paths.some(p => p.startsWith(OPAQUE_VAR_DIR))).toBe(false);
    expect(a.paths).toContain(path.join(HOME, "x.txt"));
    expect(a.paths).toContain(path.join(HOME, "y.txt"));
  }, 15000);
});
