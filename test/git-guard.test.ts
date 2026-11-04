/**
 * The git guard (3.50.0) — code-execution flags, local-history destruction and
 * the location flags git uses to operate outside the working set.
 *
 * The table entry ["git", "subcommands write/execute (push --force, reset
 * --hard, clean -fd, …)"] was a hand-written subset of a grammar whose flags
 * execute code (`--exec-path`, `--config-env`) and whose subcommands destroy
 * local state (`checkout -- .`, `stash clear`, `branch -D`, `update-ref -d`).
 * Every row here was an auto-allow before the fix.
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it, beforeAll, afterAll } from "vitest";
import { decide } from "../decide/engine";
import { createStore } from "../gate/store";
import type { Decision } from "../decide/types";
import { createContractCwd, removeContractCwd } from "./hermetic-cwd";

let cwd: string;
let outside: string;

beforeAll(() => {
  cwd = createContractCwd();
  // Under $HOME, not /tmp: /tmp is an allowed-read/write dir, so an "outside"
  // location there would be in the bar and the test would prove nothing.
  outside = fs.mkdtempSync(path.join(os.homedir(), ".halter-git-outside-"));
});
afterAll(() => {
  removeContractCwd(cwd);
  fs.rmSync(outside, { recursive: true, force: true });
});

const decideBash = (command: string, store = createStore()): Promise<Decision> =>
  decide({ type: "bash", command, cwd }, store);

const kindOf = async (command: string): Promise<string> => (await decideBash(command)).kind;

describe("local-history destruction prompts", () => {
  const destructive = [
    "git checkout -- .",
    "git checkout .",
    "git checkout -f main",
    "git switch --discard-changes main",
    "git restore .",
    "git restore --staged x",
    "git stash drop",
    "git stash clear",
    "git branch -D main",
    "git branch -f main HEAD~3",
    "git branch --delete main",
    "git tag -d v1",
    "git tag -f v1 HEAD~1",
    "git update-ref -d refs/heads/main",
    "git worktree remove --force wt",
    "git reflog delete",
    "git filter-branch --all",
    "git prune",
  ];

  it("each one reaches the prompt", async () => {
    for (const command of destructive) {
      expect(await kindOf(command), command).not.toBe("auto-allow");
    }
  });

  it("the documented non-destructive git rows still auto-allow", async () => {
    for (const command of [
      "git status",
      "git log --oneline -5",
      "git diff",
      "git add .",
      "git commit -m x",
      "git checkout main",
      "git switch main",
      "git stash",
      "git stash list",
      "git branch",
      "git branch -m new-name",
      "git tag -a v1 -m x",
      "git fetch",
      "git merge main",
    ]) {
      expect(await kindOf(command), command).toBe("auto-allow");
    }
  });
});

describe("git's code-execution flags prompt", () => {
  const exec = [
    "git --exec-path=/tmp/evil status",
    "git --exec-path /tmp/evil status",
    "git --config-env=core.fsmonitor=EVIL status",
    "git --config-env=core.pager=EVIL log",
    "git --config-env=alias.st=EVIL st",
    "git -c core.pager=EVIL log",
    "git -c alias.st='!rm -rf /tmp/x' st",
  ];

  it("each one reaches the prompt", async () => {
    for (const command of exec) {
      expect(await kindOf(command), command).not.toBe("auto-allow");
    }
  });

  it("the bare --exec-path (a print) and a benign config-env stay allowed", async () => {
    expect(await kindOf("git --exec-path")).toBe("auto-allow");
    expect(await kindOf("git --config-env=user.name=EVIL status")).toBe("auto-allow");
  });
});

describe("git location flags face the working-set bar", () => {
  it("a location flag or write destination outside cwd prompts", async () => {
    for (const command of [
      `git -C ${outside} status`,
      `git -C ${outside} init`,
      `git --git-dir=${outside}/.git status`,
      `git --work-tree=${outside} checkout -- .`,
      `git init ${outside}/repo`,
      `git worktree add ${outside}/wt main`,
      `git archive -o ${outside}/x.tar HEAD`,
      `git bundle create ${outside}/x.bundle HEAD`,
      "git -C ~/Downloads/halter-guard-probe status",
      'git -C "$DIR" status',
    ]) {
      expect(await kindOf(command), command).not.toBe("auto-allow");
    }
  });

  it("locations inside the working set (and /tmp) still auto-allow", async () => {
    for (const command of [
      "git -C . status",
      `git -C ${cwd} status`,
      "git -C /tmp status",
      `git init ${cwd}/repo`,
      "git worktree add sub main",
      "git clone https://example.com/x",
    ]) {
      expect(await kindOf(command), command).toBe("auto-allow");
    }
  });
});

describe("git behind an inline assignment / spelling", () => {
  it("an assignment-prefixed git write is never auto-allowed", async () => {
    for (const command of ["FOO=1 git push", "FOO=1 git checkout -- .", "GIT push", "\\git push", '"git" push']) {
      expect(await kindOf(command), command).not.toBe("auto-allow");
    }
  });

  it("an assignment-prefixed git read still prompts (exact grant only)", async () => {
    const d = await decideBash("FOO=1 git status");
    expect(d.kind).toBe("prompt");
    if (d.kind === "prompt" && d.promptData.type === "bash") {
      expect(d.promptData.signatures).toEqual(["foo=1 git"]);
      expect(d.promptData.hasUnsafePattern).toBe(false);
    }
  });
});
