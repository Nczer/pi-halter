import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

/**
 * The account name leaks into this repo in path literals — comments and test
 * fixtures written as `<home>/…` instead of `$HOME/…` or `~<user>`. It happened
 * twice in a row and was caught by hand both times, after the commit. The repo
 * is public, and in a quoted ledger excerpt the account name is the one field
 * that identifies the person, so the class gets a gate instead of a review
 * habit (AGENTS.md: no usernames or absolute home paths in tracked text).
 *
 * The name comes from the running host, not a literal: the leak that matters is
 * the current machine's, and the same repo is worked on Linux and macOS, so each
 * host checks its own account. The pattern is the leak's SHAPE — a home path
 * segment (`home/<user>`) or a tilde form (`~<user>`) — not the bare name, so a
 * short or common-word username cannot fail an unrelated run.
 */
const repoRoot = path.dirname(path.dirname(fileURLToPath(import.meta.url)));

/** Tracked text files: the surface a reader of the repo actually sees. */
const TEXT_FILE_RE = /\.(ts|tsx|js|mjs|cjs|json|md|sh|py|yaml|yml)$/;

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

describe("repo hygiene", () => {
  it("no tracked file carries the account name in a path", () => {
    const user = os.userInfo().username;
    expect(user, "os.userInfo().username").toBeTruthy();
    const list = spawnSync("git", ["ls-files"], { cwd: repoRoot, encoding: "utf8" });
    if (list.status !== 0) throw new Error(`git ls-files: ${list.stderr.trim()}`);
    const files = list.stdout.split("\n").filter((f) => TEXT_FILE_RE.test(f));
    expect(files.length, "tracked text files found").toBeGreaterThan(20);
    const leakRe = new RegExp(`(?:home/|~)${escapeRe(user)}(?![\\w.-])`);
    const hits = files.filter((f) => leakRe.test(fs.readFileSync(path.join(repoRoot, f), "utf8")));
    expect(hits, `tracked files naming the account in a path (${files.length} scanned)`).toEqual([]);
  }, 30_000);
});
