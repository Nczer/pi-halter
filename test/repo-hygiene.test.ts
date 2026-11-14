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
 *
 * That host-shaped rule cannot see the other host's account: the macOS home is
 * `/Users/<name>`, and a name quoted from the macOS ledgers into a fixture on
 * Linux matches nothing here (found 2026-10-29 while merging the two ledgers for
 * the location-model replay). So the macOS shape is checked by EXCEPTION instead:
 * the fixtures use an anonymized namespace (`test/canon.ts`), and a `/Users/<x>`
 * whose `<x>` is not one of those placeholders is a real account name on either
 * host. The Linux shape stays host-shaped — its fixture namespace is wider
 * (`user`, `u`, `x`, `root`, `other`) and `/home/<name>` collides with ordinary
 * fixture paths, so an exception list there would be longer than the leak.
 *
 * A path shape cannot catch a NAME, and a name is what an incident label
 * quotes: a test once read `describe("D21 gate scenarios (<client> incident)")`,
 * and vendored `node_modules` blobs carried a third-party maintainer's full name
 * before that folder was untracked. Both outlived their context — a client name
 * and a person name in a public repo, copied by every future fixture written
 * from the old test. So the words themselves are banned outright,
 * case-insensitively, at a word boundary (second test below). The list is spelled
 * with a one-letter character class so this file cannot match its own gate.
 */
const repoRoot = path.dirname(path.dirname(fileURLToPath(import.meta.url)));

/** Tracked text files: the surface a reader of the repo actually sees. */
const TEXT_FILE_RE = /\.(ts|tsx|js|mjs|cjs|json|md|sh|py|yaml|yml)$/;

/** The anonymized `/Users/…` namespace of this repo's fixtures and prose. A
 *  first segment outside this set is somebody's macOS account name. */
const ANONYMOUS_MAC_HOME = new Set(["u", "user", "me", "other"]);

/** Names this repo must never carry: a client name quoted out of an incident
 *  label, and a person's name that sat in vendored files. Matched whole-word,
 *  case-insensitive. Each pattern carries a `[x]` class so the banned literal
 *  never appears in this file (which the scan itself reads). */
const FORBIDDEN_NAMES: RegExp[] = [/\bmo[s]ac\b/i, /\bke[v]in\b/i];

/** The leak shapes one file carries, so a failure names what it found. */
function leaksIn(text: string, user: string, hostRe: RegExp): string[] {
  const found = new Set<string>();
  if (hostRe.test(text)) found.add(`home of the current account (${user})`);
  for (const m of text.matchAll(/\/Users\/([A-Za-z0-9._-]+)/g)) {
    if (!ANONYMOUS_MAC_HOME.has(m[1])) found.add(`/Users/${m[1]}`);
  }
  return [...found];
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** Tracked text files: the surface a reader of the repo actually sees. */
function trackedTextFiles(): string[] {
  const list = spawnSync("git", ["ls-files"], { cwd: repoRoot, encoding: "utf8" });
  if (list.status !== 0) throw new Error(`git ls-files: ${list.stderr.trim()}`);
  const files = list.stdout.split("\n").filter((f) => TEXT_FILE_RE.test(f));
  expect(files.length, "tracked text files found").toBeGreaterThan(20);
  return files;
}

describe("repo hygiene", () => {
  it("no tracked file carries the account name in a path", () => {
    const user = os.userInfo().username;
    expect(user, "os.userInfo().username").toBeTruthy();
    const files = trackedTextFiles();
    const leakRe = new RegExp(`(?:home/|~)${escapeRe(user)}(?![\\w.-])`);
    const hits: string[] = [];
    for (const f of files) {
      const shapes = leaksIn(fs.readFileSync(path.join(repoRoot, f), "utf8"), user, leakRe);
      if (shapes.length) hits.push(`${f}: ${shapes.join(", ")}`);
    }
    expect(hits, `tracked files naming the account in a path (${files.length} scanned)`).toEqual([]);
  }, 30_000);

  it("no tracked file names a real person or a client", () => {
    const files = trackedTextFiles();
    const hits: string[] = [];
    for (const f of files) {
      const text = fs.readFileSync(path.join(repoRoot, f), "utf8");
      const found = FORBIDDEN_NAMES.flatMap((re) => text.match(new RegExp(re, "gi")) ?? []);
      if (found.length) hits.push(`${f}: ${[...new Set(found)].join(", ")}`);
    }
    expect(hits, `tracked files naming a person or a client (${files.length} scanned)`).toEqual([]);
  }, 30_000);
});
