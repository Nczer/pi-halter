import path from "node:path";
import { EvaluationBuilder } from "./builder";
import { EvalCache, EvaluatorResult, RiskEvaluator } from "./types";
import { getFirstWord, isGitDangerous, parseGitSubcommand } from "../segment-helpers";
import { skipEnvPrefixes } from "../../config";
import { tokenizeSegment } from "../tokenizer";
import { expandTilde } from "../path-util";
import { getOutsideCwdPaths, resolvePathReal } from "../path-analysis";

/** git's own location flags: the value is a directory the command operates
 *  in/on (`git -C <dir>`, `--git-dir=<dir>`, `--work-tree=<dir>`), not a
 *  subcommand. The parser mints no path for it (git is not path-aware, and the
 *  flag is navigation, not a file operand), so a value outside the working set
 *  used to reach the table unchecked: `git -C ~/Downloads/x init` wrote a repo
 *  outside cwd and auto-allowed. */
const GIT_LOCATION_VALUE_FLAGS = new Set(["-C", "--git-dir", "--work-tree"]);

/** A remote source (`https://…`, `git://…`, `user@host:path`) — never a local
 *  read, so it is not a location question. */
const GIT_REMOTE_SOURCE_RE = /^[A-Za-z][A-Za-z0-9+.-]*:\/\/|^[^/]+@[^/]+:/;

/** The positional arguments a git subcommand WRITES (`clone <repo> [dir]`,
 *  `init [dir]`, `worktree add <dir>`, `archive -o <file>`,
 *  `bundle create <file>`) — the destination half of the location shape. */
function gitWriteLocationArgs(sub: string, args: string[]): string[] {
  const positionals = args.filter((x) => !x.startsWith("-"));
  switch (sub) {
    case "clone": {
      const out: string[] = [];
      const repo = positionals[0];
      const dest = positionals[1];
      // A local source is a READ of the tree being cloned.
      if (repo && !GIT_REMOTE_SOURCE_RE.test(repo)) out.push(repo);
      if (dest) out.push(dest);
      return out;
    }
    case "init":
      return positionals.slice(0, 1);
    case "worktree":
      return args[0] === "add" ? positionals.slice(1, 2) : [];
    case "archive": {
      const out: string[] = [];
      for (let i = 0; i < args.length; i++) {
        if (args[i] === "-o" || args[i] === "--output") {
          if (args[i + 1] !== undefined) out.push(args[i + 1]);
          i++;
        } else if (args[i].startsWith("--output=")) {
          out.push(args[i].slice("--output=".length));
        }
      }
      return out;
    }
    case "bundle":
      return args[0] === "create" ? positionals.slice(1, 2) : [];
    default:
      return [];
  }
}

/**
 * The locations a git command names outside the working set — the global
 * location flags and the write destinations above. Relative values resolve
 * against the segment's own base; a computed value (`-C "$DIR"`) is reported as
 * outside (fail closed — the location is not provable). The bar is the config
 * one (`getOutsideCwdPaths`: cwd + config-allowed + trusted scripts); a session
 * grant is not visible here, so a granted dir still stops — a false prompt,
 * never a false allow.
 */
function gitOutsideLocations(segment: string, cwd: string): string[] {
  const words = tokenizeSegment(segment);
  const args = words.slice(skipEnvPrefixes(words) + 1);
  const outside: string[] = [];
  const add = (raw: string | undefined): void => {
    if (raw === undefined || raw === "") return;
    if (/[$`]/.test(raw)) {
      outside.push(raw);
      return;
    }
    const abs = resolvePathReal(expandTilde(raw), cwd);
    if (getOutsideCwdPaths([abs], cwd).length > 0) outside.push(raw);
  };
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (GIT_LOCATION_VALUE_FLAGS.has(a)) {
      add(args[i + 1]);
      i++;
      continue;
    }
    if (a.startsWith("--git-dir=") || a.startsWith("--work-tree=")) {
      add(a.slice(a.indexOf("=") + 1));
      continue;
    }
    if (/^-C./.test(a)) {
      add(a.slice(2));
      continue;
    }
  }
  const parsed = parseGitSubcommand(segment);
  if (parsed) for (const v of gitWriteLocationArgs(parsed.sub, parsed.subArgs)) add(v);
  return [...new Set(outside)];
}

/**
 * Evaluates git commands for dangerous operations.
 */
export const GitEvaluator: RiskEvaluator = {
  name: "git",
  evaluate(seg, cwd, cache): EvaluatorResult {
    const segment = seg.text;
    const firstWord = cache?.firstWord ?? getFirstWord(segment);
    const b = new EvaluationBuilder();

    if (firstWord !== "git") return b.build();

    // Use cached result or compute inline
    const dangerous = cache?.gitDangerous ?? isGitDangerous(segment);
    if (dangerous) {
      // Subcommand resolved past global flags (git -C dir push → push) so the
      // reason and severity describe what isGitDangerous actually flagged.
      const parsed = parseGitSubcommand(segment);
      const sub = parsed?.sub ?? "?";
      const subArgs = parsed?.subArgs ?? [];
      const forcePush = sub === "push" && (subArgs.includes("--force") || subArgs.includes("--force-with-lease") || subArgs.includes("-f"));
      // A code-execution global flag is the reason when it is the reason: the
      // subcommand itself may be a read (`--exec-path` turns `status` into
      // "run /tmp/evil/git-status").
      const execFlag = tokenizeSegment(segment).find(
        (t) => t === "--exec-path" || t.startsWith("--exec-path=") || t === "--config-env" || t.startsWith("--config-env="),
      );
      // Include specific flag context so prompts show why it's dangerous
      const reason =
        execFlag ? `git ${execFlag.split("=")[0]} (runs a program the command names)`
        : sub === "reset" ? `git reset --hard (discards uncommitted changes)`
        : sub === "push" ? (forcePush ? `git push --force (rewrites remote history)` : `git push (writes to remote)`)
        : sub === "clean" ? `git clean -fdx (deletes untracked files)`
        : sub === "rm" ? `git rm (removes files from working tree)`
        : sub === "reflog" ? `git reflog expire (removes recovery history)`
        : sub === "gc" ? `git gc --prune (permanently deletes objects)`
        : sub === "checkout" || sub === "switch" || sub === "restore" ? `git ${sub} (discards uncommitted changes)`
        : sub === "stash" ? `git stash drop/clear (destroys a saved stash)`
        : sub === "branch" || sub === "tag" || sub === "update-ref" || sub === "replace" ? `git ${sub} (rewrites or deletes a local ref)`
        : sub === "worktree" ? `git worktree remove (deletes a working tree)`
        : sub === "filter-branch" || sub === "prune" ? `git ${sub} (rewrites or deletes history)`
        : `git ${sub} (dangerous)`;
      // Destructive git ops are high; a plain (non-force) push is a normal
      // remote write — medium, still dangerous.
      if (sub === "push" && !forcePush) b.danger(reason); else b.high(reason);
    }

    // Locations the command names outside the working set (the parser mints
    // none of them). Not a bar on its own: the flag matters as much as the
    // location, so the reason is class-tagged and fails closed to a prompt.
    const outside = gitOutsideLocations(segment, cwd);
    if (outside.length > 0) {
      b.danger(`git location outside the working set (${outside.slice(0, 2).join(", ")})`);
    }

    return b.build();
  },
};
