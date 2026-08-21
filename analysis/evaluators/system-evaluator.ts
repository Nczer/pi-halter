import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { EvaluationBuilder } from "./builder";
import { EvalCache, RiskEvaluator } from "./types";
import { getFirstWord } from "../segment-helpers";
import { expandTilde } from "../path-util";

/** Check if an arg contains a short flag character (exact match or composite like -if). Rejects long flags. */
function hasShortFlag(arg: string, flagChar: string): boolean {
  if (arg === "-" + flagChar) return true;
  if (arg.startsWith("-") && !arg.startsWith("--") && arg.includes(flagChar)) return true;
  return false;
}

// ── rm mass-deletion detection ──

/** Directories whose wholesale deletion is never a routine operation. */
const SYSTEM_RM_DIRS = new Set([
  "/", "/home", "/root", "/etc", "/usr", "/var", "/boot",
  "/bin", "/sbin", "/lib", "/lib64", "/dev", "/opt",
]);

/** Directories/globs with at least this many entries get called out by name. */
const LARGE_DIR_THRESHOLD = 100;

const HOME_REAL = (() => {
  try { return fs.realpathSync(os.homedir()); } catch { return path.resolve(os.homedir()); }
})();

function unquoteToken(s: string): string {
  if (s.length >= 2 && s[0] === s[s.length - 1] && (s[0] === '"' || s[0] === "'")) {
    return s.slice(1, -1);
  }
  return s;
}

/** true if the path is (or realpath-resolves to) the user's home directory. */
function isHomePath(p: string): boolean {
  try {
    return fs.realpathSync(p) === HOME_REAL;
  } catch {
    return path.resolve(p) === path.resolve(os.homedir());
  }
}

/**
 * Resolve an rm target token to an absolute path. `~`/`$HOME` expand against
 * the real home; relative tokens resolve against the segment's cwd only when
 * the cwd is known (the unknown-base marker is not a real directory).
 * Null = not resolvable → skip mass-deletion checks for this token.
 */
function resolveRmTarget(token: string, cwd: string, cwdKnown: boolean): string | null {
  const t = unquoteToken(token);
  const home = os.homedir();
  if (t === "~" || t === "$HOME" || t === "${HOME}") return home;
  if (t.startsWith("~/")) return path.join(home, t.slice(2));
  if (t.startsWith("$HOME/")) return path.join(home, t.slice("$HOME/".length));
  if (t.startsWith("${HOME}/")) return path.join(home, t.slice("${HOME}/".length));
  if (t.startsWith("/")) return t;
  if (!cwdKnown) return null;
  return path.resolve(cwd, t);
}

/** Count directory entries, stopping early at threshold. Null if not a directory or unreadable. */
function countDirEntries(p: string, threshold: number): number | null {
  try {
    if (!fs.statSync(p).isDirectory()) return null;
    const dir = fs.opendirSync(p);
    try {
      let n = 0;
      while (n < threshold) {
        if (!dir.readSync()) break;
        n += 1;
      }
      return n;
    } finally {
      dir.closeSync();
    }
  } catch {
    return null;
  }
}

/**
 * Add a mass-deletion reason if a single rm target wipes a "stupid amount of
 * stuff": the whole home dir, a system dir, a big directory tree, or a bare
 * `*` glob over a big directory. Fail-soft — any fs error just skips the
 * check (the generic rm prompt applies either way).
 */
function flagMassDeletionTarget(
  token: string,
  recursive: boolean,
  cwd: string,
  cwdKnown: boolean,
  b: EvaluationBuilder,
): void {
  if (/[*?]/.test(token)) {
    // Only count bare `*` globs (`rm dir/*`, `rm *`) — counting matches for
    // narrower patterns (*.log, *.tar.gz) would over-report. Other globs
    // still get the generic rm prompt.
    const slash = token.lastIndexOf("/");
    const dirPart = slash >= 0 ? token.slice(0, slash) : "";
    const lastPart = slash >= 0 ? token.slice(slash + 1) : token;
    if (lastPart !== "*" || /[*?]/.test(dirPart)) return;
    if (!cwdKnown && dirPart !== "/") return;
    const base = dirPart.startsWith("~")
      ? expandTilde(dirPart)
      : cwdKnown ? path.resolve(cwd, dirPart) : dirPart;
    const n = countDirEntries(base, LARGE_DIR_THRESHOLD);
    if (n !== null && n >= LARGE_DIR_THRESHOLD) {
      b.addReason(`glob matches ${n}+ files (mass deletion)`);
    }
    return;
  }
  const p = resolveRmTarget(token, cwd, cwdKnown);
  if (!p) return;
  if (isHomePath(p)) {
    b.addReason("target is the home directory (entire home deleted)");
    return;
  }
  const norm = path.normalize(p).replace(/\/+$/, "") || "/";
  if (SYSTEM_RM_DIRS.has(norm)) {
    b.addReason(`target is system directory ${norm} (entire tree deleted)`);
    return;
  }
  // Non-recursive `rm dir` fails on directories — the entry count only
  // matters for recursive deletes.
  if (recursive) {
    const n = countDirEntries(p, LARGE_DIR_THRESHOLD);
    if (n !== null && n >= LARGE_DIR_THRESHOLD) {
      b.addReason(`recursive delete of directory with ${n}+ entries (mass deletion)`);
    }
  }
}

/** Mass-deletion pass over rm (or `sudo rm …`) targets. */
function evaluateMassDeletion(
  rest: string[],
  cwd: string,
  cwdKnown: boolean,
  b: EvaluationBuilder,
): void {
  const recursive = rest.some((a) => hasShortFlag(a, "r") || hasShortFlag(a, "R") || a === "--recursive");
  const targets = rest.filter((a) => !a.startsWith("-"));
  if (targets.length >= LARGE_DIR_THRESHOLD) {
    b.addReason(`deletes ${targets.length} file arguments (mass deletion)`);
    return;
  }
  for (const t of targets) {
    flagMassDeletionTarget(t, recursive, cwd, cwdKnown, b);
  }
}

// ── System command handlers ──

/** System command → handler (match, evaluate). */
const SYSTEM_HANDLERS: Array<{ match: (cmd: string) => boolean; evaluate: (cmd: string, rest: string[], b: EvaluationBuilder, ctx: { cwd: string; cwdKnown: boolean }) => void }> = [
  // sudo
  { match: (c) => c === "sudo",
    evaluate: (_cmd, rest, b, ctx) => {
      b.addHigh("sudo (privilege escalation)");
      // `sudo rm …` / `sudo -u root rm …` — find the rm and mass-check its args.
      // A literal file named "rm" in a non-rm sudo command just yields no targets.
      const rmIdx = rest.indexOf("rm");
      if (rmIdx >= 0) evaluateMassDeletion(rest.slice(rmIdx + 1), ctx.cwd, ctx.cwdKnown, b);
    } },
  // rm/rmdir/unlink
  { match: (c) => ["rm", "rmdir", "unlink"].includes(c),
    evaluate: (cmd, rest, b, ctx) => {
      b.setHigh();
      b.markDanger();
      if (rest.some((a) => hasShortFlag(a, "r") || hasShortFlag(a, "R")))
        b.addReason("recursive delete (-r/-R)");
      if (rest.some((a) => hasShortFlag(a, "f")))
        b.addReason("forced delete (-f)");
      // rmdir only removes empty dirs and unlink a single file — mass checks are rm-only.
      if (cmd === "rm") evaluateMassDeletion(rest, ctx.cwd, ctx.cwdKnown, b);
    } },
  // chmod/chown
  { match: (c) => c === "chmod" || c === "chown",
    evaluate: (cmd, rest, b) => {
      b.markDanger();
      if (rest.includes("-R") || rest.includes("--recursive")) {
        b.addReason(`${cmd} -R (recursive ${cmd === "chmod" ? "permission" : "ownership"} changes)`);
        b.setHigh();
      } else {
        b.setMedium();
      }
    } },
  // mv/cp
  { match: (c) => c === "mv" || c === "cp",
    evaluate: (cmd, rest, b) => {
      b.markDanger();
      if (rest.some((a) => hasShortFlag(a, "f")) || rest.includes("--force")) {
        b.addMedium(`${cmd} --force/-f (can overwrite files)`);
      } else {
        b.setMedium();
      }
    } },
  // truncate
  { match: (c) => c === "truncate",
    evaluate: (_cmd, _rest, b) => { b.addReason("truncate (in-place size change, can erase contents)"); b.setHigh(); b.markDanger(); } },
  // dd of=
  { match: (c) => c === "dd",
    evaluate: (_cmd, rest, b) => {
      if (rest.some(a => a.startsWith("of="))) {
        b.addReason("dd with output file/device (can overwrite data)");
        b.setHigh();
        b.markDanger();
      }
    } },
  // kill/pkill/killall
  { match: (c) => ["kill", "pkill", "killall"].includes(c),
    evaluate: (cmd, rest, b) => {
      b.addReason(`${cmd} (process termination)`);
      if (rest.includes("-9")) {
        b.setHigh();
        b.markDanger();
        b.addReason("SIGKILL (-9)");
      }
    } },
  // shutdown/reboot
  { match: (c) => ["shutdown", "reboot"].includes(c),
    evaluate: (cmd, _rest, b) => { b.addReason(`${cmd} (system power operation)`); b.setHigh(); b.markDanger(); } },
  // systemctl
  { match: (c) => c === "systemctl",
    evaluate: (_cmd, rest, b) => {
      if (rest.includes("stop") || rest.includes("disable")) {
        b.addReason("systemctl stop/disable (service disruption)");
        b.setMedium();
        b.markDanger();
      }
    } },
  // crontab
  { match: (c) => c === "crontab",
    evaluate: (_cmd, _rest, b) => { b.addMedium("crontab (scheduled task management)"); b.markDanger(); } },
  // nohup
  { match: (c) => c === "nohup",
    evaluate: (_cmd, _rest, b) => { b.addMedium("nohup (persist process after shell exit)"); b.markDanger(); } },
  // screen
  { match: (c) => c === "screen",
    evaluate: (_cmd, _rest, b) => { b.addMedium("screen (terminal multiplexer)"); b.markDanger(); } },
  // ssh
  { match: (c) => c === "ssh",
    evaluate: (_cmd, _rest, b) => { b.addMedium("ssh (remote command execution)"); b.markDanger(); } },
  // scp/rsync
  { match: (c) => ["scp", "rsync"].includes(c),
    evaluate: (_cmd, _rest, b) => { b.addMedium(`${_cmd} (remote file transfer)`); b.markDanger(); } },
  // patch
  { match: (c) => c === "patch",
    evaluate: (_cmd, _rest, b) => { b.addMedium("patch (file patching)"); b.markDanger(); } },
  // install (not chmod install, which is cp-mode)
  { match: (c) => c === "install",
    evaluate: (_cmd, _rest, b) => { b.addMedium("install (copy and set permissions)"); b.markDanger(); } },
  // ln
  { match: (c) => c === "ln",
    evaluate: (_cmd, _rest, b) => { b.addMedium("ln (link creation)"); b.markDanger(); } },
  // tee
  { match: (c) => c === "tee",
    evaluate: (_cmd, _rest, b) => { b.addMedium("tee (file writing)"); b.markDanger(); } },
];

/**
 * Evaluates system commands: sudo, rm, chmod, chown, mv, cp, kill, shutdown, systemctl, truncate, dd.
 */
export const SystemEvaluator: RiskEvaluator = {
  name: "system",
  evaluate(seg, cwd, cache): ReturnType<EvaluationBuilder["build"]> {
    const segment = seg.text;
    const firstWord = cache?.firstWord ?? getFirstWord(segment);
    const rest = segment.trim().split(/\s+/).slice(1);
    const b = new EvaluationBuilder();

    for (const handler of SYSTEM_HANDLERS) {
      if (handler.match(firstWord)) {
        handler.evaluate(firstWord, rest, b, { cwd, cwdKnown: cache?.cwdKnown ?? true });
        return b.build();
      }
    }

    return b.build();
  },
};
