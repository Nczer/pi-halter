import path from "node:path";

// ── Bash command patterns ──

/**
 * The single source of truth for the bash command allowlist.
 *
 * Every entry is allowlisted (`allowedBashCommands` — the full pipeline).
 * An entry WITHOUT an exclusion reason is additionally unconditionally safe
 * (`unconditionallySafeCommands` — the WASM-skip fast path in FastAllowRule).
 * An entry WITH a reason has flag-dependent write/exec behavior or delegates
 * to another command: the fast path must never decide for it, the full
 * pipeline does.
 *
 * Invariant (test/allow-invariant.test.ts): for every unconditionally-safe
 * entry the full pipeline auto-allows a bare invocation — the fast path may
 * never out-run SafetyRule.
 */
type AllowEntry = readonly [cmd: string, whyNotUnconditional?: string];

const ALLOW_TABLE: readonly AllowEntry[] = [
  // Inspection / read-only
  // `stat` — pure metadata display; GNU/BSD stat has no write/exec flags.
  ["find", "-delete / -exec / -fprint* perform writes and exec"],
  ["grep", "no known write/exec flag; kept on the full pipeline (conservative)"],
  ["ls"], ["cat"], ["head"], ["tail"], ["wc"], ["file"], ["stat"],
  ["sort", "-o / --output truncates or writes files"],
  ["uniq"], ["cut"], ["tr"], ["diff"],
  ["rg", "--pre executes a command per file"],
  ["fd", "-x / --exec executes a command per result"],
  // JSON querying (stdout only — no file writes, no exec capability;
  // output redirection is shell-level and flagged by the redirect checks)
  ["jq"],
  ["tac"], ["rev"], ["nl"], ["fold"], ["expand"], ["unexpand"], ["fmt"],
  ["join"], ["comm"], ["paste"], ["column"], ["seq"],
  // Text transform (safe stdout — guarded by dangerous flag checks)
  ["sed", "-i edits files in place"],
  ["perl", "-i edits files in place"],
  // Hashing / binary inspection
  ["md5sum"], ["sha1sum"], ["sha256sum"], ["sha512sum"], ["cksum"],
  ["hexdump"], ["od"], ["strings"],
  // Strings / formatting
  // `read` — stdin-only shell builtin (no file access, no exec); keeps
  // `while read -r x; do …; done` loops from prompting on the builtin itself.
  ["echo"], ["printf"], ["basename"], ["dirname"], ["realpath"], ["readlink"],
  ["test"], ["true"], ["false"], ["read"],
  // System info (read-only, no file side effects)
  // NOTE: `printenv` is not in the table at all — with args it prints env
  // vars (often secrets: OPENAI_API_KEY) into the transcript; bare it dumps
  // ALL environment variables.
  ["pwd"], ["cd"], ["date"], ["whoami"], ["id"], ["uname"], ["hostname"],
  ["groups"], ["uptime"], ["tty"], ["tput"],
  // Disk / process inspection (read-only)
  ["df"], ["du"], ["free"], ["ps"], ["pgrep"], ["pidof"],
  // Command lookup
  ["which"],
  ["command", "-p runs the named command (command -p rm)"],
  ["type"], ["hash"], ["whence"],
  // Git (guarded by dangerous subcommand checks)
  ["git", "subcommands write/execute (push --force, reset --hard, clean -fd, …)"],
  // Tmux (guarded by dangerous subcommand checks)
  ["tmux", "send-keys / new-session can inject keystrokes or run shells"],
  // File/dir creation (writes — guarded by the no-redirect check)
  ["mkdir", "creates directories (write)"],
  ["touch", "creates files / updates mtimes (write)"],
  ["mktemp", "creates files (write)"],
  // Calculator
  ["bc"], ["expr"], ["factor"], ["yes"],
  // Process control (no fs/net/exec — a pure wait)
  ["sleep", "kept on the full pipeline (conservative)"],
  // Wrapper commands (guarded by isWrapperRunningWrite check)
  ["xargs", "delegates to an inner command (xargs rm)"],
  ["watch", "delegates to an inner command"],
  ["timeout", "delegates to an inner command (timeout rm)"],
  ["parallel", "delegates to an inner command"],
  ["nice", "delegates to an inner command"],
];

/** O(1) first-word allowlist — pre-built from the table. */
const allowedBashCommands = new Set(ALLOW_TABLE.map(([cmd]) => cmd));

/**
 * Unconditionally-safe subset: table entries without an exclusion reason.
 * Used for the fast pre-check that skips tree-sitter parsing (FastAllowRule).
 */
export const unconditionallySafeCommands = new Set(
  ALLOW_TABLE.filter((entry) => entry[1] === undefined).map(([cmd]) => cmd),
);

/** Commands whose arguments include file/dir paths. */
export const pathAwareCommands = new Set([
  // Inspection / read
  "ls", "cat", "head", "tail", "wc", "file", "stat", "touch",
  "tac", "rev", "nl", "fold", "expand", "unexpand", "fmt",
  "join", "comm", "paste", "column", "split", "shuf",
  "du", "df",
  "rg", "fd", "jq",
  // Hashing / binary
  "md5sum", "sha1sum", "sha256sum", "sha512sum", "cksum",
  "xxd", "hexdump", "od", "strings",
  // File/dir ops
  "mkdir", "rm", "cp", "mv", "chmod", "chown", "mktemp",
  "find", "grep", "diff", "patch",
  // `cd` is NOT path-aware: a cd performs no file access — it is navigation,
  // modeled by the effective-cwd state machine (analysis/cwd-tracking.ts).
  // Credential checks see `cd ~/.s?sh` via the raw-text scan regardless; the
  // base a cd leaves for later segments is flagged by baseAccessPath.
  "pushd", "popd",
  "tar", "zip", "unzip", "gzip", "gunzip",
  "python", "python3", "node", "ruby", "perl", "php",
  "sed", "awk", "sort", "uniq", "cut", "tr", "tee",
  "xargs", "watch", "timeout",
  "source", ".",
  "pip", "npm", "yarn", "cargo", "go",
  "uv",
]);

/** Flags on `find` that make it dangerous (excluding -exec which depends on the subcommand). */
export const dangerousFindFlags = /-(?:delete|empty|truncate|fprint|fprintf|fls)\b/;

/**
 * Flags that make `sed` dangerous (in-place editing). `-i` may carry a backup
 * suffix (the letters right after `i`): `-in` = in-place with backup suffix
 * "n" on GNU/BSD sed — there is no "next-line" flag, so any cluster containing
 * `i` is in-place.
 *
 * The lookbehind restricts the match to a real flag token (preceded by
 * whitespace or start of context). Unanchored, a mid-word dash inside a path
 * is misread as a flag: `agent-session.ts` matched `-[a-z]*i[a-z]*\.ts`
 * (the "i" in "session") and flagged read-only `sed -n` as in-place.
 * Long form only allows the valid GNU sed spellings `--in-place` / `--in-place=suffix`.
 */
export const dangerousSedFlags = /(?<![\w./-])-[a-z]*i[a-z]*(?:\.\S*)?(?:\s|$)|(?<![\w./-])--in-place(?:=|\s|$)/;

/** Flags that make `perl` dangerous (in-place editing via -i, optional suffix). */
export const dangerousPerlFlags = /(?<![\w./-])-[a-z]*i[a-z]*(?:\.\S*)?(?:\s|$)/;

/** Command + subcommand pairs that are always safe (read-only, no side effects). */
const allowedBashSubcommands = new Set([
  "npm ls", "npm view", "npm info",
  "yarn ls", "yarn info",
  "pnpm ls",
  "tsc",
  "cargo check", "cargo clippy", "cargo doc",
]);

/** Check if a first word matches the static allowlist (O(1)). */
export function isAllowedCommand(firstWord: string): boolean {
  return allowedBashCommands.has(firstWord);
}

/**
 * Check if a segment is a safe command+subcommand pair (or safe standalone command).
 * e.g. "npm test -- --coverage" → "npm test" → match.
 *      "tsc" → match (standalone).
 *      "tsc --noEmit" → match (standalone + flags).
 */
export function isSafeSubcommand(segment: string): boolean {
  const tokens = segment.trim().split(/\s+/);
  const cmd = path.basename(tokens[0].toLowerCase());

  // Standalone command in allowlist (e.g. "tsc", "tsc --noEmit")
  if (allowedBashSubcommands.has(cmd)) {
    // If there's a second token and it's not a flag, it's a subcommand — require exact match
    if (tokens.length >= 2 && !tokens[1].startsWith("-")) {
      return allowedBashSubcommands.has(`${cmd} ${tokens[1].toLowerCase()}`);
    }
    return true;
  }

  // Command + subcommand pair (e.g. "npm test")
  if (tokens.length >= 2) {
    const sub = tokens[1].toLowerCase();
    return allowedBashSubcommands.has(`${cmd} ${sub}`);
  }

  return false;
}

/** Wrapper commands that delegate to another command (xargs sed -i, timeout rm, etc.). */
export const wrapperCommands = new Set([
  "xargs", "watch", "timeout", "parallel", "env", "nice", "ionice", "stdbuf",
]);

/** Shell interpreters used by find -exec and similar constructs. */
export const SHELL_INTERPRETERS = new Set(["bash", "sh", "zsh", "fish", "dash", "ksh", "csh", "tcsh"]);

/** Script interpreters that execute arbitrary code (treated as write-capable). */
export const SCRIPT_INTERPRETERS = new Set([
  "python", "python3", "python2", "py",
  "node", "nodejs",
  "ruby", "rb",
  "perl", "php", "lua",
  "deno", "bun", "julia", "r",
  "go run", "rustc",
]);

/** Package manager commands that use subcommands (npm install, cargo check, etc.). */
export const PACKAGE_MANAGERS = new Set(["npm", "yarn", "pnpm", "npx", "cargo", "pip", "pip3", "uv", "go", "bun"]);

/**
 * First words that open a network connection — or fetch remote content that
 * can execute (package managers), or deploy (container/cloud CLIs). ONE
 * definition: the /dspa hard gate uses it to keep auto-allow offline, and the
 * judge packet uses it for the network line. They must not drift — a command
 * the gate calls network egress must not be annotated "network: none" in the
 * packet the judge sees.
 */
export const NETWORK_COMMANDS = new Set([
  "curl", "wget", "nc", "ncat", "ssh", "scp", "sftp", "ftp", "rsync",
  // package managers: install = fetch + execute (postinstall/build scripts)
  "npm", "npx", "pnpm", "yarn", "bun", "pip", "pip3", "uv",
  // container + cloud CLIs: pull/deploy surface
  "docker", "podman", "kubectl", "aws", "gcloud", "az",
]);

// ── D10: fetchable package run forms (docs/dspa-redesign.md) ──

/**
 * Run forms that may FETCH the package on cache miss — the same fetch class
 * the floor stops for fetch forms (arbitrary postinstall execution). Keyed by
 * first word; "all" = bare form (`npx <pkg>`), else the subcommand set
 * (`npm exec`, `pnpm dlx`, …). LOCAL run forms (`npm run`, `uv run`,
 * `bun <script>`) are deliberately absent — they execute repo-visible code
 * the judge already sees and are never trust-gated.
 *
 * ONE definition: the dspa floor (untrusted-package stop) and the bash
 * policy (trusted-package auto-allow) must not drift.
 */
export const FETCH_PKG_FORMS: Record<string, ReadonlySet<string> | "all"> = {
  npx: "all",
  uvx: "all",
  npm: new Set(["exec", "x"]),
  pnpm: new Set(["dlx", "exec", "x"]),
  yarn: new Set(["dlx", "x"]),
  uv: new Set(["x"]),
  bun: new Set(["x"]),
};

/** Strip a `@version` pin (`tsc@5.0.0` → `tsc`); keeps scoped `@scope/name`. */
function stripPkgVersion(pkg: string): string {
  const at = pkg.lastIndexOf("@");
  return at > 0 ? pkg.slice(0, at) : pkg;
}

/**
 * The package a fetchable run form segment names, or null: not a fetch form,
 * a local form (`npm run …`), or no package token. Flags and `K=V` env
 * prefixes are skipped; version pins are stripped so trust keys are bare
 * package names. Only TOP-LEVEL segments are checked (indirection like
 * `out=$(npx foo)` stays judge-only by design).
 */
export function fetchFormPackage(first: string, words: string[]): string | null {
  const forms = FETCH_PKG_FORMS[first];
  if (!forms) return null;
  let i = 1;
  let sub: string | undefined;
  for (; i < words.length; i++) {
    const w = words[i];
    if (w.startsWith("-") || /^[A-Za-z_][A-Za-z0-9_]*=/.test(w)) continue;
    sub = w.toLowerCase();
    break;
  }
  if (forms === "all") {
    return sub ? stripPkgVersion(sub) : null;
  }
  if (!sub || !forms.has(sub)) return null;
  for (let j = i + 1; j < words.length; j++) {
    const w = words[j];
    if (w.startsWith("-") || /^[A-Za-z_][A-Za-z0-9_]*=/.test(w)) continue;
    return stripPkgVersion(w);
  }
  return null;
}

/** git subcommands that talk to a remote. */
export const GIT_NETWORK_SUBCOMMANDS = new Set(["push", "fetch", "pull", "clone"]);

/** http(s) URL in command text (non-global). */
export const NETWORK_URL_RE = /https?:\/\/[^\s"'`)\]]+/;

const NETWORK_URL_RE_GLOBAL = new RegExp(NETWORK_URL_RE.source, "g");

/**
 * All network egress in a command: per-segment first words that can open a
 * network (or fetch/deploy — see NETWORK_COMMANDS), `git` remote
 * subcommands, and http(s) URLs anywhere in the text (deduped, in order).
 *
 * ONE collector for both consumers — the /dspa hard gate (first hit) and
 * the judge packet (annotated list). What counts as egress lives here so
 * the two can never drift: a command the gate treats as network egress must
 * not be annotated "network: none" in the packet the judge sees.
 */
export function findNetworkEgress(
  command: string,
  segments: string[],
): { commands: string[]; urls: string[] } {
  const commands: string[] = [];
  const add = (hit: string) => {
    if (!commands.includes(hit)) commands.push(hit);
  };
  for (const seg of segments) {
    const words = seg.trim().split(/\s+/);
    const first = words[0]?.toLowerCase();
    if (!first) continue;
    if (NETWORK_COMMANDS.has(first)) {
      add(first);
    } else if (first === "git") {
      const sub = words[1]?.toLowerCase() ?? "";
      if (GIT_NETWORK_SUBCOMMANDS.has(sub)) add(`git ${words[1]}`);
    }
  }
  const urls: string[] = [];
  for (const m of command.matchAll(NETWORK_URL_RE_GLOBAL)) {
    if (!urls.includes(m[0])) urls.push(m[0]);
  }
  return { commands, urls };
}

/** Pre-compiled regex for tee write check. */
const TEE_WRITE_RE = /\btee\b.*\S/;

/** Pre-compiled regex for sort -o / --output write target (space, `=`, attached
 *  -ox, and cluster -ro forms — getopt lets -o consume the rest of the token
 *  or the next token). */
export const SORT_OUTPUT_RE = /(?:^|\s)(?:--output(?:\s+|=)\S+|-[a-zA-Z]*o(?:\S+|\s+\S+))/;

/** Commands that always perform write operations (unconditional — no flag-dependent behavior). */
const ALWAYS_WRITE = new Set([
  "rm", "rmdir", "unlink", "mv", "cp", "chmod", "chown",
  "touch", "mkdir", "dd", "truncate", "patch", "install", "ln",
]);

/** Archive/package-manager commands that always write. */
const ALWAYS_WRITE_ARCHIVE_PKG = new Set([
  "tar", "zip", "unzip", "gzip", "gunzip",
  "pip", "npm", "yarn", "cargo", "go", "uv",
  // npx executes (and can fetch) arbitrary packages — wrapper delegation
  // (timeout npx …) must not treat it as benign.
  "npx",
]);

// ── Write operation handlers ──

/** Command → write check (match, evaluate). */
const WRITE_HANDLERS: Array<{ match: (cmd: string) => boolean; evaluate: (cmd: string, context: string) => boolean }> = [
  { match: (c) => ALWAYS_WRITE.has(c), evaluate: () => true },
  { match: (c) => ALWAYS_WRITE_ARCHIVE_PKG.has(c), evaluate: () => true },
  { match: (c) => c === "sed", evaluate: (_, ctx) => dangerousSedFlags.test(ctx) },
  { match: (c) => c === "tee", evaluate: (_, ctx) => TEE_WRITE_RE.test(ctx) },
  { match: (c) => c === "sort", evaluate: (_, ctx) => SORT_OUTPUT_RE.test(ctx) },
  { match: (c) => SHELL_INTERPRETERS.has(c), evaluate: () => true },
  { match: (c) => SCRIPT_INTERPRETERS.has(c), evaluate: () => true },
];

/**
 * Check whether a given command + surrounding context is a write operation.
 * Consolidates the duplicated logic from isWrapperRunningWrite and isFindExecWrite.
 *
 * @param command  The command name to check (lowercase).
 * @param context  The full segment text after the command (for flag-dependent checks like sed -i).
 */
export function isWriteOperation(command: string, context: string): boolean {
  for (const handler of WRITE_HANDLERS) {
    if (handler.match(command)) return handler.evaluate(command, context);
  }
  return false;
}
