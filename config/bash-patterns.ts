import path from "node:path";

// ── Bash command patterns ──

/** Commands always allowed when simple (no subshells, redirects, or dangerous flags). */
const allowedBashPatternStrings: string[] = [
  // Inspection / read-only
  "find", "grep", "ls", "cat", "head", "tail", "wc", "file",
  "sort", "uniq", "cut", "tr", "diff", "rg", "fd",
  "tac", "rev", "nl", "fold", "expand", "unexpand", "fmt",
  "join", "comm", "paste", "column", "seq",
  // Text transform (safe stdout — guarded by dangerous flag checks)
  "sed", "perl",
  // Hashing / binary inspection
  "md5sum", "sha1sum", "sha256sum", "sha512sum", "cksum",
  "hexdump", "od", "strings",
  // Strings / formatting
  "echo", "printf", "basename", "dirname", "realpath", "readlink",
  "test", "true", "false",
  // System info (read-only, no file side effects)
  "pwd", "cd", "date", "whoami", "id", "uname", "hostname",
  "groups", "printenv", "uptime", "tty", "tput",
  // Disk / process inspection (read-only)
  "df", "du", "free", "ps", "pgrep", "pidof",
  // Command lookup
  "which", "command", "type", "hash", "whence",
  // Git (guarded by dangerous flag checks)
  "git",
  // Tmux (guarded by dangerous subcommand checks)
  "tmux",
  // Safe file/dir creation (no overwriting — guarded by no-redirect check)
  "mkdir", "touch", "mktemp",
  // Calculator
  "bc", "expr", "factor", "yes",
  // Wrapper commands (guarded by isWrapperRunningWrite check)
  "xargs", "watch", "timeout", "parallel", "nice",
];

/** O(1) first-word allowlist — pre-built from pattern strings. */
const allowedBashCommands = new Set(allowedBashPatternStrings);

/**
 * Subset of allowed commands that are unconditionally safe — no flag-dependent
 * danger behavior. Used for the fast pre-check that skips tree-sitter parsing.
 * Commands like sed (-i), git (push --force), find (-delete), etc. are excluded.
 */
export const unconditionallySafeCommands = new Set([
  // Inspection / read-only
  "ls", "cat", "head", "tail", "wc", "file",
  "sort", "uniq", "cut", "tr", "diff",
  "tac", "rev", "nl", "fold", "expand", "unexpand", "fmt",
  "join", "comm", "paste", "column", "seq",
  // Hashing / binary inspection
  "md5sum", "sha1sum", "sha256sum", "sha512sum", "cksum",
  "hexdump", "od", "strings",
  // Strings / formatting
  "echo", "printf", "basename", "dirname", "realpath", "readlink",
  "test", "true", "false",
  // System info (read-only, no file side effects)
  "pwd", "cd", "date", "whoami", "id", "uname", "hostname",
  "groups", "printenv", "uptime", "tty", "tput",
  // Disk / process inspection (read-only)
  "df", "du", "free", "ps", "pgrep", "pidof",
  // Command lookup
  "which", "command", "type", "hash", "whence",
  // Calculator
  "bc", "expr", "factor", "yes",
]);

/** Commands whose arguments include file/dir paths. */
export const pathAwareCommands = new Set([
  // Inspection / read
  "ls", "cat", "head", "tail", "wc", "file", "stat", "touch",
  "tac", "rev", "nl", "fold", "expand", "unexpand", "fmt",
  "join", "comm", "paste", "column", "split", "shuf",
  "rg", "fd",
  // Hashing / binary
  "md5sum", "sha1sum", "sha256sum", "sha512sum", "cksum",
  "xxd", "hexdump", "od", "strings",
  // File/dir ops
  "mkdir", "rm", "cp", "mv", "chmod", "chown", "mktemp",
  "find", "grep", "diff", "patch",
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
export const dangerousFindFlags = /-(?:delete|empty|truncate)\b/;

/** Flags that make `sed` dangerous (in-place editing). */
export const dangerousSedFlags = /-\bi(?:\.\S*)?(?:\s|$)|--in-place(?:\b|\s)/;

/** Flags that make `perl` dangerous (in-place editing via -i). */
export const dangerousPerlFlags = /-\bi(?:\.\S*)?(?:\s|$)|-pi\b|-p.*-i\b/;

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

/** Package manager commands that use subcommands (npm install, cargo check, etc.). */
export const PACKAGE_MANAGERS = new Set(["npm", "yarn", "pnpm", "npx", "cargo", "pip", "pip3", "uv", "go", "bun"]);

/** Pre-compiled regex for tee write check. */
const TEE_WRITE_RE = /\btee\b.*\S/;

/** Commands that always perform write operations (unconditional — no flag-dependent behavior). */
const ALWAYS_WRITE = new Set([
  "rm", "rmdir", "unlink", "mv", "cp", "chmod", "chown",
  "touch", "mkdir", "dd", "truncate", "patch", "install", "ln",
]);

/** Archive/package-manager commands that always write. */
const ALWAYS_WRITE_ARCHIVE_PKG = new Set([
  "tar", "zip", "unzip", "gzip", "gunzip",
  "pip", "npm", "yarn", "cargo", "go", "uv",
]);

// ── Write operation handlers ──

/** Command → write check (match, evaluate). */
const WRITE_HANDLERS: Array<{ match: (cmd: string) => boolean; evaluate: (cmd: string, context: string) => boolean }> = [
  { match: (c) => ALWAYS_WRITE.has(c), evaluate: () => true },
  { match: (c) => ALWAYS_WRITE_ARCHIVE_PKG.has(c), evaluate: () => true },
  { match: (c) => c === "sed", evaluate: (_, ctx) => dangerousSedFlags.test(ctx) },
  { match: (c) => c === "perl", evaluate: (_, ctx) => dangerousPerlFlags.test(ctx) },
  { match: (c) => c === "tee", evaluate: (_, ctx) => TEE_WRITE_RE.test(ctx) },
  { match: (c) => SHELL_INTERPRETERS.has(c), evaluate: () => true },
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
