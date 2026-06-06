import path from "node:path";

// ── Bash command patterns ──

/** Commands always allowed when simple (no subshells, redirects, or dangerous flags). */
export const allowedBashPatterns: RegExp[] = [
  // Inspection / read-only
  /^find\b/, /^grep\b/, /^ls\b/, /^cat\b/, /^head\b/, /^tail\b/, /^wc\b/, /^file\b/,
  /^sort\b/, /^uniq\b/, /^cut\b/, /^tr\b/, /^diff\b/, /^rg\b/, /^fd\b/,
  /^tac\b/, /^rev\b/, /^nl\b/, /^fold\b/, /^expand\b/, /^unexpand\b/, /^fmt\b/,
  /^join\b/, /^comm\b/, /^paste\b/, /^column\b/, /^seq\b/,
  // Text transform (safe stdout — guarded by dangerous flag checks)
  /^sed\b/, /^perl\b/,
  // Hashing / binary inspection
  /^md5sum\b/, /^sha1sum\b/, /^sha256sum\b/, /^sha512sum\b/, /^cksum\b/,
  /^hexdump\b/, /^od\b/, /^strings\b/,
  // Strings / formatting
  /^echo\b/, /^printf\b/, /^basename\b/, /^dirname\b/, /^realpath\b/, /^readlink\b/,
  /^test\b/, /^true\b/, /^false\b/,
  // System info (read-only, no file side effects)
  /^pwd\b/, /^cd\b/, /^date\b/, /^whoami\b/, /^id\b/, /^uname\b/, /^hostname\b/,
  /^groups\b/, /^printenv\b/, /^uptime\b/, /^tty\b/, /^tput\b/,
  // Disk / process inspection (read-only)
  /^df\b/, /^du\b/, /^free\b/, /^ps\b/, /^pgrep\b/, /^pidof\b/,
  // Command lookup
  /^which\b/, /^command\b/, /^type\b/, /^hash\b/, /^whence\b/,
  // Git (guarded by dangerous flag checks)
  /^git\b/,
  // Safe file/dir creation (no overwriting — guarded by no-redirect check)
  /^mkdir\b/, /^touch\b/, /^mktemp\b/,
  // Calculator
  /^bc\b/, /^expr\b/, /^factor\b/, /^yes\b/,
  // Wrapper commands (guarded by isWrapperRunningWrite check)
  /^xargs\b/, /^watch\b/, /^timeout\b/, /^parallel\b/, /^nice\b/,
];

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
export const allowedBashSubcommands = new Set([
  "npm ls", "npm view", "npm info",
  "yarn ls", "yarn info",
  "pnpm ls",
  "tsc",
  "cargo check", "cargo clippy", "cargo doc",
]);

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

/** Commands that write to files when given certain flags. */
export const writeCapableCommands = new Set([
  // In-place editors
  "sed", "perl", "awk", "python", "python3", "node", "ruby", "php",
  // File modification
  "rm", "rmdir", "unlink", "mv", "cp", "chmod", "chown",
  "touch", "mkdir", "dd", "truncate", "patch", "install", "ln",
  // Archives (can write)
  "tar", "zip", "unzip", "gzip", "gunzip",
  // File writing
  "tee",
  // Package managers
  "pip", "npm", "yarn", "cargo", "go",
  "uv",
]);

/** Shell interpreters used by find -exec and similar constructs. */
export const SHELL_INTERPRETERS = new Set(["bash", "sh", "zsh", "fish", "dash", "ksh", "csh", "tcsh"]);

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

/**
 * Check whether a given command + surrounding context is a write operation.
 * Consolidates the duplicated logic from isWrapperRunningWrite and isFindExecWrite.
 *
 * @param command  The command name to check (lowercase).
 * @param context  The full segment text after the command (for flag-dependent checks like sed -i).
 */
export function isWriteOperation(command: string, context: string): boolean {
  if (ALWAYS_WRITE.has(command)) return true;
  if (ALWAYS_WRITE_ARCHIVE_PKG.has(command)) return true;

  if (command === "sed") return dangerousSedFlags.test(context);
  if (command === "perl") return dangerousPerlFlags.test(context);
  if (command === "tee") return /\btee\b.*\S/.test(context);

  // Shell interpreters running via exec are inherently write-capable
  if (SHELL_INTERPRETERS.has(command)) return true;

  return false;
}
