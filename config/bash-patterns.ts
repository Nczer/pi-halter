// ── Bash command patterns ──

/** Commands always allowed when simple (no subshells, redirects, or dangerous flags). */
export const allowedBashPatterns: RegExp[] = [
  // Inspection / read-only
  /^find\b/, /^grep\b/, /^ls\b/, /^cat\b/, /^head\b/, /^tail\b/, /^wc\b/, /^file\b/,
  /^sort\b/, /^uniq\b/, /^cut\b/, /^tr\b/, /^diff\b/,
  /^tac\b/, /^rev\b/, /^nl\b/, /^fold\b/, /^expand\b/, /^unexpand\b/, /^fmt\b/,
  /^join\b/, /^comm\b/, /^paste\b/, /^column\b/, /^seq\b/,
  // Hashing / binary inspection
  /^md5sum\b/, /^sha1sum\b/, /^sha256sum\b/, /^sha512sum\b/, /^cksum\b/,
  /^hexdump\b/, /^od\b/, /^strings\b/,
  // Strings / formatting
  /^echo\b/, /^printf\b/, /^basename\b/, /^dirname\b/, /^realpath\b/, /^readlink\b/,
  /^test\b/, /^true\b/, /^false\b/,
  // System info (read-only, no file side effects)
  /^pwd\b/, /^date\b/, /^whoami\b/, /^id\b/, /^uname\b/, /^hostname\b/,
  /^groups\b/, /^printenv\b/, /^uptime\b/, /^tty\b/, /^tput\b/,
  // Disk / process inspection (read-only)
  /^df\b/, /^du\b/, /^free\b/, /^ps\b/, /^pgrep\b/, /^pidof\b/,
  // Command lookup
  /^which\b/, /^command\b/, /^type\b/, /^hash\b/, /^whence\b/,
  // Safe file/dir creation (no overwriting — guarded by no-redirect check)
  /^mkdir\b/, /^touch\b/, /^mktemp\b/,
  // Calculator
  /^bc\b/, /^expr\b/, /^factor\b/, /^yes\b/,
];

/** Commands whose arguments include file/dir paths. */
export const pathAwareCommands = new Set([
  // Inspection / read
  "ls", "cat", "head", "tail", "wc", "file", "stat", "touch",
  "tac", "rev", "nl", "fold", "expand", "unexpand", "fmt",
  "join", "comm", "paste", "column", "split", "shuf",
  // Hashing / binary
  "md5sum", "sha1sum", "sha256sum", "sha512sum", "cksum",
  "xxd", "hexdump", "od", "strings",
  // File/dir ops
  "mkdir", "rm", "cp", "mv", "chmod", "chown", "mktemp",
  "find", "grep", "diff", "patch",
  "cd", "pushd", "popd",
  "tar", "zip", "unzip", "gzip", "gunzip",
  "python", "python3", "node", "ruby", "perl", "php",
  "sed", "awk", "sort", "uniq", "cut", "tr", "tee",
  "xargs", "watch", "timeout",
  "source", ".",
  "pip", "npm", "yarn", "cargo", "go",
]);

/** Flags on `find` that make it dangerous. */
export const dangerousFindFlags = /\b-(?:exec|execdir|okexec|delete|empty|truncate)\b/;
