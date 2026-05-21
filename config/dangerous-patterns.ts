// ── Regex-based dangerous patterns (safety net alongside token analysis) ──
//
// Two categories:
//   dangerousCommandPatterns — tested against the first word (command name) of each segment.
//     These match commands that are inherently dangerous regardless of arguments.
//   dangerousContextPatterns — tested against the full segment text.
//     These need specific flags/args context (e.g. "apt install", "bash -c").
//
// The split prevents false positives when dangerous-sounding words appear in
// command arguments (e.g. "grep rm file.txt" should NOT match "rm").

/** Command-name patterns — tested against the first word only (avoids matching arguments). */
export const dangerousCommandPatterns: { pattern: RegExp; label: string }[] = [
  { pattern: /^rm$/, label: "rm (any file deletion)" },
  { pattern: /^sudo$/i, label: "sudo (privilege escalation)" },
  { pattern: /^(?:chmod|chown)$/i, label: "chmod/chown (permission change)" },
  { pattern: /^mkfs/i, label: "mkfs (filesystem creation)" },
  { pattern: /^mount$/i, label: "mount" },
  { pattern: /^python[\d.]*$/, label: "python (script execution)" },
  { pattern: /^uv$/, label: "uv (python package manager)" },
  { pattern: /^node$/, label: "node (script execution)" },
  { pattern: /^ruby$/, label: "ruby (script execution)" },
  { pattern: /^php$/, label: "php (script execution)" },
  { pattern: /^lua$/, label: "lua (script execution)" },
  { pattern: /^truncate$/i, label: "truncate (in-place size change, can erase contents)" },
  { pattern: /^eval$/i, label: "eval" },
  { pattern: /^(?:kill|pkill|killall)$/i, label: "kill" },
  { pattern: /^crontab$/i, label: "crontab" },
  { pattern: /^nohup$/i, label: "nohup" },
  { pattern: /^(?:screen|tmux)$/i, label: "screen/tmux" },
  { pattern: /^ssh$/i, label: "ssh" },
  { pattern: /^(?:scp|rsync)$/i, label: "scp/rsync" },
  { pattern: /^(?:curl|wget)$/i, label: "curl/wget (network access)" },
  { pattern: /^(?:rmdir|unlink|mv|cp)$/i, label: "rmdir/unlink/mv/cp (file modification)" },
  { pattern: /^(?:patch|install|ln)$/i, label: "patch/install/ln (file modification)" },
  { pattern: /^tee$/i, label: "tee (file writing)" },
  { pattern: /^(?:tar|zip|unzip|gzip|gunzip)$/i, label: "tar/zip/unzip/gzip/gunzip (archive operations)" },
  { pattern: /^(?:yarn|cargo|go)$/i, label: "yarn/cargo/go (package manager/build)" },
  { pattern: /^(?:shutdown|reboot)$/i, label: "shutdown/reboot (system power)" },
  { pattern: /^systemctl$/i, label: "systemctl (service management)" },
];

/** Context-dependent patterns — tested against the full segment text (need flags/args context). */
export const dangerousContextPatterns: { pattern: RegExp; label: string }[] = [
  { pattern: /\b(?:apt|yum|dnf|pip|npm|uv)\s+install\b/i, label: "package install" },
  { pattern: /\bdd\b\s+(?:\S+\s+)*?(?:if|of)=/i, label: "dd (raw disk access)" },
  { pattern: /\bbash\s+-[ic]\b/i, label: "bash interactive/command" },
  { pattern: /\bsource\b.*\.(?:env|bashrc|profile|secret|local)\b/i, label: "source (config loading)" },
  // Retained for risk analysis — already caught by specific checks in isSegmentUnsafe
  { pattern: /\bperl\s+-[a-z]*i\b/i, label: "perl -i (in-place file modification)" },
  { pattern: /\bsed\s+-i(?:\s|$|\.)/i, label: "sed -i (in-place file modification)" },
  { pattern: /\bsed\s+--in-place\b/i, label: "sed --in-place (in-place file modification)" },
  { pattern: /\bgit\s+push\s+.*--force\b/i, label: "git push --force" },
  { pattern: /\bgit\s+reset\s+.*--hard\b/i, label: "git reset --hard" },
  { pattern: /\bgit\s+clean\s+.*-[fdx]\b/i, label: "git clean (can delete untracked files)" },
];

/** Combined list for backward compatibility and simple iteration (both categories). */
export const dangerousPatterns: { pattern: RegExp; label: string }[] = [
  ...dangerousCommandPatterns,
  ...dangerousContextPatterns,
];
