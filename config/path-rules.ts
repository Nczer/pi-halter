import path from "node:path";
import os from "node:os";
import fs from "node:fs";

// ── Path allow/deny rules ──

/** Resolve a path's real path (follows symlinks), falling back to the original. */
function real(p: string): string {
  try { return fs.realpathSync(p); } catch { return p; }
}

const tmpdir = os.tmpdir();
const tmpdirReal = real(tmpdir); // macOS: /var/folders/.../T → /private/var/folders/.../T

/** Directories always allowed for read access. */
export const allowedReadPaths: string[] = [
  "/opt/pi-coding-agent",
  path.join(os.homedir(), ".pi"),
  path.join(os.homedir(), ".local/lib/node_modules/@earendil-works/pi-coding-agent"),
  tmpdir,        // os.tmpdir() e.g. /var/folders/.../T
  tmpdirReal,    // macOS: realpath of tmpdir → /private/var/folders/.../T
  "/tmp",        // skill scripts write to /tmp
  "/private/tmp", // macOS: realpathSync resolves /tmp → /private/tmp
];

/** Directories always allowed for write/edit access. */
export const allowedWritePaths: string[] = [
  tmpdir,        // os.tmpdir()
  tmpdirReal,    // macOS: realpath of tmpdir
  "/tmp",        // macOS: same reason as above
  "/private/tmp", // macOS: realpathSync resolves /tmp → /private/tmp
];

/**
 * File/directory names that may contain credentials — always a prompt with a
 * very-high-risk warning, never silent, and never a hard block.
 *
 * 3.26.0: the old `deniedPaths` hard-block tier was removed and its names
 * merged here. The block tier fired on the command TEXT (credential name
 * roots, glob-decoded names), so ordinary shell work — a `sed 's|/…|/…|'`
 * program body, `echo .*`, searching this repo for the word `.ssh` — could
 * be refused outright with no way to proceed. Deny-vs-warn never changed
 * *auto-allow* behaviour (every mode stops a credential path at the manual
 * bar, see gate/dspa-gate.ts), so the tier only ever converted prompts into
 * refusals — and its false positives were refusals of benign commands.
 */
export const warnPaths: string[] = [
  // Credential directories (formerly the hard-denied tier).
  ".ssh", ".gnupg", ".gpg",
  ".vault", ".secret", ".secrets",
  ".env", ".aws", ".gcloud", ".azure",
  ".git-credentials", ".hg/hgrc",
  ".netrc", ".npmrc", ".pypirc", ".docker/config.json",
  // Standalone keyfile basenames (not covered by dir-name rules like .ssh).
  ".envrc",
  "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa",
  // Glob patterns: *.pem matches any basename ending in .pem (suffix match).
  "*.pem",
];
