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

/** File/directory names that are always denied — hard block, no prompt. */
export const deniedPaths: string[] = [
  ".ssh", ".gnupg", ".gpg",
  ".vault", ".secret", ".secrets",
];

/** File/directory names that may contain credentials — prompt with warning instead of hard block. */
export const warnPaths: string[] = [
  ".env", ".aws", ".gcloud", ".azure",
  ".git-credentials", ".hg/hgrc",
  ".netrc", ".npmrc", ".pypirc", ".docker/config.json",
];
