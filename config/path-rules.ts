import path from "node:path";
import os from "node:os";

// ── Path allow/deny rules ──

/** Directories always allowed for read access. */
export const allowedReadPaths: string[] = [
  "/opt/pi-coding-agent",
  path.join(os.homedir(), ".pi"),
  path.join(os.homedir(), ".local/lib/node_modules/@earendil-works/pi-coding-agent"),
  os.tmpdir(),
  "/tmp", // macOS: os.tmpdir() returns /var/folders/.../T, but skill scripts write to /tmp → /private/tmp
];

/** Directories always allowed for write/edit access. */
export const allowedWritePaths: string[] = [
  os.tmpdir(),
  "/tmp", // macOS: same reason as above
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
