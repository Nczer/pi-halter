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

/** File/directory names that are always denied (credentials, secrets, caches). */
export const deniedPaths: string[] = [
  ".env", ".env.local",
  "node_modules", ".npm", ".pnpm-store", ".yarn",
  ".ssh", ".gnupg", ".gpg",
  ".aws", ".gcloud", ".azure",
  ".git-credentials", ".hg/hgrc",
  ".netrc", ".npmrc", ".pypirc", ".docker/config.json",
  ".vault", ".secret", ".secrets",
];
