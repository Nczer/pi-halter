import path from "node:path";
import os from "node:os";

// ── Path allow/deny rules ──

/** Directories always allowed for read access. */
export const allowedReadPaths: string[] = [
  "/opt/pi-coding-agent",
  path.join(os.homedir(), ".pi"),
  path.join(os.homedir(), ".local/lib/node_modules/@earendil-works/pi-coding-agent"),
  os.tmpdir(),
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
