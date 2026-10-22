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

/**
 * Operator scope grants (settings key `halter.readDirs`, A of the 3.42 read-bar
 * work) appended to the READ bar once at activation (`index.ts`). The bar is
 * shared (gate/dspa-gate.ts `makeManualBar` + `isAllowedReadPath`), so one
 * entry widens manual AND dspa: a command that only READS inside such a dir
 * auto-allows in manual and needs no judge call in dspa.
 *
 * Deliberately narrow:
 *  • read half only — a durable WRITE grant in a JSON file is G3's bad click
 *    with no human in the loop; writes keep converging through the prompt's
 *    Always option (D-g: bars are an explicit click);
 *  • never `/` (same rule as `RuleGenerator.withoutRoot`), and never a
 *    RELATIVE entry — the bar must not depend on which cwd the settings
 *    happened to be read from;
 *  • `~` expands, so `["~"]` is legal and means what it says: the whole home
 *    tree becomes read-quiet. Credential patterns (`.env`, `.aws/credentials`,
 *    `id_rsa`, …) and the warn paths still stop, and writes still stop.
 *  • an existing regular FILE is skipped — the bar matches DIRS
 *    (`isChildOf`), so a file entry would look like a grant and never act
 *    as one. A path that does not exist yet is accepted (a project dir
 *    created later must work);
 *  • applied at activation, so an edit to settings-ext.json takes effect next
 *    session (or `/reload`), not mid-session.
 *
 * @returns the dirs this call put in the bar (junk and already-granted
 *   entries are not reported) — what `index.ts` and the tests assert on.
 */
export function registerAllowedReadDirs(dirs: unknown): string[] {
  if (!Array.isArray(dirs)) return [];
  const accepted: string[] = [];
  for (const raw of dirs) {
    if (typeof raw !== "string") continue;
    const trimmed = raw.trim();
    if (!trimmed) continue;
    const written = expandHome(trimmed);
    if (!path.isAbsolute(written) || written === "/") continue;
    const abs = path.resolve(written);
    let isFile = false;
    try {
      isFile = fs.statSync(abs).isFile();
    } catch {
      /* not there yet — a valid grant for a dir to be created */
    }
    if (isFile) continue;
    const spellings = [abs, real(abs)];
    let added = false;
    for (const s of spellings) {
      if (s === "/" || allowedReadPaths.includes(s)) continue;
      allowedReadPaths.push(s);
      added = true;
    }
    // Only what THIS call put in the bar is reported — a /reload re-registering
    // the same list must not read as new scope.
    if (added) accepted.push(abs);
  }
  return accepted;
}

/** `~` and `~/…` → the home dir (settings entries are hand-written). */
function expandHome(p: string): string {
  if (p === "~") return os.homedir();
  if (p.startsWith("~/")) return path.join(os.homedir(), p.slice(2));
  return p;
}

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
