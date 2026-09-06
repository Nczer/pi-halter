import path from "node:path";
import os from "node:os";

/** Current username for `~user` expansion (os.userInfo can throw in exotic
 *  environments — null falls back to /home/<user> for every user). */
let currentUsername: string | null = null;
try {
  currentUsername = os.userInfo().username;
} catch {
  currentUsername = null;
}

/** `~user` / `~user/…` — a word-initial tilde with a username (the shell
 *  expands these via the passwd database; `~/…` and bare `~` are handled
 *  before this). */
const TILDE_USER_RE = /^~([A-Za-z_][A-Za-z0-9._-]*)(?:\/(.*))?$/;

/**
 * Expand tilde (~) to home directory. `~user` expands to that user's home:
 *  the current user is well-defined (os.homedir), any other user is modeled
 *  as the standard /home/<user> — a home stored elsewhere still lands
 *  outside the session base and forces approval (conservative, never
 *  under-scoped).
 */
export function expandTilde(p: string): string {
  if (p.startsWith("~/")) return path.join(os.homedir(), p.slice(2));
  if (p === "~") return os.homedir();
  const m = TILDE_USER_RE.exec(p);
  if (m) {
    const user = m[1];
    const home =
      currentUsername !== null && user === currentUsername ? os.homedir() : path.join("/home", user);
    return m[2] ? path.join(home, m[2]) : home;
  }
  return p;
}

/**
 * Sentinel dir for paths whose runtime location is statically unbound (an
 * opaque expansion the analysis could not bind). It sits outside every real
 * dir, so the outside-cwd check can never drop a path carrying it.
 */
export const OPAQUE_VAR_DIR = "<unresolved-var>";

/**
 * Display form of an unresolved token for prompts/reasons: first line,
 * truncated to `max` chars with an ellipsis. Tokens can be whole glob
 * expansions of a long base — one short line is all the operator needs to
 * recognize the reference (the full token stays in the unresolved log).
 */
export function shortenToken(token: string, max = 60): string {
  const line = token.split("\n")[0].trim();
  if (line.length <= max) return line;
  return line.slice(0, max - 1) + "…";
}
