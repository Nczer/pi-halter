import path from "node:path";
import os from "node:os";

/** Expand tilde (~) to home directory. */
export function expandTilde(p: string): string {
  if (p.startsWith("~/")) return path.join(os.homedir(), p.slice(2));
  if (p === "~") return os.homedir();
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
