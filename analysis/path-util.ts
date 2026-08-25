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
