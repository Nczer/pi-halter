import path from "node:path";
import os from "node:os";

/** Expand tilde (~) to home directory. */
export function expandTilde(p: string): string {
  if (p.startsWith("~/")) return path.join(os.homedir(), p.slice(2));
  if (p === "~") return os.homedir();
  return p;
}
