import path from "node:path";
import os from "node:os";

/** Directories whose scripts are auto-trusted (interpreter + script in this dir bypasses dangerous-pattern check). */
const trustedScriptDirs: string[] = [
  path.join(os.homedir(), ".pi", "agent", "skills"),
];

function expandTilde(p: string): string {
  if (p.startsWith("~/")) return path.join(os.homedir(), p.slice(2));
  if (p === "~") return os.homedir();
  return p;
}

/** Check if a resolved absolute path is inside any trusted script directory. */
export function isTrustedScriptPath(resolvedPath: string): boolean {
  return trustedScriptDirs.some(dir => {
    const rel = path.relative(dir, resolvedPath);
    return rel !== "" && !rel.startsWith("..");
  });
}

/**
 * Check if a command segment is an interpreter (python, node, etc.) running
 * a script file from a trusted directory.
 */
export function isTrustedScriptCommand(segment: string, cwd: string): boolean {
  const tokens = segment.trim().split(/\s+/);
  if (tokens.length < 2) return false;

  const cmd = tokens[0].toLowerCase();
  if (!/\b(python|node|ruby|php|lua|perl|deno|bun|jruby|pypy|graalvm|uv)\b/i.test(cmd)) return false;

  // Find the script file argument (first non-flag token that looks like a file)
  for (let i = 1; i < tokens.length; i++) {
    const token = tokens[i];
    if (token.startsWith("-")) continue; // skip flags like -c, -m, -u, etc.
    if (/\.\w{2,4}$/.test(token)) {
      const resolved = path.resolve(cwd, expandTilde(token));

      // Trusted static directory only
      if (isTrustedScriptPath(resolved)) return true;
      break;
    }
  }
  return false;
}
