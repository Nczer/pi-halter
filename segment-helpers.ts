import path from "node:path";

// ── Segment helpers (pure string utilities) ──

export const CMD_SUBST_MARKER = "__CMD_SUBST__";

/** Check if a string contains command substitution markers from stripQuotedStrings. */
export function containsCommandSubstitution(s: string): boolean {
  return s.includes(CMD_SUBST_MARKER);
}

function stripQuotedStrings(cmd: string): string {
  let s = cmd.replace(/"(?:[^"\\]|\\.)*"/g, (match) => {
    if (/\$\s*\(/.test(match) || /`/.test(match)) return CMD_SUBST_MARKER;
    return "__STR__";
  });
  s = s.replace(/'[^']*'/g, "__STR__");
  s = s.replace(/\$'[^']*'/g, "__STR__");
  s = s.replace(/\s*#.*$/gm, "");
  return s;
}

export function getFirstWord(segment: string): string {
  const word = segment.trim().split(/\s+/)[0].toLowerCase();
  return path.basename(word);
}

/** Split a segment into pipeline parts (on |). */
export function splitPipeline(segment: string): string[] {
  return segment.split("|").map(s => s.trim()).filter(Boolean);
}

/** Package manager commands that use subcommands (npm install, cargo check, etc.). */
export const PACKAGE_MANAGERS = new Set(["npm", "yarn", "pnpm", "cargo", "pip", "pip3", "uv", "go", "bun"]);

/**
 * Extract a command signature, stripping redirects and quotes.
 * For pipelines, uses the first command's signature.
 * For package managers, includes the subcommand for granular allow control.
 */
export function getCommandSignature(segment: string): string {
  const firstCmd = segment.split("|")[0].trim();
  const cleaned = firstCmd
    .replace(/&?[0-9]*>>?\s*\S+/g, "")
    .replace(/<\s*\S+/g, "")
    .trim();
  const tokens = stripQuotedStrings(cleaned).split(/\s+/);
  const cmd = tokens[0].toLowerCase();

  // Package managers: include subcommand for granular control
  // npm test → "npm test", npm install → "npm install"
  // npm -v → "npm" (flag only, no subcommand)
  const cmdBase = path.basename(cmd);
  if (PACKAGE_MANAGERS.has(cmdBase)) {
    const subIdx = tokens.findIndex((t, i) => i > 0 && !t.startsWith("-"));
    if (subIdx >= 0) {
      const sub = tokens[subIdx];
      return `${cmdBase} ${sub}`;
    }
    return cmdBase; // e.g. "npm" with only flags
  }

  const flags = tokens.slice(1).filter(t => t.startsWith("-")).sort();
  return flags.length === 0 ? cmd : `${cmd} ${flags.join(" ")}`;
}
