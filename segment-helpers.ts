import path from "node:path";

// ── Segment helpers (pure string utilities) ──

function stripQuotedStrings(cmd: string): string {
  let s = cmd.replace(/"(?:[^"\\]|\\.)*"/g, (match) => {
    if (/\$\s*\(/.test(match) || /`/.test(match)) return "__CMD_SUBST__";
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

/**
 * Check if the first token is a relative path (./foo, ../foo).
 * Absolute paths (/bin/cat, /usr/bin/find) are allowed through.
 */
export function isFirstTokenRelativePath(segment: string): boolean {
  const token = segment.trim().split(/\s+/)[0];
  return /^\.\/?|^\.\./.test(token);
}

/** Split a segment into pipeline parts (on |). */
export function splitPipeline(segment: string): string[] {
  return segment.split("|").map(s => s.trim()).filter(Boolean);
}

/**
 * Extract a command signature, stripping redirects and quotes.
 * For pipelines, uses the first command's signature.
 */
export function getCommandSignature(segment: string): string {
  const firstCmd = segment.split("|")[0].trim();
  const cleaned = firstCmd
    .replace(/&?[0-9]*>>?\s*\S+/g, "")
    .replace(/<\s*\S+/g, "")
    .trim();
  const tokens = stripQuotedStrings(cleaned).split(/\s+/);
  const cmd = tokens[0].toLowerCase();
  const flags = tokens.slice(1).filter(t => t.startsWith("-")).sort();
  return flags.length === 0 ? cmd : `${cmd} ${flags.join(" ")}`;
}
