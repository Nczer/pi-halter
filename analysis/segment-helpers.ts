import path from "node:path";
import { isFirstTokenRelativePath } from "./path-analysis";
import { isWriteOperation, PACKAGE_MANAGERS } from "../config";

// ── Segment helpers (pure string utilities) ──

const CMD_SUBST_MARKER = "__CMD_SUBST__";

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

/** Strip /dev/null, /dev/stderr redirects and fd-to-fd redirects from a command string. */
export function stripNullRedirects(cmd: string): string {
  return cmd
    .replace(/[0-9]*&?>+\s*(?:\/dev\/(?:null|stderr))\b/g, "")
    .replace(/[0-9]*>&[0-9]+/g, "");
}

/**
 * Extract a command signature, stripping redirects and quotes.
 * For pipelines, uses the first command's signature.
 * For package managers, includes the subcommand for granular allow control.
 */
/**
 * Check if a command string contains a write redirect (> or >> to a file).
 * Ignores /dev/null, /dev/stderr, fd-to-fd redirects, and test/[ conditionals.
 */
export function hasWriteRedirect(cmd: string): boolean {
  const trimmed = cmd.trim();
  if (/^[0-9]*&?>+/.test(trimmed)) {
    if (!stripNullRedirects(trimmed).trim()) return false;
  }
  const stripped = stripNullRedirects(cmd);
  if (/>+\s*\S/.test(stripped)) {
    const inTest = /\[\s.*\]/.test(stripped) || /test\s/.test(stripped);
    if (!inTest) return true;
  }
  return false;
}

/**
 * Determine if a wrapper argument should be skipped (is a flag or wrapper-specific option).
 */
export function skipWrapperArg(wrapper: string, arg: string): boolean {
  if (arg.startsWith("-")) return true;
  if (wrapper === "env" && /=/.test(arg) && !arg.startsWith("/")) return true;
  if (wrapper === "timeout" && /^\d+(\.\d+)?(?:[smhd])?$/.test(arg)) return true;
  if (wrapper === "nice" && /^\d+$/.test(arg)) return true;
  if (wrapper === "ionice" && /^\d+$/.test(arg)) return true;
  return false;
}

/**
 * Check if a wrapper command (xargs, timeout, nice, etc.) is running a write operation.
 * @param includeRelativePath - If true, also returns true for relative path targets (./foo).
 */
export function isWrapperRunningWrite(segment: string, includeRelativePath = true): boolean {
  const args = segment.trim().split(/\s+/);
  const firstWord = args[0].toLowerCase();
  for (let i = 1; i < args.length; i++) {
    const arg = args[i];
    if (skipWrapperArg(firstWord, arg)) continue;
    const wrappedCmd = arg.toLowerCase();
    if (includeRelativePath && isFirstTokenRelativePath(arg)) return true;
    if (isWriteOperation(wrappedCmd, segment)) return true;
    continue;
  }
  return false;
}

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
