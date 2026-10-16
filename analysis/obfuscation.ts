import { stripQuotedStrings } from "./segment-helpers";

// ── Pre-compiled regexes for obfuscation detection ──

const OBfus_VAR_INDIRECTION_RE = /\$\{!/;
const OBfus_VAR_HOLDING_CMD_RE = /(?:^|;|\|\||&&)\s*\$[A-Z_][A-Z0-9_]*\s+\w/;
/**
 * Character concatenation: letter + quote boundary + letter (no space after quote).
 * e.g. ec"ho, ca't — used to evade command-name pattern matching.
 *
 * Evaluated at real shell quote transitions (a `"` inside `'foo"bar'` or a `'`
 * inside `"foo'bar"` is literal string content, not shell concatenation).
 * Single-quote transitions also exclude English contractions ('s, 't, 'd, 'm,
 * 've, 're, 'll followed by non-letter) to avoid false positives on
 * beginner's, don't, it'd, we've, you're, it'll, etc.
 */
const CONTRACTION_TAIL_RE = /^(?:[stmd]|ve|re|ll)(?:[^a-z]|$)/;
const OBfus_BASE64_RE = /\bbase64\s+(?:-[a-z]*d\b|--decode\b)/i;
const OBfus_PRINTF_CMD_RE = /\bprintf\b/i;
const OBfus_PRINTF_HEX_RE = /printf\s+.*\\x/i;
const OBfus_XARGS_RM_RE = /\bxargs\s.*\brm\b/;
const OBfus_XARGS_SH_RE = /\bxargs\s+sh\s+-c\b/;
const OBfus_XARGS_BASH_RE = /\bxargs\s+bash\s+-c\b/;
const OBfus_ALIAS_RE = /\b(alias|declare|typeset)\s+\w+=\s*['"]?(rm|sudo|curl|wget|ssh)\b/i;

/** True when `cmd` contains unquoted letter-quote-letter concatenation (`ec"ho`, `ca't`). */
function hasQuoteConcatenation(cmd: string): boolean {
  let inSingle = false;
  let inDouble = false;
  for (let i = 0; i < cmd.length; i++) {
    const c = cmd[i];
    if (c === "\\" && !inSingle && i + 1 < cmd.length) {
      i++;
      continue;
    }
    const prev = i > 0 ? cmd[i - 1] : "";
    const next = i + 1 < cmd.length ? cmd[i + 1] : "";
    const adjLetters = /[a-z]/.test(prev) && /[a-z]/.test(next);
    if (c === '"' && !inSingle) {
      if (adjLetters) return true;
      inDouble = !inDouble;
    } else if (c === "'" && !inDouble) {
      if (adjLetters && !CONTRACTION_TAIL_RE.test(cmd.slice(i + 1))) return true;
      inSingle = !inSingle;
    }
  }
  return false;
}

/**
 * Detect obfuscation techniques in a command string.
 * Used by segment-analysis.ts.
 */
export function detectObfuscation(cmd: string): { detected: boolean; techniques: string[] } {
  const techniques: string[] = [];
  const stripped = stripQuotedStrings(cmd);
  if (OBfus_VAR_INDIRECTION_RE.test(cmd)) techniques.push("variable indirection (obfuscation)");
  if (OBfus_VAR_HOLDING_CMD_RE.test( stripped )) techniques.push("variable holding command (obfuscation)");
  if (hasQuoteConcatenation(cmd)) techniques.push("character concatenation (obfuscation)");
  if (OBfus_BASE64_RE.test(stripped) || (OBfus_PRINTF_CMD_RE.test(stripped) && OBfus_PRINTF_HEX_RE.test(cmd))) {
    techniques.push("encoding/decoding (obfuscation)");
  }
  if (OBfus_XARGS_RM_RE.test(stripped)) techniques.push("indirect command via xargs (obfuscation)");
  if (OBfus_XARGS_SH_RE.test(stripped) || OBfus_XARGS_BASH_RE.test(stripped)) {
    techniques.push("xargs piping to shell interpreter (obfuscation)");
  }
  if (OBfus_ALIAS_RE.test(stripped) || (/\b(?:alias|declare|typeset)\b/i.test(stripped) && OBfus_ALIAS_RE.test(cmd))) {
    techniques.push("alias/function obfuscation");
  }
  return { detected: techniques.length > 0, techniques };
}
