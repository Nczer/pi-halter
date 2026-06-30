// ── Pre-compiled regexes for obfuscation detection ──

const OBfus_VAR_INDIRECTION_RE = /\$\{!/;
const OBfus_VAR_HOLDING_CMD_RE = /(?:^|;|\|\||&&)\s*\$[A-Z_][A-Z0-9_]*\s+\w/;
/**
 * Character concatenation: letter + quote + letter (no space after quote).
 * e.g. ec"ho, ca't — used to evade command-name pattern matching.
 *
 * Double-quote: require letter immediately after quote (no space).
 *   Rejects: echo "hello" (space after ")
 *   Catches: ec"ho (no space)
 *
 * Single-quote: same as above, but also exclude English contractions
 *   ('s, 't, 'd, 'm followed by non-letter) to avoid false positives
 *   on beginner's, don't, it'd, etc.
 */
const OBfus_CHAR_CONCAT_DQ_RE = /[a-z]"[a-z]/;
const OBfus_CHAR_CONCAT_SQ_RE = /[a-z]'(?![stmd](?:[^a-z]|$))[a-z]/;
const OBfus_BASE64_RE = /base64\s+[-d]/i;
const OBfus_PRINTF_HEX_RE = /printf\s+.*\\x/i;
const OBfus_XARGS_RM_RE = /xargs\s.*\brm\b/;
const OBfus_XARGS_SH_RE = /xargs\s+sh\s+-c\b/;
const OBfus_XARGS_BASH_RE = /xargs\s+bash\s+-c\b/;
const OBfus_ALIAS_RE = /\b(alias|declare|typeset)\s+\w+=\s*(rm|sudo|curl|wget|ssh)\b/i;

/**
 * Detect obfuscation techniques in a command string.
 * Used by segment-analysis.ts and tmux-helpers.ts.
 */
export function detectObfuscation(cmd: string): { detected: boolean; techniques: string[] } {
  const techniques: string[] = [];
  if (OBfus_VAR_INDIRECTION_RE.test(cmd)) techniques.push("variable indirection (obfuscation)");
  if (OBfus_VAR_HOLDING_CMD_RE.test(cmd)) techniques.push("variable holding command (obfuscation)");
  if (OBfus_CHAR_CONCAT_DQ_RE.test(cmd) || OBfus_CHAR_CONCAT_SQ_RE.test(cmd)) techniques.push("character concatenation (obfuscation)");
  if (OBfus_BASE64_RE.test(cmd) || OBfus_PRINTF_HEX_RE.test(cmd)) techniques.push("encoding/decoding (obfuscation)");
  if (OBfus_XARGS_RM_RE.test(cmd)) techniques.push("indirect command via xargs (obfuscation)");
  if (OBfus_XARGS_SH_RE.test(cmd) || OBfus_XARGS_BASH_RE.test(cmd)) techniques.push("xargs piping to shell interpreter (obfuscation)");
  if (OBfus_ALIAS_RE.test(cmd)) techniques.push("alias/function obfuscation");
  return { detected: techniques.length > 0, techniques };
}
