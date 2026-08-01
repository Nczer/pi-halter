// ── Quote-aware tokenizer infrastructure ──
//
// Canonical implementation of quote-tracking used by splitPipeline, splitOnPipe,
// splitIntoSegments, tokenize, and tokenizeSegment. Eliminates 4+ duplicated
// state machines across the codebase.

// ── Shared quote-tracking state machine ──

/**
 * Process one character through the quote-tracking state machine.
 * Returns { append: string, advance: number } to tell the caller what to append
 * and how many characters to advance.
 */
function processChar(
  cmd: string,
  i: number,
  inSingleQuote: boolean,
  inDoubleQuote: boolean,
  inAnsi: boolean,
  enableAnsi: boolean,
  skipQuoteChars: boolean,
  handleEscapes: boolean,
): { append: string; advance: number; inSingleQuote: boolean; inDoubleQuote: boolean; inAnsi: boolean } {
  const ch = cmd[i];
  const next = i + 1 < cmd.length ? cmd[i + 1] : null;

  // Inside single quote
  if (inSingleQuote) {
    if (ch === "'") {
      return {
        append: skipQuoteChars ? "" : ch,
        advance: 1,
        inSingleQuote: false,
        inDoubleQuote: false,
        inAnsi: false,
      };
    }
    return { append: ch, advance: 1, inSingleQuote: true, inDoubleQuote: false, inAnsi: false };
  }

  // Inside double quote
  if (inDoubleQuote) {
    if (handleEscapes && ch === '\\' && next) {
      return { append: next, advance: 2, inSingleQuote: false, inDoubleQuote: true, inAnsi: false };
    }
    if (ch === '"' && (i === 0 || cmd[i - 1] !== "\\")) {
      return {
        append: skipQuoteChars ? "" : ch,
        advance: 1,
        inSingleQuote: false,
        inDoubleQuote: false,
        inAnsi: false,
      };
    }
    return { append: ch, advance: 1, inSingleQuote: false, inDoubleQuote: true, inAnsi: false };
  }

  // Inside ANSI-C string ($'...') — `'` closes, backslash escapes decode
  if (inAnsi) {
    if (ch === "'") {
      return {
        append: "",
        advance: 1,
        inSingleQuote: false,
        inDoubleQuote: false,
        inAnsi: false,
      };
    }
    if (ch === "\\" && next) {
      const end = ansiEscapeEnd(cmd, i);
      return {
        append: decodeAnsiCEscapes(cmd.slice(i, end)),
        advance: end - i,
        inSingleQuote: false,
        inDoubleQuote: false,
        inAnsi: true,
      };
    }
    return { append: ch, advance: 1, inSingleQuote: false, inDoubleQuote: false, inAnsi: true };
  }

  // Outside quotes — check for quote entry
  // $'...' (ANSI-C quoting) and $"..." (locale double quoting) both decode at
  // runtime; the $ is syntax, not part of the word. Dropping it here makes the
  // decoded content visible to path/credential checks (e.g. cat $'\x2fetc\x2fpasswd').
  if (enableAnsi && ch === "$" && next === "'" && !isEscapedAt(cmd, i)) {
    return { append: "", advance: 2, inSingleQuote: false, inDoubleQuote: false, inAnsi: true };
  }
  if (enableAnsi && ch === "$" && next === '"' && !isEscapedAt(cmd, i)) {
    return { append: "", advance: 2, inSingleQuote: false, inDoubleQuote: true, inAnsi: false };
  }
  if (ch === "'") {
    return {
      append: skipQuoteChars ? "" : ch,
      advance: 1,
      inSingleQuote: true,
      inDoubleQuote: false,
      inAnsi: false,
    };
  }
  if (ch === '"') {
    return {
      append: skipQuoteChars ? "" : ch,
      advance: 1,
      inSingleQuote: false,
      inDoubleQuote: true,
      inAnsi: false,
    };
  }

  // Normal character
  return { append: ch, advance: 1, inSingleQuote: false, inDoubleQuote: false, inAnsi: false };
}

// ── ANSI-C string ($'...') decoding ──────────────────────────────────────

/**
 * Decode the contents of an ANSI-C quoted string ($'...'), matching bash semantics:
 *   \a \b \e \E \f \n \r \t \v \\ \' \" \?   simple escapes
 *   \cX                    control character (X & 0x1f)
 *   \xHH (1-2 hex)         \uHHHH (1-4 hex)  \UHHHHHHHH (1-8 hex)
 *   \NNN (1-3 octal)
 * Unrecognized escapes retain the backslash (bash keeps `\q` as `\q`).
 */
export function decodeAnsiCEscapes(content: string): string {
  let out = "";
  let i = 0;
  while (i < content.length) {
    const ch = content[i];
    if (ch !== "\\") { out += ch; i++; continue; }
    const next = content[i + 1];
    if (next === undefined) { out += "\\"; i++; continue; }
    switch (next) {
      case "a": out += "\x07"; i += 2; continue;
      case "b": out += "\x08"; i += 2; continue;
      case "e": case "E": out += "\x1b"; i += 2; continue;
      case "f": out += "\x0c"; i += 2; continue;
      case "n": out += "\n"; i += 2; continue;
      case "r": out += "\r"; i += 2; continue;
      case "t": out += "\t"; i += 2; continue;
      case "v": out += "\x0b"; i += 2; continue;
      case "\\": case "'": case '"': case "?": out += next; i += 2; continue;
      case "c": {
        const c = content[i + 2];
        if (c !== undefined) { out += String.fromCharCode(c.charCodeAt(0) & 0x1f); i += 3; continue; }
        out += "\\c"; i += 2; continue;
      }
      case "x": case "u": case "U": {
        const maxDigits = next === "x" ? 2 : next === "u" ? 4 : 8;
        let j = i + 2;
        let hex = "";
        while (j < content.length && hex.length < maxDigits && /[0-9a-fA-F]/.test(content[j])) {
          hex += content[j]; j++;
        }
        if (hex) {
          const cp = parseInt(hex, 16);
          // > U+10FFFF is invalid — bash silently drops it; never let
          // String.fromCodePoint throw (would crash the permission gate).
          out += cp > 0x10ffff ? "\ufffd" : String.fromCodePoint(cp);
          i = j;
          continue;
        }
        out += "\\" + next; i += 2; continue; // no digits — bash keeps the escape
      }
      default:
        if (next >= "0" && next <= "7") {
          let j = i + 1;
          let oct = "";
          while (j < content.length && oct.length < 3 && content[j] >= "0" && content[j] <= "7") {
            oct += content[j]; j++;
          }
          out += String.fromCharCode(parseInt(oct, 8));
          i = j;
          continue;
        }
        out += "\\" + next; i += 2; continue; // unrecognized — backslash retained
    }
  }
  return out;
}

/** End index (exclusive) of the escape sequence starting at `\` (index i). */
function ansiEscapeEnd(s: string, i: number): number {
  const next = s[i + 1];
  if (next === undefined) return i + 1;
  if (next === "x" || next === "u" || next === "U") {
    const max = next === "x" ? 2 : next === "u" ? 4 : 8;
    let j = i + 2;
    while (j < s.length && j - (i + 2) < max && /[0-9a-fA-F]/.test(s[j])) j++;
    return j;
  }
  if (next >= "0" && next <= "7") {
    let j = i + 1;
    while (j < s.length && j - (i + 1) < 3 && s[j] >= "0" && s[j] <= "7") j++;
    return j;
  }
  if (next === "c" && i + 2 < s.length) return i + 3;
  return i + 2;
}

/** True if the char at idx is escaped by an odd number of preceding backslashes. */
function isEscapedAt(cmd: string, idx: number): boolean {
  let count = 0;
  for (let j = idx - 1; j >= 0 && cmd[j] === "\\"; j--) count++;
  return count % 2 === 1;
}

// ── Public utilities ──

/**
 * Split predicate: returns { push: boolean, skip: number, append?: string } when a split point is found.
 * push=true → push current buffer before split. skip=N → advance N chars instead of normal advance.
 * append → text to append to current buffer (e.g. "||" to preserve double pipe).
 */
type SplitPredicate = (ch: string, rest: string, inSingleQuote: boolean, inDoubleQuote: boolean) => { push: boolean; skip: number; append?: string } | null;

/**
 * Unified tokenizer: runs the quote-tracking state machine and applies a split predicate.
 * @param cmd - Command string to process
 * @param split - Split predicate (null for whitespace-only tokenization)
 * @param skipQuoteChars - Strip quote characters from output
 * @param handleEscapes - Handle escape sequences in double quotes
 * @param trimInput - Trim input before processing
 * @param pushTrimmed - Trim each token before pushing
 */
function tokenizeWithSplit(
  cmd: string,
  split: SplitPredicate | null,
  skipQuoteChars: boolean,
  handleEscapes: boolean,
  trimInput: boolean,
  pushTrimmed: boolean,
  enableAnsi: boolean,
): string[] {
  const parts: string[] = [];
  let current = "";
  let inSingleQuote = false;
  let inDoubleQuote = false;
  let inAnsi = false;
  const s = trimInput ? cmd.trim() : cmd;
  let i = 0;

  while (i < s.length) {
    const { append, advance, inSingleQuote: sq, inDoubleQuote: dq, inAnsi: an } = processChar(
      s, i, inSingleQuote, inDoubleQuote, inAnsi, enableAnsi, skipQuoteChars, handleEscapes,
    );
    inSingleQuote = sq;
    inDoubleQuote = dq;
    inAnsi = an;

    // If inside quotes, just append
    if (inSingleQuote || inDoubleQuote || inAnsi) {
      current += append;
      i += advance;
      continue;
    }

    // Check split predicate
    if (split) {
      const result = split(append, s.slice(i + 1), false, false);
      if (result) {
        if (result.push) {
          const token = pushTrimmed ? current.trim() : current;
          if (token) parts.push(token);
          current = "";
        }
        if (result.append) current += result.append;
        i += result.skip;
        continue;
      }
    }

    // Whitespace delimiter (for tokenization)
    if (!split && /\s/.test(append)) {
      if (current) {
        parts.push(current);
        current = "";
      }
      i += advance;
      continue;
    }

    // Skip empty append (quote boundaries when skipQuoteChars=true)
    if (append === "") { i += advance; continue; }

    current += append;
    i += advance;
  }

  const last = pushTrimmed ? current.trim() : current;
  if (last) parts.push(last);
  return parts;
}

/**
 * Split a command on pipe operator | (not ||).
 * Respects single and double quotes.
 */
export function splitOnPipe(cmd: string): string[] {
  return tokenizeWithSplit(cmd, (ch, rest) => {
    // Skip double pipe (||) — not a pipe operator, preserve in output
    if (ch === "|" && rest.startsWith("|")) return { push: false, skip: 2, append: "||" };
    // |& (tee pipe) — consume both chars as single operator
    if (ch === "|" && rest.startsWith("&")) return { push: true, skip: 2 };
    if (ch === "|") return { push: true, skip: 1 };
    return null;
  }, false, false, false, true, false);
}

/**
 * Split a command into segments on &&, ||, ; operators (respecting quotes).
 * Pipes (|) are kept within a segment.
 */
export function splitIntoSegments(cmd: string): string[] {
  return tokenizeWithSplit(cmd, (ch, rest) => {
    // 2-char chain operators (&&, ||)
    if ((ch === "&" && rest.startsWith("&")) ||
        (ch === "|" && rest.startsWith("|"))) {
      return { push: true, skip: 2 };
    }
    // Semicolon separator (but not =)
    if (ch === ";" && !rest.startsWith("=")) {
      return { push: true, skip: 1 };
    }
    return null;
  }, false, false, false, true, false);
}

/**
 * Tokenize a shell command respecting quotes.
 * Preserves quote characters in tokens.
 */
export function tokenize(cmd: string): string[] {
  return tokenizeWithSplit(cmd, null, false, false, false, false, false);
}

/**
 * Tokenize a shell segment respecting quotes.
 * Strips quote characters and handles escape sequences in double quotes.
 */
export function tokenizeSegment(cmd: string): string[] {
  // enableAnsi=true: decode $'...' (and $"...") content so runtime-decoded
  // paths/credentials are visible to permission checks.
  return tokenizeWithSplit(cmd, null, true, true, true, false, true);
}
