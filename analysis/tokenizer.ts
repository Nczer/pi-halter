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
  skipQuoteChars: boolean,
  handleEscapes: boolean,
): { append: string; advance: number; inSingleQuote: boolean; inDoubleQuote: boolean } {
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
      };
    }
    return { append: ch, advance: 1, inSingleQuote: true, inDoubleQuote: false };
  }

  // Inside double quote
  if (inDoubleQuote) {
    if (handleEscapes && ch === '\\' && next) {
      return { append: next, advance: 2, inSingleQuote: false, inDoubleQuote: true };
    }
    if (ch === '"' && (i === 0 || cmd[i - 1] !== "\\")) {
      return {
        append: skipQuoteChars ? "" : ch,
        advance: 1,
        inSingleQuote: false,
        inDoubleQuote: false,
      };
    }
    return { append: ch, advance: 1, inSingleQuote: false, inDoubleQuote: true };
  }

  // Outside quotes — check for quote entry
  if (ch === "'") {
    return {
      append: skipQuoteChars ? "" : ch,
      advance: 1,
      inSingleQuote: true,
      inDoubleQuote: false,
    };
  }
  if (ch === '"') {
    return {
      append: skipQuoteChars ? "" : ch,
      advance: 1,
      inSingleQuote: false,
      inDoubleQuote: true,
    };
  }

  // Normal character
  return { append: ch, advance: 1, inSingleQuote: false, inDoubleQuote: false };
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
): string[] {
  const parts: string[] = [];
  let current = "";
  let inSingleQuote = false;
  let inDoubleQuote = false;
  const s = trimInput ? cmd.trim() : cmd;
  let i = 0;

  while (i < s.length) {
    const { append, advance, inSingleQuote: sq, inDoubleQuote: dq } = processChar(
      s, i, inSingleQuote, inDoubleQuote, skipQuoteChars, handleEscapes,
    );
    inSingleQuote = sq;
    inDoubleQuote = dq;

    // If inside quotes, just append
    if (inSingleQuote || inDoubleQuote) {
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
    if (ch === "|") return { push: true, skip: 1 };
    return null;
  }, false, false, false, true);
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
  }, false, false, false, true);
}

/**
 * Tokenize a shell command respecting quotes.
 * Preserves quote characters in tokens.
 */
export function tokenize(cmd: string): string[] {
  return tokenizeWithSplit(cmd, null, false, false, false, false);
}

/**
 * Tokenize a shell segment respecting quotes.
 * Strips quote characters and handles escape sequences in double quotes.
 */
export function tokenizeSegment(cmd: string): string[] {
  return tokenizeWithSplit(cmd, null, true, true, true, false);
}
