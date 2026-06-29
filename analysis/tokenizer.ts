// ── Quote-aware tokenizer infrastructure ──
//
// Canonical implementation of quote-tracking used by splitPipeline, splitOnPipe,
// splitIntoSegments, tokenize, and tokenizeSegment. Eliminates 4+ duplicated
// state machines across the codebase.

/** Options for the quote-aware scanner. */
interface ScanOptions {
  /** Called when a non-whitespace, non-quote character (or sequence) is encountered. */
  onChar?: (ch: string, next: string | null, i: number) => number; // returns chars to advance
  /** Called when whitespace is encountered outside quotes. */
  onWhitespace?: () => void;
  /** Whether to include quote characters in the accumulator. Default: true. */
  includeQuotes?: boolean;
  /** Whether to handle escape sequences in double quotes. Default: true. */
  handleEscapes?: boolean;
}

/**
 * Walk through a command string, tracking quote state and calling callbacks.
 * Returns accumulated tokens/parts.
 */
function scanCommand(cmd: string, options: ScanOptions): string[] {
  const results: string[] = [];
  let current = "";
  let inSingleQuote = false;
  let inDoubleQuote = false;
  let i = 0;
  const includeQuotes = options.includeQuotes ?? true;
  const handleEscapes = options.handleEscapes ?? true;

  while (i < cmd.length) {
    const ch = cmd[i];
    const next = i + 1 < cmd.length ? cmd[i + 1] : null;

    // Inside single quotes — everything literal until closing quote
    if (inSingleQuote) {
      current += ch;
      if (ch === "'") {
        inSingleQuote = false;
        // If stripping quotes, remove the opening quote we added
        if (!includeQuotes && current.length >= 2) {
          current = current.slice(1);
        }
      }
      i++;
      continue;
    }

    // Inside double quotes — handle escapes
    if (inDoubleQuote) {
      if (handleEscapes && ch === '\\' && next && i + 1 < cmd.length) {
        current += next; // consume escaped char
        i += 2;
        continue;
      }
      current += ch;
      if (ch === '"' && (i === 0 || cmd[i - 1] !== "\\")) {
        inDoubleQuote = false;
        if (!includeQuotes && current.length >= 2) {
          current = current.slice(1);
        }
      }
      i++;
      continue;
    }

    // Outside quotes — check for quote start
    if (ch === "'") {
      inSingleQuote = true;
      if (includeQuotes) current += ch;
      i++;
      continue;
    }

    if (ch === '"') {
      inDoubleQuote = true;
      if (includeQuotes) current += ch;
      i++;
      continue;
    }

    // Custom character handler (e.g., pipe detection, segment splitting)
    if (options.onChar) {
      const advance = options.onChar(ch, next, i);
      if (advance > 0) {
        // Flush current token
        const trimmed = current.trim();
        if (trimmed) results.push(trimmed);
        current = "";
        i += advance;
        continue;
      }
    }

    // Whitespace outside quotes — token boundary
    if (/\s/.test(ch)) {
      if (options.onWhitespace) options.onWhitespace();
      if (current.trim()) {
        results.push(current.trim());
        current = "";
      }
      i++;
      continue;
    }

    current += ch;
    i++;
  }

  // Flush remaining
  const last = current.trim();
  if (last) results.push(last);

  return results;
}

// ── Public utilities ──

/**
 * Split a command on pipe operator | (not ||).
 * Respects single and double quotes.
 */
export function splitOnPipe(cmd: string): string[] {
  const parts: string[] = [];
  let current = "";
  let inSingleQuote = false;
  let inDoubleQuote = false;
  let i = 0;

  while (i < cmd.length) {
    const ch = cmd[i];
    const next = i + 1 < cmd.length ? cmd[i + 1] : null;

    if (inSingleQuote) {
      current += ch;
      if (ch === "'") inSingleQuote = false;
      i++;
      continue;
    }

    if (inDoubleQuote) {
      current += ch;
      if (ch === '"' && (i === 0 || cmd[i - 1] !== "\\")) inDoubleQuote = false;
      i++;
      continue;
    }

    if (ch === "'") {
      inSingleQuote = true;
      current += ch;
      i++;
      continue;
    }

    if (ch === '"') {
      inDoubleQuote = true;
      current += ch;
      i++;
      continue;
    }

    // Skip double pipe (||) — not a pipe operator
    if (ch === "|" && next === "|") {
      current += "||";
      i += 2;
      continue;
    }

    // Single pipe
    if (ch === "|") {
      const trimmed = current.trim();
      if (trimmed) parts.push(trimmed);
      current = "";
      i++;
      continue;
    }

    current += ch;
    i++;
  }

  const last = current.trim();
  if (last) parts.push(last);
  return parts;
}

/**
 * Split a command into segments on &&, ||, ; operators (respecting quotes).
 * Pipes (|) are kept within a segment.
 */
export function splitIntoSegments(cmd: string): string[] {
  const segments: string[] = [];
  let current = "";
  let inSingleQuote = false;
  let inDoubleQuote = false;
  let i = 0;

  while (i < cmd.length) {
    const ch = cmd[i];
    const next = i + 1 < cmd.length ? cmd[i + 1] : null;

    if (inSingleQuote) {
      current += ch;
      if (ch === "'") inSingleQuote = false;
      i++;
      continue;
    }

    if (inDoubleQuote) {
      current += ch;
      if (ch === '"' && (i === 0 || cmd[i - 1] !== "\\")) inDoubleQuote = false;
      i++;
      continue;
    }

    if (ch === "'") {
      inSingleQuote = true;
      current += ch;
      i++;
      continue;
    }

    if (ch === '"') {
      inDoubleQuote = true;
      current += ch;
      i++;
      continue;
    }

    // Check for 2-char chain operators (&&, ||)
    if ((ch === "&" && next === "&") ||
        (ch === "|" && next === "|")) {
      const trimmed = current.trim();
      if (trimmed) segments.push(trimmed);
      current = "";
      i += 2;
      continue;
    }

    // Semicolon separator
    if (ch === ";" && next !== "=") {
      const trimmed = current.trim();
      if (trimmed) segments.push(trimmed);
      current = "";
      i++;
      continue;
    }

    current += ch;
    i++;
  }

  const last = current.trim();
  if (last) segments.push(last);
  return segments;
}

/**
 * Tokenize a shell command respecting quotes.
 * Preserves quote characters in tokens.
 */
export function tokenize(cmd: string): string[] {
  const tokens: string[] = [];
  let current = "";
  let inSingleQuote = false;
  let inDoubleQuote = false;
  let i = 0;

  while (i < cmd.length) {
    const ch = cmd[i];

    if (inSingleQuote) {
      current += ch;
      if (ch === "'") inSingleQuote = false;
      i++;
      continue;
    }

    if (inDoubleQuote) {
      current += ch;
      if (ch === '"' && (i === 0 || cmd[i - 1] !== "\\")) inDoubleQuote = false;
      i++;
      continue;
    }

    if (ch === "'") {
      inSingleQuote = true;
      current += ch;
      i++;
      continue;
    }

    if (ch === '"') {
      inDoubleQuote = true;
      current += ch;
      i++;
      continue;
    }

    if (/\s/.test(ch)) {
      if (current) {
        tokens.push(current);
        current = "";
      }
      i++;
      continue;
    }

    current += ch;
    i++;
  }

  if (current) tokens.push(current);
  return tokens;
}

/**
 * Tokenize a shell segment respecting quotes.
 * Strips quote characters and handles escape sequences in double quotes.
 */
export function tokenizeSegment(cmd: string): string[] {
  const tokens: string[] = [];
  let current = "";
  let inSingleQuote = false;
  let inDoubleQuote = false;
  let i = 0;
  const s = cmd.trim();

  while (i < s.length) {
    const ch = s[i];
    const next = i + 1 < s.length ? s[i + 1] : null;

    if (inSingleQuote) {
      if (ch === "'") {
        inSingleQuote = false;
        i++;
        continue;
      }
      current += ch;
      i++;
      continue;
    }

    if (inDoubleQuote) {
      if (ch === '\\' && next && i + 1 < s.length) {
        current += next;
        i += 2;
        continue;
      }
      if (ch === '"') {
        inDoubleQuote = false;
        i++;
        continue;
      }
      current += ch;
      i++;
      continue;
    }

    if (ch === "'") {
      inSingleQuote = true;
      i++;
      continue;
    }

    if (ch === '"') {
      inDoubleQuote = true;
      i++;
      continue;
    }

    if (/\s/.test(ch)) {
      if (current) tokens.push(current);
      current = "";
      i++;
      continue;
    }

    current += ch;
    i++;
  }

  if (current) tokens.push(current);
  return tokens;
}
