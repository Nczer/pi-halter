/**
 * Utility for wildcard matching (e.g., "git checkout *.lock").
 * Converts simple wildcard patterns into anchored Regular Expressions.
 */

/**
 * Strip trailing " *" from a pattern so "npm test *" also matches "npm test".
 * Returns the stripped string or null if no trailing " *" found.
 */
export function stripTrailingWildcard(pattern: string): string | null {
  const m = pattern.match(/^(.*) \*$/);
  return m ? m[1] : null;
}

/** Compile a wildcard pattern into a RegExp (call once, reuse). */
export function compilePattern(pattern: string): RegExp {
  return new RegExp(
    "^" + pattern
      .replace(/[.+^${}()|[\]\\]/g, "\\$&") // Escape regex special chars except * and ?
      .replace(/\*/g, ".*")                // * -> match any characters
      .replace(/\?/g, ".")                 // ? -> match one character
      + "$",
    "i"
  );
}

export function match(pattern: string, text: string): boolean {
  return compilePattern(pattern).test(text);
}
