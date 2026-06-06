/**
 * Utility for wildcard matching (e.g., "git checkout *.lock").
 * Converts simple wildcard patterns into anchored Regular Expressions.
 */

export function match(pattern: string, text: string): boolean {
  const regex = new RegExp(
    "^" + pattern
      .replace(/[.+^${}()|[\]\\]/g, "\\$&") // Escape regex special chars except * and ?
      .replace(/\*/g, ".*")                // * -> match any characters
      .replace(/\?/g, ".")                 // ? -> match one character
      + "$",
    "i"
  );
  return regex.test(text);
}
