import path from "node:path";
import os from "node:os";
import { expandTilde } from "../path-util";

/** Directories whose scripts are auto-trusted (interpreter + script in this dir bypasses dangerous-pattern check). */
const trustedScriptDirs: string[] = [
  path.join(os.homedir(), ".pi", "agent", "skills"),
];

/** Packages allowed in `uv run --with` for trusted scripts (supply chain defense). */
const TRUSTED_PACKAGES = new Set([
  "anthropic", "defusedxml", "lxml", "markitdown", "mcp",
  "openpyxl", "pandas", "pillow", "pymupdf", "pypdf", "reportlab",
]);

/**
 * Extract package name from a --with value, stripping extras like [pptx].
 * "markitdown[pptx]" → "markitdown"
 * "pymupdf" → "pymupdf"
 */
function normalizePkg(name: string): string {
  return name.replace(/\[.*\]/, "").toLowerCase();
}

/** Check if all packages in a --with value are trusted. Handles comma-separated lists. */
function arePackagesTrusted(value: string): boolean {
  return value.split(",").every(pkg => TRUSTED_PACKAGES.has(normalizePkg(pkg.trim())));
}

/** Check if a resolved absolute path is inside any trusted script directory. */
export function isTrustedScriptPath(resolvedPath: string): boolean {
  return trustedScriptDirs.some(dir => {
    const rel = path.relative(dir, resolvedPath);
    return rel !== "" && !rel.startsWith("..");
  });
}

/**
 * Tokenize a shell segment respecting single and double quotes.
 * Handles: python "my script.py", node '/path/with space/file.js'
 */
function tokenizeSegment(segment: string): string[] {
  const tokens: string[] = [];
  let i = 0;
  const s = segment.trim();

  while (i < s.length) {
    // Skip whitespace
    if (/\s/.test(s[i])) { i++; continue; }

    // Double-quoted string
    if (s[i] === '"') {
      let token = "";
      i++; // skip opening quote
      while (i < s.length && s[i] !== '"') {
        if (s[i] === '\\' && i + 1 < s.length) {
          token += s[i + 1];
          i += 2;
        } else {
          token += s[i];
          i++;
        }
      }
      i++; // skip closing quote
      tokens.push(token);
      continue;
    }

    // Single-quoted string
    if (s[i] === "'") {
      let token = "";
      i++; // skip opening quote
      while (i < s.length && s[i] !== "'") {
        token += s[i];
        i++;
      }
      i++; // skip closing quote
      tokens.push(token);
      continue;
    }

    // Unquoted token
    let token = "";
    while (i < s.length && !/\s/.test(s[i]) && s[i] !== '"' && s[i] !== "'") {
      token += s[i];
      i++;
    }
    tokens.push(token);
  }

  return tokens;
}

/**
 * Check if a command segment is an interpreter (python, node, etc.) running
 * a script file from a trusted directory.
 */
export function isTrustedScriptCommand(segment: string, cwd: string): boolean {
  const tokens = tokenizeSegment(segment);
  if (tokens.length < 2) return false;

  const cmd = tokens[0].toLowerCase();
  if (!/^(python|node|ruby|php|lua|perl|deno|bun|jruby|pypy|graalvm|uv)/i.test(cmd)) return false;

  // Determine start index for script file search
  let startIdx = 1;

  // Handle `uv run [--with deps] script.py` pattern
  if (cmd === "uv" && tokens[startIdx]?.toLowerCase() === "run") {
    startIdx++;
    // Skip --with, --with-editable, --with-requirements and their values
    // Validate --with packages against allowlist (supply chain defense)
    while (startIdx < tokens.length) {
      const t = tokens[startIdx].toLowerCase();
      if (t === "--with" && startIdx + 1 < tokens.length) {
        if (!arePackagesTrusted(tokens[startIdx + 1])) return false;
        startIdx += 2;
        continue;
      }
      if (t === "--with-editable" || t === "--with-requirements") {
        startIdx += 2; // skip flag and its value (no pkg check for editable/requirements)
        continue;
      }
      if (t.startsWith("--with=")) {
        const value = t.slice("--with=".length);
        if (!arePackagesTrusted(value)) return false;
        startIdx++;
        continue;
      }
      if (t.startsWith("--with-editable=") || t.startsWith("--with-requirements=")) {
        startIdx++; // no pkg check for editable/requirements
        continue;
      }
      break;
    }
  }

  // Find the script file argument (first non-flag token that looks like a file)
  for (let i = startIdx; i < tokens.length; i++) {
    const token = tokens[i];
    if (token.startsWith("-")) continue; // skip flags like -c, -m, -u, etc.
    if (/\.\w{2,4}$/.test(token)) {
      const resolved = path.resolve(cwd, expandTilde(token));

      // Trusted static directory only
      if (isTrustedScriptPath(resolved)) return true;
      break;
    }
  }
  return false;
}
