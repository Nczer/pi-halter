import path from "node:path";
import os from "node:os";
import { expandTilde } from "../analysis/path-util";
import { tokenizeSegment } from "../analysis/tokenizer";
import { SHELL_INTERPRETERS } from "./bash-patterns";

/** Directories whose scripts are auto-trusted (interpreter + script in this dir bypasses dangerous-pattern check). */
const trustedScriptDirs: string[] = [
  path.join(os.homedir(), ".pi", "agent", "skills"),
];

/** Packages allowed in `uv run --with` for trusted scripts (supply chain defense). */
const TRUSTED_PACKAGES = new Set([
  "anthropic", "defusedxml", "lxml", "markitdown", "mcp",
  "openpyxl", "pandas", "pillow", "pymupdf", "pypdf", "reportlab", "xlrd",
]);

/** Pre-compiled regexes for interpreter detection and file extension check. */
const INTERPRETER_RE = /^(python|node|ruby|php|lua|perl|deno|bun|jruby|pypy|graalvm|uv)/i;
const FILE_EXT_RE = /\.\w{2,4}$/;

/**
 * Check if a command token refers to a file path (direct exec) rather than a
 * bare command name: `/abs/path`, `~/path`, `./rel/path`, `rel/path`.
 */
function isPathLikeToken(token: string): boolean {
  return token.includes("/") || token.startsWith("~");
}

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
  return trustedScriptDirs.some(dir => resolvedPath.startsWith(dir + "/"));
}

/**
 * Resolve a --with-editable/--with-requirements value and require it to be inside
 * a trusted directory. Without this, any attacker-writable deps file/dir (e.g. a
 * downloaded artifact in /tmp) grants arbitrary dependency installation under the
 * trusted-script umbrella, defeating the TRUSTED_PACKAGES allowlist.
 */
function isTrustedDepsPath(value: string, cwd: string): boolean {
  const resolved = path.resolve(cwd, expandTilde(value));
  return isTrustedScriptPath(resolved);
}

/**
 * Check if a command segment is an interpreter (python, node, etc.) running
 * a script file from a trusted directory.
 */
export function isTrustedScriptCommand(segment: string, cwd: string): boolean {
  const tokens = tokenizeSegment(segment);
  if (tokens.length < 1) return false;

  // Normalize cwd once (tilde-expanding for robustness; runtime cwd is absolute).
  const base = path.resolve(expandTilde(cwd));

  const cmd = tokens[0].toLowerCase();

  // Direct exec (no interpreter): first token is a path that resolves inside
  // the trusted skills dir. Skill scripts are invoked this way (they are
  // executable, e.g. `~/.../skills/doc-search/scripts/q.sh` or
  // `./scripts/find-sessions.sh`). A path token outside the trusted dir is a
  // plain (untrusted) executable — not a trusted script.
  if (isPathLikeToken(cmd)) {
    const resolved = path.resolve(base, expandTilde(cmd));
    return isTrustedScriptPath(resolved);
  }

  // Shell interpreters: `bash script.sh` / `sh script.sh` — trusted only when
  // the first non-flag token is a script file that resolves inside the
  // trusted dir. Command-string forms (`-c`, `--command`) are NEVER trusted:
  // the quoted code is opaque to analysis (e.g. `bash -c '~/skills/q.sh; rm -rf /'`
  // must not inherit trust from the path inside the string).
  if (SHELL_INTERPRETERS.has(cmd)) {
    for (let i = 1; i < tokens.length; i++) {
      const t = tokens[i];
      if (t === "-c" || t === "--command") return false;
      if (t.startsWith("-")) continue; // skip flags like -e, -u, --norc
      // First non-flag token must be the script file itself.
      if (!FILE_EXT_RE.test(t)) return false;
      const resolved = path.resolve(base, expandTilde(t));
      return isTrustedScriptPath(resolved);
    }
    return false;
  }

  if (tokens.length < 2) return false;
  if (!INTERPRETER_RE.test(cmd)) return false;

  // Determine start index for script file search
  let startIdx = 1;

  // Handle `uv run [--with deps] script.py` pattern
  if (cmd === "uv" && tokens[startIdx]?.toLowerCase() === "run") {
    startIdx++;
    // Skip --with, --with-editable, --with-requirements and their values
    // Validate --with packages against allowlist (supply chain defense);
    // --with-editable/--with-requirements sources must themselves be trusted paths.
    while (startIdx < tokens.length) {
      const t = tokens[startIdx].toLowerCase();
      if (t === "--with" && startIdx + 1 < tokens.length) {
        if (!arePackagesTrusted(tokens[startIdx + 1])) return false;
        startIdx += 2;
        continue;
      }
      if (t === "--with-editable" || t === "--with-requirements") {
        const value = tokens[startIdx + 1];
        if (value === undefined || !isTrustedDepsPath(value, cwd)) return false;
        startIdx += 2;
        continue;
      }
      if (t.startsWith("--with=")) {
        const value = t.slice("--with=".length);
        if (!arePackagesTrusted(value)) return false;
        startIdx++;
        continue;
      }
      if (t.startsWith("--with-editable=") || t.startsWith("--with-requirements=")) {
        const value = t.slice(t.indexOf("=") + 1);
        if (!isTrustedDepsPath(value, cwd)) return false;
        startIdx++;
        continue;
      }
      break;
    }
  }

  // Find the script file argument (first non-flag token that looks like a file)
  for (let i = startIdx; i < tokens.length; i++) {
    const token = tokens[i];
    if (token.startsWith("-")) continue; // skip flags like -c, -m, -u, etc.
    if (FILE_EXT_RE.test(token)) {
      const resolved = path.resolve(base, expandTilde(token));

      // Trusted static directory only
      if (isTrustedScriptPath(resolved)) return true;
      break;
    }
  }
  return false;
}
