import path from "node:path";
import os from "node:os";
import { expandTilde } from "../analysis/path-util";
import { tokenizeSegment } from "../analysis/tokenizer";
import { skipEnvPrefixes } from "./bash-patterns";
import { findScriptOperand } from "./script-operand";

/** Directories whose scripts are auto-trusted (interpreter + script in this dir bypasses dangerous-pattern check). */
const trustedScriptDirs: string[] = [
  path.join(os.homedir(), ".pi", "agent", "skills"),
];

/** Packages allowed in `uv run --with` for trusted scripts (supply chain defense). */
const TRUSTED_PACKAGES = new Set([
  "anthropic", "defusedxml", "lxml", "markitdown", "mcp",
  "openpyxl", "pandas", "pillow", "pymupdf", "pypdf", "reportlab", "xlrd",
]);

/**
 * Extract package name from a --with value, stripping extras like [pptx].
 * "markitdown[pptx]" → "markitdown"
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
 * Supply-chain defense for the `uv run` dependency flags: every --with
 * package must be allowlisted, and every --with-editable/--with-requirements
 * source must itself be a trusted path. True for commands that are not a
 * `uv run` form (nothing to validate). Runs BEFORE the operand scan: an
 * untrusted dependency set voids trust even when the script file itself
 * sits in a trusted directory.
 */
function uvRunDepsTrusted(tokens: string[], cwd: string): boolean {
  let i = skipEnvPrefixes(tokens);
  if (tokens[i]?.toLowerCase() !== "uv" || tokens[i + 1]?.toLowerCase() !== "run") return true;
  i += 2;
  while (i < tokens.length) {
    const t = tokens[i].toLowerCase();
    if (t === "--with" && i + 1 < tokens.length) {
      if (!arePackagesTrusted(tokens[i + 1])) return false;
      i += 2;
      continue;
    }
    if (t === "--with-editable" || t === "--with-requirements") {
      const value = tokens[i + 1];
      if (value === undefined || !isTrustedDepsPath(value, cwd)) return false;
      i += 2;
      continue;
    }
    if (t.startsWith("--with=")) {
      if (!arePackagesTrusted(t.slice("--with=".length))) return false;
      i++;
      continue;
    }
    if (t.startsWith("--with-editable=") || t.startsWith("--with-requirements=")) {
      if (!isTrustedDepsPath(t.slice(t.indexOf("=") + 1), cwd)) return false;
      i++;
      continue;
    }
    break;
  }
  return true;
}

/**
 * Wrapper forms trust passes through. The fix here is about KNOWLEDGE (the
 * judge packet finally gets the script's content for wrapped runs), not
 * grants: the skills-dir bypass stays exactly as wide as it was. Pass-through
 * wrappers (`timeout`, `env`, `xargs`, `watch`) and package FETCH runners
 * (`npx`, `uvx`, `npm exec`) gain no bypass — a trusted script fan-outed by
 * xargs, or a package fetched from the registry on cache miss, is not the
 * form the trusted-skills-dir decision was made about. The two local run
 * forms are the exception because trust parsed them before (uv run).
 */
const TRUST_TRANSPARENT_FORMS = new Set(["uv run", "deno run"]);

/**
 * Check if a command segment executes a script file from a trusted
 * directory. The operand scan is the shared one (config/script-operand.ts,
 * used by analysis/script-payload.ts for identification) — trust and
 * knowledge must name the same file for the same form, or a wrapped run
 * (`uv run --with <dep> python job.py`) gets the bypass without ever
 * reaching the judge packet.
 *
 * `first` (any extension) is the trust operand: an extension-less
 * executable in the skills dir is trusted even though it is not a text
 * payload worth fencing. Command-string forms are NEVER trusted — the
 * operand scan aborts on `-c`/`-m`/`-e`, so the quoted code cannot inherit
 * trust from a path inside the string (`bash -c '~/skills/q.sh; rm -rf /'`).
 */
export function isTrustedScriptCommand(segment: string, cwd: string): boolean {
  const tokens = tokenizeSegment(segment);
  if (tokens.length < 1) return false;

  // Normalize cwd once (tilde-expanding for robustness; runtime cwd is absolute).
  const base = path.resolve(expandTilde(cwd));
  if (!uvRunDepsTrusted(tokens, base)) return false;

  const op = findScriptOperand(tokens);
  if (!op?.first) return false;
  if (!op.wrappers.every((w) => TRUST_TRANSPARENT_FORMS.has(w))) return false;
  return isTrustedScriptPath(path.resolve(base, expandTilde(op.first.token)));
}
