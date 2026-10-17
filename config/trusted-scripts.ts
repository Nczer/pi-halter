import path from "node:path";
import os from "node:os";
import { expandTilde } from "../analysis/path-util";
import { tokenizeSegmentQuoted, type QuotedToken } from "../analysis/tokenizer";
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

/** Resolve a dependency source path as install identity: absolute, tilde-expanded. */
export function resolveDepSource(value: string, cwd: string | undefined): string {
  const v = expandTilde(value);
  return cwd ? path.resolve(cwd, v) : v;
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
  return isTrustedScriptPath(resolveDepSource(value, cwd));
}

/** The dependency flags uv accepts before the runner/script. */
const UV_DEP_FLAGS = ["--with", "--with-editable", "--with-requirements"] as const;
export type UvDepFlag = (typeof UV_DEP_FLAGS)[number];

/** The interpreter-selection flags: their value names an artifact uv downloads. */
const UV_PYTHON_FLAGS = new Set(["-p", "--python"]);

/**
 * clap's short spellings for the identity flags above. `-w` IS `--with` —
 * verified against `uv run --help` — and an option the scan does not know is
 * assumed to TAKE a value, so `uv run -w evil-pkg python3 s.py` read `-w`
 * unknown, skipped `evil-pkg` as its value, recorded NO dependency, and kept
 * the coarse `uv run` signature: an unnamed registry install under the
 * trusted-script umbrella. Aliased rather than added: same dependency, same
 * grant, canonical rendering. (The remaining value-taking short flags —
 * `-i/--index-url`, `-f/--find-links`, `-P/--upgrade-package` — name a SOURCE
 * the tables do not model yet; that belongs with the closed-world flag work.)
 */
const UV_FLAG_ALIASES: Readonly<Record<string, string>> = { "-w": "--with" };

/** One dependency a `uv run` form names (see uvRunFlags). */
export interface UvRunDep {
  /** Which flag named it. */
  flag: UvDepFlag;
  /** Token text as the shell hands it to uv (quote chars stripped, ANSI-C decoded). */
  value: string;
  /**
   * The value is not decided until the shell runs it: a `$…`/backtick expansion
   * or an unquoted glob char. Nothing can be vouched for it, so the form is
   * ungrantable — a grant keyed on `$DEP` would be a grant keyed on whatever
   * `DEP` happens to be at run time.
   */
  opaque: boolean;
}

/** Everything the ONE walk knows about a `uv run` form's leading options. */
export interface UvRunFlags {
  /** Dependency flags with their values, in command order. */
  deps: UvRunDep[];
  /** uv's own option tokens, lowercased, command order (`--frozen`, `-p`). */
  uvFlags: string[];
  /** `-p`/`--python` values — the interpreter uv downloads when it is missing. */
  pythonValues: string[];
  /** A dependency flag with no value token — a malformed form, fails closed. */
  danglingSource: boolean;
}

/** Facts making a token's value unknowable at grant time. */
function isOpaqueValue(tok: QuotedToken): boolean {
  return tok.hasExpansion === true || tok.unquotedGlob === true;
}

/**
 * ONE walk over a `uv run` form's leading options — the same scan the trust
 * decision, the grant signature and the judge packet read, so the three can
 * never disagree about which command names which dependency (the drift the
 * shared operand scan exists to prevent). Null for anything that is not a
 * `uv run` form.
 *
 * The region scanned is uv's OWN options: every leading flag up to the first
 * token that cannot be one (`--`, or the runner/script word). Stopping at the
 * first flag that is not a dependency flag was the original rule and it was
 * wrong: `uv run --frozen --with evil python3 s.py` hid the whole dependency
 * set from the allowlist check, so an arbitrary registry install ran under the
 * trusted-script umbrella. An unknown option is assumed to TAKE a value (uv has
 * dozens; curating the list is drift-prone) — the wrongly-skipped word is the
 * runner, which can only make the scan narrower, never wider.
 */
export function uvRunFlags(tokens: QuotedToken[]): UvRunFlags | null {
  const texts = tokens.map((t) => t.text);
  let i = skipEnvPrefixes(texts);
  if (texts[i]?.toLowerCase() !== "uv" || texts[i + 1]?.toLowerCase() !== "run") return null;
  i += 2;
  const deps: UvRunDep[] = [];
  const uvFlags: string[] = [];
  const pythonValues: string[] = [];
  let danglingSource = false;
  while (i < tokens.length) {
    const tok = tokens[i];
    const lower = tok.text.toLowerCase();
    if (lower === "--") break;
    if (!lower.startsWith("-")) break; // the runner/script ends uv's option region
    const eq = lower.indexOf("=");
    const rawName = eq === -1 ? lower : lower.slice(0, eq);
    const name = UV_FLAG_ALIASES[rawName] ?? rawName;
    const inline = eq === -1 ? undefined : tok.text.slice(eq + 1);

    const depFlag = UV_DEP_FLAGS.find((f) => name === f);
    if (depFlag) {
      if (inline !== undefined) {
        deps.push({ flag: depFlag, value: inline, opaque: isOpaqueValue(tok) });
        i++;
      } else {
        const v = tokens[i + 1];
        if (v === undefined) { danglingSource = true; break; }
        deps.push({ flag: depFlag, value: v.text, opaque: isOpaqueValue(v) });
        i += 2;
      }
      continue;
    }

    if (UV_PYTHON_FLAGS.has(name)) {
      // Rendered as `--python <value>` by the signature builder — the flag name
      // is not a separate identity item (a value for what it selects is the
      // whole point of putting it in the grant).
      if (inline !== undefined) { pythonValues.push(inline); i++; }
      else if (tokens[i + 1] !== undefined) { pythonValues.push(tokens[i + 1].text); i += 2; }
      else i++; // `--python` with no value: malformed, uv exits
      continue;
    }
    // `-p3.11` — a short flag with its value attached (clap accepts it).
    if (name.startsWith("-p") && !name.startsWith("--") && name.length > 2) {
      pythonValues.push(tok.text.slice(2));
      i++;
      continue;
    }

    uvFlags.push(name);
    const next = tokens[i + 1];
    if (eq === -1 && next !== undefined && !next.text.startsWith("-")) i += 2; // its possible value
    else i++;
  }
  return { deps, uvFlags, pythonValues, danglingSource };
}

/**
 * Supply-chain defense for the `uv run` dependency flags: every --with
 * package must be allowlisted, and every --with-editable/--with-requirements
 * source must itself be a trusted path. True for commands that are not a
 * `uv run` form (nothing to validate). Runs BEFORE the operand scan: an
 * untrusted dependency set voids trust even when the script file itself
 * sits in a trusted directory.
 */
function uvRunDepsTrusted(tokens: QuotedToken[], cwd: string): boolean {
  const flags = uvRunFlags(tokens);
  if (!flags) return true;
  if (flags.danglingSource) return false;
  return flags.deps.every((d) =>
    d.flag === "--with" ? arePackagesTrusted(d.value) : isTrustedDepsPath(d.value, cwd)
  );
}

/** A registry package a command names, as the operator's allowlist sees it. */
export interface RegistryDep {
  /** Normalized name (extras stripped, lowercased). */
  name: string;
  /** True when it is in TRUSTED_PACKAGES. */
  allowlisted: boolean;
}

/**
 * The registry packages the command's `uv run --with` forms fetch at run
 * time, each marked against TRUSTED_PACKAGES — KNOWLEDGE for the judge
 * packet, never a grant (the allowlist's only enforcement stays
 * uvRunDepsTrusted: an unallowlisted package voids trust, and the judge
 * deciding beside it stays the operator's problem at the prompt). Without
 * it the packet's only trace of the fetch is `network: yes (uv)`, so the
 * judge guesses about a supply-chain question the operator already
 * answered in config — and cannot tell a vetted `pandas` from `pdfplumber`.
 * Deduped, command order; empty when no such form is present (a segment is
 * a `uv run` form only when the flags lead it, mirroring trust's walk).
 */
export function registryRunDeps(segments: string[]): RegistryDep[] {
  const out: RegistryDep[] = [];
  const seen = new Set<string>();
  for (const seg of segments) {
    const flags = uvRunFlags(tokenizeSegmentQuoted(seg));
    if (!flags) continue;
    for (const dep of flags.deps) {
      if (dep.flag !== "--with") continue;
      for (const raw of dep.value.split(",")) {
        const name = normalizePkg(raw.trim());
        if (!name || seen.has(name)) continue;
        seen.add(name);
        out.push({ name, allowlisted: TRUSTED_PACKAGES.has(name) });
      }
    }
  }
  return out;
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
  const quoted = tokenizeSegmentQuoted(segment);
  const tokens = quoted.map((t) => t.text);
  if (tokens.length < 1) return false;

  // Normalize cwd once (tilde-expanding for robustness; runtime cwd is absolute).
  const base = path.resolve(expandTilde(cwd));
  if (!uvRunDepsTrusted(quoted, base)) return false;

  const op = findScriptOperand(tokens);
  if (!op?.first) return false;
  if (!op.wrappers.every((w) => TRUST_TRANSPARENT_FORMS.has(w))) return false;
  return isTrustedScriptPath(path.resolve(base, expandTilde(op.first.token)));
}
