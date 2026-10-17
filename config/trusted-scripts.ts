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
 * uv's run forms — ONE scan covers all of them because they take the SAME
 * option set (`uvx` is `uv tool run`, and `uv tool run`/`uv x` are its long
 * spellings). Naming only `uv run` left `uvx -p /tmp/evil/python tsc` outside
 * the option table entirely: package trust vouched for `tsc` while the
 * interpreter came from anywhere on the filesystem.
 */
export interface UvRunner { runner: string; end: number; }

function uvRunnerOf(texts: string[], i: number): UvRunner | null {
  const a = texts[i]?.toLowerCase();
  if (a === "uvx") return { runner: "uvx", end: i + 1 };
  if (a !== "uv") return null;
  const b = texts[i + 1]?.toLowerCase();
  if (b === "run") return { runner: "uv run", end: i + 2 };
  if (b === "x") return { runner: "uv x", end: i + 2 };
  if (b === "tool" && texts[i + 2]?.toLowerCase() === "run") return { runner: "uv tool run", end: i + 3 };
  return null;
}

/**
 * uv's own options that select NOTHING the grant has to name — behaviour and
 * verbosity switches, and the switches that only REDUCE what is fetched or
 * built (`--frozen`, `--locked`, `--no-sync`, `--offline`, `--no-build`,
 * `--no-index`, `--no-python-downloads`). Curated from `uv run --help`
 * (uv 0.13.x: 83 options). The default is the other way round: an option that
 * is not listed here, below, or in the dep/python classes is NOT benign.
 *
 * Not benign on purpose: anything that widens or redirects the install set
 * (`--extra`, `--group`, `--all-extras`, `--upgrade`, `--reinstall`,
 * `--index-url`, `--default-index`, `--find-links`, `--index`), points uv at a
 * project/directory/config/env file it would not otherwise read (`--project`,
 * `--directory`, `--config-file`, `--env-file`, `--cache-dir`), weakens
 * verification (`--allow-insecure-host`, `--no-require-build-hashes`,
 * `--keyring-provider subprocess`), or picks a package by name (`--package`).
 * None of those can be covered by a decision made about the plain form, and
 * their values name a source no grant saw.
 */
const UV_BENIGN_FLAGS: ReadonlySet<string> = new Set([
  "--active", "--compile-bytecode", "--exact", "--frozen", "--gui-script",
  "-h", "--help", "--isolated", "--locked", "--managed-python", "-n", "--no-cache",
  "--no-build", "--no-config", "--no-default-groups", "--no-dev", "--no-editable",
  "--no-env-file", "--no-index", "--no-managed-python", "--no-progress", "--no-project",
  "--no-python-downloads", "--no-sync", "--offline", "-q", "--quiet", "-s", "--script",
  "-v", "--verbose", "--require-build-hashes",
]);

/**
 * Options that DO take a value but from a closed enumeration with no source,
 * path or package in it — the flag joins the identity, its value cannot change
 * what is executed (`--color never`, `--link-mode copy`). Every name here must
 * also be in bash-patterns UV_VALUE_FLAGS: if the arity table missed it, the
 * operand scan would read the value as the script (`--color never` → `never`).
 */
const UV_BENIGN_VALUE_FLAGS: ReadonlySet<string> = new Set([
  "--color", "--fork-strategy", "--index-strategy", "--link-mode", "--python-platform",
]);

/**
 * clap's short spellings for the identity flags above. `-w` IS `--with` —
 * verified against `uv run --help` — and an option the scan does not know is
 * assumed to TAKE a value, so `uv run -w evil-pkg python3 s.py` read `-w`
 * unknown, skipped `evil-pkg` as its value, recorded NO dependency, and kept
 * the coarse `uv run` signature: an unnamed registry install under the
 * trusted-script umbrella. Aliased rather than added: same dependency, same
 * grant, canonical rendering. (The other value-taking short flags —
 * `-i/--index-url`, `-f/--find-links`, `-P/--upgrade-package`, `-C` — are
 * arity-known through bash-patterns UV_VALUE_FLAGS and non-benign by omission,
 * so they void the umbrella instead of hiding their operands.)
 */
const UV_FLAG_ALIASES: Readonly<Record<string, string>> = { "-w": "--with" };

/** An option value the grant has to name, with the flag that carries it. */
export interface UvRunOption {
  /** Canonical option name (`-p 3.12` renders as `--python 3.12`). */
  flag: string;
  /** Token text as the shell hands it to uv (quote chars stripped). */
  value: string;
  /** The value is not decided until the shell runs it — see UvRunDep.opaque. */
  opaque: boolean;
}

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

/** Everything the ONE walk knows about a uv run form's leading options. */
export interface UvRunFlags {
  /** The matched runner text (`uv run`, `uv tool run`, `uv x`, `uvx`). */
  runner: string;
  /** Dependency flags with their values, in command order. */
  deps: UvRunDep[];
  /** Benign option NAMES, lowercased, command order (`--frozen`, `--color`). */
  uvFlags: string[];
  /** `-p`/`--python` values — the interpreter uv downloads when it is missing. */
  pythonValues: UvRunOption[];
  /** Options the closed world does not vouch for, with their values.
   *  Their presence voids the trusted-script umbrella (see uvOptionsVetted). */
  otherOptions: UvRunOption[];
  /** A value-taking option with no value token — a malformed form, fails closed. */
  danglingValue: boolean;
}

/** Facts making a token's value unknowable at grant time. */
function isOpaqueValue(tok: QuotedToken): boolean {
  return tok.hasExpansion === true || tok.unquotedGlob === true;
}

/**
 * ONE walk over a `uv run` form's leading options — the same scan the trust
 * decision, the grant signature and the judge packet read, so the three can
 * never disagree about which command names which dependency (the drift the
 * shared operand scan exists to prevent). Null for anything that is not one of
 * uv's run forms (`uv run`, `uv tool run`, `uv x`, `uvx` — same option set).
 *
 * The region scanned is uv's OWN options: every leading flag up to the first
 * token that cannot be one (`--`, or the runner/script word). Stopping at the
 * first flag that is not a dependency flag was the original rule and it was
 * wrong: `uv run --frozen --with evil python3 s.py` hid the whole dependency
 * set from the allowlist check, so an arbitrary registry install ran under the
 * trusted-script umbrella. An option the closed world does not know is assumed
 * to TAKE a value (the wrongly-skipped word is the runner, which can only make
 * the scan narrower) and lands in `otherOptions`: unknown is never benign.
 */
export function uvRunFlags(tokens: QuotedToken[]): UvRunFlags | null {
  const texts = tokens.map((t) => t.text);
  let i = skipEnvPrefixes(texts);
  const form = uvRunnerOf(texts, i);
  if (!form) return null;
  i = form.end;
  const deps: UvRunDep[] = [];
  const uvFlags: string[] = [];
  const pythonValues: UvRunOption[] = [];
  const otherOptions: UvRunOption[] = [];
  let danglingValue = false;
  // Reads the next token as an option's value: `danglingValue` if there is none.
  // (`i` already sits past the option flag itself.)
  const valueOf = (name: string, inline: string | undefined, tok: QuotedToken): UvRunOption | null => {
    if (inline !== undefined) return { flag: name, value: inline, opaque: isOpaqueValue(tok) };
    const v = tokens[i];
    if (v === undefined) { danglingValue = true; return null; }
    i++;
    return { flag: name, value: v.text, opaque: isOpaqueValue(v) };
  };
  while (i < tokens.length) {
    const tok = tokens[i];
    // clap matches SHORT flags case-sensitively and they are not interchangeable
    // here: `-P` is `--upgrade-package` (widens the install set) while `-p` is
    // `--python`. Folding them let `uv run -P pandas python3 s.py` read as
    // `--python pandas` — a vetted interpreter version, umbrella intact. Long
    // spellings stay folded, as everywhere in these tables.
    const text = tok.text.startsWith("--") ? tok.text.toLowerCase() : tok.text;
    if (text === "--") break;
    if (!text.startsWith("-")) break; // the runner/script ends uv's option region
    const eq = text.indexOf("=");
    const rawName = eq === -1 ? text : text.slice(0, eq);
    const name = UV_FLAG_ALIASES[rawName] ?? rawName;
    const inline = eq === -1 ? undefined : tok.text.slice(eq + 1);
    i++; // valueOf below advances past the value when it consumes one

    const depFlag = UV_DEP_FLAGS.find((f) => name === f);
    if (depFlag) {
      if (inline !== undefined) { deps.push({ flag: depFlag, value: inline, opaque: isOpaqueValue(tok) }); }
      else {
        const v = tokens[i];
        if (v === undefined) { danglingValue = true; break; }
        deps.push({ flag: depFlag, value: v.text, opaque: isOpaqueValue(v) });
        i++;
      }
      continue;
    }

    if (UV_PYTHON_FLAGS.has(name)) {
      // Rendered as `--python <value>` by the signature builder — the flag name
      // is not a separate identity item (a value for what it selects is the
      // whole point of putting it in the grant).
      const v = valueOf("--python", inline, tok);
      if (v) pythonValues.push(v);
      continue;
    }
    // `-p3.11` — a short flag with its value attached (clap accepts it).
    if (name.startsWith("-p") && !name.startsWith("--") && name.length > 2) {
      pythonValues.push({ flag: "--python", value: tok.text.slice(2), opaque: isOpaqueValue(tok) });
      continue;
    }

    if (UV_BENIGN_FLAGS.has(name)) { uvFlags.push(name); continue; }
    if (UV_BENIGN_VALUE_FLAGS.has(name)) {
      uvFlags.push(name);
      if (inline === undefined && tokens[i] !== undefined && !tokens[i].text.startsWith("-")) i++;
      continue;
    }
    // Not in the closed world: its value joins the grant identity (so one
    // Always cannot cover every `--project`), and the form loses the
    // trusted-script umbrella — `--project /tmp/evil-proj python3
    // ~/.pi/agent/skills/x.py` runs a script from a project the operator
    // never looked at, resolving its imports from wherever that points.
    const v = valueOf(name, inline, tok);
    otherOptions.push(v ?? { flag: name, value: "", opaque: true });
  }
  return { runner: form.runner, deps, uvFlags, pythonValues, otherOptions, danglingValue };
}

/** A value that names a filesystem location (as opposed to a version, a
 *  package name or an enum member). */
function isPathLike(value: string): boolean {
  return value.includes("/") || value.startsWith("~");
}

/**
 * The options themselves vetted — the part of the trust decision that does not
 * depend on WHY the form is being trusted. An option the closed world does not
 * know, a value the shell decides at run time, or a malformed form all fail
 * closed. A `--python`/`-p` value that names a PATH must resolve inside the
 * base the command runs from: `uvx -p /tmp/evil/python tsc` runs the trusted
 * package's code THROUGH an interpreter nobody vouched for, while the ordinary
 * `--python 3.12` (a version uv resolves itself, or a bare name found on PATH)
 * stays as cheap as it always was.
 */
function uvOptionsVetted(flags: UvRunFlags, base: string | null): boolean {
  if (flags.danglingValue || flags.otherOptions.length > 0) return false;
  return flags.pythonValues.every((v) =>
    !v.opaque && (!isPathLike(v.value) || isInsideTrustedOrBase(resolveDepSource(v.value, base ?? undefined), base)));
}

/** A resolved path inside the trusted script dirs, or inside the working
 *  directory the command runs from. The base half is the existing boundary for
 *  a uv form — the project's own environment (its venv, its lockfile) is the
 *  project's business, already accepted for a bare `uv run`; what must be
 *  vetted is an interpreter from OUTSIDE the project (`-p /tmp/evil/python`).
 *  With no knowable base (`cd $(…) && uvx …`) only the trusted dirs pass. */
function isInsideTrustedOrBase(resolved: string, base: string | null): boolean {
  if (isTrustedScriptPath(resolved)) return true;
  return base !== null && (resolved === base || resolved.startsWith(base + "/"));
}

/**
 * Supply-chain defense for the trusted-script umbrella. Runs BEFORE the operand
 * scan: an untrusted dependency set, an option outside the closed world, or an
 * interpreter from outside the base voids trust even when the script file
 * itself sits in a trusted directory — the umbrella was decided about
 * "this skills script, with these vetted deps", and every one of those knobs
 * changes what is installed or which code imports it.
 */
function uvUmbrellaOk(tokens: QuotedToken[], base: string): boolean {
  const flags = uvRunFlags(tokens);
  if (!flags) return true; // not a uv run form: nothing uv decides
  if (!uvOptionsVetted(flags, base)) return false;
  return flags.deps.every((d) =>
    d.opaque ? false : d.flag === "--with" ? arePackagesTrusted(d.value) : isTrustedDepsPath(d.value, base)
  );
}

/**
 * Whether a FETCH form's uv options are covered by package trust alone.
 * Stricter than the umbrella: trusting `tsc` says nothing about an install set
 * (`--with`) or a project directory, and what the operator approved is the
 * fetched package's code — so anything but a benign switch stops the form.
 * Used by the D10 trust gate on both sides of the floor/policy pair
 * (analysis/segment-helpers supplies the scan, which looks through wrappers).
 */
export function uvFetchFormOk(flags: UvRunFlags | null, base: string | null): boolean {
  if (!flags) return true; // npx/npm/pnpm/yarn/bun fetch forms: option vetting
  // there is not done in G7 — see docs/architecture.md, accepted limit
  if (flags.deps.length > 0) return false;
  return uvOptionsVetted(flags, base);
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
  if (!uvUmbrellaOk(quoted, base)) return false;

  const op = findScriptOperand(tokens);
  if (!op?.first) return false;
  if (!op.wrappers.every((w) => TRUST_TRANSPARENT_FORMS.has(w))) return false;
  return isTrustedScriptPath(path.resolve(base, expandTilde(op.first.token)));
}
