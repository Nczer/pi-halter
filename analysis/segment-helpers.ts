import path from "node:path";
import { isFirstTokenRelativePath } from "./path-analysis";
import type { BashSegment } from "./bash-parser";
import { isWriteOperation, isAllowedCommand, PACKAGE_MANAGERS, unconditionallySafeCommands, wrapperCommands, GIT_GLOBAL_FLAGS, skipEnvPrefixes, fetchFormScan, type FetchFormScan, uvRunFlags, uvFetchFormOk, resolveDepSource, type UvRunDep, type UvRunOption, type UvRunFlags } from "../config";
import { splitIntoSegments, splitOnPipe, tokenizeSegment, tokenizeSegmentQuoted } from "./tokenizer";
import { resolveDelegatedTokens, skipWrapperArg, commandPositionWord } from "./wrapper-unwrap";
import { classifyArgv0 } from "./argv0-path";

// splitPipeline is splitOnPipe — same semantics (split on | not ||)
export { splitOnPipe as splitPipeline };

// ── Segment helpers (pure string utilities) ──

const CMD_SUBST_MARKER = "__CMD_SUBST__";

// ── Pre-compiled regexes for hot paths ──

/** Detect command substitution in quoted strings. */
const CMD_SUBST_IN_QUOTE_RE = /\$\s*\(/;
const BACKTICK_RE = /`/;
/** Write redirect patterns. */
export const STARTS_WITH_REDIRECT_RE = /^[0-9]*&?>+/;
const WRITE_REDIRECT_RE = />+\s*\S/;
/** `[[ … ]]` conditional expressions where `>` is string comparison, not file redirection. */
export const DOUBLE_BRACKET_COND_RE = /\[\[\s[\s\S]*?\s\]\]/g;
/** Null redirect stripping. */
const NULL_REDIRECT_RE1 = /[0-9]*&?>+\s*(?:\/dev\/(?:null|stderr))\b/g;
const NULL_REDIRECT_RE2 = /[0-9]*>&[0-9]+/g;
/** Signature extraction. */
const SIG_REDIRECT_RE = /&?[0-9]*>>?\s*\S+/g;
const SIG_INPUT_RE = /<\s*\S+/g;
/** Find/fd/rg exec detection.
 * -ok/-okdir execute the same command as -exec/-execdir, but prompt y/n per
 * match — and read that answer from stdin when there is no tty, so
 * `echo y | find . -ok rm {} \;` deletes silently. The exec'd command must be
 * checked identically. */
const FIND_EXEC_RE = /(?<![\w./-])-(?:execdir|exec|okdir|ok)\b\s+(\S+)/g;
const FD_EXEC_RE = /(?<![\w./-])(?:-(?:x|X)\b|--exec(?:-batch)?(?:=|\s+))\s*(\S+)/g;
const RG_PRE_RE = /(?<![\w./-])--pre(?:=|\s+)(\S+)/g;

/**
 * Package-manager flags that consume the NEXT token as their value (space-separated
 * form). Without this, `npm --prefix /x test` yields signature "npm /x" — junk in the
 * auto-allow list and a misleading "Always" label.
 * Flags with inline values (--prefix=/x) start with "-" and are skipped already.
 */
const PM_VALUE_FLAGS = new Set([
  "--prefix", "--registry", "--cache", "--cache-dir", "--userconfig", "--globalconfig",
  "--workspace", "-w", "--loglevel", "--cwd", "--manifest-path", "--config",
  "--target", "--target-dir", "-Z", "--index-url", "--extra-index-url", "-i",
]);
/** Check if a string contains command substitution markers from stripQuotedStrings. */
export function containsCommandSubstitution(s: string): boolean {
  return s.includes(CMD_SUBST_MARKER);
}

/**
 * The pipeline stages of a segment (G1): the parser-built list when the AST
 * saw a pipeline, else a quote-aware split of the segment text.
 *
 * This is the unit every "what does this segment run" rule answers for — the
 * signature, the allow table, base access, egress. A stage is NOT a segment:
 * stages share a cwd and a stdin chain, so segment-indexed state (effective
 * base, relative-tool binding, run-dep sets) stays keyed by segment and the
 * stage list hangs off that index.
 *
 * The fallback exists for hand-built segments (delegation tails, tmux payload
 * chunks, `subshellTexts` bodies), not for parser output — a consumer that
 * splits parser output itself is how the per-stage rules drifted apart.
 */
export function segmentStages(seg: BashSegment): string[] {
  if (seg.stages && seg.stages.length > 0) return seg.stages;
  const parts = splitOnPipe(seg.text);
  return parts.length > 0 ? parts : [seg.text];
}


/**
 * Replace quoted spans (`'…'`, `$'…'`, `"…"`, `$"…"`) with `__STR__` (or
 * `__CMD_SUBST__` when a double-quoted span contains an unescaped `$(…)` /
 * backtick) and strip word-boundary `#` comments in a single left-to-right
 * pass. Sequential `.replace()` passes paired quotes across different strings
 * (`echo '"' ; rm -rf src ; echo '"'`), treated `QUOTE_DOLLAR_RE` as dead code,
 * and desynchronized on `$'\''`.
 */
export function stripQuotedStrings(cmd: string): string {
  let out = "";
  let i = 0;
  while (i < cmd.length) {
    const ch = cmd[i];
    const next = cmd[i + 1];

    // Unquoted backslash escape: keep both chars so FastAllowRule still sees
    // `/\\/` while preventing `\"`, `\'`, or `\#` from opening a quote/comment.
    if (ch === "\\" && next !== undefined) {
      out += ch + next;
      i += 2;
      continue;
    }

    // ANSI-C quoting ($'...') — `\'` and `\\` are escaped inside.
    if (ch === "$" && next === "'") {
      let j = i + 2;
      while (j < cmd.length && cmd[j] !== "'") {
        if (cmd[j] === "\\" && j + 1 < cmd.length) j += 2;
        else j++;
      }
      if (j < cmd.length) {
        out += "__STR__";
        i = j + 1;
        continue;
      }
    }

    // Single-quoted string ('...') — no backslash escaping inside.
    if (ch === "'") {
      const close = cmd.indexOf("'", i + 1);
      if (close !== -1) {
        out += "__STR__";
        i = close + 1;
        continue;
      }
    }

    // Double-quoted string ("..." or $"...").
    if (ch === '"' || (ch === "$" && next === '"')) {
      const start = ch === "$" ? i + 2 : i + 1;
      let j = start;
      let inner = "";
      while (j < cmd.length && cmd[j] !== '"') {
        if (cmd[j] === "\\" && j + 1 < cmd.length) {
          // Escaped `\$` or `\` inside double quotes is literal, not a substitution.
          if (cmd[j + 1] !== "$" && cmd[j + 1] !== "`") inner += cmd[j] + cmd[j + 1];
          j += 2;
        } else {
          inner += cmd[j];
          j++;
        }
      }
      if (j < cmd.length) {
        out += (CMD_SUBST_IN_QUOTE_RE.test(inner) || BACKTICK_RE.test(inner))
          ? CMD_SUBST_MARKER
          : "__STR__";
        i = j + 1;
        continue;
      }
    }

    // Word-boundary `#` comment (start of line or preceded by whitespace).
    if (ch === "#" && (i === 0 || /\s/.test(cmd[i - 1]))) {
      const nl = cmd.indexOf("\n", i + 1);
      if (nl === -1) break;
      i = nl;
      continue;
    }

    out += ch;
    i++;
  }
  return out;
}

/**
 * Detect terminal escape/OSC sequences in echo/printf arguments — screen
 * spoofing (\033[2J + fake prompt) or OSC 52 clipboard write (\033]52;c;…).
 * Matches both literal ESC bytes and the escape notations bash interprets:
 * \033, \x1b, \e (printf always; echo with -e or $'…' quoting).
 */
const TERMINAL_ESCAPE_RE = /\\033|\\x1[bB]|\\x9[dD]|\\e(?![a-zA-Z0-9_])|[\x1b\x9d]/;

export function hasTerminalEscape(segment: string): boolean {
  return TERMINAL_ESCAPE_RE.test(segment);
}

/**
 * True if an `echo` invocation will interpret backslash escapes.
 * Echo options are the LEADING flag tokens; clusters are legal (-ne = -n -e)
 * and the last e/E in a cluster wins (bash processes left to right: -Ee →
 * escapes on, -eE → off). ANSI-C quoting ($'…') always interprets escapes.
 * Stops at the first non-option token (once arguments start, -e is data).
 */
export function echoInterpretsEscapes(segment: string): boolean {
  if (/\$'/.test(segment)) return true;
  const tokens = tokenizeSegment(segment);
  for (let i = 1; i < tokens.length; i++) {
    const t = tokens[i];
    if (!t.startsWith("-") || t === "--" || t.startsWith("--")) break;
    if (t.lastIndexOf("e") > t.lastIndexOf("E")) return true;
  }
  return false;
}

/**
 * The program a segment runs first, in the form the closed tables are keyed
 * on: inline env assignments skipped (`FOO=1 ls` runs ls), quotes removed
 * (`"cat"`, `$'cat'`), word-boundary backslashes stripped (`\cat`), basename,
 * lowercased. WRAPPERS ARE NOT UNWRAPPED — `timeout cat` answers `timeout`,
 * which is the word the allow table and the pattern tables must judge; the
 * delegated command is `getEffectiveCommand`'s / `getDelegatedCommand`'s
 * question. One reading for every verb-keyed consumer: reading the raw first
 * whitespace word let `FOO=1 rm -rf`, `"rm" -rf` and `\rm -rf` name no
 * program at all (no `[Pattern] rm`, so an Always was offered for a recursive
 * forced delete, and a grant minted from one spelling covered another).
 */
export function getFirstWord(segment: string): string {
  const words = tokenizeSegment(segment);
  const word = (words[skipEnvPrefixes(words)] ?? "").replace(/^\\+/, "");
  return path.basename(word.toLowerCase());
}

/**
 * True when the segment leads with an inline env assignment (`FOO=1 cmd`).
 * Such an invocation carries an environment the closed tables cannot vouch
 * for (PATH decides which binary runs; LD_PRELOAD decides what it loads), so
 * the table, the delegation rule and the prefix-grant rule all refuse it —
 * only the exact, assignment-aware signature grant can approve the spelling.
 */
export function hasInlineAssignment(segment: string): boolean {
  return /^[A-Za-z_][A-Za-z0-9_]*=/.test(tokenizeSegment(segment)[0] ?? "");
}

/**
 * What a segment's fetchable run form fetches, with inline env-assignment
 * prefixes (`FOO=bar npx evil`) and prefix/wrapper delegation (`env npx evil`,
 * `timeout npx evil`) resolved FIRST — the D10 trust gate must not be evadable
 * by prefixing, mirroring the manual policy's wrapper transparency. Null when
 * the segment names no fetchable run form. Quote-aware (tokenizeSegment).
 * The single definition for both consumers — the /dspa floor and SafetyRule's
 * trust check (the "ONE definition" invariant of FETCH_PKG_FORMS).
 */
export function segmentFetchPackage(segment: string): (FetchFormScan & { first: string }) | null {
  const words = tokenizeSegment(segment);
  let i = 0;
  while (i < words.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(words[i])) i++;
  const rest = words.slice(i);
  // Prefix/wrapper delegation (env/timeout/command/…): the package the
  // wrapped run form names (`env npx evil` → npx evil).
  const deleg = getDelegatedCommand(rest.join(" "));
  if (deleg) {
    const scan = fetchFormScan(deleg.cmd, deleg.tail.split(/\s+/));
    return scan ? { first: deleg.cmd, ...scan } : null;
  }
  const first = rest[0]?.toLowerCase() ?? "";
  const scan = fetchFormScan(first, rest);
  return scan ? { first, ...scan } : null;
}

/**
 * Get the effective command name after shell prefix wrappers. `command …`,
 * `builtin …`, `exec …`, and `env …` all *execute* the following command, so
 * checks keyed on the first word (printf/echo terminal escapes, sort -o, …)
 * would miss `command printf '\033]52;…'` or `env sort -o x y`. Also strips
 * leading backslashes (\printf) and `env` flags/assignments. Pure text.
 */
export function getEffectiveCommand(segment: string): string {
  const words = tokenizeSegment(segment);
  const res = resolveDelegatedTokens(words);
  if (res && !res.capped) return res.cmd;
  // Non-delegating segment: the program is the first word after the inline
  // assignments (`FOO=1 rm` runs rm), dequoted by the tokenizer and with
  // word-boundary backslashes removed (`\rm` runs rm).
  const word = (words[skipEnvPrefixes(words)] ?? "").replace(/^\\+/, "");
  return path.basename(word.toLowerCase());
}

/**
 * The command a segment actually executes when its first word is a shell
 * prefix (command/builtin/exec/env) or wrapper (timeout/xargs/watch/…).
 * `tail` is the text from the delegated command onward (quote-stripped tokens
 * re-joined) so it can be evaluated as if it were a bare first word.
 * Returns null for non-delegating segments and `command -v/-V` lookups.
 */
export function getDelegatedCommand(segment: string): { cmd: string; tail: string } | null {
  const words = tokenizeSegment(segment);
  const res = resolveDelegatedTokens(words);
  if (!res || res.lookup || res.capped) return null;
  return { cmd: res.cmd, tail: words.slice(res.index).join(" ") };
}

/** Strip /dev/null, /dev/stderr redirects and fd-to-fd redirects from a command string. */
export function stripNullRedirects(cmd: string): string {
  return cmd
    .replace(NULL_REDIRECT_RE1, "")
    .replace(NULL_REDIRECT_RE2, "");
}

/**
 * Check if a command string contains a write redirect (> or >> to a file).
 * Ignores /dev/null, /dev/stderr, fd-to-fd redirects, and test/[ conditionals.
 * Quote-aware: operators inside quoted strings (e.g. a grep pattern containing
 * "=>" or ">") are not treated as redirects. Unquoted command substitution
 * $(...) is preserved, so real redirects inside subshells are still detected.
 */
export function hasWriteRedirect(cmd: string): boolean {
  const noQuotes = stripQuotedStrings(cmd);
  const trimmed = noQuotes.trim();
  if (STARTS_WITH_REDIRECT_RE.test(trimmed)) {
    if (!stripNullRedirects(trimmed).trim()) return false;
  }
  const stripped = stripNullRedirects(noQuotes).replace(DOUBLE_BRACKET_COND_RE, "");
  return WRITE_REDIRECT_RE.test(stripped);
}

/**
 * Iterate wrapper command args (skipping flags/options) and apply a predicate.
 * @param firstOnly - If true, check only the first non-flag arg. If false, check all.
 */
function checkWrapperArg(segment: string, predicate: (arg: string) => boolean, firstOnly = false): boolean {
  const args = segment.trim().split(/\s+/);
  const firstWord = args[0].toLowerCase();
  for (let i = 1; i < args.length; i++) {
    const arg = args[i];
    if (skipWrapperArg(firstWord, arg)) continue;
    if (predicate(arg)) return true;
    if (firstOnly) break;
  }
  return false;
}

/**
 * Check if a wrapper command (xargs, timeout, nice, etc.) is running a write operation.
 * @param includeRelativePath - If true, also returns true for relative path targets (./foo).
 */
export function isWrapperRunningWrite(segment: string, includeRelativePath = true): boolean {
  return checkWrapperArg(segment, (arg) => {
    if (includeRelativePath && isFirstTokenRelativePath(arg)) return true;
    return isWriteOperation(arg.toLowerCase(), segment);
  });
}

/**
 * Check if a wrapper command is targeting a relative path (./foo, ../foo).
 */
export function isWrapperRunningRelativePath(segment: string): boolean {
  return checkWrapperArg(segment, (arg) => isFirstTokenRelativePath(arg), true);
}

/** Rendered in place of an option/dependency value no grant can name (see
 *  segmentRunFormUngrantable). */
const UNRESOLVED_DEP = "<unresolved>";

/** A value written as a filesystem location (`/x`, `./x`, `../x`, `~x`) — the
 *  ones whose identity depends on the directory they resolve against. */
const PATH_VALUE_RE = /^(~|\.\.?\/|\/)/;

/** Render one dependency as grant identity: exact value (case-folded) for a
 *  registry package, resolved absolute path for a local source. */
function renderRunDep(dep: UvRunDep, base: string | null | undefined): string {
  if (dep.opaque) return `${dep.flag} ${UNRESOLVED_DEP}`;
  if (dep.flag === "--with") return `--with ${dep.value.toLowerCase()}`;
  // A relative source resolves against the runtime cwd; when that cwd is not
  // knowable (`cd $(…) && uv run …`) the same signature text would name a
  // different file per cwd, so it names nothing at all.
  if (!base) return `${dep.flag} ${UNRESOLVED_DEP}`;
  return `${dep.flag} ${resolveDepSource(dep.value, base)}`;
}

/** Render a non-dependency option value as grant identity. A location is
 *  resolved (and kept case-sensitive — two cases are two files); a URL, a
 *  version, a package name or an enum member is written as it stands. */
function renderRunOption(opt: UvRunOption, base: string | null | undefined): string {
  if (opt.opaque) return `${opt.flag} ${UNRESOLVED_DEP}`;
  if (PATH_VALUE_RE.test(opt.value)) {
    if (!base) return `${opt.flag} ${UNRESOLVED_DEP}`;
    return `${opt.flag} ${resolveDepSource(opt.value, base)}`;
  }
  return `${opt.flag} ${opt.value.toLowerCase()}`;
}

/**
 * The grant-identity items of a uv run form's options — the benign option NAMES
 * (sorted, deduped) plus the VALUES that decide what is downloaded or executed:
 * the dependency flags, `-p`/`--python`, and every option the closed world does
 * not vouch for (`--project /tmp/x`). Every other flag value stays out of
 * signatures, as everywhere else. Sorting and deduping is what makes a grant
 * match a reordered repeat of the same command.
 *
 * Null when `segment` is not a uv run form, is malformed (`--with-requirements`
 * with no value), or has nothing to name — a bare `uv run` keeps the coarse
 * signature (it syncs the project environment from pyproject.toml/uv.lock, which
 * names nothing in the command, so there is nothing to put in the grant;
 * documented in the README).
 */
function runFormItems(segment: string, base?: string | null): { runner: string; items: string[] } | null {
  const flags = uvRunFlags(tokenizeSegmentQuoted(segment));
  if (!flags) return null;
  if (flags.danglingValue) return null; // malformed: uv exits on it, no grant to scope
  if (flags.deps.length === 0 && flags.uvFlags.length === 0
      && flags.pythonValues.length === 0 && flags.otherOptions.length === 0) return null;
  const items = new Set<string>(flags.uvFlags);
  for (const v of flags.pythonValues) items.add(renderRunOption(v, base));
  for (const o of flags.otherOptions) items.add(renderRunOption(o, base));
  for (const dep of flags.deps) items.add(renderRunDep(dep, base));
  return { runner: flags.runner, items: [...items].sort() };
}

/** The dependency-aware signature of a uv run form, or null to fall through
 *  to the coarse package-manager signature (see runFormItems). The runner text
 *  is the form's own (`uvx`, `uv tool run`) — a signature must not name a
 *  command the command did not run. */
export function uvRunSignature(segment: string, base?: string | null): string | null {
  const res = runFormItems(segment, base);
  return res === null ? null : `${res.runner} ${res.items.join(" ")}`;
}

/** uv's run options for a segment, looking THROUGH a pass-through wrapper:
 *  `timeout 60 uv run --with pandas …` and `env FOO=1 uv run …` install exactly
 *  what the inner form says, so the wrapper hides nothing. */
function runFlagsOfSegment(segment: string): UvRunFlags | null {
  const direct = uvRunFlags(tokenizeSegmentQuoted(segment));
  if (direct) return direct;
  const deleg = getDelegatedCommand(segment);
  return deleg ? uvRunFlags(tokenizeSegmentQuoted(deleg.tail)) : null;
}

/** True when a segment (or a form wrapped around it) NAMES options whose value
 *  decides what is installed or executed. Its signature is that option set, so
 *  a coarser grant ("uv run", "timeout uv") must not prefix-match it — the
 *  grant has to name the same set to apply. */
export function segmentNamesRunOptions(segment: string): boolean {
  const flags = runFlagsOfSegment(segment);
  if (!flags) return false;
  return flags.deps.length > 0 || flags.otherOptions.length > 0 || flags.pythonValues.length > 0;
}

/** True when a uv run form cannot be granted at all: an option or dependency
 *  value the shell decides at run time (`--with "$PKG"`, `--project "$D"`, an
 *  unquoted glob), a path value whose cwd is not knowable, or a dangling value.
 *  No Always can vouch for what the value becomes, so the form prompts every
 *  time — and minting a grant for it would only pollute the store (same
 *  reasoning as relative tools). */
export function segmentRunFormUngrantable(segment: string, base?: string | null): boolean {
  // A fetch form whose selected package is decided at run time
  // (`npx -p "$PKG" tsc`) has no package to grant trust for, and a signature
  // keyed on the token text (`npx $PKG`) is a grant keyed on whatever `PKG`
  // happens to be — the same pollution the dependency rule prevents.
  if (segmentFetchPackage(segment)?.opaque === true) return true;
  const flags = runFlagsOfSegment(segment);
  if (!flags) return false;
  if (flags.danglingValue) return true;
  if (flags.deps.some((d) => d.opaque || (d.flag !== "--with" && !base))) return true;
  return [...flags.pythonValues, ...flags.otherOptions].some(
    (o) => o.opaque || (PATH_VALUE_RE.test(o.value) && !base));
}

/** True when a FETCH form's uv options stay inside what package trust covers —
 *  trusting `tsc` must not cover `uvx -p /tmp/evil/python tsc` (an interpreter,
 *  not the package's code) or `uvx --with evil tsc` (an install set). See
 *  config/trusted-scripts uvFetchFormOk. Null-scan (npx/… forms) is true here:
 *  their fetch set is the whole decision. */
export function segmentFetchOptionsOk(segment: string, base: string | null): boolean {
  return uvFetchFormOk(runFlagsOfSegment(segment), base);
}

/**
 * Extract a command signature, stripping redirects and quotes.
 * For pipelines, uses the first command's signature.
 * For package managers, includes the subcommand for granular allow control.
 *
 * `base` is the segment's EFFECTIVE cwd (null = the runtime cwd is not
 * knowable). It resolves the two path-named parts of the identity: `uv run`
 * dependency sources, and a PATH-qualified argv0 (G4) — whether `bin/ls` is a
 * system program or a program in the base depends on where the base is.
 */
export function getCommandSignature(segment: string, base?: string | null): string {
  const firstCmd = splitOnPipe(segment)[0] ?? segment;
  const cleaned = firstCmd
    .replace(SIG_REDIRECT_RE, "")
    .replace(SIG_INPUT_RE, "")
    .trim();
  // The COMMAND POSITION is read from dequoted words: `"rm"`, `$'rm'` and
  // `\rm` all run rm, and an inline `FOO=1` is not the program. The
  // marker-stripped view stays for the ARGUMENT identity below (a quoted
  // argument must not contribute flags or a subcommand).
  const words = tokenizeSegment(cleaned);
  const assignments = words.slice(0, skipEnvPrefixes(words));
  // The environment prefix is part of the invocation (`PATH=…` decides which
  // binary runs, `LD_PRELOAD=…` what it loads), so it is part of the identity —
  // and a grant can only ever cover the same prefix. Lowercased like every
  // other identity part (the signature is a table key, not a path).
  const prefix = assignments.length > 0 ? `${assignments.join(" ").toLowerCase()} ` : "";
  const programWord = (words[assignments.length] ?? "").replace(/^\\+/, "");
  const programName = path.basename(programWord.toLowerCase());
  if (!programName) return prefix.trim();
  const tokens = stripQuotedStrings(cleaned).split(/\s+/);
  const cmdBase = programName;
  // G4: when the command position names a program BY PATH (`bin/ls`,
  // `./node_modules/.bin/npm`, `nice bin/ls`), that location is part of the
  // identity. A qualified program is named by its path AS WRITTEN — folding a
  // path's case folds two different files into one grant — while everything
  // else keeps the folded name the closed sets are keyed on.
  const pos = commandPositionWord(words);
  const qualWord = pos.word.includes("/") && !pos.lookup && !pos.capped
    && classifyArgv0(pos.word, base ?? null) === "qualified" ? pos.word : null;
  // Wrapper/prefix transparency: a wrapped command's signature must name the
  // delegated command, so an "Always" grant on `timeout curl` can't cover
  // `timeout ssh`, and a bare `timeout` grant covers nothing wrapped at all.
  const deleg = resolveDelegatedTokens(words);
  if (deleg?.capped) {
    // Past the unwrap cap the chain names no program. The signature is the
    // first program word alone — never a program name a grant could not see —
    // and the parser has already marked the command position obscured, so this
    // segment is not auto-allowable regardless of what is granted.
    return `${prefix}${cmdBase}`;
  }
  if (deleg && !deleg.lookup) {
    // A wrapped `uv run` keeps its dependency set in the signature: the wrapper
    // is transparent to the grant, the install set it carries is not (a coarse
    // "timeout uv" grant must not vouch for every later `--with`).
    // The inner form is read from the RAW text, not from these stripped tokens:
    // stripQuotedStrings collapses quoted values to `__STR__`, and a quoted pin
    // (`--with "pandas>=2.0"`) has to keep its exact value to be grant identity.
    const wrapped = (deleg.cmd === "uv" || deleg.cmd === "uvx") ? getDelegatedCommand(cleaned) : null;
    const inner = wrapped ? runFormItems(wrapped.tail, base) : null;
    const name = qualWord ?? deleg.cmd;
    // A uv form with a multi-word runner (`timeout uv tool run …`) keeps the
    // runner's tail in the signature: the grant has to name the command that
    // actually runs. Its first word is the delegated name already rendered.
    const runnerTail = inner ? inner.runner.split(/\s+/).slice(1) : [];
    if (inner === null) return `${prefix}${cmdBase} ${name}`;
    return prefix + [cmdBase, name, ...runnerTail, ...inner.items].join(" ");
  }

  // uv's run forms name their ENTIRE install set (registry deps, local
  // sources, the interpreter it may download), so the coarse "uv run"
  // signature let one Always vouch for every later dependency — and the
  // generic flag-name rule did the same for uv's FETCH forms: `uvx -p
  // /tmp/evil/python tsc` had the identity `uvx -p`, so an "Always" stored a
  // grant for an interpreter that is a filesystem location and never named it.
  // The option-aware signature is the grant's identity; see uvRunSignature.
  if (cmdBase === "uv" || cmdBase === "uvx") {
    // uvRunFlags skips the inline assignments itself, so the dependency
    // identity survives `FOO=1 uv run …` (the prefix above keeps it honest).
    const runSig = uvRunSignature(firstCmd, base);
    if (runSig !== null) return `${prefix}${runSig}`;
  }

  // Package managers: include subcommand for granular control
  // npm test → "npm test", npm install → "npm install"
  // npm -v → "npm" (flag only, no subcommand)
  if (PACKAGE_MANAGERS.has(cmdBase)) {
    // Find the subcommand: first non-flag token, skipping values of flags that
    // consume the next token (--prefix /x). Inline values (--prefix=/x) are
    // part of the flag token and skipped with it. The scan starts after the
    // command words (an inline assignment is itself a token).
    for (let i = assignments.length + 1; i < tokens.length; i++) {
      const t = tokens[i];
      if (t.startsWith("-")) {
        if (PM_VALUE_FLAGS.has(t) && !t.includes("=")) i++; // skip the flag's value
        continue;
      }
      return `${prefix}${qualWord ?? cmdBase} ${t}`;
    }
    return `${prefix}${qualWord ?? cmdBase}`; // e.g. "npm" with only flags
  }

  const flags = tokens.slice(1).filter(t => t.startsWith("-")).sort();
  // A qualified program is named by its path (case-true); a system-dir path
  // keeps its written form (`/usr/bin/ls`); a bare name folds to the key form.
  const head = qualWord ?? (programWord.includes("/") ? programWord : cmdBase);
  const named = `${prefix}${head}`;
  return flags.length === 0 ? named : `${named} ${flags.join(" ")}`;
}

/**
 * Check if a tool's exec/pre flag triggers a write operation.
 * Generic helper for find -exec, fd -x, rg --pre, etc.
 *
 * The payload is trusted only against the UNCONDITIONALLY-safe subset, not the
 * auto-allow table: a table entry with an exclusion reason (`git`, `grep`,
 * `sort`, `find`, `timeout`, …) is allowed because the SEGMENT-level checks —
 * egress, git-clean, dangerous-flag, delegation — vet it. None of those run on
 * an exec payload, which sits inside a `find` segment, so table membership
 * there vouches for nothing: `find . -exec git push \;` used to be approved by
 * `git`'s own entry while nothing ever asked whether `git push` was safe.
 */
function checkExecWrite(segment: string, regex: RegExp): boolean {
  for (const match of segment.matchAll(regex)) {
    // The exec'd command may be quoted (`find . -exec 'rm' {} \;` — runtime-
    // verified to delete); strip surrounding quotes so it matches by name.
    const rawCmd = match[1].replace(/^["']+|["']+$/g, "");
    const after = segment.slice(match.index! + match[0].length);
    if (isFirstTokenRelativePath(rawCmd)) return true;
    const cmd = path.basename(rawCmd).toLowerCase();
    const deleg = getDelegatedCommand(`${rawCmd} ${after}`);
    if (deleg) {
      if (isFirstTokenRelativePath(deleg.tail) || isWriteOperation(deleg.cmd, deleg.tail) || !unconditionallySafeCommands.has(deleg.cmd)) {
        return true;
      }
    }
    if (isWriteOperation(cmd, after) || !unconditionallySafeCommands.has(cmd)) return true;
  }
  return false;
}

export function isFindExecWrite(segment: string): boolean {
  return checkExecWrite(segment, FIND_EXEC_RE);
}

export function isFdExecWrite(segment: string): boolean {
  return checkExecWrite(segment, FD_EXEC_RE);
}

export function isRgPreWrite(segment: string): boolean {
  return checkExecWrite(segment, RG_PRE_RE);
}

/** Pre-compiled regex for git clean flags. */
const GIT_CLEAN_FLAGS_RE = /-[a-z]*[fdx][a-z]*/;

/**
 * `git -c name=value` / `--config name=value` inline config values that make
 * git execute a command:
 *   - alias.*=!…      → shell alias: `git st` runs the `!` command
 *   - core.pager=…    → run as pager (tty)
 *   - core.editor=…   → run as editor
 *   - core.sshCommand=… → run instead of ssh
 *   - core.fsmonitor=…  → run on every refresh (unconditional)
 *   - core.askpass=…    → run to prompt for credentials
 *   - core.hooksPath=…  → run hooks from a directory outside the repo
 */
const GIT_DANGEROUS_CONFIG_RE = /^(?:alias\.[^=]+=!|credential\.helper=!|diff\.external=|filter\.[^=]+\.(?:clean|smudge)=|pager\.[^=]+=|interactive\.diffFilter=|sequence\.editor=|core\.(?:pager|editor|sshCommand|fsmonitor|askpass|hooksPath)=)/;

/** True if a `-c`/`--config` value configures git to execute a command. */
function isDangerousGitConfigValue(value: string | undefined): boolean {
  return value !== undefined && GIT_DANGEROUS_CONFIG_RE.test(value);
}

/**
 * `--config-env=<key>=<ENVAR>` is `-c key=$ENVAR` with the value read from the
 * environment — the same exec vectors (`core.fsmonitor`, `core.pager`, …), and
 * `alias.*` is unreadable here (the env value may start with `!`), so every
 * alias key is treated as dangerous. Only the KEY is visible, which is why the
 * key is what gets tested.
 */
function dangerousConfigEnvKey(key: string): boolean {
  if (/^alias\./.test(key)) return true;
  return GIT_DANGEROUS_CONFIG_RE.test(`${key}=`);
}

/** The key of a `--config-env` value (`key=ENVAR`), or undefined when malformed. */
function configEnvKey(value: string | undefined): string | undefined {
  if (value === undefined) return undefined;
  const eq = value.indexOf("=");
  return eq > 0 ? value.slice(0, eq) : undefined;
}

/** True if a git global arg (plus its value token) carries dangerous inline config. */
function hasDangerousInlineConfig(arg: string, next: string | undefined): boolean {
  if (arg === "-c" || arg === "--config") return isDangerousGitConfigValue(next);
  if (arg.startsWith("-c") && !arg.startsWith("-C") && arg.includes("=")) return isDangerousGitConfigValue(arg.slice(2));
  if (arg.startsWith("--config=")) return isDangerousGitConfigValue(arg.slice("--config=".length));
  if (arg === "--config-env") {
    const key = configEnvKey(next);
    return key === undefined ? true : dangerousConfigEnvKey(key);
  }
  if (arg.startsWith("--config-env=")) {
    const key = configEnvKey(arg.slice("--config-env=".length));
    return key === undefined ? true : dangerousConfigEnvKey(key);
  }
  return false;
}

// ── Git subcommand danger handlers ──

/** `git config` flags that modify a config file (write, or run an editor). */
const GIT_CONFIG_WRITE_FLAGS = new Set(["--add", "--unset", "--replace-all", "--remove-section", "--rename-section", "--edit", "-e"]);

/** Read-only trailing flags that may follow the key name. */
const GIT_CONFIG_READ_TAIL_FLAGS = new Set(["--name-only", "--show-origin", "--null", "-z"]);

/**
 * True if `git config` writes a config file (vs. a read like `--list` or
 * `--get name`). Persistent config is a code-execution vector (alias.*=!cmd,
 * core.fsmonitor, core.pager, templateDir hooks) and lives OUTSIDE cwd
 * (~/.gitconfig), so path checks can never catch it — every set form must
 * prompt.
 */
function isGitConfigWrite(subArgs: string[]): boolean {
  if (subArgs.some(a => GIT_CONFIG_WRITE_FLAGS.has(a))) return true;
  // Find the first non-flag token (the key name). Any inline `name=value`
  // token is a set; anything after the key (beyond read-only tail flags) is
  // the value.
  let keyIdx = -1;
  for (let i = 0; i < subArgs.length; i++) {
    const a = subArgs[i];
    if (a.startsWith("-")) continue;
    if (a.includes("=")) return true;
    keyIdx = i;
    break;
  }
  if (keyIdx < 0) return false; // pure read: --list, --get, scoped list, bare flags
  return subArgs.slice(keyIdx + 1).some(a => !GIT_CONFIG_READ_TAIL_FLAGS.has(a));
}

/** `git checkout`/`switch` flags (or operands) that discard uncommitted work:
 *  -f/--force, --discard-changes, -p/--patch (interactive hunk selection),
 *  and a path operand (`--`, `.`, `..`, anything with a slash — resolving a
 *  bare filename that is also a branch is git's own ambiguity, not ours). */
const GIT_DISCARD_FLAG_RE = /^(?:-f|--force|--discard-changes|-p|--patch)$|^-[a-zA-Z]*f[a-zA-Z]*$/;
const isGitPathOperand = (x: string): boolean => x === "--" || x === "." || x === ".." || x.includes("/");

const GIT_DANGER_HANDLERS: Array<{ match: (sub: string, subArgs: string[]) => boolean }> = [
  { match: (sub) => sub === "rm" },
  { match: (sub, a) => sub === "clean" && a.some(x => GIT_CLEAN_FLAGS_RE.test(x)) },
  { match: (sub, a) => sub === "reset" && a.includes("--hard") },
  // ANY push writes to the remote ("any write = prompt"). Force variants
  // additionally rewrite history — GitEvaluator reports those as high.
  { match: (sub) => sub === "push" },
  { match: (sub, a) => sub === "reflog" && a.some(x => x === "expire" || x === "delete") },
  { match: (sub, a) => sub === "gc" && a.some(x => x.startsWith("--prune")) },
  { match: (sub, a) => sub === "config" && isGitConfigWrite(a) },
  // Local-history destruction (3.50.0): verbs and flags that throw away
  // commits, stashes, tags or uncommitted work. The remote-write list above
  // never covered these, so `git checkout -- .`, `git stash clear`, `git
  // branch -D` and `git update-ref -d` auto-allowed through the table.
  { match: (sub, a) => (sub === "checkout" || sub === "switch") && a.some(x => GIT_DISCARD_FLAG_RE.test(x) || isGitPathOperand(x)) },
  { match: (sub) => sub === "restore" },
  { match: (sub, a) => sub === "branch" && a.some(x => x === "--delete" || x === "--force" || /^-[a-zA-Z]*[dDf]/.test(x)) },
  { match: (sub, a) => sub === "tag" && a.some(x => x === "--delete" || x === "--force" || /^-[a-zA-Z]*[df]/.test(x)) },
  { match: (sub, a) => sub === "stash" && a.some(x => x === "drop" || x === "clear") },
  { match: (sub, a) => sub === "worktree" && a[0] === "remove" },
  { match: (sub) => sub === "update-ref" || sub === "filter-branch" || sub === "replace" || sub === "prune" },
];

/**
 * Resolve the git subcommand, skipping the global flags that may precede it
 * (-c value, -C value, --git-dir value, --work-tree value, --config-env value,
 * --exec-path value, --flag=value, attached -C<dir>, and bare global flags like
 * --no-pager). `git -C dir push` → { sub: "push" } — the -C dir is a location,
 * not the subcommand. Inline env assignments are skipped first (`FOO=1 git …`).
 */
export function parseGitSubcommand(segment: string): { sub: string; subArgs: string[] } | null {
  return parseGitSubcommandWords(tokenizeSegment(segment));
}

function parseGitSubcommandWords(args: string[]): { sub: string; subArgs: string[] } | null {
  const start = skipEnvPrefixes(args);
  if (args.length < start + 2) return null;
  let subIdx = start + 1;
  while (subIdx < args.length) {
    const arg = args[subIdx];
    if (GIT_GLOBAL_FLAGS.has(arg)) {
      // -c and -C take a value argument
      if (arg === "-c" || arg === "-C") subIdx++;
      // --git-dir, --work-tree take a value argument
      if (arg.startsWith("--git-dir") || arg.startsWith("--work-tree")) subIdx++;
      subIdx++;
      continue;
    }
    // --exec-path / --config-env may carry their value in the next token.
    if (arg === "--exec-path" || arg === "--config-env") { subIdx += 2; continue; }
    // --flag=value form (e.g., --git-dir=x)
    if (arg.startsWith("--") && arg.includes("=")) {
      subIdx++;
      continue;
    }
    // Attached short values: -C<dir>, -c<name=value> (git accepts both).
    if (/^-[cC].+/.test(arg)) { subIdx++; continue; }
    break;
  }
  if (subIdx >= args.length) return null;
  return { sub: args[subIdx].toLowerCase(), subArgs: args.slice(subIdx + 1) };
}

/**
 * Check if a git command is dangerous.
 * Used by segment-analysis.ts (pipeline loop) and GitEvaluator.
 * Skips inline env assignments and global flags to find the actual subcommand.
 */
export function isGitDangerous(segment: string): boolean {
  // Quote-aware tokenization: `git -c "alias.st=!rm /tmp/x" st` must be seen
  // as -c + one value token, not split on the space inside the quotes.
  const words = tokenizeSegment(segment);
  const start = skipEnvPrefixes(words);
  const args = words.slice(start);
  if (args.length < 2) return false;

  // Inline config that executes code is dangerous regardless of subcommand —
  // scanned across all args (a -c after the subcommand is invalid git, but
  // flagging it is the safe direction).
  for (let i = 1; i < args.length; i++) {
    if (hasDangerousInlineConfig(args[i], args[i + 1])) return true;
    // `--exec-path` decides which `git-<sub>` binary runs: the bare form only
    // prints the path (harmless), a value — inline or in the next token — sets
    // it and is arbitrary code execution.
    if (args[i].startsWith("--exec-path=") || (args[i] === "--exec-path" && args[i + 1] !== undefined)) return true;
  }

  const parsed = parseGitSubcommandWords(args);
  if (!parsed) return false;
  return GIT_DANGER_HANDLERS.some(h => h.match(parsed.sub, parsed.subArgs));
}


