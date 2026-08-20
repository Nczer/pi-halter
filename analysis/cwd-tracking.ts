import os from "node:os";
import path from "node:path";
import fs from "node:fs";
import { expandTilde } from "./path-util";
import { tokenizeSegment } from "./tokenizer";
import { pathAwareCommands } from "../config";
import type { BashSegment } from "./bash-parser";

// ── cwd tracking across `cd` ───────────────────────────────────────────────
//
// Top-level segments in a single bash invocation run sequentially in the same
// shell, so a `cd <dir>` changes the effective working directory for every
// later segment. Without threading, relative paths in later segments are
// analyzed against the session cwd, which
//   (a) defeats the trusted-script bypass for the standard
//       `cd <skill-dir> && uv run --with <deps> python scripts/x.py`
//       invocation (script resolves outside the skills dir → uv flagged), and
//   (b) can hide outside-cwd access: `cd /tmp && cat ./secret` resolves
//       ./secret against the session cwd, never flagged as outside.
//
// The effective base is stateful: known(dir) or UNKNOWN (null).
// Every uncertainty resolves conservatively — the two directions of error are
// not symmetric (over-suppression is unrecoverable, over-surfacing is a prompt):
//   • a cd whose target cannot be determined exactly ($VAR, glob, cd -) makes
//     the base UNKNOWN — a later relative path could resolve ANYWHERE, so it
//     is flagged for approval rather than resolved against a guessed directory.
//   • `||` makes the base UNKNOWN iff the current (;) statement could have
//     changed it: the branch segment's runtime cwd is then branch-dependent
//     (a left cd may or may not have run). A statement without cds — or with
//     only provably-failed cds — keeps its tracked base: `ls a || ls b` really
//     does run in the session cwd, and freezing it would over-flag bare names
//     that resolve inside cwd.
//   • a backgrounded cd runs in a subshell and does not persist — no change.
//   • a literal cd to a nonexistent dir cannot succeed — no change (under &&
//     nothing after it runs; under ; the cwd is untouched).
//   • an absolute literal cd RECOVERS an unknown base (runtime cwd becomes
//     exactly that dir, independent of history); a relative literal cd on an
//     unknown base stays unknown.
// Failing to thread preserves today's behavior (prompt), never false trust.

/** Per-segment effective base: the known directory, or null when unknown. */
export type CwdBase = string | null;

type CdResolution =
  | { kind: "thread"; dir: string } // literal target that exists → base becomes dir
  | { kind: "unknown" }             // target not exactly determinable → base unknown
  | { kind: "unchanged" };          // not a cd, or the cd cannot succeed at runtime

/** Strip backslash escapes from a shell word (\X → X) so escaped literal
 *  targets (`cd /tmp/ha\lt`) resolve to the same directory bash cd's into. */
function stripEscapes(text: string): string {
  let result = "";
  for (let i = 0; i < text.length; i++) {
    if (text[i] === "\\" && i + 1 < text.length) {
      result += text[i + 1];
      i++;
    } else {
      result += text[i];
    }
  }
  return result;
}

/**
 * Resolve the target directory of a `cd` segment relative to the current base.
 * `cwd === null` means the base is already unknown (relative targets stay
 * unknown; absolute literals recover).
 */
function resolveCdTarget(seg: BashSegment, cwd: CwdBase): CdResolution {
  // Pipeline stages and subshells run in a subshell — their cd does not
  // persist into subsequent segments.
  if (seg.hasSubshell) return { kind: "unchanged" };
  if (seg.ops.includes("|") || seg.ops.includes("|&")) return { kind: "unchanged" };

  const tokens = tokenizeSegment(seg.text);
  // Skip leading env-assignment prefixes (VAR=x cd /tmp — the assignment is
  // not the command).
  let ti = 0;
  while (ti < tokens.length && ENV_ASSIGN_RE.test(tokens[ti])) ti++;
  if (tokens[ti]?.toLowerCase() !== "cd") return { kind: "unchanged" };

  // cd accepts only -L, -P and -- plus ONE target. Multiple targets or an
  // unexpected flag make bash error (`cd: too many arguments`) — cd fails,
  // so the cwd does not change.
  let target: string | null = null;
  let targetCount = 0;
  for (const t of tokens.slice(ti + 1)) {
    if (t === "--" || t === "-L" || t === "-P") continue;
    // `cd -` → OLDPWD: `-` is a target here, not a flag (checked below).
    if (t !== "-" && t.startsWith("-")) return { kind: "unchanged" };
    // $(…)` / backtick in a target — the tokenizer may split the substitution
    // into several tokens, which would read as "too many arguments" (unchanged)
    // when the runtime cd actually succeeds. Command substitution → unknown.
    if (/\$\(|`/.test(t)) return { kind: "unknown" };
    target = stripEscapes(t);
    targetCount++;
  }
  if (targetCount > 1) return { kind: "unchanged" };

  // Bare `cd` → $HOME (resolvable regardless of the current base).
  if (target === null) return { kind: "thread", dir: os.homedir() };
  // `cd -` → OLDPWD — not trackable.
  if (target === "-") return { kind: "unknown" };
  // Globs, $VAR / $(…) / backtick expansions can't be resolved at gate time.
  if (/[?*[\]$`]/.test(target)) return { kind: "unknown" };

  const expanded = expandTilde(target);
  // Relative literal on an unknown base: runtime dir is <unknown>/<rel>.
  if (!path.isAbsolute(expanded) && cwd === null) return { kind: "unknown" };

  const resolved = path.resolve(cwd ?? "/", expanded);
  try {
    if (!fs.statSync(resolved).isDirectory()) return { kind: "unchanged" };
  } catch {
    // cd fails at runtime: under && nothing after it runs; under ; the next
    // command keeps the OLD cwd — exactly what "unchanged" preserves.
    return { kind: "unchanged" };
  }
  return { kind: "thread", dir: resolved };
}

/**
 * Effective cwd for each top-level segment (before that segment's own cd
 * takes effect). null = unknown base (a non-literal cd or a `||` branch made
 * the runtime directory statically unresolvable).
 *
 * Transitions (per segment):
 *   • precedingOp `||`     → unknown BEFORE recording — the branch segment's
 *     own runtime cwd is unresolvable (the left side may or may not have run,
 *     and a left cd may or may not have succeeded)
 *   • backgrounded segment → no change (subshell cd doesn't persist)
 *   • resolvable cd        → thread (absolute literal recovers an unknown base)
 *   • non-literal cd       → unknown (sticky until an absolute literal cd)
 */
export function trackEffectiveCwd(segments: BashSegment[], baseCwd: string): CwdBase[] {
  const result: CwdBase[] = [];
  let cwd: CwdBase = path.resolve(expandTilde(baseCwd));
  // Base at the start of the current (;) statement — the || freeze anchor.
  let stmtStart: CwdBase = cwd;
  for (const seg of segments) {
    if (seg.precedingOp === ";") stmtStart = cwd;
    // The branch segment's runtime cwd is wherever the statement left it —
    // branch-dependent (unknown) only if a cd earlier in the statement could
    // have changed the base. No cd / provably-failed cd → the tracked base
    // holds (the statement's runtime cwd is exactly the tracked one).
    if (seg.precedingOp === "||" && cwd !== stmtStart) cwd = null;
    result.push(cwd);
    if (seg.backgrounded) continue;
    const r = resolveCdTarget(seg, cwd);
    if (r.kind === "thread") cwd = r.dir;
    else if (r.kind === "unknown") cwd = null;
  }
  return result;
}

/** Display marker for paths that resolve against an unknown effective cwd. */
export const UNKNOWN_CWD_MARKER = "<unresolved-cwd>";

/** Leading env-assignment prefix (VAR=x / _VAR=x) — not the command itself. */
const ENV_ASSIGN_RE = /^[A-Za-z_][A-Za-z0-9_]*=/;

/** Path-aware commands that operate on the cwd when given no file args. */
const CWD_DEFAULT_COMMANDS = new Set(["ls", "find", "du"]);

// Redirect operators. Output: [N]>, [N]>>, [N]&>, [N]>&(. Input: [N]< — but
// not the heredoc forms (<< / <<<), which carry DATA, not a file target.
// The target may be glued to the operator (2>/dev/null) or a separate token.
const OUT_REDIRECT_RE = /^(\d{0,1}(?:&?>|>&))(.*)$/;
const IN_REDIRECT_RE = /^(\d{0,1}<)(?!<)(.*)$/;
const BARE_REDIRECT_RE = /^(?:\d{0,1}(?:&?>|>&)|\d{0,1}<)$/;

/** Token names a location resolvable (or already marker-flagged) by the path set. */
function isResolvableTarget(t: string): boolean {
  return t.startsWith("/") || t.startsWith("~") ||
    t === "$HOME" || t.startsWith("$HOME/") || t === "${HOME}" || t.startsWith("${HOME}/") ||
    t.startsWith("./") || t.startsWith("../") || (t.includes("..") && t.includes("/")) ||
    t.includes("$") || t.includes("`");
}

/**
 * Subshell / pipeline / group-list segments: an INNER cd sets a local base
 * for the rest of the segment. The top-level state machine ignores inner cds
 * (a subshell cwd does not persist), so the access check looks inside:
 * (cd /var && ls) lists /var. The local base starts at the outer base and is
 * updated by each inner cd (literal → thread; nonexistent literal → no
 * change; non-literal → unknown). Any path-aware command inside the segment
 * then operates under that local base. Residual: unspaced operator joins
 * (`(cd /var&&ls)`) defeat the token scan — the parser sees them, this
 * scan does not.
 */
function subshellBaseAccess(tokens: string[], base: CwdBase): string | null {
  let localBase: CwdBase = base;
  let hasAccess = false;
  let i = 0;
  while (i < tokens.length) {
    const t = tokens[i];
    if (ENV_ASSIGN_RE.test(t)) { i++; continue; }
    const cmd = path.basename(t).toLowerCase();
    if (cmd === "cd" || cmd === "pushd" || cmd === "popd") {
      i++;
      let target: string | null = null;
      let invalid = false;
      while (i < tokens.length) {
        const nt = tokens[i];
        if (nt === "--" || nt === "-L" || nt === "-P") { i++; continue; }
        if (nt !== "-" && nt.startsWith("-")) { invalid = true; break; }
        if ([";", "&&", "||", "|", "|&", "&", "(", ")"].includes(nt)) break;
        target = stripEscapes(nt);
        i++;
        break;
      }
      if (invalid) localBase = null;
      else if (target === null) localBase = os.homedir(); // bare cd → $HOME
      else if (target === "-" || /\$\(|`/.test(target) || /[?*\[\]$]/.test(target)) localBase = null;
      else {
        const expanded = expandTilde(target);
        if (path.isAbsolute(expanded)) {
          try {
            if (fs.statSync(expanded).isDirectory()) localBase = expanded;
            // nonexistent: the inner cd fails — localBase unchanged
          } catch { /* unchanged */ }
        } else if (localBase !== null) {
          localBase = path.resolve(localBase, expanded);
        } else {
          localBase = null;
        }
      }
      continue;
    }
    if (pathAwareCommands.has(cmd)) hasAccess = true;
    i++;
  }
  if (!hasAccess) return null;
  return localBase === null ? UNKNOWN_CWD_MARKER : localBase;
}

/**
 * The filesystem target a segment falls back to when it names no resolvable
 * path of its own: the directory it runs under.
 *
 * parseCommand does not collect `cd` targets (a cd performs no file access),
 * so the outside-cwd bar for "what happens under a threaded base" lives here.
 * A path-aware segment whose first-stage tokens name no resolvable target
 * (`/x`, `~/x`, closed-set $HOME, `./x`, `../x`, or an expansion — the last
 * already marker-flagged by the parser) operates on the base itself:
 * `cd /var/tmp && ls`, `cd $D && find .`, `cd /var/tmp && cat main.txt`.
 * Bare names under an outside base are exactly the access the
 * directory-granularity approval covers, so they do not suppress the flag.
 * No-arg commands only flag when they default to the cwd (ls, find) —
 * stream readers (cat, wc, head, …) read stdin and touch no directory.
 * Likewise a redirect to a bare name (`cd /var/tmp && echo x > out.txt`)
 * writes the base even when the command is not path-aware — bare redirect
 * targets are not path candidates, so the path set never sees them.
 * Subshell/pipeline/group segments are scanned for an inner cd (see
 * subshellBaseAccess). Returns the base (or the unknown-cwd marker), or null
 * when the segment has a resolvable/opaque target of its own (already in the
 * path set) or performs no directory access (e.g. `echo`, `pwd`, `wc -l`).
 */
export function baseAccessPath(seg: BashSegment, base: CwdBase): string | null {
  const tokens = tokenizeSegment(seg.text);
  let ti = 0;
  while (ti < tokens.length && ENV_ASSIGN_RE.test(tokens[ti])) ti++;
  const first = tokens[ti] ? path.basename(tokens[ti]).toLowerCase() : "";

  if (seg.hasSubshell || first === "(" || first === "{") {
    return subshellBaseAccess(tokens, base);
  }

  // Only the first pipeline stage targets the base; later stages read stdin.
  // (`;`/`&&`/`||` already split into separate segments.)
  const stage: string[] = [];
  for (const t of tokens.slice(ti + 1)) {
    if (t === "|" || t === "|&") break;
    stage.push(t);
  }

  const pathAware = first !== "" && pathAwareCommands.has(first);

  // Redirect to a bare name reads/writes the base (see above).
  let bareRedirectTarget = false;
  for (let i = 0; i < stage.length; i++) {
    const tok = stage[i];
    let target: string | null = null;
    const m = tok.match(OUT_REDIRECT_RE) ?? tok.match(IN_REDIRECT_RE);
    if (m) target = m[2] !== "" ? m[2] : (stage[i + 1] ?? null);
    else if (BARE_REDIRECT_RE.test(tok)) target = stage[i + 1] ?? null;
    if (target === null) continue;
    if (!isResolvableTarget(target)) bareRedirectTarget = true;
  }

  if (!pathAware && !bareRedirectTarget) return null;

  if (pathAware) {
    let sawBareArg = false;
    for (const token of stage) {
      if (BARE_REDIRECT_RE.test(token)) continue; // bare operator; target scanned separately
      let t = token;
      const m = t.match(OUT_REDIRECT_RE) ?? t.match(IN_REDIRECT_RE);
      if (m) {
        if (m[2] === "") continue;
        t = m[2]; // glued target (2>/dev/null)
      }
      // Flag with an embedded value: the VALUE is the target (--file=/x).
      if (t.startsWith("-")) {
        const eq = t.indexOf("=");
        if (eq === -1 || eq >= t.length - 1) continue; // bare flag / empty value
        t = t.slice(eq + 1);
      }
      if (isResolvableTarget(t)) return null; // resolvable (or marker-flagged) target of its own
      sawBareArg = true;
    }
    if (sawBareArg) return base === null ? UNKNOWN_CWD_MARKER : base;
    // No file args: only cwd-defaulting commands access the directory.
    return CWD_DEFAULT_COMMANDS.has(first) ? (base === null ? UNKNOWN_CWD_MARKER : base) : null;
  }
  return base === null ? UNKNOWN_CWD_MARKER : base;
}

/**
 * Tokens whose filesystem location depends on the effective cwd:
 * `./x`, `../x` (and ..-bearing relatives) and the statically resolvable
 * `$PWD` / `${PWD}` forms (closed set — `$PWD` means "wherever the cd chain
 * left us"; any other expansion is a computed path and stays opaque).
 * `rel` is the cwd-relative remainder (empty string = the directory itself).
 */
interface CwdDependentToken {
  readonly isPwd: boolean;
  readonly rel: string;
}

function cwdDependentTokens(seg: BashSegment): CwdDependentToken[] {
  const out: CwdDependentToken[] = [];
  for (const token of tokenizeSegment(seg.text)) {
    let t = token;
    if (t.startsWith("-")) {
      const eq = t.indexOf("=");
      if (eq === -1 || eq >= t.length - 1) continue; // bare flag or empty value
      t = t.slice(eq + 1);
    }
    // Only cwd-dependent tokens need re-resolving: ./x, ../x, $PWD/x.
    // Absolute and ~/ paths resolve identically under any cwd.
    if (t === "$PWD" || t === "${PWD}") {
      out.push({ isPwd: true, rel: "" });
      continue;
    }
    if (t.startsWith("$PWD/") || t.startsWith("${PWD}/")) {
      out.push({ isPwd: true, rel: t.slice(t.indexOf("/") + 1) });
      continue;
    }
    if (t.startsWith("./") || t.startsWith("../") || (t.includes("..") && t.includes("/"))) {
      out.push({ isPwd: false, rel: t });
    }
  }
  return out;
}

/**
 * Re-resolve a segment's cwd-dependent path tokens against its effective base.
 * parseCommand resolves relative tokens against the session cwd, so in
 * post-`cd` segments they land in the wrong place and outside-cwd approval
 * never sees the real runtime location. With `base === null` (unknown base)
 * the tokens resolve to a marker path that is outside every allowed dir —
 * forcing path approval, which is the only safe outcome when the runtime
 * location is unresolvable.
 *
 * `skipDotPaths` — when the base equals the session cwd, parseCommand already
 * resolved ./../ tokens against it; collect only the $PWD tokens it never saw.
 */
export function reResolveCwdDependentPaths(
  seg: BashSegment,
  base: CwdBase,
  opts?: { skipDotPaths?: boolean },
): string[] {
  const out: string[] = [];
  for (const { isPwd, rel } of cwdDependentTokens(seg)) {
    if (opts?.skipDotPaths && !isPwd) continue;
    out.push(base === null
      ? (rel ? path.join(UNKNOWN_CWD_MARKER, rel) : UNKNOWN_CWD_MARKER)
      : path.resolve(base, rel));
  }
  return out;
}
