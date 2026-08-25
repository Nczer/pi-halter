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
export function resolveCdTarget(seg: BashSegment, cwd: CwdBase): CdResolution {
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
  // Loop-bound variable (`cd $d` with `d` bound by an enclosing for loop):
  // thread a known local base when the in-list resolves to exactly ONE real
  // directory — the runtime base is then that directory exactly. Zero
  // candidates → the cd always fails at runtime (unchanged). Multiple distinct
  // directories → keep the conservative unknown: a set-valued base would need
  // per-value path checks, which the current path pipeline doesn't do.
  if (seg.loopCdInList) {
    const cands = resolveLoopCdCandidates(seg.loopCdInList, cwd);
    if (cands === null) return { kind: "unknown" };
    if (cands.length === 0) return { kind: "unchanged" };
    if (cands.length === 1) return { kind: "thread", dir: cands[0] };
    return { kind: "unknown" };
  }
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
 * The set of directories a marker segment's UNKNOWN base could be at runtime
 * (the /dspa floor's D7 bound — dspa-gate.ts).
 *
 * Soundness: a marker exists because trackEffectiveCwd lost the base. The
 * base is only ever (a) the session cwd, (b) the target of a LITERAL cd that
 * existed when the gate stat'd it, or (c) nowhere knowable — an UNRESOLVABLE
 * cd (variable, glob, `cd -`, …) makes it (c) and it stays (c): no later cd
 * can re-narrow it (even a literal one — the unresolvable side may still be
 * the runtime base if the later cd fails). So:
 *  - any unresolvable persistent cd → `unbounded: true` (the base could be
 *    ANYWHERE — the caller must fail closed, not guess);
 *  - otherwise the base ∈ {session cwd} ∪ {each literal cd's target}: a cd
 *    that could fail at runtime (TOCTOU) leaves its pre-cd base possible,
 *    so candidates only ever grow. Proved-failed cds (target missing) and
 *    subshell/pipeline/backgrounded cds change nothing.
 *
 * Only persistent top-level cds participate: a ( ) subshell's cd dies with
 * the child, a pipeline stage's cd runs in a subshell, a backgrounded cd is
 * `cd … &` (subshell). resolveCdTarget already classifies those as
 * "unchanged"; the depth/background filter keeps the scan honest for them.
 */
export function cdBaseBounds(
  segments: BashSegment[],
  sessionCwd: string,
): { unbounded: boolean; candidates: string[] } {
  const candidates: string[] = [sessionCwd];
  let base: CwdBase = sessionCwd;
  let unbounded = false;
  for (const seg of segments) {
    if ((seg.subshellDepth ?? 0) !== 0 || seg.backgrounded) continue;
    if (unbounded) continue;
    const r = resolveCdTarget(seg, base);
    if (r.kind === "unknown") unbounded = true;
    else if (r.kind === "thread") {
      base = r.dir;
      if (!candidates.includes(r.dir)) candidates.push(r.dir);
    }
  }
  return { unbounded, candidates };
}

/**
 * Effective cwd for each segment (before that segment's own cd takes effect).
 * null = unknown base (a non-literal cd or a `||` branch made the runtime
 * directory statically unresolvable).
 *
 * Scoping: `( )` subshells run in a child process — a cd inside sets only the
 * subshell's local base and must NEVER persist into the outer scope (runtime:
 * `(cd /x && ls); pwd` still prints the outer cwd). Bases are kept in a
 * per-depth stack indexed by BashSegment.subshellDepth: entering a subshell
 * pushes a copy of the enclosing base (fork inherits cwd), leaving pops back.
 * Top-level behavior is unchanged.
 *
 * Transitions (per segment, at its depth):
 *   • precedingOp `||`     → unknown BEFORE recording — the branch segment's
 *     own runtime cwd is unresolvable (the left side may or may not have run,
 *     and a left cd may or may not have succeeded)
 *   • backgrounded segment → no change (subshell cd doesn't persist)
 *   • resolvable cd        → thread (absolute literal recovers an unknown base)
 *   • non-literal cd       → unknown (sticky until an absolute literal cd)
 */
export function trackEffectiveCwd(segments: BashSegment[], baseCwd: string): CwdBase[] {
  const result: CwdBase[] = [];
  const bases: CwdBase[] = [path.resolve(expandTilde(baseCwd))];
  // Base at the start of the current (;) statement, per depth — the || freeze anchor.
  const stmtStarts: CwdBase[] = [bases[0]];
  let depth = 0;
  for (const seg of segments) {
    const d = seg.subshellDepth ?? 0;
    // Subshells open/close in document (DFS) order and a segment only exists
    // if every enclosing node produced it, so depth changes are well-formed.
    while (depth < d) { bases.push(bases[depth]); stmtStarts.push(bases[depth]); depth++; }
    while (depth > d) { bases.pop(); stmtStarts.pop(); depth--; }
    if (seg.precedingOp === ";") stmtStarts[depth] = bases[depth];
    // The branch segment's runtime cwd is wherever the statement left it —
    // branch-dependent (unknown) only if a cd earlier in the statement could
    // have changed the base. No cd / provably-failed cd → the tracked base
    // holds (the statement's runtime cwd is exactly the tracked one).
    if (seg.precedingOp === "||" && bases[depth] !== stmtStarts[depth]) bases[depth] = null;
    result.push(bases[depth]);
    if (seg.backgrounded) continue;
    const r = resolveCdTarget(seg, bases[depth]);
    if (r.kind === "thread") bases[depth] = r.dir;
    else if (r.kind === "unknown") bases[depth] = null;
  }
  return result;
}

/** Display marker for paths that resolve against an unknown effective cwd. */
export const UNKNOWN_CWD_MARKER = "<unresolved-cwd>";

/**
 * Resolve a for-loop in-list to the set of REAL directories a `cd $var` can
 * land in (realpath — symlinked in-list entries resolve to their target).
 * Returns null (fail closed) when a token makes the set statically
 * unknowable: runtime expansion ($, backtick), expansion inside double
 * quotes, a relative token under an unknown base, an unexpandable glob, or
 * a glob with too many matches. A token whose values are missing or not
 * directories is dropped — the cd fails at runtime for those values.
 */
function resolveLoopCdCandidates(inList: string[], base: CwdBase): string[] | null {
  const dirs = new Set<string>();
  for (const raw of inList) {
    let t = raw;
    const q = t.match(/^(['"])(.*)\1$/);
    if (q) {
      if (q[1] === '"' && /[$`]/.test(q[2])) return null; // expansion inside double quotes
      t = q[2];
    }
    if (/[`$]/.test(t)) return null; // runtime expansion — target not knowable
    if (t.startsWith("~")) t = expandTilde(t);
    let resolved: string;
    if (path.isAbsolute(t)) {
      resolved = t;
    } else {
      if (base === null) return null; // relative token under unknown base
      resolved = path.resolve(base, t);
    }
    if (resolved.search(/[*?[[]/) !== -1) {
      const pattern = resolved.endsWith("/") ? resolved.slice(0, -1) : resolved;
      let matches: string[];
      try {
        matches = fs.globSync(pattern);
      } catch {
        return null; // bad pattern — fail closed
      }
      if (matches.length > 4096) return null; // too many to verify — fail closed
      for (const m of matches) {
        try {
          const r = fs.realpathSync(m);
          if (fs.statSync(r).isDirectory()) dirs.add(r);
        } catch { /* missing / not a dir — the cd fails for that value */ }
      }
    } else {
      try {
        const r = fs.realpathSync(resolved);
        if (fs.statSync(r).isDirectory()) dirs.add(r);
      } catch { /* missing / not a dir — the cd fails for that value */ }
    }
  }
  return [...dirs];
}

/** Leading env-assignment prefix (VAR=x / _VAR=x) — not the command itself. */
const ENV_ASSIGN_RE = /^[A-Za-z_][A-Za-z0-9_]*=/;

/** Path-aware commands that operate on the cwd when given no file args. */
const CWD_DEFAULT_COMMANDS = new Set(["ls", "find", "du"]);

// Redirect operators. Output: [N]>, [N]>>, [N]&>, [N]>&(. Input: [N]< — but
// not the heredoc forms (<< / <<<), which carry DATA, not a file target.
// The target may be glued to the operator (2>/dev/null) or a separate token.
// Shared with dspa-gate's quote-aware self-write scan (checkRmTargets).
export const OUT_REDIRECT_RE = /^(\d{0,1}(?:&?>|>&))(.*)$/;
export const IN_REDIRECT_RE = /^(\d{0,1}<)(?!<)(.*)$/;
export const BARE_REDIRECT_RE = /^(?:\d{0,1}(?:&?>|>&)|\d{0,1}<)$/;

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
    if (m) {
      // `2>&1` parses as target "&1" — an fd reference, not a file. The
      // startsWith("&") check below skips it (log FP: counted as a bare
      // redirect target, adding a spurious base access / `.` outside-dir).
      target = m[2] !== "" ? m[2] : (stage[i + 1] ?? null);
    } else if (BARE_REDIRECT_RE.test(tok)) target = stage[i + 1] ?? null;
    if (target === null || target.startsWith("&")) continue; // fd duplication (2>&1, > &1)
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
        // Empty target (`> file`) or fd reference (2>&1): no file argument.
        if (m[2] === "" || m[2].startsWith("&")) continue;
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
    // String join, NOT path.join: join normalizes `..` so the marker escapes
    // (`<unresolved-cwd>/../x` → `../x`) and a bare relative token lands in
    // the outside set — displayed as its dirname (`.`, `node_modules/.bin`).
    // Keeping the marker prefix intact makes the prompt read `outside <unresolved-cwd>`.
    out.push(base === null
      ? (rel ? `${UNKNOWN_CWD_MARKER}/${rel.replace(/^\.\//, "")}` : UNKNOWN_CWD_MARKER)
      : path.resolve(base, rel));
  }
  return out;
}
