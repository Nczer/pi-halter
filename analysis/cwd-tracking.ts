import os from "node:os";
import path from "node:path";
import fs from "node:fs";
import { expandTilde } from "./path-util";
import { tokenizeSegment } from "./tokenizer";
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
//   • `||` makes the base UNKNOWN — the runtime cwd is branch-dependent (a
//     failed left cd lets the right branch run), so it is statically
//     unresolvable. Note a literal left cd to a NONEXISTENT dir fails at
//     runtime, so the right branch IS reachable — freezing at the left dir
//     would be a bypass.
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
  if (tokens[0]?.toLowerCase() !== "cd") return { kind: "unchanged" };

  // cd accepts only -L, -P and -- plus ONE target. Multiple targets or an
  // unexpected flag make bash error (`cd: too many arguments`) — cd fails,
  // so the cwd does not change.
  let target: string | null = null;
  let targetCount = 0;
  for (const t of tokens.slice(1)) {
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
  for (const seg of segments) {
    if (seg.precedingOp === "||") cwd = null;
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
