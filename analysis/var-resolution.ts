import path from "node:path";
import { expandTilde, OPAQUE_VAR_DIR } from "./path-util";
import { resolvePathReal } from "./path-analysis";
import { isCwdLocalSubstitution } from "./cwd-local";
import { UNKNOWN_CWD_MARKER } from "./cwd-tracking";
import type { BashSegment, OpaqueRef } from "./bash-parser";

/**
 * Opaque-reference resolution — the dataflow layer the `<unresolved-var>`
 * marker used to hide behind.
 *
 * The parser emits an OpaqueRef for every expansion in path position it
 * cannot resolve on its own. This module binds what the command's own text
 * proves, against the effective-cwd threading (cwd-tracking):
 *
 *  - visible local assignments (`f=x; cat $f`, scoped: a depth-0 segment sees
 *    the assignments before it; a ( ) subshell inherits only those made
 *    before the subshell started — `(f=x; cat $f)` leaks nothing out and
 *    the outer `cat $f` stays unbound);
 *  - `${NAME:-default}` defaults (the command's stated fallback);
 *  - cwd-local values (whole-value `$(find …)` substitutions, see cwd-local)
 *    and cwd-local loop in-lists (bare names / globs / `$(find …)` words)
 *    bound to the segment's EFFECTIVE base — the base must be proven known
 *    (unknown → sentinel, never a guess);
 *  - pinned prefixes: `prefix/$var` where the in-list is bounded (no `..`,
 *    no expansion) — every expansion lands under the prefix dir.
 *
 * A reference that resolves inside the session base (cwd + allowed roots +
 * granted dirs) is DROPPED — the runtime location is proven, no approval
 * needed. A reference that resolves outside lands as a CONCRETE path (the
 * prompt names the real dir, and one Always-for-dir makes later runs pass).
 * Everything else stays a SENTINEL (the marker forces approval; the prompt
 * shows the token and, when the token pins a static prefix, that prefix).
 *
 * Invariants (why the inside-drop is safe): a literal value is taken only
 * from a variable assigned exactly ONCE (no reassignment ambiguity); a
 * cwdLocal value's base is the exact runtime cwd (trackEffectiveCwd is
 * proven, not guessed); a bounded in-list word cannot contain `..` or an
 * expansion (the value is exactly one in-list word). Any doubt → sentinel.
 */

/** A shell assignment the resolver may use. */
export interface ShellAssignment {
  name: string;
  /** Raw value, surrounding quotes intact (the resolver strips one pair). */
  value: string;
  /** Number of segments emitted at the assignment's document position; a
   *  reference in segment r sees it iff `at` is within r's visibility bound. */
  at: number;
}

/** A reference the analysis could not statically bind. */
export interface UnresolvedRef {
  /** The token as written ($f, ${d:-x}, /prefix/$f, …). */
  token: string;
  /** "var": the value is not statically knowable; "base": the cwd-local
   *  value's base cwd is unknown. */
  reason: "var" | "base";
  /** Marker path pushed into the command's path set (forces approval). */
  marker: string;
}

export interface OpaqueResolution {
  /** Concrete paths that resolved OUTSIDE (real, resolved). */
  paths: string[];
  /** References that stayed unbound (their markers join the path set). */
  unresolved: UnresolvedRef[];
}

/** What a value expression stands for. */
type SubResult = { kind: "literal"; value: string } | { kind: "cwdLocal" } | null;

/** A $-form that cannot be bounded (globs, array subscripts, other ${…}
 *  forms, a leftover $). */
const UNRESOLVED_RE = /[?*$`\[{}]/;

/** Parse a `${NAME}` / `${NAME:-default}` expression (balanced braces).
 *  Other ${…} forms (arithmetic, ${#x}, …) → null. */
function parseVarExpr(v: string, start: number): { name: string; def: string | null; end: number } | null {
  if (v.slice(start, start + 2) !== "${") return null;
  let i = start + 2;
  const nameStart = i;
  while (i < v.length && /[A-Za-z0-9_]/.test(v[i])) i++;
  if (i === nameStart) return null;
  const name = v.slice(nameStart, i);
  if (v[i] === "}") return { name, def: null, end: i + 1 };
  if (v.slice(i, i + 2) === ":-") {
    let depth = 1;
    let j = i + 2;
    let defEnd = -1;
    while (j < v.length) {
      if (v[j] === "{") depth++;
      else if (v[j] === "}") {
        depth--;
        if (depth === 0) {
          defEnd = j;
          break;
        }
      }
      j++;
    }
    if (defEnd < 0) return null;
    return { name, def: v.slice(i + 2, defEnd), end: defEnd + 1 };
  }
  return null;
}

/** The value a reference stands for: the local assignment when unambiguous
 *  (exactly one), else the `:-` default (the command's stated fallback). */
function resolveRef(
  name: string,
  def: string | null,
  assignments: Map<string, string[]>,
  depth: number,
): SubResult {
  const values = assignments.get(name);
  if (values && values.length === 1) return resolveValue(values[0], depth + 1, assignments);
  if (def !== null) return resolveValue(def, depth + 1, assignments);
  return null; // env var with no local assignment and no default
}

/** Resolve a value expression: strip one outer quote pair (single quotes are
 *  literal — a `$` inside is a filename character, not an expansion), then
 *  substitute every $-reference. A whole-value cwd-local substitution
 *  models itself (its values are names relative to the base). */
function resolveValue(raw: string, depth: number, assignments: Map<string, string[]>): SubResult {
  if (depth > 4) return null;
  let val = raw;
  const sq = val.length >= 2 && val.startsWith("'") && val.endsWith("'");
  const dq = val.length >= 2 && val.startsWith('"') && val.endsWith('"');
  if (sq || dq) val = val.slice(1, -1);
  if (sq) {
    if (UNRESOLVED_RE.test(val)) return null;
    return { kind: "literal", value: expandTilde(val) };
  }
  if (val === "") return null;
  if (val.startsWith("$(") && /^\$\((.*)\)$/s.test(val)) {
    if (isCwdLocalSubstitution(val.slice(2, -1))) return { kind: "cwdLocal" };
    return null; // other substitutions — runtime value
  }
  const sub = substitute(val, assignments, depth);
  if (sub === null) return null;
  if (sub.kind === "cwdLocal") return sub; // whole-string substitution (substitute guarantees it)
  if (UNRESOLVED_RE.test(sub.value)) return null;
  return { kind: "literal", value: expandTilde(sub.value) };
}

/** Substitute every `$NAME` / `${NAME…}` reference in `v`; null if any
 *  cannot be bounded. A cwdLocal value may only stand for the ENTIRE string
 *  (a glued literal would change where the names land). */
function substitute(v: string, assignments: Map<string, string[]>, depth: number): SubResult {
  if (depth > 4) return null;
  let out = "";
  let i = 0;
  while (i < v.length) {
    if (v[i] !== "$") {
      out += v[i];
      i++;
      continue;
    }
    if (v[i + 1] === "{") {
      const expr = parseVarExpr(v, i);
      if (!expr) return null;
      const r = resolveRef(expr.name, expr.def, assignments, depth);
      if (r === null) return null;
      if (r.kind === "cwdLocal") {
        if (out !== "" || expr.end !== v.length) return null;
        return r;
      }
      out += r.value;
      i = expr.end;
      continue;
    }
    const m = /^[A-Za-z_][A-Za-z0-9_]*/.exec(v.slice(i + 1));
    if (!m) return null; // $?, $$, $@, trailing $ — unresolvable
    const r = resolveRef(m[0], null, assignments, depth);
    if (r === null) return null;
    if (r.kind === "cwdLocal") {
      if (out !== "" || i + 1 + m[0].length !== v.length) return null;
      return r;
    }
    out += r.value;
    i += 1 + m[0].length;
  }
  return { kind: "literal", value: out };
}

/**
 * Local assignments visible to the reference in segment `refIdx`: a depth-0
 * segment sees those before it in document order (at <= refIdx); a segment
 * inside a ( ) subshell inherits only those made before the subshell's first
 * segment (the fork point) — assignments inside the subshell are local to
 * the child and never visible (from inside or out).
 */
function visibleAssignments(
  segments: BashSegment[],
  refIdx: number,
  assignments: ShellAssignment[],
): Map<string, string[]> {
  const depth = segments[refIdx]?.subshellDepth ?? 0;
  let bound = refIdx;
  if (depth > 0) {
    let i = refIdx;
    while (i > 0 && (segments[i - 1].subshellDepth ?? 0) > 0) i--;
    bound = i;
  }
  const m = new Map<string, string[]>();
  for (const a of assignments) {
    if (a.at > bound) continue;
    const prev = m.get(a.name) ?? [];
    prev.push(a.value);
    m.set(a.name, prev);
  }
  return m;
}

type OneRef =
  | { kind: "inside" }
  | { kind: "outside"; paths: string[] }
  | { kind: "sentinel"; reason: "var" | "base" };

/** Resolve against one candidate segment index. */
function resolveAt(
  ref: OpaqueRef,
  idx: number,
  segments: BashSegment[],
  effectiveCwds: (string | null)[],
  assignments: ShellAssignment[],
  sessionCwd: string,
  isInside: (p: string) => boolean,
): OneRef {
  let sub: SubResult;
  if (ref.kind === "cwdLocal") {
    sub = { kind: "cwdLocal" }; // in-list words (bare / globs / $(find …)) are base-relative by construction
  } else {
    sub = resolveValue(ref.raw, 0, visibleAssignments(segments, idx, assignments));
  }
  if (sub === null) return { kind: "sentinel", reason: "var" };
  const base = effectiveCwds[idx] ?? null;
  let resolved: string;
  if (sub.kind === "cwdLocal") {
    if (base === null) return { kind: "sentinel", reason: "base" };
    resolved = resolvePathReal(".", base);
  } else {
    if (!path.isAbsolute(sub.value) && base === null) return { kind: "sentinel", reason: "base" };
    resolved = resolvePathReal(sub.value, base ?? sessionCwd);
  }
  return isInside(resolved) ? { kind: "inside" } : { kind: "outside", paths: [resolved] };
}

/**
 * Resolve one opaque reference. When the owning segment is unidentifiable
 * (segIdx -1), resolve against every containing segment and take the worst
 * case (sentinel > concrete outside > inside) — sound in every order.
 */
function resolveOneRef(
  ref: OpaqueRef,
  segments: BashSegment[],
  effectiveCwds: (string | null)[],
  assignments: ShellAssignment[],
  sessionCwd: string,
  isInside: (p: string) => boolean,
): OneRef {
  // Base-independent: the in-list is statically pinned to a known root —
  // every expansion lands under prefixDir, whatever the cwd.
  if (ref.kind === "pinned" && ref.prefixDir) {
    return isInside(ref.prefixDir) ? { kind: "inside" } : { kind: "outside", paths: [ref.prefixDir] };
  }
  const idxs = ref.segIdx >= 0 ? [ref.segIdx] : (ref.candidates ?? []);
  if (idxs.length === 0) {
    return { kind: "sentinel", reason: ref.kind === "cwdLocal" ? "base" : "var" };
  }
  const out: string[] = [];
  for (const i of idxs) {
    const r = resolveAt(ref, i, segments, effectiveCwds, assignments, sessionCwd, isInside);
    if (r.kind === "sentinel") return r;
    if (r.kind === "outside") out.push(...r.paths);
  }
  return out.length ? { kind: "outside", paths: [...new Set(out)] } : { kind: "inside" };
}

/**
 * Resolve every opaque reference of a parsed command. Concrete outside
 * locations join `paths`; inside ones are dropped; unbound ones come back
 * as `unresolved` (callers push their markers into the path set so the
 * outside-cwd bar still forces approval).
 */
export function resolveOpaqueRefs(
  refs: OpaqueRef[],
  segments: BashSegment[],
  effectiveCwds: (string | null)[],
  assignments: ShellAssignment[],
  sessionCwd: string,
  isInside: (p: string) => boolean,
): OpaqueResolution {
  const paths = new Set<string>();
  const unresolved: UnresolvedRef[] = [];
  for (const ref of refs) {
    const r = resolveOneRef(ref, segments, effectiveCwds, assignments, sessionCwd, isInside);
    if (r.kind === "outside") for (const p of r.paths) paths.add(p);
    else if (r.kind === "sentinel") {
      unresolved.push({
        token: ref.raw,
        reason: r.reason,
        marker: r.reason === "base"
          ? UNKNOWN_CWD_MARKER
          : path.join(OPAQUE_VAR_DIR, ref.raw),
      });
    }
  }
  return { paths: [...paths], unresolved };
}
