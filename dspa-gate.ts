/**
 * dspa-gate.ts — deterministic hard floor for /dspa auto-allow.
 *
 * The code-enforced floor (docs/dspa-redesign.md, D1): an operation may only
 * reach the judge (and be auto-allowed) if it passes every check here. The
 * LLM never has authority over these. Everything the gate does NOT check is
 * JUDGEABLE — the judge sees the full command text (including inline script
 * bodies) plus halter's analysis digest and decides; a wrong verdict can at
 * most produce a prompt, never an auto-allowed operation the floor forbids.
 *
 * Hard floor (fail closed on any):
 *  - bash: parseable, no obscured command position (variable indirection —
 *    NOT flagged by halter's own analysis, checked here explicitly), no
 *    credential-pattern paths, no network egress, no paths outside the
 *    session base. Unsafe patterns (inline scripts, redirects, pipes,
 *    subshells) and risk reasons are NOT floor checks — judgeable: the
 *    packet already carries the full command text and the analysis digest.
 *    Package-manager RUN forms (npx, `uv run`, `bun <script>`, …) are
 *    judgeable too (D8) — they execute local/cached code the judge can see;
 *    FETCH forms (`npm install`, `uv sync`, `bun add`, …) stay on the floor.
 *  - rm carve-out (dspa only): halter always flags rm as dangerous, and
 *    danger patterns always prompt even after Always grants. An rm command
 *    may reach the judge only when every rm target is explicit, not the
 *    working directory itself, and either inside the session base or part
 *    of a create-then-delete set (a path this same command writes via
 *    redirect/tee/touch/mkdir in an earlier segment AND rms), or a
 *    non-recursive world-scratch target directly under /tmp (D8). With
 *    -r/-R the target (if it exists) must be a directory or self-written.
 *    Non-rm danger reasons still block the carve-out (rm's neighborhood is
 *    bounded by design). The judge still approves.
 *  - file: ungranted writes inside the session base, no credential-pattern
 *    warning. A write into a session-granted dir is JUDGEABLE (D3) — the dir
 *    is user-trusted, the content is judged; ungranted outside-cwd writes
 *    stay on the floor (Q1: outside base). Reads are never judged.
 *  - mcp: never auto-allowed — the gate has no model of server behavior, so
 *    the judge's word alone is not enough for automatic execution.
 */
import fs from "node:fs";
import path from "node:path";
import type { PromptData } from "./decision-engine";
import type { Store } from "./store";
import { analyzeCommand } from "./analysis/command-analysis";
import { expandTilde } from "./analysis/path-util";
import { resolvePathReal } from "./analysis/path-analysis";
import { UNKNOWN_CWD_MARKER } from "./analysis/cwd-tracking";
import { rootScanTarget } from "./analysis/evaluators/disk-evaluator";
import { OPAQUE_VAR_DIR } from "./analysis/bash-parser";
import {
  NETWORK_COMMANDS,
  GIT_NETWORK_SUBCOMMANDS,
  NETWORK_URL_RE,
  fetchFormPackage,
} from "./config";

export type DspaGateResult =
  | { ok: true }
  | {
      ok: false;
      reason: string;
      /** D10: bare package names that stopped the command (prompt offers Trust). */
      untrustedPackages?: string[];
    };

/**
 * Command position obscured by variable indirection, subshell, or backtick
 * (e.g. `f=rm; $f -rf ./build`). halter's own analysis does not flag this,
 * so the gate checks it explicitly — an obscured command can never be
 * verified for auto-allow.
 */
const OBSCURED_CMD_RE = /^\s*(?:\$\w|\$\(|`)/;

function obscuredHit(segments: string[]): string | null {
  for (const seg of segments) {
    const t = seg.trim();
    if (OBSCURED_CMD_RE.test(t)) return t.split(/\s+/)[0].slice(0, 20);
  }
  return null;
}

/**
 * D8 (docs/dspa-redesign.md): a package-manager RUN form executes
 * local/cached code — the package name and args are visible in the judge's
 * full-text input, so it is judgeable, not a floor stop. FETCH forms
 * (`npm install`, `uv sync`, `bun add`, …) stay on the floor: fetch =
 * arbitrary postinstall execution + registry access. The 2026-08-24 log:
 * the pre-D8 floor stopped 7 of 26 dspa prompts (`npx tsc`, `npx vitest`,
 * `uv run`) while the judge stopped zero.
 */
const PKG_RUN_FORMS: Record<string, ReadonlySet<string> | "all" | "except-fetch"> = {
  npx: "all", // inherently run-a-package (fetches on miss — the judge sees the name)
  uvx: "all",
  npm: new Set(["run", "exec", "x"]),
  pnpm: new Set(["run", "dlx", "exec", "x"]),
  yarn: new Set(["run", "dlx", "x"]),
  uv: new Set(["run", "x"]),
  bun: "except-fetch", // `bun <script>` interpreter form: all but fetch verbs
};

/** bun subcommands that fetch from the registry. */
const BUN_FETCH_VERBS = new Set([
  "install", "i", "add", "remove", "rm", "update", "upgrade", "up",
  "publish", "pub", "link",
]);

/** First operative token after the command word (skips flags, `K=V` env prefixes). */
function firstSubcommand(words: string[]): string | null {
  for (let i = 1; i < words.length; i++) {
    const w = words[i];
    if (w.startsWith("-") || /^[A-Za-z_][A-Za-z0-9_]*=/.test(w)) continue;
    return w.toLowerCase();
  }
  return null;
}

/** True when this segment's first word is a judgeable package-manager RUN form (D8). */
function isPkgRunForm(first: string, words: string[]): boolean {
  const forms = PKG_RUN_FORMS[first];
  if (!forms) return false;
  if (forms === "all") return true;
  const sub = firstSubcommand(words);
  if (forms === "except-fetch") return !sub || !BUN_FETCH_VERBS.has(sub);
  return !!sub && forms.has(sub);
}

/** First egress hit only (gate reason line); URLs truncated to 60 chars.
 *  Package-manager RUN forms are skipped (D8 — judgeable). */
function networkHit(command: string, segments: string[]): string | null {
  for (const seg of segments) {
    const words = seg.trim().split(/\s+/);
    const first = words[0]?.toLowerCase();
    if (!first) continue;
    if (isPkgRunForm(first, words)) continue;
    if (NETWORK_COMMANDS.has(first)) return first;
    if (first === "git") {
      const sub = words[1]?.toLowerCase() ?? "";
      if (GIT_NETWORK_SUBCOMMANDS.has(sub)) return `git ${words[1]}`;
    }
  }
  const m = command.match(NETWORK_URL_RE);
  return m ? m[0].slice(0, 60) : null;
}

/**
 * D7 (docs/dspa-redesign.md): outside paths the parser could not bind to a
 * location — `<unresolved-cwd>` (a cd inside a `||` chain leaves the side's
 * directory genuinely ambiguous) or `<unresolved-var>` (opaque variable).
 * The floor resolves what it can from the command text itself (the
 * 2026-08-24 log: a read-only `cd ~/… && ls || echo; grep;` flow and a
 * `SOCKET_DIR=${…:-/tmp/…}` probe forced manual prompts instead of reaching
 * the judge):
 *
 * - opaque vars: command-local `VAR=value` assignments — literal values,
 *   `${X:-default}` default chains (the default is taken when X has no local
 *   assignment; the environment may set X elsewhere, which the judge still
 *   sees in the full text), `~` expansion;
 * - unresolved cwd: the command's cd target (exactly one resolvable cd)
 *   bounds the side — it runs under either the original cwd or that target.
 *
 * Resolved → the ordinary in-base/grant bar applies: a stop then names the
 * CONCRETE dir, so one Always-for-dir makes later runs judgeable (D3-style).
 * Still unresolvable → judgeable: the packet carries the full text and stage
 * 2 has session context the static parser lacks. Resolved outside-base paths
 * and the rm carve-out are unchanged.
 */
const D7_ASSIGNMENT_RE = /^(?:export\s+|readonly\s+|declare\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$/;
const D7_UNRESOLVED_RE = /[?*$`\[{}]/;

type D7Resolution =
  | { kind: "inside" } // resolves inside base or a granted dir
  | { kind: "outside"; path: string } // resolves to a concrete outside-base path
  | { kind: "open" }; // unresolvable — judgeable

/** Command-local `VAR=value` assignments, in appearance order. */
function d7Assignments(command: string): Map<string, string[]> {
  const m = new Map<string, string[]>();
  for (const chunk of command.split(/;|&&|\|\||\||\n/)) {
    const tokens = chunk.trim().match(/\S+/g) ?? [];
    for (const tok of tokens) {
      const am = D7_ASSIGNMENT_RE.exec(tok);
      if (!am) break; // first non-assignment token ends the env prefix
      const prev = m.get(am[1]) ?? [];
      prev.push(am[2]);
      m.set(am[1], prev);
    }
  }
  return m;
}

/** Parse a `${NAME}` / `${NAME:-default}` expression with balanced braces. */
function d7ParseVarExpr(v: string, start: number): { name: string; def: string | null; end: number } | null {
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
  return null; // other ${NAME…} forms ($?, arithmetic, …) — unresolvable
}

/** The value a reference stands for: the local assignment when unambiguous,
* else the `:-` default (the command's stated fallback) when present. */
function d7ResolveRef(
  expr: { name: string; def: string | null },
  assignments: Map<string, string[]>,
  depth: number,
): string | null {
  const values = assignments.get(expr.name);
  const local = values && values.length === 1 ? d7ResolveExpr(values[0], assignments, depth) : null;
  if (local !== null) return local;
  if (expr.def !== null) return d7ResolveExpr(expr.def, assignments, depth);
  return null; // env var with no local assignment and no default
}

/** Resolve a value expression: a lone `${…}`, or a literal with `$` refs inside. */
function d7ResolveExpr(v: string, assignments: Map<string, string[]>, depth = 0): string | null {
  if (depth > 4) return null;
  let val = v;
  const quoted = /^"(.*)"$/.exec(val)?.[1] ?? /^'(.*)'$/.exec(val)?.[1];
  if (quoted !== undefined) val = quoted;
  if (val === "") return null;
  if (val.startsWith("${")) {
    const expr = d7ParseVarExpr(val, 0);
    if (!expr) return null;
    if (expr.end === val.length) return d7ResolveRef(expr, assignments, depth + 1);
  } // expression with a literal tail → fall through to substitution
  const sub = d7Substitute(val, assignments, depth);
  if (sub === null || D7_UNRESOLVED_RE.test(sub)) return null;
  return expandTilde(sub);
}

/** Substitute every `$NAME` / `${NAME…}` reference in `v`; null if any cannot be bounded. */
function d7Substitute(v: string, assignments: Map<string, string[]>, depth = 0): string | null {
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
      const expr = d7ParseVarExpr(v, i);
      if (!expr) return null;
      const r = d7ResolveRef(expr, assignments, depth);
      if (r === null) return null;
      out += r;
      i = expr.end;
      continue;
    }
    const m = /^[A-Za-z_][A-Za-z0-9_]*/.exec(v.slice(i + 1));
    if (!m) return null;
    const values = assignments.get(m[0]);
    const r = values && values.length === 1 ? d7ResolveExpr(values[0], assignments, depth) : null;
    if (r === null) return null;
    out += r;
    i += 1 + m[0].length;
  }
  return out;
}

/** The command's cd targets (flags skipped; `cd -` and `cd` are unresolvable). */
function d7CdTargets(command: string): string[] {
  const out: string[] = [];
  for (const chunk of command.split(/;|&&|\|\||\||\n/)) {
    const tokens = chunk.trim().match(/\S+/g) ?? [];
    let i = 0;
    while (i < tokens.length && D7_ASSIGNMENT_RE.test(tokens[i])) i++;
    if (path.basename(tokens[i] ?? "").toLowerCase() !== "cd") continue;
    i++;
    while (i < tokens.length && ["--", "-L", "-P"].includes(tokens[i])) i++;
    const t = tokens[i];
    if (t && t !== "-" && !t.startsWith("-")) out.push(t);
  }
  return out;
}

/**
 * Resolve one sentinel outside path. `rest` keeps the variable reference or
 * relative tail exactly as the parser emitted it.
 */
function d7ResolveOutsidePath(
  p: string,
  cwd: string,
  isInsideBase: (p: string) => boolean,
  assignments: Map<string, string[]>,
  cdTargets: string[],
): D7Resolution {
  if (p.startsWith(OPAQUE_VAR_DIR)) {
    // The parser emits path.join(OPAQUE_VAR_DIR, rawVal) — drop the join
    // slash so a RELATIVE resolved value stays cwd-relative (not "/./x").
    const rest = p.slice(OPAQUE_VAR_DIR.length + 1);
    const substituted = d7Substitute(rest, assignments);
    if (substituted === null || D7_UNRESOLVED_RE.test(substituted)) return { kind: "open" };
    const resolved = path.resolve(cwd, expandTilde(substituted));
    return isInsideBase(resolved) ? { kind: "inside" } : { kind: "outside", path: resolved };
  }
  if (p.startsWith(UNKNOWN_CWD_MARKER)) {
    const rest = p.slice(UNKNOWN_CWD_MARKER.length);
    const targets = cdTargets.filter((t) => !D7_UNRESOLVED_RE.test(t)).map(expandTilde);
    if (targets.length !== 1) return { kind: "open" };
    const resolved = path.resolve(targets[0], rest.replace(/^\//, ""));
    return isInsideBase(resolved) ? { kind: "inside" } : { kind: "outside", path: resolved };
  }
  return { kind: "open" };
}

export async function checkDspaGate(
  pd: PromptData,
  store: Store,
): Promise<DspaGateResult> {
  if (pd.type === "mcp") {
    return { ok: false, reason: "MCP calls are never auto-allowed (server behavior is outside the gate's model)" };
  }

  if (pd.type === "file") {
    // D3 (docs/dspa-redesign.md): a write into a session-granted dir is
    // judgeable — the user trusted the dir, so the outside-base stop does
    // not apply; the two-stage judge decides on the content. Ungranted
    // outside-cwd writes stay on the floor (Q1). Reads are never judged.
    const grantedDirWrite = pd.isWriteOp && store.isInsideAllowedDir(pd.resolved, "write");
    if (!grantedDirWrite && pd.outsideDir) return { ok: false, reason: `outside base (${pd.outsideDir})` };
    if (pd.warnedRule) return { ok: false, reason: `credential pattern (${pd.warnedRule})` };
    return { ok: true };
  }

  // bash — trust the analysis the decision was made from (single analysis
  // per decision); re-analyze only for hand-constructed prompt data.
  const analysis =
    pd.analysis ??
    (await analyzeCommand(pd.command, pd.cwd, {
      isInsideAllowedDir: (p) => store.isInsideAllowedDir(p, "read"),
    }));
  if (analysis.hasParseError) return { ok: false, reason: "unparseable command" };

  const isInsideBase = (p: string) =>
    p === pd.cwd || p.startsWith(pd.cwd + "/") || store.isInsideAllowedDir(p, "write");

  let outsideExempt = new Set<string>();
  const hasRm = analysis.segments.some(isRmSegment);
  if (hasRm) {
    // rm carve-out: bounded, explicit targets only (see header).
    const rm = checkRmTargets(analysis.segments, pd.cwd, isInsideBase);
    if (rm.reason) return { ok: false, reason: rm.reason };
    outsideExempt = rm.exempt;
    // Non-rm dangerous reasons still block: the carve-out covers only the
    // rm's own footprint (recursive/forced delete, its self-written
    // redirect/pipe). Other dangerous content in the command — script
    // interpreters, file-modification patterns, … — is not judgeable.
    const otherDanger = analysis.risk.reasons.filter((r) => !RM_RISK_REASON_RE.test(r));
    if (otherDanger.length > 0) {
      return { ok: false, reason: `dangerous: ${otherDanger.join("; ").slice(0, 120)}` };
    }
  }
  // Non-rm: unsafe patterns and risk reasons are JUDGEABLE (D1) — inline
  // scripts, redirects, pipes, subshells, file-modification patterns. The
  // packet carries the full command text (heredoc bodies included) plus
  // halter's analysis digest; the judge decides. The floor checks below
  // (obscured position, credentials, network, outside base) still apply.
  const obscured = obscuredHit(analysis.segments);
  if (obscured) return { ok: false, reason: `obscured command position (${obscured})` };
  if (pd.credentialRule) return { ok: false, reason: `credential pattern (${pd.credentialRule})` };
  // D10 (docs/dspa-redesign.md): a fetchable run form names a package that
  // may be FETCHED (and executed) on cache miss — the same fetch class the
  // floor stops for fetch forms. Trust is per bare package name, granted
  // only by the user's "Trust" click on the stop's prompt. Local run forms
  // (npm run, uv run, bun <script>) execute repo-visible code and are never
  // gated. The parser flattens subshell contents into segments, so
  // `out=$(npx foo)` is seen too; only opaque indirection (eval, $f) stays
  // judge-only (the obscured-position check above).
  const untrusted: string[] = [];
  for (const seg of analysis.segments) {
    const words = seg.trim().split(/\s+/);
    const first = words[0]?.toLowerCase() ?? "";
    const pkg = fetchFormPackage(first, words);
    if (pkg && !store.hasTrustedPackage(pkg)) untrusted.push(`${first} ${pkg}`);
  }
  if (untrusted.length > 0) {
    const uniq = [...new Set(untrusted)];
    return {
      ok: false,
      reason: `untrusted package (${uniq.slice(0, 3).join(", ")})`,
      untrustedPackages: uniq.map((s) => s.split(/\s+/)[1]),
    };
  }
  // Full-filesystem scan (find /, grep -rn /): a dedicated stop reason —
  // conspicuous in plain sight, and the generic outside-base reason
  // ("touches paths outside base (/)") understates what the command does.
  for (const seg of analysis.segments) {
    const scan = rootScanTarget(seg);
    if (scan) return { ok: false, reason: `full filesystem scan (${scan} /)` };
  }
  const net = networkHit(pd.command, analysis.segments);
  if (net) return { ok: false, reason: `network egress (${net})` };
  const outside = (analysis.prompt.outsidePaths ?? []).filter((p) => !outsideExempt.has(p));
  // D7: resolve what the parser could not bind, then apply the ordinary bar.
  // Concrete resolved paths stop (naming the dir for a one-time grant);
  // still-unresolvable paths go to the judge.
  const assignments = d7Assignments(pd.command);
  const cdTargets = d7CdTargets(pd.command);
  const resolvedOutside: string[] = [];
  for (const p of outside) {
    if (!p.startsWith(OPAQUE_VAR_DIR) && !p.startsWith(UNKNOWN_CWD_MARKER)) {
      resolvedOutside.push(p);
      continue;
    }
    const r = d7ResolveOutsidePath(p, pd.cwd, isInsideBase, assignments, cdTargets);
    if (r.kind === "outside") resolvedOutside.push(r.path);
    // inside → drop; open → judgeable (the judge sees the full text)
  }
  if (resolvedOutside.length > 0) {
    const shown = [...new Set(resolvedOutside)].slice(0, 2);
    return { ok: false, reason: `touches paths outside base (${shown.join(", ")})` };
  }
  return { ok: true };
}

// ── rm carve-out ────────────────────────────────────────────────────────

/** Risk reasons that belong to rm's own footprint (or the self-write that
 * feeds it) — filtered out in the rm branch instead of blocking. Everything
 * else in analysis.risk.reasons blocks the judge. The medium-noise entries
 * (pipe operator, input/output redirection, tee's file-writing flag) appear
 * in legitimate self-write shapes (`echo … | tee f && rm f`); the dangerous
 * pipeline forms have their own, non-matching reasons ("pipe to a shell",
 * per-stage evaluator hits). New reason strings fail safe (block → prompt). */
const RM_RISK_REASON_RE =
  /\brm\b|recursive delete|forced delete|shell (?:input|output) redirection|pipe operator|tee \(file writing\)/i;
/** Targets that can never be auto-allowed: globs, tildes, computed
 * (variable/substitution) paths. */
const RM_FORBIDDEN_TARGET_RE = /[*?[~$`]/;

/**
 * D8 (docs/dspa-redesign.md): an explicit, non-recursive rm of a
 * world-scratch target directly under /tmp is judgeable — the judge sees
 * the full text, and /tmp is the conventional scratch area (`rm -f
 * /tmp/probe.log` cleanup stopped 4 of 26 dspa prompts in the 2026-08-24
 * log). Recursive, glob, variable, and tilde targets never reach here
 * (the explicitness checks fail first); /tmp itself is not a target.
 */
function isTmpScratchTarget(resolved: string, recursive: boolean): boolean {
  return !recursive && resolved.startsWith("/tmp/");
}

function isRmSegment(seg: string): boolean {
  const first = seg.trim().split(/\s+/)[0]?.split("/").pop()?.toLowerCase();
  return first === "rm";
}

/** Write-redirect target (`> p` / `>> p` / `2> p`) in a raw segment. */
const REDIRECT_TARGET_RE = /\d*(?:>>?)\s*([A-Za-z0-9_./-]+|"[^"\s]+"|'[^'\s]+')/g;
const SELF_WRITE_CMDS = new Set(["tee", "touch", "mkdir"]);

/** Strip one pair of matching quotes from a raw token. */
function cleanToken(t: string): string {
  if (t.length >= 2 && ((t[0] === '"' && t.endsWith('"')) || (t[0] === "'" && t.endsWith("'")))) {
    return t.slice(1, -1);
  }
  return t;
}

/** /dev/* targets are not real writes (>/dev/null, /dev/stderr, …). */
function isDevNullish(resolved: string): boolean {
  return resolved === "/dev" || resolved.startsWith("/dev/");
}

/**
 * Validate every rm target in the command. Returns a block reason, or the
 * create-then-delete set (self-written paths that are also rm targets) to
 * exempt from the outside-base check.
 */
function checkRmTargets(
  segments: string[],
  cwd: string,
  isInsideBase: (p: string) => boolean,
): { reason: string | null; exempt: Set<string> } {
  const written = new Set<string>();
  const rmTargets = new Set<string>();
  const noPreserveRoot = () => ({ reason: "rm with --no-preserve-root" as string | null, exempt: new Set<string>() });

  // First pass: collect self-written paths (ordered by segment) and rm targets.
  for (let i = 0; i < segments.length; i++) {
    const seg = segments[i];
    const words = seg.trim().split(/\s+/);
    if (isRmSegment(seg)) {
      if (words.includes("--no-preserve-root")) return noPreserveRoot();
      const args = words.slice(1).filter((t) => !t.startsWith("-"));
      if (args.length === 0) return { reason: "rm without explicit targets", exempt: new Set() };
      const recursive = words.slice(1).some(
        (t) => t === "--recursive" || (t.startsWith("-") && !t.startsWith("--") && t !== "-" && /[rR]/.test(t)),
      );
      for (const a of args) {
        const target = cleanToken(a);
        if (RM_FORBIDDEN_TARGET_RE.test(target)) {
          return { reason: `rm target not explicit (${target.slice(0, 40)})`, exempt: new Set() };
        }
        if (target === "-") return { reason: "rm reading from stdin", exempt: new Set() };
        const resolved = resolvePathReal(expandTilde(target), cwd);
        if (resolved === cwd) return { reason: "rm target is the working directory itself", exempt: new Set() };
        if (recursive) {
          try {
            const st = fs.statSync(resolved);
            const selfWritten = written.has(resolved);
            if (!st.isDirectory() && !st.isFile() && !selfWritten) {
              return { reason: `rm -r target is not a file or directory (${a.slice(0, 60)})`, exempt: new Set() };
            }
            if (!st.isDirectory() && !st.isFile() && selfWritten) {
              /* self-written: trust the earlier segment */
            }
          } catch {
            /* doesn't exist — nothing to delete */
          }
        }
        rmTargets.add(resolved);
        if (
          !isInsideBase(resolved) &&
          !written.has(resolved) &&
          !isTmpScratchTarget(resolved, recursive)
        ) {
          return { reason: `rm target outside session base (${a.slice(0, 60)})`, exempt: new Set() };
        }
      }
    } else {
      // Self-written paths from this earlier segment.
      for (const m of seg.matchAll(REDIRECT_TARGET_RE)) {
        const raw = cleanToken(m[1]);
        if (RM_FORBIDDEN_TARGET_RE.test(raw)) continue;
        const resolved = resolvePathReal(expandTilde(raw), cwd);
        if (isDevNullish(resolved)) continue;
        written.add(resolved);
      }
      // Self-write commands per pipeline stage — `a | tee f` hides tee
      // behind the segment's first word.
      for (const stage of seg.split("|")) {
        const sw = stage.trim().split(/\s+/);
        const scmd = sw[0]?.split("/").pop()?.toLowerCase() ?? "";
        if (!SELF_WRITE_CMDS.has(scmd)) continue;
        for (const t of sw.slice(1)) {
          const target = cleanToken(t);
          if (t.startsWith("-") || /^[\d<>]/.test(t) || RM_FORBIDDEN_TARGET_RE.test(target)) continue;
          const resolved = resolvePathReal(expandTilde(target), cwd);
          if (isDevNullish(resolved)) continue;
          written.add(resolved);
        }
      }
    }
  }

  // Every self-written path must be in-base or cleaned up by this command.
  for (const w of written) {
    if (!isInsideBase(w) && !rmTargets.has(w)) {
      return { reason: `write-redirect outside base, not cleaned by this command (${w.slice(0, 60)})`, exempt: new Set() };
    }
  }

  return { reason: null, exempt: new Set([...rmTargets].filter((t) => written.has(t))) };
}
