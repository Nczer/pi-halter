import path from "node:path";
import { parseCommand, type OpaqueRef, type BashSegment } from "./bash-parser";
import { analyzeSegment } from "./segment-analysis";
import { trackEffectiveCwd, reResolveCwdDependentPaths, baseAccessPath } from "./cwd-tracking";
import { expandTilde, OPAQUE_VAR_DIR } from "./path-util";
import { resolveOpaqueRefs, type UnresolvedRef, type ShellAssignment } from "./var-resolution";
import { parseTmuxCommand, tmuxSendKeysKeys } from "./tmux";
import { analyzeWholeCommandRisk, type CommandRisk } from "./risk-analyzer";
import { hasRelativePath, getOutsideCwdPaths, resolvePathsToDirs, checkCommandForCredentialPaths } from "./path-analysis";
import { UNKNOWN_CWD_MARKER } from "./cwd-tracking";
import { getCommandSignature, getFirstWord, STARTS_WITH_REDIRECT_RE } from "./segment-helpers";
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
  /** Command signatures for auto-allow matching (e.g. "git -R", "ls"). */
  signatures: string[];
  /** All extracted file/dir paths, resolved to absolute. */
  paths: string[];
  /** Detailed safety verdict. */
  safety: SafetyVerdict;
  /** Detailed risk assessment from token-based and regex-based analysis. */
  risk: CommandRisk;
  /** Indices of segments that contain relative path tokens (./foo, ../foo). */
  relativePathSegmentIndices: number[];
  /** Effective working directory per segment (null = unresolvable base). */
  effectiveCwds: (string | null)[];
  /** Raw opaque data (unresolved — the dspa floor re-resolves it under its
   * own stricter bar). Parsed segments carry subshell depth for scoping. */
  opaque: OpaqueRef[];
  assignments: ShellAssignment[];
  parsedSegments: BashSegment[];
  /** Credential path detected in the command (denied paths are blocked earlier; this is for warned paths). */
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
  for (const chunk of chunks) {
    const parsed = await parseCommand(chunk, cwd);
    if (parsed.hasParseError) return { simple: false, unsafe: true, paths: [], reasons: [] };
    // The payload's opaque refs resolve against the payload's own segment
    // bases (a cd inside the payload threads); the full outside-cwd bar
    // (allowed roots, granted dirs) applies downstream at command level.
    const payloadCwds = trackEffectiveCwd(parsed.segments, cwd);
    const payloadOpaque = resolveOpaqueRefs(
      parsed.opaque,
      parsed.segments,
      payloadCwds,
      parsed.assignments,
      cwd,
      (p) => p === cwd || p.startsWith(cwd + "/"),
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
  const { segments, paths, opaque, assignments, hasParseError } = parseResult;
  const segmentTexts = segments.map(s => s.text);
  const signatures = segmentTexts.map(getCommandSignature);

  // Effective cwd per segment: a resolvable `cd` in an earlier top-level
  // segment changes the working directory for later segments — relative script
  // paths must be analyzed against it for the trusted-script bypass to work
  // (`cd <skill-dir> && uv run … scripts/x.py`). null = unknown base (a
  // non-literal cd or a `||` branch made the runtime cwd unresolvable).
  const effectiveCwds = trackEffectiveCwd(segments, cwd);

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
  // set. Inside-cwd/allowed bases are filtered out by getOutsideCwdPaths.
  const normBase = path.resolve(expandTilde(cwd));
  for (let i = 0; i < segments.length; i++) {
    const base = effectiveCwds[i];
    if (base !== normBase) {
      paths.push(...reResolveCwdDependentPaths(segments[i], base));
      const basePath = baseAccessPath(segments[i], base);
      if (basePath) paths.push(basePath);
    } else {
      // Base === session cwd: parseCommand already resolved ./../ tokens
      // against it — collect only the $PWD tokens it never saw.
      paths.push(...reResolveCwdDependentPaths(segments[i], base, { skipDotPaths: true }));
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
  // tokens (base-independent) keep their normal verdict. cwdKnown flags the
  // marker as non-real, so evaluators (rm mass-deletion) skip relative-token
  // resolution instead of resolving against "/".
  const UNKNOWN_BASE_CWD = "/";
  const segmentAnalyses = await Promise.all(
    segments.map((seg, i) => {
      const base = effectiveCwds[i];
      return analyzeSegment(seg, base ?? UNKNOWN_BASE_CWD, base !== null && base !== undefined);
    }),
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

  // Pre-compute prompt hints: non-allowlisted segment indices and signatures
  const nonAllowlistedSegmentIndices = signatures
    .map((sig, i) =>
      STARTS_WITH_REDIRECT_RE.test(segmentTexts[i].trim())
        ? -1
        : isSafeSubcommand(segmentTexts[i])
        ? -1
        : isAllowedCommand(getFirstWord(segmentTexts[i])) ? -1 : i,
    )
    .filter(i => i >= 0);
  const promptSignatures = [...new Set(nonAllowlistedSegmentIndices.map(i => signatures[i]))];

  // Pre-compute outside paths (requires store-provided allowed dirs)
  let outsidePaths: string[] | undefined;
  let outsideDirs: string[] | undefined;
  let needsPathApproval: boolean | undefined;
  if (options?.isInsideAllowedDir) {
    const op = getOutsideCwdPaths(
      paths.filter((p) => !unresolvedRawTokens.has(p)),
      cwd,
      options.isInsideAllowedDir,
    );
    outsidePaths = op;
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

  // Credential path check — denies are blocked earlier by CredentialDenyRule,
  // but we check both here for defense-in-depth (prevents auto-allow if a rule is bypassed)
  const credentialCheck = checkCommandForCredentialPaths(cmd, cwd);

  // Fold the [TmuxPayload] reasons into the whole-command risk (order-stable,
  // deduped) so PromptFallbackRule surfaces them in the prompt and log.
  const riskReasons = tmuxPayloadReasons.length
    ? [...new Set([...wholeRisk.reasons, ...tmuxPayloadReasons])]
    : wholeRisk.reasons;

  const analysis = {
    segments: segmentTexts,
    signatures,
    paths,
    hasParseError,
    safety: {
      // canBeAutoAllowed requires the payload's TOP-LEVEL bar too: a session
      // auto-allow rule for "tmux" (or a simple payload that still isn't
      // simple) must not carry the payload through SafetyRule's signature
      // branch. Non-tmux commands are unaffected (flags stay at their
      // direct-command values).
      canBeAutoAllowed: !hasUnsafe && !tmuxPayloadUnsafe && tmuxPayloadSimple,
      isSimple: allSimple && tmuxPayloadSimple,
      hasUnsafePattern: hasUnsafe || tmuxPayloadUnsafe,
    },
    risk: { ...wholeRisk, reasons: riskReasons },
    relativePathSegmentIndices,
    effectiveCwds,
    opaque,
    assignments,
    parsedSegments: segments,
    hasCredentialPath: credentialCheck.denied !== null || credentialCheck.warned !== null,
    credentialRule: credentialCheck.denied ?? credentialCheck.warned,
    prompt: {
      nonAllowlistedSegmentIndices,
      promptSignatures,
      outsidePaths,
      outsideDirs,
      needsPathApproval,
      unresolved: opaqueResolution.unresolved,
    },
  };
  return analysis;
}
