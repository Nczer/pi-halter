import { parseCommand } from "./bash-parser";
import { analyzeSegment } from "./segment-analysis";
import { getTmuxSubcommand, extractTmuxSendKeys } from "./tmux-helpers";
import { analyzeWholeCommandRisk, type CommandRisk } from "./risk-analyzer";
import { hasRelativePath, getOutsideCwdPaths, resolvePathsToDirs, checkCommandForCredentialPaths } from "./path-analysis";
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
 */
async function analyzeTmuxSendKeysPayload(
  payload: string,
  cwd: string,
  depth: number,
): Promise<{ simple: boolean; unsafe: boolean }> {
  if (depth > TMUX_PAYLOAD_MAX_DEPTH) return { simple: false, unsafe: true };
  const chunks = payload.split(TMUX_PAYLOAD_ENTER_RE).map(p => p.trim()).filter(Boolean);
  let simple = true;
  let unsafe = false;
  for (const chunk of chunks) {
    const parsed = await parseCommand(chunk, cwd);
    if (parsed.hasParseError) return { simple: false, unsafe: true };
    for (const seg of parsed.segments) {
      const text = seg.text.trim();
      if (getFirstWord(text) === "tmux" && getTmuxSubcommand(text) === "send-keys") {
        const innerPayload = normalizeTmuxPayload(extractTmuxSendKeys(text));
        const r = innerPayload
          ? await analyzeTmuxSendKeysPayload(innerPayload, cwd, depth + 1)
          : { simple: true, unsafe: false };
        simple &&= r.simple;
        unsafe ||= r.unsafe;
      } else {
        const a = await analyzeSegment(seg, cwd);
        simple &&= a.isSimple;
        unsafe ||= a.isUnsafe;
      }
    }
  }
  return { simple, unsafe };
}

export async function analyzeCommand(
  cmd: string,
  cwd: string,
  options?: AnalyzeCommandOptions,
): Promise<CommandAnalysis> {
  // Single AST parse: segments, paths, and subshell flags in one pass
  const parseResult = await parseCommand(cmd, cwd);
  const { segments, paths, hasParseError } = parseResult;
  const segmentTexts = segments.map(s => s.text);
  const signatures = segmentTexts.map(getCommandSignature);

  // Unified segment analysis: one call per segment replaces
  // hasKnownDanger + isSimpleAllowedCommand + isSegmentUnsafe + analyzeSegmentRisk
  const segmentAnalyses = await Promise.all(segments.map(seg => analyzeSegment(seg, cwd)));

  const allSimple = segmentAnalyses.every(a => a.isSimple);
  const hasUnsafe = segmentAnalyses.some(a => a.isUnsafe);

  // tmux send-keys payloads inherit the session's auto-allow rules — and must
  // meet the same auto-allow bar as a direct command. The sync evaluator's
  // quick check (isTmuxSendKeysSafe) predates wrapper/prefix delegation, so
  // the payload is recursively analyzed here with the full pipeline
  // (timeout 5 curl, command -p sh -c, nice rm, git config, … all prompt).
  let tmuxPayloadSimple = true;
  let tmuxPayloadUnsafe = false;
  for (const seg of segments) {
    const text = seg.text.trim();
    if (getFirstWord(text) !== "tmux" || getTmuxSubcommand(text) !== "send-keys") continue;
    const payload = normalizeTmuxPayload(extractTmuxSendKeys(text));
    if (!payload) continue; // bare Enter keystroke — harmless
    const r = await analyzeTmuxSendKeysPayload(payload, cwd, 1);
    tmuxPayloadSimple &&= r.simple;
    tmuxPayloadUnsafe ||= r.unsafe;
  }

  // Merge per-segment risks with whole-command risk
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
    outsidePaths = getOutsideCwdPaths(
      paths,
      cwd,
      options.isInsideAllowedDir,
    );
    outsideDirs = await resolvePathsToDirs(outsidePaths);
    needsPathApproval = outsidePaths.length > 0;
  }

  // Credential path check — denies are blocked earlier by CredentialDenyRule,
  // but we check both here for defense-in-depth (prevents auto-allow if a rule is bypassed)
  const credentialCheck = checkCommandForCredentialPaths(cmd, cwd);

  const analysis = {
    segments: segmentTexts,
    signatures,
    paths,
    hasParseError,
    safety: {
      canBeAutoAllowed: !hasUnsafe && !tmuxPayloadUnsafe,
      isSimple: allSimple && tmuxPayloadSimple,
      hasUnsafePattern: hasUnsafe || tmuxPayloadUnsafe,
    },
    risk: wholeRisk,
    relativePathSegmentIndices,
    hasCredentialPath: credentialCheck.denied !== null || credentialCheck.warned !== null,
    credentialRule: credentialCheck.denied ?? credentialCheck.warned,
    prompt: {
      nonAllowlistedSegmentIndices,
      promptSignatures,
      outsidePaths,
      outsideDirs,
      needsPathApproval,
    },
  };
  return analysis;
}
