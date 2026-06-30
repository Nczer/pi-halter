import { parseCommand } from "./bash-parser";
import { analyzeSegment } from "./segment-analysis";
import { analyzeWholeCommandRisk, type CommandRisk } from "./risk-analyzer";
import { hasRelativePath, getOutsideCwdPaths, resolvePathsToDirs } from "./path-analysis";
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
  /** Allowed read directories (from store). When provided, outsidePaths/outsideDirs are computed. */
  allowedReadDirs?: Set<string>;
  /** Allowed write directories (from store). When provided, outsidePaths/outsideDirs are computed. */
  allowedWriteDirs?: Set<string>;
}

export async function analyzeCommand(
  cmd: string,
  cwd: string,
  options?: AnalyzeCommandOptions,
): Promise<CommandAnalysis> {
  // Single AST parse: segments, paths, and subshell flags in one pass
  const parseResult = await parseCommand(cmd, cwd);
  const { segments, paths } = parseResult;
  const segmentTexts = segments.map(s => s.text);
  const signatures = segmentTexts.map(getCommandSignature);

  // Unified segment analysis: one call per segment replaces
  // hasKnownDanger + isSimpleAllowedCommand + isSegmentUnsafe + analyzeSegmentRisk
  const segmentAnalyses = await Promise.all(segments.map(seg => analyzeSegment(seg, cwd)));

  const allSimple = segmentAnalyses.every(a => a.isSimple);
  const hasUnsafe = segmentAnalyses.some(a => a.isUnsafe);

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
  if (options?.allowedReadDirs && options?.allowedWriteDirs) {
    outsidePaths = getOutsideCwdPaths(
      paths,
      cwd,
      options.allowedReadDirs,
      options.allowedWriteDirs,
    );
    outsideDirs = await resolvePathsToDirs(outsidePaths);
    needsPathApproval = outsidePaths.length > 0;
  }

  const analysis = {
    segments: segmentTexts,
    signatures,
    paths,
    safety: {
      canBeAutoAllowed: !hasUnsafe,
      isSimple: allSimple,
      hasUnsafePattern: hasUnsafe,
    },
    risk: wholeRisk,
    relativePathSegmentIndices,
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
