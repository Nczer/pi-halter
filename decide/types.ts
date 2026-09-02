/**
 * Core decision types — the shared vocabulary of halter's decision layer.
 *
 * Request types (what a gated call is), decision types (what the gate
 * resolved it to), and prompt data (what the prompt shows and what
 * "Always" would grant). Pure types: no runtime code.
 */
import type { CommandAnalysis } from "../analysis/command-analysis";

export type { Store, AllowRules } from "../gate/store";

// ── Request types (discriminated union) ──

export interface BashRequest {
  type: "bash";
  command: string;
  cwd: string;
}

export interface FileRequest {
  type: "file";
  toolName: "read" | "write" | "edit";
  filePath: string;
  cwd: string;
  /** Pre-resolved path to avoid redundant fs.realpathSync calls. */
  resolvedPath?: string;
  /**
   * Content being written (write: full new content; edit: newText blocks
   * joined with "\u2026"). Absent for read. Carried for the judge only —
   * never shown in the human prompt.
   */
  content?: string;
}

export type PermissionRequest = BashRequest | FileRequest | ToolRequest;

/**
 * A call to a gated tool ext (one that ships a <ext>/halter plugin).
 * The plugin (plugins/types.ts) classifies the call; the core routes the
 * `gate` kind: exec → script pipeline (judge/dspa), file → path prompt,
 * consent → per-kind session consent.
 */
export interface ToolRequest {
  type: "tool";
  /** Tool ext name — equals the plugin name and the ext directory name. */
  tool: string;
  /** Short operation label (usually the action name). */
  label: string;
  gate: "exec" | "file" | "consent";
  cwd: string;
  /** exec: the FINAL script payload — byte-identical to what will run. */
  script?: string;
  /** file: the target path. */
  path?: string;
  /** consent: the consent kind (e.g. "read"). */
  consentKind?: string;
  /** Human-readable argument preview for the prompt. */
  argsPreview?: string;
  /** Context line, e.g. "Runs Python inside a running Blender instance". */
  note?: string;
}

// ── Decision types (discriminated union) ──

/** Command was auto-allowed — proceed without prompting. */
interface AutoAllowDecision {
  kind: "auto-allow";
  /** Set when /dspa auto-allowed (audit trail: which model approved). */
  reason?: string;
  /** D11: the analysis a bash auto-allow was made from — the dspa content
   *  review (granted script executions) reuses it instead of re-parsing. */
  analysis?: CommandAnalysis;
}

/** Command must be blocked — no prompt shown. */
interface BlockDecision {
  kind: "block";
  reason: string;
}

/** Command requires user confirmation. */
export interface PromptDecision {
  kind: "prompt";
  /** Structured data for the PromptBuilder to format into title/body. */
  promptData: PromptData;
}

export type Decision = AutoAllowDecision | BlockDecision | PromptDecision;

// ── Prompt data (discriminated union, mirrors request types) ──

export interface BashPromptData {
  type: "bash";
  command: string;
  cwd: string;
  outsideDirs: string[];
  segments: string[];
  signatures: string[];
  /**
   * Signatures of relative-path tool segments with the EFFECTIVE base they
   * resolve against (the working dir the path pipeline checks them under).
   * The regular promptSignatures filter drops these when their basename is
   * allowlisted, so the rule generator and the prompt use this list to
   * offer/store base-bound grants. Segments under an unresolvable base are
   * omitted (their grants fail closed — the prompt already demands path
   * approval for them).
   */
  relativeToolIds: Array<{ sig: string; base: string }>;
  /** Indices of segments whose signature is NOT in the static allowlist. */
  nonAllowedSegmentIndices: number[];
  riskDangerous: boolean;
  riskSeverity: "high" | "medium" | null;
  riskReasons: string[];
  /** Patterns that block auto-allow (subshells, write redirects, obfuscation) — excludes display-only risks like pipes. */
  hasUnsafePattern: boolean;
  /** Matched credential pattern, if any (e.g. ".env", ".aws"). Prevents auto-allow. */
  credentialRule: string | null;
  needsCommandApproval: boolean;
  needsPathApproval: boolean;
  /**
   * Opaque references the analysis could not statically bind (the prompt
   * lists them; they force path approval via their markers but are never
   * part of an Always grant). Absent on hand-constructed PromptData.
   */
  unresolved?: Array<{ token: string; reason: "var" | "base" }>;
  /**
   * Fetchable run-form segments (npx tsc, uvx tsc, bunx …) whose package is
   * NOT yet session-trusted, with the segment signature and bare package
   * name. Package trust is the grant for these forms: their signatures are
   * excluded from the command tier and its rules, and the prompt offers
   * "Trust: <pkg> (session)" (deduped by package across run forms).
   * Absent on hand-constructed PromptData.
   */
  fetchableForms?: Array<{ sig: string; pkg: string }>;
  /**
   * The single analysis this decision was made from. Downstream consumers
   * (the /dspa hard gate, the judge packet) use it instead of re-parsing,
   * so they see exactly the analysis the decision was based on — one
   * tree-sitter parse per tool call, no divergence from store mutations
   * between passes. Absent only for hand-constructed PromptData (tests,
   * future synthetic sources); consumers fall back to re-analyzing.
   */
  analysis?: CommandAnalysis;
}

export interface FilePromptData {
  type: "file";
  action: string;
  filePath: string;
  resolved: string;
  cwd: string;
  outsideDir: string | null; // null if inside cwd
  isWriteOp: boolean;
  warnedRule: string | null; // credential warning (prompt, not block)
  symlinkHint: string | null; // e.g. "/home/user/data → /mnt/storage"
  /** Whether the target file already exists on disk. */
  exists: boolean;
  /** Content being written (write/edit) — judge input only, not shown in the human prompt. */
  content?: string;
}

/**
 * Prompt data for a gated tool call (ToolRequest, resolved). `file`-gated
 * calls carry the resolved path facts (the prompt warns on outside-cwd).
 */
export interface ToolPromptData {
  type: "tool";
  tool: string;
  label: string;
  gate: "exec" | "file" | "consent";
  script?: string;
  argsPreview?: string;
  consentKind?: string;
  note?: string;
  // file gate only:
  resolved?: string;
  outsideDir?: string | null;
  exists?: boolean;
}

export type PromptData = BashPromptData | FilePromptData | ToolPromptData;

// ── Decision options ──

/**
 * Pure decision function. Given a permission request and the current store
 * state, returns a decision: auto-allow, block, or prompt.
 *
 * UI-agnostic — always returns "prompt" when human judgment is needed,
 * regardless of whether a UI is available. The handler adapts.
 */
export interface DecideOptions {
  /**
   * D3/D11 (docs/dspa-redesign.md, dspa mode only): a file WRITE that manual
   * mode would auto-allow (session-granted dir or file, config-allowed,
   * project-pi) returns the prompt decision instead — the location is
   * trusted, the content is judged in full. Off (default): manual/dspat
   * behavior — auto-allow.
   */
  judgeWriteAutoAllows?: boolean;
}
