import { decideBash } from "./policies/bash";
import { decideFile } from "./policies/file";
import { decideMcp } from "./policies/mcp";
import type { Store, AllowRules } from "./store";
export type { Store, AllowRules };

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
}

export interface McpRequest {
  type: "mcp";
  server: string;
  tool: string;
  /** Truncated tool arguments for display in permission prompts. */
  argsPreview?: string;
}

export type PermissionRequest = BashRequest | FileRequest | McpRequest;

// ── Decision types (discriminated union) ──

/** Command was auto-allowed — proceed without prompting. */
interface AutoAllowDecision {
  kind: "auto-allow";
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
}

export interface FilePromptData {
  type: "file";
  action: string;
  filePath: string;
  resolved: string;
  cwd: string;
  outsideDir: string | null; // null if inside cwd
  isWriteOp: boolean;
  deniedRule: string | null;
  warnedRule: string | null; // credential warning (prompt, not block)
  symlinkHint: string | null; // e.g. "/home/user/data → /mnt/storage"
}

export interface McpPromptData {
  type: "mcp";
  server: string;
  tool: string;
  op: string;
  /** Truncated tool arguments for display in permission prompts. */
  argsPreview?: string;
}

export type PromptData = BashPromptData | FilePromptData | McpPromptData;

// ── Decision engine ──

/**
 * Pure decision function. Given a permission request and the current store state,
 * returns a decision: auto-allow, block, or prompt.
 *
 * UI-agnostic — always returns "prompt" when human judgment is needed,
 * regardless of whether a UI is available. The handler adapts.
 */
export async function decide(request: PermissionRequest, store: Store): Promise<Decision> {
  switch (request.type) {
    case "bash":
      return decideBash(request, store);
    case "file":
      return decideFile(request, store);
    case "mcp":
      return decideMcp(request, store);
  }
}
