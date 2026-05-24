import path from "node:path";
import fs from "node:fs";
import { ABORT_REMEMBER_MS, allowedBashPatterns } from "./config";
import { analyzeCommand, isFirstTokenRelativePath } from "./command-analysis";
import {
  resolvePathReal,
  expandTilde,
  isInsideCwd,
  isInsideAutoAllowedDir,
  isAllowedReadPath,
  isAllowedWritePath,
  isProjectPiPath,
  isPathDenied,
  getOutsideCwdPaths,
} from "./path-analysis";
import type { Store, AllowRules } from "./store";

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
}

export interface McpRequest {
  type: "mcp";
  server: string;
  tool: string;
  /** Truncated tool arguments for display in permission prompts. */
  argsPreview?: string;
}

type PermissionRequest = BashRequest | FileRequest | McpRequest;

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
  /** Rules to apply if user selects "Always (everything)". */
  allowRules: AllowRules;
  /** Rules to apply if user selects "Always (paths only)" (bash only). */
  allowPathsRules?: AllowRules;
  /** Rules to apply if user selects "This file only" (file only). */
  allowFileRules?: AllowRules;
  /** Whether to include the "Always (paths only)" option. */
  includePathsOption?: boolean;
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

// ── Bash decision ──

async function decideBash(req: BashRequest, store: Store): Promise<Decision> {
  // Retry-loop prevention
  const lastAbort = store.getLastAbort(req.command);
  if (lastAbort && Date.now() - lastAbort < ABORT_REMEMBER_MS) {
    return {
      kind: "block",
      reason:
        "Blocked by bash-guard: command was already aborted recently. " +
        "Ask the user for a safer alternative; do not retry the same command.",
    };
  }

  const analysis = await analyzeCommand(req.command, req.cwd);
  const outsidePaths = getOutsideCwdPaths(
    analysis.paths,
    req.cwd,
    store.listAllowedReadDirs(),
    store.listAllowedWriteDirs(),
  );

  // Auto-allow: all segments simple + no unsafe patterns + no unapproved outside paths
  if (analysis.allSimple && !analysis.hasUnsafePattern && outsidePaths.length === 0) {
    return { kind: "auto-allow" };
  }

  // Auto-allow if all signatures are either previously approved or in the static allowlist
  // Relative path signatures (./scripts/foo) must not match the allowlist
  // Segments with relative path arguments (timeout 30 ./scripts/foo.sh) must also be blocked
  const hasRelativePathArg = (seg: string) => {
    const tokens = seg.trim().split(/\s+/);
    for (let i = 1; i < tokens.length; i++) {
      if (isFirstTokenRelativePath(tokens[i])) return true;
    }
    return false;
  };
  const isSigApproved = (sig: string, segIdx: number) => {
    if (store.hasAllowedBash(sig)) return true;
    if (isFirstTokenRelativePath(sig)) return false;
    // Check if the segment has relative path arguments
    if (hasRelativePathArg(analysis.segments[segIdx])) return false;
    return allowedBashPatterns.some(p => p.test(sig.split(/\s+/)[0]));
  };
  if (analysis.signatures.every((sig, i) => isSigApproved(sig, i))) {
    if (!analysis.hasUnsafePattern && outsidePaths.length === 0) {
      return { kind: "auto-allow" };
    }
  }

  // For directories, use the path itself; for files, use the parent directory.
  const outsideDirs = [...new Set(outsidePaths.map(p => {
    try {
      const stat = fs.statSync(p);
      return stat.isDirectory() ? p : path.dirname(p);
    } catch {
      return path.dirname(p); // Assume directory if stat fails (e.g. non-existent)
    }
  }))].sort();
  const needsCommandApproval = !analysis.allSimple;
  const needsPathApproval = outsidePaths.length > 0;

  if (!needsCommandApproval && !needsPathApproval) {
    return { kind: "auto-allow" };
  }

  // Only store signatures that aren't already in the static allowlist.
  // Allowed commands auto-allow via `allSimple` anyway — no need to clutter the store.
  // Redirect-only segments (e.g. 2>/dev/null) are not commands — skip them.
  const isRedirectOnly = (text: string) => /^[0-9]*&?>+/.test(text.trim());
  const nonAllowlistedSegmentIndices = analysis.signatures
    .map((sig, i) =>
      isRedirectOnly(analysis.segments[i])
        ? -1
        : allowedBashPatterns.some(p => p.test(sig.split(/\s+/)[0])) ? -1 : i,
    )
    .filter(i => i >= 0);
  const nonAllowlistedSigs = nonAllowlistedSegmentIndices.map(i => analysis.signatures[i]);
  const uniqueSigs = [...new Set(nonAllowlistedSigs)];

  // Build allow rules for "always" confirmation
  const allowRules: AllowRules = {};
  if (needsPathApproval) allowRules.readDirs = outsideDirs;
  if (needsCommandApproval && nonAllowlistedSigs.length > 0) allowRules.bashSigs = nonAllowlistedSigs;

  const hasBoth = needsCommandApproval && needsPathApproval;
  const allowPathsRules = hasBoth
    ? { readDirs: outsideDirs }
    : undefined;

  return {
    kind: "prompt",
    promptData: {
      type: "bash",
      command: req.command,
      cwd: req.cwd,
      outsideDirs,
      segments: analysis.segments,
      signatures: uniqueSigs,
      nonAllowedSegmentIndices: nonAllowlistedSegmentIndices,
      riskDangerous: analysis.risk.dangerous,
      riskSeverity: analysis.risk.severity,
      riskReasons: analysis.risk.reasons,
      needsCommandApproval,
      needsPathApproval,
    },
    allowRules,
    allowPathsRules,
    includePathsOption: hasBoth,
  };
}

// ── File decision ──

function decideFile(req: FileRequest, store: Store): Decision {
  const resolved = resolvePathReal(expandTilde(req.filePath), req.cwd);

  // Denied paths block everything — check before any auto-allow
  const deniedResult = isPathDenied(req.filePath, req.cwd);
  if (deniedResult.denied) {
    return { kind: "block", reason: `Blocked: '${deniedResult.matchedRule}' is a denied path (credentials/secrets)` };
  }

  // Auto-allow checks
  if (isProjectPiPath(req.filePath, req.cwd)) return { kind: "auto-allow" };
  if (req.toolName === "read" && store.hasAllowedReadPath(resolved)) return { kind: "auto-allow" };
  if (req.toolName !== "read" && store.hasAllowedWritePath(resolved)) return { kind: "auto-allow" };

  const autoAllowedDirs = req.toolName === "read"
    ? store.listAllowedReadDirs()
    : store.listAllowedWriteDirs();

  if (!isInsideCwd(resolved, req.cwd) && isInsideAutoAllowedDir(resolved, autoAllowedDirs)) {
    return { kind: "auto-allow" };
  }
  if (req.toolName === "read" && isAllowedReadPath(resolved)) return { kind: "auto-allow" };
  if (req.toolName !== "read" && isAllowedWritePath(resolved)) return { kind: "auto-allow" };
  if (req.toolName === "read" && isInsideCwd(resolved, req.cwd)) return { kind: "auto-allow" };
  const action = req.toolName.charAt(0).toUpperCase() + req.toolName.slice(1);
  const isWriteOp = req.toolName !== "read";

  // Detect symlink: compare parent of original path vs parent of resolved path
  const originalParent = path.dirname(expandTilde(req.filePath));
  const resolvedParent = path.dirname(resolved);
  const symlinkHint = originalParent !== resolvedParent
    ? `${originalParent} → ${resolvedParent}`
    : null;

  const promptData: FilePromptData = {
    type: "file",
    action,
    filePath: req.filePath,
    resolved,
    cwd: req.cwd,
    outsideDir: isInsideCwd(resolved, req.cwd) ? null : path.dirname(resolved),
    isWriteOp,
    deniedRule: deniedResult.matchedRule,
    symlinkHint,
  };

  const allowRules: AllowRules = isInsideCwd(resolved, req.cwd)
    ? (isWriteOp ? { writePaths: [resolved] } : { readPaths: [resolved] })
    : (isWriteOp ? { writeDirs: [path.dirname(resolved)] } : { readDirs: [path.dirname(resolved)] });

  const allowFileRules = isInsideCwd(resolved, req.cwd)
    ? undefined
    : (isWriteOp ? { writePaths: [resolved] } : { readPaths: [resolved] });

  return { kind: "prompt", promptData, allowRules, allowFileRules };
}

// ── MCP decision ──────────────────────────────────────────────────────────

/**
 * Parse qualified tool name `server:tool` to extract server.
 */
function parseServerFromTool(tool: string): string | null {
  const colonIndex = tool.indexOf(":");
  if (colonIndex > 0 && colonIndex < tool.length - 1) {
    return tool.slice(0, colonIndex).trim();
  }
  return null;
}

function decideMcp(req: McpRequest, store: Store): Decision {
  // Auto-allow if server is already approved
  if (store.hasAllowedMcpServer(req.server)) {
    return { kind: "auto-allow" };
  }

  // Try to extract server from tool name if not explicitly provided
  const toolServer = parseServerFromTool(req.tool);
  const effectiveServer = toolServer ?? req.server;

  // Never allow "unknown" servers — they would auto-allow all unresolvable tools
  if (effectiveServer === "unknown") {
    return {
      kind: "block",
      reason: `Blocked: cannot resolve MCP server for tool '${req.tool}'. Refusing unresolvable server identifier.`,
    };
  }

  return {
    kind: "prompt",
    promptData: {
      type: "mcp",
      server: effectiveServer,
      tool: req.tool,
      op: "call",
      argsPreview: req.argsPreview,
    },
    allowRules: { mcpServers: [effectiveServer] },
  };
}
