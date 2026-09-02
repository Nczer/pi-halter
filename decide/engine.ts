/**
 * Decision engine — the async policy dispatcher.
 *
 * Given a permission request and the current store state, routes to the
 * right policy (bash rule pipeline, file checks, tool grants) and returns
 * a decision: auto-allow, block, or prompt. UI-agnostic: it always returns
 * "prompt" when human judgment is needed, regardless of whether a UI is
 * available. The gate (gate/gate.ts) adapts.
 *
 * The shared types (requests, decisions, prompt data) live in ./types.
 */
import fs from "node:fs";
import path from "node:path";
import { decideBash } from "./bash-policy";
import { decideFile } from "./file-policy";
import { resolvePathReal, isInsideCwd } from "../analysis/path-analysis";
import { expandTilde } from "../analysis/path-util";
import type {
  DecideOptions,
  Decision,
  PermissionRequest,
  Store,
  ToolPromptData,
  ToolRequest,
} from "./types";

export async function decide(request: PermissionRequest, store: Store, opts?: DecideOptions): Promise<Decision> {
  switch (request.type) {
    case "bash":
      return decideBash(request, store);
    case "file":
      return decideFile(request, store, opts);
    case "tool":
      return decideTool(request, store);
  }
}

/**
 * Tool-call decision (plugins). Grant model — two scopes, session-scoped:
 *  - `<tool>` (whole tool; the "Always" on an exec/file prompt): covers
 *    every action of the tool, INCLUDING code execution;
 *  - `<tool>:kind:<consentKind>` (the "Always" on a consent prompt): covers
 *    only that kind — a read consent can never cover an exec action.
 * No grant → prompt. (Per-action grants are a later refinement.)
 */
function decideTool(req: ToolRequest, store: Store): Decision {
  if (store.hasToolGrant(req.tool)) return { kind: "auto-allow" };
  if (req.gate === "consent" && req.consentKind
      && store.hasToolGrant(`${req.tool}:kind:${req.consentKind}`)) {
    return { kind: "auto-allow" };
  }
  const pd: ToolPromptData = {
    type: "tool",
    tool: req.tool,
    label: req.label,
    gate: req.gate,
    script: req.script,
    argsPreview: req.argsPreview,
    consentKind: req.consentKind,
    note: req.note,
  };
  if (req.gate === "file" && req.path) {
    const resolved = resolvePathReal(expandTilde(req.path), req.cwd);
    pd.resolved = resolved;
    pd.outsideDir = isInsideCwd(resolved, req.cwd) ? null : path.dirname(resolved);
    pd.exists = fs.existsSync(resolved);
  }
  return { kind: "prompt", promptData: pd };
}
