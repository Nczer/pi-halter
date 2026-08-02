import type { ExtensionContext, ToolCallEvent } from "@earendil-works/pi-coding-agent";
import fs from "node:fs";
import type { FileRequest } from "../decision-engine";
import { decide } from "../decision-engine";
import { gate, rejectFile } from "../gate";
import { store } from "../store";
import {
  expandTilde,
  resolvePathReal,
  isPathDeniedResolved,
  isPathWarnedResolved,
} from "../analysis/path-analysis";

const FILE_TOOLS = ["read", "write", "edit"] as const;

/** Skip edit pre-validation above this size — a full readFileSync would stall the TUI. */
const EDIT_PREVALIDATE_MAX_BYTES = 1_048_576; // 1 MB

export async function handleFile(
  event: ToolCallEvent,
  ctx: ExtensionContext,
) {
  const toolName = event.toolName as string;
  if (!FILE_TOOLS.includes(toolName as "read" | "write" | "edit")) return;

  const input = event.input as { path?: string; edits?: Array<{ oldText: string; newText: string }> };
  const filePath = input.path;
  if (!filePath) return;

  // Resolve once — reused by pre-validation and decision engine
  const resolvedPath = resolvePathReal(expandTilde(filePath), ctx.cwd);

  // Structurally validate edit calls first (no fs access).
  let edits: Array<{ oldText: string; newText: string }> | null = null;
  if (toolName === "edit") {
    edits = input.edits ?? null;
    if (!edits || !Array.isArray(edits) || edits.length === 0) return;
    if (!edits.every(e => typeof e.oldText === "string" && typeof e.newText === "string")) return;
  }

  const request: FileRequest = {
    type: "file",
    toolName: toolName as "read" | "write" | "edit",
    filePath,
    cwd: ctx.cwd,
    resolvedPath,
  };

  // Decide BEFORE any file-content read. Pre-validation only runs for paths the
  // gate would auto-allow anyway — reading a prompted/blocked path first would
  // leak its content through prompt visibility (e.g. "oldText occurs exactly
  // once" only appearing when the edit would succeed).
  const decision = await decide(request, store);

  if (toolName === "edit" && decision.kind === "auto-allow" && edits) {
    // Defense-in-depth: never read credential paths even if some auto-allow
    // path (e.g. an allowed dir) overlaps a warned name.
    const isCredentialPath =
      isPathDeniedResolved(filePath, resolvedPath).denied ||
      isPathWarnedResolved(filePath, resolvedPath).warned;

    if (!isCredentialPath) {
      try {
        // Size cap: skip pre-validation on large files rather than blocking the
        // event loop on a full synchronous read. The edit will simply prompt.
        if (fs.statSync(resolvedPath).size <= EDIT_PREVALIDATE_MAX_BYTES) {
          const content = fs.readFileSync(resolvedPath, "utf-8");
          for (const edit of edits) {
            if (edit.oldText === edit.newText) return; // Identical content — edit will fail
            const matches: number[] = [];
            let idx = 0;
            while (idx < content.length) {
              const pos = content.indexOf(edit.oldText, idx);
              if (pos === -1) break;
              matches.push(pos);
              idx = pos + 1;
            }
            if (matches.length !== 1) return; // 0 or multiple matches — edit will fail
          }
        }
      } catch {
        return; // Can't read file — skip prompt
      }
    }
  }

  return await gate(request, ctx, store, (decision, result) =>
    rejectFile(decision, result, store, ctx),
    decision,
  );
}
