import type { ExtensionContext, ToolCallEvent } from "@earendil-works/pi-coding-agent";
import fs from "node:fs";
import type { FileRequest } from "../decision-engine";
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

  // Pre-validate edit calls — skip the permission prompt if the edit would fail anyway.
  // Structurally validate first (no fs access), then only read file content for ordinary
  // paths. Denied/warned paths are credentials (secrets) — they must reach the gate before
  // any read, otherwise this handler would read sensitive content before the permission
  // check decides whether the access is even allowed.
  if (toolName === "edit") {
    const edits = input.edits;
    if (!edits || !Array.isArray(edits) || edits.length === 0) return;
    if (!edits.every(e => typeof e.oldText === "string" && typeof e.newText === "string")) return;

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

  const request: FileRequest = {
    type: "file",
    toolName: toolName as "read" | "write" | "edit",
    filePath,
    cwd: ctx.cwd,
    resolvedPath,
  };

  return await gate(request, ctx, store, (decision, result) =>
    rejectFile(decision, result, store, ctx),
  );
}
