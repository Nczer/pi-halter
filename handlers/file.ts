import type { ExtensionContext, ToolCallEvent } from "@earendil-works/pi-coding-agent";
import fs from "node:fs";
import type { FileRequest } from "../decision-engine";
import { gate, gateDecide, rejectFile } from "../gate";
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

  const input = event.input as { path?: string; content?: string; edits?: Array<{ oldText: string; newText: string }> };
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

  // Content being written — carried for the judge (verification input),
  // never shown in the human prompt. write: full new content; edit: the
  // newText blocks (what lands in the file), joined with an ellipsis line.
  let content: string | undefined;
  if (toolName === "write" && typeof input.content === "string") {
    content = input.content;
  } else if (toolName === "edit" && edits && edits.length > 0) {
    content = edits.map((e) => e.newText).join("\n…\n");
  }

  const request: FileRequest = {
    type: "file",
    toolName: toolName as "read" | "write" | "edit",
    filePath,
    cwd: ctx.cwd,
    resolvedPath,
    content,
  };

  // Decide BEFORE any file-content read — and through gateDecide's fail-closed
  // guard (an analysis crash must yield a block decision, not an exception).
  const decision = await gateDecide(request, store, ctx);

  if (toolName === "edit" && edits && decision.kind !== "block") {
    // Pre-validation (also for PROMPT decisions): an edit whose oldText can't
    // match is guaranteed to fail — prompting the user for it is pure noise.
    // Pass it through so the agent gets the normal tool error instead.
    //
    // Credential paths (denied/warned) are NEVER pre-validated: prompt-vs-
    // silent-failure would leak whether a guessed oldText occurs exactly once
    // in the file — a content oracle on a secret. Those always prompt (or
    // block) without a content read, even when the edit will fail.
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
