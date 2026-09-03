import type { ExtensionContext, ToolCallEvent } from "@earendil-works/pi-coding-agent";
import fs from "node:fs";
import type {FileRequest} from "../decide/types";
import { gate, gateDecide, rejectFile } from "../gate/gate";
import { store } from "../gate/store";
import {
  expandTilde,
  resolvePathReal,
  isPathDeniedResolved,
  isPathWarnedResolved,
} from "../analysis/path-analysis";

const FILE_TOOLS = ["read", "write", "edit"] as const;

/** Skip edit pre-validation above this size — a full readFileSync would stall the TUI. */
const EDIT_PREVALIDATE_MAX_BYTES = 1_048_576; // 1 MB

/** Context lines shown around each replaced region in the edit after-view. */
const EDIT_VIEW_CONTEXT = 10;

/** Index of a needle occurring EXACTLY once in the haystack (pi edit
 * semantics — 0 or 2+ occurrences fail the edit); -1 otherwise. */
function uniqueIndexOf(haystack: string, needle: string): number {
  if (needle === "") return -1;
  const first = haystack.indexOf(needle);
  if (first === -1) return -1;
  return haystack.indexOf(needle, first + 1) === -1 ? first : -1;
}

/**
 * The judge's view of an edit: the file AFTER all blocks are applied, each
 * replaced region shown with ±EDIT_VIEW_CONTEXT context lines. Line numbers
 * are 1-based final-file lines; '>' marks the lines the edit sets, '·'
 * context, '…' omitted runs.
 *
 * Built on a marker-stamped copy — replacement i is bracketed by
 * \u0001i\u0002 … \u0001i\u0003 — so the changed ranges are read off the FINAL
 * file (later blocks' line shifts are already reflected). Returns null when
 * a block does not match exactly once (the caller pre-validates; defensive).
 *
 * The after-view is the edit's EFFECT (delta + where it lands). Unlike a
 * write — where the whole new file IS the effect and rides untrimmed (D11) —
 * the surrounding file is context, so it stays bounded.
 */
export function buildEditAfterView(
  file: string,
  edits: Array<{ oldText: string; newText: string }>,
): string | null {
  let marked = file;
  for (let i = 0; i < edits.length; i++) {
    const pos = uniqueIndexOf(marked, edits[i].oldText);
    if (pos === -1) return null;
    marked =
      marked.slice(0, pos) +
      `\u0001${i}\u0002` +
      edits[i].newText +
      `\u0001${i}\u0003` +
      marked.slice(pos + edits[i].oldText.length);
  }
  const lines = marked.split("\n");
  const ranges: Array<[number, number]> = []; // 0-based final-file line ranges
  for (let i = 0; i < edits.length; i++) {
    let start = -1;
    let end = -1;
    for (let l = 0; l < lines.length; l++) {
      if (start === -1 && lines[l].includes(`\u0001${i}\u0002`)) start = l;
      if (lines[l].includes(`\u0001${i}\u0003`)) end = l;
    }
    if (start === -1 || end === -1) return null; // marker lost — impossible; defensive
    ranges.push([Math.min(start, end), Math.max(start, end)]);
  }
  const finalLines = lines.map((l) => l.replace(/\u0001\d+\u0002|\u0001\d+\u0003/g, ""));
  const total = finalLines.length;

  const changed = new Set<number>();
  for (const [s, e] of ranges) for (let l = s; l <= e; l++) changed.add(l);

  // ±context around each range, merged into display intervals.
  const intervals = ranges
    .map(
      ([s, e]) =>
        [Math.max(0, s - EDIT_VIEW_CONTEXT), Math.min(total - 1, e + EDIT_VIEW_CONTEXT)] as [number, number],
    )
    .sort((a, b) => a[0] - b[0]);
  const merged: Array<[number, number]> = [];
  for (const iv of intervals) {
    if (merged.length > 0 && iv[0] <= merged[merged.length - 1][1] + 1) {
      merged[merged.length - 1][1] = Math.max(merged[merged.length - 1][1], iv[1]);
    } else {
      merged.push([iv[0], iv[1]]);
    }
  }

  const deletions = edits.filter((e) => e.newText === "").length;
  const out: string[] = [
    `${total} lines total · ${edits.length} replacement${edits.length === 1 ? "" : "s"}` +
      (deletions ? ` (${deletions} deletion${deletions === 1 ? "" : "s"})` : "") +
      ` · ${EDIT_VIEW_CONTEXT}-line context · '>' = line set by the edit, '·' = context`,
  ];
  let cursor = 0;
  for (const [s, e] of merged) {
    if (s > cursor) out.push("…");
    for (let l = s; l <= e; l++) {
      out.push(`${String(l + 1).padStart(4, " ")} ${changed.has(l) ? ">" : "·"} ${finalLines[l]}`);
    }
    cursor = e + 1;
  }
  if (cursor < total) out.push("…");
  return out.join("\n");
}

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
          // Every block matches exactly once: swap the judge's input from the
          // bare newText blocks to the AFTER-EDIT file view (replaced regions
          // with context, line numbers). A fragment alone reads "truncated /
          // non-self-contained" and forced a stage-2 pass — and a defer — on
          // every safe edit; the human prompt is untouched (judge input only).
          if (decision.kind === "prompt" && decision.promptData.type === "file") {
            const view = buildEditAfterView(content, edits);
            if (view) {
              decision.promptData.content = view;
              decision.promptData.contentHeading = "File after this edit";
            }
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
