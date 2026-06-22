import type { ExtensionContext, ToolCallEvent } from "@earendil-works/pi-coding-agent";
import path from "node:path";
import fs from "node:fs";
import type { FileRequest } from "../decision-engine";
import { decide } from "../decision-engine";
import { showPrompt } from "../prompt-flow";
import { store } from "../store";
import {
  expandTilde,
  resolvePathReal,
} from "../analysis/path-analysis";

const FILE_TOOLS = ["read", "write", "edit"] as const;

export async function handleFile(
  event: ToolCallEvent,
  ctx: ExtensionContext,
) {
  const toolName = event.toolName as string;
  if (!FILE_TOOLS.includes(toolName as "read" | "write" | "edit")) return;

  const input = event.input as { path?: string; edits?: Array<{ oldText: string; newText: string }> };
  const filePath = input.path;
  if (!filePath) return;

  // Pre-validate edit calls — skip permission prompt if the edit would fail anyway
  if (toolName === "edit") {
    const edits = input.edits;
    if (!edits || !Array.isArray(edits) || edits.length === 0) return;
    if (!edits.every(e => typeof e.oldText === "string" && typeof e.newText === "string")) return;
    try {
      const resolvedPath = resolvePathReal(expandTilde(filePath), ctx.cwd);
      if (!fs.existsSync(resolvedPath)) return;
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
    } catch {
      return; // Can't read file — skip prompt
    }
  }

  const request: FileRequest = { type: "file", toolName: toolName as "read" | "write" | "edit", filePath, cwd: ctx.cwd };
  const decision = await decide(request, store);

  // Auto-allow: proceed without prompting
  if (decision.kind === "auto-allow") return;

  // Block: no prompt shown
  if (decision.kind === "block") {
    return { block: true, reason: decision.reason };
  }

  // No UI available — block
  if (!ctx.hasUI) {
    const pd = decision.promptData;
    const reasons: string[] = [];
    if (pd.type === "file" && pd.deniedRule) reasons.push(`matches denied rule "${pd.deniedRule}"`);
    if (pd.type === "file" && pd.outsideDir) reasons.push("outside cwd");
    const action = pd.type === "file" ? pd.action : "Access";
    return { block: true, reason: reasons.length > 0
      ? `[Permission Policy] Auto-blocked (no UI): ${action} ${filePath} — ${reasons.join(", ")}`
      : `[Permission Policy] Auto-blocked (no UI): ${action} ${filePath} requires confirmation` };
  }

  const wasExpanded = ctx.ui.getToolsExpanded();
  if (!wasExpanded) ctx.ui.setToolsExpanded(true);

  try {
    const result = await showPrompt(decision, ctx, store);
    if (!result.allowed) {
      // Note: unlike bash, we don't call store.recordAbort() here.
      // File accesses are deterministic (same path → same result) and the
      // agent's rejection reason is sufficient to prevent retry loops.
      const pd = decision.promptData;
      const action = (pd.type === "file" ? pd.action : "Access").toLowerCase();
      const resolved = pd.type === "file" ? pd.resolved : filePath;
      const reasonDetail = result.reason ? ` Reason: ${result.reason}.` : "";
      ctx.ui.notify(`Permission denied: ${action} ${path.basename(filePath)}`, "error");
      return { block: true, reason: `[USER REJECTED] You denied ${action} access to ${path.basename(filePath)} (${resolved}).${reasonDetail}` };
    }
  } finally {
    ctx.ui.setToolsExpanded(wasExpanded);
  }
}
