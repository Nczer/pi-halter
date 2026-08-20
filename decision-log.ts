/**
 * JSONL decision log — blast-radius measurement.
 *
 * Every decision that flows through the gate is appended as one JSON line,
 * so "what the gate decided, and why" can be reviewed after the fact:
 *  • after changing gate code — did anything that used to auto-allow start
 *    prompting (or vice versa)?
 *  • mining contract rows — which commands prompt repeatedly?
 *
 * Fire-and-forget: a logging failure must never affect the gate decision
 * (this runs inside the gate; a throw would become a fail-closed block).
 *
 * Default path: <extension dir>/.log/decisions.jsonl, rotated to
 * decisions.jsonl.1 when it exceeds 5 MiB (older backup overwritten).
 * Override: HALTER_DECISION_LOG=<path> or HALTER_DECISION_LOG=off.
 * Under vitest the default is disabled (tests opt in via the env override).
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { Decision, PermissionRequest } from "./decision-engine";

const here = path.dirname(fileURLToPath(import.meta.url));

export const DEFAULT_LOG_FILE = path.join(here, ".log", "decisions.jsonl");
export const MAX_LOG_BYTES = 5 * 1024 * 1024;
const MAX_TARGET_LEN = 1000;

export interface DecisionLogEntry {
  /** ISO timestamp. */
  ts: string;
  tool: "bash" | "file" | "mcp";
  kind: Decision["kind"];
  /** Block reason, or a one-line summary of why a prompt was needed; null for auto-allow. */
  reason: string | null;
  /** Bash command (truncated), file path, or "server/tool". */
  target: string;
  /** The tool call's working directory (bash + file). */
  cwd?: string;
}

/** Resolve the active log file. null = logging disabled. */
export function resolveLogPath(): string | null {
  const env = process.env.HALTER_DECISION_LOG;
  if (env === "off" || env === "") return null;
  if (!env && process.env.VITEST_WORKER_ID) return null;
  return env || DEFAULT_LOG_FILE;
}

/**
 * Append one decision to the JSONL log. Never throws — logging problems are
 * silently dropped; the gate's behavior must not depend on disk state.
 */
export function logDecision(request: PermissionRequest, decision: Decision): void {
  try {
    const file = resolveLogPath();
    if (!file) return;

    const entry: DecisionLogEntry = {
      ts: new Date().toISOString(),
      tool: request.type,
      kind: decision.kind,
      reason:
        decision.kind === "block"
          ? decision.reason
          : decision.kind === "prompt"
            ? summarizePrompt(decision)
            : null,
      target: targetOf(request).slice(0, MAX_TARGET_LEN),
      cwd: "cwd" in request ? request.cwd : undefined,
    };
    const line = JSON.stringify(entry) + "\n";

    let size = 0;
    try {
      size = fs.statSync(file).size;
    } catch {
      /* new file */
    }
    if (size + line.length > MAX_LOG_BYTES) {
      try {
        fs.renameSync(file, file + ".1");
      } catch {
        /* keep logging even if the backup fails */
      }
    }
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.appendFileSync(file, line);
  } catch {
    /* never throw */
  }
}

function targetOf(request: PermissionRequest): string {
  if (request.type === "bash") return request.command;
  if (request.type === "file") return request.filePath;
  return `${request.server}/${request.tool}`;
}

/** One-line "why did this prompt" summary (the useful half of PromptData). */
function summarizePrompt(decision: Extract<Decision, { kind: "prompt" }>): string {
  const p = decision.promptData;
  if (p.type === "bash") {
    const parts: string[] = [];
    if (p.credentialRule) parts.push(`credential ${p.credentialRule}`);
    if (p.riskSeverity) parts.push(`risk:${p.riskSeverity} ${p.riskReasons.join("; ")}`);
    if (p.hasUnsafePattern) parts.push("unsafe pattern");
    if (p.needsCommandApproval) parts.push(`cmd ${p.signatures.slice(0, 3).join(",")}`);
    if (p.needsPathApproval) parts.push(`outside ${p.outsideDirs.slice(0, 3).join(",")}`);
    return parts.join("; ") || "unclassified";
  }
  if (p.type === "file") {
    let s = p.isWriteOp ? "file write" : "file read";
    if (p.outsideDir) s += ` outside ${p.outsideDir}`;
    if (p.warnedRule) s += ` warn ${p.warnedRule}`;
    return s;
  }
  return `mcp ${p.op}`;
}
