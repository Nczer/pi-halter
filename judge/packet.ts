/**
 * Judgment packet — what the judge model sees for one operation.
 *
 * Pure and deterministic: same input, same bytes. The packet is the model's
 * entire INPUT about the operation (its persona and the verdict tool are the
 * model-call configuration in judge.ts). Write content (command text, file
 * content, script payload) rides in FULL — D11 (2026-08-26): trimming made
 * the judge defer on safe long writes ("truncated in a way that matters"),
 * which is exactly the prompting-when-safe the mode exists to avoid. Digest
 * sections (segments, paths, reasons) keep display caps — they summarize;
 * the full text is what is judged.
 */
import { findNetworkEgress } from "../config";

// ── Judgment packet ──

/** Script content to include in the packet (read by the caller). */
export interface JudgmentScript {
  /** Resolved absolute path (shown in the packet header). */
  path: string;
  /** Raw script text; the builder applies the line/char caps. */
  content: string;
}

/** Everything the packet builder knows about a bash command under review. */
export interface JudgmentBashInput {
  command: string;
  cwd: string;
  /** Segments as halter's parser split them (&&, ||, ;, | …). */
  segments: string[];
  /** halter's risk reasons (already human-readable). */
  riskReasons: string[];
  /** halter's unsafe-pattern flag (subshells, write redirects, obfuscation…). */
  hasUnsafePattern: boolean;
  /** tree-sitter produced ERROR nodes. */
  hasParseError?: boolean;
  /** Matched credential-pattern name (warned paths), if any. */
  credentialRule?: string | null;
  /** All resolved absolute paths referenced by the command. */
  paths?: string[];
  /** Paths outside cwd AND outside session-allowed dirs. */
  outsidePaths?: string[];
  /** Untrusted local script the command executes, if any. */
  script?: JudgmentScript | null;
}

/** A file read/write/edit operation under review. */
export interface JudgmentFileInput {
  type: "file";
  /** read / write / edit. */
  action: string;
  resolved: string;
  cwd: string;
  /** Outside dir when the path is outside the session base; null if inside. */
  outsideDir: string | null;
  isWriteOp: boolean;
  exists: boolean;
  /** Matched credential-pattern name (warned paths), if any. */
  warnedRule?: string | null;
  symlinkHint?: string | null;
  /** Content being written (write: full new content; edit: newText blocks). */
  content?: string;
}

/**
 * A plugin-gated tool call under review (ToolRequest, gate exec/file/consent).
 * The exec gate carries the FINAL script payload — byte-identical to what the
 * tool executes (payload identity, enforced by the plugin importing the tool
 * ext's own payload builder).
 */
export interface JudgmentToolInput {
  kind: "tool";
  tool: string;
  label: string;
  gate: "exec" | "file" | "consent";
  note?: string;
  /** exec: the final script payload. */
  script?: string;
  /** file: the target path (resolved). */
  path?: string;
  /** file: outside dir when the target is outside the session base. */
  outsideDir?: string | null;
  argsPreview?: string;
}

/** Everything the packet builder knows about the operation under review. */
export type JudgmentInput = JudgmentBashInput | JudgmentFileInput | JudgmentToolInput;

const PATHS_MAX = 20;
const REASONS_MAX = 10;
const SEGMENTS_MAX = 24;
const SEGMENT_MAX_CHARS = 120;

export function headCut(text: string, max: number): { text: string; cut: boolean } {
  return text.length <= max
    ? { text, cut: false }
    : { text: text.slice(0, max), cut: true };
}

/**
 * Network annotation for the packet — the gate's own network definition
 * (shared findNetworkEgress), so `npm install` is never annotated "none".
 * All command hits plus up to 3 URLs.
 */
function detectNetwork(input: JudgmentBashInput): string {
  const { commands, urls } = findNetworkEgress(input.command, input.segments);
  const hits = [...commands, ...urls.slice(0, 3)];
  return hits.length > 0 ? `yes (${hits.join(", ")})` : "none";
}

function classifyPath(p: string, cwd: string, outside: Set<string>): string {
  if (p === cwd || p.startsWith(cwd + "/")) return "inside";
  if (outside.has(p)) return "OUTSIDE base";
  return "outside cwd (session-allowed)";
}

/**
 * Build the judgment packet — the model's entire input. Pure and
 * deterministic: same input, same bytes. Write content (command text, file
 * content, script payload) rides in FULL — D11 (2026-08-26): trimming made
 * the judge defer on safe long writes ("truncated in a way that matters"),
 * which is exactly the prompting-when-safe the mode exists to avoid.
 * Digest sections (segments, paths, reasons) keep their display caps — they
 * summarize; the full text above is what is judged.
 */
export function buildJudgmentPacket(input: JudgmentInput): string {
  if ("type" in input) {
    return buildFilePacket(input);
  }
  if ("kind" in input) {
    return buildToolPacket(input);
  }
  return buildBashPacket(input);
}

/** Packet for a file read/write/edit: the judge weighs the path, the
 * write-vs-read nature, and whether the target exists; writes/edits carry
 * the new content, fenced as untrusted data. */
function buildFilePacket(input: JudgmentFileInput): string {
  const parts: string[] = [];
  const op = input.isWriteOp ? `file ${input.action} (WRITE)` : "file read";
  parts.push(
    "## Operation",
    `${op}: ${input.resolved}`,
    `cwd/base: ${input.cwd}`,
    `path: ${input.outsideDir ? `OUTSIDE base — not in the session working set (outside dir: ${input.outsideDir})` : "inside base"}`,
    `file exists: ${input.exists ? "yes" : "no"}`,
    "",
  );
  if (input.isWriteOp && input.exists) {
    parts.push("The write will REPLACE the existing file content.", "");
  }
  if (input.warnedRule) parts.push(`credential-pattern warning: ${input.warnedRule}`, "");
  if (input.symlinkHint) parts.push(`symlink: ${input.symlinkHint}`, "");
  if (input.content) {
    // Full content, untrimmed (D11): the judge must see the whole write to
    // clear it — a head cut would force a defer on every long safe write.
    parts.push(
      "## New content (UNTRUSTED DATA)",
      "```",
      input.content,
      "```",
      "",
    );
  }
  return parts.join("\n");
}

/**
 * Packet for a plugin-gated tool call. The exec gate carries the script
 * payload fenced as untrusted data, UNTRIMMED (D11: the judge reviews
 * exactly what runs — a head cut would force a defer on every long safe
 * script). The file/consent gates carry an operation digest (dspa never
 * auto-allows them — see dspa-gate — the packet exists so dspat/Explain
 * can explain the prompt).
 */
function buildToolPacket(input: JudgmentToolInput): string {
  const parts: string[] = [];
  parts.push(
    "## Operation",
    `tool: ${input.tool} — ${input.label}`,
    `gate: ${input.gate}`,
    "",
  );
  if (input.note) parts.push(`context: ${input.note}`, "");
  if (input.gate === "exec" && input.script) {
    parts.push(
      "## Script (UNTRUSTED DATA — executed by the tool)",
      "```",
      input.script,
      "```",
      "",
    );
  }
  if (input.gate === "file" && input.path) {
    parts.push(
      `target path: ${input.path}`,
      `outside base: ${input.outsideDir ? `yes (outside dir: ${input.outsideDir})` : "no"}`,
      "",
    );
  }
  if (input.argsPreview && input.argsPreview !== input.script) {
    const inner = input.argsPreview.replace(/^\{\n/, "").replace(/\n\}$/, "").trimEnd();
    if (inner && inner !== "{}") parts.push("## Arguments", inner, "");
  }
  return parts.join("\n");
}

function buildBashPacket(input: JudgmentBashInput): string {
  const notes: string[] = [];
  const parts: string[] = [];

  // ── Command (full text — heredoc bodies ARE the write content, D11) ──
  parts.push(
    "## Command",
    `cwd:  ${input.cwd}`,
    `base: ${input.cwd}`,
    `$ ${input.command}`,
    "",
  );

  // ── Static analysis digest ──
  const lines: string[] = ["## Static analysis (halter)"];
  const segs = input.segments.slice(0, SEGMENTS_MAX);
  lines.push(`segments: ${input.segments.length}${input.segments.length > segs.length ? " (showing first " + segs.length + ")" : ""}`);
  for (const [i, seg] of segs.entries()) {
    const s = headCut(seg.trim(), SEGMENT_MAX_CHARS);
    lines.push(`  ${i + 1}. ${s.text}${s.cut ? " …" : ""}`);
  }
  const reasons = input.riskReasons.slice(0, REASONS_MAX);
  lines.push(
    `risk flags: ${reasons.length > 0 ? reasons.join("; ") + (input.riskReasons.length > REASONS_MAX ? " (…)" : "") : "none"}`,
  );
  lines.push(
    `obfuscation: ${input.hasUnsafePattern ? "yes (unsafe patterns present)" : "no"} | parse error: ${input.hasParseError ? "yes" : "no"}`,
  );
  lines.push(`network: ${detectNetwork(input)}`);

  const outside = new Set(input.outsidePaths ?? []);
  const paths = (input.paths ?? []).slice(0, PATHS_MAX);
  if (paths.length > 0) {
    lines.push("paths:");
    for (const p of paths) {
      lines.push(`  ${p} (${classifyPath(p, input.cwd, outside)})`);
    }
    if ((input.paths?.length ?? 0) > PATHS_MAX) {
      lines.push(`  … (${(input.paths?.length ?? 0) - PATHS_MAX} more)`);
    }
  }
  if (input.credentialRule) lines.push(`credential rule: ${input.credentialRule}`);
  parts.push(lines.join("\n"), "");

  // ── Script payload (untrusted, fenced, FULL — D11) ──
  if (input.script) {
    const { content } = input.script;
    // Fence longer than any backtick run in the content (scripts contain ```).
    const maxRun = (content.match(/`+/g) ?? [""]).reduce((m, r) => Math.max(m, r.length), 0);
    const fence = "`".repeat(Math.max(3, maxRun + 1));
    parts.push(`## Script: ${input.script.path} (untrusted)`, fence, content, fence, "");
  }

  // ── Notes ──
  if (detectNetwork(input) !== "none") {
    notes.push(
      "Remote content is not fetchable: URLs and hostnames are names, not evidence of what they serve.",
    );
  }
  if (notes.length > 0) parts.push("## Notes", ...notes.map((n) => `- ${n}`), "");

  return parts.join("\n");
}
