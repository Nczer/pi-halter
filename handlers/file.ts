import type { ExtensionContext, ToolCallEvent } from "@earendil-works/pi-coding-agent";
import fs from "node:fs";
import type {FileRequest} from "../decide/types";
import { gate, gateDecide, rejectFile } from "../gate/gate";
import { store } from "../gate/store";
import {
  resolvePathReal,
  isPathWarnedResolved,
} from "../analysis/path-analysis";
import { expandTilde } from "../analysis/path-util";

const FILE_TOOLS = ["read", "write", "edit"] as const;

/** Skip edit pre-validation above this size — a full readFileSync would stall the TUI. */
const EDIT_PREVALIDATE_MAX_BYTES = 1_048_576; // 1 MB

/** Context lines shown around each replaced region in the edit after-view. */
const EDIT_VIEW_CONTEXT = 10;

// ── pi edit-tool match semantics (mirrored from the harness) ────────────
//
// pi matches every block against the ORIGINAL file (not sequentially) — but
// with two normalizations the exact-only check below would miss, and a miss
// here is not cosmetic: the pre-validation's `return` skips the gate, so a
// block pi WILL apply must never be classified as "guaranteed to fail".
// Mirrored from the installed harness edit tool (normalizeToLF,
// normalizeForFuzzyMatch, the fuzzy fallback, and fuzzy occurrence
// counting); keep in sync if pi changes its matcher.

/** Line-ending normalization: pi's `normalizeToLF`. */
function normalizeEditText(text: string): string {
  return text.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
}

/** pi's `normalizeForFuzzyMatch`: NFKC, per-line trailing-whitespace trim,
 *  typographic quotes/dashes/spaces folded to ASCII. */
function normalizeForFuzzyMatch(text: string): string {
  return text
    .normalize("NFKC")
    .split("\n")
    .map((line) => line.trimEnd())
    .join("\n")
    .replace(/[\u2018\u2019\u201A\u201B]/g, "'")
    .replace(/[\u201C\u201D\u201E\u201F]/g, '"')
    .replace(/[\u2010\u2011\u2012\u2013\u2014\u2015\u2212]/g, "-")
    .replace(/[\u00A0\u2002-\u200A\u202F\u205F\u3000]/g, " ");
}

/** pi's `fuzzyFindText`: exact hit first, then the fuzzy normalization. */
function findEdit(base: string, oldText: string): { index: number; length: number } | null {
  const exact = base.indexOf(oldText);
  if (exact !== -1) return { index: exact, length: oldText.length };
  const fBase = normalizeForFuzzyMatch(base);
  const fOld = normalizeForFuzzyMatch(oldText);
  const idx = fBase.indexOf(fOld);
  return idx === -1 ? null : { index: idx, length: fOld.length };
}

/** pi's `countOccurrences` — always on the fuzzy normalization. */
function countEdits(base: string, oldText: string): number {
  return normalizeForFuzzyMatch(base).split(normalizeForFuzzyMatch(oldText)).length - 1;
}

interface MatchedEditRange {
  start: number;
  end: number;
  newText: string;
  order: number;
}

/**
 * Compute non-overlapping match ranges against the original file using pi's
 * exact-then-fuzzy matcher (BOM-stripped, LF-normalized). Shared by
 * `editWillApply` and `buildEditAfterView` so pre-validation and the judge
 * packet never disagree about what pi will write.
 */
function matchEditRanges(
  rawContent: string,
  edits: Array<{ oldText: string; newText: string }>,
): {
  base: string;
  matchBase: string;
  ranges: MatchedEditRange[];
  needsFuzzy: boolean;
  normalized: Array<{ oldText: string; newText: string }>;
} | null {
  const base = normalizeEditText(rawContent.replace(/^\uFEFF/, ""));
  const normalized = edits.map((e) => ({
    oldText: normalizeEditText(e.oldText),
    newText: normalizeEditText(e.newText),
  }));
  // pi rejects an empty oldText (getEmptyOldTextError) before matching.
  if (normalized.length === 0 || normalized.some((e) => e.oldText.length === 0)) return null;
  // The matcher base flips to the fuzzy normalization when ANY block misses
  // exactly (pi's replacementBaseContent).
  const needsFuzzy = normalized.some((e) => base.indexOf(e.oldText) === -1);
  const matchBase = needsFuzzy ? normalizeForFuzzyMatch(base) : base;
  const ranges: MatchedEditRange[] = [];
  for (let i = 0; i < normalized.length; i++) {
    const e = normalized[i];
    const m = findEdit(matchBase, e.oldText);
    if (!m) return null; // not-found error
    if (countEdits(matchBase, e.oldText) > 1) return null; // duplicate error
    ranges.push({ start: m.index, end: m.index + m.length, newText: e.newText, order: i });
  }
  ranges.sort((a, b) => a.start - b.start);
  for (let i = 1; i < ranges.length; i++) {
    if (ranges[i - 1].end > ranges[i].start) return null; // overlap error
  }
  return { base, matchBase, ranges, needsFuzzy, normalized };
}

/**
 * Will pi's edit tool apply this multi-block edit? Mirrors the harness's
 * matcher end to end: BOM-stripped LF-normalized base, exact-then-fuzzy
 * lookup, fuzzy occurrence counting (a block that is unique exactly but
 * duplicated fuzzily fails with the duplicate error), the overlap check,
 * and the unchanged-replacement rejection. `false` = pi is guaranteed to
 * fail this call, so the pre-validation may pass it through ungated.
 */
export function editWillApply(
  rawContent: string,
  edits: Array<{ oldText: string; newText: string }>,
): boolean {
  const matched = matchEditRanges(rawContent, edits);
  if (!matched) return false;
  // No-change rejection (getNoChangeError): decidable without simulating
  // pi's splice only in the fully-exact all-identical case — every block
  // replaces its range with the same text, so the result equals the base.
  // A fuzzy no-op is NOT a failure: pi rewrites the matched lines from the
  // trim-normalized base, so it usually IS a write — never claim it fails.
  if (!matched.needsFuzzy && matched.normalized.every((e) => e.oldText === e.newText)) return false;
  return true;
}

/** Splice `±` markers + newText into `content`; `offset` re-bases absolute
 *  range offsets onto a slice of the matcher base. Reverse order so earlier
 *  offsets stay valid (pi's `applyReplacements`). */
function markRanges(
  content: string,
  ranges: MatchedEditRange[],
  offset = 0,
): string {
  let marked = content;
  for (let i = ranges.length - 1; i >= 0; i--) {
    const r = ranges[i];
    marked =
      marked.slice(0, r.start - offset) +
      `\u0001${r.order}\u0002` +
      r.newText +
      `\u0001${r.order}\u0003` +
      marked.slice(r.end - offset);
  }
  return marked;
}

/**
 * pi's `applyReplacementsPreservingUnchangedLines`, mirrored (see also
 * `getReplacementLineRange`/`getLineSpans`): each replacement is widened to the
 * lines it actually touches, the touched lines are rewritten from the folded
 * matcher base, and every other line is copied back verbatim from the file. The
 * ranges drive the preservation, so a line whose folded form collides with
 * another cannot be aligned to the wrong occurrence.
 *
 * Without this, a fuzzy-matched edit shows the judge typographic quotes, dashes
 * and spaces folded to ASCII on lines the edit never touched: a file line
 * `const msg = “‑ keep ‑”;` reads back as `const msg = "- keep -";`.
 *
 * `null` = the fold changed the line count (pi throws on this; the view falls
 * back to raw newText rather than showing a file that does not exist).
 */
function markPreservingUnchangedLines(
  matched: NonNullable<ReturnType<typeof matchEditRanges>>,
): string | null {
  const rawLines = matched.base.split("\n");
  const baseLines = matched.matchBase.split("\n");
  if (rawLines.length !== baseLines.length) return null;
  // Line spans in matcher-base coordinates; every line but the last carries its
  // own "\n", which is what decides a replacement ending exactly at a line end.
  const spans: Array<{ start: number; end: number }> = [];
  let off = 0;
  for (let i = 0; i < baseLines.length; i++) {
    spans.push({ start: off, end: off + baseLines[i].length + (i === baseLines.length - 1 ? 0 : 1) });
    off = spans[i].end;
  }
  const groups: Array<{ startLine: number; endLine: number; ranges: MatchedEditRange[] }> = [];
  for (const r of matched.ranges) {
    // ranges are already sorted by start, so groups come out sorted too.
    const startLine = spans.findIndex((s) => r.start >= s.start && r.start < s.end);
    if (startLine === -1) return null;
    let endLine = startLine;
    while (endLine < spans.length && spans[endLine].end < r.end) endLine++;
    if (endLine >= spans.length) return null;
    const current = groups[groups.length - 1];
    if (current && startLine < current.endLine) {
      current.endLine = Math.max(current.endLine, endLine + 1);
      current.ranges.push(r);
    } else {
      groups.push({ startLine, endLine: endLine + 1, ranges: [r] });
    }
  }
  const out: string[] = [];
  let copied = 0;
  for (const g of groups) {
    out.push(...rawLines.slice(copied, g.startLine));
    const groupStart = spans[g.startLine].start;
    const groupEnd = spans[g.endLine - 1].end;
    out.push(...markRanges(matched.matchBase.slice(groupStart, groupEnd), g.ranges, groupStart).split("\n"));
    copied = g.endLine;
  }
  out.push(...rawLines.slice(copied));
  return out.join("\n");
}

/**
 * The judge's view of an edit: the file AFTER all blocks are applied, each
 * replaced region shown with ±EDIT_VIEW_CONTEXT context lines. Line numbers
 * are 1-based final-file lines; '>' marks the lines the edit sets, '·'
 * context, '…' omitted runs.
 *
 * Shares `matchEditRanges` with `editWillApply` and splices markers in reverse
 * offset order against the matcher base — matching pi's own non-sequential
 * application (including CRLF and BOM) while reflecting final line shifts. On a
 * fuzzy match the untouched lines come back from the file itself
 * (`markPreservingUnchangedLines`), so the view never folds characters of a line
 * the edit did not touch.
 *
 * The after-view is the edit's EFFECT (delta + where it lands). Unlike a
 * write — where the whole new file IS the effect and rides untrimmed (D11) —
 * the surrounding file is context, so it stays bounded.
 */
export function buildEditAfterView(
  file: string,
  edits: Array<{ oldText: string; newText: string }>,
): string | null {
  const matched = matchEditRanges(file, edits);
  if (!matched) return null;
  const marked = matched.needsFuzzy
    ? markPreservingUnchangedLines(matched)
    : markRanges(matched.matchBase, matched.ranges);
  if (marked === null) return null;
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

/** True when a filesystem error indicates the target does not exist (ENOENT). */
function isEnoent(err: unknown): boolean {
  const e = err as { code?: unknown; message?: unknown } | null;
  return e?.code === "ENOENT" || (typeof e?.message === "string" && /\bENOENT\b/.test(e.message));
}

export async function handleFile(
  event: ToolCallEvent,
  ctx: ExtensionContext,
) {
  const toolName = event.toolName as string;
  if (!FILE_TOOLS.includes(toolName as "read" | "write" | "edit")) return;

  const input = (event.input ?? {}) as { path?: unknown; content?: unknown; edits?: unknown };
  const filePath = input.path;
  // Fail closed on unexpected input shape (matching handlers/bash.ts): a custom
  // or malformed call without a valid `path` string must not slip past the gate.
  if (typeof filePath !== "string" || filePath.trim().length === 0) {
    return {
      block: true,
      reason: `[Permission Policy] Built-in ${toolName} tool called with unexpected input shape — blocked (missing \`path\` string).`,
    };
  }

  // Resolve once — reused by pre-validation and decision engine
  const resolvedPath = resolvePathReal(expandTilde(filePath), ctx.cwd);

  // Structurally validate edit calls first (no fs access) — fail closed on
  // missing/malformed edits rather than passing through ungated.
  let edits: Array<{ oldText: string; newText: string }> | null = null;
  if (toolName === "edit") {
    const rawEdits = input.edits;
    if (
      !Array.isArray(rawEdits) ||
      rawEdits.length === 0 ||
      !rawEdits.every(
        (e): e is { oldText: string; newText: string } =>
          e !== null &&
          typeof e === "object" &&
          typeof (e as { oldText?: unknown }).oldText === "string" &&
          typeof (e as { newText?: unknown }).newText === "string",
      )
    ) {
      return {
        block: true,
        reason: "[Permission Policy] Built-in edit tool called with unexpected input shape — blocked (missing or malformed `edits` array).",
      };
    }
    edits = rawEdits;
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
    // Credential paths are NEVER pre-validated: prompt-vs-silent-failure
    // would leak whether a guessed oldText occurs exactly once in the file — a
    // content oracle on a secret. Those always prompt without a content read,
    // even when the edit will fail.
    const isCredentialPath = isPathWarnedResolved(filePath, resolvedPath).warned;

    if (!isCredentialPath) {
      let fileContent: string | null = null;
      try {
        // Size cap: skip pre-validation on large files rather than blocking the
        // event loop on a full synchronous read. The edit will simply prompt.
        if (fs.statSync(resolvedPath).size <= EDIT_PREVALIDATE_MAX_BYTES) {
          fileContent = fs.readFileSync(resolvedPath, "utf-8");
        }
      } catch (err) {
        // Only ENOENT proves pi's edit will fail; any other error (EACCES,
        // special file, etc.) fails closed into gate().
        if (isEnoent(err)) return;
        fileContent = null;
      }

      if (fileContent !== null) {
        // Only a call pi WILL REJECT may pass through ungated (the
        // editWillApply mirror decides); everything else reaches the gate.
        if (!editWillApply(fileContent, edits)) return;
        // Every block matches exactly once: swap the judge's input from the
        // bare newText blocks to the AFTER-EDIT file view (replaced regions
        // with context, line numbers). Isolated so a view-builder failure falls
        // back to raw edits content and never skips gate().
        if (decision.kind === "prompt" && decision.promptData.type === "file") {
          try {
            const view = buildEditAfterView(fileContent, edits);
            if (view) {
              decision.promptData.content = view;
              decision.promptData.contentHeading = "File after this edit";
            }
          } catch {
            /* fall back to raw edits content; never skip gate() */
          }
        }
      }
    }
  }

  return await gate(request, ctx, store, (decision, result) =>
    rejectFile(decision, result, store, ctx),
    decision,
  );
}
