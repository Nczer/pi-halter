/**
 * Tmux-aware bash command renderer.
 *
 * Formats tmux commands into structured, readable output:
 *   tmux -f /dev/null -S $SOCKET send-keys -t foo ls Enter
 *   → tmux send-keys  target=foo → ls Enter
 *
 * Renders the shared tmux command model (analysis/tmux.ts) — the same parse
 * the security pipeline judges, with display names overlaid here (display
 * vocabulary stays in the UI). Global boilerplate (-f /dev/null, -S socket,
 * -L alias) is consumed by the parse and never displayed.
 */

import { parseTmuxCommand, type TmuxCommand } from "../analysis/tmux";
import { splitOnPipe, splitIntoSegments } from "../analysis/tokenizer";

// ── Flag display names ──

/**
 * Display names for tmux flags (rendering only — the parse is
 * analysis/tmux.ts). Some flags are subcommand-specific (e.g., -S is the
 * socket globally but the start line for capture-pane); the most common
 * meaning is used. Unmapped flags render raw.
 */
const FLAG_NAMES: Record<string, string> = {
  "-t": "target", "-d": "detached", "-p": "print", "-l": "literal",
  "-J": "join", "-s": "session", "-n": "window", "-F": "format",
  "-S": "start", "-H": "copy-mode", "-R": "replace", "-M": "magic",
};

// ── Dispatch ──

/**
 * Check if a command starts with "tmux".
 */
export function isTmuxCommand(cmd: string): boolean {
  const trimmed = cmd.trim();
  return trimmed === "tmux" || trimmed.startsWith("tmux ");
}

// ── Formatting ──

/**
 * Truncate a formatted segment for compact display in numbered lists.
 * Multi-line: show first line + line count. Single line: hard truncate at 80 chars.
 */
export function truncateSegmentDisplay(display: string): string {
  const lines = display.split("\n");
  if (lines.length > 1) {
    const first = lines[0].trimEnd();
    return lines.length > 5
      ? `${first} ... (>${lines.length} lines)`
      : `${first} ... (${lines.length} lines)`;
  }
  return display.length > 80 ? display.slice(0, 77) + "..." : display;
}

/**
 * Format a parsed tmux command into structured text.
 * e.g. "tmux send-keys  target=foo → ls Enter"
 *
 * Flags render as display names (value or bare); positionals render raw in
 * original order. For send-keys, the positional key stream renders after an
 * arrow — exactly the tokens the pipeline judged.
 */
function formatParsedTmux(parsed: TmuxCommand): string {
  if (!parsed.subcommand) return "tmux";

  let result = `tmux ${parsed.subcommand}`;

  const parts: string[] = [];
  const keys: string[] = [];
  for (const arg of parsed.args) {
    if (arg.name) {
      const name = FLAG_NAMES[arg.name] ?? arg.name;
      parts.push(arg.value !== null ? `${name}=${arg.value}` : name);
    } else if (parsed.subcommand === "send-keys") {
      keys.push(arg.value as string);
    } else {
      parts.push(arg.value as string);
    }
  }

  // Double space before params to separate subcommand from them
  if (parts.length > 0 || keys.length > 0) {
    result += " ";
  }
  for (const part of parts) {
    result += ` ${part}`;
  }

  // send-keys key stream with arrow
  if (parsed.subcommand === "send-keys" && keys.length > 0) {
    result += ` → ${keys.join(" ")}`;
  }

  return result;
}

/**
 * Format a single tmux command segment.
 * Renders the shared parse (boilerplate stripped, flags mapped to names).
 */
export function formatTmuxSegment(segment: string): string {
  const trimmed = segment.trim();
  if (!isTmuxCommand(trimmed)) return trimmed;

  return formatParsedTmux(parseTmuxCommand(trimmed));
}

/**
 * Format a single segment (tmux or non-tmux).
 * Tmux commands get structured formatting, others pass through trimmed.
 * For pipe chains, format each side separately.
 */
export function formatSegment(segment: string): string {
  const trimmed = segment.trim();
  if (!trimmed) return trimmed;

  // Handle pipe chains: split on | (not ||), format each side
  const pipeParts = splitOnPipe(trimmed);
  if (pipeParts.length > 1) {
    return pipeParts.map(part => {
      const p = part.trim();
      if (isTmuxCommand(p)) {
        return formatTmuxSegment(p);
      }
      return p;
    }).join(" | ");
  }

  if (isTmuxCommand(trimmed)) {
    return formatTmuxSegment(trimmed);
  }

  return trimmed;
}

// ── Full bash command formatting ──

/**
 * Format a full bash command for display.
 * - Single command: "$ cmd"
 * - Chained: "bash (N segments)\n  1. cmd1\n  2. cmd2\n ..."
 * @param nonAllowedIndices - indices of segments that are not auto-allowed (marked with ⚠)
 * @param segments - optional pre-parsed segments (avoids re-splitting; caller owns consistency)
 */
export function formatBashCommand(command: string, nonAllowedIndices: Set<number> = new Set(), segments?: string[]): string {
  const trimmed = command.trim();
  if (!trimmed) return "";

  // Use pre-parsed segments if provided, otherwise split + check
  const segmentList = segments ?? splitIntoSegments(trimmed);

  // Only use breakdown format if at least one segment is a tmux command
  // (otherwise return raw command unchanged for non-tmux)
  // Skip the check when caller provided segments — they already verified.
  const hasTmux = segments ? true : segmentList.some(isTmuxCommand);
  if (!hasTmux) {
    return trimmed;
  }

  if (segmentList.length === 1) {
    return `$ ${formatSegment(segmentList[0])}`;
  }

  // Multiple segments with tmux — numbered list
  let result = `bash (${segmentList.length} segments)`;
  segmentList.forEach((seg, i) => {
    const formatted = truncateSegmentDisplay(formatSegment(seg));
    const marker = nonAllowedIndices.has(i) ? " \u26a0\ufe0f" : "";
    result += `\n  ${i + 1}.${marker} ${formatted}`;
  });

  return result;
}


