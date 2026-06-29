/**
 * Tmux-aware bash command renderer.
 *
 * Formats tmux commands into structured, readable output:
 *   tmux -f /dev/null -S $SOCKET send-keys -t foo ls Enter
 *   → tmux send-keys  target=foo → ls Enter
 */

import { splitOnPipe, splitIntoSegments, tokenize } from "../analysis/tokenizer";

// Re-export tokenizer utilities for backwards compatibility
export { splitOnPipe, splitIntoSegments };

// ── Flag definitions ──

/** Tmux boilerplate flags to strip (agent infrastructure, not semantic). */
const BOILERPLATE_FLAGS = new Set(["-f", "-S", "-L"]);

/**
 * Mapping of tmux flag short forms to named params.
 * Some flags are subcommand-specific (e.g., -s for new-session vs -s for send-keys).
 * When a flag has multiple meanings, we use the most common one.
 */
interface FlagMapping {
  /** Named param to display (e.g., "target", "session"). */
  name: string;
  /** Whether this flag takes a value (true) or is boolean (false). */
  hasValue: boolean;
  /** Raw flag string (e.g., "-t", "-d"). */
  short: string;
  /** Long form if applicable (e.g., "-target"). */
  long?: string;
}

const FLAG_MAP: Map<string, FlagMapping> = new Map([
  // Common flags
  ["-t", { name: "target", hasValue: true, short: "-t" }],
  ["-d", { name: "detached", hasValue: false, short: "-d" }],
  ["-p", { name: "print", hasValue: false, short: "-p" }],
  ["-l", { name: "literal", hasValue: false, short: "-l" }],
  ["-J", { name: "join", hasValue: false, short: "-J" }],
  // new-session flags
  ["-s", { name: "session", hasValue: true, short: "-s" }],
  ["-n", { name: "window", hasValue: true, short: "-n" }],
  ["-F", { name: "format", hasValue: true, short: "-F" }],
  // capture-pane flags
  ["-S", { name: "start", hasValue: true, short: "-S" }], // -S for capture-pane (start line)
  // send-keys flags
  ["-H", { name: "copy-mode", hasValue: false, short: "-H" }],
  ["-R", { name: "replace", hasValue: false, short: "-R" }],
  ["-M", { name: "magic", hasValue: false, short: "-M" }],
  ["-r", { name: "repeat", hasValue: false, short: "-r" }],
]);

/** Short alias → canonical subcommand name. */
const SUBCOMMAND_ALIASES: Record<string, string> = {
  "new": "new-session",
  "kill-sg": "kill-session",
  "kill-wg": "kill-window",
  "move-w": "move-window",
  "rename-s": "rename-session",
  "rename-w": "rename-window",
  "respawn-p": "respawn-pane",
  "respawn-w": "respawn-window",
  "show-m": "show-messages",
  "show-o": "show-options",
  "split-w": "split-window",
  "swap-p": "swap-pane",
  "swap-w": "swap-window",
};

/** Parsed tmux command structure. */
export interface ParsedTmuxFlags {
  /** The tmux subcommand (e.g., "send-keys", "new-session"). Null if not a tmux command. */
  subcommand: string | null;
  /** Parsed flags (boilerplate stripped). */
  flags: ParsedFlag[];
  /** Keys being sent (for send-keys subcommand). Null for other subcommands. */
  keys: string | null;
}

/** A parsed flag. */
export interface ParsedFlag {
  /** Named param (e.g., "target", "detached"). Null for raw flags. */
  name: string | null;
  /** Value for flags that take one. Null for boolean flags. */
  value: string | null;
  /** Raw representation (e.g., "-D 5"). Used for unmapped flags. */
  raw: string;
}

// ── Parsing ──

/**
 * Check if a command starts with "tmux".
 */
export function isTmuxCommand(cmd: string): boolean {
  const trimmed = cmd.trim();
  return trimmed === "tmux" || trimmed.startsWith("tmux ");
}

/**
 * Parse tmux command flags into structured data.
 * Strips boilerplate (-f /dev/null, -S socket, -L alias).
 * Maps known flags to named params.
 * Extracts send-keys keys.
 */
export function parseTmuxFlags(cmd: string): ParsedTmuxFlags {
  if (!isTmuxCommand(cmd)) {
    return { subcommand: null, flags: [], keys: null };
  }

  const tokens = tokenize(cmd);
  if (tokens.length < 2) {
    return { subcommand: null, flags: [], keys: null };
  }

  // Find subcommand (skip tmux global flags)
  let subIdx = 1;
  while (subIdx < tokens.length) {
    const token = tokens[subIdx];
    if (token === "-S" || token === "-L" || token === "-f") {
      subIdx += 2; // skip flag + value
      continue;
    }
    if (token.startsWith("-") && !token.startsWith("--")) {
      subIdx++; // skip unknown short flag
      continue;
    }
    if (token.startsWith("--")) {
      subIdx += 2; // skip unknown long flag + value
      continue;
    }
    break;
  }

  let subcommand = subIdx < tokens.length ? tokens[subIdx].toLowerCase() : null;
  // Resolve aliases
  subcommand = subcommand ? (SUBCOMMAND_ALIASES[subcommand] ?? subcommand) : null;

  // Parse flags after subcommand
  const flags: ParsedFlag[] = [];
  const isSendKeys = subcommand === "send-keys";
  let keysStartIdx = -1;

  for (let i = subIdx + 1; i < tokens.length; i++) {
    const token = tokens[i];

    // Handle -- separator (everything after is keys for send-keys)
    if (token === "--") {
      if (isSendKeys) {
        keysStartIdx = i + 1;
      }
      break;
    }

    // Skip boilerplate flags (-S is in BOILERPLATE_FLAGS for socket, but for capture-pane it means start line)
    if (BOILERPLATE_FLAGS.has(token) && !(token === "-S" && subcommand === "capture-pane")) {
      i++; // skip value
      continue;
    }

    // For send-keys, stop collecting flags when we hit a non-flag token
    if (isSendKeys && !token.startsWith("-")) {
      keysStartIdx = i;
      break;
    }

    // Try to map the flag
    const mapping = FLAG_MAP.get(token);
    if (mapping) {
      if (mapping.hasValue && i + 1 < tokens.length) {
        flags.push({ name: mapping.name, value: tokens[i + 1], raw: `${token} ${tokens[i + 1]}` });
        i++;
      } else if (!mapping.hasValue) {
        flags.push({ name: mapping.name, value: null, raw: token });
      }
      continue;
    }

    // Unmapped flag — keep as raw
    if (token.startsWith("-")) {
      if (i + 1 < tokens.length && !tokens[i + 1].startsWith("-")) {
        flags.push({ name: null, value: null, raw: `${token} ${tokens[i + 1]}` });
        i++;
      } else {
        flags.push({ name: null, value: null, raw: token });
      }
    } else if (!isSendKeys) {
      // Positional argument for non-send-keys commands (e.g., display-message 'hello')
      flags.push({ name: null, value: null, raw: token });
    }
  }

  // Extract keys for send-keys
  let keys: string | null = null;
  if (isSendKeys && keysStartIdx > 0 && keysStartIdx < tokens.length) {
    keys = tokens.slice(keysStartIdx).join(" ");
  }

  return { subcommand, flags, keys };
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
 */
function formatParsedTmux(parsed: ParsedTmuxFlags): string {
  if (!parsed.subcommand) return "tmux";

  let result = `tmux ${parsed.subcommand}`;

  // Add flags (skip boilerplate, use named params)
  // Double space before flags to separate subcommand from params
  const hasFlags = parsed.flags.length > 0 || parsed.keys;
  if (hasFlags) {
    result += " ";
  }
  for (const flag of parsed.flags) {
    if (flag.name) {
      if (flag.value !== null) {
        result += ` ${flag.name}=${flag.value}`;
      } else {
        result += ` ${flag.name}`;
      }
    } else {
      // Raw flag (unmapped)
      result += ` ${flag.raw}`;
    }
  }

  // Add send-keys keys with arrow
  if (parsed.keys) {
    result += ` → ${parsed.keys}`;
  }

  return result;
}

/**
 * Format a single tmux command segment.
 * Strips boilerplate, maps flags to named params.
 */
export function formatTmuxSegment(segment: string): string {
  const trimmed = segment.trim();
  if (!isTmuxCommand(trimmed)) return trimmed;

  const parsed = parseTmuxFlags(trimmed);
  return formatParsedTmux(parsed);
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
  const hasTmux = segments ? true : segmentList.some(s => isTmuxCommand(s.trim()));
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


