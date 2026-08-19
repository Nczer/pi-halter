import { isAllowedCommand, dangerousCommandPatterns, dangerousContextPatterns } from "../config";
import { containsCommandSubstitution, hasWriteRedirect } from "./segment-helpers";
import { detectObfuscation } from "./obfuscation";
import { isGitDangerous } from "./segment-helpers";
import { tokenizeSegment } from "./tokenizer";

// ── Tmux safe subcommands ──

/**
 * Tmux subcommands that are safe (read-only, session management, no code execution).
 * All other subcommands prompt — whitelist approach.
 */
export const TMUX_SAFE_SUBCOMMANDS = new Set([
  // Read-only inspection
  "capture-pane", "list-sessions", "list-panes", "list-windows", "list-buffers",
  "has-session", "show-options", "show-messages", "display-message", "display-panes",
  "wait-for", "save-buffer", "delete-buffer",
  // Session/window/pane management (no code execution)
  // NOTE: new-session/new are safe only when flag-only — a shell-command
  // argument executes code (see tmuxNewSessionRunsCommand, checked in the
  // TmuxEvaluator).
  "new-session", "new", "attach", "attach-session", "start-server", "switch-client",
  "move-window", "rename-window", "rename-session",
  "select-window", "select-pane",
  "resize-pane", "resize-window",
  "break-pane", "swap-pane", "swap-window", "join-pane",
  // Aliases (tmux 3.7b alias table) of the safe full names above. Dangerous
  // aliases (run, send, if, set, bind, source, splitw, newp, neww, respawn*,
  // menu, popup, confirm, detach, lock*) are intentionally NOT listed — they
  // prompt via the whitelist.
  "capturep", "ls", "lsw", "lsp", "lsb", "has",
  "show", "showmsgs", "display", "displayp",
  "wait", "saveb", "deleteb", "start", "switchc",
  "movew", "rename", "renamew", "selectw", "selectp",
  "resizew", "resizep", "breakp", "swapp", "swapw", "joinp",
]);

/** Human-readable descriptions for known dangerous tmux subcommands. */
export const TMUX_DANGEROUS_DESCRIPTIONS: Record<string, string> = {
  "send-keys": "arbitrary keystroke injection — executes commands inside tmux pane",
  "run-shell": "executes commands on tmux server",
  "pipe-pane": "pipes pane output to a shell command",
  "respawn-pane": "respawns pane with arbitrary command",
  "kill-session": "destroys a tmux session",
  "kill-server": "shuts down the entire tmux server",
  "kill-window": "destroys a tmux window",
  "kill-pane": "destroys a tmux pane",
  "split-window": "spawns a new shell in a split pane",
  "new-window": "spawns a new shell in a window",
  "set-option": "modifies tmux configuration",
  "bind-key": "modifies tmux keybindings",
  // Only reached when the session carries a shell-command argument or the
  // global -c option (flag-only new-session/new stays safe — see
  // tmuxNewSessionRunsCommand).
  "new-session": "shell-command argument executes code in the new session",
  "new": "shell-command argument executes code in the new session",
};

// ── Tmux parsing ──

/**
 * Short flags of new-session/new that consume the NEXT token as their value.
 * (from `man tmux`: new-session [-AdDEPXg] [-c start-directory] [-e environment]
 * [-f flags] [-F format] [-n window-name] [-s session-name] [-t control[.pane]]
 * [-x width] [-y height] [shell-command [argument ...]])
 */
const TMUX_NEW_SESSION_VALUE_FLAGS = new Set(["c", "e", "f", "F", "g", "n", "s", "t", "x", "y"]);

/** Long forms of new-session/new flags that take a value in space form. */
const TMUX_NEW_SESSION_LONG_VALUE_FLAGS = new Set([
  "--start-directory", "--environment", "--flags", "--format", "--group",
  "--window-name", "--session-name", "--target-pane", "--width", "--height",
]);

/**
 * True if a `new-session`/`new` invocation carries a shell command tmux will
 * execute: the optional [shell-command] argument after the flags, or the
 * global `-c shell-command` option before the subcommand. Flag-only
 * invocations (`tmux new-session -d -s name`) return false.
 */
export function tmuxNewSessionRunsCommand(segment: string): boolean {
  const args = tokenizeSegment(segment);
  let i = 1;
  // Global options before the subcommand
  while (i < args.length) {
    const a = args[i];
    if ((a === "-S" || a === "-L" || a === "-f") && i + 1 < args.length) { i += 2; continue; }
    if (a === "-c") return true; // global -c shell-command (no value needed to be suspicious)
    if (a.startsWith("-")) { i++; continue; } // other global options are boolean
    break; // subcommand
  }
  if (i >= args.length) return false;
  const sub = args[i].toLowerCase();
  if (sub !== "new-session" && sub !== "new") return false;
  // Options after the subcommand; the first non-flag token is the shell command.
  i++;
  while (i < args.length) {
    const a = args[i];
    if (a.startsWith("--")) {
      i++;
      // Space form `--flag value` consumes the next token; `--flag=value` doesn't.
      if (!a.includes("=") && TMUX_NEW_SESSION_LONG_VALUE_FLAGS.has(a)) i++;
      continue;
    }
    if (a.startsWith("-")) {
      // Short flag cluster: only the LAST letter may take a value.
      const last = a[a.length - 1];
      i++;
      if (TMUX_NEW_SESSION_VALUE_FLAGS.has(last)) i++;
      continue;
    }
    return true; // non-flag token → shell command
  }
  return false;
}

/**
 * Extract the tmux subcommand from a segment, skipping -S/-L socket flags and other options.
 */
export function getTmuxSubcommand(segment: string): string | null {
  const args = segment.trim().split(/\s+/);
  if (args.length < 2) return null;
  let i = 1;
  while (i < args.length) {
    const arg = args[i];
    if ((arg === "-S" || arg === "-L" || arg === "-f") && i + 1 < args.length) { i += 2; continue; }
    if (arg.startsWith("-") && !arg.startsWith("--")) { i++; continue; }
    if (arg.startsWith("--")) { i += 2; continue; }
    return args[i].toLowerCase();
  }
  return null;
}

export function isTmuxDangerous(segment: string): boolean {
  const sub = getTmuxSubcommand(segment);
  if (!sub) return true; // no subcommand → prompt
  return !TMUX_SAFE_SUBCOMMANDS.has(sub);
}

/**
 * Extract the keys being sent from a `tmux send-keys` segment.
 * Skips flags like -t, -l, -H, -T and returns the remaining tokens.
 * e.g. "tmux send-keys -t foo 'hello' Enter" → "hello Enter"
 */
export function extractTmuxSendKeys(segment: string): string | null {
  const args = segment.trim().split(/\s+/);
  if (args.length < 3) return null;

  // Find the actual index of "send-keys" (may be after -S/-L flags)
  let subIdx = -1;
  for (let i = 1; i < args.length; i++) {
    if (args[i] === "-S" || args[i] === "-L" || args[i] === "-f") { i++; continue; } // skip socket flags
    if (args[i] === "send-keys") { subIdx = i; break; }
    break;
  }
  if (subIdx < 0) return null;

  // Collect keys starting after "send-keys", only skip known send-keys flags
  const keys: string[] = [];
  let i = subIdx + 1;
  while (i < args.length) {
    const arg = args[i];
    // send-keys flags that take a value
    if ((arg === "-t" || arg === "-c" || arg === "-N") && i + 1 < args.length) {
      i += 2;
      continue;
    }
    // send-keys flags that don't take a value
    if (arg === "-l" || arg === "-H" || arg === "-T" || arg === "-M" || arg === "-R" || arg === "-X") {
      i++;
      continue;
    }
    // Everything else is a key (including unknown flags like -fd which belong to the inner command)
    keys.push(arg);
    i++;
  }
  return keys.length > 0 ? keys.join(" ") : null;
}

// ── Pre-compiled regexes for send-keys safety ──

const SEND_KEYS_ENTER_RE1 = /\s+Enter$/;
const SEND_KEYS_ENTER_RE2 = /^Enter$/;
const SEND_KEYS_QUOTE_RE = /^("|')(.*\1)$/;
/** Shell operators that would chain commands inside send-keys. */
const SEND_KEYS_SHELL_OPS_RE = /[;|&]/;

// ── Tmux send-keys safety ──

/**
 * Check if send-keys keys are safe (would auto-allow as a standalone command).
 * Allows the send-keys to inherit the session's auto-allow rules.
 */
export function isTmuxSendKeysSafe(keys: string): boolean {
  // Strip trailing "Enter" since it's just a keystroke, not part of the command
  const cmd = keys.replace(SEND_KEYS_ENTER_RE1, "").replace(SEND_KEYS_ENTER_RE2, "").trim();
  if (!cmd) return true; // pressing Enter on empty line is safe

  // Handle shell-quoted arguments: strip outer quotes from the full key string
  const unquoted = cmd.replace(SEND_KEYS_QUOTE_RE, "$2").trim();

  // Split on whitespace to get the first command
  const firstToken = unquoted.split(/\s+/)[0];
  // Remove any remaining leading/trailing quotes
  const bare = firstToken.replace(/^["']+/, "").replace(/["']+$/, "");

  // Must be an allowed command
  if (!isAllowedCommand(bare)) return false;

  // Must not match dangerous command patterns
  if (dangerousCommandPatterns.some(({ pattern }) => pattern.test(bare))) return false;

  // Must not match dangerous context patterns
  if (dangerousContextPatterns.some(({ pattern }) => pattern.test(unquoted))) return false;

  // Must not have shell operators (would chain multiple commands)
  if (SEND_KEYS_SHELL_OPS_RE.test(unquoted)) return false;

  // Must not have write redirects, subshells, or obfuscation
  if (hasWriteRedirect(unquoted)) return false;
  if (containsCommandSubstitution(unquoted)) return false;
  if (detectObfuscation(unquoted).detected) return false;

  // Check if it's a dangerous git/tmux subcommand
  if (bare === "git" && isGitDangerous(unquoted)) return false;
  if (bare === "tmux") {
    // For nested tmux send-keys, recursively check the keys
    const innerSub = getTmuxSubcommand(unquoted);
    if (innerSub === "send-keys") {
      const innerKeys = extractTmuxSendKeys(unquoted);
      if (!innerKeys || !isTmuxSendKeysSafe(innerKeys)) return false;
    } else if (isTmuxDangerous(unquoted)) {
      return false;
    }
  }

  return true;
}
