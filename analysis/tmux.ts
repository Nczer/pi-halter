/**
 * tmux.ts — the tmux command model: ONE parse, shared by the security
 * pipeline and the prompt display.
 *
 * The tmux CLI is parsed exactly once. Security consumers (TmuxEvaluator,
 * the send-keys payload analysis in command-analysis.ts) derive the
 * subcommand, the new-session shell command, and the send-keys key stream
 * from the parse; the prompt display (ui/tmux-render.ts) renders the same
 * parse with display names. What the pipeline judges is what the prompt
 * shows.
 *
 * Grammar: `tmux [global flags] <subcommand> [flags] [arguments...]`
 *
 * - Global flags: -S/-L/-f take a value; -c carries a shell command (it
 *   is the command authority for new-session); other shorts are boolean;
 *   --long takes a space-separated value unless in --flag=value form.
 *   Unknown globals never hide the subcommand or a send-keys payload
 *   (fail-closed).
 * - Subcommands are canonical (alias table below). Unlisted aliases
 *   (run, send, if, set, bind, source, splitw, newp, neww, respawn*,
 *   menu, popup, confirm, detach, lock*) stay raw and prompt via the
 *   whitelist.
 * - send-keys: known flags are -t/-c/-N (value) and -l/-H/-T/-M/-R/-X
 *   (boolean); `--` ends flag parsing. EVERYTHING else — unknown flags
 *   included, with their values — is part of the key stream that gets
 *   typed into a pane. Fail-closed by construction.
 * - new-session: flag table per `man tmux`; the first non-flag token
 *   starts the shell command.
 * - Other subcommands: dash tokens are flags (common value set for
 *   display fidelity), non-dash tokens are positional arguments.
 */
import { tokenize } from "./tokenizer";

// ── Safety tables (canonical subcommand names) ──

/**
 * Tmux subcommands that are safe (read-only, session management, no code
 * execution). All other subcommands prompt — whitelist approach.
 * Canonical names only; aliases are resolved by the parser (TMUX_ALIASES).
 */
export const TMUX_SAFE_SUBCOMMANDS = new Set([
  // Read-only inspection
  "capture-pane", "list-sessions", "list-panes", "list-windows", "list-buffers",
  "has-session", "show-options", "show-messages", "display-message", "display-panes",
  "wait-for", "save-buffer", "delete-buffer",
  // Session/window/pane management (no code execution)
  // NOTE: new-session is safe only when flag-only — a shell-command
  // argument (or the global -c option) executes code (see
  // tmuxNewSessionCommand, checked in the TmuxEvaluator).
  "new-session", "attach", "attach-session", "start-server", "switch-client",
  "move-window", "rename-window", "rename-session",
  "select-window", "select-pane",
  "resize-pane", "resize-window",
  "break-pane", "swap-pane", "swap-window", "join-pane",
  // send-keys is intentionally NOT in the whitelist — it is not judged
  // here; the send-keys PAYLOAD is analyzed by the full pipeline (see
  // analyzeTmuxSendKeysPayload in command-analysis.ts), and bare send-keys
  // (no payload) auto-allows as a harmless no-op.
]);

/**
 * Tmux alias → canonical subcommand (tmux 3.7b alias table).
 *
 * Only aliases whose decision is preserved by canonicalization are listed:
 * safe aliases → safe canonicals, and "new"/"start" → new-session (both
 * carry the shell-command check). Aliases whose canonical form is SAFE but
 * that do not resolve to one today (show-m, show-o, move-w, rename-s,
 * rename-w, swap-p, swap-w) are intentionally NOT listed — normalizing
 * them would turn a prompt into an auto-allow. Dangerous aliases (run,
 * send, if, set, bind, source, splitw, newp, neww, respawn*, menu, popup,
 * confirm, detach, lock*) are NOT listed either — they stay raw and prompt
 * via the whitelist.
 */
const TMUX_ALIASES: Record<string, string> = {
  new: "new-session", start: "new-session",
  capturep: "capture-pane",
  ls: "list-sessions", lsw: "list-windows", lsp: "list-panes", lsb: "list-buffers",
  has: "has-session",
  show: "show-options", showmsgs: "show-messages",
  display: "display-message", displayp: "display-panes",
  wait: "wait-for", saveb: "save-buffer", deleteb: "delete-buffer",
  switchc: "switch-client", movew: "move-window",
  rename: "rename-session", renamew: "rename-window",
  selectw: "select-window", selectp: "select-pane",
  resizew: "resize-window", resizep: "resize-pane",
  breakp: "break-pane", swapp: "swap-pane", swapw: "swap-window", joinp: "join-pane",
  // Dangerous canonicals — listed for display normalization only (they
  // prompt either way).
  "kill-sg": "kill-session", "kill-wg": "kill-window",
  "respawn-p": "respawn-pane", "respawn-w": "respawn-window",
  "split-w": "split-window",
};

/** Human-readable descriptions for known dangerous tmux subcommands. */
export const TMUX_DANGEROUS_DESCRIPTIONS: Record<string, string> = {
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
  // global -c option (flag-only new-session stays safe — see
  // tmuxNewSessionCommand).
  "new-session": "shell-command argument executes code in the new session",
};

// ── Parsing ──

/** One parsed argument: a flag (name set, value if it took one) or a
 *  positional (name null, value the token). For send-keys, positionals are
 *  the key stream; for new-session, they start the shell command. */
export interface TmuxArg {
  name: string | null;
  value: string | null;
}

export interface TmuxCommand {
  /** True if the first token is tmux. */
  isTmux: boolean;
  /** Canonical subcommand (lowercased, alias-resolved). Raw lowercase name
   *  for unlisted aliases; null for a bare `tmux` (global flags only). */
  subcommand: string | null;
  /** Subcommand arguments in original order. */
  args: TmuxArg[];
  /** The global -c value (a shell command — the command authority for
   *  new-session). */
  globalCommand: string | null;
}

/** Global flags before the subcommand that consume the next token. */
const TMUX_GLOBAL_VALUE_FLAGS = new Set(["-S", "-L", "-f"]);

/** send-keys flags that take a value. */
const TMUX_SEND_KEYS_VALUE_FLAGS = new Set(["-t", "-c", "-N"]);
/** send-keys flags that do not take a value. */
const TMUX_SEND_KEYS_BOOL_FLAGS = new Set(["-l", "-H", "-T", "-M", "-R", "-X"]);

/**
 * Short flags of new-session/new that consume the NEXT token as their value.
 * (from `man tmux`: new-session [-AdDEPXg] [-c start-directory] [-e environment]
 * [-f flags] [-F format] [-n window-name] [-s session-name] [-t control[.pane]]
 * [-x width] [-y height] [shell-command [argument ...]])
 * Bare letters: in a flag cluster only the LAST letter may take a value.
 */
const TMUX_NEW_SESSION_VALUE_FLAGS = new Set(["c", "e", "f", "F", "g", "n", "s", "t", "x", "y"]);

/** Long forms of new-session/new flags that take a value in space form. */
const TMUX_NEW_SESSION_LONG_VALUE_FLAGS = new Set([
  "--start-directory", "--environment", "--flags", "--format", "--group",
  "--window-name", "--session-name", "--target-pane", "--width", "--height",
]);

/** Value flags for subcommands the parser does not model — display fidelity
 *  (flag/value pairing for the prompt), no security semantics. */
const TMUX_COMMON_VALUE_FLAGS = new Set(["-t", "-s", "-n", "-F", "-S", "-c", "-e", "-f", "-g", "-x", "-y"]);

/**
 * Parse a tmux command segment. The single parse shared by the security
 * pipeline and the prompt display.
 */
export function parseTmuxCommand(segment: string): TmuxCommand {
  const tokens = tokenize(segment);
  if (tokens.length === 0 || tokens[0] !== "tmux") {
    return { isTmux: false, subcommand: null, args: [], globalCommand: null };
  }
  let i = 1;
  let globalCommand: string | null = null;
  // Global flags before the subcommand.
  while (i < tokens.length) {
    const t = tokens[i];
    if (t === "-c" && i + 1 < tokens.length) {
      globalCommand = tokens[i + 1];
      i += 2;
      continue;
    }
    if (TMUX_GLOBAL_VALUE_FLAGS.has(t) && i + 1 < tokens.length) { i += 2; continue; }
    if (t.startsWith("--")) {
      // --flag=value is self-contained; a space form takes the next token
      // unless it looks like another flag.
      if (!t.includes("=") && i + 1 < tokens.length && !tokens[i + 1].startsWith("-")) i += 2;
      else i++;
      continue;
    }
    if (t.startsWith("-")) { i++; continue; } // other global options are boolean
    break; // subcommand
  }
  if (i >= tokens.length) {
    return { isTmux: true, subcommand: null, args: [], globalCommand };
  }
  const raw = tokens[i].toLowerCase();
  const subcommand = TMUX_ALIASES[raw] ?? raw;
  return { isTmux: true, subcommand, args: parseTmuxArgs(tokens, i + 1, subcommand), globalCommand };
}

function parseTmuxArgs(tokens: string[], start: number, subcommand: string): TmuxArg[] {
  const args: TmuxArg[] = [];
  const isSendKeys = subcommand === "send-keys";
  const isNewSession = subcommand === "new-session";
  for (let i = start; i < tokens.length; i++) {
    const t = tokens[i];

    if (isSendKeys) {
      if (t === "--") continue; // separator: everything after is keys
      if (TMUX_SEND_KEYS_VALUE_FLAGS.has(t) && i + 1 < tokens.length) {
        args.push({ name: t, value: tokens[++i] });
        continue;
      }
      if (TMUX_SEND_KEYS_BOOL_FLAGS.has(t)) {
        args.push({ name: t, value: null });
        continue;
      }
      // Key token — unknown flags (and their values) are fail-closed keys:
      // they belong to whatever gets typed into the pane.
      args.push({ name: null, value: t });
      continue;
    }

    if (isNewSession) {
      if (t.startsWith("--")) {
        // Space form `--flag value` consumes the next token; `--flag=value`
        // doesn't.
        if (!t.includes("=") && TMUX_NEW_SESSION_LONG_VALUE_FLAGS.has(t) && i + 1 < tokens.length) {
          args.push({ name: t, value: tokens[++i] });
        } else {
          args.push({ name: t, value: null });
        }
        continue;
      }
      if (t.startsWith("-")) {
        // Short flag cluster: only the LAST letter may take a value.
        if (TMUX_NEW_SESSION_VALUE_FLAGS.has(t[t.length - 1]) && i + 1 < tokens.length) {
          args.push({ name: t, value: tokens[++i] });
        } else {
          args.push({ name: t, value: null });
        }
        continue;
      }
      // First non-flag token: the shell command starts (including this one).
      while (i < tokens.length) args.push({ name: null, value: tokens[i++] });
      break;
    }

    // Other subcommands: dash tokens are flags (common value set for
    // display fidelity), non-dash tokens are positional arguments.
    if (t.startsWith("-")) {
      if (TMUX_COMMON_VALUE_FLAGS.has(t) && i + 1 < tokens.length) {
        args.push({ name: t, value: tokens[++i] });
      } else {
        args.push({ name: t, value: null });
      }
    } else {
      args.push({ name: null, value: t });
    }
  }
  return args;
}

/**
 * The send-keys key stream — the tokens that get typed into a pane's shell
 * (fail-closed: unknown flags and their values included). Null unless
 * send-keys, or when there is no payload (bare send-keys is a no-op tmux
 * itself rejects).
 */
export function tmuxSendKeysKeys(cmd: TmuxCommand): string | null {
  if (cmd.subcommand !== "send-keys") return null;
  const keys = cmd.args.filter(a => a.name === null).map(a => a.value as string);
  return keys.length > 0 ? keys.join(" ") : null;
}

/**
 * The shell command a `new-session` invocation runs: the positional
 * [shell-command] argument, or the global -c option. Null when flag-only
 * (or not new-session).
 */
export function tmuxNewSessionCommand(cmd: TmuxCommand): string | null {
  if (cmd.subcommand !== "new-session") return null;
  if (cmd.globalCommand) return cmd.globalCommand;
  const command = cmd.args.filter(a => a.name === null).map(a => a.value as string);
  return command.length > 0 ? command.join(" ") : null;
}
