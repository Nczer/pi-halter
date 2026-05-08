# Changelog

## 3.8 — Remove `isMemoryFile` auto-allow

### Breaking changes

- **Removed `isMemoryFile()` auto-allow**. Project memory (MEMORY.md) is now managed by the memory extension's `memory` tool with target `"project"`, not via direct file operations. Global memory files are in `~/.pi` which is already in `allowedReadPaths`. No permission prompts needed.

### Code changes

- **`path-analysis.ts`** — Removed `isMemoryFile()` function entirely.
- **`decision-engine.ts`** — Removed `isMemoryFile` import and auto-allow check.

***
## 3.7 — Operation-scoped file permissions

### Bug fixes

- **Read "Always" no longer grants write/edit**. Approving "Always" for a file read stored the path in a generic `paths` set that auto-allowed **all operations** (read, write, edit). Split `paths` into `readPaths` and `writePaths` — approving read "Always" now only auto-allows future reads; write/edit will still prompt, and vice versa. Applies to both inside-cwd files (`allowRules`) and outside-cwd "this file only" approvals (`allowFileRules`).
- **Prompt text reflects actual scope**. Tier-2 confirmation dialogs for inside-cwd files now say "read will still prompt" (for write) or "write/edit will still prompt" (for read). Outside-cwd "this file only" confirmation also updated.

### Code changes

- **`store.ts`** — Replaced `paths` with `readPaths` / `writePaths` in `Store` interface, `AllowRules` type, and `createStore()` implementation. Renamed `hasAllowedPath()` → `hasAllowedReadPath()` / `hasAllowedWritePath()`, `listAllowedPaths()` → `listAllowedReadPaths()` / `listAllowedWritePaths()`.
- **`decision-engine.ts`** — Auto-allow checks use operation-specific path methods. `allowRules` and `allowFileRules` split by `isWriteOp`.
- **`widget.ts`** — Shows "Read paths:" and "Write paths:" separately instead of generic "Paths:".

***
## 3.6 — MEMORY.md auto-allow + Redirect handling overhaul + Bug fixes

### New features

- **`MEMORY.md` auto-allow**. Read, write, and edit operations on `MEMORY.md` inside the current working directory are auto-allowed without prompting. Files named `MEMORY.md` outside cwd still prompt. Implemented via `isMemoryFile()` in `path-analysis.ts` with a check in `decideFile()` before store lookup.

### Bug fixes

- **Bash write redirects to files now prompt correctly**. Commands like `echo data > file.txt` were auto-allowed via the signature approval path because `hasWriteRedirect()` was only checked in `isSimpleAllowedCommand()`, not in the signature-based auto-allow path. Redirect-only segments (e.g., `2>/dev/null`, `>&1`) extracted by tree-sitter are now recognized as safe modifiers in `isSimpleAllowedCommand()` and `isSegmentUnsafe()`, and excluded from non-allowlisted segment indices in `decideBash()`. This ensures:
  - `cmd > file.txt` → prompts (write to file)
  - `cmd 2>/dev/null` → no prompt (safe discard)
  - `cmd >&1` → no prompt (fd duplication)
  - `cmd 2>&1 >/dev/null` → no prompt (all safe)
- **`2>&1` no longer flagged as write redirect**. FD duplication (`2>&1`, `>&1`, `>&2`, `3>&1`, etc.) was incorrectly treated as a file write redirect, causing false positives in both `hasWriteRedirect()` and the risk analyzer. Added `/[0-9]*>&[0-9]+/g` strip before the redirect check in both locations.
- **`dd` false positive on `"info"`, `"remove"`, etc.**. The check `rest.includes("of")` matched any argument containing the substring `of`, not just `of=` assignments. Removed — `anyArgStartsWith(rest, "of=")` covers all valid `dd` output syntax.
- **`hasFlag` prefix collision**. `hasFlag(rest, "-i")` matched `"-info"` via raw `startsWith()`. Now checks exact match, `flag=` (e.g., `-i=bak`), or `flag.` (e.g., `-i.bak`) suffixes only.

### Code cleanup

- **Removed dead `/dev/null` strip**. The second `replace(/2>&1\s*>+\s*(?:\/dev\/(?:null|stderr))\b/g, "")` in both `hasWriteRedirect()` and `analyzeRisk()` was unreachable — the first strip already handles all `/dev/null` and `/dev/stderr` redirect forms. Removed from both functions.

***
## 3.5 — MCP tool call guard

### New features

- **MCP tool call interception**. Intercepts both proxy tool calls (`mcp({tool: "..."})`) and direct tools (e.g., `exa_web_search_exa`) before execution. Auto-allows metadata operations (`status`, `list`, `search`, `describe`, `connect`) and prompts for tool invocations. Parses qualified `server:tool` names and detects direct tools by matching against MCP server names from `mcp.json`.
- **Argument preview in MCP prompts**. Permission prompts show tool arguments (truncated) so the user can see what the MCP tool will do — e.g., search queries, file paths, or other parameters.
- **Session-scoped MCP server approval**. "Always" option grants permission for all tools from a specific MCP server for the session (e.g., `exa:*`). Pattern suggestion derives server-level wildcard from tool name.
- **MCP awareness in widget**. Status widget displays allowed MCP servers alongside bash, paths, and subagent allowances.

### Architecture changes

- **`handlers/mcp.ts`** — New handler with two entry points: `handleMcp()` for proxy tool calls and `handleMcpDirectTool()` for direct tools. Loads MCP config from `mcp.json` to detect direct tool servers. Shared `checkMcpPermission()` function handles the permission flow. `buildArgsPreview()` formats tool arguments for display.
- **`decision-engine.ts`** — Added `McpRequest`, `McpPromptData`, `decideMcp()`. Auto-allows known metadata operations. Derives server name from qualified tool names.
- **`store.ts`** — Added `hasAllowedMcpServer()`, `hasAllowedMcpTool()`, `listAllowedMcpServers()`, `listAllowedMcpTools()`, and `mcpServers`/`mcpTools` to `AllowRules`.
- **`prompt-builder.ts`** — Added `buildMcpPrompt()` with server/tool display, operation type, and tier-2 confirmation.
- **`widget.ts`** — Shows MCP allowances in status widget.

### Behavior changes

- MCP metadata operations (`status`, `list`, `search`, `describe`, `connect`) auto-allow without prompting.
- MCP tool calls (`mcp({ tool: "exa:search" })`) prompt for user confirmation.
- "Always" on MCP prompt allows all tools from that server for the session.
- Subagents forward MCP permission requests to the main session via file-based IPC.

***
## 3.4 — tree-sitter for all bash parsing (shell-quote removed)

### Security hardening

- **Full tree-sitter segmentation**. Replaced `shell-quote` for command segmentation with tree-sitter AST. Segments are now extracted from `pipeline`, `binary_expression`, `command_list`, and `backgrounding` nodes. Eliminates false splits like `2>&1` being split into `2>` and `1`.
- **Operator detection from AST**. Pipe (`|`, `|&`), redirect (`>`, `>>`, `2>`, `2>>`, `<`), and chain operators (`&&`, `||`, `;`, `&`) are all detected from the AST structure, not from tokenized output.
- **Single parsing engine**. All bash analysis (segments, paths, operators, subshells) now uses tree-sitter. Eliminates dual interpretation of commands.

### Architecture changes

- **`bash-parser.ts`** — Added `extractSegments()` and `BashSegment` interface. Public API: `extractSegments()`, `extractPathsFromBash()`, `hasSubshell()`.
- **`command-analysis.ts`** — `analyzeSegmentRisk()` now takes `(text: string, ops: string[])` instead of shell-quote tokens. `analyzeRisk()` is now async and uses tree-sitter segments.
- **`package.json`** — Removed `shell-quote` dependency. Only `tree-sitter-bash` + `web-tree-sitter` remain.

### Dependencies

- Removed `shell-quote` (pure JS, but inaccurate for complex shell constructs)
- tree-sitter WASM is lazy-loaded once, cached for the session

***
## 3.3 — Subagent permission forwarding

### New features

- **Subagent permission forwarding**. When a subagent runs without direct UI access and hits an `ask` permission, the request is forwarded to the main interactive session via file-based IPC. The main session polls for pending requests on each tool call, shows the confirmation prompt, and writes the response back. The subagent resumes once the decision is available.
- **File-based IPC**. Requests and responses are exchanged as JSON files under `~/.pi/agent/extensions/permissions/sessions/<sessionId>/`. Atomic writes prevent corruption. 10-minute timeout with cleanup on completion.

### Architecture changes

- **`forwarding/io.ts`** — File-based IPC types and utilities: `ForwardedRequest`/`ForwardedResponse` types, atomic file I/O, session directory resolution.
- **`forwarding/polling.ts`** — Two-sided polling: `processForwardedRequests()` (main session) checks for pending requests and shows prompts; `forwardAndWait()` (subagent) writes request and polls for response.
- **`index.ts`** — Calls `processForwardedRequests()` on each `tool_call` event in the main session.
- **All handlers** — When `!ctx.hasUI` and running in a subagent with a parent session, forward the permission request instead of auto-blocking.

### Behavior changes

- Subagents no longer auto-block on permission prompts — they forward to the main session for confirmation.
- Forwarded prompts show the requester agent name and session ID for context.
- Non-subagent headless sessions still auto-block as before (no parent session to forward to).

***
## 3.2 — tree-sitter-bash AST for path extraction

### Security hardening

- **Full bash AST parsing**. Replaced heuristic whitespace-split path extraction with `tree-sitter-bash` + `web-tree-sitter`. Paths are now extracted from command argument and redirect-destination nodes in the AST, correctly skipping heredoc bodies, comments, variable assignments, and quoted string contents. Eliminates false positives from heredocs and nested quotes.
- **AST-based subshell detection**. `hasSubshell()` now uses the AST for accurate detection of `command_substitution` and `process_substitution` nodes, with a fast regex pre-check for common patterns.
- **Safe system path exclusion**. `/dev/null`, `/dev/stdin`, `/dev/stdout`, `/dev/stderr` are never flagged as external paths.

### Architecture changes

- **`bash-parser.ts`** — New module wrapping tree-sitter for lazy-loaded AST parsing. Public API: `extractPathsFromBash(command, cwd)` and `hasSubshell(command)`.
- **`command-analysis.ts`** — `analyzeCommand()` is now async. Uses tree-sitter for path extraction, keeps `shell-quote` for segmentation and signature extraction.
- **`decision-engine.ts`** — `decide()` and `decideBash()` are now async.

### Dependencies

- Added `tree-sitter-bash` and `web-tree-sitter` (lazy-loaded WASM, ~2MB, loaded on first bash command).

***
## 3.1 — Path containment hardening + Symlink defense + Bash allowlist audit

### Security hardening

- **Symlink TOCTOU defense**. `resolvePathReal()` now walks up the directory tree for non-existent paths, resolving any parent directory symlinks before re-appending the non-existent suffix. Prevents symlink swap attacks where a path is checked before the target symlink is created.
- **Single path containment helper**. Replaced three divergent implementations (`startsWith(d + "/")` in `isInsideAutoAllowedDir`, `path.relative` in `isInsideCwd`, mixed in `isProjectPiPath`) with a unified `isChildOf(child, parent)` helper using `path.relative`. Eliminates audit complexity and prevents future logic drift.
- **`homePiDir` normalization fix**. `isProjectPiPath` now resolves `~/.pi` through `resolvePathReal()` instead of using `path.join()`, preventing mismatches when `~/.pi` is a symlink.

### UI improvements

- **Symlink hint in file prompts**. When a path resolves through a symlink, file prompts now show `🔗 Resolved via symlink: original → resolved` so the user can see the actual target location.
- **Optimized auto-allowed dir check**. `isInsideAutoAllowedDir` now does an O(1) `Set.has()` exact match before iterating, avoiding unnecessary `path.relative` calls for commonly allowed paths.

### Bash allowlist changes

- **Added ~36 safe commands** to `allowedBashPatterns` across 6 categories: text processing (`tac`, `rev`, `nl`, `fold`, `expand`, `fmt`, `join`, `comm`, `paste`, `column`, `seq`), hashing/binary inspection (`md5sum`, `sha*sum`, `cksum`, `hexdump`, `od`, `strings`), system info (`pwd`, `date`, `whoami`, `id`, `uname`, `hostname`, `groups`, `printenv`, `uptime`, `tty`, `tput`), disk/process inspection (`df`, `du`, `free`, `ps`, `pgrep`, `pidof`), command lookup (`which`, `command`, `type`, `hash`, `whence`), safe creation (`mkdir`, `touch`, `mktemp`), calculator (`bc`, `expr`, `factor`, `yes`).
- **Removed `split`, `shuf`, `xxd`** from allowlist — all can write files via built-in flags (`split` creates chunks, `shuf -o` writes output, `xxd -r` writes raw binary) without using shell redirects, bypassing the redirect safety check. Kept in `pathAwareCommands` so their file arguments are still tracked in permission prompts.
- **Updated `pathAwareCommands`** to include newly allowlisted file-taking commands (`tac`, `rev`, `nl`, `fold`, `join`, `comm`, `paste`, `split`, `shuf`, `md5sum`, `sha*sum`, `cksum`, `xxd`, `hexdump`, `od`, `strings`, `mkdir`, `mktemp`) so their path arguments trigger outside-cwd permission checks.

### Reduction in prompt fatigue

- Routine inspection commands (`df`, `du`, `ps`, `pwd`, `date`, `which`, etc.) now auto-allow when simple, reducing unnecessary prompts for standard development workflows.

***
## 3.0 — Custom selector + No (with reason) + Always (this file only)

### New features

- **No (with reason)**. All prompts now include "No (with reason)" option. Opens a text editor for user to specify rejection reason, included in the block message returned to the LLM. Escaping the reason editor returns to the selector.
- **Custom selector UI**. Replaced `ctx.ui.select` with a custom component (following ask_user_question pattern). Cyclic navigation (↑ from first wraps to last, ↓ from last wraps to first). Consistent styling with borders and help text.
- **Always (this file only)**. File prompts outside cwd now include "Always (this file only)" option. Auto-allows just this specific file for the session, not the entire directory. Other files in the same directory will still prompt.

### Bug fixes

- File tier-2 confirmation now shows actual directory path (`Confirm Always Allow: Edit /tmp`) instead of generic `Edit this dir`.

### Code cleanup

- Unified prompt body formatting across bash, file, and subagent (all have trailing newline for separator).
- Unified tier-2 confirmation body formatting (all use `\n\n"Back" returns...` pattern).
- Removed unused imports from selector.ts.

### Prompt layout

- **Title above separator**. All prompts now show title first, then `---`, then body. Easier to scan at a glance.
- **Deduplicated danger flags**. `rm` no longer shows both "rm (file deletion)" and "rm (any file deletion)" — token-based analysis defers to regex pattern for rm/rmdir/unink.

***
## 2.4 — Prompt UI overhaul

### Behavior changes

- **Prompt highlights non-permitted segments**. All segments are shown, but only those that triggered the prompt get a ⚠️ marker for quick visual scanning.
  - `find sth && ls sth2 && rm -r sth3` → all 3 shown, only `rm -r sth3` marked ⚠️
- **Store filters allowlisted signatures**. Commands in `allowedBashPatterns` are not stored, keeping the widget lean.

### Prompt UI improvements

- **Title reflects prompt type**. Shows "Path", "Bash" or "Bash + Path" instead of always "Bash".
- **Body shows essential info only**. Command, outside paths, danger flags, chain segments. Removed redundant cwd and help text.
- **Segment markers aligned**. ⚠️ placed after the number (`3. ⚠️ rm -rf`) instead of before (`⚠️ 3. rm -rf`) for consistent alignment.
- **Tier-2 confirmations show actual paths**. "Confirm Always: rm -rf + /tmp" instead of "rm -rf + 1 dir(s)".
- **Tier-2 confirmations include danger flags**. Warning section shown for dangerous commands.
- **Path-only prompts show correct confirmation**. "Confirm Always Allow: /tmp" instead of empty "Confirm Always Allow: ".
- **Directories stored correctly**. `ls /tmp` stores `/tmp`, not `/` (was using `path.dirname()` incorrectly).

### File prompt improvements

- **Simplified file prompts**. Match bash prompt style: just path and outside-cwd warning.
- **Consistent title format**. "⚠️ Edit outside cwd" instead of "⚠️ Edit outside cwd: /full/path".

### Subagent prompt improvements

- **Simplified subagent prompts**. Match bash/file prompt style for consistency.

### Bug fixes

- Fixed body not rendering (ctx.ui.select doesn't support body argument — body now prepended to title).
- Fixed path-only tier-2 confirmation showing empty command list.
- Fixed outside directory computation returning parent instead of the directory itself.

***
## 2.3 — Architecture deepening

### New modules

- **`prompt-flow.ts`** — Centralized prompt interaction loop. `showPrompt(decision, ctx, store)` owns building the prompt, displaying it, mutating the store on "always", and updating the widget. Handlers no longer orchestrate UI logic.
- **`widget.ts`** — Extracted TUI rendering from `permission-state.ts`. All widget drawing lives here.
- **`config/`** — Split monolithic `config.ts` into focused sub-modules: `thresholds.ts`, `bash-patterns.ts`, `path-rules.ts`, `dangerous-patterns.ts`, barrel `index.ts`.

### Refactored modules

- **`command-analysis.ts`** — Unified "fat analyzer". Merged `path-analysis.ts` path extraction into `analyzeCommand()`. Single tokenization pass, single result. `path-analysis.ts` shrunk to pure path utilities.
- **`decision-engine.ts`** — Pure policy function `decide(request, store) → Decision`. No UI dependency. Store injected for testability. Filters allowlisted signatures before storing (avoids cluttering store with `ls`, `find`, etc. that auto-allow via static rules anyway).
- **`prompt-builder.ts`** — Pure formatter `buildPrompt(PromptDecision) → BuiltPrompt`. All prompt wording centralized here.
- **`prompts.ts`** — `twoTierAlwaysPrompt` now consumes `BuiltPrompt` directly instead of raw strings + callbacks.
- **`store.ts`** — `Store` interface + `createStore()` factory. One implementation for runtime and tests. No duplication.
- **`permission-state.ts`** — Thin re-export hub + `resetState()` for session lifecycle.

### Handler simplification

- **`handlers/bash.ts`** — ~100 lines → 51 lines. Single `showPrompt()` call replaces `buildPrompt` + `twoTierAlwaysPrompt` + inline store mutations.
- **`handlers/file.ts`** — Same reduction. Pre-validation of edit calls preserved.
- **`handlers/subagent.ts`** — Same reduction.

### Behavior changes

- **Store no longer keeps allowlisted signatures**. `find sth && ls sth2 && rm -r sth3` now stores only `rm -r` (not `find`, `ls`). Widget shows only non-trivial allowances.
- **No functional changes** to permission decisions, prompt wording, or auto-allow semantics.

### Testability

- **Decision engine** — unit-testable with `createStore()` fake (no UI dependency)
- **Prompt builder** — pure function, testable in isolation
- **Command analysis** — pure function, testable in isolation
- **Path utilities** — pure functions, testable in isolation
- **Store** — factory pattern enables deterministic test state
