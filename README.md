# Permissions (pi extension)

A permission gate for pi tool calls. Intercepts `bash`, `read`/`write`/`edit`, and `subagent` calls, auto-allowing safe operations and prompting the user for anything risky.

## Features

- **Bash commands** — auto-allows simple read-only commands (`ls`, `grep`, `find`, etc.); prompts for dangerous operations (`rm`, `sudo`, `curl | bash`, etc.)
- **File access** — auto-allows reads inside cwd and trusted paths; prompts for paths outside cwd, denied names (`.env`, `.ssh`, etc.)
- **Subagent spawning** — prompts before spawning subagents, with warnings for write-capable agents
- **MCP tool calls** — intercepts both proxy tool calls (`mcp({tool: "..."})`) and direct tools (e.g., `exa_web_search_exa`); auto-allows metadata operations; prompts for tool invocations showing server, tool, and argument preview; server-level "Always" approval (e.g., `exa:*`)
- **Auto-allow** — "Always" option grants session-scoped permission; status widget shows active allowances
- **Retry-loop prevention** — recently-aborted commands are auto-blocked for 60 seconds
- **Prompt frequency warning** — after 20 prompts, warns the user to use "Always" to reduce noise
- **No-UI fallback** — auto-blocks when no UI is available; subagents forward permission requests to the main session instead
- **Subagent permission forwarding** — subagents without UI access forward `ask` permissions to the main interactive session via file-based IPC. The main session polls for pending requests, shows the confirmation prompt, and writes the response back (10-minute timeout).

## How It Works

Every intercepted tool call flows through three stages:

```
Handler → Decision Engine → Prompt Flow
```

1. **Handler** — validates the event, builds a `PermissionRequest`, calls `await decide()`
2. **Decision Engine** — async policy function. Checks auto-allow rules, retry-loop prevention, and analysis results (including tree-sitter AST parsing). Returns `auto-allow`, `block`, or `prompt`
3. **Prompt Flow** — on `prompt` decisions, builds structured prompt content, displays the two-tier confirmation UI, and mutates the store on "always"

### Two-tier confirmation

When the user selects "Always", a second prompt requires explicit confirmation before granting session-scoped permission. This prevents accidental auto-allow from misclicks.

### Auto-allow categories

| Category | Scope | Granted by |
|----------|-------|------------|
| Bash signatures | Command + flags (e.g. `git -am`) | "Always" on bash prompt |
| Read directories | Any read in that directory | "Always" on file/bash path prompt |
| Write directories | Any write/edit in that directory | "Always" on file write prompt |
| File paths | Specific resolved path | "Always" on file-inside-cwd prompt |
| Subagent names | Agent name (e.g. `scout`) | "Always" on subagent prompt |
| MCP servers | All tools from a server (e.g. `exa:*`) | "Always" on MCP prompt |

## Architecture

```
index.ts                          Extension entry — event registration
├── handlers/                     Thin adapters (50–100 lines each)
│   ├── bash.ts                   Bash command interceptor
│   ├── file.ts                   File operation interceptor (incl. edit pre-validation)
│   ├── mcp.ts                    MCP tool call interceptor
│   └── subagent.ts               Subagent spawning interceptor
├── forwarding/                   File-based IPC for subagent permission forwarding
│   ├── io.ts                     Types, atomic file I/O, session directory resolution
│   └── polling.ts                Main-session polling + subagent wait-and-forward
├── bash-parser.ts                tree-sitter-bash wrapper — lazy WASM load, AST path extraction
├── decision-engine.ts            Pure policy — async decide(request, store) → Decision
├── command-analysis.ts           Fat analyzer — async analyzeCommand(cmd, cwd) → CommandAnalysis
├── path-analysis.ts              Pure path utilities (resolve, deny rules, cwd checks)
├── prompt-flow.ts                UI interaction loop — showPrompt(decision, ctx, store)
├── prompt-builder.ts             Pure formatter — PromptDecision → BuiltPrompt (title/body)
├── prompts.ts                    Two-tier confirmation flow (orchestrates selector)
├── selector.ts                   Custom TUI components — showSelect + showReasonEditor
├── store.ts                      Auto-allow state — Store interface + factory
├── widget.ts                     TUI rendering — permissions status bar
├── permission-state.ts           Session lifecycle — reset + re-export hub
└── config/                       Focused configuration modules
    ├── thresholds.ts             Time/count constants
    ├── bash-patterns.ts          Allowed commands, path-aware set, dangerous find flags
    ├── path-rules.ts             Allowed read paths, denied path names
    └── dangerous-patterns.ts     Regex danger patterns (safety net)
```

### Key seams

- **Store** — injected into `decide()` for testability. Runtime singleton + `createStore()` factory for tests
- **Decision Engine** — async pure function, no UI dependency. All policy logic concentrated here
- **Bash Parser** — lazy-loaded tree-sitter WASM. Public API: `extractPathsFromBash()`, `hasSubshell()`
- **Prompt Builder** — pure function. All prompt wording lives in one module
- **Selector** — only module calling `ctx.ui.custom()`. UI seam for selection prompts and reason editor

## Configuration

All config lives in `config/` as focused modules, re-exported through `config/index.ts`:

| Module | What it controls |
|--------|-----------------|
| `thresholds.ts` | `ABORT_REMEMBER_MS` (60s), `PROMPT_WARNING_THRESHOLD` (20) |
| `bash-patterns.ts` | Auto-allowed commands, path-aware commands, dangerous find flags |
| `path-rules.ts` | Always-allowed read paths, always-denied path names |
| `dangerous-patterns.ts` | Regex patterns for risk detection (safety net alongside token analysis) |

## Testing

- **Decision engine** — unit-testable with `createStore()` fake. Async, no UI dependency
- **Prompt builder** — pure function. Verify prompt content for each decision type
- **Command analysis** — async pure function. Verify risk scoring, AST path extraction, obfuscation detection
- **Bash parser** — lazy WASM loading. Verify path extraction across heredocs, comments, quotes, subshells
- **Path utilities** — pure functions. Verify path resolution, deny rules, cwd checks
- **MCP handler** — verify server:tool parsing, metadata op auto-allow, server-level session approval

## Dependencies

- `tree-sitter-bash` + `web-tree-sitter` — full bash AST parsing for segmentation, path extraction, operator detection, and subshell detection (handles heredocs, comments, quotes, subshells, and redirects correctly)
- No external dependencies for forwarding — uses only `node:fs` and `node:path` for file-based IPC
