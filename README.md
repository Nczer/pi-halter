# Halter (pi extension)

A halter for pi tool calls. Intercepts `bash`, `read`/`write`/`edit`, and `mcp` calls, auto-allowing safe operations and prompting the user for anything risky.

## Features

- **Bash commands** — auto-allows simple read-only commands (`ls`, `grep`, `find`, etc.); prompts for dangerous operations (`rm`, `sudo`, `curl | bash`, etc.); blocks denied credential paths (`.ssh`, `.gnupg`, etc.) and prompts for warned paths (`.env`, `.aws`, etc.) even via `cat`/`grep`
- **File access** — auto-allows reads inside cwd and trusted paths; prompts for paths outside cwd, denied names (`.env`, `.ssh`, etc.)
- **MCP tool calls** — intercepts both proxy tool calls (`mcp({tool: "..."})`) and direct tools (e.g., `exa_web_search_exa`); auto-allows metadata operations; prompts for tool invocations showing server, tool, and argument preview; server-level "Always" approval (e.g., `exa:*`)
- **Auto-allow** — "Always" option grants session-scoped permission; status widget shows active allowances
- **Retry-loop prevention** — recently-aborted commands are auto-blocked for 60 seconds
- **Prompt frequency warning** — after 20 prompts, warns the user to use "Always" to reduce noise
- **No-UI fallback** — auto-blocks when no UI is available
- **DSP mode** — `/dsp` command toggles "Dangerously Skip Permissions" to bypass all checks (with persistent warning widget)

## How It Works

Every intercepted tool call flows through five stages:

```
Handler → Gate → Decision Engine → Prompt Flow → Rule Generator
```

1. **Handler** — validates the event, builds a request, passes it to `gate()`
2. **Gate** — shared flow: calls `decide()`, handles auto-allow / block / prompt routing, manages UI expand/collapse, and formats rejections
3. **Decision Engine** — async policy function. Routes to the right policy (bash, file, mcp). Returns `auto-allow`, `block`, or `prompt` with `PromptData`
4. **Prompt Flow** — on `prompt` decisions, builds and displays the two-tier confirmation UI. On "Always", generates rules and saves them
5. **Rule Generator** — derives auto-allow rules from `PromptData` (on-demand, only when user picks "Always")

### Two-tier confirmation

When the user selects "Always", a second prompt requires explicit confirmation before granting session-scoped permission. This prevents accidental auto-allow from misclicks.

### Auto-allow categories

| Category | Scope | Granted by |
|----------|-------|------------|
| Bash signatures | Command + flags (e.g. `git -am`) | "Always" on bash prompt |
| Paths (R) | Read access to dirs/files | "Always" on read prompt |
| Paths (R/W) | Read+write access to dirs/files | "Always" on write prompt (implies read) |
| MCP servers | All tools from a server (e.g. `exa:*`) | "Always" on MCP prompt |

## Architecture

```
index.ts                          Extension entry — event registration, /dsp command
gate.ts                           Shared halter gate — decide → prompt → reject flow
rule-generator.ts                 Derives auto-allow rules from PromptData (on-demand)
├── handlers/                     Thin adapters (all call gate())
│   ├── index.ts                  Re-exports for handlers
│   ├── bash.ts                   Bash command interceptor
│   ├── file.ts                   File operation interceptor
│   └── mcp.ts                    MCP tool call interceptor (proxy + direct tools)
├── analysis/                     Command analysis and risk assessment
│   ├── bash-parser.ts            tree-sitter-bash wrapper — lazy WASM load, parseCommand() API
│   ├── tokenizer.ts              Command tokenization
│   ├── segment-analysis.ts       Unified segment analysis — runs evaluators, pipeline checks, safety verdicts
│   ├── segment-helpers.ts        Shared helpers: wrapper commands, git danger, stage danger, pipeline splitting
│   ├── command-analysis.ts       Orchestrates analysis → CommandAnalysis (with SafetyVerdict + PromptHints)
│   ├── risk-analyzer.ts          Whole-command risk assessment (merge segment risks + operator checks)
│   ├── path-analysis.ts          Pure path utilities (resolve, deny rules, cwd checks, outside-path detection)
│   ├── path-util.ts              Path helpers (tilde expansion)
│   ├── mcp-resolver.ts           MCP server resolution from tool names, proxy target derivation
│   ├── tmux-helpers.ts           Tmux-specific analysis
│   ├── obfuscation.ts            Obfuscation detection (variable indirection, base64, xargs tricks, etc.)
│   └── evaluators/               Per-domain risk evaluators (modular, pluggable)
│       ├── types.ts              RiskEvaluator interface definition
│       ├── builder.ts            Fluent builder for EvaluatorResult (eliminates boilerplate)
│       ├── disk-evaluator.ts     Disk/volume management commands (mount, mkfs, fdisk, etc.)
│       ├── git-evaluator.ts      git dangerous operations (reset --hard, push --force, etc.)
│       ├── shell-evaluator.ts    Subshells, heredocs, redirects, sed/perl, wrappers
│       ├── system-evaluator.ts   sudo, rm, chmod, chown, mv, cp, kill, shutdown, systemctl, dd
│       ├── tmux-evaluator.ts     tmux dangerous subcommands (send-keys, run-shell, etc.)
│       └── tool-evaluator.ts     find/fd/rg exec, kubectl, terraform, aws, gcloud, curl/wget pipe
├── decision-engine.ts            Pure policy dispatcher — async decide(request, store) → Decision
├── policies/                     Request-specific decision logic
│   ├── bash.ts                   Bash policy (runs bash-rules.ts pipeline)
│   ├── bash-rules.ts             Composable bash rules: UserDeny → RetryLoop → FastAllow → Safety → PromptFallback
│   ├── file.ts                   File policy
│   └── mcp.ts                    MCP policy
├── prompt-flow.ts                UI interaction loop — showPrompt(decision, ctx, store)
├── prompt-builder.ts             Pure formatter — PromptData → BuiltPrompt (title/body/options)
├── prompts.ts                    Two-tier confirmation flow (orchestrates selector)
├── selector.ts                   Custom TUI components — showSelect + showReasonEditor
├── store.ts                      Auto-allow state — Store interface + singleton
├── widget.ts                     TUI rendering — halter status bar
├── dsp-mode.ts                   DSP mode toggle — bypass all halter checks with warning widget
├── renderers/                    Display formatting helpers
│   ├── mcp.ts                    MCP tool call formatting (proxy + direct, args preview, truncation)
│   └── tmux.ts                   Tmux command formatting (strips boilerplate flags, structures output)
└── config/                       Focused configuration modules
    ├── index.ts                  Config re-exports, thresholds (ABORT_REMEMBER_MS, PROMPT_WARNING_THRESHOLD)
    ├── bash-patterns.ts          Allowed commands, write handlers, dangerous flags, wrapper commands
    ├── path-rules.ts             Path allow/deny rules (deniedPaths, warnPaths, allowedReadPaths, allowedWritePaths)
    ├── dangerous-patterns.ts     Dangerous command/context regex patterns
    └── trusted-scripts.ts        Trusted packages (TRUSTED_PACKAGES), trusted script path checks
```

### Key seams

- **Gate** (`gate.ts`) — single shared flow for all handlers. Handlers only provide request construction and rejection formatting
- **Store** — injected into `decide()` and `showPrompt()`. Runtime singleton
- **Decision Engine** — async pure function, no UI dependency. All policy logic concentrated here
- **Rule Generator** (`rule-generator.ts`) — derives auto-allow rules from `PromptData` on-demand. Decouples policy decision from rule specifics
- **Bash Parser** — lazy-loaded tree-sitter WASM. Public API: `parseCommand(command, cwd) → ParseResult` returns `{ segments, paths, hasSubshell }` in one call
- **Evaluators** — modular risk evaluators in `analysis/evaluators/`. Each implements `RiskEvaluator` interface. Adding new analyzers is a drop-in file
- **Segment Helpers** (`segment-helpers.ts`) — shared utilities: `checkStageDanger()`, `isGitDangerous()`, `isWrapperRunningWrite()`, `getCommandSignature()`, `hasWriteRedirect()`, `isFindExecWrite()`, `isFdExecWrite()`, `isRgPreWrite()`
- **Prompt Builder** — pure function. All prompt wording lives in one module. Truncates long commands to 20 lines
- **Selector** — only module calling `ctx.ui.custom()`. UI seam for selection prompts and reason editor

## Reading the Code (Beginner's Guide)

### The flow of a single request

Follow a bash command (`ls -la`) through the system:

1. **`handlers/bash.ts`** — pi intercepts the command, handler builds a `BashRequest` and calls `gate()`
2. **`gate.ts`** — calls `decide(request, store)`
3. **`decision-engine.ts`** — routes to `policies/bash.ts`
4. **`policies/bash.ts`** — runs the rule pipeline from `bash-rules.ts`:
   - `RetryLoopRule` — was it recently aborted? → block
   - `CredentialDenyRule` — does it reference a denied credential path (`.ssh`, `.gnupg`)? → block
   - `FastAllowRule` — is it trivially safe? → auto-allow (skipped if credential pattern detected)
   - `SafetyRule` — full analysis via `analysis/command-analysis.ts` → auto-allow or null (also blocks auto-allow for warned credential paths like `.env`)
   - `PromptFallbackRule` — everything else → prompt
5. **`gate.ts`** — on prompt, calls `showPrompt()`
6. **`prompt-flow.ts`** → **`prompt-builder.ts`** → **`prompts.ts`** — displays the prompt
7. User picks "Always" → **`rule-generator.ts`** derives rules → saved to **`store.ts`**

### File sizes (small → large)

| File | Lines | What it does |
|------|-------|---|
| `handlers/bash.ts` | ~20 | Intercept bash commands |
| `handlers/file.ts` | ~63 | Intercept file operations |
| `handlers/mcp.ts` | ~86 | Intercept MCP tool calls (proxy + direct) |
| `gate.ts` | ~153 | Shared decide → prompt → reject flow |
| `rule-generator.ts` | ~121 | Derive auto-allow rules from data |
| `prompt-flow.ts` | ~71 | Prompt orchestration |
| `policies/bash.ts` | ~36 | Bash policy entry point |
| `policies/bash-rules.ts` | ~125 | Composable bash rules |
| `analysis/command-analysis.ts` | ~140 | Command analysis orchestrator |
| `analysis/segment-analysis.ts` | ~263 | Segment safety analysis |
| `analysis/segment-helpers.ts` | ~270 | Shared analysis utilities |
| `analysis/bash-parser.ts` | ~507 | tree-sitter parser wrapper, `parseCommand()` API |
| `analysis/mcp-resolver.ts` | ~227 | MCP server/tool resolution |
| `prompt-builder.ts` | ~298 | Build prompt content |
| `prompts.ts` | ~160 | Two-tier confirmation UI |
| `store.ts` | ~370 | Auto-allow state management |
| `renderers/tmux.ts` | ~336 | Tmux command formatting |

## Configuration

Config is split across focused modules in `config/`:

| File | What it controls |
|------|-----------------|
| `config/index.ts` | Thresholds: `ABORT_REMEMBER_MS` (60s), `PROMPT_WARNING_THRESHOLD` (20). Re-exports from other config modules. |
| `config/bash-patterns.ts` | `unconditionallySafeCommands`, `pathAwareCommands`, `isAllowedCommand()`, `isSafeSubcommand()`, `isWriteOperation()`, `wrapperCommands`, `SHELL_INTERPRETERS`, `PACKAGE_MANAGERS`, `dangerousFindFlags`, `dangerousSedFlags`, `dangerousPerlFlags` |
| `config/path-rules.ts` | `deniedPaths`, `warnPaths`, `allowedReadPaths`, `allowedWritePaths` |
| `config/dangerous-patterns.ts` | `dangerousCommandPatterns`, `dangerousContextPatterns` (regex patterns) |
| `config/trusted-scripts.ts` | `TRUSTED_PACKAGES` allowlist for `uv run --with`, `isTrustedScriptPath()`, `isTrustedScriptCommand()` |
## Testing

- **Decision engine** — async, no UI dependency. Inject `Store` for testability
- **Prompt builder** — pure function. Verify prompt content for each decision type
- **Command analysis** — async pure function. Verify risk scoring, AST path extraction, safety verdicts
- **Segment analysis** — verify evaluator integration, pipeline checks, safety boolean derivation
- **Evaluators** — each evaluator is independently testable via `RiskEvaluator.evaluate()`
- **Bash parser** — lazy WASM loading. Verify path extraction across heredocs, comments, quotes, subshells
- **Path utilities** — pure functions. Verify path resolution, deny rules, cwd checks
- **Obfuscation detection** — pure function. Verify each technique regex
- **MCP renderer** — pure functions. Verify formatting, truncation, edge cases
- **Round-trip tests** — verify prompt → rules → auto-allow cycle works end-to-end

## Trusted Packages (`uv run --with`)

`config/trusted-scripts.ts` maintains a `TRUSTED_PACKAGES` allowlist. Commands like `uv run --with <pkg> python script.py` are only auto-trusted if:
1. The script is in a trusted directory (e.g. `~/.pi/agent/skills/`)
2. All packages in `--with` are in the `TRUSTED_PACKAGES` set

To add a new package, edit the `TRUSTED_PACKAGES` set in `config/trusted-scripts.ts` (lowercase, no extras — `markitdown[pptx]` is matched against `markitdown`).

## Dependencies

- `tree-sitter-bash` + `web-tree-sitter` — full bash AST parsing for segmentation, path extraction, operator detection, and subshell detection (handles heredocs, comments, quotes, subshells, and redirects correctly)
- No external dependencies for forwarding — uses only `node:fs` and `node:path` for file-based IPC
