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

### Decisions: pass, prompt, block

Before any session grants exist, every bash command resolves to exactly one outcome. Fail-closed is the default: anything unresolvable prompts. The agreed principles (`test/cases.test.ts` header — that file is the contract suite):

1. **Write → prompt** (carve-out: "safe creation" — `mkdir`/`touch`/`mktemp` — auto-allows)
2. **Read inside cwd → auto-allow**
3. **Code execution → prompt** (unless trusted script)
4. **Outside cwd → prompt (first time), remembered → auto-allow**
5. **Unsafe patterns → always prompt** — no session grant can override them

**Command substitution: a read-only body is data, not code (2026-08).** A `$(…)`/backtick/process-substitution (`<(...)`, `>(...)`) body made of read-only commands (the unconditionally-safe set + `grep`/`rg`/`fd`/`ag`) with no write redirect (null redirects like `> /dev/null` aren't writes — pre-existing gate convention), backgrounding, or multi-line list is pure data production — it no longer counts as code execution, so `sed -n "$(grep -n x f | cut -d: -f1),+5p" f` and `cat <(ls)` auto-allow. Guards: the body's own paths get the same path checks (a `$(cat /etc/shadow)` inside a read-only body still prompts the outside path), nested substitutions are classified individually, and any other body keeps the always-prompt flag (principle 5). `find` is excluded from the body set (`-exec`/`-delete`), and so are wrappers — the delegated command isn't visible at this level. Quote-aware throughout (`grep "a\|b" f` inside a body does not mis-split).

**Sed's script argument is not a file (2026-08).** Sed's grammar is `sed [flags] script [files…]`, so the first non-flag arg (and `-e`'s value) is skipped by path analysis — the line-range idiom above no longer produces `<unresolved-var>`. File-position args keep the opaque marker (`sed -n 'p' $(echo /etc/shadow)` still prompts), and a bare literal path in script position stays path-checked (fail closed).

Rules run in order — `RetryLoop → CredentialDeny → FastAllow → Safety → PromptFallback` (`policies/bash-rules.ts`).

**Pass (auto-allow)** — all of these hold:
- every segment's command is allowlisted (`config/bash-patterns.ts`) or is a trusted-script invocation (see *Trusted Scripts*). The allowlist is mostly read-only inspection, but deliberately includes a few first-time writes: safe creation (`touch`, `mkdir`, `mktemp`) and non-destructive git (`add`, `commit`, `checkout`, `branch`, `merge`, `stash`)
- every resolved path stays inside the session cwd, `allowedReadPaths`, `allowedWritePaths`, or the trusted skills dir
- no write operation or dangerous flag/pattern (write redirects, `tee`/`cp`/`mv`/`rm`/`truncate`, `sed -i`, `sort -o`, `find -delete`/`-exec`, **any** `git push`, destructive git, `npm install`, script execution, wrappers running writes, …)

**Prompt** — three flavors:

*First time — "Always" grants and later runs auto-allow:*
- a path resolves **outside** cwd/allowed dirs — the prompt lists the outside dirs; "Always" grants that dir for the session
- a safe command not in the allowlist (`npm run …`, `docker …`, …) — "Always" grants the command signature for the session
- `warnPaths` matches (e.g. `.env.*`) — prompt with a warning; a **bare-name symlink in cwd resolving outside it** (`cat link` → `/etc/…`) prompts the same way — the literal name carries no path text, so the gate lstats bare tokens (symlinks only; a regular file in cwd cannot escape it)

*Every time — the prompt builder suppresses "Always" for these (principle 5; only Yes/No):*
- **write redirects** — `>`, `>>` — anywhere, including inside cwd (`ls > out.txt`)
- **write commands not in the allowlist** — `tee`, `cp`, `mv`, `rm`, `truncate`, `sed -i`, `find -delete`/`-exec`, `sort -o`, wrappers running writes (`xargs rm`, `timeout rm`)
- **code execution** — `python`, `curl`, `npm install`, … (unless trusted)
- **destructive / remote git** — any `git push` (writes to remote; force variants are high severity), `git rm`, `git clean -f`, `git reset --hard`, `git reflog expire`, `git gc --prune`

*Unresolvable targets — the location can't be determined at parse time:*
- **opaque targets**: `$VAR`, `${VAR}`, `$(…)`, backticks in path position — flagged with an `<unresolved-var>` marker, never fast-allowed. (Exception: sed's script argument — see above; a read-only substitution body doesn't flag the segment itself, but its unbound vars in path position still do: `cat $(wc -c < $f)` prompts until `$f` is loop-bound to bare names)
- **unknown base**: a `cd` whose target can't be resolved (`cd $D`, globs, `cd -`) makes later relative paths unresolvable → `<unresolved-cwd>` marker
- **base access**: `cd` is navigation, not access — a path-aware segment with no target of its own (`cd /outside && ls`, `cd $D && find .`, `cd /outside && cat main.txt`, bare-name redirects like `cd /outside && echo x > out.txt`) operates on the base the cd left; that base is what gets approved

**Block** — never promptable, rejected with a reason:
- credential patterns anywhere in the raw command text (glob- and quote-aware): `.ssh`, `.gnupg`, `.env`, `.aws`, `id_rsa`, `*.pem`, … — plus a symlink-name check for bare tokens pointing at credentials. Shell comments and heredoc bodies are data, not operands: the scan is comment-aware (word-boundary `#`, quote/continuation-aware, 2026-08) so `# check the .ssh dir\nls` no longer blocks `ls` — a live credential operand on any line is still blocked
- paths matching `deniedPaths` (`config/path-rules.ts`)
- retry-loop guard: a command the user aborted within 60s is blocked instead of re-prompting

**The cd model (one rule to remember)**: `cd` performs no file access, so its target is never itself a path. What matters is (a) where later segments run — their relative paths re-resolve against the effective base (`cd /tmp && cat ./secret` approves `/tmp/secret`) — and (b) what they do with no resolvable target, which flags the base. Consequences: standalone `cd /outside` auto-allows (state dies with the process); `cd /nonexistent && …` auto-allows when the rest never runs; `cd $HOME/.ssh && ls` still **blocks** (the credential scan is raw-text, independent of the path set).

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
│   ├── cwd-tracking.ts           Effective cwd per segment across cd (threading / unknown base) + base-access flagging
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
│   ├── bash-rules.ts             Composable bash rules: RetryLoop → CredentialDeny → FastAllow → Safety → PromptFallback
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

### Key files (small → large)

| File | What it does |
|------|---|
| `handlers/bash.ts` | Intercept bash commands |
| `handlers/file.ts` | Intercept file operations |
| `handlers/mcp.ts` | Intercept MCP tool calls (proxy + direct) |
| `gate.ts` | Shared decide → prompt → reject flow |
| `rule-generator.ts` | Derive auto-allow rules from data |
| `prompt-flow.ts` | Prompt orchestration |
| `policies/bash.ts` | Bash policy entry point |
| `policies/bash-rules.ts` | Composable bash rules |
| `analysis/command-analysis.ts` | Command analysis orchestrator |
| `analysis/segment-analysis.ts` | Segment safety analysis |
| `analysis/segment-helpers.ts` | Shared analysis utilities |
| `analysis/bash-parser.ts` | tree-sitter parser wrapper, `parseCommand()` API |
| `analysis/mcp-resolver.ts` | MCP server/tool resolution |
| `prompt-builder.ts` | Build prompt content |
| `prompts.ts` | Two-tier confirmation UI |
| `store.ts` | Auto-allow state management |
| `renderers/tmux.ts` | Tmux command formatting |

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

## Ad-hoc testing a command

To see what halter will do with a specific command — without running it — call the decision engine directly: the same function the gate uses, with the real store and config.

```ts
// probe.mts — in the halter dir
import { decide } from "./decision-engine";
import { createStore } from "./store";

const d = await decide(
  { type: "bash", command: "cd /var/tmp && ls", cwd: "/mnt/Ndr/Projects" },
  createStore(),
);
console.log(d.kind, d.kind === "prompt" ? d.promptData : d.kind === "block" ? d.reason : "");
```

```
npx tsx probe.mts
```

Reading the result:
- `d.kind` — `"auto-allow" | "block" | "prompt"`
- `d.promptData.outsideDirs` — which dirs the prompt would ask for; `d.promptData.segments` / `signatures` — what the prompt shows
- `d.reason` (block) — the matched rule

For analysis-level debugging (paths, markers, safety verdicts) use `analyzeCommand(cmd, cwd)` from `analysis/command-analysis` instead. `test/cwd-threading.test.ts` is the contract file for cd/var behavior; `test/cases.test.ts` is the curated pass/prompt/block suite.

## Trusted Packages (`uv run --with`)

`config/trusted-scripts.ts` maintains a `TRUSTED_PACKAGES` allowlist. Commands like `uv run --with <pkg> python script.py` are only auto-trusted if:
1. The script is in a trusted directory (e.g. `~/.pi/agent/skills/`)
2. All packages in `--with` are in the `TRUSTED_PACKAGES` set
3. `--with-requirements` / `--with-editable` sources are also inside a trusted directory (they bypass the package allowlist, so the deps file/dir must be trusted too)

To add a new package, edit the `TRUSTED_PACKAGES` set in `config/trusted-scripts.ts` (lowercase, no extras — `markitdown[pptx]` is matched against `markitdown`).

## Trusted Scripts (skills dir)

Scripts resolving into a trusted directory (`~/.pi/agent/skills/`) are auto-allowed — the directory is treated as user-curated. Three invocation forms qualify:

1. **Interpreter + script** — `python3 ~/…/skills/x/script.py`, `uv run --with <trusted-pkg> python ~/…/skills/x/script.py` (package allowlist applies)
2. **Shell interpreter + script** — `bash ~/…/skills/x/script.sh`, `sh ./scripts/script.sh` (cwd inside the skill dir). Only the *first non-flag token* may be the script file; anything else falls back to normal analysis.
3. **Direct exec** — `~/…/skills/x/script.sh`, `./scripts/script.sh` (executable scripts are invoked this way by skill docs). Any file path resolving into the trusted dir qualifies.

**`-c`/`--command` is never trusted** for shell interpreters: `bash -c '~/skills/q.sh; rm -rf /'` must not inherit trust from the path inside the opaque quoted string.

**Trust covers the script invocation only — never shell operators around it.** These still prompt:
- pipe stages that are unsafe: `q.sh … | bash` (RCE via the output), `q.sh … | ./evil`, `q.sh … | sort -o file`
- write redirects: `q.sh … > ./out` (the write is a side effect the user didn't curate)
- command substitution in arguments: `script.py "$(cmd)"` (executed by the shell before the script runs)

Piping a trusted script into safe read-only stages (`| head`, `| grep`) remains auto-allowed.

## Dependencies

- `tree-sitter-bash` + `web-tree-sitter` — full bash AST parsing for segmentation, path extraction, operator detection, and subshell detection (handles heredocs, comments, quotes, subshells, and redirects correctly)
- No external dependencies for forwarding — uses only `node:fs` and `node:path` for file-based IPC
