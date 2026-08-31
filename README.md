# Halter (pi extension)

A halter for pi tool calls. Intercepts `bash` and `read`/`write`/`edit` calls, auto-allowing safe operations and prompting the user for anything risky. Tool extensions can additionally opt in through a small **gate plugin** (`<ext>/halter/`) — halter then gates their calls with the same prompts, grants, judge, and dspa machinery.

## Features

- **Bash commands** — auto-allows simple read-only commands (`ls`, `grep`, `find`, etc.); prompts for dangerous operations (`rm`, `sudo`, `curl | bash`, etc.); blocks denied credential paths (`.ssh`, `.gnupg`, etc.) and prompts for warned paths (`.env`, `.aws`, etc.) even via `cat`/`grep`
- **File access** — auto-allows reads inside cwd, trusted paths, and nonexistent paths (a read can only ENOENT — nothing can leak); prompts for paths outside cwd, denied names (`.env`, `.ssh`, etc.)
- **Tool plugins** — any tool ext that ships `<ext>/halter/index.ts` is gated: the plugin classifies calls as `exec` (script payload → judge/dspa), `file` (target path → outside-cwd warning), or `consent` (per-kind session consent); discovery calls pass ungated; a broken plugin blocks its tool fail-closed
- **Auto-allow** — "Always" option grants session-scoped permission; status widget shows active allowances
- **Retry-loop prevention** — recently-aborted commands are auto-blocked for 60 seconds
- **Prompt frequency warning** — after 20 prompts, warns the user to use "Always" to reduce noise
- **No-UI fallback** — auto-blocks when no UI is available
- **DSP mode** — `/dsp` command toggles "Dangerously Skip Permissions" to bypass all checks (with a persistent warning line pinned on top of the status widget)
- **Judge modes** — `/dspa` auto-allows operations that pass a deterministic hard floor *and* a two-stage LLM-judge verdict (stateless pass, then an intent pass with reasoning-blind session context) (visible toast); `/dspat` shows the judge's verdict in every bash prompt and records agreement stats; both fail toward the prompt. The modes are one machine — **manual / dspa / dspat / dsp**: enabling one leaves the others off (switching resets the left judge mode's session stats)
- **Judge settings** — `/judge` (bare = show; `on|off`, `model <provider/id|session>`, `thinking <level>`, `timeout <ms>`) — persisted in the `halter` namespace of `~/.pi/agent/settings-ext.json`
- **Decision log** — `/halter-decision-log` records every gate decision to a JSONL file (see *Configuration → Decision log*)

## How It Works

Every intercepted tool call flows through five stages:

```
Handler → Gate → Decision Engine → Prompt Flow → Rule Generator
```

1. **Handler** — validates the event, builds a request, passes it to `gate()`
2. **Gate** — shared flow: calls `decide()`, handles auto-allow / block / prompt routing, manages UI expand/collapse, and formats rejections
3. **Decision Engine** — async policy function. Routes to the right policy (bash, file, tool). Returns `auto-allow`, `block`, or `prompt` with `PromptData`
4. **Prompt Flow** — on `prompt` decisions, builds and displays the two-tier confirmation UI. On "Always", generates rules and saves them
5. **Rule Generator** — derives auto-allow rules from `PromptData` (on-demand, only when user picks "Always")

### Tool plugins

A tool ext opts into halter by shipping a `halter/` subfolder that default-exports a plugin (`plugins/types.ts`):

```ts
// <ext>/halter/index.ts — e.g. for a tool that can execute code
import { actions } from "../registry.ts";
export default {
  name: "blender", // the tool name this plugin gates (the loader keys slots on it)
  buildRequest: (event, ctx) => {                   // ctx = session context (read-only)
    const a = actions.get(String(event.input?.action));
    if (!a || a.discovery) return null;             // discovery → ungated pass
    if (a.risk === "exec")  return { kind: "exec", label: a.name, script: a.finalize(event.input).code };
    if (a.risk === "write") return { kind: "file", label: a.name, path: event.input.path as string };
    return { kind: "consent", label: a.name, consentKind: "read" };
  },
};
```

The loader (`plugins/loader.ts`) scans the extensions root at halter load and keys slots by the GATED TOOL's name — a multi-tool ext can gate any of its tools (tool name ≠ ext dir is fine). `handleTool` (`handlers/tool.ts`) dispatches by tool name and passes `(event, ctx)` to the plugin; `ctx` is read-only session state the classifier may consult (e.g. `ctx.model` for a local-reader exemption). The plugin only CLASSIFIES — prompts, grants, judge, dspa, decision log, and widget all live in the core:

- **Grant scopes** (session): `<tool>` = whole tool (the "Always" on an exec/file prompt — the tier-2 confirmation names the code-execution risk); `<tool>:kind:<kind>` = one consent kind (a read consent can never cover the tool's exec actions). Shown as the widget's `Tools:` line.
- **Payload identity**: an `exec` request must carry the FINAL payload, byte-identical to what the tool will execute — plugins import the tool ext's own payload builder so the judge reviews exactly what runs (D11, untrimmed packet).
- **dspa**: `exec` is judgeable (the payload IS the model); `file`/`consent` are never auto-allowed (session grants cover them).
- **Fail-closed**: a plugin that fails to import or violates the contract blocks ALL calls to its tool — the loader recovers the tool name from the plugin file's `name:` literal (no literal → ext dir fallback); a `buildRequest` throw blocks the call. A tool without a plugin is simply not gated.

### Two-tier confirmation

When the user selects "Always", a second prompt requires explicit confirmation before granting session-scoped permission. This prevents accidental auto-allow from misclicks. The filesystem root is never an Always grant: a root-only path prompt (e.g. `find /`) offers no dir tier at all, mixed prompts drop `/` from the grant, and a file prompt's broader umbrella stops before root — one click can never hand out the whole disk.

### The judge (LLM second opinion)

The judge is a stateless one-shot model call at the permission prompt: its entire input is a judgment packet — the command (capped), halter's static-analysis digest, and — when the command executes an untrusted local script — the script's content as fenced untrusted data. No conversation history, no session state. Any failure (model unresolved, auth, timeout, malformed reply) resolves to "no verdict": the prompt shows exactly what it would have shown without the judge. The judge never alters the gate's decision on its own.

- **`/dspat`** — the prompt body gains a `💭 Judge:` block (explanation + `→ suggests: APPROVE|REJECT|DEFER (<risk>)` — defer is its own word, not collapsed into REJECT); the user's choice is recorded against the verdict (session stats, incl. disagreements)
- **`/dspa`** — before any prompt, the deterministic hard floor (`dspa-gate.ts`: parse errors, obscured command positions, credential patterns, network egress — fetch forms and raw egress, except loopback-only curl/wget (every URL in the command is 127.0.0.0/8, ::1, or localhost — judgeable, D14); all other egress stops are advisory — the judge's verdict renders in the prompt but the stop stands, egress is never auto-allowed (D14); package-manager RUN forms are judgeable, D8 — except FETCHABLE ones (`npx <pkg>`, `uvx`, `npm exec`, `pnpm dlx`, `bun x` …), which stop on an untrusted package (D10): the judge's verdict is shown advisory in the prompt and a "Trust: <pkg> (session)" option grants deterministic auto-allow for that package across run forms (env prefixes and wrapper delegation are resolved first, so `FOO=bar npx evil` cannot hide from the stop), network egress after trust is the user's explicit choice; local run forms like `npm run`, `uv run`, `bun <script>` stay judge-only, D8), paths outside the **manual bar** — the bar manual mode auto-allows (cwd + session grants + config-allowed + trusted scripts, D11: the floor's bar *is* the manual bar; scope-class stops get the judge's verdict rendered advisory in the prompt) — including unbound ones, which the floor first tries to resolve from the command itself (local var assignments, every candidate base of the `||`-ambiguous cd) before gating on the concrete dir; a location it cannot resolve is a floor stop, never auto-allowed (D7, D11), the rm carve-out — explicit `/tmp` scratch targets are judgeable, D8/D11) runs — everything else is judgeable (the judge sees the full, untrimmed command, including inline script bodies and heredocs, plus halter's analysis). Then the two-stage judge: stage 1 (stateless) auto-allows `approve` + `low` only; when it doesn't, stage 2 (same packet + reasoning-blind session context — the user's last messages, a tool-call digest, session grants; never agent prose or tool outputs) auto-allows `approve` + `low|medium`. `approve` + `high` and rejects always prompt; auto-allows toast. Content-bearing manual auto-alls are judged too (D3/D11: every file-write auto-allow — grants, config-allowed, project-pi — and granted script executions ride their full content into the two-stage judge; manual's "Always-for-dir" stays a blind auto-allow outside `/dspa`). Stage 2 also reports the paths the operation touches; the gate cross-checks them against the floor's own knowledge and logs what the static analysis never saw as `judgePathMisses` — diagnostic only, the floor is never fed LLM output (D13, `log-inspect.mjs dspa --paths`). The floor is code, the model is advisory (`docs/dspa-redesign.md`)
- **One mode at a time** — manual / dspa / dspat / dsp is a single machine: enabling one disables the others (enabling `/dsp` always confirms; leaving a judge mode resets its session stats; a cancelled `/dsp` confirmation keeps the current mode)
- **Default mode** — an on-demand `💭 Explain` prompt option runs the judge when picked and appends the same full verdict block (it does not record agreement stats: the human picks when to consult, so those decisions are a self-selected subset)

### Auto-allow categories

| Category | Scope | Granted by |
|----------|-------|------------|
| Bash signatures | Command + flags (e.g. `git -am`) | "Always" on bash prompt |
| Paths (R) | Read access to dirs/files | "Always" on read prompt |
| Paths (R/W) | Read+write access to dirs/files | "Always" on write prompt (implies read) |
| Trusted packages | One package across fetchable run forms (`npx/uvx/dlx …`, any args) | "Trust" on any prompt with an untrusted fetchable form — the only grant for those forms (all modes, D10) |

### Decisions: pass, prompt, block

Before any session grants exist, every bash command resolves to exactly one outcome. Fail-closed is the default: anything unresolvable prompts. The agreed principles (`test/cases.test.ts` header — that file is the contract suite):

1. **Write → prompt** (carve-out: "safe creation" — `mkdir`/`touch`/`mktemp` — auto-allows)
2. **Read inside cwd → auto-allow**
3. **Code execution → prompt** (unless trusted script)
4. **Outside cwd → prompt (first time), remembered → auto-allow**
5. **Unsafe patterns → always prompt** — no session grant can override them (the prompt's command tiers are suppressed; dir grants stay offerable — they can't auto-allow the command)

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
- **opaque targets**: `$VAR`, `${VAR}`, `$(…)`, backticks in path position — flagged with an `<unresolved-var>` marker, never fast-allowed. (Exceptions: sed's script argument — see above; a read-only substitution body doesn't flag the segment itself, but its unbound vars in path position still do: `cat $(wc -c < $f)` prompts until `$f` is loop-bound to bare names. **D15 (2026-08-31)**: a ref the command itself pins is resolved, not flagged — a glob-tailed value binds to its directory (`F=/a/b; grep $F/*.js` → `/a/b`, a glob never matches `/`), and a `for` whose in-list is ALL literal paths names every word (`for d in /a /b; do ls "$d"; done` → both, concrete and grantable — a glob/$/`..` word keeps the marker); path-like literals in script bodies (heredoc bodies, multi-line literal args) join the path set fail-closed — the shell never touches them, but the script does)
- **unknown base**: a `cd` whose target can't be resolved (`cd $D`, globs, `cd -`) makes later relative paths unresolvable → `<unresolved-cwd>` marker
- **base access**: `cd` is navigation, not access — a path-aware segment with no target of its own (`cd /outside && ls`, `cd $D && find .`, `cd /outside && cat main.txt`, bare-name redirects like `cd /outside && echo x > out.txt`) operates on the base the cd left; that base is what gets approved

**Block** — never promptable, rejected with a reason:
- credential patterns anywhere in the raw command text (glob- and quote-aware): `.ssh`, `.gnupg`, `.env`, `.aws`, `id_rsa`, `*.pem`, … — plus a symlink-name check for bare tokens pointing at credentials. Shell comments and heredoc bodies are data, not operands: the scan is comment-aware (word-boundary `#`, quote/continuation-aware, 2026-08) so `# check the .ssh dir\nls` no longer blocks `ls` — a live credential operand on any line is still blocked
- paths matching `deniedPaths` (`config/path-rules.ts`)
- retry-loop guard: a command the user aborted within 60s is blocked instead of re-prompting

**The cd model (one rule to remember)**: `cd` performs no file access, so its target is never itself a path. What matters is (a) where later segments run — their relative paths re-resolve against the effective base (`cd /tmp && cat ./secret` approves `/tmp/secret`) — and (b) what they do with no resolvable target, which flags the base. Consequences: standalone `cd /outside` auto-allows (state dies with the process); `cd /nonexistent && …` auto-allows when the rest never runs; `cd $HOME/.ssh && ls` still **blocks** (the credential scan is raw-text, independent of the path set).

## Architecture

```
index.ts                          Extension entry — event registration, /dsp, /dspa, /dspat, /judge, /halter-decision-log
gate.ts                           Shared halter gate — decide → prompt → reject flow
rule-generator.ts                 Derives auto-allow rules from PromptData (on-demand)
├── handlers/                     Thin adapters (all call gate())
│   ├── index.ts                  Re-exports for handlers
│   ├── bash.ts                   Bash command interceptor
│   ├── file.ts                   File operation interceptor
│   └── tool.ts                   Plugin-gated tool calls (fail-closed dispatch by tool name)
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
│   ├── tmux-helpers.ts           Tmux-specific analysis
│   ├── obfuscation.ts            Obfuscation detection (variable indirection, base64, xargs tricks, etc.)
│   └── evaluators/               Per-domain risk evaluators (modular, pluggable)
│       ├── types.ts              RiskEvaluator interface definition
│       ├── builder.ts            Fluent builder for EvaluatorResult (eliminates boilerplate)
│       ├── disk-evaluator.ts     Disk/volume management commands (mount, mkfs, fdisk, etc.)
│       ├── git-evaluator.ts      git dangerous operations (reset --hard, push --force, etc.)
│       ├── shell-evaluator.ts    Subshells, heredocs, redirects, sed/perl, wrappers
│       ├── system-evaluator.ts   sudo, rm (incl. mass-deletion flags: home/system dirs, 100+ entries), chmod, chown, mv, cp, kill, shutdown, systemctl, dd
│       ├── tmux-evaluator.ts     tmux dangerous subcommands (run-shell, pipe-pane, etc.)
│       └── tool-evaluator.ts     find/fd/rg exec, kubectl, terraform, aws, gcloud, curl/wget pipe
├── decision-engine.ts            Pure policy dispatcher — async decide(request, store) → Decision
├── policies/                     Request-specific decision logic
│   ├── bash.ts                   Bash policy (runs bash-rules.ts pipeline)
│   ├── bash-rules.ts             Composable bash rules: RetryLoop → CredentialDeny → FastAllow → Safety → PromptFallback
│   └── file.ts                   File policy
├── plugins/                      Tool-plugin system (see *Tool plugins*)
│   ├── types.ts                  HalterPlugin contract + ToolGateRequest (exec/file/consent)
│   └── loader.ts                 Scans <ext>/halter/index.ts, validates, fail-closed slots
├── prompt-flow.ts                UI interaction loop — showPrompt(decision, ctx, store)
├── prompt-builder.ts             Pure formatter — PromptData → BuiltPrompt (title/body/options/labels)
├── prompts.ts                    Two-tier confirmation flow — native select + rejection-reason input
├── store.ts                      Auto-allow state — Store interface + singleton
├── widget.ts                     TUI rendering — the single halter status widget (mode lines pinned on top, one line each, + session rules)
├── dsp-mode.ts                   DSP mode toggle — bypass all halter checks (warning line on the status widget)
├── judge.ts                      Judge settings + the one-shot model call (stateless)
├── judge-prompt.ts               Judge packet, verdict, on-demand explanation
├── dspa-mode.ts                  /dspa toggle + session-health counters (auto-allow/reject/defer/declined/gate — compact widget line)
├── dspa-gate.ts                  Deterministic hard floor for /dspa auto-allow
├── session-context.ts            Reasoning-blind session context for the stage-2 intent pass
├── dspat-mode.ts                 /dspat toggle + agreement stats (status-widget line)
├── decision-log.ts               JSONL decision log (off by default)
├── halter-settings.ts            Owner of the halter namespace in settings-ext.json (stat-cached reads, corrupt → .bak + defaults)
├── renderers/                    Display formatting helpers
│   └── tmux.ts                   Tmux command formatting (strips boilerplate flags, structures output)
└── config/                       Focused configuration modules
    ├── index.ts                  Config re-exports, thresholds (ABORT_REMEMBER_MS, PROMPT_WARNING_THRESHOLD)
    ├── bash-patterns.ts          Allowed commands, write handlers, dangerous flags, wrapper commands
    ├── path-rules.ts             Path allow/deny rules (deniedPaths, warnPaths, allowedReadPaths, allowedWritePaths)
    ├── dangerous-patterns.ts     Dangerous command/context regex patterns
    ├── trusted-scripts.ts        Trusted packages (TRUSTED_PACKAGES), trusted script path checks
    └── logging.ts                Decision-log compile-time default (DECISION_LOG_ENABLED)
```

### Key seams

- **Gate** (`gate.ts`) — single shared flow for all handlers. Handlers only provide request construction and rejection formatting
- **Store** — injected into `decide()` and `showPrompt()`. Runtime singleton
- **Decision Engine** — async pure function, no UI dependency. All policy logic concentrated here
- **Rule Generator** (`rule-generator.ts`) — derives auto-allow rules from `PromptData` on-demand. Decouples policy decision from rule specifics
- **Bash Parser** — lazy-loaded tree-sitter WASM. Public API: `parseCommand(command, cwd)` returns `{ segments, paths, opaque, assignments, hasParseError }` in one call
- **Evaluators** — modular risk evaluators in `analysis/evaluators/`. Each implements `RiskEvaluator` interface. Adding new analyzers is a drop-in file
- **Segment Helpers** (`segment-helpers.ts`) — shared utilities: `checkStageDanger()`, `isGitDangerous()`, `isWrapperRunningWrite()`, `getCommandSignature()`, `hasWriteRedirect()`, `isFindExecWrite()`, `isFdExecWrite()`, `isRgPreWrite()`
- **Prompt Builder** — pure function. All prompt wording lives in one module (prompt labels + the decision-log why-summary). Truncates long commands to 20 lines
- **Prompt UI** (`prompts.ts`) — two-tier selection flow on native `ctx.ui.select` / `ctx.ui.input`; the only module that displays the confirmation prompt
- **Judge** (`judge.ts`, `judge-prompt.ts`) — one-shot model call, two dspa stages: stage 1 stateless (LRU-cached on the operation); stage 2 adds the session context and runs uncached (its context includes the just-blocked op → a hit is impossible). Verdicts are advisory: display-only by default, auto-allow only behind `/dspa`'s hard floor
- **DSP floor** (`dspa-gate.ts`) — deterministic hard floor for `/dspa`: parse errors, obscured command positions, credential patterns, untrusted fetchable package run forms (`npx <pkg>`, `uvx`, `bunx`, `npm exec`, `pnpm dlx`, `bun x` — stop with `untrusted package (…)`; the judge's verdict is shown advisory and the prompt offers a session `Trust: <pkg>` grant, D10), network egress (fetch forms + raw egress; loopback-only curl/wget — every URL loopback-hosted — is judgeable, all other egress stops are advisory: verdict in the prompt, stop stands, never auto-allowed — D14; local run forms like `npm run`/`uv run`/`bun <script>` are judgeable — D8), full-filesystem scans (`find /`, `grep -rn x /` — dedicated reason, D9), paths outside the manual bar (the bar manual mode auto-allows — D11; unbound paths are resolved from the command when possible; unresolvable locations stop, with the verdict advisory — D7/D11), the rm carve-out (explicit `/tmp` scratch rm is judgeable — D8/D11). Everything else is judgeable — including all content-bearing file-write auto-alls and granted script executions (D3/D11: the location is user-trusted, the content is not). Judges the analysis carried on the prompt — one tree-sitter parse per decision
- **Session context** (`session-context.ts`) — the reasoning-blind `## Session context` section for stage 2 (user messages + tool-call digest + grants; never agent prose or tool outputs — a compromised agent can't talk the approver into compliance)
- **Settings** (`halter-settings.ts`) — sole owner of the `halter` namespace in `~/.pi/agent/settings-ext.json` (judge settings + log toggle): mtime+size stat cache, corrupt file → `.bak` + defaults, namespace merge writes, defaults materialized on first read
- **Decision log** (`decision-log.ts`) — fire-and-forget JSONL of gate decisions (off by default; see *Configuration*)

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
| `gate.ts` | Shared decide → prompt → reject flow |
| `rule-generator.ts` | Derive auto-allow rules from data |
| `prompt-flow.ts` | Prompt orchestration |
| `policies/bash.ts` | Bash policy entry point |
| `policies/bash-rules.ts` | Composable bash rules |
| `analysis/command-analysis.ts` | Command analysis orchestrator |
| `analysis/segment-analysis.ts` | Segment safety analysis |
| `analysis/segment-helpers.ts` | Shared analysis utilities |
| `analysis/bash-parser.ts` | tree-sitter parser wrapper, `parseCommand()` API |
| `prompt-builder.ts` | Build prompt content |
| `prompts.ts` | Two-tier confirmation UI |
| `dspa-gate.ts` | Deterministic hard floor for /dspa auto-allow |
| `session-context.ts` | Reasoning-blind session context (stage-2 intent pass) |
| `judge-prompt.ts` | Judge packet + verdict (stateless model call) |
| `decision-log.ts` | JSONL decision log (off by default) |
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

### Decision log

**Off by default.** When enabled, every decision the gate makes is appended to a JSONL log — one line per tool call, `auto-allow`, `prompt` (with a one-line why), and `block` (with the reason), plus the command/path and cwd. (`deny` is a reserved kind for the planned judge-denial flow — an op the judge rejects returned to the agent instead of a prompt; not emitted yet.) It exists to measure blast radius: after changing gate code, diff what now prompts vs. what used to auto-allow; or mine repeatedly-prompting commands into contract rows. The log records what the *gate* decided — user approvals/rejections of prompts are not logged. Lines made under a judge mode carry a `mode` tag — `dspa` (a prompt that fell through the judge auto-allow, or the judge auto-allow itself) or `dspat` (a prompt shown with the verdict) — so judge-mode decisions can be debugged separately from the manual regime; untagged lines are manual. (A regime marker, not verdict content: verdicts stay session-scoped, and the dsp bypass regime never reaches the log — the gate is skipped.)

- Enable: `/halter-decision-log [on|off]` (bare = toggle) — persisted in the `halter` namespace of `~/.pi/agent/settings-ext.json` (the shared extension settings file; pi owns `settings.json`). Compile-time default: `DECISION_LOG_ENABLED` in `config/logging.ts` (false)
- Transient override: `HALTER_DECISION_LOG=<path>` (enables at that path); `HALTER_DECISION_LOG=off` forces off
- Path: `<extension dir>/.log/decisions.jsonl` (gitignored); rotates to `decisions.jsonl.1` at 5 MiB — a few KB per day, SSD wear negligible (writes coalesce into 16 KiB pages)
- A companion log, `.log/unresolved.jsonl` (same toggle, same rotation; `HALTER_DECISION_LOG=off` disables it too), records the fate of each path token static analysis couldn't bind: `outcome: prompted | gate-stop | auto-allowed`, the LLM resolver's suggested dirs, the user's decision, and whether the token became a confirmed resolution (dspa-gate.ts then resolves it deterministically — no LLM). Convergence is visible as the same token flipping from `prompted` to `auto-allowed` across runs (docs/dspa-redesign.md, D12)
- The log reflects the gate code that was *running* when each line was written. After a `/reload` of changed gate code (or a crash/reload loop), delete `.log/decisions.jsonl` before aggregating — decisions made by the old code would pollute top-N prompt reasons and auto-allow diffs
- Logging is fire-and-forget: disk problems never affect a decision (and a throw here would surface as a fail-closed block)

**Debugging judge modes from the log** — the `mode` tag splits each regime out of the manual noise. `tools/log-inspect.mjs` (zero-dep, node ≥ 18) does the recurring extractions without jq: `node tools/log-inspect.mjs summary` (counts, top prompt reasons, all blocks, anomaly counts), `audit` (test-fixture pollution, mixed-kind same target, phantom root paths, outside-base labels that name the target's own dir, config-allowed writes the dspa floor never saw, repeated prompts, duplicate lines), `list --grep X --kind K --mode M --tool T`, `dspa` (judge-regime entries with stop tags), `dspa --paths` (D13 stage-2 path-report mismatches — the parser-gap mining view), `stats` (per-target counts + span), `show N` (full JSON). `--all` includes the rotated `.1`.

The raw jq one-liners, for ad-hoc shapes:

```
# what /dspa auto-allowed (the approving model is in .reason)
jq -r 'select(.mode=="dspa" and .kind=="auto-allow") | .target' .log/decisions.jsonl
# what /dspa let fall through to a prompt — top risk summaries
jq -r 'select(.mode=="dspa" and .kind=="prompt") | .reason' .log/decisions.jsonl | sort | uniq -c | sort -rn | head
# /dspat shadow prompts (verdict shown, human decided)
jq -r 'select(.mode=="dspat" and .kind=="prompt") | .target' .log/decisions.jsonl
# manual-regime prompts (no judge mode active)
jq -r 'select(.kind=="prompt" and .mode==null) | .reason' .log/decisions.jsonl | sort | uniq -c | sort -rn | head
```
The dspa prompt line additionally carries a `dspa` stop-tag — which layer stopped the auto-allow: `gate: <reason>` (the deterministic floor; code-produced), `judge: declined (stage 2)` (the intent pass rendered a final verdict that did not auto-allow), `judge: stage 2 failed` (only the stateless verdict rendered), `judge: <note>` (no verdict at all). And the dspa auto-allow line's `reason` carries the approving stage + model (`dspa: judge approved (stage 2, <model>)`). A line whose final verdict is stage 2 additionally carries `judgePaths` / `judgePathMisses` (D13) — the judge's sanitized path report and the paths the floor never saw: model output, but diagnostic only — nothing in the gate reads it back; it exists to be mined (`dspa --paths`). Still no verdict *content* — verdicts stay session-scoped.

### Iterating policy from the log (debug/fix cycle)

The log is the *input* to a log-driven fix loop, not just a measurement: the suite proves correctness, the log aims the next test.

1. **Enable** — `/halter-decision-log on`, then use pi normally for a while (growth is a few KB/day).
2. **Aggregate** — top prompt reasons, and the full auto-allow set:
   ```
   jq -r 'select(.kind=="prompt") | .reason' .log/decisions.jsonl | sort | uniq -c | sort -rn | head
   jq -r 'select(.kind=="auto-allow") | .target' .log/decisions.jsonl | sort -u
   jq -r 'select(.mode != null) | [.mode, .kind, .reason // "judge/auto-allow"] | @tsv' .log/decisions.jsonl | sort | uniq -c
   ```
3. **Triage** — prompt lines split into by-design (outside-cwd paths, first-encounter commands, genuinely risky operators), false positives (analysis misreading safe syntax), and noise (risk reasons, not gates). For bypass hunting read the *auto-allow* set instead: entries with operators, quotes, wrappers, or globs that auto-allowed are the ones worth a second look — that is the direction that matters.
4. **Reproduce** — `npx tsx tools/probe.mts '<cmd>'` shows the first-encounter decision with its why; drop to `analyzeCommand` / `parseCommand` to see extracted paths and markers.
5. **Fix** — every fix is a code change *plus* a contract row: `test/cases-data.ts` for pass/prompt/block decisions, `test/cwd-threading.test.ts` for cd/var/path threading. The row encodes the observed command with its expected decision, so the same input can never silently regress.
6. **Prove** — `npx vitest run` (full suite) plus `npm run typecheck` (strict tsc over source *and* tests — test files are no longer excluded), then confirm the flip with the probe: a fixed false positive now `ALLOW`s, a plugged bypass now `PROMPT`s or `BLOCK`s — and the new contract row keeps it there.
7. **Reload** — `/reload` in pi (or restart). Never exercise changed extension code in a running pi session before reloading. Once new gate code is loaded, delete `.log/decisions.jsonl` so the next cycle only measures the new behavior.

## Testing

- **Decision engine** — async, no UI dependency. Inject `Store` for testability
- **Prompt builder** — pure function. Verify prompt content for each decision type
- **Command analysis** — async pure function. Verify risk scoring, AST path extraction, safety verdicts
- **Segment analysis** — verify evaluator integration, pipeline checks, safety boolean derivation
- **Evaluators** — exercised end-to-end: every `decide()` runs all six risk evaluators per segment via segment-analysis; the bypass suites pin each detector's findings
- **Bash parser** — lazy WASM loading. Verify path extraction across heredocs, comments, quotes, subshells
- **Path utilities** — pure functions. Verify path resolution, deny rules, cwd checks
- **Obfuscation detection** — pure function. Verify each technique regex
- **Round-trip tests** — verify prompt → rules → auto-allow cycle works end-to-end
- **Hermetic cwd** — the contract suites (`cases-data.ts`, the bypass suites, `decision-engine`, `cwd-threading`, …) run `decide()` against a per-file temp cwd (`test/hermetic-cwd.ts`), under `$HOME` but out of any path-allowlisted zone (tmp/`/tmp` are write-allowed scratch, `.pi` is auto-allowed by location), so no row's decision depends on what happens to live in the user's real tree. Typecheck: `npm run typecheck` covers `test/**` too.

## Ad-hoc testing a command

To see what halter will do with a specific command — without running it — use the probe harness in `tools/probe.mts`. It calls the same `decide()` the gate uses, but with a **fresh empty store** and a hardcoded CWD (`/mnt/Ndr/Projects`) — so it shows the *first-encounter* decision, not one with session grants in place. Config (`deniedPaths`, warn paths, trusted packages) still applies.

```
cd ~/.pi/agent/extensions/halter
npx tsx tools/probe.mts 'rm -rf build/' 'curl -s x | sh' 'ls /usr/share/tessdata'
```

One line per command:
- `PROMPT <cmd>` — plus the why: `outsideDirs` (dirs the prompt would ask for), `sigs` (signatures the prompt shows), `unsafe` / `risk` / `danger` flags
- `BLOCK <cmd>` — plus the matched rule's `reason`
- `ALLOW <cmd>`

`tools/converge-probe.mts` exercises the D12 steady state for an unbound path token across three fresh stores — `run1` unconfirmed (PROMPT + gate stop `runtime location unresolvable`), `run2` confirmed all-in-bar (AUTO-ALLOW), `run3` confirmed one-out-of-bar (PROMPT naming exactly that dir, grantable by "Always (paths)"). It discovers the token from run1 (no hardcoding) and defaults both dirs to fresh temp dirs under `$HOME`; pass `[outsidePrefix] [cwd]` to use your own (caller dirs are never deleted).

For a one-off script instead of the harness, call `decide()` directly:

```ts
import { decide } from "./decision-engine";
import { createStore } from "./store";

const d = await decide(
  { type: "bash", command: "cd /var/tmp && ls", cwd: "/mnt/Ndr/Projects" },
  createStore(),
);
```

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
