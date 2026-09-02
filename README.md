# Halter (pi extension)

A halter for pi tool calls. Intercepts `bash` and `read`/`write`/`edit` calls, auto-allowing safe operations and prompting the user for anything risky. Tool extensions can additionally opt in through a small **gate plugin** (`<ext>/halter/`) — halter then gates their calls with the same prompts, grants, judge, and dspa machinery.

## Features

- **Bash commands** — auto-allows simple read-only commands (`ls`, `grep`, `find`, etc.); prompts for dangerous operations (`rm`, `sudo`, `curl | bash`, etc.); blocks denied credential paths (`.ssh`, `.gnupg`, etc.) and prompts for warned paths (`.env`, `.aws`, etc.) even via `cat`/`grep`
- **File access** — auto-allows reads inside cwd, trusted paths, and nonexistent paths (a read can only ENOENT — nothing can leak); prompts for paths outside cwd, denied names (`.env`, `.ssh`, etc.)
- **Opaque path resolution** — tokens static analysis cannot bind (`$VAR`, `$(…)`, globs over unknown bases) are listed as unresolved in the prompt; with the judge enabled it suggests concrete dirs, and a user-confirmed suggestion becomes a binding deterministic resolution (the token stops prompting)
- **Tool plugins** — any tool ext that ships `<ext>/halter/index.ts` is gated: the plugin classifies calls as `exec` (script payload → judge/dspa), `file` (target path → outside-cwd warning), or `consent` (per-kind session consent); discovery calls pass ungated; a broken plugin blocks its tool fail-closed
- **Auto-allow** — "Always" option grants session-scoped permission; status widget shows active allowances
- **Retry-loop prevention** — recently-aborted commands are auto-blocked for 60 seconds
- **Prompt frequency warning** — after 20 prompts, warns the user to use "Always" to reduce noise
- **No-UI fallback** — auto-blocks when no UI is available
- **DSP mode** — `/dsp` command toggles "Dangerously Skip Permissions" to bypass all checks (with a persistent warning line pinned on top of the status widget)
- **Judge modes** — `/dspa` auto-allows operations that pass a deterministic hard floor *and* a two-stage LLM-judge verdict (stateless pass, then an intent pass with reasoning-blind session context) (visible toast); when a judge call fails (model unreachable, or no verdict within the deadline), a repeatable "Judge again" re-runs the intent pass; `/dspat` shows the judge's verdict in every bash prompt and records agreement stats; both fail toward the prompt. The modes are one machine — **manual / dspa / dspat / dsp**: enabling one leaves the others off (switching resets the left judge mode's session stats)
- **Judge settings** — `/judge` (bare = show; `on|off`, `model <provider/id|session>`, `thinking <level>`, `timeout <ms>`) — persisted in the `halter` namespace of `~/.pi/agent/settings-ext.json`
- **Decision log** — `/halter-decision-log` records every gate decision to a JSONL file (see *Configuration → Decision log*)

## How It Works

Every intercepted tool call flows through five stages:

```
Handler → Gate → Decision Engine → Prompt Flow → Rule Generator
```

1. **Handler** — validates the event, builds a request, passes it to `gate()`
2. **Gate** — shared flow: decides, applies the dspa regime (auto-allow→prompt conversions, hard floor, two-stage judge), writes the decision log line, then routes auto-allow / block / prompt
3. **Decision Engine** — async policy dispatcher (bash rule pipeline, file checks) returning `auto-allow`, `block`, or `prompt` with `PromptData`
4. **Prompt Flow** — two-tier confirmation UI; on "Always", the Rule Generator derives the session grant
5. **Rule Generator** — grant derivation, on-demand (only when the user picks "Always")

The full behavior contract — pass/prompt/block semantics, the cd model, the
four regimes, the hard floor, the judge, grants, trusted code — is specified in
[docs/architecture.md](docs/architecture.md). The executable contract is
`test/cases-data.ts`; decision rationale for the judge regimes is in
`docs/dspa-redesign.md`.

### The five principles (manual regime)

1. **Write → prompt** (carve-out: "safe creation" — `mkdir`/`touch`/`mktemp` — auto-allows)
2. **Read inside cwd → auto-allow**
3. **Code execution → prompt** (unless trusted script)
4. **Outside cwd → prompt (first time), remembered → auto-allow**
5. **Unsafe patterns → always prompt** — no session grant can override them

**The cd model (one rule to remember)**: `cd` performs no file access, so its
target is never itself a path. What matters is where later segments run
(relative paths re-resolve against the effective base) and what they do with no
resolvable target (that names the base). Standalone `cd /outside`
auto-allows; `cd $HOME/.ssh && ls` still blocks (the credential scan is
raw-text, independent of the path set).

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

The loader scans the extensions root at halter load and keys slots by the
GATED TOOL's name. The plugin only CLASSIFIES — prompts, grants, judge, dspa,
decision log, and widget all live in the core. Grant scopes, payload identity,
dspa applicability, and the fail-closed rules:
[docs/architecture.md → Tool plugin contract](docs/architecture.md#tool-plugin-contract).

### Two-tier confirmation

"Always" takes a second confirmation before the session grant is made. The
filesystem root is never an Always grant: a root-only path prompt offers no dir
tier, mixed prompts drop `/`, and a file prompt's dir umbrella stops before root.

### Regimes

`manual` / `dspa` / `dspat` / `dsp` are one machine — enabling one leaves the
others off (leaving a judge mode resets its session stats; enabling `/dsp`
always confirms). Semantics of each regime, including the hard floor, the
two-stage judge, and the content-bearing auto-allow conversions:
[docs/architecture.md → The four regimes](docs/architecture.md#the-four-regimes).

## Architecture

[docs/architecture.md](docs/architecture.md) — module map (one line per module),
the end-to-end request flow, and every seam: the gate, the store, the decision
engine, the evaluators, the prompt builder, the judge family, the dspa floor,
settings, and the decision log.

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
import { decide } from "./decide/engine";
import { createStore } from "./gate/store";

const d = await decide(
  { type: "bash", command: "cd /var/tmp && ls", cwd: "/mnt/Ndr/Projects" },
  createStore(),
);
```

For analysis-level debugging (paths, markers, safety verdicts) use `analyzeCommand(cmd, cwd)` from `analysis/command-analysis` instead. `test/cwd-threading.test.ts` is the contract file for cd/var behavior; `test/cases.test.ts` is the curated pass/prompt/block suite.

## Trusted code

- **Skills dir** — scripts resolving into `~/.pi/agent/skills/` auto-allow: the directory is treated as user-curated. Three invocation forms qualify (interpreter + script, shell interpreter + script, direct exec); `-c`/`--command` is never trusted; trust covers the invocation only, never shell operators around it (unsafe pipe stages, write redirects, command substitution still prompt).
- **`uv run --with`** — trusts the invocation only when every `--with` package is in `TRUSTED_PACKAGES` (edit `config/trusted-scripts.ts`; lowercase, no extras) and the script is in a trusted dir. `--with-requirements`/`--with-editable` sources must be trusted too (they bypass the package allowlist).

Edge cases and the exact matching semantics: [docs/architecture.md](docs/architecture.md#trusted-scripts-and-packages).

## Dependencies

- `tree-sitter-bash` + `web-tree-sitter` — full bash AST parsing for segmentation, path extraction, operator detection, and subshell detection (handles heredocs, comments, quotes, subshells, and redirects correctly)
- No external dependencies for forwarding — uses only `node:fs` and `node:path` for file-based IPC
