# Halter architecture

What halter does, end to end: which tool calls it sees, how each resolves to
auto-allow / prompt / block, and where every piece lives. The executable
contract is `test/cases-data.ts` (the curated pass/prompt/block rows) plus the
bypass and threading suites; this document is the spec they implement.
Decision rationale for the judge regimes lives in `docs/dspa-redesign.md`.

## Terms

| Term | Meaning |
|------|---------|
| regime | One of the four mutually exclusive modes: `manual`, `dspa`, `dspat`, `dsp`. Enabling one disables the others. |
| floor | The deterministic hard gate in `gate/dspa-gate.ts`. Code only, no model. The only thing that may stop `/dspa` from asking the judge. |
| judgeable | An operation the floor lets through to the two-stage judge. |
| bar | The manual bar: exactly the set of paths manual mode auto-allows (cwd + session grants + config-allowed + trusted scripts). Since D11 the floor's bar IS the manual bar. |
| opaque ref | A path token static analysis cannot bind: `$VAR`, `${VAR}`, `$(…)`, backticks in path position, a glob over an unknown base. Marked, never fast-allowed, resolved via D12 convergence when the user confirms. |
| unknown base | A `cd` whose target does not resolve; later relative paths in that segment chain get the `<unresolved-cwd>` marker. |
| fetchable form | A package-manager run form that fetches from a registry: `npx <pkg>`, `uvx`, `npm exec`, `pnpm dlx`, `bun x`. Gated by per-package trust (D10). |
| run form | A package-manager form that executes local code: `npm run`, `uv run`, `bun <script>`, `python <file>`. Judgeable, never fetch-gated (D8). |
| grant | A session-scoped "Always" outcome: command signature, path (read or read+write), or trusted package. |
| fall-through | A prompt shown because the dspa auto-allow attempt did not complete: floor stop or judge verdict/absence. Carries which layer stopped it. |
| packet | The judge's entire input for one operation: command, analysis digest, script content. Untrimmed (D11). |

## Request flow

```
pi tool call
  → handlers/        validate, build request, call gate()
  → gate/gate.ts     orchestrate (below)
      → decide/      engine → policy → bash rules / file policy → analysis/
      → gate/        dspa conversions, dspa auto-allow attempt (floor + judge)
      → ui/          prompt flow on prompt decisions
      → decide/      rule generator on "Always"
      → gate/        decision log (fire-and-forget)
```

1. **Handler** (`handlers/`) builds a `PermissionRequest` (bash, file, or
   plugin-classified tool) and calls `gate()`. Handlers add no policy.
2. **Gate** (`gate/gate.ts`) decides, applies the dspa regime conversions and
   auto-allow attempt, writes the decision log line, then routes: auto-allow
   returns silently; block returns the reason; prompt goes to the prompt flow;
   no UI blocks. `gateDecide` wraps `decide()` in the fail-closed guard: any
   internal analysis error blocks, never allows.
3. **Decision engine** (`decide/engine.ts`) is an async pure dispatcher:
   routes by request type, returns `{kind: auto-allow | block | prompt}`.
   Prompt decisions carry `PromptData` (what the prompt shows and what
   "Always" would grant).
4. **Policies** run the rule pipeline (bash) or the file checks. Bash rule
   order is fixed: `RetryLoop → CredentialDeny → FastAllow → Safety →
   PromptFallback`. First matching rule decides.
5. **Analysis** (`analysis/`) is the AST layer: tree-sitter bash parse (lazy
   WASM), segment splitting, cwd threading, variable resolution, path
   extraction, obfuscation detection, and the six per-domain risk evaluators.
6. **Prompt flow** (`ui/`) renders the two-tier confirmation. "Always" runs
   the second confirmation tier, then the rule generator derives the grant
   into the session store.

## The four regimes

| | auto-allow | prompt | extra |
|--|-----------|--------|-------|
| **manual** (default) | rule pipeline pass | everything else | "Always" grants, session rules |
| **dspa** | manual pass **plus** judge auto-allows that clear the floor | fall-throughs (floor stop or judge decline/deny/defer/no-verdict) | two-stage judge, content-bearing auto-allows are judged too |
| **dspat** | manual pass (identical to manual) | same prompts as manual, plus a `💭 Judge:` verdict block | agreement stats (verdict vs user choice) |
| **dsp** | everything (gate skipped) | none | pinned warning line on the widget; enabling always confirms |

Mode switching resets the leaving judge mode's session stats. The regimes are
one machine in `modes/`; `index.ts` enforces exclusivity at the commands
(`/dsp`, `/dspa`, `/dspat`).

## Manual regime (the contract)

The five principles, from the header of `test/cases.test.ts`:

1. Write → prompt (carve-out: safe creation `mkdir`/`touch`/`mktemp` auto-allows).
2. Read inside cwd → auto-allow.
3. Code execution → prompt (unless trusted script).
4. Outside cwd → prompt the first time, remembered (grant) → auto-allow.
5. Unsafe patterns → always prompt; no session grant overrides them (the
   prompt's command tiers are suppressed; dir grants stay offerable).

**Pass (auto-allow)** requires all of:
- every segment's command is allowlisted (`config/bash-patterns.ts`) or a
  trusted-script invocation. The allowlist is mostly read-only inspection but
  deliberately includes first-time writes: safe creation, non-destructive git
  (`add`, `commit`, `checkout`, `branch`, `merge`, `stash`);
- every resolved path stays inside the session cwd, `allowedReadPaths`,
  `allowedWritePaths`, or the trusted skills dir;
- no write operation or dangerous flag: write redirects, `tee`/`cp`/`mv`/`rm`/
  `truncate`, `sed -i`, `sort -o`, `find -delete`/`-exec`, any `git push`,
  destructive git, `npm install`, script execution, wrappers running writes.

**Prompt** comes in three flavors:
- *First time*: a path resolves outside cwd/allowed dirs (grant the dir); a
  safe command is not allowlisted (grant the signature); a `warnPaths` match
  such as `.env.*`; a bare-name symlink in cwd that resolves outside it.
- *Every time* (no "Always" offered, principle 5): write redirects anywhere;
  write commands not in the allowlist; code execution; destructive or remote
  git (any `git push`, `git rm`, `git clean -f`, `git reset --hard`, ...).
- *Unresolvable*: opaque refs (`<unresolved-var>`), unknown base
  (`<unresolved-cwd>`), or base access (a path-aware segment with no target of
  its own after a `cd` names the cd's destination base as the location to
  approve).

**Block** (never promptable):
- credential patterns anywhere in the raw command text, glob- and quote-aware,
  comment-aware: `.ssh`, `.gnupg`, `.env`, `.aws`, `id_rsa`, `*.pem`, ... plus
  bare-token symlink checks;
- `deniedPaths` matches;
- retry-loop guard: a command aborted within 60 s is blocked, not re-prompted.

### The cd model

`cd` performs no file access; its target is never itself a path. Two
consequences: (a) later segments run against the effective base, so
`cd /tmp && cat ./secret` approves `/tmp/secret`; (b) a path-aware segment
with no target of its own (`cd /outside && ls`) operates on the base the cd
left, and that base is what gets approved. Standalone `cd /outside`
auto-allows (state dies with the process); `cd /nonexistent && …` auto-allows
when the rest never runs; `cd $HOME/.ssh && ls` still blocks (the credential
scan is raw-text, independent of the path set).

### Command substitution

A `$(…)`/backtick/`<(...)` body made of read-only commands (the
unconditionally-safe set plus `grep`/`rg`/`fd`/`ag`) with no write redirect,
backgrounding, or multi-line list is data production, not code execution.
The body's own paths still get path checks; nested substitutions classify
individually; any other body keeps the always-prompt flag. `find` and
wrappers are excluded from the body set.

### Sed grammar

`sed [flags] script [files…]`: the first non-flag arg (and `-e` values) is
not a file and is skipped by path analysis; file-position args keep the
opaque marker; a bare literal path in script position stays path-checked.

### D15 parser resolutions

Refs the command itself pins resolve instead of flagging:
- a glob-tailed value binds to its directory (`F=/a/b; grep $F/*.js` → `/a/b`;
  a glob never matches `/`); braces stay sentinel (several names);
- an all-literal `for` in-list names every word concretely (symlink words
  name their real target; still outside, never exempt);
- an embedded loop ref over an all-literal in-list substitutes each word
  textually (one loop-bound `$var`, expansion-free static part);
- path-like literals in script bodies (heredoc bodies, multi-line literal
  args) join the path set fail-closed.

### File policy

- reads: inside cwd / allowed / nonexistent paths auto-allow (a read can only
  ENOENT; nothing leaks). Warned paths prompt even for reads; denied paths
  block.
- writes: outside cwd prompts (dir grant); denied blocks; warn prompts.
- the filesystem root is never an Always grant: a root-only path prompt offers
  no dir tier, mixed prompts drop `/`, and a file prompt's dir umbrella stops
  before root.

### Trusted scripts and packages

Scripts resolving into `~/.pi/agent/skills/` auto-allow in three forms
(interpreter + script; shell interpreter + script, first non-flag token only;
direct exec). `-c`/`--command` is never trusted. Trust covers the invocation
only: unsafe pipe stages, write redirects, and command substitution around a
trusted script still prompt. `uv run --with <pkg>` trusts the invocation only
when every `--with` package is in `TRUSTED_PACKAGES` and the script is in a
trusted dir (`--with-requirements`/`--with-editable` sources must be trusted
too; they bypass the package allowlist).

### Grants and two-tier confirmation

| Category | Scope | Granted by |
|----------|-------|------------|
| Bash signature | command + flags | "Always" on a bash prompt |
| Path (R) | dir/file read | "Always" on a read prompt |
| Path (R/W) | dir/file read+write (implies read) | "Always" on a write prompt |
| Trusted package | one package across fetchable run forms | "Trust" on any prompt carrying an untrusted fetchable form; the only grant for those forms (all modes, D10) |

"Always" always takes a second confirmation tier. Fetchable signatures get no
exact-form option: a signature grant would short-circuit `decide()` before the
floor is consulted, which is how `npx *` once disabled the floor
session-wide.

## dspa regime

Before any prompt, `gate/fallthrough.ts` attempts the auto-allow:

1. **Floor** (`gate/dspa-gate.ts`, code only). Stops, by class:
   - parse error (fail-closed);
   - obscured command position (obfuscation detection hit);
   - credential pattern;
   - untrusted **fetchable** run form (D10) → stop names the package; the
     prompt offers `Trust: <pkg> (session)`;
   - network egress: fetch forms and raw egress stop; **loopback-only
     curl/wget is judgeable** (every URL in the command is 127.0.0.0/8, ::1,
     or localhost, D14); all other egress stops are **advisory**: the judge
     still runs, the verdict renders in the prompt, the stop stands (egress
     never auto-allows);
   - full-filesystem scans (`find /`, `grep -rn x /`) get a dedicated stop (D9);
   - paths outside the manual bar (D11). Unbound locations are first resolved
     from the command itself (local assignments, every candidate base of an
     `||`-ambiguous cd); a location it cannot resolve is a stop, never an
     auto-allow (D7).
   - the rm carve-out: explicit `/tmp` scratch targets are judgeable (D8/D11);
     computed/glob rm and `rm /etc/hosts` still stop.
2. **Stage 1** (stateless, LRU-cached on the operation): the packet's static
   analysis is the whole input. `approve` + `low` auto-allows.
3. **Stage 2** (reasoning-blind session context, uncached): runs when stage 1
   did not auto-allow. `approve` + `low|medium` auto-allows. Its verdict is
   final.

`approve` + `high`, `deny`, `defer`, and any no-verdict outcome prompt.

**"Judge again" retry.** When the floor passed but the judge call itself
failed — the model was unreachable, or a stage produced no verdict within
its deadline (the carried verdict is stage 1's or absent) — the prompt
offers a repeatable `Judge again` option: a fresh, uncached stage-2 call
(the model may have been busy loading). An approving verdict (low/medium
risk) auto-allows with the normal dspa side effects; anything else re-shows
the prompt with the new verdict (or a failure note). Legitimate stage-2
verdicts (DEFER, REJECT, approve above authority) are judgments, not infra
failures — never re-judged (Yes/No are the user's tools). Not offered when
the judge is off (a choice, not a transient failure), after a floor stop
(the deterministic layer cannot be re-judged), or without the permission
request.
Scope-class floor stops (outside bar, unresolvable, untrusted package) run
the judge anyway and render the verdict advisory; danger-class stops (parse,
obscured, credential, egress) stay bare. Auto-allowed operations toast.

**Content-bearing manual auto-allows are judged too (D3/D11).** In dspa, a
file WRITE that manual mode would auto-allow (grants, config-allowed,
project-pi) is re-decided with `judgeWriteAutoAllows`; every write auto-allow
fast path converts to the judgeable path with its full content in the packet
(reads are never judged). A bash auto-allow that runs a reviewable script
payload (granted interpreter execution) converts the same way: the manual
prompt is synthesized from the analysis so the shared floor → judge path
handles it uniformly. Judge off/invalid → no conversion; the manual
auto-allow stands.

**Stop classification and counters.** Every fall-through records one stop in
the session-health counters, model-scoped (a new non-null model resets; a
null-model floor stop never resets): `a` auto-allowed, `g` floor stop, `r`
final reject, `c` approve-above-authority or declined, `d` defer or no-verdict
fail-safe bucket. The widget renders non-zero counts in `g r c d` order after
`a`.

**Path report (D13).** A stage-2 verdict also reports the paths the operation
touches; the gate cross-checks them against the floor's own knowledge and
logs mismatches as `judgePathMisses` (diagnostic only; nothing in the gate reads
model output back). Mine with `tools/log-inspect.mjs dspa --paths`.

**D4 (denials to the agent) is on HOLD**: the planned behavior where a
stage-2 `deny` returns to the agent as a good-faith block (escalating to a
prompt after 3 consecutive denials, session degrade after 20 total) is
designed and documented in `docs/dspa-redesign.md` D4 but unimplemented,
pending more observed data.

## dspat regime

Identical to manual plus a `💭 Judge:` block in every bash prompt (explanation
+ `→ suggests: APPROVE|REJECT|DEFER (<risk>)`). The user's choice is recorded
against the verdict as session agreement stats (widget line). No auto-allow.
An on-demand `💭 Explain` prompt option runs the judge in any regime without
recording agreement stats (the human picks when to consult, so the subset is
self-selected).

## dsp regime

`/dsp` bypasses the gate entirely (the gate is skipped, so the decision log
never sees these calls). Enabling always takes a confirmation; a cancelled
confirmation keeps the current mode. A warning line stays pinned on the
widget while active.

## The judge

One one-shot model call per stage. The packet is the judge's entire input:
command (capped 4000), analysis digest, and, when the operation executes an
untrusted local script, the script content as fenced untrusted data (file 8000,
script 150 lines / 64 KB; overflow → defer → prompt; only MCP-style args take
head-cuts). No conversation history reaches stage 1. Stage 2 adds a
reasoning-blind session context: the user's last messages (4 / 3000 chars
verbatim) plus a 10-line tool-call digest (≤120 chars/line) plus session
grants. Agent prose and tool outputs never appear: a compromised agent cannot
talk the approver into compliance.

**Timeouts are two deadlines, not one.** `timeout` (default 8000ms) is a
FIRST-TOKEN deadline: the streaming call is aborted if the model produces no
output (any event past the stream's `start` handshake) within that window — a
dead or saturated model fails fast. The whole response is separately capped
(`JUDGE_RESPONSE_CAP_MS`, 60s), so a responsive model can finish a long
verdict; a call that starts promptly but never finishes still aborts. Stage 2
gets `STAGE2_TIMEOUT_FACTOR` (3×) the base first-token window: its larger
packet has a slower prefill on local models, and an unmet stage-2 deadline is
what turns an approvable operation into a "stage 2 unavailable" fall-through.

Any failure (model unresolved, auth, timeout, malformed reply) resolves to
no verdict, and the prompt shows exactly what it would have shown without the
judge. The judge never alters a decision on its own: display-only by default,
auto-allow only behind the floor.

Settings (`/judge`: bare = show; `on|off`, `model <provider/id|session>`,
`thinking <level>`, `timeout <ms>` — first-token deadline, see above) persist
in the `halter` namespace of
`~/.pi/agent/settings-ext.json` via `halter-settings.ts` (stat-cached reads,
corrupt file → `.bak` + defaults, defaults materialized on first read).

### Path resolution fallback (second use of the judge model)

When static analysis cannot bind an opaque token, the prompt lists it as
unresolved and, with the judge enabled, `judge/path-resolver.ts` asks the judge
model for the concrete runtime directories, grounded only in what the command
text proves. The suggestion is advisory display (`→ LLM: dir1, dir2`); it
becomes binding only when the user takes an option granting those dirs. The
gate then persists the confirmed resolution (D12 convergence) and resolves the
same token deterministically thereafter: no LLM call, the token flips from
`prompted` to `auto-allowed` in `.log/unresolved.jsonl`. The gate never
auto-allows on the resolver's output; any failure resolves to null and the
prompt is unchanged.

## Path resolution layer

`analysis/` resolves, per segment: the command's cwd (cd threading with
subshell depth tracking and `||`-ambiguous candidate bases), every path
(literal, tilde, variable), and every unresolvable location (sentinels:
`<unresolved-var>`, `<unresolved-cwd>`, `OPAQUE_VAR_DIR`). Variable
resolution covers depth-0 assignments, subshell inheritance, loop bindings,
and the D15 shapes (glob tails, literal in-lists, script-body paths). The
result is one `CommandAnalysis` per decision: paths with classification
(inside/outside/warned/denied), opaque markers, assignments, safety verdicts,
and the prompt hints. One tree-sitter parse per decision; the floor and the
judge consume the same analysis.

## Tool plugin contract

A tool extension opts in by shipping `<ext>/halter/index.ts` that default-exports
a plugin (`plugins/types.ts`). `buildRequest(event, ctx)` classifies each call:

- `exec` carries the final script payload, byte-identical to what the tool
  will execute (plugins import the tool ext's own payload builder). The
  payload goes through the bash script pipeline: floor + judge + dspa. No
  deterministic floor applies to the payload's internals; the payload IS the
  model.
- `file` carries a target path: outside-cwd warning, dir grants.
- `consent` is a per-kind session grant (a read consent can never cover the
  tool's exec actions).
- `null` returns the call ungated (discovery calls).

Grants: `<tool>` = whole tool (the "Always" on exec/file prompts);
`<tool>:kind:<k>` = one consent kind. `exec` is judgeable under dspa;
`file`/`consent` are never auto-allowed (session grants cover them). Fail-
closed: a plugin that fails to import or violates the contract blocks ALL
calls to its tool; the loader recovers the tool name from the plugin file's
`name:` literal. The loader scans the extensions root at halter load.

## Session state and observability

- **Store** (`gate/store.ts`): session-scoped grants (signatures, paths,
  trusted packages), confirmed path resolutions, abort timestamps. Injected
  into `decide()` and the prompt flow; a runtime singleton.
- **Decision log** (`.log/decisions.jsonl`, off by default): one line per tool
  call with kind, target, why/reason, regime tag, and dspa stop tag.
  Version-bound: delete after a `/reload` of gate code. `tools/log-inspect.mjs`
  does the recurring extractions (summary, audit, dspa, dspa --paths, stats).
- **Unresolved log** (`.log/unresolved.jsonl`): the fate of each unbound token
  (outcome, LLM suggestion, user decision, whether it became a confirmed
  resolution). Convergence is the token flipping from `prompted` to
  `auto-allowed`.
- **Widget** (`ui/widget.ts`): one status widget. Mode lines pinned on top (one
  line each: dsp warning, dspa health counts, dspat agreement), then the
  session's active rules.

## Module map

Target layout, locked by the 2026-09-02 structure grill. `analysis/`,
`config/`, `handlers/`, `plugins/` are unchanged by the refactor.

```
index.ts                  entry: events, /dsp* commands, /judge, wiring
halter-settings.ts        owner of the halter namespace in settings-ext.json
decide/
  engine.ts               async dispatcher: request type → policy → Decision
  types.ts                Decision, PromptData, requests, DecideOptions
  bash-rules.ts           the rule pipeline (RetryLoop → … → PromptFallback);
                          synthesizeManualBashPrompt (D3 bash conversion)
  bash-policy.ts          bash entry: parse → rules
  file-policy.ts          file entry: path checks
  rule-generator.ts       "Always" → grant derivation (on-demand)
gate/
  gate.ts                 thin orchestrator: decide → conversions → dspa →
                          log → route (auto-allow / block / prompt / reject)
  fallthrough.ts          dspa prompt path: floor + two-stage attempt, stop
                          classification, DspaFallthrough type, auto-allow
                          record + toasts
  conversions.ts          D3/D11 auto-allow → prompt probes (file writes,
                          bash script payloads)
  dspa-gate.ts            the deterministic hard floor + manual bar
  store.ts                session grants + confirmed resolutions + aborts
  decision-log.ts         JSONL logs (decisions + unresolved)
judge/
  judge.ts                judge settings access + streaming model call
                          (first-token deadline + response cap) + cache
  packet.ts               packet building + system prompts + script payload
  verdict.ts              verdict wrappers, advisory block rendering
  session-context.ts      reasoning-blind stage-2 context
  paths.ts                stage-2 path report cross-check (log-only)
  path-resolver.ts        LLM resolution of opaque tokens (advisory → binding)
modes/
  dsp-mode.ts             /dsp toggle state
  dspa-mode.ts            /dspa toggle + session-health counters
  dspat-mode.ts           /dspat toggle + agreement stats
  status-bus.ts           notifyStatus(ctx); index.ts wires the widget refresh
ui/
  prompt-flow.ts          prompt interaction loop (two-tier, grants, widgets)
  prompt-builder.ts       pure formatter: PromptData → prompt content
  prompts.ts              two-tier confirmation UI (native select/input)
  widget.ts               the unified status widget
  tmux-render.ts          tmux display (renders the shared analysis/tmux
                          parse — what is judged is what is shown)
analysis/                 (unchanged) bash-parser, tokenizer, cwd-tracking,
                          cwd-local, var-resolution, path-analysis,
                          segment-analysis, segment-helpers, command-analysis,
                          risk-analyzer, obfuscation,
                          tmux (command model: the one shared parse —
                          canonical subcommand, flags, send-keys key stream,
                          new-session command — plus the safety tables),
                          script-payload (the local script a command
                          executes, read in full),
                          evaluators/ (6 domain evaluators + builder + types)
config/                   (unchanged) bash-patterns, path-rules,
                          dangerous-patterns, trusted-scripts, logging, index
handlers/                 (unchanged) bash, file, tool adapters
plugins/                  (unchanged) loader + types (tool plugin contract)
test/                     flat; the contract suites pin behavior
```
