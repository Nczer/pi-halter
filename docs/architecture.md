# Halter architecture

What halter does, end to end: which tool calls it sees, how each resolves to
auto-allow / prompt / block, and where every piece lives. The executable
contract is `test/cases-data.ts` (the curated pass/prompt/block rows) plus the
bypass and threading suites; this document is the spec they implement.
Decision rationale for the judge regimes lives in `docs/dspa-redesign.md`; per-class judge authority (operation classes C1–C4) in `docs/dspa-content-classes.md`.

## Terms

| Term | Meaning |
|------|---------|
| regime | One of the four mutually exclusive modes: `manual`, `dspa`, `dspat`, `dsp`. Enabling one disables the others. |
| floor | The deterministic hard gate in `gate/dspa-gate.ts`. Code only, no model. The only thing that may stop `/dspa` from asking the judge. |
| judgeable | An operation the floor lets through to the two-stage judge. |
| operation class | The four-way split that selects the judge pipeline: C1 content-determined (the payload IS the effect), C2 effect-extending (payload is code), C3 context-dependent (opaque refs), C4 policy-absolute. `docs/dspa-content-classes.md`. |
| bar | The manual bar: exactly the set of paths manual mode auto-allows (cwd + session grants + config-allowed + trusted scripts). Since D11 the floor's bar IS the manual bar. |
| opaque ref | A path token static analysis cannot bind: `$VAR`, `${VAR}`, `$(…)`, backticks in path position, a glob over an unknown base. Marked, never fast-allowed, resolved via D12 convergence when the user confirms. |
| unknown base | A `cd` whose target does not resolve; later relative paths in that segment chain get the `<unresolved-cwd>` marker. |
| fetchable form | A package-manager run form that fetches from a registry: `npx <pkg>`, `uvx`, `npm exec`, `pnpm dlx`, `bun x`. Gated by per-package trust (D10). |
| run form | A package-manager form that executes local code: `npm run`, `uv run`, `bun <script>`, `python <file>`. Judgeable, never fetch-gated (D8). |
| grant | A session-scoped "Always" outcome: command signature, path (read or read+write), or trusted package. |
| fall-through | A prompt shown because the dspa auto-allow attempt did not complete: floor stop or judge verdict/absence. Carries which layer stopped it. |
| packet | The judge's entire input for one operation: command, analysis digest, script content. Untrimmed (D11); file EDITS carry the after-edit view (replaced regions ±10 lines, line numbers) instead of the whole file. |

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
(`/dsp`, `/dspa`, `/dspat`). The `/dspa` toggle is the only session-persistent
mode: it is stored in `settings-ext.json` (`halter.mode`, written by the
`/dspa` command, applied on `session_start` — restart and `/reload` both
re-apply it). `/dsp` (the full bypass) and `/dspat` never touch the setting —
a new session must never silently start with all checks skipped. Session-health
counters stay session-scoped even when the mode persists.

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
  safe command is not allowlisted (grant the signature); a bare-name symlink
  in cwd that resolves outside it.
- *Every time* (no "Always" offered, principle 5): write redirects anywhere;
  write commands not in the allowlist; code execution; destructive or remote
  git (any `git push`, `git rm`, `git clean -f`, `git reset --hard`, ...).
- *Unresolvable*: opaque refs (`<unresolved-var>`), unknown base
  (`<unresolved-cwd>`), or base access (a path-aware segment with no target of
  its own after a `cd` names the cd's destination base as the location to
  approve).
- *Credential* (3.26.0, no "Always" offered): any credential path match
  (`warnPaths`: `.ssh`, `.gnupg`, `.env`, `.aws`, `id_rsa`, `*.pem`, …) —
  glob- and quote-aware, comment-aware, plus bare-token symlink checks and a
  filesystem-verified answer for pure-wildcard globs. The old hard-block tier
  was removed: its false positives (a `sed` program body, `echo .*`) refused
  benign commands, and deny-vs-warn never changed auto-allow behaviour.

**Block** (never promptable):
- retry-loop guard: a command aborted within 60 s is blocked, not re-prompted.

### The cd model

`cd` performs no file access; its target is never itself a path. Two
consequences: (a) later segments run against the effective base, so
`cd /tmp && cat ./secret` approves `/tmp/secret`; (b) a path-aware segment
with no target of its own (`cd /outside && ls`) operates on the base the cd
left, and that base is what gets approved. Standalone `cd /outside`
auto-allows (state dies with the process); `cd /nonexistent && …` auto-allows
when the rest never runs; `cd $HOME/.ssh && ls` still prompts (the credential
scan is raw-text, independent of the path set).

### Command substitution

A `$(…)`, backtick, `<(…)` or `>(…)` body is a PROGRAM the shell runs before the
outer command starts, so it is analyzed as one: the body text is re-parsed and
its segments go through the same pipeline a top-level segment goes through —
operands minted, flags checked, its own `cd` re-basing only the body (a
substitution runs in a subshell), and its nested bodies analyzed in turn (depth
-capped; beyond the cap fails closed). The body's paths join the command's path
set, and its programs extend the parent segment's STAGE list, so a body program
needs its own grant and a grant for the outer program never vouches for it.

Two holes this replaced. (1) A name table (`READONLY_SUBSHELL_CMDS`) classified
the body TEXT by word — blind to flags (`fd -x rm`), to relative operands
(`cat .env`) and to a `cd` inside the body. (2) The body extractor took the
substitution node's FIRST child: `&&`/`||`/`|` bodies arrive as one `list`/
`pipeline` child, but `;`- and `&`-separated bodies arrive as SEPARATE children,
so `$(ls & rm -rf /)` yielded the body `ls`. Bodies now come from the node's
source span verbatim; an unrecognized node shape hands over the node text, which
parses as a substitution in command position and is refused. A substitution node
with no body to hand over (`$()`) keeps the always-prompt flag.

The credential scan is a separate text pass and cannot see an operand inside a
QUOTED substitution (`echo "$(cat .env)"` — the whole span is one quoted word),
so each body gets its own credential pass with the body's base.

### The command position (prefixes and wrappers)

`command`/`builtin`/`exec`/`env` and the pass-through wrappers
(`timeout`/`nice`/`ionice`/`stdbuf`/`xargs`/`watch`/`parallel`) do not run a
program of their own, so every rule that asks *what does this segment run* asks
ONE unwrapper — `analysis/wrapper-unwrap.ts`, `resolveDelegatedTokens`. It
iterates to a fixpoint (prefixes nest: `nice command ssh` unwraps once to
`command`, which names nothing) up to `MAX_UNWRAP_HOPS`, and the signature, the
allow-table/delegation grant path, the parser's operand model, the egress check
and `baseAccessPath`/`baseWriteAccess` all take the same answer. Per-consumer
patching was the bug class: with the parser keying on the first word,
`nice command cat /etc/hosts` named `nice` — not path-aware, so the operand
model never ran, `paths=[]`, and no location bar existed (3.38.0 G6).

Past the hop cap there is no program identity, and the answer is `capped`, never
"the first word": the parser marks the position obscured (like an unsafe
pattern), the signature collapses to the wrapper alone so no grant can name it,
and the base checks assume the base is touched. `lookup` resolutions
(`command -v ls`) keep the head word — nothing runs, so nothing may be modeled
as running.

The corollary for payloads (`find -exec`, `fd -x`, `rg --pre`, a shell body):
only `unconditionallySafeCommands` — table entries with NO exclusion reason — are
trusted there. An entry with a reason (`git`, `grep`, `sort`, `timeout`) is
allowed because segment-level vetting (egress, git-clean, dangerous flags,
delegation) covers it, and that vetting runs on the enclosing segment, never on
the payload: `find . -exec git push \;` used to be approved by `find`'s entry and
again by `git`'s, and vetted by neither.

### argv0 location semantics

`ls` and `~/Downloads/ls` are the same word to a basename lookup, which is how
`bin/ls`, `scripts/cat README.md`, `/tmp/evil/git status` and
`node_modules/.bin/tsc` auto-allowed: the table matched the BASENAME, and the
parser minted no path for the program itself, so the read bar never saw the
binary the shell execs (2026-10-17 round-6 corpus). `analysis/argv0-path.ts`
answers one question per argv0 — `bare` (no path form), `system` (under a dir
the distro's package manager owns: `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`) or
`qualified` (every other path-qualified invocation) — against the base the shell
would resolve it from. An unresolvable base classifies `qualified`: a relative
program whose base is unknown cannot be shown to be a system program.

`qualified` means the program is a path operand OF ITS OWN COMMAND, and the same
class answers every consumer (the per-consumer patching lesson again):

- the parser mints its location, right after the delegation branch resolves the
  wrapper chain, so it is the delegated word that gets minted — and the word is
  read case-true, because a path resolves by case where a table key does not;
- the signature names that path instead of collapsing it: `nice bin/ls` is
  `nice bin/ls`, not `nice ls`, and an env-assignment prefix that hides argv0
  (`FOO=/tmp/x /tmp/y`) gets the program appended to the identity. A grant that
  names a program the command did not run is not a grant;
- the fast path (`FastAllow`) refuses to cover it, the stage is grant-bound like
  a `./` token (exact, base-bound signature grant only — never a basename), it
  is excluded from the safe-sub auto-allow, it is never `isSimple`, and the
  prompt offers the base-bound identity rather than the bare name.

`command -v /tmp/x` keeps bare-name semantics: a lookup executes nothing, so
nothing's location is touched. `/usr/local/bin` and `/opt/homebrew/bin` are
deliberately NOT system dirs — admin/homebrew-writable is the class this rule
targets — so the first such call prompts once and the exact base-bound grant
covers it after that (`test/argv0-path.test.ts`). Cost, measured on the frozen
ledger (875 unique real commands): zero verdict changes, because the only
absolute argv0 rows in real usage are `/usr/bin/bwrap`.

### Argument roles (the data/location rule)

A location token is minted only at a FILE-operand position of a path-aware
command. Anywhere else the argument is DATA: the shell hands it to the program
and touches no path named inside it, so minting a token there invents a
location whose "token" is the program text and which can never converge (the
2026-10-15 unresolved.jsonl case: 13 of 28 rows were `python3 -c` / `node -e`
bodies — the multi-line-literal guard is voided by any `$` in the body, and
program bodies are where `$` is densest). The grammars below are instances of
this one rule (sed script, grep/rg pattern, awk program), and so is an
interpreter's inline program (`-c`/`-e`/`-m`/`-r`, read from
config/script-operand.ts — the same flag set that decides which operand the
judge reads, so the two views cannot drift). Data is still read: path-like
literals inside it join the path set (see D15), with closed-set `$HOME`
expanded exactly where the shell would expand it (a double-quoted arg, HOME
not reassigned), and no expansion the closed set cannot bind contributes a path
(`${X}/a/b` names nothing statically, and slicing `/a/b` out of it points at a
nonexistent cwd child counted as INSIDE — the wrong direction). A multi-line
arg at a FILE position keeps its sentinel (`cat "a\n$X/b"`): the role decides,
not the shape.

### Write-role operands

The manual path asked ONE location question — may this path be READ? — and every
write verb answered it with the same predicate, so `mkdir ~/.pi/agent/pwned-dir`
and `touch ~/.pi/agent/pwned-file` auto-allowed (`~/.pi` is an
`allowedReadPath`: skills, extensions). `analysis/write-roles.ts` answers the
other question, "which operands does this command WRITE?", as a closed table of
operand ROLES — `WRITE_ALL` (`rm`, `mkdir`, `touch`, `chmod`, gzip/xz: the verb
mutates what it names), `WRITE_LAST` (`mv cp install split ln`: the last operand
is the destination — `ln` deliberately LAST, not ALL, because its first operand
is a name the link points at and is never written), `WRITE_FIRST` (`zip patch`),
`WRITE_IN_PLACE` (`sed perl`, decided by the in-place flag) — plus per-command
flag tables for the destinations that hide in flags (`tar -f`/`--file`,
`cp -t`, `sort -o`, `dd of=`, `find -fprint`), the flag-that-switches-the-verb
form (`find -delete` ⇒ every walked directory), and `tarWrites()` for tar's
extract/create asymmetry.

The operands are minted into `analysis.writePaths` at the SAME sites as `paths`
and with the same hop/skip/dedup filters, so `writePaths ⊆ paths` by
construction — one resolution path, not a parallel one (the G4/G6 lesson).
Same for provenance: a write inside a code body (`python3 -c 'open(p,"w")'`,
`sed -i` in a `$(…)` body) is recorded per segment and folded into the parent
BEFORE the SAFE_SYSTEM_PATHS dedup, or the write is silently dropped. The
decision layer then bars write operands against cwd ∪ `allowedWritePaths` ∪ the
session's WRITE grants — a READ grant never satisfies one — and the prompt
names them as writes (`⚠️ writes outside cwd`, title `Write`) so the Always tier
stores `writeDirs`, which is the click that actually covers the next run.

Closed world: no table entry ⇒ no write operand claimed. That adds no looseness
(the location was never scopable anyway); it stays outside both bars until the
verb is added. Cost, measured on the frozen ledger (875 unique real commands):
zero verdict changes. Known boundary, documented not fixed: a
`SHELL_INTERPRETERS` body (`sh -c 'echo > ~/.pi/agent/x'`) mints no paths at
all — measured `paths=[]`, `writePaths=[]` — so neither bar can see it, and the
/dspa floor passes it; what gates such a call is its command-level grant (`sh`
and `bash` are not table-allowed, so it prompts) and, under dspa, the judge
packet's full command text (`test/write-roles.test.ts`,
`test/verified-bypasses.test.ts` P15).

### Sed grammar

`sed [flags] script [files…]`: the first non-flag arg (and `-e` values) is
not a file and is skipped by path analysis; file-position args keep the
opaque marker; a bare literal path in script position stays path-checked.

### Search grammar (grep, rg)

`grep|rg [flags] PATTERN [files…]`: the first non-flag arg (and `-e`/
`--regexp` values) is the pattern — data, never a file, so it is skipped by
path analysis and never mints an opaque ref (the 2026-08-26 grep case: a
`//…` pattern resolved as a network-prefix absolute, a phantom root child;
the 2026-09-21 unresolved.jsonl case: `$1`/`$pat` in an rg helper function
floor-stopped a read-only census). `-f`/`--file` switches the grammar: its
value IS a file (the pattern file, stays path-checked) and every later
non-flag arg is a file. rg carries value-taking flags grep lacks (`-g/--glob`,
`-t/--type`, `-m`, `-A/-B/-C`, `--pre`, `-r/--replace`), so “first non-flag”
can pick a flag's VALUE as the pattern; both mistakes are conservative — a
flag value is never a file, and a real pattern pushed one slot right stays
path-checked. The flag list is deliberately not modeled (it cannot drift).

### D15 parser resolutions

Refs the command itself pins resolve instead of flagging:
- a glob-tailed value binds to its directory (`F=/a/b; grep $F/*.js` → `/a/b`;
  a glob never matches `/`); braces stay sentinel (several names);
- an all-literal `for` in-list names every word concretely (symlink words
  name their real target; still outside, never exempt);
- an embedded loop ref over an all-literal in-list substitutes each word
  textually (one loop-bound `$var`, expansion-free static part);
- path-like literals in script bodies (heredoc bodies, multi-line literal
  args, inline interpreter programs) join the path set fail-closed;

### File policy

- reads: inside cwd / allowed / nonexistent paths auto-allow (a read can only
  ENOENT; nothing leaks). Credential paths prompt even for reads (3.26.0:
  no block tier — the very-high-risk warning is the gate).
- writes: outside cwd prompts (dir grant); credential paths prompt.
- the filesystem root is never an Always grant: a root-only path prompt offers
  no dir tier, mixed prompts drop `/`, and a file prompt's dir umbrella stops
  before root.

### Trusted scripts and packages

Scripts resolving into `~/.pi/agent/skills/` auto-allow in three forms
(interpreter + script; shell interpreter + script, first non-flag token only;
direct exec). `-c`/`--command` is never trusted. Trust covers the invocation
only: unsafe pipe stages and write redirects around a trusted script still
prompt (a substitution argument is judged by what its body does — see
Command substitution). `uv run --with <pkg>` trusts the invocation only
when every `--with` package is in `TRUSTED_PACKAGES` and the script is in a
trusted dir (`--with-requirements`/`--with-editable` sources must be trusted
too; they bypass the package allowlist). Matching is exact after extras and
case are stripped (`markitdown[pptx]` → `markitdown` matches; a quoted pin,
`--with 'pandas>=2.0'`, is a different name and voids trust — unquoted, `>` is
a shell redirect before uv ever sees the pin, and the redirect is gated on its
own).
Trust and the judge packet read ONE scan (`uvRunDeps`, 3.30.0): the walk that
gates trust is the walk that feeds `registryRunDeps()`, so the two can never
disagree about which command names which dependency. Naming a package in the
packet is knowledge, never a grant — the allowlist's only enforcement stays
here.

The same dependency identity carries into **grants** (3.31.0). A `uv run` form's
bash signature names its dependencies — `uv run --with pandas
--with-requirements req.txt` — with a local source resolved to an absolute path
against the cwd the shell would actually have at that point in the chain, and
with the wrapper looked through (`timeout`/`env`/`xargs`/`command`, the same rule
as `command -v`). Consequences: a bare `uv run` Always covers only bare `uv run`;
`--with pandas` never covers `--with pdfplumber` (dep flags are matched exactly,
while every other flag keeps prefix semantics — a form is an allowlist, and the
prefix rule exists for flag *omission*, which cannot silently add a fetch); a
dependency that cannot be named (`<unresolved>` from an unresolvable cwd, an
opaque quoted value) makes the whole segment ungrantable — the prompt says so and
`Always` is refused for it, rather than granting a signature that
under-names the fetch. This is defence in depth, not an observable fix: every
`uv run` form already floors at code-exec review, so a coarse `uv run` grant
never auto-allowed a dependency form — but the signature *recorded* it as
covered, and a recorded grant is reusable by other rules (the shape of the
`command -v` hole). Sibling fix, the soundness prerequisite: `cd $(…)` no longer
leaves the pre-`cd` cwd as the base for later segments (a substitution inside
`cd` is not eval-free), which is what made a path-named dependency nameable at
all — the direction is fail-closed, the base becomes unknown, not guessed.

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
session-wide. A `uv run` dependency form with an unnameable source gets no
signature grant at all (3.31.0): the segment is marked ungrantable, the prompt
says why, and no broader rule is generated for it — a grant that covers fewer
deps than the command fetches is the failure being removed.

A wide dir tier summarizes **for display** (`ui/path-display.ts`): sub-paths of
a listed dir drop out of the body line and the Always label (`a/aa a/ab a` →
`a`), and a set under one parent is named once — body
`⚠️ outside cwd: ~/Projects/halter/ (4 dirs under it) +1 others`, label
`Read 4 dirs under ~/Projects/halter/ +1 more`. Picking: the candidate with the
most entries under it, ties to the deeper one, root never a candidate. Not
summarized: below 4 dirs; a scattered set (nothing covers 2+ — the body lists
all, sibling-combined for width, the label caps at 3 + `…+N more dirs`); or when
an unresolved marker dir is present. Display-only by construction: `pathGrantDirs`
and the minted `readDirs` stay the exact set, the label never writes
`<covering>/*` (rule shape for a dir that is not itself granted), and tier-2
lists every directory.

## dspa regime

Before any prompt, `gate/fallthrough.ts` attempts the auto-allow:

1. **Floor** (`gate/dspa-gate.ts`, code only). Stops, by class:
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
   Detection-limited stops are judgeable (content-classes T2): an obscured
   command position and an unparseable command pass to the judge — the packet
   carries the full raw text plus both flags, so the judge has strictly more
   information than the static pass. Everything above is a POLICY stop and
   stays absolute.

   Every floor stop is **advisory** (D16): the judge runs both stages and the
   verdict renders in the prompt ("— advisory (floor stop stands)") — the stop
   stands, the judge never grants over the floor.
2. **Stage 1** (stateless, LRU-cached on the operation): the packet's static
   analysis is the whole input. `approve` + `low` auto-allows. Script
   payloads (C2, content-classes T3) skip stage 1 — the class always
   escalates, so stage 1 would only add a call.
3. **Stage 2** (reasoning-blind session context, uncached): runs when stage 1
   did not auto-allow (or immediately for script payloads). `approve` +
   `low|medium` auto-allows. Its verdict is final.

`approve` + `high`, `deny`, `defer`, and any no-verdict outcome prompt.

**"Judge again" retry.** When the floor passed but the judge call itself
failed — the model was unreachable, or a stage produced no verdict within
its deadline (the carried verdict is stage 1's or absent) — the prompt
offers a repeatable `Judge again` option: a fresh, uncached stage-2 call
(the model may have been busy loading). An approving verdict (low/medium
risk) auto-allows with the normal dspa side effects; anything else re-shows
the prompt with the new verdict (or a failure note naming the class —
`timeout 8.0s`, `auth-failed`, `no-tool-call`). Legitimate stage-2
verdicts (DEFER, REJECT, approve above authority) are judgments, not infra
failures — never re-judged (Yes/No are the user's tools). Not offered when
the judge is off (a choice, not a transient failure), after a floor stop
(the deterministic layer cannot be re-judged), or without the permission
request.
The failure class is carried, never re-guessed: a judge stage returns a
`JudgeStageOutcome` (the verdict, or `judge()`'s typed `failReason` plus model
and latency), and every no-verdict surface — the dspa stop-tag, the prompt note,
the dspat warning, the retry note — renders it. That is what makes "stage 2 fails
while the server is up" answerable: the ledger says which kind of failure it was.
EVERY floor stop is advisory (D16): the judge runs both stages and renders
the verdict in the prompt — the stop stands. Auto-allowed operations toast.

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
model output back). Mismatches land in the decision log AND the judge ledger
(on by default, D17); mine with `tools/log-inspect.mjs judge` (or
`dspa --paths` on a toggle-on decision log).

**D4 (denials to the agent) is on HOLD**: the planned behavior where a
stage-2 `deny` returns to the agent as a good-faith block (escalating to a
prompt after 3 consecutive denials, session degrade after 20 total) is
designed and documented in `docs/dspa-redesign.md` D4 but unimplemented,
pending more observed data.

## dspat regime

Identical to manual plus a `💭 Judge:` block in every prompt — bash, file,
and tool (the packet builder covers all three prompt types). D17: BOTH judge
stages run (the same cascade order as /dspa, but stage 2 is never skipped,
even on stage-1 approve+low — the cross-check of stage-1 lows is the data
/dspa's auto-allow path cannot produce) and the block shows the FINAL
verdict — stage 2's, or stage 1's when stage 2 produced none
(explanation + `→ suggests: APPROVE|REJECT|DEFER (<risk>)`). The user's
choice is recorded against that final verdict as session agreement stats
(widget line). Stage disagreements and stage-2 path mismatches are mirrored
to the judge ledger (on by default, D17). No auto-allow.
An on-demand `💭 Explain` prompt option runs the judge in any regime without
recording agreement stats (the human picks when to consult, so the subset is
self-selected).

## dsp regime

`/dsp` bypasses the gate entirely (the gate is skipped, so the decision log
never sees these calls). Enabling always takes a confirmation; a cancelled
confirmation keeps the current mode. A warning line stays pinned on the
widget while active.

## The judge

One one-shot model call per stage. The packet is the judge's entire input,
untrimmed by design (D11): the full command text (heredoc bodies included),
the analysis digest, and, when the operation executes a local script, its
content in full as fenced untrusted data — the heading states the trust state
honestly (3.30.0): a script inside the operator's trusted scripts dir is shown
as an invocation that lost trust, not as a foreign file. The digest names the
registry packages a `uv run --with` form fetches, each marked with the
operator's allowlist verdict (`registry deps (uv fetches these at run time):
pandas (on the operator's package allowlist), …`; 3.30.0, max 8 named) —
`network: yes (uv)` alone left the judge guessing about a supply-chain
question config already answered; file writes carry the full new
content, edits the after-edit view (replaced regions ±10 lines, line numbers).
Only the digest sections head-cut (24 segments at ≤120 chars, 10 risk
reasons, 20 paths); tool packets carry the plugin's argsPreview verbatim
(the plugin caps its own previews, e.g. joplin). No conversation history
reaches stage 1. Stage 2 adds a reasoning-blind session context: the user's
last messages (4 / 3000 chars, head-truncated) plus a 10-line tool-call
digest (≤120 chars/line) plus up to 10 session-grant lines. Agent prose and
tool outputs never appear: a compromised agent cannot talk the approver into
compliance.

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
a plugin (`plugins/types.ts`). `buildRequest(event, ctx)` classifies each
call, and the KIND SELECTS THE PATH — two families (content-classes):

Content-judge (judgeable — the /dspa cascade can auto-allow):

- `exec` carries the final script payload, byte-identical to what the tool
  will execute (plugins import the tool ext's own payload builder). The
  payload goes through the bash script pipeline: floor + judge + dspa. No
  deterministic floor applies to the payload's internals; the payload IS the
  model.
- `egress` carries the outgoing payload (a web search query, a url list) —
  data leaving the machine (C1, content-classes T1). The full args ride in
  the packet (the judge sees exactly what goes out); no deterministic floor
  on the payload; standard cascade (stage-1 approve+low auto-allows, stage 2
  low|medium is the de-risking pass).

Human-gated (never auto-allowed — the prompt is the gate):

- `file` carries a target path: outside-cwd warning, dir grants.
- `consent` — the action's meaning comes from the session (opaque args the
  judge cannot vouch, C3), prompt session-scoped (content-classes T4): the
  first prompt per kind per session asks "Allow <kind> this session?" — yes
  IS the session grant, no blocks that op, single tier, the prompt names the
  model. Consent grants reset on model switch (T5): the trust decision is
  about a specific model.

Mixed: classification is PER CALL — one tool's actions map to whichever
path their payload demands (joplin: all consent; exa: all egress; a tool may
combine, e.g. consent reads + exec actions + egress fetches). Grant scopes
stay separate per kind (a read consent can never cover exec).

`null` returns the call ungated (discovery calls).

Grants: `<tool>` = whole tool (the "Always" on exec/file prompts);
`<tool>:kind:<k>` = one consent or egress kind. `exec`/`egress` are
judgeable under dspa; `file`/`consent` are never auto-allowed (session
grants cover them). Fail-closed: a plugin that fails to import or violates
the contract blocks ALL calls to its tool; the loader recovers the tool name
from the plugin file's `name:` literal. The loader scans the extensions root
at halter load.

## Session state and observability

- **Store** (`gate/store.ts`): session-scoped grants (signatures, paths,
  trusted packages), confirmed path resolutions, abort timestamps. Injected
  into `decide()` and the prompt flow; a runtime singleton.
- **Decision log** (`.log/decisions.jsonl`, off by default): one line per tool
  call with kind, target, why/reason, regime tag, and dspa stop tag.
  Version-bound: delete after a `/reload` of gate code. The decision log has
  its own toggle (`/halter-decision-log`); the three ledgers share one
  (`/halter-ledger-log`; same arg handling; D17 split). `tools/log-inspect.mjs`
  does the recurring extractions (summary, audit, dspa, dspa --paths, stats).
- **Unresolved log** (`.log/unresolved.jsonl`, on by default): the fate of
  each unbound token (outcome, LLM suggestion, user decision, whether it
  became a confirmed resolution). Convergence is the token flipping from
  `prompted` to `auto-allowed`.
- **Judge ledger** (`.log/judge.jsonl`, on by default, D17): signal-only
  judge diagnostics — stage-2 tightenings over stateless stage 1 (`diff` — a
  stage-2 loosening is the expected direction, not a line), stage
  failures (`infra`: `error` is judge()'s own typed class — model-unresolved
  / auth-failed / timeout / no-tool-call / bad-args / call-failed, with the
  message in `detail`; a question-shaped reply is `bad-args` with detail
  `asked-user: …`), and D13 path mismatches (`paths`: `floorMisses` = paths
  the floor never saw, `contextMisses` = stage-2 echoes of paths named only
  in the Session context section). Mine with `tools/log-inspect.mjs judge`.
- **Glob-err ledger** (`.log/glob-err.jsonl`, on by default): credential-scan
  glob-verify failures only — a healthy run writes nothing. When a relative
  glob's `fs.globSync` throws (or is missing in the runtime), the scan fails
  closed with an honest `glob-unverified:` stop; this ledger keeps the error
  for mining (the pattern, the error name+message, the cwd).
- **Widget** (`ui/widget.ts`): one status widget. Mode lines pinned on top (one
  line each: dsp warning, dspa health counts, dspat agreement), then the
  session's active rules. Path display (sub-path dedup, `~`-shortening, sibling
  combining, dir-list summaries) lives in `ui/path-display.ts`, shared with the
  bash prompt.

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
  dspa-mode.ts            /dspa toggle + session-health counters + persistent startup mode (settings-ext.json)
  dspat-mode.ts           /dspat toggle + agreement stats
  status-bus.ts           notifyStatus(ctx); index.ts wires the widget refresh
ui/
  prompt-flow.ts          prompt interaction loop (two-tier, grants, widgets)
  prompt-builder.ts       pure formatter: PromptData → prompt content
  prompts.ts              two-tier confirmation UI (native select/input)
  widget.ts               the unified status widget
  path-display.ts         path display shared by widget + prompts: sub-path
                          dedup, ~-shortening, sibling combining, dir-tier
                          summaries (display-only — grants stay the exact set)
  tmux-render.ts          tmux display (renders the shared analysis/tmux
                          parse — what is judged is what is shown)
analysis/                 (unchanged) bash-parser, tokenizer, cwd-tracking,
                          cwd-local, var-resolution, path-analysis,
                          credentials (raw-text credential scan; resolves
                          operands through path-analysis),
                          segment-analysis, segment-helpers, wrapper-unwrap
                          (the one fixpoint unwrapper for the command position),
                          argv0-path (where a program comes from: bare / system
                          dir / path-qualified, per stage and base),
                          write-roles (which operands of a path-aware command
                          it WRITES: the closed role + flag table),
                          command-analysis,
                          risk-analyzer, obfuscation,
                          tmux (command model: the one shared parse —
                          canonical subcommand, flags, send-keys key stream,
                          new-session command — plus the safety tables),
                          script-payload (the local script a command
                          executes, read in full),
                          evaluators/ (6 domain evaluators + builder + types)
config/                   (unchanged) bash-patterns, path-rules,
                          dangerous-patterns, trusted-scripts, script-operand,
                          logging, index
handlers/                 (unchanged) bash, file, tool adapters
plugins/                  (unchanged) loader + types (tool plugin contract)
test/                     flat; the contract suites pin behavior
```
