# Changelog

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
