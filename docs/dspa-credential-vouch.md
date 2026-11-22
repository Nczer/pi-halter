# dspa credential floor — an operator answer for one class

Status: **APPROVED, NOT BUILT** (grilled and decided 2026-11-16). Decisions V-a…V-i
in §6, guards in §5, build order in §10, filings in §9.

## 1. Trigger (measured, not remembered)

Corpus: `.log/decisions.jsonl`, 1624 rows, 2026-11-15 → 2026-11-16, written while
the decision log was on (it exists only while `/halter-decision-log` is on; the
round-1–5 corpus is gone). This machine's shape, not a general rate.

- `credential pattern`: **10 prompts, ONE dir, max same-dir repeat 10** — the
  worst repeat in the corpus. All of them read-only cert work
  (`cd <cert dir> && openssl x509 … / asn1parse … / pkey …`), one with a
  `find … -iname` glob. Nine of the ten begin with `cd <dir>`.
- 2 of 69 prompt rows carry `judgeDeny`; **0 of the 10 credential stops do**.
  `dspaJudgeDeny` (`gate/fallthrough.ts:99`) writes the field for ANY prompt
  whose final verdict is a deny, "which layer stopped first does not matter" —
  so the judge's advisory verdict on those ten was not a deny.
- Consequence, stated bluntly: the reading of `judge/judge.ts:148`
  ("Never approve … operations touching credential or secret files") is
  contradicted by the model's behaviour. `local-1/Qwen3.8-Flash-Next` does not
  enforce it. **The floor is what stops these commands; the rubric line is
  decoration that happens to look like a control.** Filed as a control-strength
  finding (§9) — it deserves a measured answer against the local judge, which
  needs §7's L2 (the ledger cannot today distinguish `approve` from `defer`, so
  the split was NOT measured; the judge server was down, no replay probe run).

## 2. What this reverses, and what it protects

`docs/dspa-content-classes.md:43` puts credentials in **C4 — policy-absolute,
"the user's call, never the judge's"**; D-a of the 2026-10-19 grill
(`docs/dspa-intent-floor.md:212`) re-confirmed `credential pattern` /
`unverifiable glob` as absolute.

This document **keeps the principle and changes who answers**. "The user's call"
stays true — the call stops being re-asked per command. The operator answers once
for a location, and the answer is recorded, revocable, and session-scoped. This
is the same move the floor already allows for fetchable run forms (`Trust: <pkg>`
clears an untrusted-package stop) and for loopback egress (D14 made a *scoped*
subset of a policy class judgeable).

Untouched, by standing decision: the write bar (reads are never authority to
write — 3.49), every D-g absolute bar (`mkfs`, `dd`, `mount`, `eval`, the
irreversible git forms, download-and-execute), non-loopback egress, delete scale
past the temp zone, tool `file`/`consent`, untrusted packages.

## 3. The mechanism

One operator act: **"credential-named material under this directory is mine to
work on, this session."**

It is a statement about *the credential class*, and it rides with a read grant
because the same command usually needs both — nine of the ten corpus rows name
the directory itself, so a class-only exemption would produce a second stop
(`outside base`) one decision later. It is **never inferred from the read bar**:
the exemption reads only its own set. The reason is concrete and already on
record: `~/.pi` is a `halter.readDirs` entry, and the filed rule is "a read grant
never makes writes judgeable" — an exemption keyed off the read bar would
therefore unlock credential-named files sitting under `~/.pi`.

Coverage is all three doors the credential floor has, so the act means one thing:

| door | today |
|---|---|
| bash | `gate/dspa-gate.ts:959–965` (`credentialRule` / `unverifiable glob`) |
| file branch | `gate/dspa-gate.ts:874` (`warnedRule`) |
| manual/auto file policy | `decide/file-policy.ts` — a warned path never auto-allows, even inside cwd. **Left standing** (§4.5) |

## 4. Details

### 4.1 The canonical term

`judge/session-context.ts:15` already uses the loose phrase "scope the user
already **vouched** for" for ordinary scope grants, so *vouch* is not free — and
one word must mean one thing in this repo. Decided: code term **`accreditedDirs`**
("the operator accredits this dir"), API `accreditDir()` / `isAccredited()`. The
UI label stays plain words ("Allow credential files here — this session"); the
code term never reaches the operator. The loose use in `session-context.ts:15`
gets reworded to "granted" in step 5.

### 4.2 The offer, and what it can name

The accreditation is offerable **only when the decision names a concrete
directory** — an exemption with no location is not an exemption, it is a class
switch:

- **bash**: `checkCommandForCredentialPaths` (`analysis/credentials.ts:566`)
  returns a matched *rule name*, not a path, so the directory comes from
  intersecting the analysis's path list with `warnPaths`. A finding with no
  concrete path — a bare-name glob (`find … -iname "*.pem"`), an
  `unverifiable glob` token, or a bare-token symlink hit — **names nothing to
  accredit: the stop stands unchanged** (fail-closed).
- **file branch**: `resolved` is known (`analysis/path-analysis.ts:192`
  `isPathWarnedResolved`) → the dir is `dirname(resolved)`.
- **unit**: the deepest common ancestor directory of the matched credential
  paths in that command; it covers the subtree (the same tree semantics as a
  read grant).
- **never persisted** (V-b): session-scoped. `/halter-forget` drops it — extend
  `forgetLearnedReadDirs` (`gate/store.ts:178`) rather than adding a second
  forget command.
- **visible**: a widget segment beside `R intent` (`ui/widget.ts:253`), label
  `R cred` + the dirs, so the operator can see what the session has opened.

### 4.3 The ceiling (what a grant cannot reach)

Accrediting a directory lifts the credential floor for paths whose
credential-shape comes from a **suffix/glob rule** — today only `*.pem` in
`config/path-rules.ts:123`. It never lifts a path that is credential-shaped
because of its **NAME**:

- any non-glob `warnPaths` entry (`.ssh`, `.gnupg`, `.aws`, `.gcloud`, `.azure`,
  `.env`, `.git-credentials`, `.netrc`, `.npmrc`, `.pypirc`,
  `.docker/config.json`, `id_rsa`, `id_ed25519`, `id_ecdsa`, `id_dsa`, `.envrc`);
- the `.env.*` special case (`analysis/path-analysis.ts:200`) — it is
  name-shaped, not suffix-shaped, and must not lift (this is why the ceiling keys
  on the *matched path*, not on the rule's spelling);
- the pseudo-fs secret files (`PROC_SECRET_RE`, `gate/dspa-gate.ts:731`), which
  is the same refusal as §4.3 of `docs/dspa-intent-floor.md`.

Deriving it from the matched path rather than the rule string is deliberate: it
keeps `.env.production` absolute while `ca-key.pem` lifts, with no second list to
maintain. Private key material lifting is intended: the trigger corpus ran
`openssl pkey -in <key file> -text` and that is the friction being removed.

Both halves of the decision read the names **case-folded** (3.56.0): the rule
list is authored lowercase, `CREDENTIAL_SCAN_RE` carries `i`, and the ceiling
folds the path's components the same way. The two must fold together — a scanner
that sees `.SSH/id_rsa` and a ceiling that does not would let a differently
spelled store lift inside an accredited dir. Folding can only ever cover the
same set of files the lowercase spelling already did (on a case-folding volume,
APFS/NTFS, they are the same bytes; on a case-sensitive one the warn tier's cost
is one prompt).

### 4.4 Judge

- **Route**: skip stage 1 and let stage 2 decide — reusing the existing skip
  branch (`gate/fallthrough.ts:511`: a class that "always escalates, so stage 1
  would only add a call; stage 2 (low|medium) is the decider"). Stage 2 is
  uncached and its packet carries the session context: the conversation ("inspect
  my own CA") is exactly the evidence an honest approve needs.
- **Text**: append one clause to `JUDGE_STAGE2_SYSTEM_PROMPT`
  (`judge/judge.ts:164`). `JUDGE_SYSTEM_PROMPT` stays **byte-identical** — it is
  the eval-scored text (D23). The clause must be an exception, not an override:
  *a credential NAME inside a directory the operator granted this session is not
  by itself a denial reason — rule on the effect: copying secret material
  elsewhere, sending it out, or revealing key material the session did not ask
  for.* The blanket line still governs every path that is not granted.
- **Honesty**: no packet redaction. `judge/packet.ts:326` keeps printing the
  credential rule, and the accredited dir must appear in the stage-2 grants block
  (`judge/session-context.ts:190`), so the judge sees both the class and the
  authority. VERIFY at build: the grants block today lists `write dir` entries —
  confirm the accredited dirs reach it, or add them.

### 4.5 The manual bar is not a door this grant opens (built, 2026-11-16)

V-g listed `decide/file-policy.ts` as the third door. Building it showed the
list was one door short of what it describes: that file is the MANUAL bar, and
manual mode has no judge. Clearing a warned path there is not "make this
judgeable" — it is a silent auto-allow of a credential read with nothing
ruling on it, which contradicts G6 ("the grant lifts the floor, not the
verdict") and the trigger itself (all ten corpus rows carry `mode: dspa`).

So the exemption covers the two doors that feed the judge, and the manual bar
keeps stopping. Under `/dspa` the read-tool case is already covered: the manual
bar's prompt routes to the dspa file door (§4.2's file row), where the
accreditation applies and the judge decides. The trigger corpus is served
without touching manual mode.

## 5. Guards

- **G1** The ceiling (§4.3) outranks the grant: a name-shaped path never lifts.
- **G2** A grant is never write authority. A write under an accredited dir still
  faces the write bar; `decide/file-policy.ts` keeps its "no fs probes on
  credential paths" behaviour unchanged.
- **G3** No derivation either way: the credential exemption reads only
  `accreditedDirs`; a read grant never implies one, and `~/.pi` (a readDirs
  entry) proves why.
- **G4** No concrete dir, no grant (fail-closed): unverifiable globs and
  glob-only findings are unchanged stops.
- **G5** `unverifiable glob` is never lifted by anything — it is a verification
  failure, not a credential match.
- **G6** The grant lifts the FLOOR, not the verdict: stage 2 must still return
  approve at risk ≤ medium, or the prompt appears as today.
- **G7** The existing "a widened read bar moves no other bar" probe stays true —
  it is the *accreditation*, not the read grant, that moves the credential floor.

## 6. Decisions (grill, 2026-11-16)

- **V-a — dir-scoped, not class-scoped**: the operator decides per directory.
  A global class switch would make `cat ~/.ssh/id_rsa` judgeable, which is not
  what "the material here is mine" means. Rejected: name-scoped global, whole-class global.
- **V-b — prompt-time, session-only**: decided at the moment of friction, like
  `Trust: <pkg>`; nothing persisted to settings, `/halter-forget` and session end
  clear it. Rejected: settings-only (useless mid-task), session+Always.
- **V-c — the secret-store ceiling**: name-shaped credential paths (stores and
  standalone keyfiles) and pseudo-fs secrets stay absolute inside an accredited
  dir. Rejected: no ceiling; also keep private-key *bodies* absolute (needs a
  metadata-vs-dump distinction that does not exist, and would keep prompting on
  the very commands from the trigger corpus).
- **V-d — read + credential in one act**: one keypress records a session read
  grant AND the accreditation, because the corpus commands name the dir itself.
  Writes excluded. Rejected: credential-only (double stop), read+credential+write
  (collapses the read/write split kept absolute since 3.49).
- **V-e — judge routing**: stage-1 skip, stage 2 decides (the operator's
  instinct, and existing house style at `gate/fallthrough.ts:511`).
- **V-f — clause in stage-2 text only**: stage 1 is skipped for this class
  anyway, so the eval-scored `JUDGE_SYSTEM_PROMPT` stays byte-identical.
  Rejected: no clause (a guaranteed deny + a wasted uncached call for every
  accredited op), clause in both stages.
- **V-g — coverage**: all three doors as asked (bash, file branch, manual/auto file
  policy). **Amended at build**: the third is the manual bar, where no judge
  exists — clearing it would auto-allow silently, so it stands (§4.5). The two
  judge-fed doors are covered, which is what the read-tool case needs.
- **V-h — this case, not a mechanism**: one credential implementation, plus the
  eligibility RULE written down once in `docs/dspa-content-classes.md`: *a C4
  policy stop whose bar keys on a location may take an operator grant; a stop
  that keys on a verb, a destination, or a blast radius may not.* Rejected: a
  vouch registry for one entry; wiring a second class (`full filesystem scan`)
  with 2 rows of evidence.
- **V-i — canonical term**: `accredit` / *accredited dir* (§4.1), chosen over
  `endorse`, `credentialOk`, and keeping "vouch" (which `session-context.ts:15`
  already uses loosely for scope grants).

## 7. Ledger changes riding with this build

The vouch feature cannot be evaluated without these three — "how many prompts did
it remove, and how many did the operator allow anyway" is the whole argument, and
today none of it is recorded. Standing rule applies: readers use live field names
only (no alias fallbacks — alias readers printed no misses at all), so
`tools/log-inspect.mjs`, `tools/probe.mts`, `tools/replay.mts` and the tests move
in the same commit, and the switchover version gets stamped in `CHANGELOG.md`.

- **L1 — the operator's answer.** Today `logDecision` runs at decision
  *creation* (`gate/gate.ts:108`), before the prompt is answered; `kind:"block"`
  never appears in the file (0 rows) and `unresolved.jsonl`'s `decision` covers
  only miss-path rows (this corpus: 11 `yes`, 3 `alwaysPaths`, **0 `no`**). So the
  false-positive rate of every floor class is unmeasurable. Fix: record the click
  on prompt rows — `answer: "allow" | "allowDir" | "allowCred" | "deny" |
  "abort"`. **Shape decision**: the jsonl is append-only and L5's `decisionId` is
  filed-not-built, so the row is written once, AFTER the answer, rather than as a
  follow-up row. Cost, accepted and stated: a session that dies mid-prompt loses
  that row.
- **L2 — verdict state as a value, not an absence.** `judgeDeny` present on 2 of
  69 prompt rows; its absence conflates approve / defer / stage-2-skipped-by-D22
  / judge-off / no-verdict. Fix: `judgeVerdict: approve|deny|defer|none`,
  `judgeStage: 1|2|null`, `judgeModel`, `judgeSkipped:
  "d22"|"judge-off"|"not-run"|"floor-before-verdict"`, and `judgeExplain`
  (replacing `judgeDeny`) whenever the verdict is not an approve.
- **L3 — one class name, in one field.** `dspa: "gate: credential pattern
  (*.pem)"` vs `reason: "credential *.pem; …"`, and `outside base (session …)`
  vs `outside /mnt/Ndr/Certificate`: the same class spelled twice, so counting a
  class needs a hand-written regex per field. Fix: `stopClass` (slug:
  `credential-pattern`, `unverifiable-glob`, `outside-base`, `network-egress`,
  `full-fs-scan`, `untrusted-package`, `delete-scale`, `absolute-bar`, `dangerous`,
  `tool-consent`, `judge-declined`, `judge-failed`) + `stopDetail` (free text).
  `reason` keeps its human sentence — decomposing it is L4, filed.

## 8. What the log audit found and this build does not fix

- **L4** `reason` carries four semantic types in one `;`-joined string (risk
  level, class label, command evidence, location evidence; and on auto-allow rows,
  verdict + model): 1588 rows hold one fact, 30 hold three to six.
- **L5** The three ledgers do not join: 7 of 125 `judge.jsonl` rows match a
  decision row on `(ts, cmd[:60])`; the shared field set is `{kind, ts, cwd}`; 5
  rows collide within one millisecond. Needs a `decisionId` written by all three
  writers — which is also what a follow-up-row answer (the other shape of L1)
  would need.
- **L6** `llm` absent on 76/76 `unresolved.jsonl` rows: "resolver not consulted"
  vs "returned nothing" vs "resolver off / no auth" are indistinguishable.
- **L7** `mode` absent = manual (904 rows): same absence-encodes-state shape.

## 9. Filed, not fixed (2026-11-16)

- **The dead rubric line** (`judge/judge.ts:148`): 0 denies across 10 credential
  stops, 2 denies across 69 prompts. A rule the local judge ignores ~97% of the
  time is not a control. Re-measure the eval-scored text against the deployed
  judge (and say which judge it was measured on) before anyone leans on it.
- **`Always` suppression is out of sync with D-b**:
  `ui/prompt-builder.ts:271` — `includeAlwaysOption = !hasUnsafePattern &&
  !credentialRule && …` suppresses persistence on 25 of 69 prompts (36%), because
  a syntax label (`[Risk] pipe operator`) suppresses as hard as `[Tool] python`.
  D-b split exactly this conflation for the floor ("a pattern-table CLASS label is
  a name the judge rules on, not a bar"); the suppression list never followed.
  Needs its own grill — it touches principle 5.
- **`tool consent` repeated 5× in one dir** although `ui/prompt-builder.ts:601`
  offers "Allow `<kind>` this session": either the option is not offered for that
  kind or the grant does not stick. Not root-caused.
- **`untrusted package` repeated 4×** although the prompt offers `Trust: <pkg>
  (session)`: the click exists and did not land. Not root-caused.
- **`network egress` repeated 6× in one dir**: a destination-shaped answer
  ("this host is mine") is the right concept, and V-h's eligibility rule excludes
  it (a destination is not a location). Needs a new class of operator answer.
- **`full filesystem scan` (D9)** is the only other location-shaped class, so it
  is eligible by V-h's rule; 2 rows in the corpus is not a case yet.

## 10. Build order

1. store: `accreditedDirs` + `accreditDir` / `isAccredited` (+ read grant
   companion), cleared by `forgetLearnedReadDirs`; widget segment `R cred`; tests.
2. ceiling helper: name-shaped / pseudo-fs absolute, suffix-shaped liftable;
   tests pinning `.env`, `.env.production`, `id_rsa`, `/proc/<pid>/environ` never
   lift, and a private-key file lifting under a grant.
3. floor: bash branch (`gate/dspa-gate.ts:959`), file branch (`:874`);
   `decide/file-policy.ts` deliberately unchanged (§4.5). The offer dir rides
   the gate result (`accreditDir`), next to `writeOutside`/`confirmedOutside`.
   DONE (2026-11-16): the scan now also reports WHICH paths it matched
   (`CredentialFindings`) — a finding it cannot name suppresses both the
   clearance and the offer.
4. prompt: the new option in the grant tier, plain-words label; the `Always`
   suppression for credentials stays as-is (that is the §9 D-b item, not this one).
5. judge: stage-1 skip route + the stage-2 clause + verify the accredited dir
   reaches the grants block (`judge/session-context.ts:190`).
6. ledger L1 / L2 / L3 + every reader updated in the same commit.
   DONE (2026-11-16). Two vocabulary additions beyond §7's illustrative lists, both because the list could not name what actually happened: the slug
   `judge-unauthorized` (a verdict that approved above its stage's risk
   authority — filing it under `judge-declined` would blame a yes) and the
   `judgeSkipped` value `risk-tier`, set where the cascade holds an approving
   verdict — including the stage-1 approve that stage 2 (D22) never re-raised.
   `judge-failed` stays the one slug for "nothing vouched", with `judgeSkipped:
   "judge-off"` plus `stopDetail` naming why: the slug says what stopped the
   operation, the fields beside it say why that layer was silent. L1's `abort`
   also reaches `unresolved.jsonl`'s `decision` field.
7. docs in place: `docs/dspa-content-classes.md` (the C4 row + V-h eligibility
   rule), `docs/architecture.md` (glossary term, the floor class list, the
   "judge never grants over a bar" line), `docs/dspa-intent-floor.md` §6 D-a
   marked reversed-in-place + §9 additions, `docs/dspa-redesign.md` (D7/D11 marks),
   `CHANGELOG.md`.
   DONE (2026-11-16) except `CHANGELOG.md`: an entry there carries the release
   version and the frozen-ledger replay numbers, so it lands at the release
   commit, where the version bump happens. It must also stamp the ledger field
   switchover (`judgeDeny` → `judgeExplain`, the new `answer` / `stopClass` /
   `stopDetail` / `judge*` fields, the `abort` answer) — readers use live field
   names only, so a changelog reader is the only place that bridge exists.
8. re-scope the pinned safety probe (`docs/dspa-intent-floor.md:760` and its
   test): a widened read bar still moves no other bar — the accreditation is what
   moves the credential floor.
   DONE (2026-11-16): the probe lives in `test/dspa-gate.test.ts` ("the ceiling
   survives the grant"), and a second test now shares its fixture and
   discriminates the two operator answers — read grant alone (still stops, and
   names the dir it wants), accreditation (cleared), the V-c pair under the
   same accredited dir (`id_rsa`, `.env` — stopped, nothing offered), a write
   to the accredited cert (stopped). One correction worth keeping: `.env` was
   the obvious clearance case to reach for and is NOT one — an env file is
   name-shaped whatever it ends with (`ENV_FILE_RE` in
   `analysis/credentials.ts`), so the ceiling keeps it absolute. `ca.pem` is
   the case an accreditation can reach.

Pacing (standing rule for this repo): per stage = suite + the 62-row manual
corpus + the 31-row dspa floor; the 875-row frozen-ledger replay runs once, at the
release commit.
