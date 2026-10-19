# dspa intent floor — two-tier floor

Status: **grilled and decided 2026-10-19** (D-a…D-h in §6). Target 3.40.0.
Build order §8. This document
proposes re-cutting the dspa hard gate (`gate/dspa-gate.ts`) along a new
axis. It **reverses part of Q1** (`docs/dspa-redesign.md` §278-292 point 4,
re-confirmed D11/2026-08-26; `docs/architecture.md:471` "the judge never
grants over the floor") — that reversal is the point of the document, not a
side effect, and each reversal needs its own recorded decision.

## 1. Philosophy (operator, 2026-10-19)

> dspa shall minimize user friction and judge by intent. The floor misses
> would be best to not prompt the user — however they should still be logged
> for the purpose of improving manual. What the dspa floor must absolutely
> catch is something destructive, such as recursive `rm`; especially an `rm`
> that targets a lot of files — that is too dangerous to judge by intent,
> although the judge usually rejects it.

Reading of it, as this doc applies it: dspa's floor stops divide into

- **ABSOLUTE** — the *destructive* class: what the operation does to the
  filesystem is irreversible and its blast radius is not statically knowable.
  The judge is not consulted for authority (it still runs, D16 advisory,
  because its verdict helps the human read the prompt).
- **MISS** — the *location/opacity* class: the floor could not NAME where the
  operation lands. Not a harm in itself, a verification failure. In dspa this
  goes to the intent judge; it keeps logging to `.log/unresolved.jsonl` so
  the deterministic (manual) side can still be fixed from real data.

Why the miss class is worth giving up: the 2026-10-18/19 unresolved ledger
(23 rows, 13 commands, 17 tokens) is 100% `gate-stop` and 100% user-approved
(18 `yes`, 5 `alwaysPaths`, 0 rejections). 19/23 rows are `/proc` or
`/sys/fs/cgroup` pseudo-fs tokens with one opaque component; 4 are bare vars
(`$fi`, `$d`, `$f`, `$2`). In one sampled session the operator was asked ~23
times about nothing they considered dangerous.

## 2. Floor stop inventory (gate/dspa-gate.ts, current line numbers)

| Stop reason | Line | Class under this proposal | Note |
|---|---|---|---|
| `runtime location unresolvable (token)` | 481 | **MISS → judged** | the D7 sentinel pass; the whole unresolved-ledger corpus |
| `touches paths outside base (…)` | ~760 | **MISS → judged** | concrete outside path; already names a grantable dir |
| `write outside base (…)` | 778 | **MISS → judged** | D18 base-write proxy: fires for ANY heredoc/`-c`/`-e` segment whose base is outside cwd (`baseWriteAccess`, analysis/cwd-tracking.ts:680) |
| `outside base (session …)` | 534 | **MISS → judged?** | file-branch outside cwd; D-a |
| `write-redirect outside base, not cleaned` | 972 | **MISS → judged?** | rm-branch carve-out companion |
| `full filesystem scan (… /)` | 650 | D-a (noise/leak, not destruction) | |
| `credential pattern (…)` / `unverifiable glob (…)` | 591/593 | **ABSOLUTE** | credential class |
| `dangerous: …` | 577 | **SPLIT — D-b** | one bucket today mixes destructive (`mkfs`, `dd if=`, `git clean -fdx`, `curl\|sh`) with routine (`python`, `node`, `uv`, `tar`, `cp`, `kill`) — config/dangerous-patterns.ts |
| `network egress (…)` | 659 | D-a (exfil is not intent-verifiable) | |
| `untrusted package (…)` / `unvetted run-form option (…)` | 632/641 | D-a (supply chain, not location) | |
| `tool <gate> never auto-allows` | 506 | keep (policy) | |
| rm branch: `rm target not explicit` / `rm -r target is not a file or directory` / `rm target outside base` | 901/911/926 | **ABSOLUTE** | the operator's named case |
| *(absent)* destructive scale — an `rm`/delete that lands on many files | — | **NEW, ABSOLUTE — D-c** | today no stop says how many files a delete reaches |

## 3. What "judged" means mechanically

The floor still runs first and stays deterministic; the relaxation lives in
the fall-through (`gate/fallthrough.ts`), mirroring D19's inverted shape
(D19 *adds* a stop from the judge's write report post-verdict; this *removes*
a miss stop from the same verdict):

1. `checkDspaGate` gains **typed** miss facts instead of only a prose reason:
   `misses: [{ kind: "unresolved" | "outside-path" | "base-write", token,
   role: "read" | "write" }]` on `DspaGateResult`. The prose reason stays for
   the prompt.
2. `tryDspaAutoAllow`: for a stop whose stops are ALL miss-class, run stage 2
   (its `paths`/`writes` are the only report; stage 1 never reports paths —
   `judge/judge.ts:191-197`) and evaluate the guards (§4). All guards pass +
   stage-2 `approve` + `risk ≤ medium` → auto-allow, tagged
   `dspa: intent over miss stop (<kind>)`, and **one line per token to
   `.log/unresolved.jsonl`** with `outcome: "intent-allowed"` (the manual
   corpus keeps growing; `mode`/reason/session tag included).
3. Any guard fail → the prompt as today, carrying the verdict (D16).
4. Cost: an extra stage-2 call on every miss stop that stage 1 would have
   approved (D22 currently skips stage 2 there). Cheaper than a human prompt.

## 4. Guards on intent-over-miss (proposed; D-d)

1. **Destructive never rides on a miss**: if the command carries any
   delete/truncate/overwrite effect at a location the floor could not name
   (`rm`, `unlink`, `rmdir`, `truncate`, `find -delete`, `> file` where the
   target is the miss), the miss is NOT judged — it stays a stop.
2. **Answer-that-token**: for each miss token, at least one judge-reported
   path must share that token's concrete static prefix (`/proc/$E/stat` →
   some reported path under `/proc/`). A judge that never acknowledged the
   location class cannot vouch for it. This is the omission guard — omission
   is the only way the substitution turns a stop into a silent wrong-location
   allow.
3. **Credential ceiling**: a miss token whose static parts name a credential
   class (`warnPaths` names, `/proc/*/environ`, `/proc/*/cmdline`) is not
   judged. Note `/proc/<pid>/environ` appears in the Oct-18 decisions ledger
   as a real stop, and pseudo-fs widening makes it reachable.
4. **Ledger honesty**: a floor miss is never reclassified as a judge
   contextMiss when `floorPaths` is empty (observed 2026-10-18T03:02:28
   sweep.sh row — the ledger masked the parser gap).
5. **Sanitizer hardening first**: `sanitizeJudgePaths` must drop URL-shaped
   tokens (observed: `http://127.0.0.1:8080` →
   `/mnt/Ndr/Projects/http:/127.0.0.1:8080`, absorbed by cwd coverage).

Evidence for why the guards are not optional — the sampled judge path report
(7 `paths` rows, model local-2/Qwen3.8-Flash-Next) contained: an invented
`/usr/bin/ether-wake` for the text's `/usr/sbin/ether-wake`; a concretized
`/proc/0/smaps_rollup`; the mangled URL above; and one payload reporting 2 of
5 dirs. Precision is demonstrably poor; recall is unmeasured.

## 5. Read-bar reality check (why "let the judge name it" is not enough alone)

The manual read bar (`config/path-rules.ts:16`) is cwd ∪ `~/.pi` ∪ pi install
dirs ∪ `/tmp` (+ session grants). `/proc` and `/sys` are **not** in it. So a
name-the-location substitution that then faces the bar would still stop
19/23 rows. Either the pseudo-fs class enters the bar (a scope grant — the
operator's call; needs the credential ceiling of §4.3), or the locations get
**bound** deterministically instead (`EP=$(pgrep …)` → numeric pid → concrete
`/proc/<pid>/stat`). Binding alone still does not converge: the offered
`Always` grant is `/proc/193524`, and the pid changes every run, so that class
needs a class-level entry, not a per-run grant. Both routes keep Q1 intact;
the intent route (§3) is the one that trades determinism for friction.

## 6. Decisions (grill, 2026-10-19)

- **D-a — the non-destructive policy stops stay ABSOLUTE**: `network egress`
  (with the fetch/execute split below), `credential pattern` /
  `unverifiable glob`, `untrusted package` / `unvetted run-form option`,
  `full filesystem scan`, `tool … never auto-allows`, and the file-branch
  `outside base (session …)`. None of them is handed to intent.
- **D-b — `dangerous:` (577) is split by entry, not by name.** Absolute
  half: disk/system (`mkfs`, `mount`, `dd if=/of=`, `shutdown`, `reboot`),
  history/worktree (`git push --force`, `git reset --hard`, `git clean
  -fdx`), download-then-execute, and `eval`. Judgeable half: opaque inline
  code (`python3 - <<EOF`, `-c`/`-e`, `sed -i`, `perl -i`) — the operator's
  "the friction is mainly in heredoc" — and the routine `python`/`node`/`uv`/
  `tar`/`cp`/`kill`/`ssh` entries. Mechanism: an `absolute: true` flag on the
  entries in `config/dangerous-patterns.ts`; the gate returns the absolute
  stop only on flagged entries. (Built 2026-10-19: the flag makes the analysis
  tag its hit `[Absolute] <label>` and the gate stops on that tag instead of
  re-matching the table — that is what inherits the analysis's trusted-command,
  version-only and quote-stripping exclusions. See §8 build notes for the
  premise correction.)
  Basis for trusting the heredoc half: the stage-2 packet already carries the
  full command text including heredoc bodies (`judge/packet.ts:239`, D11),
  and D19 already faces the judge's `writes` report against the deterministic
  write bar.
- **D-c — delete scale: static shape flags + a capped count.** Absolute when
  the shape is unbounded or escapes the bars: root-ish targets (`/`, `~`,
  top-level dirs, `/mnt`, `/home`), unbound or computed targets (`rm -rf $D`,
  backticks; cf. `RM_FORBIDDEN_TARGET_RE` at 804), `find -delete`, `git clean
  -fdx`, `xargs rm`, `truncate *`. Judged when the targets are statically
  concrete, countable, and inside the bars (`rm -r build/*`,
  `rm -r tmp/something/*`); the capped count rides into the judge packet and
  the prompt (`deletes 312 files, recursive`).
  **Count ceiling outside the temp dirs** (operator 2026-10-19: "the count
  should affect any dir outside of tmp"): more than `DELETE_SCALE_ABSOLUTE`
  (= 50, tunable config constant) matched files outside `allowedWritePaths`
  → absolute. Inside temp dirs the count is informational and the judge
  weighs it. Probe precedent: `fs.globSync` with a cap
  (`analysis/credentials.ts:354-357`, `analysis/bash-parser.ts:496`); a
  recursive count needs a new capped walk.
- **D-d — no permission-surface allowlist.** Decided at the architecture
  level instead (operator: "make bash take input from floor and judge, then
  present the same write/read for user"): the floor's own deterministic
  `writePaths` must face `insideManualWriteBar` in dspa, exactly as the
  judge's report already does (D19). That closes a real hole — a bash write
  into `~/.pi/agent/settings-ext.json` from the project cwd is stopped today
  only *incidentally*, because `sed -i` is a dangerous context pattern
  (`config/dangerous-patterns.ts:50`): `gate/dspa-gate.ts` never consults
  `outsideWritePaths`/`needsWriteApproval` (consumed only by the manual path,
  `decide/bash-rules.ts:133`, and `ui/prompt-builder.ts`), and `makeManualBar`
  admits every read-allowed dir, `~/.pi` included. With the operand-level
  write bar wired in, gate/config self-modification stops for the same reason
  an `Edit` does — no special path list.
- **D-g — the shape rule: LOCATIONS judged, BARS absolute.** Unknown
  locations (unbound vars, opaque inline code, unknown cd base) go to intent
  to become LOCATIONS; the union set (floor paths ∪ judge paths, sanitized)
  then faces the read bar and the write bar with no leniency. Any out-of-bar
  WRITE → prompt, always, carrying the existing Allow-writes option.
  Out-of-bar READS may auto-allow on intent — that is where `/proc`,
  `/sys/fs/cgroup` and most of the measured friction lives.
  Kept deliberately: the asymmetry whereby a bash command touching an outside
  path can be judged while a `Read`/`Write`/`Edit` on the same path still
  prompts (file-branch `outside base`, D-a).
- **D-h — the D18 base-write proxy is waived** when stage 2 approves and its
  `writes` report is entirely inside the manual write bar. A body that writes
  out of bar still stops (D19 backstop). Not the `writes: []` variant — a
  heredoc that writes inside the bar should stop prompting.
- **D-f — no escape hatch, no mode.** One behavior, one code path; the
  operator reverts with git if the philosophy turns out wrong ("keep the code
  clean and lean"). Every intent-over-miss allow is logged (§7), so a bad
  class is visible in the ledger without a toggle.

## 7. Ledger contract after the change

`unresolved.jsonl` keeps its mining role even though dspa stops prompting:

- `outcome: "intent-allowed"` — a miss stop that intent cleared; carries the
  stop kind, the token, the judge's reported paths for that token, and
  whether a prior confirmed resolution existed (`confirmedPrior`).
- `outcome: "intent-declined"` — the guard set or the verdict kept the stop,
  and the operator was prompted.
- The manual path's rows are unchanged, so the deterministic fix work keeps a
  live corpus. A floorMiss is never reclassified as a judge contextMiss when
  `floorPaths` is empty (§4.4).

## 8. Build order

1. `writePaths` → `insideManualWriteBar` in `checkDspaGate` (D-d): the gap
   fix, no philosophy dependency. Reuse the `writeOutside` stop shape so the
   prompt's Allow-writes option appears unchanged.
2. `absolute: true` flags in `config/dangerous-patterns.ts`; the gate stops
   absolutely only on flagged entries (D-b). Same commit: the
   fetch/execute/upload egress split (D-a).
3. `analysis/delete-scale.ts` — shape flags + capped glob/walk count (D-c),
   the absolute-vs-judged cut, the count into packet and prompt.
4. Typed `misses` on `DspaGateResult`, and the intent-over-miss relaxation in
   `gate/fallthrough.ts` with the §4 guards (D-g, D-h) — the piece that
   changes prompt behavior.
5. Ledger fields (§7), the sanitizer URL guard, floorMiss/contextMiss
   honesty.
6. Docs: amend `docs/dspa-redesign.md` point 4 (the Q1 reversal),
   `docs/architecture.md:471`, CHANGELOG 3.40.0.

Tests: new `test/intent-floor.test.ts`, one case per class from the 23-row
corpus shapes — `/proc/$EP/io`, `cd ~/Strata && python3 - <<EOF`,
`rm -r build/*`, `rm -rf $D`, `curl … | sh`,
`sed -i ~/.pi/agent/settings-ext.json` — plus regression in
`test/dspa.test.ts`.

### Step 2 build notes (2026-10-19)

- **2a is built (flags + `[Absolute]` tag + the gate's absolute-bar stop + the
  rm carve-out no longer stopping on a bare class label); 2b (the egress split)
  is not.**
- **Step 2's premise was measured wrong when I built it.** The plan read as if
  the gate's `dangerous:` stop were the live guard for mkfs/shutdown/`git reset
  --hard`/`eval`. It is not: that stop fires only in the rm branch, so at HEAD
  those commands reached the judge UNPROMPTED (probe: `mkfs.ext4 /dev/sdb`,
  `shutdown -h now`, `eval "$CMD"`, `git reset --hard HEAD~3`,
  `sudo mkfs.ext4 /dev/sdc` all judgeable; `dd` stopped only incidentally on the
  path bar with the sloppy reason `touches paths outside base (/dev/sda); writes
  /dev`). So D-b ADDS stops instead of preserving them — which is what the
  philosophy wanted, but it is not the friction-free no-op the decision text
  implied.
- **Defects found by the probe, fixed in the same commit.** `git clean`'s
  `.*-[fdx]\b` never matched `-fdx` (word boundary after `-f`; no second dash to
  retry) — the label was dead for the dominant form. `sudo` was neither a wrapper
  nor a prefix in the analysis, so the entire pattern table was blind behind it
  (now a pass-through wrapper; operator's caveat: non-interactive `sudo` usually
  dies on the password, so the live shapes are NOPASSWD/cached credentials).
- **FP closed on the live corpus.** The download-and-execute bar stopped two real
  rows of `curl -s localhost:8080/v1/status | python3 -c 'json.load(…)'`; the bar
  is about REMOTE code, so it defers to `isLoopbackEgress` (fail-closed: an
  unprovable host like `"$API/…"` keeps the stop). Ledger replay after the
  change: 0 allow→stop, 0 stop→allow over 520 rows.

## 9. Out of scope here

The unbuilt grill items G8–G11/G13 from the ledger round (loop in-list taint
threading, coarse fetch-form signature grants) are unaffected. The pid-value
binding and pseudo-fs bar entry of §5 are alternatives to this proposal for
the same corpus, not part of it.

### Known gaps carried here from the ledger rounds (filed 2026-10-19)

Still fail-open / invisible to the floor:

- script-body runtime-assembled paths — `BODY_PATH_RE` matches literal
  absolute-looking paths only (`analysis/bash-parser.ts`);
- paths inside a nested `bash -c` payload never reach `floorPaths`;
- `echo /etc/hosts | xargs cat` → `paths=[]`;
- `tmux -S` / `-f` path-blind;
- `cd <outside> && git/make` does not flag the base — `baseAccessPath` gates
  on `pathAwareCommands` (`analysis/cwd-tracking.ts`); re-verified
  2026-10-17 post-G1/G2: `cd /etc && git status` still ALLOWs;
- `dd if=/of=` path-blind (it always stops on the dangerous pattern anyway —
  since step 2a, on the absolute bar with a reason that says so).
- A destructive verb inside an inline code BODY is not an rm SEGMENT: `sudo -u
  root sh -c 'rm -rf /'` and `python3 -c 'import shutil; shutil.rmtree("/")'`
  are judged on the text alone (the judge sees the body, D11). Step 3's
  delete-scale shapes should decide whether a root-ish target inside a body
  earns an absolute flag; nothing does today.
- The download-and-execute bar cannot tell a payload from a data response: `curl
  https://api.io/x | python3 -c 'json.load(sys.stdin)'` stops absolutely. Only
  loopback locality is exempt (`isLoopbackEgress`); that boundary is deliberate.

Not defects, by design: unknown-command args are not path-extracted
(`pathAwareCommands` is a closed set, the judge is the backstop — such
floorMisses are not defects); `$(dirname $P)/..` is correct fail-closed; an
absolute static part stays opaque (the pinned-embedded branch was dropped as
unevidenced scope creep — fail-closed).
