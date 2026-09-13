# DSPA content classes — judge authority per operation class

Status: **resolved via grill and IMPLEMENTED** (2026-09-12, halter 3.24.0;
the exa-side T1 change ships in the exa ext). All decisions T1–T7 are final.
Supersedes in part: `dspa-redesign.md`'s "the file/consent gates are never
auto-allowed" (now class-dependent) and the absolute floor for
detection-limited stops. Everything in `dspa-redesign.md` not named here
stands.

## 1. Problem

Three observations from live `/dspa` use (llama-cpp Qwen judge):

1. **exa always paid full cost and always prompted.** exa is a consent-kind
   prompt; the floor never auto-allows consent; every stop is advisory (D16)
   → **both** judge stages ran on every search (two model calls, 3× timeout
   headroom) and the verdict was display-only. The judge saw only the
   120-char label — it could not actually check the query. Ledger line from
   the session: `exa/fetch text of 1 url` → s1 `approve/low`, s2 `deny/medium`
   — two calls, zero authority.
2. **The floor stopped what the judge would have approved.** 2026-08-24 log:
   the pre-D8 floor stopped 7 of 26 prompts while the judge stopped zero; D8
   already eroded the floor once for this. Detection-limited stops (obscured
   command position, unparseable) kept firing on commands whose full text was
   sitting in the judge's packet all along.
3. **Joplin's judge verdicts were useless.** The note id is an opaque
   reference; the note content never reaches the judge (tool outputs are
   deliberately excluded from stage-2 context). Judging the edit content was
   judging text with no referent — "intent without much context is
   impossible to judge". The content is recoverable (note version history,
   trash) and the human prompt is the right gate.

## 2. Principle — four operation classes

An operation's safety reduces to exactly one thing; that thing selects the
pipeline.

| class | safety reduces to | members |
|---|---|---|
| **C1 — content-determined** | the visible payload IS the effect | exa search/contents (T1); file write/edit (as-is) |
| **C2 — effect-extending** | payload is code; the effect reaches beyond the text | bash; script payloads (T3) |
| **C3 — context-dependent** | arguments are opaque refs; meaning comes from the session | joplin (T6) |
| **C4 — policy-absolute** | the user's call, never the judge's | egress bash (D14), outside-base scope (Q1), rm, credentials, unresolvable sentinels (D7) |

**The gate kind is the mechanism.** Tool plugins classify each call into a
kind that selects its class's pipeline — content-judge: `exec` (C2,
script payload) and `egress` (C1, outgoing payload); human-gated: `file`
and `consent` (C3). Classification is PER CALL, so a tool's actions mix
paths as their payloads demand (joplin: all consent; exa: all egress; a
tool may combine consent reads + exec actions + egress fetches) — grant
scopes stay separate per kind. Bash maps by command shape: plain commands
and fetch forms face C4 policy checks at the floor, everything else
judgeable (C2).

Stage 2's role follows from the classes: it is for operations that are
slightly risky or need more context before judgment can happen — C2 always,
C1 when stage 1 does not clear, C4 display-only.

## 3. Decisions

### T1 — exa becomes C1: new gate kind `egress`, judgeable

The plugin contract gains a fourth kind, `egress`: the call carries an
outgoing payload (a web search query, a url list) — data leaving the
machine. Rules:

- **Packet carries the full args** (query, urls, filters) — the judge must
  see exactly what goes out (payload identity for egress, the exec-gate rule
  applied to data egress). Today the judge sees only the 120-char label; a
  sensitivity check on a truncated query is not a check. Token cost is
  trivial (a query is short; a `contents` url list is ≤100 short urls).
- **Standard cascade**: floor passes (no deterministic floor on the payload —
  same as `exec`), stage 1 approve+low → auto-allow (one call, "it's just a
  websearch"); stage 1 not-low → stage 2 (context-aware; low|medium →
  auto-allow) — stage 2 is where "the user did not ask for this search"
  (reject/defer) and "this touches internal material" (tightening) live.
- **Grant**: `exa:kind:web` (the existing `<tool>:kind:<k>` shape) remains
  the override — one click, no prompts, no judge calls for the session.

Rejected alternative: **S2 as the egress authority** (S1 low routes to S2,
S2 alone auto-allows). Cost: two calls per clean search; and the stateless
content check is the right primary test for "does this payload contain
sensitive info" — session context only matters when stage 1 flags or cannot
vouch.

### T2 — Floor: detection-limited stops become judgeable

The floor's stops split into two classes:

- **Policy stops** — the floor encodes user policy, not a detection limit:
  network egress (D14), outside-base scope (Q1), dangerous rm, credential
  patterns, untrusted fetchable packages (D10), root scans (D9), unresolvable
  sentinels (D7). **Absolute** — never auto-allowed, both stages run
  display-only (D16 as-is).
- **Detection-limited stops** — static analysis is genuinely blind, the judge
  sees the same text with semantics: **obscured command position** (`f=rm;
  $f build/` — the assignment is in the packet) and **unparseable
  commands** (tree-sitter failed, the judge reads the raw text; the packet
  already carries the `parse error: yes` flag). These now **pass to the
  judge** with the normal cascade.

Rejected alternative: blanket "S1 approve+low overrides any floor stop". It
would hand egress and scope authority to the LLM (exactly what Q1 excluded)
and break the core invariant — a wrong verdict can at most produce a prompt,
never an auto-allowed op the floor forbids (the Claude Code classifier's
17% false-negative rate is the failure mode the floor backstops).

The sentinel escape is unchanged: D12 convergence (user-confirmed
resolutions) is how a D7 stop becomes a deterministic pass.

### T3 — Script payloads skip stage 1

Bash commands that execute a file script (`python file.py`, `./job.sh`,
`bash job.sh` — the `findExecutedScript` identification D3/D11 share) go
**straight to stage 2**: the class always escalates (slightly risky by
class), so stage 1 would only add a call. Stage 2 (low|medium) is the
authority; the writes report still feeds the D19 bar.

Acknowledged cost: the judge ledger loses stage-1-vs-2 `diff` lines for this
class — the disagreement signal that found D7–D12. Accepted: the class is
small relative to its cost, and stage-2 verdicts still log (`paths`,
auto-allow lines).

### T4 — Session-scoped consent prompts (C3)

Consent prompts change from "prompt every op until Always" to **one prompt
per kind per session**:

- The first prompt per kind per session asks "Allow <kind> this session?" —
  **yes IS the session grant**, no blocks that op.
- **Single tier** (no second confirmation): the explicit prompt text plus the
  session lifetime (grants die with the session, never persist) is the
  boundary. The two-tier confirm guarded a broad "Always" hidden among
  options; here the grant is the question.
- **The prompt names the model** (the trust decision — "the model could be
  trusted and is not incompetent" — is made at the prompt; today only read
  labels show the provider).
- Applies to every consent kind of every consenting tool (joplin
  read-remote / write / delete). **Identical in manual and dspa** — the
  consent store is mode-independent (already true).

### T5 — Consent grants reset on model switch

The consent trust decision is about a specific model. A mid-session model
switch (local → cloud, model A → model B) **resets all consent grants**; the
next op re-prompts. Consistent with the judge stats, which are already
model-scoped.

### T6 — Joplin stays C3; content-bearing pre-fetch rejected

Joplin read (remote-class readers) was considered for content-bearing
judgeability: `buildRequest` pre-fetching the note body into the packet
(payload identity), standard cascade. **Rejected**: the note content with no
referent is not judgeable — the judge cannot know what a note is about, only
that its text looks safe or not; "S1 low → auto-allow" on the bare label
degenerates into a judge-mediated session grant (weaker than the human's
Always, plus a model call). The local/cloud reader distinction
(`localProviders`, fail-closed) already enforces the egress policy at class
level; the human prompt enforces the trust decision (T4/T5). Local readers
keep ungated reads (as-is); writes/deletes consent for every reader (as-is,
now session-scoped via T4).

### T7 — Parked: destructive content-bearing tools

A hypothetical future tool with a visible high-risk payload (e.g. "delete all
notes") would map to **judgeable with authority = never** (the file-gate
shape — judge scrutinizes and renders, the human always decides) or a C4
policy stop. Decide when such a tool exists.

## 4. Unchanged (confirmed in the grill)

- **C4 / D13 / D19**: the stage-2 path report is a shadow measurement —
  cross-checked against the floor's knowledge, mismatches logged
  (`floorMisses` = paths the judge saw that the floor never saw), both sides
  on the ledger line for fault attribution. The deterministic analysis stays
  the decision authority; the one deliberate feed is the `writes` subset →
  D19 write bar (narrowing only, never a false allow, per-run, nothing
  persisted).
- **D3/D11 conversions** (manual write auto-allows judged; bash script
  payloads converted).
- **dspat** (both stages, display, cross-check data), **Judge-again** retry,
  stop classification/counters, ledgers.
- **C1 file write/edit**: standard cascade as-is (S1 low auto-allows).

## 5. Grill trail (condensed)

- User: exa "often goes to stage 2" — why not "just judge if the content
  contains sensitive info"? → root cause: consent never auto-allows +
  advisory stops run both stages + the judge only saw the 120-char label.
- User: "stage 2 is for anything slightly risky or requiring more context";
  scripts "go to stage 2 anyway, stage 1 may be skipped entire" → T3, and the
  stage-2 role statement in §2.
- Floor: user "even considering allow, low risk to be able to skip floor, as
  floor may classify totally safe command as non-safe" → resolved as T2
  (detection-limited only; policy stays absolute) after the 2026-08-24
  data (floor 7/26 stops, judge 0) was surfaced.
- Egress authority: user "S1 low auto-allows, I don't see S2 being called
  necessary here, it's just a websearch" → T1 (Row B), S2 guards the
  not-low path.
- User: "we need different models for halter: 1. local/cloud difference …
  joplin … write edit being judged is not useful for notes, as intent without
  much context is impossible to judge; 2. whole content / content-bearing /
  selected tools judgeable — exa" → the four classes, T6.
- User: "prompt once for all edit/delete when the model could be trusted and
  is not incompetent, same for manual and dspa" → T4 (session-scoped,
  single-tier, names the model).
- User confirmed the consolidated design 2026-09-12, incl. the three flagged
  calls (egress kind, single-tier prompt, model-switch reset).
