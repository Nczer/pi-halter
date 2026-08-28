# Changelog

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
