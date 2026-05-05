# Changelog

## 3.1 — Path containment hardening + Symlink defense + Bash allowlist audit

### Security hardening

- **Symlink TOCTOU defense**. `resolvePathReal()` now walks up the directory tree for non-existent paths, resolving any parent directory symlinks before re-appending the non-existent suffix. Prevents symlink swap attacks where a path is checked before the target symlink is created.
- **Single path containment helper**. Replaced three divergent implementations (`startsWith(d + "/")` in `isInsideAutoAllowedDir`, `path.relative` in `isInsideCwd`, mixed in `isProjectPiPath`) with a unified `isChildOf(child, parent)` helper using `path.relative`. Eliminates audit complexity and prevents future logic drift.
- **`homePiDir` normalization fix**. `isProjectPiPath` now resolves `~/.pi` through `resolvePathReal()` instead of using `path.join()`, preventing mismatches when `~/.pi` is a symlink.

### UI improvements

- **Symlink hint in file prompts**. When a path resolves through a symlink, file prompts now show `🔗 Resolved via symlink: original → resolved` so the user can see the actual target location.
- **Optimized auto-allowed dir check**. `isInsideAutoAllowedDir` now does an O(1) `Set.has()` exact match before iterating, avoiding unnecessary `path.relative` calls for commonly allowed paths.

### Bash allowlist changes

- **Added ~36 safe commands** to `allowedBashPatterns` across 6 categories: text processing (`tac`, `rev`, `nl`, `fold`, `expand`, `fmt`, `join`, `comm`, `paste`, `column`, `seq`), hashing/binary inspection (`md5sum`, `sha*sum`, `cksum`, `hexdump`, `od`, `strings`), system info (`pwd`, `date`, `whoami`, `id`, `uname`, `hostname`, `groups`, `printenv`, `uptime`, `tty`, `tput`), disk/process inspection (`df`, `du`, `free`, `ps`, `pgrep`, `pidof`), command lookup (`which`, `command`, `type`, `hash`, `whence`), safe creation (`mkdir`, `touch`, `mktemp`), calculator (`bc`, `expr`, `factor`, `yes`).
- **Removed `split`, `shuf`, `xxd`** from allowlist — all can write files via built-in flags (`split` creates chunks, `shuf -o` writes output, `xxd -r` writes raw binary) without using shell redirects, bypassing the redirect safety check. Kept in `pathAwareCommands` so their file arguments are still tracked in permission prompts.
- **Updated `pathAwareCommands`** to include newly allowlisted file-taking commands (`tac`, `rev`, `nl`, `fold`, `join`, `comm`, `paste`, `split`, `shuf`, `md5sum`, `sha*sum`, `cksum`, `xxd`, `hexdump`, `od`, `strings`, `mkdir`, `mktemp`) so their path arguments trigger outside-cwd permission checks.

### Reduction in prompt fatigue

- Routine inspection commands (`df`, `du`, `ps`, `pwd`, `date`, `which`, etc.) now auto-allow when simple, reducing unnecessary prompts for standard development workflows.

***
## 3.0 — Custom selector + No (with reason) + Always (this file only)

### New features

- **No (with reason)**. All prompts now include "No (with reason)" option. Opens a text editor for user to specify rejection reason, included in the block message returned to the LLM. Escaping the reason editor returns to the selector.
- **Custom selector UI**. Replaced `ctx.ui.select` with a custom component (following ask_user_question pattern). Cyclic navigation (↑ from first wraps to last, ↓ from last wraps to first). Consistent styling with borders and help text.
- **Always (this file only)**. File prompts outside cwd now include "Always (this file only)" option. Auto-allows just this specific file for the session, not the entire directory. Other files in the same directory will still prompt.

### Bug fixes

- File tier-2 confirmation now shows actual directory path (`Confirm Always Allow: Edit /tmp`) instead of generic `Edit this dir`.

### Code cleanup

- Unified prompt body formatting across bash, file, and subagent (all have trailing newline for separator).
- Unified tier-2 confirmation body formatting (all use `\n\n"Back" returns...` pattern).
- Removed unused imports from selector.ts.

### Prompt layout

- **Title above separator**. All prompts now show title first, then `---`, then body. Easier to scan at a glance.
- **Deduplicated danger flags**. `rm` no longer shows both "rm (file deletion)" and "rm (any file deletion)" — token-based analysis defers to regex pattern for rm/rmdir/unink.

***
## 2.4 — Prompt UI overhaul

### Behavior changes

- **Prompt highlights non-permitted segments**. All segments are shown, but only those that triggered the prompt get a ⚠️ marker for quick visual scanning.
  - `find sth && ls sth2 && rm -r sth3` → all 3 shown, only `rm -r sth3` marked ⚠️
- **Store filters allowlisted signatures**. Commands in `allowedBashPatterns` are not stored, keeping the widget lean.

### Prompt UI improvements

- **Title reflects prompt type**. Shows "Path", "Bash" or "Bash + Path" instead of always "Bash".
- **Body shows essential info only**. Command, outside paths, danger flags, chain segments. Removed redundant cwd and help text.
- **Segment markers aligned**. ⚠️ placed after the number (`3. ⚠️ rm -rf`) instead of before (`⚠️ 3. rm -rf`) for consistent alignment.
- **Tier-2 confirmations show actual paths**. "Confirm Always: rm -rf + /tmp" instead of "rm -rf + 1 dir(s)".
- **Tier-2 confirmations include danger flags**. Warning section shown for dangerous commands.
- **Path-only prompts show correct confirmation**. "Confirm Always Allow: /tmp" instead of empty "Confirm Always Allow: ".
- **Directories stored correctly**. `ls /tmp` stores `/tmp`, not `/` (was using `path.dirname()` incorrectly).

### File prompt improvements

- **Simplified file prompts**. Match bash prompt style: just path and outside-cwd warning.
- **Consistent title format**. "⚠️ Edit outside cwd" instead of "⚠️ Edit outside cwd: /full/path".

### Subagent prompt improvements

- **Simplified subagent prompts**. Match bash/file prompt style for consistency.

### Bug fixes

- Fixed body not rendering (ctx.ui.select doesn't support body argument — body now prepended to title).
- Fixed path-only tier-2 confirmation showing empty command list.
- Fixed outside directory computation returning parent instead of the directory itself.

***
## 2.3 — Architecture deepening

### New modules

- **`prompt-flow.ts`** — Centralized prompt interaction loop. `showPrompt(decision, ctx, store)` owns building the prompt, displaying it, mutating the store on "always", and updating the widget. Handlers no longer orchestrate UI logic.
- **`widget.ts`** — Extracted TUI rendering from `permission-state.ts`. All widget drawing lives here.
- **`config/`** — Split monolithic `config.ts` into focused sub-modules: `thresholds.ts`, `bash-patterns.ts`, `path-rules.ts`, `dangerous-patterns.ts`, barrel `index.ts`.

### Refactored modules

- **`command-analysis.ts`** — Unified "fat analyzer". Merged `path-analysis.ts` path extraction into `analyzeCommand()`. Single tokenization pass, single result. `path-analysis.ts` shrunk to pure path utilities.
- **`decision-engine.ts`** — Pure policy function `decide(request, store) → Decision`. No UI dependency. Store injected for testability. Filters allowlisted signatures before storing (avoids cluttering store with `ls`, `find`, etc. that auto-allow via static rules anyway).
- **`prompt-builder.ts`** — Pure formatter `buildPrompt(PromptDecision) → BuiltPrompt`. All prompt wording centralized here.
- **`prompts.ts`** — `twoTierAlwaysPrompt` now consumes `BuiltPrompt` directly instead of raw strings + callbacks.
- **`store.ts`** — `Store` interface + `createStore()` factory. One implementation for runtime and tests. No duplication.
- **`permission-state.ts`** — Thin re-export hub + `resetState()` for session lifecycle.

### Handler simplification

- **`handlers/bash.ts`** — ~100 lines → 51 lines. Single `showPrompt()` call replaces `buildPrompt` + `twoTierAlwaysPrompt` + inline store mutations.
- **`handlers/file.ts`** — Same reduction. Pre-validation of edit calls preserved.
- **`handlers/subagent.ts`** — Same reduction.

### Behavior changes

- **Store no longer keeps allowlisted signatures**. `find sth && ls sth2 && rm -r sth3` now stores only `rm -r` (not `find`, `ls`). Widget shows only non-trivial allowances.
- **No functional changes** to permission decisions, prompt wording, or auto-allow semantics.

### Testability

- **Decision engine** — unit-testable with `createStore()` fake (no UI dependency)
- **Prompt builder** — pure function, testable in isolation
- **Command analysis** — pure function, testable in isolation
- **Path utilities** — pure functions, testable in isolation
- **Store** — factory pattern enables deterministic test state
