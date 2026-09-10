import path from "node:path";
import type {PromptDecision, PromptData, BashPromptData, FilePromptData, ToolPromptData} from "../decide/types";

import { formatBashCommand, isTmuxCommand, truncateSegmentDisplay } from "./tmux-render";
import { shortenToken } from "../analysis/path-util";
import { isGlobUnverified, globUnverifiedToken } from "../analysis/credentials";
import type { ResolutionMap } from "../judge/path-resolver";

// ── Output types (match twoTierAlwaysPrompt's expected inputs) ──

export interface BuiltPrompt {
  title: string;
  body: string;
  tier2Everything: { title: string; body: string };
  tier2Paths?: { title: string; body: string };
  tier2File?: { title: string; body: string };
  tier2Broader?: { title: string; body: string };
  includePathsOption: boolean;
  includeFileOption: boolean;
  includeBroaderOption: boolean;
  includeAlwaysOption: boolean;
  /** Labels for "Always" choices (e.g. "npm test *", "/path/*") */
  alwaysLabel: string;
  alwaysPathsLabel?: string;
  alwaysFileLabel?: string;
  /** Broader parent-directory alternatives for file prompts (1–3 levels up);
   *  pre-filtered — entries already covered by a standing session grant are
   *  dropped (re-granting a subset of a grant is noise, not a choice). */
  broaderPaths?: { label: string; dir: string }[];
  /** File prompt parent-hierarchy layout: outside-cwd (primary = the
   *  outside-dir grant) vs inside-cwd (primary = the file grant). */
  fileHierarchy?: "inside" | "outside";
  /** File prompt: the primary/path Always option's scope is already covered
   *  by a standing session grant — suppressed. */
  pathOptionCovered?: boolean;
  /** File prompt: the file option's scope is already covered — suppressed. */
  fileOptionCovered?: boolean;
  /** Whether the operation is a write (vs read) — used for accurate prompt text. */
  isWriteOp?: boolean;
  /** D10: bare package names of fetchable run forms in the command — tier-1
   *  offers a "Trust" option (session grant) when set. */
  trustPackages?: string[];
  /** Directories the "Always (paths)" option would grant — the concrete
   *  outside-cwd dirs plus any LLM-resolved token dirs (bash prompts only;
   *  empty elsewhere). The prompt flow grants EXACTLY these on that option. */
  pathGrantDirs: string[];
  /** The LLM-resolved token dirs included in pathGrantDirs (absent when the
   *  resolver ran nothing or found nothing) — persisted as confirmed
   *  resolutions when the user accepts a paths grant. */
  resolverDirs?: string[];
}

/**
 * Short target label for PromptData — one shape, used by the /dspa and
 * /dspat widgets, their audit lines, and the /dspat disagreement stats.
 * (The decision log has its own request-shaped targetOf, which also covers
 * blocks; this is the prompt-shaped one.)
 */
export function pdTargetLabel(pd: PromptData): string {
  if (pd.type === "bash") return pd.command;
  if (pd.type === "file") return `${pd.action} ${pd.resolved}`;
  return `${pd.tool}/${pd.label}`;
}

/**
 * One-line "why did this prompt" summary (the useful half of PromptData).
 * Used by the decision log (decision-log.ts).
 */
export function summarizePrompt(decision: PromptDecision): string {
  const p = decision.promptData;
  if (p.type === "tool") {
    return `tool ${p.gate}${p.consentKind ? ` (${p.consentKind})` : ""}`;
  }
  if (p.type === "bash") {
    const parts: string[] = [];
    if (p.credentialRule) parts.push(`credential ${p.credentialRule}`);
    if (p.riskSeverity) parts.push(`risk:${p.riskSeverity} ${p.riskReasons.join("; ")}`);
    if (p.hasUnsafePattern) parts.push("unsafe pattern");
    // (unlisted): command approval is required but no segment carries a
    // namable signature (e.g. a relative-path binary whose basename is
    // allowlisted — the prompt still fires on the unallowlisted first word).
    // Relative-path tools are named via their cwd-bound grant identity.
    if (p.needsCommandApproval) {
      const named = p.signatures.length > 0
        ? p.signatures.slice(0, 3).join(",")
        : (p.relativeToolIds?.length ? `${p.relativeToolIds.slice(0, 3).map(r => r.sig).join(",")} (unlisted)` : "(unlisted)");
      parts.push(`cmd ${named}`);
    }
    if (p.needsPathApproval) {
      const dirs = p.outsideDirs.slice(0, 3).join(",");
      const unres = (p.unresolved ?? []).slice(0, 3).map(u => shortenToken(u.token)).join(",");
      if (dirs && unres) parts.push(`outside ${dirs}; unresolved ${unres}`);
      else if (dirs) parts.push(`outside ${dirs}`);
      else if (unres) parts.push(`unresolved ${unres}`);
    }
    return parts.join("; ") || "unclassified";
  }
  // p is a file prompt (bash/tool returned above)
  let s = p.isWriteOp ? "file write" : "file read";
  // outsideDir is the target's own parent (the grant-offer unit) — name
  // it as the location, not as the thing the file is outside of.
  if (p.outsideDir) s += ` outside cwd (${p.outsideDir})`;
  if (p.warnedRule) s += ` warn ${p.warnedRule}`;
  return s;
}

/**
 * Format a PromptDecision's structured data into title/body strings
 * for the two-tier prompt flow. All prompt wording lives here.
 */
/**
 * `resolutions` — token → runtime dirs from the path resolver (LLM) and/or
 * the gate's confirmed resolutions; `confirmedTokens` marks which of them
 * are user-confirmed (deterministic) rather than LLM-suggested — the body
 * labels them differently.
 */
export function buildPrompt(
  decision: PromptDecision,
  resolutions?: ResolutionMap,
  confirmedTokens?: Set<string>,
  /** A dir is "covered" when a standing session grant already covers it —
   *  file prompts suppress Always options whose scope is covered. */
  isCovered?: (dir: string) => boolean,
): BuiltPrompt {
  const { promptData } = decision;

  switch (promptData.type) {
    case "bash":
      return buildBashPrompt(promptData, resolutions, confirmedTokens);
    case "file":
      return buildFilePrompt(promptData, isCovered);
    case "tool":
      return buildToolPrompt(promptData);
  }
}

// ── Bash prompt ──

/**
 * Truncate a long multiline command to keep the prompt compact.
 * Shows first HEAD_LINES lines, ellipsis, last TAIL_LINES lines.
 * Full command is visible in chat history above the prompt.
 */
/**
 * Render risk reasons. Grouping is only for order and merging: [Pattern]
 * leads (the class reason — why this command prompts at all), then the
 * other source tags in first-seen order, untagged last; single-line
 * reasons of one group MERGE into one line ("recursive delete (-r/-R),
 * forced delete (-f)"), multi-line reasons keep their own block. The tags
 * themselves are NOT rendered — every reason names its own command/flag,
 * so the prefix is noise in the prompt (the tags stay in the stored
 * reasons, where the log and the rejection message use them).
 */
function riskReasonLines(reasons: string[]): string[] {
  const groups: { tag: string; items: string[] }[] = [];
  const groupOf = (tag: string) => {
    let g = groups.find((x) => x.tag === tag);
    if (!g) { g = { tag, items: [] }; groups.push(g); }
    return g;
  };
  for (const r of reasons) {
    const m = /^\[([A-Za-z]+)\]\s?/.exec(r);
    groupOf(m ? m[1] : "").items.push(r);
  }
  const ordered = [
    ...groups.filter((g) => g.tag === "Pattern"),
    ...groups.filter((g) => g.tag !== "Pattern" && g.tag !== ""),
    ...groups.filter((g) => g.tag === ""),
  ];
  const lines: string[] = [];
  for (const g of ordered) {
    const single = g.items.filter((r) => !r.includes("\n"));
    if (single.length) {
      const text = single.map((r) => r.replace(/^\[[A-Za-z]+\]\s*/, "")).join(", ");
      lines.push(`\u26a0\ufe0f ${text}\n`);
    }
    for (const r of g.items.filter((x) => x.includes("\n"))) {
      const ls = r.split("\n");
      lines.push(`\u26a0\ufe0f ${ls[0].replace(/^\[[A-Za-z]+\]\s*/, "")}\n` + ls.slice(1).map((l) => `  ${l}\n`).join(""));
    }
  }
  return lines;
}

function truncateLongCommand(command: string): string {
  const HEAD_LINES = 8;
  const TAIL_LINES = 4;
  const MAX_LINES = 20;

  const lines = command.split("\n");
  if (lines.length <= MAX_LINES) return command;

  const skipped = lines.length - HEAD_LINES - TAIL_LINES;
  return [
    lines.slice(0, HEAD_LINES),
    `  ... (+${skipped} more lines)`,
    lines.slice(-TAIL_LINES),
  ].join("\n");
}

function buildBashPrompt(
  data: BashPromptData,
  resolutions?: ResolutionMap,
  confirmedTokens?: Set<string>,
): BuiltPrompt {
  const { command, cwd, outsideDirs, segments, signatures,
          riskDangerous, riskSeverity, riskReasons, hasUnsafePattern,
          needsCommandApproval, needsPathApproval, nonAllowedSegmentIndices,
          credentialRule, relativeToolIds } = data;
  const unresolved = data.unresolved ?? [];
  // LLM/confirmed token dirs join the concrete outside dirs as grantable —
  // the "Always (paths)" option offers exactly this union (see
  // pathGrantDirs). Sanitized the same way: no root, no sentinels.
  const resolverDirs = [...new Set([...(resolutions?.values() ?? [])].flat())]
    .filter((d) => d !== "/" && !d.startsWith("<"))
    .sort();
  const nonAllowedSet = new Set(nonAllowedSegmentIndices);

  const hasBoth = needsCommandApproval && needsPathApproval;
  const uniqueSigs = [...new Set(signatures)];
  // The root is never an Always grant (one click must not hand out the whole
  // disk): filter it from every dir tier. A root-only path prompt (find /)
  // then offers no dir tier at all instead of a dead "Read /*" button.
  // Marker dirs (<unresolved-…>) are never grantable either — a grant for a
  // sentinel can never match, and one for a token's static prefix would be
  // escapable (an unbound value could contain `..`).
  const grantableDirs = outsideDirs.filter((d) => d !== "/" && !d.startsWith("<"));
  const pathGrantDirs = [...new Set([...grantableDirs, ...resolverDirs])].sort();
  // Relative-path tool identities (../node_modules/.bin/tsc …) with the base
  // they resolve against. Deduped against uniqueSigs — a relative tool whose
  // basename is NOT allowlisted appears in both lists. Granted base-bound
  // (exact sig + this effective working dir only).
  const relToolIds = (relativeToolIds ?? []).filter(r => !uniqueSigs.includes(r.sig));

  // Compute prompt options from data
  const includePathsOption = hasBoth && pathGrantDirs.length > 0;
  // Fetchable run forms (npx tsc, uvx …) are granted by per-package trust,
  // not signature rules: their sigs drop out of the command tier, and the
  // prompt offers "Trust: <pkg> (session)" instead (deduped by package).
  const fetchableForms = data.fetchableForms ?? [];
  const fetchableSigSet = new Set(fetchableForms.map(f => f.sig));
  const commandSigs = uniqueSigs.filter(s => !fetchableSigSet.has(s));
  const trustPackages = [...new Set(fetchableForms.map(f => f.pkg))].sort();
  const includeAlwaysOption = !hasUnsafePattern && !credentialRule && (commandSigs.length > 0 || pathGrantDirs.length > 0 || relToolIds.length > 0);
  const cmdBullets = [
    ...commandSigs.map(s => `  \u2022 ${s} *`),
    ...relToolIds.map(r => `  \u2022 ${r.sig} (this cwd)`),
  ].join("\n");

  // Title — reflect what triggered the prompt
  const titlePrefix = needsCommandApproval && needsPathApproval
    ? "Bash + Path"
    : needsCommandApproval
    ? "Bash"
    : needsPathApproval
    ? "Path"
    : credentialRule
    ? "Credential"
    : "Bash";
  const title = riskSeverity === "high"
    ? `\u26a0\ufe0f ${titlePrefix}`
    : titlePrefix;

  // Body — dense layout (the prompt dialog blocks the screen; every line
  // must earn its place). No re-listing of the command itself: the pending
  // tool call above the prompt carries it, and each prompt sits directly
  // under its own call, so the pairing is unambiguous. Each signal is ONE
  // ⚠️ line: outside dirs, unresolved tokens (resolution inline), risk
  // reasons (severity already in the title ⚠️), flagged segments, and the
  // credential note. No section headers, no inter-section blank lines, no
  // re-listing of unflagged segments — the command above carries them.
  let body = "";

  if (needsPathApproval) {
    if (outsideDirs.length > 0) {
      body += `\u26a0\ufe0f outside cwd: ${outsideDirs.join(", ")}\n`;
    }
    for (const u of unresolved) {
      let line = `\u26a0\ufe0f unresolved ${shortenToken(u.token)}`;
      if (u.reason === "base") line += ` \u2014 working directory not statically known`;
      const dirs = resolutions?.get(u.token);
      if (dirs && dirs.length > 0) {
        const source = confirmedTokens?.has(u.token) ? "confirmed" : "LLM";
        const shown = dirs.slice(0, 3).join(", ");
        line += ` \u2192 ${source}: ${shown}${dirs.length > 3 ? ` (+${dirs.length - 3} more)` : ""}`;
      }
      body += line + "\n";
    }
  }
  if (riskDangerous) {
    for (const line of riskReasonLines(riskReasons)) body += line;
  }

  // Segment breakdown — tmux chains keep the full formatted view (their
  // nesting is unreadable raw); plain chains list ONLY the flagged
  // segment texts (no indices — the raw command line is gone, the text
  // stands on its own).
  if (segments.length > 1) {
    const hasTmuxSegment = segments.some(isTmuxCommand);
    if (hasTmuxSegment) {
      const formattedCommand = formatBashCommand(command, nonAllowedSet, segments);
      body += `Segments:\n${formattedCommand}\n`;
    } else {
      const FLAGGED_MAX = 5;
      const flagged = segments
        .map((s, i) => ({ s, i }))
        .filter(({ i }) => nonAllowedSet.has(i));
      for (const { s } of flagged.slice(0, FLAGGED_MAX)) {
        body += `\u26a0\ufe0f ${truncateSegmentDisplay(s.trimEnd())}\n`;
      }
      if (flagged.length > FLAGGED_MAX) {
        body += `\u26a0\ufe0f \u2026 ${flagged.length - FLAGGED_MAX} more flagged segments\n`;
      }
    }
  }
  if (credentialRule) {
    if (isGlobUnverified(credentialRule)) {
      body += `\u26a0\ufe0f glob "${globUnverifiedToken(credentialRule)}" could not be expanded and verified \u2014 may reach credential files; prompted for safety\n`;
    } else {
      body += `\u26a0\ufe0f credential pattern "${credentialRule}" \u2014 may contain secrets or tokens\n`;
    }
  }

  // Tier 2 — "always (everything)" confirmation (dense, same as the body)
  const dangerWarning = riskDangerous
    ? "\n" + riskReasonLines(riskReasons).join("")
    : "";
  const pathBullets = pathGrantDirs.map(d => `  \u2022 ${d}/*`).join("\n");
  const tier2Everything = hasBoth
    ? {
        title: `Confirm Always Allow`,
        body: `"Always Yes" will auto-allow:\nCommands:\n${cmdBullets}${pathGrantDirs.length ? `\nPaths:\n${pathBullets}` : ""}${dangerWarning}`,
      }
    : needsPathApproval
    ? {
        title: `Confirm Always Allow`,
        body: `"Always Yes" will auto-allow read for these directories this session:\n${pathBullets}`,
      }
    : {
        title: `Confirm Always Allow`,
        body: `"Always Yes" will auto-allow these command signatures this session:\n${cmdBullets}${dangerWarning}`,
      };

  // Tier 2 — "always (paths only)" confirmation
  const tier2Paths = hasBoth && pathGrantDirs.length > 0
    ? {
        title: `Confirm Always (paths only)`,
        body: `"Always Yes" will auto-allow read for these directories this session:\n${pathBullets}\nThe command will still prompt next time`,
      }
    : undefined;

  const alwaysLabel = (needsCommandApproval && (commandSigs.length > 0 || relToolIds.length > 0))
    ? [...commandSigs.map(s => s + " *"), ...relToolIds.map(r => r.sig + " (this cwd)")].join(", ")
    : (needsPathApproval ? pathGrantDirs.map(d => `Read ${d}/*`).join(", ") : "");
  const alwaysPathsLabel = hasBoth && pathGrantDirs.length > 0
    ? pathGrantDirs.map(d => `Read ${d}/*`).join(", ")
    : undefined;

  return { title, body, tier2Everything, tier2Paths, includePathsOption, includeFileOption: false, includeBroaderOption: false, includeAlwaysOption, alwaysLabel, alwaysPathsLabel, pathGrantDirs, trustPackages: trustPackages.length > 0 ? trustPackages : undefined, resolverDirs: resolverDirs.length > 0 ? resolverDirs : undefined };
}

// ── File prompt ──

function buildFilePrompt(
  data: FilePromptData,
  isCovered?: (dir: string) => boolean,
): BuiltPrompt {
  const { action, filePath, resolved, cwd, outsideDir, isWriteOp, warnedRule, symlinkHint, exists } = data;
  const insideCwd = outsideDir === null;
  const covered = (d: string) => (isCovered ? isCovered(d) : false);
  const symlinkLine = symlinkHint ? `\n\u{1F517} Resolved via symlink: ${symlinkHint}` : "";
  const warnLine = warnedRule ? `\n\u26a0\ufe0f credential pattern "${warnedRule}" — may contain secrets or tokens` : "";
  const existsNote = exists && action === "Write"
    ? `\n\u2139\ufe0f file exists — writing will overwrite`
    : "";

  if (insideCwd) {
    const scopeNote = isWriteOp
      ? `"Always Yes" will auto-allow ${action.toLowerCase()} on this file this session (includes read).`
      : `"Always Yes" will auto-allow read on this file this session (write/edit will still prompt).`;
    const dirScope = isWriteOp
      ? `auto-allow ${action.toLowerCase()} for this directory this session (includes read)`
      : `auto-allow read for this directory this session (write/edit will still prompt)`;
    const fileName = resolved.split("/").pop() || resolved;
    const parentDir = path.dirname(resolved);
    // Compute broader parent directories: immediate parent then up to 3 levels
    // above. The root is never an option (a file directly under / would
    // otherwise offer "Always (broader): /").
    const broaderPaths: { label: string; dir: string }[] = [];
    // Immediate parent is the file's containing directory
    if (parentDir !== "/") {
      broaderPaths.push({
        label: `${action} ${path.join(parentDir, '*')}`,
        dir: parentDir,
      });
    }
    // Additional levels above the parent
    let cur = parentDir;
    for (let i = 0; i < 3; i++) {
      const parent = path.dirname(cur);
      if (parent === cur) break; // hit root
      if (parent === "/") break; // never offer a grant of the root
      cur = parent;
      broaderPaths.push({
        label: `${action} ${path.join(cur, '*')}`,
        dir: cur,
      });
    }
    // Coverage: an Always option whose scope a standing session grant already
    // covers is suppressed (re-granting a subset of a grant is noise, not a
    // choice). broaderPaths is pre-filtered so the layout's [0]/umbrella math
    // follows the surviving list.
    const kept = broaderPaths.filter((b) => !covered(b.dir));
    return {
      title: action,
      body: `Path:\n  ${filePath}${warnLine}${symlinkLine}${existsNote}\n`,
      tier2Everything: {
        title: `Confirm Always Allow`,
        body: `${scopeNote}\n  ${resolved}`,
      },
      tier2Broader: kept.length > 0 ? {
        title: `Confirm Always Allow`,
        body: `"Always Yes" will ${dirScope}:\n  ${path.join(kept[0].dir, '*')}`,
      } : undefined,
      includePathsOption: false,
      includeFileOption: false,
      includeBroaderOption: kept.length > 0,
      includeAlwaysOption: true,
      alwaysLabel: `${action} ${fileName}`,
      fileHierarchy: "inside",
      fileOptionCovered: covered(parentDir),
      broaderPaths: kept.length > 0 ? kept : undefined,
      pathGrantDirs: [],
    };
  }

  const scope = isWriteOp
    ? `auto-allow ${action.toLowerCase()} for this directory this session`
    : `auto-allow read for this directory this session (write/edit will still prompt)`;
  // A file directly under / has no grantable directory (the root is never
  // granted): the primary label is the file, matching the sanitized rule.
  const tier2Label = outsideDir === "/"
    ? `${isWriteOp ? action : "Read"} ${resolved.split("/").pop() || resolved}`
    : isWriteOp ? `${action} ${path.join(outsideDir, '*')}` : `Read ${path.join(outsideDir, '*')}`;
  const fileName = resolved.split("/").pop() || resolved;
  const fileScope = isWriteOp
    ? `auto-allow ${action.toLowerCase()} on this file this session (includes read)`
    : `auto-allow read on this file this session (write/edit will still prompt)`;

  // Broader paths: parents of outsideDir (1–3 levels above). The root is
  // never an option — an /etc file prompt used to offer "Always (broader): /
  //" (write the whole disk with one click).
  const broaderPaths: { label: string; dir: string }[] = [];
  let cur = outsideDir;
  for (let i = 0; i < 3; i++) {
    const parent = path.dirname(cur);
    if (parent === cur) break; // hit root
    if (parent === "/") break; // never offer a grant of the root
    cur = parent;
    broaderPaths.push({
      label: `${action} ${path.join(cur, '*')}`,
      dir: cur,
    });
  }

  const outsideDirGlob = outsideDir === "/" ? resolved : path.join(outsideDir, '*');

  // Coverage — same rule as the inside branch: a standing session grant that
  // already covers a scope suppresses the Always option for it. The umbrella
  // keeps offering genuinely new (uncovered) parent scopes.
  const kept = broaderPaths.filter((b) => !covered(b.dir));

  return {
    title: `\u26a0\ufe0f ${action} outside cwd`,
    // The flag rides the path line as a suffix — the dir itself is the path
    // prefix (and the Always (path) option shows it globbed), so a separate
    // "⚠️ outside cwd: <dir>" line was pure duplication.
    body: `Path:\n  ${filePath} \u26a0\ufe0f outside cwd${warnLine}${symlinkLine}${existsNote}\n`,
    tier2Everything: {
      title: `Confirm Always Allow`,
      body: `"Always Yes" will ${scope}:\n  ${outsideDirGlob}`,
    },
    tier2File: {
      title: `Confirm Always Allow`,
      body: `"Always Yes" will ${fileScope}:\n  ${resolved}\nOther files in ${outsideDir} will still prompt.`,
    },
    includePathsOption: false,
    includeFileOption: true,
    includeBroaderOption: kept.length > 0,
    includeAlwaysOption: true,
    alwaysLabel: tier2Label,
    alwaysFileLabel: `${action} ${fileName}`,
    fileHierarchy: "outside",
    pathOptionCovered: covered(outsideDir),
    fileOptionCovered: covered(path.dirname(resolved)),
    broaderPaths: kept.length > 0 ? kept : undefined,
    pathGrantDirs: [],
  };
}

// ── Tool prompt (plugin-gated tool calls) ────────────────────────────

/**
 * Prompt for a gated tool call (ToolPromptData). Single "Always" option,
 * the old MCP prompt's layout. Grant scope per gate:
 *  - exec / file → the WHOLE tool (`<tool>:*`) — the tier-2 confirmation
 *    names the code-execution risk explicitly;
 *  - consent     → the consent kind only (`<tool> (<kind>)`) — a kind grant
 *    can never cover the tool's exec actions.
 */
function buildToolPrompt(data: ToolPromptData): BuiltPrompt {
  const { tool, label, gate, note } = data;

  if (gate === "consent") {
    let body = `${label} (${data.consentKind})`;
    const args = data.argsPreview ? stripBraces(data.argsPreview) : "";
    if (args) body += `\nArguments:\n${args}`;
    return {
      title: tool,
      body,
      tier2Everything: {
        title: `Confirm Always Allow`,
        body: `"Always" will auto-allow ${data.consentKind} actions of ${tool} this session.\n\nOther ${tool} actions (including code execution) still prompt.`,
      },
      includePathsOption: false,
      includeFileOption: false,
      includeBroaderOption: false,
      includeAlwaysOption: true,
      alwaysLabel: `${tool} (${data.consentKind})`,
      pathGrantDirs: [],
    };
  }

  // exec / file — Always grants the whole tool.
  let body = label;
  if (gate === "exec") {
    if (data.script) body += `\nScript:\n${truncateLongCommand(data.script)}`;
    const args = data.argsPreview ? stripBraces(data.argsPreview) : "";
    if (args) body += `\nArguments:\n${args}`;
    body += `\n\u26a0\ufe0f ${note ?? "Executes code in an external tool."}`;
  } else {
    const target = data.resolved ?? "(unresolved)";
    // Suffix on the path line — the dir is the path prefix (no separate
    // line; see buildFilePrompt's note).
    const outside = data.outsideDir ? ` \u26a0\ufe0f outside cwd` : "";
    const existsNote = data.exists
      ? `\n\u2139\ufe0f file exists — the tool will overwrite it`
      : "";
    body += `\nPath:\n  ${target}${outside}${existsNote}`;
    if (note) body += `\n\u26a0\ufe0f ${note}`;
  }

  return {
    title: `\u26a0\ufe0f ${tool}`,
    body,
    tier2Everything: {
      title: `Confirm Always Allow`,
      body: `"Always" will auto-allow ALL actions of ${tool} this session — including code execution.`,
    },
    includePathsOption: false,
    includeFileOption: false,
    includeBroaderOption: false,
    includeAlwaysOption: true,
    alwaysLabel: `${tool}:*`,
    pathGrantDirs: [],
  };
}

/** Strip outer JSON braces from an args preview (cleaner inline look). */
function stripBraces(preview: string): string {
  const inner = preview.replace(/^\{\n/, "").replace(/\n\}$/, "").trimEnd();
  return inner && inner !== "{}" ? inner : "";
}

