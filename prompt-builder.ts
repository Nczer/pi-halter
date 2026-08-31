import path from "node:path";
import type { PromptDecision, PromptData, BashPromptData, FilePromptData, ToolPromptData } from "./decision-engine";
import { PACKAGE_MANAGERS } from "./config";
import { formatBashCommand, isTmuxCommand, truncateSegmentDisplay } from "./renderers/tmux";
import { shortenToken } from "./analysis/path-util";
import type { ResolutionMap } from "./path-resolver";

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
  /** Labels for "Always" choices (e.g. "npm test *", "npm *", "/path/*") */
  alwaysLabel: string;
  alwaysBroaderLabel?: string;
  alwaysPathsLabel?: string;
  alwaysFileLabel?: string;
  /** Broader parent-directory alternatives for file prompts (1–3 levels up). */
  broaderPaths?: { label: string; dir: string }[];
  /** Whether the operation is a write (vs read) — used for accurate prompt text. */
  isWriteOp?: boolean;
  /** D10: bare package names from a dspa untrusted-package stop — tier-1
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
): BuiltPrompt {
  const { promptData } = decision;

  switch (promptData.type) {
    case "bash":
      return buildBashPrompt(promptData, resolutions, confirmedTokens);
    case "file":
      return buildFilePrompt(promptData);
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

  // Pre-compute aligned risk reasons (reused in body and tier2)
  const alignedReasons = riskDangerous
    ? riskReasons.map(r => {
        const m = r.match(/^(\[.+?\]\s*)(.*)/);
        const tagLen = m ? m[1].length : 0;
        return { tagLen, tag: m ? m[1] : "", rest: m ? m[2] : r };
      })
    : [];
  const tagWidth = alignedReasons.length ? Math.max(...alignedReasons.map(r => r.tagLen)) : 0;

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
  const pmSigs = uniqueSigs.filter(sig => PACKAGE_MANAGERS.has(sig.split(/\s+/)[0]));
  const broaderSigs = [...new Set(pmSigs.map(sig => sig.split(/\s+/)[0]))];
  const includeBroaderOption = broaderSigs.some(s => !uniqueSigs.includes(s));
  const includeAlwaysOption = !hasUnsafePattern && !credentialRule && (uniqueSigs.length > 0 || pathGrantDirs.length > 0 || relToolIds.length > 0);
  const cmdBullets = [
    ...uniqueSigs.map(s => `  \u2022 ${s} *`),
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

  // Always show raw command first (truncated if long)
  const rawDisplay = truncateLongCommand(command);
  let body = `Command:\n  ${rawDisplay}\n`;

  if (needsPathApproval) {
    if (outsideDirs.length > 0) {
      body += `\n\u26a0\ufe0f Paths outside cwd:\n${outsideDirs.map(d => `  \u2022 ${d}`).join("\n")}`;
    }
    if (unresolved.length > 0) {
      const lines = unresolved.map((u) => {
        let line = `  \u2022 ${shortenToken(u.token)}`;
        if (u.reason === "base") line += ` \u2014 working directory not statically known`;
        const dirs = resolutions?.get(u.token);
        if (dirs && dirs.length > 0) {
          const source = confirmedTokens?.has(u.token) ? "confirmed" : "LLM";
          const shown = dirs.slice(0, 3).join(", ");
          line += `\n    \u2192 ${source}: ${shown}${dirs.length > 3 ? ` (+${dirs.length - 3} more)` : ""}`;
        }
        return line;
      });
      body += `\n\u26a0\ufe0f Unresolved references (runtime location not statically provable):\n${lines.join("\n")}`;
    }
  }
  if (riskDangerous) {
    body += `\n\u26a0\ufe0f Danger flags (${riskSeverity?.toUpperCase()} risk):\n`;
    for (let i = 0; i < alignedReasons.length; i++) {
      const { tag, rest } = alignedReasons[i];
      const lines = riskReasons[i].split("\n");
      body += `  \u2022 ${tag.padEnd(tagWidth)} ${rest}\n`;
      for (let j = 1; j < lines.length; j++) body += `    ${lines[j]}\n`;
    }
  }

  // Segment breakdown: formatted for tmux chains, plain list for others
  if (segments.length > 1) {
    // Guard: skip expensive format pass when no segment is a tmux command
    const hasTmuxSegment = segments.some(isTmuxCommand);
    if (hasTmuxSegment) {
      const formattedCommand = formatBashCommand(command, nonAllowedSet, segments);
      body += `\nSegments:\n${formattedCommand}\n`;
    } else {
      // Non-tmux chain — plain numbered list
      body += `\nThis chains ${segments.length} commands:\n`;
      segments.forEach((s, i) => {
        const marker = nonAllowedSet.has(i) ? " \u26a0\ufe0f" : "";
        const display = truncateSegmentDisplay(s.trimEnd());
        body += `  ${i + 1}.${marker} ${display}\n`;
      });
    }
  }
  if (hasUnsafePattern) {
    body += `\n\u26a0\ufe0f Commands matching danger patterns always prompt, even after auto-allowing.`;
  }
  if (credentialRule) {
    body += `\n\u26a0\ufe0f Matches credential pattern "${credentialRule}" \u2014 may contain secrets or tokens.`;
  }
  body += "\n";

  // Tier 2 — "always (everything)" confirmation
  let dangerWarning = "";
  if (riskDangerous) {
    const aligned = alignedReasons.map(({ tag, rest }) => `  \u2022 ${tag.padEnd(tagWidth)} ${rest}`);
    dangerWarning = `\n\n\u26a0\ufe0f Danger flags (${riskSeverity?.toUpperCase()} risk):\n${aligned.join("\n")}`;
  }
  const pathBullets = pathGrantDirs.map(d => `  \u2022 ${d}/*`).join("\n");
  const tier2Everything = hasBoth
    ? {
        title: `Confirm Always Allow`,
        body: `"Always Yes" will auto-allow:\n\nCommands:\n${cmdBullets}${pathGrantDirs.length ? `\n\nPaths:\n${pathBullets}` : ""}${dangerWarning}`,
      }
    : needsPathApproval
    ? {
        title: `Confirm Always Allow`,
        body: `"Always Yes" will auto-allow read for these directories this session:\n\n${pathBullets}`,
      }
    : {
        title: `Confirm Always Allow`,
        body: `"Always Yes" will auto-allow these command signatures this session:\n\n${cmdBullets}${dangerWarning}`,
      };

  // Tier 2 — "always (paths only)" confirmation
  const tier2Paths = hasBoth && pathGrantDirs.length > 0
    ? {
        title: `Confirm Always (paths only)`,
        body: `"Always Yes" will auto-allow read for these directories this session:\n\n${pathBullets}\n\nThe command will still prompt next time`,
      }
    : undefined;

  const alwaysLabel = (needsCommandApproval && (uniqueSigs.length > 0 || relToolIds.length > 0))
    ? [...uniqueSigs.map(s => s + " *"), ...relToolIds.map(r => r.sig + " (this cwd)")].join(", ")
    : (needsPathApproval ? pathGrantDirs.map(d => `Read ${d}/*`).join(", ") : "");
  const alwaysBroaderLabel = includeBroaderOption
    ? uniqueSigs.map(s => s.split(" ")[0] + " *").join(", ")
    : undefined;
  const alwaysPathsLabel = hasBoth && pathGrantDirs.length > 0
    ? pathGrantDirs.map(d => `Read ${d}/*`).join(", ")
    : undefined;

  // Tier 2 — broader (package manager prefix only, e.g. "npm *")
  const tier2Broader = includeBroaderOption
    ? {
        title: `Confirm Always Allow`,
        body: `"Always Yes" will auto-allow all commands from these package managers this session:\n\n${broaderSigs.map(s => `  \u2022 ${s} *`).join("\n")}`,
      }
    : undefined;

  return { title, body, tier2Everything, tier2Paths, tier2Broader, includePathsOption, includeFileOption: false, includeBroaderOption, includeAlwaysOption, alwaysLabel, alwaysBroaderLabel, alwaysPathsLabel, pathGrantDirs, resolverDirs: resolverDirs.length > 0 ? resolverDirs : undefined };
}

// ── File prompt ──

function buildFilePrompt(
  data: FilePromptData,
): BuiltPrompt {
  const { action, filePath, resolved, cwd, outsideDir, isWriteOp, warnedRule, symlinkHint, exists } = data;
  const insideCwd = outsideDir === null;
  const symlinkLine = symlinkHint ? `\n\n\u{1F517} Resolved via symlink: ${symlinkHint}` : "";
  const warnLine = warnedRule ? `\n\n\u26a0\ufe0f Matches credential pattern "${warnedRule}" — may contain secrets or tokens.` : "";
  const existsNote = exists && action === "Write"
    ? `\n\n\u2139\ufe0f File already exists at this path. Writing will overwrite it.`
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
    return {
      title: action,
      body: `Path:\n  ${filePath}${warnLine}${symlinkLine}${existsNote}\n`,
      tier2Everything: {
        title: `Confirm Always Allow`,
        body: `${scopeNote}\n\n  ${resolved}`,
      },
      tier2Broader: {
        title: `Confirm Always Allow`,
        body: `"Always Yes" will ${dirScope}:\n\n  ${path.join(parentDir, '*')}`,
      },
      includePathsOption: false,
      includeFileOption: false,
      includeBroaderOption: broaderPaths.length > 0,
      includeAlwaysOption: true,
      alwaysLabel: `${action} ${fileName}`,
      alwaysBroaderLabel: broaderPaths.length > 0 ? broaderPaths[0].label : undefined,
      broaderPaths: broaderPaths.length > 0 ? broaderPaths : undefined,
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

  return {
    title: `\u26a0\ufe0f ${action} outside cwd`,
    body: `Path:\n  ${filePath}\n\n\u26a0\ufe0f Outside cwd: ${outsideDir}${warnLine}${symlinkLine}${existsNote}\n`,
    tier2Everything: {
      title: `Confirm Always Allow`,
      body: `"Always Yes" will ${scope}:\n\n  ${outsideDirGlob}`,
    },
    tier2File: {
      title: `Confirm Always Allow`,
      body: `"Always Yes" will ${fileScope}:\n\n  ${resolved}\n\nOther files in ${outsideDir} will still prompt.`,
    },
    includePathsOption: false,
    includeFileOption: true,
    includeBroaderOption: broaderPaths.length > 0,
    includeAlwaysOption: true,
    alwaysLabel: tier2Label,
    alwaysFileLabel: `${action} ${fileName}`,
    alwaysBroaderLabel: broaderPaths.length > 0 ? broaderPaths[0].label : undefined,
    broaderPaths: broaderPaths.length > 0 ? broaderPaths : undefined,
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
    if (args) body += `\n\nArguments:\n${args}`;
    body += `\n\n\u26a0\ufe0f ${note ?? "Executes code in an external tool."}`;
  } else {
    const target = data.resolved ?? "(unresolved)";
    const outside = data.outsideDir ? `\n\n\u26a0\ufe0f Outside cwd: ${data.outsideDir}` : "";
    const existsNote = data.exists
      ? `\n\n\u2139\ufe0f File already exists at this path. The tool will overwrite it.`
      : "";
    body += `\nPath:\n  ${target}${outside}${existsNote}`;
    if (note) body += `\n\n\u26a0\ufe0f ${note}`;
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

