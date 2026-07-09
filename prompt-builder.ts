import path from "node:path";
import type { PromptDecision, BashPromptData, FilePromptData, McpPromptData } from "./decision-engine";
import { PACKAGE_MANAGERS } from "./config";
import { formatBashCommand, isTmuxCommand, truncateSegmentDisplay } from "./renderers/tmux";

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
}

/**
 * Format a PromptDecision's structured data into title/body strings
 * for the two-tier prompt flow. All prompt wording lives here.
 */
export function buildPrompt(decision: PromptDecision): BuiltPrompt {
  const { promptData } = decision;

  switch (promptData.type) {
    case "bash":
      return buildBashPrompt(promptData);
    case "file":
      return buildFilePrompt(promptData);
    case "mcp":
      return buildMcpPrompt(promptData);
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
): BuiltPrompt {
  const { command, cwd, outsideDirs, segments, signatures,
          riskDangerous, riskSeverity, riskReasons, hasUnsafePattern,
          needsCommandApproval, needsPathApproval, nonAllowedSegmentIndices,
          credentialRule } = data;
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

  // Compute prompt options from data (previously on PromptDecision)
  const includePathsOption = hasBoth;
  // PACKAGE_MANAGERS imported from config
  const pmSigs = uniqueSigs.filter(sig => PACKAGE_MANAGERS.has(sig.split(/\s+/)[0]));
  const broaderSigs = [...new Set(pmSigs.map(sig => sig.split(/\s+/)[0]))];
  const includeBroaderOption = broaderSigs.some(s => !uniqueSigs.includes(s));
  const includeAlwaysOption = !hasUnsafePattern && !credentialRule && (uniqueSigs.length > 0 || outsideDirs.length > 0);

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
    body += `\n\u26a0\ufe0f Paths outside cwd:\n${outsideDirs.map(d => `  \u2022 ${d}`).join("\n")}`;
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
  const tier2Everything = hasBoth
    ? {
        title: `Confirm Always Allow`,
        body: `"Always Yes" will auto-allow:\n\nCommands:\n${uniqueSigs.map(s => `  \u2022 ${s} *`).join("\n")}\n\nPaths:\n${outsideDirs.map(d => `  \u2022 ${d}/*`).join("\n")}${dangerWarning}`,
      }
    : needsPathApproval
    ? {
        title: `Confirm Always Allow`,
        body: `"Always Yes" will auto-allow read for these directories this session:\n\n${outsideDirs.map(d => `  \u2022 ${d}/*`).join("\n")}`,
      }
    : {
        title: `Confirm Always Allow`,
        body: `"Always Yes" will auto-allow these command signatures this session:\n\n${uniqueSigs.map(s => `  \u2022 ${s} *`).join("\n")}${dangerWarning}`,
      };

  // Tier 2 — "always (paths only)" confirmation
  const tier2Paths = hasBoth
    ? {
        title: `Confirm Always (paths only)`,
        body: `"Always Yes" will auto-allow read for these directories this session:\n\n${outsideDirs.map(d => `  \u2022 ${d}/*`).join("\n")}\n\nThe command will still prompt next time`,
      }
    : undefined;

  const alwaysLabel = (needsCommandApproval && uniqueSigs.length > 0)
    ? uniqueSigs.map(s => s + " *").join(", ")
    : (needsPathApproval ? outsideDirs.map(d => `Read ${d}/*`).join(", ") : "");
  const alwaysBroaderLabel = includeBroaderOption
    ? uniqueSigs.map(s => s.split(" ")[0] + " *").join(", ")
    : undefined;
  const alwaysPathsLabel = hasBoth
    ? outsideDirs.map(d => `Read ${d}/*`).join(", ")
    : undefined;

  return { title, body, tier2Everything, tier2Paths, includePathsOption, includeFileOption: false, includeBroaderOption, includeAlwaysOption, alwaysLabel, alwaysBroaderLabel, alwaysPathsLabel };
}

// ── File prompt ──

function buildFilePrompt(
  data: FilePromptData,
): BuiltPrompt {
  const { action, filePath, resolved, cwd, outsideDir, isWriteOp, deniedRule, warnedRule, symlinkHint } = data;
  const insideCwd = outsideDir === null;
  const symlinkLine = symlinkHint ? `\n\n\u{1F517} Resolved via symlink: ${symlinkHint}` : "";
  const warnLine = warnedRule ? `\n\n\u26a0\ufe0f Matches credential pattern "${warnedRule}" — may contain secrets or tokens.` : "";
  const deniedLine = deniedRule ? `\n\n\u26a0\ufe0f Matches denied rule "${deniedRule}" — typically contains credentials or generated files.` : "";

  if (insideCwd) {
    const scopeNote = isWriteOp
      ? `"Always Yes" will auto-allow ${action.toLowerCase()} on this file this session (includes read).`
      : `"Always Yes" will auto-allow read on this file this session (write/edit will still prompt).`;
    const dirScope = isWriteOp
      ? `auto-allow ${action.toLowerCase()} for this directory this session (includes read)`
      : `auto-allow read for this directory this session (write/edit will still prompt)`;
    const fileName = resolved.split("/").pop() || resolved;
    const parentDir = path.dirname(resolved);
    // Compute broader parent directories: immediate parent then up to 3 levels above
    const broaderPaths: { label: string; dir: string }[] = [];
    // Immediate parent is the file's containing directory
    broaderPaths.push({
      label: `${action} ${path.join(parentDir, '*')}`,
      dir: parentDir,
    });
    // Additional levels above the parent
    let cur = parentDir;
    for (let i = 0; i < 3; i++) {
      const parent = path.dirname(cur);
      if (parent === cur) break; // hit root
      cur = parent;
      broaderPaths.push({
        label: `${action} ${path.join(cur, '*')}`,
        dir: cur,
      });
    }
    return {
      title: action,
      body: `Path:\n  ${filePath}${warnLine}${deniedLine}${symlinkLine}\n`,
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
      includeBroaderOption: true,
      includeAlwaysOption: true,
      alwaysLabel: `${action} ${fileName}`,
      alwaysBroaderLabel: `${action} ${path.join(parentDir, '*')}`,
      broaderPaths,
    };
  }

  const scope = isWriteOp
    ? `auto-allow ${action.toLowerCase()} for this directory this session`
    : `auto-allow read for this directory this session (write/edit will still prompt)`;
  const tier2Label = isWriteOp ? `${action} ${path.join(outsideDir, '*')}` : `Read ${path.join(outsideDir, '*')}`;
  const fileName = resolved.split("/").pop() || resolved;
  const fileScope = isWriteOp
    ? `auto-allow ${action.toLowerCase()} on this file this session (includes read)`
    : `auto-allow read on this file this session (write/edit will still prompt)`;

  // Broader paths: parents of outsideDir (1–3 levels above)
  const broaderPaths: { label: string; dir: string }[] = [];
  let cur = outsideDir;
  for (let i = 0; i < 3; i++) {
    const parent = path.dirname(cur);
    if (parent === cur) break; // hit root
    cur = parent;
    broaderPaths.push({
      label: `${action} ${path.join(cur, '*')}`,
      dir: cur,
    });
  }

  const outsideDirGlob = path.join(outsideDir, '*');

  return {
    title: `\u26a0\ufe0f ${action} outside cwd`,
    body: `Path:\n  ${filePath}\n\n\u26a0\ufe0f Outside cwd: ${outsideDir}${warnLine}${deniedLine}${symlinkLine}\n`,
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
  };
}

// ── MCP prompt ────────────────────────────────────────────────────────────

function buildMcpPrompt(
  data: McpPromptData,
): BuiltPrompt {
  const { server, tool, argsPreview } = data;

  let body = `Server: ${server}\nTool: ${tool}`;
  if (argsPreview) {
    // Strip outer braces for a cleaner inline look
    const inner = argsPreview.replace(/^\{\n/, "").replace(/\n\}$/, "").trimEnd();
    if (inner && inner !== "{}") {
      body += `\nArguments: \n${inner}`;
    }
  }
  body += `\n\n\u26a0\ufe0f Calling an external MCP tool.\n`;

  return {
    title: `\u26a0\ufe0f MCP`,
    body,
    tier2Everything: {
      title: `Confirm Always Allow`,
      body: `"Always Yes" will auto-allow all tools from MCP server '${server}' this session:\n\n  ${server}:*`,
    },
    includePathsOption: false,
    includeFileOption: false,
    includeBroaderOption: false,
    includeAlwaysOption: true,
    alwaysLabel: `${server}:*`,
  };
}
