import type { PromptDecision, BashPromptData, FilePromptData, McpPromptData } from "./decision-engine";

// ── Output types (match twoTierAlwaysPrompt's expected inputs) ──

export interface BuiltPrompt {
  title: string;
  body: string;
  tier2Everything: { title: string; body: string };
  tier2Paths?: { title: string; body: string };
  tier2File?: { title: string; body: string };
  includePathsOption: boolean;
  includeFileOption: boolean;
  includeBroaderOption: boolean;
  /** Labels for "Always" choices (e.g. "npm test *", "npm *", "/path/*") */
  alwaysLabel: string;
  alwaysBroaderLabel?: string;
  alwaysPathsLabel?: string;
  alwaysFileLabel?: string;
}

/**
 * Format a PromptDecision's structured data into title/body strings
 * for the two-tier prompt flow. All prompt wording lives here.
 */
export function buildPrompt(decision: PromptDecision): BuiltPrompt {
  const { promptData, allowRules, allowPathsRules, includePathsOption = false, includeBroaderOption = false } = decision;

  switch (promptData.type) {
    case "bash":
      return buildBashPrompt(promptData, allowRules, includePathsOption, includeBroaderOption ?? false);
    case "file":
      return buildFilePrompt(promptData, allowRules);
    case "mcp":
      return buildMcpPrompt(promptData, allowRules);
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
  _allowRules: { bashSigs?: string[]; readDirs?: string[] },
  includePathsOption: boolean,
  includeBroaderOption: boolean,
): BuiltPrompt {
  const { command, cwd, outsideDirs, segments, signatures,
          riskDangerous, riskSeverity, riskReasons,
          needsCommandApproval, needsPathApproval, nonAllowedSegmentIndices } = data;
  const nonAllowedSet = new Set(nonAllowedSegmentIndices);

  const cmdDisplay = command.length > 60 ? command.slice(0, 57) + "..." : command;
  const hasBoth = needsCommandApproval && needsPathApproval;
  const uniqueSigs = [...new Set(signatures)];

  // Title — reflect what triggered the prompt
  const titlePrefix = needsCommandApproval && needsPathApproval
    ? "Bash + Path"
    : needsCommandApproval
    ? "Bash"
    : "Path";
  const title = riskSeverity === "high"
    ? `\u26a0\ufe0f ${titlePrefix}`
    : titlePrefix;

  // Truncate long commands to keep prompt compact (user can scroll above for full command)
  const commandDisplay = truncateLongCommand(command);

  // Body
  let body = `Command:\n  ${commandDisplay}\n`;

  if (needsPathApproval) {
    body += `\n\u26a0\ufe0f Paths outside cwd:\n${outsideDirs.map(d => `  \u2022 ${d}`).join("\n")}`;
  }
  if (riskDangerous) {
    body += `\n\u26a0\ufe0f Danger flags (${riskSeverity?.toUpperCase()} risk):\n`;
    for (const reason of riskReasons) body += `  \u2022 ${reason}\n`;
  }
  if (segments.length > 1) {
    body += `\nThis chains ${segments.length} commands:\n`;
    segments.forEach((s, i) => {
      const marker = nonAllowedSet.has(i) ? " \u26a0\ufe0f" : "";
      body += `  ${i + 1}.${marker} ${s}\n`;
    });
  }
  if (riskDangerous) {
    body += `\n⚠️ Commands matching danger patterns always prompt, even after auto-allowing.`;
  }
  body += "\n";

  // Tier 2 — "always (everything)" confirmation
  let dangerWarning = "";
  if (riskDangerous) {
    dangerWarning = `\n\n\u26a0\ufe0f Danger flags (${riskSeverity?.toUpperCase()} risk):\n${riskReasons.map(r => `  \u2022 ${r}`).join("\n")}`;
  }
  const tier2Everything = hasBoth
    ? {
        title: `Confirm Always: ${uniqueSigs.map(s => s + " *").join(", ")} + ${outsideDirs.map(d => d + "/*").join(", ")}`,
        body: `"Always Yes" will auto-allow:\n\nCommands:\n${uniqueSigs.map(s => `  \u2022 ${s} *`).join("\n")}\n\nPaths:\n${outsideDirs.map(d => `  \u2022 ${d}/*`).join("\n")}${dangerWarning}\n\n"Back" returns to the previous prompt.`,
      }
    : needsPathApproval
    ? {
        title: `Confirm Always Allow: ${outsideDirs.map(d => d + "/*").join(", ")}`,
        body: `"Always Yes" will auto-allow read access for these directories this session:\n\n${outsideDirs.map(d => `  \u2022 ${d}/*`).join("\n")}\n\n"Back" returns to the previous prompt.`,
      }
    : {
        title: `Confirm Always Allow: ${uniqueSigs.map(s => s + " *").join(", ")}`,
        body: `"Always Yes" will auto-allow each of these command signatures this session:\n\n${uniqueSigs.map(s => `  \u2022 ${s} *`).join("\n")}${dangerWarning}\n\n"Back" returns to the previous prompt.`,
      };

  // Tier 2 — "always (paths only)" confirmation
  const tier2Paths = hasBoth
    ? {
        title: `Confirm Always (paths only): ${outsideDirs.map(d => d + "/*").join(", ")}`,
        body: `"Always Yes" will auto-allow read access for these directories this session:\n\n${outsideDirs.map(d => `  \u2022 ${d}/*`).join("\n")}\n\nThe command will still prompt next time.\n\n"Back" returns to the previous prompt.`,
      }
    : undefined;

  const alwaysLabel = uniqueSigs.map(s => s + " *").join(", ");
  const alwaysBroaderLabel = includeBroaderOption
    ? uniqueSigs.map(s => s.split(" ")[0] + " *").join(", ")
    : undefined;
  const alwaysPathsLabel = hasBoth
    ? outsideDirs.map(d => d + "/*").join(", ")
    : undefined;

  return { title, body, tier2Everything, tier2Paths, includePathsOption, includeFileOption: false, includeBroaderOption, alwaysLabel, alwaysBroaderLabel, alwaysPathsLabel };
}

// ── File prompt ──

function buildFilePrompt(
  data: FilePromptData,
  _allowRules: { readPaths?: string[]; writePaths?: string[]; readDirs?: string[]; writeDirs?: string[] },
): BuiltPrompt {
  const { action, filePath, resolved, cwd, outsideDir, isWriteOp, deniedRule, warnedRule, symlinkHint } = data;
  const insideCwd = outsideDir === null;
  const symlinkLine = symlinkHint ? `\n\n🔗 Resolved via symlink: ${symlinkHint}` : "";
  const warnLine = warnedRule ? `\n\n⚠️ Matches credential pattern "${warnedRule}" — may contain secrets or tokens.` : "";
  const deniedLine = deniedRule ? `\n\n⚠️ Matches denied rule "${deniedRule}" — typically contains credentials or generated files.` : "";

  if (insideCwd) {
    const scopeNote = isWriteOp
      ? `"Always Yes" will auto-allow ${action.toLowerCase()} on this file this session (read will still prompt).`
      : `"Always Yes" will auto-allow read on this file this session (write/edit will still prompt).`;
    const fileName = resolved.split("/").pop() || resolved;
    return {
      title: action,
      body: `Path:\n  ${filePath}${warnLine}${deniedLine}${symlinkLine}\n`,
      tier2Everything: {
        title: `Confirm Always Allow: ${action} ${fileName}`,
        body: `${scopeNote}\n\n  ${resolved}\n\n"Back" returns to the previous prompt.`,
      },
      includePathsOption: false,
      includeFileOption: false,
      includeBroaderOption: false,
      alwaysLabel: `${action} ${fileName}`,
    };
  }

  const scope = isWriteOp
    ? `auto-allow ${action} for this directory this session`
    : `auto-allow read for this directory this session (write/edit will still prompt)`;
  const tier2Label = isWriteOp ? `${action} ${outsideDir}/*` : `read ${outsideDir}/*`;
  const fileName = resolved.split("/").pop() || resolved;
  const fileScope = isWriteOp
    ? `auto-allow ${action.toLowerCase()} on this file this session (read will still prompt)`
    : `auto-allow read on this file this session (write/edit will still prompt)`;

  return {
    title: `⚠️ ${action} outside cwd`,
    body: `Path:\n  ${filePath}\n\n⚠️ Outside cwd: ${outsideDir}${warnLine}${deniedLine}${symlinkLine}\n`,
    tier2Everything: {
      title: `Confirm Always Allow: ${tier2Label}`,
      body: `"Always Yes" will ${scope}:\n\n  ${outsideDir}/*\n\n"Back" returns to the previous prompt.`,
    },
    tier2File: {
      title: `Confirm Always Allow: ${action} ${fileName}`,
      body: `"Always Yes" will ${fileScope}:\n\n  ${resolved}\n\nOther files in ${outsideDir} will still prompt.\n\n"Back" returns to the previous prompt.`,
    },
    includePathsOption: false,
    includeFileOption: true,
    includeBroaderOption: false,
    alwaysLabel: tier2Label,
    alwaysFileLabel: `${action} ${fileName}`,
  };
}

// ── MCP prompt ────────────────────────────────────────────────────────────

function buildMcpPrompt(
  data: McpPromptData,
  _allowRules: { mcpServers?: string[] },
): BuiltPrompt {
  const { server, tool, op, argsPreview } = data;

  // tool is now a formatted call label (e.g. "mcp call foo @ server" or "tool_name")
  const isCallLabel = tool.startsWith("mcp ") || tool.includes(": ");
  const toolDisplay = isCallLabel ? tool : `${server}:${tool}`;

  let body = `Server: ${server}\nTool: ${toolDisplay}\nOperation: ${op}`;
  if (argsPreview) {
    body += `\nArguments:\n${argsPreview}`;
  }
  body += `\n\n⚠️ This MCP tool will be called through an external server.\n`;

  return {
    title: `\u26a0\ufe0f MCP`,
    body,
    tier2Everything: {
      title: `Confirm Always Allow: ${server}:*`,
      body: `"Always Yes" will auto-allow all tools from MCP server '${server}' this session:\n\n  ${server}:*\n\n"Back" returns to the previous prompt.`,
    },
    includePathsOption: false,
    includeFileOption: false,
    includeBroaderOption: false,
    alwaysLabel: `${server}:*`,
  };
}
