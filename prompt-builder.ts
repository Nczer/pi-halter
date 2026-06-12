import path from "node:path";
import type { PromptDecision, BashPromptData, FilePromptData, McpPromptData } from "./decision-engine";

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
  /** Context-aware examples for the permanent allow pattern editor. */
  permanentAllowExamples?: string;
}

/**
 * Format a PromptDecision's structured data into title/body strings
 * for the two-tier prompt flow. All prompt wording lives here.
 */
export function buildPrompt(decision: PromptDecision): BuiltPrompt {
  const { promptData, allowRules, allowPathsRules, includePathsOption = false, includeBroaderOption = false, includeAlwaysOption = true } = decision;

  switch (promptData.type) {
    case "bash":
      return buildBashPrompt(promptData, allowRules, includePathsOption, includeBroaderOption ?? false, includeAlwaysOption);
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
  includeAlwaysOption: boolean,
): BuiltPrompt {
  const { command, cwd, outsideDirs, segments, signatures,
          riskDangerous, riskSeverity, riskReasons, hasUnsafePattern,
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
    for (const reason of riskReasons) {
      const lines = reason.split("\n");
      body += `  \u2022 ${lines[0]}\n`;
      for (let i = 1; i < lines.length; i++) body += `    ${lines[i]}\n`;
    }
  }
  if (segments.length > 1) {
    body += `\nThis chains ${segments.length} commands:\n`;
    segments.forEach((s, i) => {
      const marker = nonAllowedSet.has(i) ? " \u26a0\ufe0f" : "";
      body += `  ${i + 1}.${marker} ${s}\n`;
    });
  }
  if (hasUnsafePattern) {
    body += `\n\u26a0\ufe0f Commands matching danger patterns always prompt, even after auto-allowing.`;
  }
  body += "\n";

  // Tier 2 — "always (everything)" confirmation
  let dangerWarning = "";
  if (riskDangerous) {
    dangerWarning = `\n\n\u26a0\ufe0f Danger flags (${riskSeverity?.toUpperCase()} risk):\n${riskReasons.map(r => `  \u2022 ${r}`).join("\n")}`;
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

  const cmdFirst = command.split(" ")[0];
  const sigExample = uniqueSigs.length > 0 ? uniqueSigs[0] + " *" : cmdFirst + " *";
  const broaderExample = cmdFirst + " *";
  let permExamples = sigExample !== broaderExample
    ? `Try: '${sigExample}' (these commands) or '${broaderExample}' (all ${cmdFirst} commands)`
    : `Try: '${broaderExample}' (all ${cmdFirst} commands)`;
  if (needsPathApproval) {
    permExamples += `\nFor path access: '${outsideDirs[0]}/*' (add as read rule)`;
  }
  return { title, body, tier2Everything, tier2Paths, includePathsOption, includeFileOption: false, includeBroaderOption, includeAlwaysOption, alwaysLabel, alwaysBroaderLabel, alwaysPathsLabel, permanentAllowExamples: permExamples };
}

// ── File prompt ──

function buildFilePrompt(
  data: FilePromptData,
  _allowRules: { readPaths?: string[]; writePaths?: string[]; readDirs?: string[]; writeDirs?: string[] },
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
    return {
      title: action,
      body: `Path:\n  ${filePath}${warnLine}${deniedLine}${symlinkLine}\n`,
      tier2Everything: {
        title: `Confirm Always Allow`,
        body: `${scopeNote}\n\n  ${resolved}`,
      },
      tier2Broader: {
        title: `Confirm Always Allow`,
        body: `"Always Yes" will ${dirScope}:\n\n  ${parentDir}/*`,
      },
      includePathsOption: false,
      includeFileOption: false,
      includeBroaderOption: true,
      includeAlwaysOption: true,
      alwaysLabel: `${action} ${fileName}`,
      alwaysBroaderLabel: `${action} ${parentDir}/*`,
      permanentAllowExamples: `Try: '${fileName}' (anywhere) or '${parentDir}/*' (this directory)`,
    };
  }

  const scope = isWriteOp
    ? `auto-allow ${action.toLowerCase()} for this directory this session`
    : `auto-allow read for this directory this session (write/edit will still prompt)`;
  const tier2Label = isWriteOp ? `${action} ${outsideDir}/*` : `Read ${outsideDir}/*`;
  const fileName = resolved.split("/").pop() || resolved;
  const fileScope = isWriteOp
    ? `auto-allow ${action.toLowerCase()} on this file this session (includes read)`
    : `auto-allow read on this file this session (write/edit will still prompt)`;

  return {
    title: `\u26a0\ufe0f ${action} outside cwd`,
    body: `Path:\n  ${filePath}\n\n\u26a0\ufe0f Outside cwd: ${outsideDir}${warnLine}${deniedLine}${symlinkLine}\n`,
    tier2Everything: {
      title: `Confirm Always Allow`,
      body: `"Always Yes" will ${scope}:\n\n  ${outsideDir}/*`,
    },
    tier2File: {
      title: `Confirm Always Allow`,
      body: `"Always Yes" will ${fileScope}:\n\n  ${resolved}\n\nOther files in ${outsideDir} will still prompt.`,
    },
    includePathsOption: false,
    includeFileOption: true,
    includeBroaderOption: false,
    includeAlwaysOption: true,
    alwaysLabel: tier2Label,
    alwaysFileLabel: `${action} ${fileName}`,
    permanentAllowExamples: `Try: '${fileName}' (anywhere) or '${outsideDir}/*' (this directory)`,
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
  body += `\n\n\u26a0\ufe0f This MCP tool will be called through an external server.\n`;

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
