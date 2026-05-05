import type { PromptDecision, PromptData, BashPromptData, FilePromptData, SubagentPromptData } from "./decision-engine";

// ── Output types (match twoTierAlwaysPrompt's expected inputs) ──

export interface BuiltPrompt {
  title: string;
  body: string;
  tier2Everything: { title: string; body: string };
  tier2Paths?: { title: string; body: string };
  tier2File?: { title: string; body: string };
  includePathsOption: boolean;
  includeFileOption: boolean;
}

/**
 * Format a PromptDecision's structured data into title/body strings
 * for the two-tier prompt flow. All prompt wording lives here.
 */
export function buildPrompt(decision: PromptDecision): BuiltPrompt {
  const { promptData, allowRules, allowPathsRules, includePathsOption = false } = decision;

  switch (promptData.type) {
    case "bash":
      return buildBashPrompt(promptData, allowRules, includePathsOption);
    case "file":
      return buildFilePrompt(promptData, allowRules);
    case "subagent":
      return buildSubagentPrompt(promptData, allowRules);
  }
}

// ── Bash prompt ──

function buildBashPrompt(
  data: BashPromptData,
  _allowRules: { bashSigs?: string[]; readDirs?: string[] },
  includePathsOption: boolean,
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

  // Body
  let body = `Command:\n  ${command}\n`;

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
        title: `Confirm Always: ${uniqueSigs.join(", ")} + ${outsideDirs.join(", ")}`,
        body: `"Always Yes" will auto-allow:\n\nCommands:\n${uniqueSigs.map(s => `  \u2022 ${s}`).join("\n")}\n\nPaths:\n${outsideDirs.map(d => `  \u2022 ${d}`).join("\n")}${dangerWarning}\n\n"Back" returns to the previous prompt.`,
      }
    : needsPathApproval
    ? {
        title: `Confirm Always Allow: ${outsideDirs.join(", ")}`,
        body: `"Always Yes" will auto-allow read access for these directories this session:\n\n${outsideDirs.map(d => `  \u2022 ${d}`).join("\n")}\n\n"Back" returns to the previous prompt.`,
      }
    : {
        title: `Confirm Always Allow: ${uniqueSigs.join(", ")}`,
        body: `"Always Yes" will auto-allow each of these command signatures this session:\n\n${uniqueSigs.map(s => `  \u2022 ${s}`).join("\n")}${dangerWarning}\n\n"Back" returns to the previous prompt.`,
      };

  // Tier 2 — "always (paths only)" confirmation
  const tier2Paths = hasBoth
    ? {
        title: `Confirm Always (paths only): ${outsideDirs.join(", ")}`,
        body: `"Always Yes" will auto-allow read access for these directories this session:\n\n${outsideDirs.map(d => `  \u2022 ${d}`).join("\n")}\n\nThe command will still prompt next time.\n\n"Back" returns to the previous prompt.`,
      }
    : undefined;

  return { title, body, tier2Everything, tier2Paths, includePathsOption, includeFileOption: false };
}

// ── File prompt ──

function buildFilePrompt(
  data: FilePromptData,
  _allowRules: { paths?: string[]; readDirs?: string[]; writeDirs?: string[] },
): BuiltPrompt {
  const { action, filePath, resolved, cwd, outsideDir, isWriteOp, deniedRule, symlinkHint } = data;
  const insideCwd = outsideDir === null;
  const symlinkLine = symlinkHint ? `\n\n🔗 Resolved via symlink: ${symlinkHint}` : "";

  if (insideCwd) {
    return {
      title: action,
      body: `Path:\n  ${filePath}${deniedRule ? `\n\n⚠️ Matches denied rule "${deniedRule}" — typically contains credentials or generated files.` : ""}${symlinkLine}\n`,
      tier2Everything: {
        title: `Confirm Always Allow: ${action} ${resolved.split("/").pop() || resolved}`,
        body: `"Always Yes" will auto-allow "${action}" on this path this session:\n\n  ${resolved}\n\n"Back" returns to the previous prompt.`,
      },
      includePathsOption: false,
      includeFileOption: false,
    };
  }

  const scope = isWriteOp
    ? `auto-allow ${action} for this directory this session`
    : `auto-allow read for this directory this session (write/edit will still prompt)`;
  const tier2Label = isWriteOp ? `${action} ${outsideDir}` : `read ${outsideDir}`;
  const fileName = resolved.split("/").pop() || resolved;

  return {
    title: `⚠️ ${action} outside cwd`,
    body: `Path:\n  ${filePath}\n\n⚠️ Outside cwd: ${outsideDir}${symlinkLine}${deniedRule ? `\n\n⚠️ Matches denied rule "${deniedRule}" — typically contains credentials or generated files.` : ""}\n`,
    tier2Everything: {
      title: `Confirm Always Allow: ${tier2Label}`,
      body: `"Always Yes" will ${scope}:\n\n  ${outsideDir}\n\n"Back" returns to the previous prompt.`,
    },
    tier2File: {
      title: `Confirm Always Allow: ${action} ${fileName}`,
      body: `"Always Yes" will auto-allow "${action}" for this file this session:\n\n  ${resolved}\n\nOther files in ${outsideDir} will still prompt.\n\n"Back" returns to the previous prompt.`,
    },
    includePathsOption: false,
    includeFileOption: true,
  };
}

// ── Subagent prompt ──

function buildSubagentPrompt(
  data: SubagentPromptData,
  _allowRules: { subagentNames?: string[] },
): BuiltPrompt {
  const { mode, taskCount, agentNames, hasWriteAccess } = data;
  const agentsDisplay = agentNames.length > 1 ? agentNames.join(", ") : agentNames[0];
  const modeDisplay = mode === "parallel" ? `parallel (${taskCount} tasks)` : "single";
  const writeWarning = hasWriteAccess
    ? "\n\n\u26a0\ufe0f One or more agents can write files and execute commands."
    : "";

  return {
    title: hasWriteAccess
      ? `\u26a0\ufe0f Subagent`
      : `Subagent`,
    body: `Mode: ${modeDisplay}\nAgent${agentNames.length > 1 ? "s" : ""}: ${agentsDisplay}${writeWarning}\n`,
    tier2Everything: {
      title: "Confirm Always Allow: Subagent spawning",
      body: `"Always Yes" will auto-allow subagent spawning this session.\n\n"Back" returns to the previous prompt.`,
    },
    includePathsOption: false,
    includeFileOption: false,
  };
}
