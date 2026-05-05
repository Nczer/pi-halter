import type { ExtensionContext } from "@mariozechner/pi-coding-agent";
import { truncateToWidth } from "@mariozechner/pi-tui";
import { store } from "./store";

// ── Widget rendering ──

/** Group command signature variants for compact display (e.g. "git[-m, -am]"). */
function groupCommandVariants(items: string[]): string[] {
  const groups = new Map<string, Set<string>>();
  for (const sig of items) {
    const [cmd, ...flags] = sig.split(/\s+/);
    const group = groups.get(cmd) ?? new Set();
    const flagStr = flags.length === 0 ? "" : flags.join(" ");
    group.add(flagStr);
    groups.set(cmd, group);
  }
  const result: string[] = [];
  for (const [cmd, flags] of groups) {
    const nonEmpty = [...flags].filter(f => f).sort();
    const hasNoFlags = flags.has("");
    if (nonEmpty.length === 0 && hasNoFlags) {
      result.push(cmd);
    } else if (nonEmpty.length === 1 && !hasNoFlags) {
      result.push(`${cmd} ${nonEmpty[0]}`);
    } else {
      const sigs: string[] = [];
      if (hasNoFlags) sigs.push(cmd);
      for (const f of nonEmpty) sigs.push(`${cmd} ${f}`);
      result.push(`${cmd}[${sigs.join(", ")}]`);
    }
  }
  return result;
}

/**
 * Update the permissions status widget based on current store state.
 * Hides the widget when no permissions are active.
 */
export function updateWidget(ctx: ExtensionContext): void {
  const bashItems = [...store.listAllowedBash()];
  const pathItems = [...store.listAllowedPaths()];
  const readDirItems = [...store.listAllowedReadDirs()];
  const writeDirItems = [...store.listAllowedWriteDirs()];
  const subagentItems = [...store.listAllowedSubagent()];

  if (bashItems.length === 0 && pathItems.length === 0 && readDirItems.length === 0 && writeDirItems.length === 0 && subagentItems.length === 0) {
    ctx.ui.setWidget("permissions", undefined);
    return;
  }

  ctx.ui.setWidget("permissions", (_tui, theme) => {
    const baseLines: string[] = [theme.fg("accent", theme.bold("Permissions (this session)"))];

    if (bashItems.length > 0) {
      const grouped = groupCommandVariants(bashItems);
      baseLines.push(theme.fg("muted", "Bash:") + " " + theme.fg("dim", grouped.join(" ")));
    }
    if (readDirItems.length > 0) {
      baseLines.push(theme.fg("muted", "Read dirs:") + " " + theme.fg("dim", readDirItems.join(" ")));
    }
    if (writeDirItems.length > 0) {
      baseLines.push(theme.fg("muted", "Write dirs:") + " " + theme.fg("dim", writeDirItems.join(" ")));
    }
    if (pathItems.length > 0) {
      baseLines.push(theme.fg("muted", "Paths:") + " " + theme.fg("dim", pathItems.join(" ")));
    }
    if (subagentItems.length > 0) {
      baseLines.push(theme.fg("muted", "Subagents:") + " " + theme.fg("dim", subagentItems.join(", ")));
    }

    return { render: (width: number) => baseLines.map(l => truncateToWidth(l, width)), invalidate: () => {} };
  }, { placement: "belowEditor" });
}
