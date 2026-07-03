import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import { truncateToWidth } from "@earendil-works/pi-tui";
import { store } from "./store";

// ── Path deduplication ──

/** Remove paths that are sub-paths of another entry in the same list. */
export function filterSubPaths(paths: string[]): string[] {
  const sorted = [...paths].sort();
  const result: string[] = [];
  for (const p of sorted) {
    // Normalize: strip trailing slash for comparison
    const pNorm = p.endsWith("/") ? p.slice(0, -1) : p;
    let isSub = false;
    for (const parent of result) {
      const parentNorm = parent.endsWith("/") ? parent.slice(0, -1) : parent;
      if (pNorm === parentNorm || pNorm.startsWith(parentNorm + "/")) { isSub = true; break; }
    }
    if (!isSub) result.push(p);
  }
  return result;
}

// ── Widget rendering ──

/** Group command signature variants for compact display (e.g. "git[-m, -am]"). */
export function groupCommandVariants(items: string[]): string[] {
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
 * Update the halter status widget based on current store state.
 * Hides the widget when no halter rules are active.
 */
export function updateWidget(ctx: ExtensionContext): void {
  const bashItems = [...store.listAllowedBash()];
  const readPathItems = filterSubPaths([...store.listAllowedReadPaths()]);
  const writePathItems = filterSubPaths([...store.listAllowedWritePaths()]);
  const readDirItems = filterSubPaths([...store.listAllowedReadDirs()]);
  const writeDirItems = filterSubPaths([...store.listAllowedWriteDirs()]);
  const mcpServerItems = [...store.listAllowedMcpServers()];

  // Merge dirs + paths; since write implies read, R/W paths don't also appear in R
  const allReadPaths = filterSubPaths([...readDirItems, ...readPathItems]);
  const allWritePaths = filterSubPaths([...writeDirItems, ...writePathItems]);
  const readOnlyPaths = allReadPaths.filter(p => !allWritePaths.some(wp => p === wp || p.startsWith(wp + "/")));

  const hasSessionRules = bashItems.length > 0 || readOnlyPaths.length > 0 || allWritePaths.length > 0 || mcpServerItems.length > 0;

  if (!hasSessionRules) {
    ctx.ui.setWidget("halter", undefined);
    return;
  }

  ctx.ui.setWidget("halter", (_tui, theme) => {
    const baseLines: string[] = [theme.fg("accent", theme.bold("Halter"))];

    if (hasSessionRules) {
      if (bashItems.length > 0) {
        const grouped = groupCommandVariants(bashItems);
        baseLines.push(theme.fg("muted", "Bash:") + " " + theme.fg("dim", grouped.join(" ")));
      }
      if (readOnlyPaths.length > 0) {
        baseLines.push(theme.fg("muted", "R:") + " " + theme.fg("dim", readOnlyPaths.join(" ")));
      }
      if (allWritePaths.length > 0) {
        baseLines.push(theme.fg("muted", "R/W:") + " " + theme.fg("dim", allWritePaths.join(" ")));
      }
      if (mcpServerItems.length > 0) {
        baseLines.push(theme.fg("muted", "MCP:") + " " + theme.fg("dim", mcpServerItems.map(s => `${s}:*`).join(", ")));
      }
    }

    return { render: (width: number) => baseLines.map(l => truncateToWidth(l, width)), invalidate: () => {} };
  }, { placement: "belowEditor" });
}
