import path from "node:path";
import { PACKAGE_MANAGERS } from "./config";
import type { AllowRules } from "./store";
import type { PromptData, BashPromptData, FilePromptData, McpPromptData } from "./decision-engine";

/**
 * Generates auto-allow rules based on the provided prompt data.
 * Decouples policy decision from the specific rules used for "Always" options.
 */
export class RuleGenerator {
  /**
   * Generate the primary "Always" rules (e.g. the specific command signatures or directories).
   */
  static generatePrimaryRules(data: PromptData): AllowRules {
    switch (data.type) {
      case "bash":
        return this.generateBashPrimaryRules(data);
      case "file":
        return this.generateFilePrimaryRules(data);
      case "mcp":
        return this.generateMcpPrimaryRules(data);
    }
  }

  /**
   * Generate broader auto-allow rules (e.g. all commands from a package manager).
   * @param data - The prompt data.
   * @param targetDir - For file prompts, the specific parent directory to allow (instead of one dirname up).
   */
  static generateBroaderRules(data: PromptData, targetDir?: string): AllowRules | undefined {
    if (data.type !== "bash" && data.type !== "file") return undefined;

    if (data.type === "bash") {
      return this.generateBashBroaderRules(data);
    }
    if (data.type === "file") {
      return this.generateFileBroaderRules(data, targetDir);
    }
  }

  /**
   * Generate "Paths only" rules for bash commands.
   */
  static generatePathsOnlyRules(data: PromptData): AllowRules | undefined {
    if (data.type !== "bash") return undefined;
    const bash = data as BashPromptData;
    if (bash.outsideDirs.length === 0) return undefined;
    return { readDirs: bash.outsideDirs };
  }

  /**
   * Generate "This file only" rules for file operations.
   */
  static generateFileOnlyRules(data: PromptData): AllowRules | undefined {
    if (data.type !== "file") return undefined;
    const file = data as FilePromptData;
    if (file.outsideDir === null) return undefined; // Only for outside-cwd files

    return file.isWriteOp
      ? { writePaths: [file.resolved], readPaths: [file.resolved] }
      : { readPaths: [file.resolved] };
  }

  // ── Bash Internal ──

  private static generateBashPrimaryRules(data: BashPromptData): AllowRules {
    const rules: AllowRules = {};
    if (data.outsideDirs.length > 0) {
      rules.readDirs = data.outsideDirs;
    }
    // Relative-path tools: store the exact signature bound to this cwd —
    // "Always" must actually work for ../node_modules/.bin/*, and the cwd
    // binding is what keeps a repo-shipped executable from inheriting
    // session-wide bare-name grants elsewhere. SafetyRule refuses an UNBOUND
    // sig grant on any command with a relative-path segment, so a bare
    // bashSigs twin would never auto-allow — it would only pollute the store
    // and mislead the widget. The store stays honest: a relative tool's
    // grant exists only as a cwd-bound entry; non-relative sigs are kept
    // unbound (a mixed command's other sigs still work).
    const relativeSigs = new Set(data.relativeToolIds.map((r) => r.sig));
    const unboundSigs = data.signatures.filter((sig) => !relativeSigs.has(sig));
    if (unboundSigs.length > 0) {
      rules.bashSigs = unboundSigs;
    }
    if (data.relativeToolIds.length > 0) {
      // Bound to the segment's EFFECTIVE base (the working dir the relative
      // token resolves against) — not data.cwd: a grant for ./x must not
      // cover `cd /elsewhere && ./x`.
      rules.bashSigCwds = data.relativeToolIds.map(({ sig, base }) => ({ sig, cwd: base }));
    }
    return rules;
  }

  private static generateBashBroaderRules(data: BashPromptData): AllowRules | undefined {
    // PACKAGE_MANAGERS imported from config
    const signatures = data.signatures;
    const pmSigs = signatures.filter(sig => {
      const firstWord = sig.split(/\s+/)[0];
      return PACKAGE_MANAGERS.has(firstWord);
    });

    if (pmSigs.length === 0) return undefined;

    const broaderSigs = [...new Set(pmSigs.map(sig => sig.split(/\s+/)[0]))];
    return {
      bashSigs: broaderSigs,
      ...(data.outsideDirs.length > 0 ? { readDirs: data.outsideDirs } : {}),
    };
  }

  // ── File Internal ──

  private static generateFilePrimaryRules(data: FilePromptData): AllowRules {
    const { resolved, outsideDir } = data;
    if (outsideDir !== null) {
      // Outside cwd: Always allow the directory
      return data.isWriteOp
        ? { writeDirs: [outsideDir], readDirs: [outsideDir] }
        : { readDirs: [outsideDir] };
    }
    // Inside cwd: Always allow the specific file
    return data.isWriteOp
      ? { writePaths: [resolved], readPaths: [resolved] }
      : { readPaths: [resolved] };
  }

  private static generateFileBroaderRules(data: FilePromptData, targetDir?: string): AllowRules | undefined {
    if (data.outsideDir !== null && !targetDir) return undefined; // Only for inside-cwd (or explicit target)
    const dir = targetDir ?? (data.outsideDir ?? path.dirname(data.resolved));
    return data.isWriteOp
      ? { writeDirs: [dir], readDirs: [dir] }
      : { readDirs: [dir] };
  }

  // ── MCP Internal ──

  private static generateMcpPrimaryRules(data: McpPromptData): AllowRules {
    return { mcpServers: [data.server] };
  }
}
