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
   */
  static generateBroaderRules(data: PromptData): AllowRules | undefined {
    if (data.type !== "bash" && data.type !== "file") return undefined;

    if (data.type === "bash") {
      return this.generateBashBroaderRules(data);
    }
    if (data.type === "file") {
      return this.generateFileBroaderRules(data);
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
    if (data.signatures.length > 0) {
      rules.bashSigs = data.signatures;
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

  private static generateFileBroaderRules(data: FilePromptData): AllowRules | undefined {
    if (data.outsideDir !== null) return undefined; // Only for inside-cwd
    const parentDir = path.dirname(data.resolved);
    return data.isWriteOp
      ? { writeDirs: [parentDir], readDirs: [parentDir] }
      : { readDirs: [parentDir] };
  }

  // ── MCP Internal ──

  private static generateMcpPrimaryRules(data: McpPromptData): AllowRules {
    return { mcpServers: [data.server] };
  }
}
