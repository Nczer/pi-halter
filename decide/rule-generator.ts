import path from "node:path";
import type { AllowRules } from "../gate/store";
import type {PromptData, BashPromptData, FilePromptData, ToolPromptData} from "./types";

/**
 * The filesystem root is never part of an Always grant: one click must not
 * hand out read/write of `/`. A `find /` prompt used to offer
 * "Always (paths only): /" → readDirs ["/"] (read the whole disk), and an
 * /etc file prompt's broader umbrella reached up to `/` (write the whole
 * disk). Root-touching prompts still prompt; they just can't be Always-ed.
 */
function withoutRoot(dirs: string[]): string[] {
  // Marker dirs (<unresolved-…>) are never granted: a grant for a sentinel
  // can never match, and a token's static prefix is escapable by a value
  // containing `..` (the prompt already shows it for context).
  return dirs.filter((d) => d !== "/" && !d.startsWith("<"));
}

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
      case "tool":
        return this.generateToolPrimaryRules(data);
    }
  }

  /**
   * Tool-plugin grants. Consent prompts grant the KIND only (a read consent
   * can never cover the tool's exec actions); exec/file prompts grant the
   * WHOLE tool (the tier-2 confirmation names the exec risk).
   */
  private static generateToolPrimaryRules(data: ToolPromptData): AllowRules {
    const grant =
      data.gate === "consent" && data.consentKind
        ? `${data.tool}:kind:${data.consentKind}`
        : data.tool;
    return { toolGrants: [grant] };
  }

  /**
   * Generate broader auto-allow rules (file prompts: the parent-directory
   * umbrella; bash commands have no broader tier — fetchable run forms are
   * granted by per-package trust, other commands by their signature).
   * @param data - The prompt data.
   * @param targetDir - For file prompts, the specific parent directory to allow (instead of one dirname up).
   */
  static generateBroaderRules(data: PromptData, targetDir?: string): AllowRules | undefined {
    if (data.type !== "file") return undefined;
    return this.generateFileBroaderRules(data, targetDir);
  }

  /**
   * Generate "Paths only" rules for bash commands.
   */
  static generatePathsOnlyRules(data: PromptData): AllowRules | undefined {
    if (data.type !== "bash") return undefined;
    const bash = data as BashPromptData;
    const readDirs = withoutRoot(bash.outsideDirs);
    if (readDirs.length === 0) return undefined;
    return { readDirs };
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
    const readDirs = withoutRoot(data.outsideDirs);
    if (readDirs.length > 0) {
      rules.readDirs = readDirs;
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
    // Fetchable run forms are granted by package trust, not sig rules —
    // a primary "Always" must not silently grant the form signature too.
    const fetchableSigs = new Set((data.fetchableForms ?? []).map((f) => f.sig));
    const unboundSigs = data.signatures.filter((sig) => !relativeSigs.has(sig) && !fetchableSigs.has(sig));
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

  // ── File Internal ──

  private static generateFilePrimaryRules(data: FilePromptData): AllowRules {
    const { resolved, outsideDir } = data;
    if (outsideDir !== null && outsideDir !== "/") {
      // Outside cwd: Always allow the directory (never the root — a file
      // directly under / falls through to the file-level grant below)
      return data.isWriteOp
        ? { writeDirs: [outsideDir], readDirs: [outsideDir] }
        : { readDirs: [outsideDir] };
    }
    // Inside cwd (or outsideDir is the root): Always allow the specific file
    return data.isWriteOp
      ? { writePaths: [resolved], readPaths: [resolved] }
      : { readPaths: [resolved] };
  }

  private static generateFileBroaderRules(data: FilePromptData, targetDir?: string): AllowRules | undefined {
    if (data.outsideDir !== null && !targetDir) return undefined; // Only for inside-cwd (or explicit target)
    const dir = targetDir ?? (data.outsideDir ?? path.dirname(data.resolved));
    if (dir === "/") return undefined; // never grant the root
    return data.isWriteOp
      ? { writeDirs: [dir], readDirs: [dir] }
      : { readDirs: [dir] };
  }

}
