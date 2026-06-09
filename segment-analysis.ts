import {
  isAllowedCommand,
  dangerousFindFlags,
  dangerousPerlFlags,
  dangerousSedFlags,
  dangerousCommandPatterns,
  dangerousContextPatterns,
  isTrustedScriptCommand,
  wrapperCommands,
  isWriteOperation,
  SHELL_INTERPRETERS,
} from "./config";
import type { BashSegment } from "./bash-parser";
import { isFirstTokenRelativePath } from "./path-analysis";
import { containsCommandSubstitution, getFirstWord, splitPipeline, stripNullRedirects } from "./segment-helpers";

// ── Constants ──

const LOOKUP_COMMANDS = new Set(["which", "type", "command", "hash", "whence"]);
const ECHO_COMMANDS = new Set(["echo", "printf", "true", "false"]);
const PROCESS_INSPECTION_COMMANDS = new Set(["pgrep", "pidof"]);
const SHELL_NAMES = new Set(["sh", "bash", "zsh", "fish"]);

// ── Result type ──

/** Risk assessment for a single segment. */
export interface SegmentRisk {
  severity: "high" | "medium" | null;
  reasons: string[];
}

/**
 * Unified analysis of a single command segment.
 * Combines safety checks (simple/unsafe/danger) with risk assessment (reasons/severity).
 * One call replaces hasKnownDanger + isSimpleAllowedCommand + isSegmentUnsafe + analyzeSegmentRisk.
 */
export interface SegmentAnalysis {
  /** Command is a simple allowed command (allowlist, no subshells, no dangerous flags). */
  isSimple: boolean;
  /** Segment matches any unsafe pattern (danger flags, obfuscation, dangerous commands). */
  isUnsafe: boolean;
  /** Segment has known danger patterns (cached result of hasKnownDanger). */
  hasDanger: boolean;
  /** Risk assessment with human-readable reasons and severity. */
  risk: SegmentRisk;
}

// ── Pattern checks (shared by danger detection and risk reasons) ──

function hasWriteRedirect(cmd: string): boolean {
  const trimmed = cmd.trim();
  if (/^[0-9]*&?>+/.test(trimmed)) {
    if (!stripNullRedirects(trimmed).trim()) return false;
  }
  const stripped = stripNullRedirects(cmd);
  if (/>+\s*\S/.test(stripped)) {
    const inTest = /\[\s.*\]/.test(stripped) || /test\s/.test(stripped);
    if (!inTest) return true;
  }
  return false;
}

function detectObfuscation(cmd: string): { detected: boolean; techniques: string[] } {
  const techniques: string[] = [];
  if (/\$\{!/.test(cmd)) techniques.push("variable indirection");
  if (/(?:^|;|\|\||&&)\s*\$[A-Z_][A-Z0-9_]*\s+\w/.test(cmd)) techniques.push("variable holding command");
  if (/[a-z]"[a-z]/.test(cmd) || /[a-z]'[a-z]/.test(cmd)) techniques.push("character concatenation");
  if (/base64\s+[-d]/i.test(cmd) || /printf\s+.*\\x/i.test(cmd)) techniques.push("encoding/decoding");
  if (/xargs\s.*\brm\b/.test(cmd)) techniques.push("indirect command via xargs");
  if (/xargs\s+sh\s+-c\b/.test(cmd) || /xargs\s+bash\s+-c\b/.test(cmd)) techniques.push("xargs piping to shell interpreter");
  if (/\b(alias|declare|typeset)\s+\w+=\s*(rm|sudo|curl|wget|ssh)\b/i.test(cmd)) techniques.push("alias/function obfuscation");
  return { detected: techniques.length > 0, techniques };
}

function hasFlag(args: string[], flag: string): boolean {
  return args.includes(flag) || args.some((a) => a.startsWith(flag + "=") || a.startsWith(flag + "."));
}

function anyArgStartsWith(args: string[], prefix: string): boolean {
  return args.some((a) => a.startsWith(prefix));
}

// ── Git ──

function isGitDangerous(segment: string): boolean {
  const args = segment.trim().split(/\s+/);
  if (args.length < 2) return false;
  const sub = args[1].toLowerCase();
  const subArgs = args.slice(2);
  if (sub === "rm") return true;
  if (sub === "clean" && subArgs.some(a => /-[fdx]/.test(a))) return true;
  if (sub === "reset" && subArgs.includes("--hard")) return true;
  if (sub === "push" && subArgs.some(a => a === "--force" || a === "--force-with-lease" || a === "-f")) return true;
  if (sub === "reflog" && subArgs.includes("expire")) return true;
  if (sub === "gc" && subArgs.some(a => a.startsWith("--prune"))) return true;
  return false;
}

// ── Wrapper commands ──

function skipWrapperArg(firstWord: string, arg: string): boolean {
  if (arg.startsWith("-")) return true;
  if (firstWord === "timeout" && /^\d+(\.\d+)?(?:[smhd])?$/.test(arg)) return true;
  if (firstWord === "nice" && /^\d+$/.test(arg)) return true;
  if (firstWord === "ionice" && /^\d+$/.test(arg)) return true;
  if (firstWord === "env" && /=/.test(arg) && !arg.startsWith("/")) return true;
  return false;
}

function isWrapperRunningWrite(segment: string): boolean {
  const args = segment.trim().split(/\s+/);
  const firstWord = args[0].toLowerCase();
  for (let i = 1; i < args.length; i++) {
    const arg = args[i];
    if (skipWrapperArg(firstWord, arg)) continue;
    const wrappedCmd = arg.toLowerCase();
    if (isWriteOperation(wrappedCmd, segment)) return true;
    break;
  }
  return false;
}

// ── find/fd/rg exec ──

function isFindExecWrite(segment: string): boolean {
  const execMatch = segment.match(/-(?:exec|execdir)\b\s+(\S+)/);
  if (!execMatch) return false;
  const execCmd = execMatch[1].toLowerCase();
  const afterExec = segment.slice(execMatch.index! + execMatch[0].length);
  return isWriteOperation(execCmd, afterExec);
}

function isFdExecWrite(segment: string): boolean {
  const execMatch = segment.match(/-(?:x|X)\b\s+(\S+)/);
  if (!execMatch) return false;
  const execCmd = execMatch[1].toLowerCase();
  const afterExec = segment.slice(execMatch.index! + execMatch[0].length);
  return isWriteOperation(execCmd, afterExec);
}

function isRgPreWrite(segment: string): boolean {
  const preMatch = segment.match(/--pre(?:=|\s+)(\S+)/);
  if (!preMatch) return false;
  const preCmd = preMatch[1].toLowerCase();
  const afterPre = segment.slice(preMatch.index! + preMatch[0].length);
  return isWriteOperation(preCmd, afterPre);
}

// ── Unified segment analysis ──

/**
 * Analyze a single command segment. Produces safety booleans and risk assessment
 * in one pass. Replaces hasKnownDanger + isSimpleAllowedCommand + isSegmentUnsafe + analyzeSegmentRisk.
 */
export async function analyzeSegment(seg: BashSegment, cwd: string): Promise<SegmentAnalysis> {
  const segment = seg.text;
  const trimmed = segment.trim();
  const firstWord = getFirstWord(segment);
  const args = trimmed.split(/\s+/);
  const rest = args.slice(1);
  const ops = seg.ops;

  const reasons: string[] = [];
  let severity: "high" | "medium" | null = null;
  const setSeverity = (s: "high" | "medium") => {
    if (s === "high" || !severity) severity = s;
  };

  // ── Danger flags (accumulated, used for isSimple/isUnsafe derivation) ──
  let hasDangerFlag = false;
  let hasDangerInPipeline = false;

  // Subshell
  if (seg.hasSubshell) {
    hasDangerFlag = true;
    reasons.push("command substitution (subshell)");
    setSeverity("high");
  }

  // Heredoc to interpreter
  const hasHeredoc = ops.includes("<<") || ops.includes("<<<");
  const isInterpreterWithHeredoc = hasHeredoc && new RegExp("^(python|node|ruby|php|lua|perl|deno|bun|jruby|pypy|graalvm|uv|bash|sh|zsh|fish|csh|tcsh|ksh)", "i").test(firstWord);
  if (isInterpreterWithHeredoc) {
    hasDangerFlag = true;
    reasons.push("heredoc to shell interpreter (executable code)");
    setSeverity("high");
  }

  // Write redirect
  const writeRedirect = hasWriteRedirect(segment);
  if (writeRedirect) {
    hasDangerFlag = true;
    reasons.push("shell output redirection (can overwrite files)");
    setSeverity("medium");
  }

  // find/fd/rg exec write
  if (firstWord === "find" && dangerousFindFlags.test(segment)) {
    hasDangerFlag = true;
    reasons.push("find with dangerous flags");
    setSeverity("high");
  }
  if (firstWord === "find" && isFindExecWrite(segment)) {
    hasDangerFlag = true;
    reasons.push("find -exec with write operation");
    setSeverity("high");
  }
  if (firstWord === "fd" && isFdExecWrite(segment)) {
    hasDangerFlag = true;
    reasons.push("fd -x with write operation");
    setSeverity("high");
  }
  if (firstWord === "rg" && isRgPreWrite(segment)) {
    hasDangerFlag = true;
    reasons.push("rg --pre with write operation");
    setSeverity("high");
  }

  // sed/perl flags
  if (firstWord === "sed" && dangerousSedFlags.test(segment)) {
    hasDangerFlag = true;
    reasons.push("sed -i (in-place file modification)");
    setSeverity("high");
  }
  if (firstWord === "perl" && dangerousPerlFlags.test(segment)) {
    hasDangerFlag = true;
    reasons.push("perl -pi/-i (in-place file modification)");
    setSeverity("high");
  }

  // Git dangerous
  if (firstWord === "git" && isGitDangerous(segment)) {
    hasDangerFlag = true;
    setSeverity("high");
  }

  // Wrapper running write
  if (wrapperCommands.has(firstWord) && isWrapperRunningWrite(segment)) {
    hasDangerFlag = true;
    setSeverity("high");
  }

  // ── Pipeline analysis (single loop for all checks) ──
  const stages = splitPipeline(segment);
  if (stages.length > 1) {
    let allStagesSimple = true;
    for (let i = 1; i < stages.length; i++) {
      const stage = stages[i];
      const stageCmd = getFirstWord(stage);

      // Check for relative path in pipeline stage
      if (isFirstTokenRelativePath(stage)) {
        allStagesSimple = false;
        continue;
      }

      // Check if stage is an allowed command
      if (!isAllowedCommand(stageCmd)) {
        allStagesSimple = false;
        // Pipe to shell
        if (SHELL_NAMES.has(stageCmd)) {
          reasons.push("pipe to a shell (possible remote code execution)");
          setSeverity("high");
        }
        // Check dangerous command patterns even for non-allowed commands
        if (dangerousCommandPatterns.some(({ pattern }) => pattern.test(stageCmd))) {
          hasDangerInPipeline = true;
        }
        if (dangerousContextPatterns.some(({ pattern }) => pattern.test(stage))) {
          hasDangerInPipeline = true;
        }
        continue;
      }

      // Check stage-specific danger patterns
      let stageDangerous = false;

      if (stageCmd === "find" && (dangerousFindFlags.test(stage) || isFindExecWrite(stage))) stageDangerous = true;
      if (stageCmd === "fd" && isFdExecWrite(stage)) stageDangerous = true;
      if (stageCmd === "rg" && isRgPreWrite(stage)) stageDangerous = true;
      if (stageCmd === "sed" && dangerousSedFlags.test(stage)) {
        stageDangerous = true;
        if (!reasons.includes("sed -i (in-place file modification)")) {
          reasons.push("sed -i in pipeline (in-place file modification)");
          setSeverity("high");
        }
      }
      if (stageCmd === "perl" && dangerousPerlFlags.test(stage)) {
        stageDangerous = true;
        if (!reasons.includes("perl -pi/-i (in-place file modification)")) {
          reasons.push("perl -pi/-i in pipeline (in-place file modification)");
          setSeverity("high");
        }
      }
      if (stageCmd === "git" && isGitDangerous(stage)) stageDangerous = true;
      if (wrapperCommands.has(stageCmd) && isWrapperRunningWrite(stage)) stageDangerous = true;
      if (hasWriteRedirect(stage)) stageDangerous = true;
      if (dangerousCommandPatterns.some(({ pattern }) => pattern.test(stageCmd))) stageDangerous = true;
      if (dangerousContextPatterns.some(({ pattern }) => pattern.test(stage))) stageDangerous = true;

      if (stageDangerous) {
        allStagesSimple = false;
        hasDangerInPipeline = true;
      }
    }
    if (hasDangerInPipeline) {
      hasDangerFlag = true;
    }
    // Store for isSimple derivation
    (analyzeSegment as any)._allStagesSimple = allStagesSimple;
  } else {
    (analyzeSegment as any)._allStagesSimple = true;
  }

  // ── Per-segment risk (token analysis) ──
  // sudo
  if (firstWord === "sudo") {
    reasons.push("sudo (elevated privileges)");
    setSeverity("high");
  }

  // rm/rmdir/unlink
  if (firstWord === "rm" || firstWord === "rmdir" || firstWord === "unlink") {
    setSeverity("high");
    if (rest.some((a) => a.includes("-r") || a.includes("-R"))) reasons.push("recursive delete (-r/-R)");
    if (rest.some((a) => a.includes("-f"))) reasons.push("forced delete (-f)");
  }

  // find -delete
  if (firstWord === "find" && rest.includes("-delete")) {
    setSeverity("high");
    reasons.push("find -delete (bulk deletion)");
  }

  // git operations
  if (firstWord === "git") {
    const sub = rest[0];
    const subArgs = rest.slice(1);
    reasons.push(sub ? `git ${sub} (git command)` : "git (git command)");
    if (sub === "rm") {
      setSeverity("high");
      reasons.push("git rm (deletes files from working tree and stages deletions)");
    }
    if (sub === "clean" && (subArgs.some((a) => a.includes("-f")) || subArgs.includes("-d") || subArgs.includes("-x"))) {
      setSeverity("high");
      reasons.push("git clean (can delete untracked files)");
    }
    if (sub === "reset" && subArgs.includes("--hard")) {
      setSeverity("high");
      reasons.push("git reset --hard (discard changes)");
    }
    if ((sub === "checkout" || sub === "restore") && (subArgs.includes(".") || subArgs.includes("--") || subArgs.includes("--source"))) {
      reasons.push("git checkout/restore (can overwrite working tree)");
    }
    if (sub === "push" && (subArgs.includes("--force") || subArgs.includes("--force-with-lease") || subArgs.includes("-f"))) {
      setSeverity("high");
      reasons.push("git push --force (rewrite remote history)");
    }
    if (sub === "reflog" && subArgs.includes("expire")) {
      setSeverity("high");
      reasons.push("git reflog expire (can remove recovery history)");
    }
    if (sub === "gc" && subArgs.some((a) => a.startsWith("--prune"))) {
      setSeverity("high");
      reasons.push("git gc --prune (can permanently delete objects)");
    }
  }

  // truncate
  if (firstWord === "truncate") {
    reasons.push("truncate (in-place size change, can erase contents)");
  }

  // dd of=
  if (firstWord === "dd" && anyArgStartsWith(rest, "of=")) {
    setSeverity("high");
    reasons.push("dd with output file/device (can overwrite data)");
  }

  // Disk / volume management
  if (firstWord.startsWith("mkfs")) { setSeverity("high"); reasons.push("mkfs (filesystem formatting)"); }
  if (firstWord.startsWith("newfs_")) { setSeverity("high"); reasons.push("newfs_* (filesystem formatting)"); }
  if (firstWord === "wipefs") { setSeverity("high"); reasons.push("wipefs (disk signature wipe)"); }
  if (firstWord === "diskutil") {
    setSeverity("high"); reasons.push("diskutil (disk management command)");
    if (rest.includes("eraseDisk") || rest.includes("eraseVolume")) reasons.push("diskutil erase (destructive disk operation)");
  }
  if (firstWord === "hdiutil") { setSeverity("high"); reasons.push("hdiutil (disk image management command)"); }
  if (firstWord === "gpt") { setSeverity("high"); reasons.push("gpt (partition table manipulation)"); }
  if (firstWord === "asr") { setSeverity("high"); reasons.push("asr (Apple Software Restore; can overwrite volumes)"); }
  if (["parted", "fdisk", "gdisk", "sgdisk"].includes(firstWord)) { setSeverity("high"); reasons.push(`${firstWord} (disk/partition management)`); }
  if (firstWord === "lsblk") { setSeverity("medium"); reasons.push("lsblk (disk listing)"); }
  if (firstWord === "cryptsetup") { setSeverity("high"); reasons.push("cryptsetup (disk encryption management)"); }
  if (["pvcreate", "vgcreate", "lvcreate"].includes(firstWord)) { setSeverity("high"); reasons.push(`${firstWord} (LVM volume management)`); }
  if (firstWord === "zpool") { setSeverity("high"); reasons.push("zpool (ZFS pool management)"); }

  // chmod/chown recursive
  if (firstWord === "chmod" && (rest.includes("-R") || rest.includes("--recursive"))) reasons.push("chmod -R (recursive permission changes)");
  if (firstWord === "chown" && (rest.includes("-R") || rest.includes("--recursive"))) reasons.push("chown -R (recursive ownership changes)");

  // mv/cp overwriting
  if (firstWord === "mv" && (rest.includes("-f") || rest.includes("--force"))) reasons.push("mv --force/-f (can overwrite files)");
  if (firstWord === "cp" && (rest.includes("-f") || rest.includes("--force"))) reasons.push("cp --force/-f (can overwrite files)");

  // kill/shutdown/systemctl
  if (["kill", "pkill", "killall"].includes(firstWord)) {
    reasons.push(`${firstWord} (process termination)`);
    if (rest.includes("-9")) { setSeverity("high"); reasons.push("SIGKILL (-9)"); }
  }
  if (["shutdown", "reboot"].includes(firstWord)) { setSeverity("high"); reasons.push(`${firstWord} (system power operation)`); }
  if (firstWord === "systemctl" && (rest.includes("stop") || rest.includes("disable"))) reasons.push("systemctl stop/disable (service disruption)");

  // Remote execution via pipe
  if ((firstWord === "curl" || firstWord === "wget") && ops.includes("|")) {
    setSeverity("high");
    reasons.push("curl/wget piped (possible remote code execution)");
  }

  // Infra deletes
  if (firstWord === "kubectl" && rest[0] === "delete") { setSeverity("high"); reasons.push("kubectl delete (resource deletion)"); }
  if (firstWord === "terraform" && rest[0] === "destroy") { setSeverity("high"); reasons.push("terraform destroy (infrastructure teardown)"); }
  if (firstWord === "aws" && rest[0] === "s3" && rest[1] === "rm" && rest.includes("--recursive")) { setSeverity("high"); reasons.push("aws s3 rm --recursive (bulk deletion)"); }
  if (firstWord === "gcloud" && rest.includes("delete")) { setSeverity("high"); reasons.push("gcloud delete (resource deletion)"); }

  // ── Obfuscation ──
  const obfuscation = detectObfuscation(segment);
  const isObfuscated = containsCommandSubstitution(segment) || obfuscation.detected;
  if (obfuscation.techniques.length > 0) {
    for (const tech of obfuscation.techniques) {
      if (!reasons.includes(tech)) reasons.push(tech);
    }
    setSeverity("high");
  }

  // ── Regex-based safety net (dangerous command/context patterns) ──
  const isLookupOrEcho = LOOKUP_COMMANDS.has(firstWord) || ECHO_COMMANDS.has(firstWord) || PROCESS_INSPECTION_COMMANDS.has(firstWord);
  const isTrusted = isTrustedScriptCommand(segment, cwd);

  if (!isTrusted && !isLookupOrEcho) {
    for (const { pattern, label } of dangerousCommandPatterns) {
      if (pattern.test(firstWord) && !reasons.includes(label)) {
        reasons.push(label);
        setSeverity("medium");
      }
    }
    for (const { pattern, label } of dangerousContextPatterns) {
      if (pattern.test(segment) && !reasons.includes(label)) {
        reasons.push(label);
        setSeverity("medium");
      }
    }
  }

  // ── Derive booleans ──
  const allStagesSimple = (analyzeSegment as any)._allStagesSimple as boolean;
  const hasDanger = hasDangerFlag;

  // isSimple: allowed command, no danger, no relative path, all pipeline stages simple
  const isRedirectOnly = /^[0-9]*&?>+/.test(trimmed);
  let isSimple: boolean;
  if (isRedirectOnly) {
    isSimple = !writeRedirect;
  } else if (isTrusted) {
    isSimple = true;
  } else if (isFirstTokenRelativePath(segment)) {
    isSimple = false;
  } else {
    isSimple = isAllowedCommand(firstWord) && !hasDanger
      && !(wrapperCommands.has(firstWord) && isWrapperRunningRelativePath(segment))
      && allStagesSimple;
  }

  // isUnsafe: danger flag, obfuscation, or dangerous command/context patterns
  let isUnsafe: boolean;
  if (isRedirectOnly && !writeRedirect) {
    isUnsafe = false;
  } else {
    isUnsafe = hasDanger || isObfuscated || (!isTrusted && !isLookupOrEcho && (
      dangerousCommandPatterns.some(({ pattern }) => pattern.test(firstWord))
      || dangerousContextPatterns.some(({ pattern }) => pattern.test(segment))
    ));
  }

  return { isSimple, isUnsafe, hasDanger, risk: { severity, reasons } };
}

// ── Helpers used by isSimple derivation ──

function isWrapperRunningRelativePath(segment: string): boolean {
  const args = segment.trim().split(/\s+/);
  const firstWord = args[0].toLowerCase();
  for (let i = 1; i < args.length; i++) {
    const arg = args[i];
    if (skipWrapperArg(firstWord, arg)) continue;
    if (isFirstTokenRelativePath(arg)) return true;
    break;
  }
  return false;
}
