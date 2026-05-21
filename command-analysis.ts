import path from "node:path";
import {
  allowedBashPatterns,
  dangerousFindFlags,
  dangerousPerlFlags,
  dangerousSedFlags,
  dangerousCommandPatterns,
  dangerousContextPatterns,
  isTrustedScriptCommand,
  wrapperCommands,
  writeCapableCommands,
} from "./config";
import { extractPathsFromBash, hasSubshell as hasSubshellAST, extractSegments as extractSegmentsAST } from "./bash-parser";

// ── Public types ──

export type Severity = "high" | "medium";

export interface CommandRisk {
  dangerous: boolean;
  reasons: string[];
  severity: Severity | null;
}

export interface ObfuscationResult {
  detected: boolean;
  techniques: string[];
}

/** Full analysis of a shell command — single source of truth for parsing, safety, and risk. */
export interface CommandAnalysis {
  /** Raw segment strings, split on &&, ||, ;, |, etc. */
  segments: string[];
  /** Command signatures for auto-allow matching (e.g. "git -R", "ls"). */
  signatures: string[];
  /** All extracted file/dir paths, resolved to absolute. */
  paths: string[];
  /** Every segment is a simple allowed command (allowlist, no subshells/redirects/dangerous flags). */
  allSimple: boolean;
  /** Any segment matches an unsafe pattern (subshell, obfuscation, dangerous flags, write redirect, danger regex). */
  hasUnsafePattern: boolean;
  /** Detailed risk assessment from token-based and regex-based analysis. */
  risk: CommandRisk;
  /** Obfuscation detection results. */
  obfuscation: ObfuscationResult;
}

// ── Segment helpers (string-based, for signature extraction) ──

function stripQuotedStrings(cmd: string): string {
  let s = cmd.replace(/"(?:[^"\\]|\\.)*"/g, (match) => {
    if (/\$\s*\(/.test(match) || /`/.test(match)) return "__CMD_SUBST__";
    return "__STR__";
  });
  s = s.replace(/'[^']*'/g, "__STR__");
  s = s.replace(/\$'[^']*'/g, "__STR__");
  s = s.replace(/\s*#.*$/gm, "");
  return s;
}

// ── Segment helpers ──

function getFirstWord(segment: string): string {
  const word = segment.trim().split(/\s+/)[0].toLowerCase();
  // Normalize path-prefixed binaries (e.g. /usr/bin/git → git)
  return path.basename(word);
}

/**
 * Split a segment into pipeline parts (on |). Each part is one command in the pipeline.
 * Returns trimmed command strings for each pipeline stage.
 */
function splitPipeline(segment: string): string[] {
  return segment.split("|").map(s => s.trim()).filter(Boolean);
}

/** Check if ANY command in a pipeline has dangerous sed flags. */
function hasDangerousSedInPipeline(segment: string): boolean {
  return splitPipeline(segment).some(part => {
    const cmd = getFirstWord(part);
    return cmd === "sed" && dangerousSedFlags.test(part);
  });
}

/** Check if ANY command in a pipeline has dangerous perl flags. */
function hasDangerousPerlInPipeline(segment: string): boolean {
  return splitPipeline(segment).some(part => {
    const cmd = getFirstWord(part);
    return cmd === "perl" && dangerousPerlFlags.test(part);
  });
}

/** Check if a git command is dangerous (rm, clean, reset --hard, push --force, etc.). */
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

/**
 * Extract a command signature from a segment, handling pipelines and redirects.
 * Strips shell redirections (2>&1, >, >>, etc.) before extracting command + flags.
 * For pipelines ("cmd1 | cmd2"), uses the first command's signature.
 */
function getCommandSignature(segment: string): string {
  // For pipelines, take the first command part
  const firstCmd = segment.split("|")[0].trim();
  // Strip shell redirections: 2>&1, > file, >> file, 2> file, &> file, etc.
  const cleaned = firstCmd
    .replace(/&?[0-9]*>>?\s*\S+/g, "") // redirect patterns
    .replace(/<\s*\S+/g, "")           // input redirects
    .trim();
  const tokens = stripQuotedStrings(cleaned).split(/\s+/);
  const cmd = tokens[0].toLowerCase();
  const flags = tokens.slice(1).filter(t => t.startsWith("-")).sort();
  return flags.length === 0 ? cmd : `${cmd} ${flags.join(" ")}`;
}

// ── Safety checks ──

async function hasSubshell(cmd: string): Promise<boolean> {
  // Quick regex check for common patterns (fast path)
  if (/\$\s*\(/.test(cmd) || /`/.test(cmd) || /<\s*\(/.test(cmd)) return true;
  // Full AST check for edge cases
  return hasSubshellAST(cmd);
}

function hasWriteRedirect(cmd: string): boolean {
  // If the segment is ONLY a redirect (no command name), check if it's safe
  const trimmed = cmd.trim();
  if (/^[0-9]*&?>+/.test(trimmed)) {
    // Strip safe redirects
    let stripped = trimmed;
    stripped = stripped.replace(/[0-9]*&?>+\s*(?:\/dev\/(?:null|stderr))\b/g, "");
    stripped = stripped.replace(/[0-9]*>&[0-9]+/g, ""); // fd duplication
    if (!stripped.trim()) return false; // entire segment is safe redirect
  }

  let stripped = cmd;
  stripped = stripped.replace(/[0-9]*&?>+\s*(?:\/dev\/(?:null|stderr))\b/g, "");
  stripped = stripped.replace(/[0-9]*>&[0-9]+/g, ""); // fd duplication (e.g. 2>&1, >&1) is safe
  if (/>+\s*\S/.test(stripped)) {
    const inTest = /\[\s.*\]/.test(stripped) || /test\s/.test(stripped);
    if (!inTest) return true;
  }
  return false;
}

function detectObfuscation(cmd: string): ObfuscationResult {
  const techniques: string[] = [];
  if (/\$\{!/.test(cmd) || /\$[A-Z_]+\s/.test(cmd)) {
    techniques.push("variable indirection");
  }
  if (/[a-z]"[a-z]/.test(cmd) || /[a-z]'[a-z]/.test(cmd)) {
    techniques.push("character concatenation");
  }
  if (/base64\s+[-d]/i.test(cmd) || /printf\s+.*\\x/i.test(cmd)) {
    techniques.push("encoding/decoding");
  }
  if (/xargs\s.*\brm\b/.test(cmd)) {
    techniques.push("indirect command via xargs");
  }
  if (/\b(alias|declare|typeset)\s+\w+=\s*(rm|sudo|curl|wget|ssh)\b/i.test(cmd)) {
    techniques.push("alias/function obfuscation");
  }
  return { detected: techniques.length > 0, techniques };
}

function isSegmentObfuscated(seg: string): boolean {
  return /__CMD_SUBST__/.test(seg) || detectObfuscation(seg).detected;
}

/**
 * Check if a wrapper command (xargs, watch, timeout) is running a write-capable command.
 * e.g. "xargs sed -i" → true, "xargs grep -l" → false
 */
function isWrapperRunningWrite(segment: string): boolean {
  const args = segment.trim().split(/\s+/);
  const firstWord = args[0].toLowerCase();
  // Skip wrapper flags (-0, -r, -I, -n, etc.) and duration args (for timeout) to find the actual command
  for (let i = 1; i < args.length; i++) {
    const arg = args[i];
    if (arg.startsWith("-")) continue; // skip flags
    // timeout has a duration argument before the command (e.g., "timeout 30 rm")
    if (firstWord === "timeout" && /^\d+(\.\d+)?(?:[smhd])?$/.test(arg)) continue;
    const wrappedCmd = arg.toLowerCase();
    // Command itself writes
    if (writeCapableCommands.has(wrappedCmd)) {
      // Check for write-indicating flags on the wrapped command
      const rest = args.slice(i + 1);
      if (wrappedCmd === "sed" && /-\bi(?:\.\S*)?(?:\s|$)|--in-place(?:\b|\s)/.test(segment)) return true;
      if (wrappedCmd === "perl" && /-\bi(?:\.\S*)?(?:\s|$)|-pi\b|-p.*-i\b/.test(segment)) return true;
      if (wrappedCmd === "rm" || wrappedCmd === "rmdir" || wrappedCmd === "unlink") return true;
      if (wrappedCmd === "mv" || wrappedCmd === "cp") return true;
      if (wrappedCmd === "chmod" || wrappedCmd === "chown") return true;
      if (wrappedCmd === "touch" || wrappedCmd === "mkdir") return true;
      if (wrappedCmd === "dd" || wrappedCmd === "truncate") return true;
      if (wrappedCmd === "patch" || wrappedCmd === "install") return true;
      // Archive/package commands — write by default
      if (["tar", "zip", "unzip", "gzip", "gunzip"].includes(wrappedCmd)) return true;
      if (["pip", "npm", "yarn", "cargo", "go", "uv"].includes(wrappedCmd)) return true;
      // tee writes when given file args (not just stdout)
      if (wrappedCmd === "tee" && /\btee\b.*\S/.test(segment)) return true;
    }
    break; // only check first non-flag argument (the command)
  }
  return false;
}

/**
 * Check if `find -exec` or `find -execdir` runs a write-capable command.
 * e.g. "find . -exec sed -i ... {} \;" → true, "find . -exec grep -l ... {} \;" → false
 */
function isFindExecWrite(segment: string): boolean {
  // Check for -exec or -execdir
  const execMatch = segment.match(/-(?:exec|execdir)\b\s+(\S+)/);
  if (!execMatch) return false;

  const execCmd = execMatch[1].toLowerCase();
  if (writeCapableCommands.has(execCmd)) {
    // Only check flags after -exec <cmd> to avoid matching find's own flags
    const afterExec = segment.slice(execMatch.index! + execMatch[0].length);
    if (execCmd === "sed" && /-\bi(?:\.\S*)?(?:\s|$)|--in-place(?:\b|\s)/.test(afterExec)) return true;
    if (execCmd === "perl" && /-\bi(?:\.\S*)?(?:\s|$)|-pi\b|-p.*-i\b/.test(afterExec)) return true;
    if (execCmd === "rm" || execCmd === "rmdir" || execCmd === "unlink") return true;
    if (execCmd === "mv" || execCmd === "cp") return true;
    if (execCmd === "chmod" || execCmd === "chown") return true;
    if (execCmd === "touch" || execCmd === "mkdir") return true;
    if (execCmd === "dd" || execCmd === "truncate") return true;
    if (execCmd === "patch" || execCmd === "install") return true;
    if (["tar", "zip", "unzip", "gzip", "gunzip"].includes(execCmd)) return true;
    if (["pip", "npm", "yarn", "cargo", "go", "uv"].includes(execCmd)) return true;
  }
  return false;
}

async function isSimpleAllowedCommand(segment: string, cwd: string): Promise<boolean> {
  // Redirect-only segments (e.g. 2>/dev/null, >&1) are safe modifiers, not commands
  const trimmed = segment.trim();
  if (/^[0-9]*&?>+/.test(trimmed)) {
    return !hasWriteRedirect(segment); // safe if no real file write
  }

  // Trusted scripts in known directories are simple-allowed
  if (isTrustedScriptCommand(segment, cwd)) return true;

  const firstWord = getFirstWord(segment);
  if (!allowedBashPatterns.some(p => p.test(firstWord))) return false;
  if (await hasSubshell(segment)) return false;
  if (firstWord === "find" && dangerousFindFlags.test(segment)) return false;
  if (firstWord === "find" && isFindExecWrite(segment)) return false;
  if (firstWord === "sed" && dangerousSedFlags.test(segment)) return false;
  if (firstWord === "perl" && dangerousPerlFlags.test(segment)) return false;
  if (hasDangerousSedInPipeline(segment)) return false;
  if (hasDangerousPerlInPipeline(segment)) return false;
  if (firstWord === "git" && isGitDangerous(segment)) return false;
  if (wrapperCommands.has(firstWord) && isWrapperRunningWrite(segment)) return false;
  if (hasWriteRedirect(segment)) return false;
  return true;
}

const LOOKUP_COMMANDS = new Set(["which", "type", "command", "hash", "whence"]);
const ECHO_COMMANDS = new Set(["echo", "printf", "true", "false"]);
const PROCESS_INSPECTION_COMMANDS = new Set(["pgrep", "pidof"]);

async function isSegmentUnsafe(seg: string, cwd: string): Promise<boolean> {
  // Redirect-only segments are safe if they don't write to a real file
  const trimmed = seg.trim();
  if (/^[0-9]*&?>+/.test(trimmed) && !hasWriteRedirect(seg)) return false;

  // Trusted scripts: skip dangerous-pattern check for interpreter + script in trusted dir
  const trusted = isTrustedScriptCommand(seg, cwd);
  const firstWord = getFirstWord(seg);

  // Lookup commands (which, type, etc.), echo commands, and process inspection commands
  // don't execute their arguments — skip dangerousPatterns for them
  const isLookupOrEcho = LOOKUP_COMMANDS.has(firstWord) || ECHO_COMMANDS.has(firstWord) || PROCESS_INSPECTION_COMMANDS.has(firstWord);

  return (await hasSubshell(seg))
    || isSegmentObfuscated(seg)
    || (firstWord === "find" && dangerousFindFlags.test(seg))
    || (firstWord === "find" && isFindExecWrite(seg))
    || (firstWord === "sed" && dangerousSedFlags.test(seg))
    || (firstWord === "perl" && dangerousPerlFlags.test(seg))
    || hasDangerousSedInPipeline(seg)
    || hasDangerousPerlInPipeline(seg)
    || (firstWord === "git" && isGitDangerous(seg))
    || (wrapperCommands.has(firstWord) && isWrapperRunningWrite(seg))
    || hasWriteRedirect(seg)
    || (!trusted && !isLookupOrEcho && (
      dangerousCommandPatterns.some(({ pattern }) => pattern.test(firstWord))
      || dangerousContextPatterns.some(({ pattern }) => pattern.test(seg))
    ));
}

// ── Path extraction (tree-sitter AST) ──
// Delegated to bash-parser.ts for accurate parsing of heredocs, quotes, subshells, redirects.

// ── Risk analysis ──

function hasFlag(args: string[], flag: string): boolean {
  return args.includes(flag) || args.some((a) => a === flag || a.startsWith(flag + "=") || a.startsWith(flag + "."));
}

function anyArgStartsWith(args: string[], prefix: string): boolean {
  return args.some((a) => a.startsWith(prefix));
}

interface Risk {
  severity: Severity;
  reasons: string[];
}

/**
 * Analyze risk for a single command segment (string text + operators).
 * Operates on the segment text directly, not on shell-quote tokens.
 */
function analyzeSegmentRisk(text: string, ops: string[]): Risk | null {
  const reasons: string[] = [];
  let severity: Severity = "medium";

  // Parse args from the segment text
  const args = text.trim().split(/\s+/);
  if (args.length === 0) return null;

  const cmd = args[0].toLowerCase();
  const rest = args.slice(1);

  // Pipe to shell: check pipe targets (commands after |), not all args
  if (ops.includes("|")) {
    const parts = text.split("|").map(p => p.trim());
    const pipeTargets = parts.slice(1);
    const shellNames = new Set(["sh", "bash", "zsh", "fish"]);
    if (pipeTargets.some(target => shellNames.has(getFirstWord(target)))) {
      reasons.push("pipe to a shell (possible remote code execution)");
      severity = "high";
    }
  }

  // sudo
  if (cmd === "sudo") {
    reasons.push("sudo (elevated privileges)");
    severity = "high";
  }

  // rm/rmdir/unlink
  if (cmd === "rm" || cmd === "rmdir" || cmd === "unlink") {
    severity = "high";
    if (rest.some((a) => a.includes("-r") || a.includes("-R"))) reasons.push("recursive delete (-r/-R)");
    if (rest.some((a) => a.includes("-f"))) reasons.push("forced delete (-f)");
  }

  // find -delete
  if (cmd === "find" && rest.includes("-delete")) {
    severity = "high";
    reasons.push("find -delete (bulk deletion)");
  }

  // git operations
  if (cmd === "git") {
    const sub = rest[0];
    const subArgs = rest.slice(1);

    reasons.push(sub ? `git ${sub} (git command)` : "git (git command)");

    if (sub === "rm") {
      severity = "high";
      reasons.push("git rm (deletes files from working tree and stages deletions)");
    }
    if (sub === "clean" && (subArgs.some((a) => a.includes("-f")) || subArgs.includes("-d") || subArgs.includes("-x"))) {
      severity = "high";
      reasons.push("git clean (can delete untracked files)");
    }
    if (sub === "reset" && subArgs.includes("--hard")) {
      severity = "high";
      reasons.push("git reset --hard (discard changes)");
    }
    if ((sub === "checkout" || sub === "restore") && (subArgs.includes(".") || subArgs.includes("--") || subArgs.includes("--source"))) {
      reasons.push("git checkout/restore (can overwrite working tree)");
    }
    if (sub === "push" && (subArgs.includes("--force") || subArgs.includes("--force-with-lease") || subArgs.includes("-f"))) {
      severity = "high";
      reasons.push("git push --force (rewrite remote history)");
    }
    if (sub === "reflog" && subArgs.includes("expire")) {
      severity = "high";
      reasons.push("git reflog expire (can remove recovery history)");
    }
    if (sub === "gc" && subArgs.some((a) => a.startsWith("--prune"))) {
      severity = "high";
      reasons.push("git gc --prune (can permanently delete objects)");
    }
  }

  // truncate
  if (cmd === "truncate") {
    reasons.push("truncate (in-place size change, can erase contents)");
  }

  // dd of=
  if (cmd === "dd" && anyArgStartsWith(rest, "of=")) {
    severity = "high";
    reasons.push("dd with output file/device (can overwrite data)");
  }

  // Disk / volume management
  if (cmd.startsWith("mkfs")) {
    severity = "high";
    reasons.push("mkfs (filesystem formatting)");
  }
  if (cmd.startsWith("newfs_")) {
    severity = "high";
    reasons.push("newfs_* (filesystem formatting)");
  }
  if (cmd === "wipefs") {
    severity = "high";
    reasons.push("wipefs (disk signature wipe)");
  }
  if (cmd === "diskutil") {
    severity = "high";
    reasons.push("diskutil (disk management command)");
    if (rest.includes("eraseDisk") || rest.includes("eraseVolume")) {
      reasons.push("diskutil erase (destructive disk operation)");
    }
  }
  if (cmd === "hdiutil") {
    severity = "high";
    reasons.push("hdiutil (disk image management command)");
  }
  if (cmd === "gpt") {
    severity = "high";
    reasons.push("gpt (partition table manipulation)");
  }
  if (cmd === "asr") {
    severity = "high";
    reasons.push("asr (Apple Software Restore; can overwrite volumes)");
  }
  if (cmd === "parted" || cmd === "fdisk" || cmd === "gdisk" || cmd === "sgdisk") {
    severity = "high";
    reasons.push(`${cmd} (disk/partition management)`);
  }
  if (cmd === "lsblk") {
    reasons.push("lsblk (disk listing)");
  }
  if (cmd === "cryptsetup") {
    severity = "high";
    reasons.push("cryptsetup (disk encryption management)");
  }
  if (cmd === "pvcreate" || cmd === "vgcreate" || cmd === "lvcreate") {
    severity = "high";
    reasons.push(`${cmd} (LVM volume management)`);
  }
  if (cmd === "zpool") {
    severity = "high";
    reasons.push("zpool (ZFS pool management)");
  }

  // chmod/chown recursive
  if (cmd === "chmod" && (rest.includes("-R") || rest.includes("--recursive"))) {
    reasons.push("chmod -R (recursive permission changes)");
  }
  if (cmd === "chown" && (rest.includes("-R") || rest.includes("--recursive"))) {
    reasons.push("chown -R (recursive ownership changes)");
  }

  // mv/cp overwriting
  if (cmd === "mv" && (rest.includes("-f") || rest.includes("--force"))) {
    reasons.push("mv --force/-f (can overwrite files)");
  }
  if (cmd === "cp" && (rest.includes("-f") || rest.includes("--force"))) {
    reasons.push("cp --force/-f (can overwrite files)");
  }

  // sed/perl in-place
  if (cmd === "sed" && (hasFlag(rest, "-i") || rest.includes("--in-place"))) {
    reasons.push("sed -i (in-place file modification)");
  }
  if (cmd === "perl" && (rest.includes("-pi") || (rest.includes("-p") && rest.includes("-i")))) {
    reasons.push("perl -pi/-i (in-place file modification)");
  }

  // kill/shutdown/systemctl
  if (cmd === "kill" || cmd === "pkill" || cmd === "killall") {
    reasons.push(`${cmd} (process termination)`);
    if (rest.includes("-9")) {
      severity = "high";
      reasons.push("SIGKILL (-9)");
    }
  }
  if (cmd === "shutdown" || cmd === "reboot") {
    severity = "high";
    reasons.push(`${cmd} (system power operation)`);
  }
  if (cmd === "systemctl" && (rest.includes("stop") || rest.includes("disable"))) {
    reasons.push("systemctl stop/disable (service disruption)");
  }

  // Remote execution via pipe
  if ((cmd === "curl" || cmd === "wget") && ops.includes("|")) {
    severity = "high";
    reasons.push("curl/wget piped (possible remote code execution)");
  }

  // Infra deletes
  if (cmd === "kubectl" && rest[0] === "delete") {
    severity = "high";
    reasons.push("kubectl delete (resource deletion)");
  }
  if (cmd === "terraform" && rest[0] === "destroy") {
    severity = "high";
    reasons.push("terraform destroy (infrastructure teardown)");
  }
  if (cmd === "aws" && rest[0] === "s3" && rest[1] === "rm" && rest.includes("--recursive")) {
    severity = "high";
    reasons.push("aws s3 rm --recursive (bulk deletion)");
  }
  if (cmd === "gcloud" && rest.includes("delete")) {
    severity = "high";
    reasons.push("gcloud delete (resource deletion)");
  }

  if (reasons.length === 0) return null;
  return { severity, reasons };
}

// ── Unified risk analysis ──

async function analyzeRisk(cmd: string, segments: { text: string; ops: string[] }[]): Promise<CommandRisk> {
  const reasons: string[] = [];
  let severity: Severity | null = null;

  // Collect all operators from all segments
  const allOps = new Set<string>();
  for (const seg of segments) {
    for (const op of seg.ops) {
      allOps.add(op);
    }
  }

  // Whole-command operator checks
  // Strip redirects to /dev/null or /dev/stderr — they're safe discards, not file writes
  let cmdNoNullRedirect = cmd
    .replace(/[0-9]*&?>+\s*\/dev\/(?:null|stderr)\b/g, "");
  cmdNoNullRedirect = cmdNoNullRedirect.replace(/[0-9]*>&[0-9]+/g, ""); // fd duplication (2>&1, >&1) is safe
  const hasRealWriteRedirect = /[0-9]*&?>+\s*\S/.test(cmdNoNullRedirect);
  if (hasRealWriteRedirect) {
    reasons.push("shell output redirection (can overwrite files)");
  }
  if (allOps.has("<")) {
    reasons.push("shell input redirection");
  }
  if (allOps.has("|") || allOps.has("|&")) {
    reasons.push("pipe operator (chained commands)");
  }

  // Per-segment risk
  for (const seg of segments) {
    const segRisk = analyzeSegmentRisk(seg.text, seg.ops);
    if (!segRisk) continue;
    if (segRisk.severity === "high") severity = "high";
    else if (!severity) severity = "medium";
    for (const r of segRisk.reasons) {
      if (!reasons.includes(r)) reasons.push(r);
    }
  }

  // Regex-based checks (safety net for patterns not caught by AST analysis)
  // Command patterns: test against each segment's first word to avoid false positives in args
  const cmdFirstWord = getFirstWord(cmd);
  for (const { pattern, label } of dangerousCommandPatterns) {
    if (pattern.test(cmdFirstWord) && !reasons.includes(label)) {
      reasons.push(label);
      if (!severity) severity = "medium";
    }
  }
  // Context patterns: test against full command (need flags/args context)
  for (const { pattern, label } of dangerousContextPatterns) {
    if (pattern.test(cmd) && !reasons.includes(label)) {
      reasons.push(label);
      if (!severity) severity = "medium";
    }
  }

  return { dangerous: reasons.length > 0, reasons, severity };
}

// ── Public interface ──

/**
 * Analyze a shell command. Single source of truth for parsing, path extraction,
 * safety evaluation, and risk assessment.
 *
 * Uses tree-sitter-bash AST for accurate segmentation, path extraction,
 * and operator detection (handles heredocs, comments, quotes, subshells,
 * and redirects correctly).
 */
export async function analyzeCommand(cmd: string, cwd: string): Promise<CommandAnalysis> {
  // Extract segments from AST (splits on &&, ||, ;, |, |&, &)
  const astSegments = await extractSegmentsAST(cmd);
  const segmentTexts = astSegments.map(s => s.text);
  const signatures = segmentTexts.map(getCommandSignature);
  const paths = await extractPathsFromBash(cmd, cwd);
  const allSimple = (await Promise.all(segmentTexts.map(seg => isSimpleAllowedCommand(seg, cwd)))).every(Boolean);
  const hasUnsafe = (await Promise.all(segmentTexts.map(seg => isSegmentUnsafe(seg, cwd)))).some(Boolean);
  const risk = await analyzeRisk(cmd, astSegments);
  const obfuscation = detectObfuscation(cmd);

  return { segments: segmentTexts, signatures, paths, allSimple, hasUnsafePattern: hasUnsafe, risk, obfuscation };
}
