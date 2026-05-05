import { parse as shellParse } from "shell-quote";
import path from "node:path";
import os from "node:os";
import fs from "node:fs";
import {
  allowedBashPatterns,
  dangerousFindFlags,
  dangerousPatterns,
  pathAwareCommands,
} from "./config";
import { expandTilde, resolvePathReal } from "./path-analysis";

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

// ── Internal types ──

type OpToken = { op: string; [k: string]: unknown };
type Token = string | OpToken;

function isOpToken(t: Token): t is OpToken {
  return typeof t === "object" && t !== null && "op" in t;
}

// ── Shell parsing (shell-quote based) ──

function parseCommand(command: string): Token[] | null {
  try {
    return shellParse(command) as Token[];
  } catch {
    return null;
  }
}

function tokensToStrings(tokens: Token[]): string[] {
  return tokens.filter((t) => typeof t === "string") as string[];
}

function splitTokensOnOps(tokens: Token[], splitOps: string[]): Token[][] {
  const out: Token[][] = [];
  let current: Token[] = [];
  for (const t of tokens) {
    if (isOpToken(t) && splitOps.includes(t.op)) {
      if (current.length) out.push(current);
      current = [];
      continue;
    }
    current.push(t);
  }
  if (current.length) out.push(current);
  return out;
}

function getSegmentOps(seg: Token[]): string[] {
  return seg.filter(isOpToken).map((o) => o.op);
}

function getAllOps(tokens: Token[]): string[] {
  return tokens.filter(isOpToken).map((t) => t.op);
}

// ── String-based segment splitting ──

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

function splitIntoSegments(cmd: string): string[] {
  return stripQuotedStrings(cmd)
    .split(/\s*(?:;\s*|&&\s*|\|\|\s*|\|&\s*|\|\s*|&\s*|\n\s*)/)
    .map(s => s.trim())
    .filter(s => s.length > 0 && s !== "__STR__");
}

// ── Segment helpers ──

function getFirstWord(segment: string): string {
  return segment.trim().split(/\s+/)[0].toLowerCase();
}

function getCommandSignature(segment: string): string {
  const tokens = stripQuotedStrings(segment.trim()).split(/\s+/);
  const cmd = tokens[0].toLowerCase();
  const flags = tokens.slice(1).filter(t => t.startsWith("-")).sort();
  return flags.length === 0 ? cmd : `${cmd} ${flags.join(" ")}`;
}

// ── Safety checks ──

function hasSubshell(cmd: string): boolean {
  return /\$\s*\(/.test(cmd)
    || /`/.test(cmd)
    || /<\s*\(/.test(cmd)
    || />\s*\(/.test(cmd)
    || /<<</.test(cmd);
}

function hasWriteRedirect(cmd: string): boolean {
  let stripped = cmd;
  stripped = stripped.replace(/[0-9]*&?>+\s*(?:\/dev\/(?:null|stderr))\b/g, "");
  stripped = stripped.replace(/2>&1\s*>+\s*(?:\/dev\/(?:null|stderr))\b/g, "");
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

function isSimpleAllowedCommand(segment: string): boolean {
  const firstWord = getFirstWord(segment);
  if (!allowedBashPatterns.some(p => p.test(firstWord))) return false;
  if (hasSubshell(segment)) return false;
  if (firstWord === "find" && dangerousFindFlags.test(segment)) return false;
  if (hasWriteRedirect(segment)) return false;
  return true;
}

function isSegmentUnsafe(seg: string): boolean {
  return hasSubshell(seg)
    || isSegmentObfuscated(seg)
    || (getFirstWord(seg) === "find" && dangerousFindFlags.test(seg))
    || hasWriteRedirect(seg)
    || dangerousPatterns.some(({ pattern }) => pattern.test(seg));
}

// ── Path extraction ──

function extractPathsFromSegment(segment: string, cwd: string): string[] {
  const firstWord = getFirstWord(segment);
  if (!pathAwareCommands.has(firstWord)) return [];

  const tokens = stripQuotedStrings(segment.trim()).split(/\s+/);
  const paths: string[] = [];

  if (firstWord === "find") {
    for (let i = 1; i < tokens.length; i++) {
      if (!tokens[i].startsWith("-") && tokens[i] !== "__STR__") {
        paths.push(resolvePathReal(expandTilde(tokens[i]), cwd));
      }
    }
  } else if (firstWord === "grep") {
    let foundPattern = false;
    for (let i = 1; i < tokens.length; i++) {
      if (tokens[i].startsWith("-") || tokens[i] === "__STR__") continue;
      if (!foundPattern) { foundPattern = true; continue; }
      paths.push(resolvePathReal(expandTilde(tokens[i]), cwd));
    }
  } else if (firstWord === "cd" || firstWord === "pushd" || firstWord === "popd") {
    for (let i = 1; i < tokens.length; i++) {
      if (!tokens[i].startsWith("-") && tokens[i] !== "__STR__") {
        paths.push(resolvePathReal(expandTilde(tokens[i]), cwd));
      }
    }
  } else if (firstWord === "sed" || firstWord === "awk") {
    for (let i = 1; i < tokens.length; i++) {
      const t = tokens[i];
      if (t.startsWith("-")) continue;
      if (t === "__STR__") continue;
      if (firstWord === "sed") {
        if (/^s[\/\\#%|]/.test(t) || /^[adiwct]=$/.test(t) || /^[adiwct]\\?\//.test(t)) continue;
      }
      if (t.includes("/") || t.includes(".") || t.startsWith("~") || t === "..") {
        paths.push(resolvePathReal(expandTilde(t), cwd));
      }
    }
  } else {
    for (let i = 1; i < tokens.length; i++) {
      const t = tokens[i];
      if (t.startsWith("-") || /^\d+$/.test(t) || t === "__STR__") continue;
      if ((t.includes("*") || t.includes("?")) && !t.includes("/")) continue;
      if (t.includes("/") || t.includes(".") || t.startsWith("~") || t === "..") {
        paths.push(resolvePathReal(expandTilde(t), cwd));
      }
    }
  }

  return paths;
}

function extractPathsFromSegments(segments: string[], cwd: string): string[] {
  const allPaths: string[] = [];
  for (const seg of segments) {
    allPaths.push(...extractPathsFromSegment(seg, cwd));
  }
  return [...new Set(allPaths)];
}

// ── Token-based risk analysis ──

function hasFlag(args: string[], flag: string): boolean {
  return args.includes(flag) || args.some((a) => a.startsWith(flag) && flag.length === 2 && a.startsWith("-"));
}

function anyArgStartsWith(args: string[], prefix: string): boolean {
  return args.some((a) => a.startsWith(prefix));
}

interface Risk {
  severity: Severity;
  reasons: string[];
}

function analyzeSegmentRisk(seg: Token[]): Risk | null {
  const reasons: string[] = [];
  let severity: Severity = "medium";

  const args = tokensToStrings(seg);
  if (args.length === 0) return null;

  const ops = getSegmentOps(seg);
  const cmd = args[0];
  const rest = args.slice(1);

  // Pipe to shell
  if (ops.includes("|") && (args.includes("sh") || args.includes("bash") || args.includes("zsh") || args.includes("fish"))) {
    reasons.push("pipe to a shell (possible remote code execution)");
    severity = "high";
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
  if (cmd === "dd" && (anyArgStartsWith(rest, "of=") || rest.includes("of"))) {
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

function analyzeRisk(cmd: string): CommandRisk {
  const reasons: string[] = [];
  let severity: Severity | null = null;

  // Token-based analysis (shell-quote)
  const tokens = parseCommand(cmd);
  if (tokens) {
    const allOps = getAllOps(tokens);

    // Whole-command operator checks
    if (allOps.some((op) => op === ">" || op === ">>" || op === "2>" || op === "2>>")) {
      reasons.push("shell output redirection (can overwrite files)");
    }
    if (allOps.includes("<")) {
      reasons.push("shell input redirection");
    }
    if (allOps.includes("|")) {
      reasons.push("pipe operator (chained commands)");
    }

    // Per-segment risk
    const segments = splitTokensOnOps(tokens, ["&&", "||", ";"]);
    for (const seg of segments) {
      const segRisk = analyzeSegmentRisk(seg);
      if (!segRisk) continue;
      if (segRisk.severity === "high") severity = "high";
      else if (!severity) severity = "medium";
      for (const r of segRisk.reasons) {
        if (!reasons.includes(r)) reasons.push(r);
      }
    }
  } else {
    reasons.push("unparsed shell command (unable to analyze safely)");
    severity = "medium";
  }

  // Regex-based checks (safety net for patterns not caught by token analysis)
  for (const { pattern, label } of dangerousPatterns) {
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
 * safety evaluation, and risk assessment. One tokenization pass, one result.
 */
export function analyzeCommand(cmd: string, cwd: string): CommandAnalysis {
  const segments = splitIntoSegments(cmd);
  const signatures = segments.map(getCommandSignature);
  const paths = extractPathsFromSegments(segments, cwd);
  const allSimple = segments.every(isSimpleAllowedCommand);
  const hasUnsafe = segments.some(isSegmentUnsafe);
  const risk = analyzeRisk(cmd);
  const obfuscation = detectObfuscation(cmd);

  return { segments, signatures, paths, allSimple, hasUnsafePattern: hasUnsafe, risk, obfuscation };
}
