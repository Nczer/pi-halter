import {
  dangerousCommandPatterns,
  dangerousContextPatterns,
} from "./config";
import type { BashSegment } from "./bash-parser";
import { getFirstWord } from "./segment-helpers";

// ── Types ──

type Severity = "high" | "medium";

interface Risk {
  severity: Severity;
  reasons: string[];
}

export interface CommandRisk {
  dangerous: boolean;
  reasons: string[];
  severity: Severity | null;
}

// ── Helpers ──

function hasFlag(args: string[], flag: string): boolean {
  return args.includes(flag) || args.some((a) => a === flag || a.startsWith(flag + "=") || a.startsWith(flag + "."));
}

function anyArgStartsWith(args: string[], prefix: string): boolean {
  return args.some((a) => a.startsWith(prefix));
}

// ── Per-segment risk analysis ──

function analyzeSegmentRisk(text: string, ops: string[]): Risk | null {
  const reasons: string[] = [];
  let severity: Severity = "medium";

  const args = text.trim().split(/\s+/);
  if (args.length === 0) return null;

  const cmd = args[0].toLowerCase();
  const rest = args.slice(1);

  // Pipe to shell
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
    severity = "medium";
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

/**
 * Analyze risk for a command and its segments.
 * Combines per-segment token analysis with whole-command regex safety net.
 */
export async function analyzeRisk(cmd: string, segments: BashSegment[]): Promise<CommandRisk> {
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
  let cmdNoNullRedirect = cmd
    .replace(/[0-9]*&?>+\s*\/dev\/(?:null|stderr)\b/g, "");
  cmdNoNullRedirect = cmdNoNullRedirect.replace(/[0-9]*>&[0-9]+/g, "");
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

  // Regex-based checks (safety net)
  const cmdFirstWord = getFirstWord(cmd);
  for (const { pattern, label } of dangerousCommandPatterns) {
    if (pattern.test(cmdFirstWord) && !reasons.includes(label)) {
      reasons.push(label);
      if (!severity) severity = "medium";
    }
  }
  for (const { pattern, label } of dangerousContextPatterns) {
    if (pattern.test(cmd) && !reasons.includes(label)) {
      reasons.push(label);
      if (!severity) severity = "medium";
    }
  }

  return { dangerous: reasons.length > 0, reasons, severity };
}
