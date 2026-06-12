import { EvaluatorResult, RiskEvaluator } from "./types";
import { getFirstWord } from "../segment-helpers";

/**
 * Evaluates disk/volume management commands.
 */
export const DiskEvaluator: RiskEvaluator = {
  name: "disk",
  evaluate(seg, cwd): EvaluatorResult {
    const segment = seg.text;
    const firstWord = getFirstWord(segment);
    const args = segment.trim().split(/\s+/);
    const rest = args.slice(1);
    const reasons: string[] = [];
    let severity: "high" | "medium" | null = null;
    let hasDanger = false;
    const setSeverity = (s: "high" | "medium") => {
      if (s === "high" || !severity) severity = s;
    };

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

    return { reasons, severity, hasDanger, isSimple: undefined };
  },
};
