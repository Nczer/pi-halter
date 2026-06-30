import { EvaluationBuilder } from "./builder";
import { EvalCache, RiskEvaluator } from "./types";
import { getFirstWord } from "../segment-helpers";

// ── Disk command handlers ──

/** Disk command → handler (reason, severity, extra checks). */
const DISK_HANDLERS: Array<{ match: (cmd: string) => boolean; reason: (cmd: string) => string; severity: "high" | "medium"; extra?: (cmd: string, rest: string[]) => string[] }> = [
  { match: (c) => c.startsWith("mkfs"), reason: () => "mkfs (filesystem formatting)", severity: "high" },
  { match: (c) => c.startsWith("newfs_"), reason: () => "newfs_* (filesystem formatting)", severity: "high" },
  { match: (c) => c === "wipefs", reason: () => "wipefs (disk signature wipe)", severity: "high" },
  { match: (c) => c === "diskutil", reason: () => "diskutil (disk management command)", severity: "high",
    extra: (c, rest) => (rest.includes("eraseDisk") || rest.includes("eraseVolume")) ? ["diskutil erase (destructive disk operation)"] : [] },
  { match: (c) => c === "hdiutil", reason: () => "hdiutil (disk image management command)", severity: "high" },
  { match: (c) => c === "gpt", reason: () => "gpt (partition table manipulation)", severity: "high" },
  { match: (c) => c === "asr", reason: () => "asr (Apple Software Restore; can overwrite volumes)", severity: "high" },
  { match: (c) => ["parted", "fdisk", "gdisk", "sgdisk"].includes(c), reason: (c) => `${c} (disk/partition management)`, severity: "high" },
  { match: (c) => c === "lsblk", reason: () => "lsblk (disk listing)", severity: "medium" },
  { match: (c) => c === "cryptsetup", reason: () => "cryptsetup (disk encryption management)", severity: "high" },
  { match: (c) => ["pvcreate", "vgcreate", "lvcreate"].includes(c), reason: (c) => `${c} (LVM volume management)`, severity: "high" },
  { match: (c) => c === "zpool", reason: () => "zpool (ZFS pool management)", severity: "high" },
];

/**
 * Evaluates disk/volume management commands.
 */
export const DiskEvaluator: RiskEvaluator = {
  name: "disk",
  evaluate(seg, cwd, cache): ReturnType<EvaluationBuilder["build"]> {
    const segment = seg.text;
    const firstWord = cache?.firstWord ?? getFirstWord(segment);
    const rest = segment.trim().split(/\s+/).slice(1);
    const b = new EvaluationBuilder();

    for (const handler of DISK_HANDLERS) {
      if (handler.match(firstWord)) {
        b.addReason(handler.reason(firstWord));
        if (handler.extra) {
          for (const extra of handler.extra(firstWord, rest)) {
            b.addReason(extra);
          }
        }
        b.setSeverity(handler.severity);
        return b.build();
      }
    }

    return b.build();
  },
};
