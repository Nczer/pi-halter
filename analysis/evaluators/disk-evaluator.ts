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

/** Commands that traverse the filesystem. */
const ROOT_SCANNERS = new Set(["find", "grep", "egrep", "fgrep", "rg", "ag", "locate"]);

/**
 * A full-filesystem scan: a scanner whose path argument is exactly `/`
 * (`find / -name x`, `grep -rn pat /`). Conspicuous in plain sight — it gets
 * its own reason instead of the generic "outside base (/)" (2026-08-24 log:
 * a `find /` probe stopped with a reason that hid what the command does).
 * Returns the scanner name, or null.
 */
export function rootScanTarget(segment: string): string | null {
  const words = segment.trim().split(/\s+/);
  const cmd = words[0]?.split("/").pop()?.toLowerCase() ?? "";
  if (!ROOT_SCANNERS.has(cmd)) return null;
  for (const w of words.slice(1)) {
    if (w === "/") return cmd;
  }
  return null;
}

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
        b.markDanger();
        return b.build();
      }
    }

    const scan = rootScanTarget(segment);
    if (scan) {
      // Medium, not dangerous: read-only traversal, but heavy and
      // conspicuous — the dspa floor stops it with the same dedicated reason.
      b.addMedium(`full filesystem scan (${scan} /)`);
      return b.build();
    }

    return b.build();
  },
};
