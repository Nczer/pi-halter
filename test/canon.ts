/**
 * Canonical (real-path) form of a fixture path on THIS platform.
 *
 * The gate resolves every path with a realpath walk-up (existence-, symlink-
 * and firmlink-aware); tests that assert on paths must name the same form.
 * Linux is mostly identity, macOS is not:
 *   /tmp → /private/tmp · /etc → /private/etc · /var/tmp → /private/var/tmp
 *   os.tmpdir() → /private/var/folders/…
 *   /home/… → /System/Volumes/Data/home/…   (firmlink)
 * The anonymized fixtures use /Users/u/…, which is identity on BOTH
 * platforms (/Users exists on macOS but realpath keeps it; it does not
 * exist on Linux, so the walk-up stops at /).
 *
 * Independent of resolvePathReal on purpose: expectations must be OS truth,
 * not a copy of the code under test (path resolution itself is covered by
 * its own tests).
 */
import fs from "node:fs";
import path from "node:path";

export function canon(p: string): string {
  let probe = path.resolve(p);
  let suffix = "";
  for (;;) {
    try {
      const real = fs.realpathSync(probe);
      return suffix ? path.join(real, suffix) : real;
    } catch {
      const parent = path.dirname(probe);
      if (parent === probe) return p; // nothing exists — as-is
      suffix = suffix ? path.join(path.basename(probe), suffix) : path.basename(probe);
      probe = parent;
    }
  }
}
