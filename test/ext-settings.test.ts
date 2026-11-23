// The vendored kit copies are pinned to their sources. halter imports
// ./ext-settings for everything that touches settings-ext.json and ./ui-lock for
// every dialog it opens, so a copy that stops matching ui-kit means two
// extensions behaving differently for no reason. `npm run sync:kit` (from
// extensions/) rewrites them; this test is what makes a forgotten sync a failing
// test. ui-kit/README.md.
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const here = dirname(fileURLToPath(import.meta.url));
// [the copy in this extension, its authoring source in the workspace]
const COPIES: Array<[string, string]> = [
  ["ext-settings.ts", join(here, "..", "..", "ui-kit", "ext-settings.ts")],
  ["ui-lock.ts", join(here, "..", "..", "ui-kit", "ui-lock.ts")],
];

const sha = (p: string) => createHash("sha256").update(readFileSync(p)).digest("hex");

describe("vendored copies", () => {
  for (const [copy, source] of COPIES) {
    const path = join(here, "..", copy);
    it(`${copy} matches its source byte for byte`, () => {
      if (!existsSync(source)) return; // a published clone of this extension: the copy is the source
      expect(existsSync(path), `${copy} is missing — run npm run sync:kit`).toBe(true);
      expect(sha(path), `${copy} is stale — run npm run sync:kit`).toBe(sha(source));
    });
  }
});
