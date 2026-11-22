// The vendored settings copy is pinned to its source. halter imports
// ./ext-settings for everything that touches settings-ext.json, so a copy that
// stops matching ui-kit/ext-settings.ts means two extensions behaving
// differently for no reason. `npm run sync:kit` (from extensions/) rewrites it;
// this test is what makes a forgotten sync a failing test. ui-kit/README.md.
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const here = dirname(fileURLToPath(import.meta.url));
const vendored = join(here, "..", "ext-settings.ts");
const source = join(here, "..", "..", "ui-kit", "ext-settings.ts");

const sha = (p: string) => createHash("sha256").update(readFileSync(p)).digest("hex");

describe("vendored ext-settings copy", () => {
  it("matches the source byte for byte", () => {
    if (!existsSync(source)) return; // a published clone of this extension: the copy is the source
    expect(existsSync(vendored), "ext-settings.ts is missing — run npm run sync:kit").toBe(true);
    expect(sha(vendored), "ext-settings.ts is stale — run npm run sync:kit").toBe(sha(source));
  });
});
