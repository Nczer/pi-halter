// Loader fixture: fails at IMPORT TIME (top-level throw — deterministic in
// vitest and node alike; a missing-module import is vitest-resolver
// dependent). The name literal is still present → the broken slot must key
// on "serrtool" (sniffed), so the real tool is blocked fail-closed, not
// just the ext dir.
const plugin = {
  name: "serrtool",
  buildRequest: (_event: unknown) => null,
};
throw new Error("boom: classifier init failed");
export default plugin;
