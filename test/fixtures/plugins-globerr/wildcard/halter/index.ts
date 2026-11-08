// Loader fixture, OWN root (plugins-globerr): a wildcard-only `match` would gate
// EVERY tool, so validate() rejects it and the slot comes up broken — keyed "*",
// which blocks every call until the plugin is fixed (fail closed).
// This file is deliberately NOT under fixtures/plugins/: a slot keyed "*" there
// would swallow the tool names every other dispatch test uses.
const plugin = {
  name: "wildcardhost",
  match: "*",
  buildRequest: (_event: unknown) => null,
};
export default plugin;
