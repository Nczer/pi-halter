// Loader fixture: a GLOB plugin — one plugin gating a whole namespace.
// Classifies exec so dispatch is observable (the gate blocks it with no UI).
const plugin = {
  name: "globhost",
  match: "fakeglob__*",
  buildRequest: (_event: unknown) => ({ kind: "exec", label: "glob exec", script: "print(1)" }),
};
export default plugin;
