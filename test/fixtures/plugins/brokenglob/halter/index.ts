// Loader fixture: a GLOB plugin that FAILS AT IMPORT. The loader must still
// key the slot by the sniffed `match:` literal, so every concrete tool in the
// namespace is blocked (fail closed) — not just the ext directory name.
const plugin = {
  name: "brokenglobhost",
  match: "fakebroken__*",
  buildRequest: (_event: unknown) => null,
};
throw new Error("boom-glob-import");
export default plugin;
