// Loader fixture: name does NOT equal the ext directory name — LEGAL (a
// multi-tool ext may gate a tool whose name differs from its dir).
const plugin = {
  name: "othertool",
  buildRequest: (_event: unknown) => null,
};
export default plugin;
