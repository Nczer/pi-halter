// Loader fixture: name does NOT equal the ext directory name → broken slot.
const plugin = {
  name: "other",
  buildRequest: (_event: unknown) => null,
};
export default plugin;
