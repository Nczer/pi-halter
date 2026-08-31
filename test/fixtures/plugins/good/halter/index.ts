// Loader fixture: a valid plugin (classification null = pass-through).
const plugin = {
  name: "good",
  buildRequest: (_event: unknown) => null,
};
export default plugin;
