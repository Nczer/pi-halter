// Loader fixture: an EXACT slot inside another plugin's glob namespace —
// exact keys must win over patterns (plugins/loader.ts).
const plugin = {
  name: "fakeglob__exact",
  buildRequest: (_event: unknown) => null,
};
export default plugin;
