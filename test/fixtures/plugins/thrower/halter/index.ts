// Loader fixture: valid contract, but buildRequest throws → fail-closed block.
const plugin = {
  name: "thrower",
  buildRequest: (_event: unknown) => {
    throw new Error("classification exploded");
  },
};
export default plugin;
