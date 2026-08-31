// Loader fixture: proves ctx is forwarded to buildRequest (throws if it
// isn't); classification null = pass-through.
const plugin = {
  name: "ctxfwd",
  buildRequest: (_event: unknown, ctx: { cwd?: string } | undefined) => {
    if (!ctx || typeof ctx.cwd !== "string") {
      throw new Error("ctx was not forwarded");
    }
    return null;
  },
};
export default plugin;
