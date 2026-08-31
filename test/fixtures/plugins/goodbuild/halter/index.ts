// Loader fixture: classifies `run` actions as exec (with a payload).
const plugin = {
  name: "goodbuild",
  buildRequest: (event: { toolName?: string; input?: { action?: string; code?: string } }) => {
    if (event.input?.action !== "run") return null;
    return {
      kind: "exec",
      label: "run",
      script: event.input.code ?? "",
      note: "fixture: executes code",
    };
  },
};
export default plugin;
