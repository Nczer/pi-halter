// Loader fixture: an ASYNC classifier — the 3.55.0 contract lets a plugin ask
// its own tool for a fact it cannot cache, so the gate must `await` the result.
//  - a normal call classifies after a microtask (a handler that skipped the
//    await would classify `undefined` and pass the call ungated → undefined);
//  - `action: "boom"` REJECTS after a microtask: the contract's rule 3, proven
//    from the outside — only an awaited rejection lands in the try/catch and
//    produces the fail-closed block. An unawaited one would sail past it.
const plugin = {
  name: "asyncclass",
  async buildRequest(event: { input?: Record<string, unknown> }) {
    const action = event?.input?.action;
    const settled = await Promise.resolve(typeof action === "string" ? action : "");
    if (settled === "boom") throw new Error("lookup failed after awaiting");
    return { kind: "consent", consentKind: "read", label: "slow_read" };
  },
};
export default plugin;
