// Loader fixture: an UNSUPPORTED glob syntax (`?`) — validate() rejects it, so
// the slot is broken and keyed by the sniffed `match:` literal (fail closed on
// the tools the pattern can still name).
const plugin = {
  name: "badglobhost",
  match: "fake?bad__*",
  buildRequest: (_event: unknown) => null,
};
export default plugin;
