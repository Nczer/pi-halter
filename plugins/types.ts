import type { ExtensionContext, ToolCallEvent } from "@earendil-works/pi-coding-agent";

/**
 * What a tool plugin classifies a call as. The kind selects the call's
 * PATH — what its safety reduces to decides the pipeline (docs/
 * dspa-content-classes.md). Two families:
 *
 *  CONTENT-JUDGE (judgeable — the /dspa two-stage cascade can auto-allow):
 *  - exec:    the call carries a script payload — runs through the bash
 *             script path (judge, D11 content review, dspa auto-allow).
 *             The plugin must pass the FINAL payload, byte-identical to
 *             what the tool will execute (payload identity: the judge
 *             reviews exactly what runs).
 *  - egress:  the call carries an outgoing payload (data leaving the
 *             machine — a web query, a url list). The full args must ride
 *             in `argsPreview` (the judge sees exactly what goes out);
 *             the `<tool>:kind:<k>` session grant is the override (no
 *             prompts, no judge).
 *
 *  HUMAN-GATED (never auto-allowed — the prompt is the gate):
 *  - file:    the call writes a filesystem path — prompted with the target
 *             (outside-cwd warning included), granted per tool.
 *  - consent: the action's meaning comes from the session (opaque args —
 *             a note id, external state) that the judge cannot vouch. The
 *             session-scoped trust prompt decides (T4): first prompt per
 *             kind per session, yes IS the session grant, single tier,
 *             names the model; the grant resets on model switch (T5).
 *
 *  MIXED: buildRequest classifies PER CALL — one tool's actions map to
 *  whichever path their payload demands (joplin: reads and writes are
 *  consent; exa: search and contents are egress; a tool may combine, e.g.
 *  consent reads + exec actions + egress fetches). Grant scopes stay
 *  separate per kind — a read consent can never cover the tool's exec
 *  actions.
 *
 * null = the call passes ungated (discovery actions, status checks).
 */
export type ToolGateRequest =
  | { kind: "exec"; label: string; script: string; argsPreview?: string; note?: string }
  | { kind: "file"; label: string; path: string; note?: string }
  | { kind: "consent"; label: string; consentKind: string; argsPreview?: string; note?: string }
  | { kind: "egress"; label: string; consentKind: string; argsPreview?: string; note?: string };

/**
 * A gate plugin for one tool ext. Lives at <ext>/halter/index.ts and
 * default-exports an object with this shape; the loader (loader.ts) scans
 * the extensions root, validates the contract, and hands the slots to
 * handleTool (handlers/tool.ts), keyed by the GATED TOOL's name — a
 * multi-tool ext can gate any of its tools (tool name ≠ ext dir is fine).
 * Plugins only CLASSIFY — all decisions, prompts, grants, judging, and
 * logging happen in the halter core.
 *
 * The plugin may import the tool ext's own modules (same directory) — the
 * classification and the tool's payload building share one source of truth.
 */
export interface HalterPlugin {
  /** The tool name this plugin gates (the dispatch key; loader-enforced non-empty). */
  name: string;
  /**
   * @param event the tool call (name + args).
   * @param ctx the session context the classifier may READ (e.g. `ctx.model`
   *            for a local-reader exemption). Read-only input — no decisions
   *            or prompts here (the core owns those).
   */
  buildRequest(event: ToolCallEvent, ctx: ExtensionContext): ToolGateRequest | null;
}

/** Load state for one <ext>/halter plugin. */
export type PluginSlot =
  | { state: "ok"; plugin: HalterPlugin }
  | { state: "broken"; error: string };
