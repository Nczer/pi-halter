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
  /** The tool name this plugin gates (the dispatch key; loader-enforced non-empty).
   *  With `match` set, this is the plugin's IDENTITY (messages, fail-closed sniffing);
   *  `match` is what dispatches. */
  name: string;
  /**
   * Optional glob over tool NAMES — one plugin for a whole namespace, e.g. the
   * tools of an MCP server (`match: "mcp__blender__*"`). `*` matches any
   * characters, the same rule pi uses for `toolExposure`, and the value must be
   * DATA (a string, never a predicate) so the loader can still scope a
   * fail-closed block for a plugin that fails to import (plugins/loader.ts).
   * Dispatch: an exact `name` slot always wins over a pattern; among patterns
   * the first in sorted-key order matches. Grants are unaffected: they key on
   * the CONCRETE tool name (decide/rule-generator.ts), so gating a namespace
   * per-server still grants per-verb.
   */
  match?: string;
  /**
   * @param event the tool call (name + args).
   * @param ctx the session context the classifier may READ (e.g. `ctx.model`
   *            for a local-reader exemption). Read-only input — no decisions
   *            or prompts here (the core owns those).
   * @returns the classification, or a Promise of it. Since 3.55.0 the gate
   *            `await`s the result, so a classifier may ASK ITS OWN TOOL a
   *            question instead of answering from a cache: the joplin plugin
   *            resolves a note's notebook on a cache miss, because a write
   *            that cannot name its destination costs a consent prompt even
   *            when it lands in the exempt tree (a restarted pi loses both the
   *            map and the session grant). Rules for an async classifier:
   *            1. ASK ONLY WHEN THE ANSWER CHANGES THE CLASSIFICATION — one
   *               bounded call, on this call, never a poll or a warm at startup
   *               (idle calls are the ext's own ban, not the gate's);
   *            2. NEVER DECIDE IN THE ASK — the lookup returns FACTS; the
   *               kind/label/note are computed after it, as before;
   *            3. A FAILED LOOKUP IS AN ABSENCE, NOT AN ALLOW — resolve to
   *               `null`/unknown and let the existing fail-closed branch speak
   *               (an unreachable server must never buy an exemption). A
   *               REJECT here still fails closed (the call is blocked), so
   *               swallow transport errors and return the unknown.
   *            Sync classifiers keep working unchanged.
   */
  buildRequest(
    event: ToolCallEvent,
    ctx: ExtensionContext,
  ): ToolGateRequest | null | Promise<ToolGateRequest | null>;
}

/** Load state for one <ext>/halter plugin. */
export type PluginSlot =
  | { state: "ok"; plugin: HalterPlugin }
  | { state: "broken"; error: string };
