import type { ExtensionContext, ToolCallEvent } from "@earendil-works/pi-coding-agent";

/**
 * What a tool plugin classifies a call as. The core routes each kind into
 * an EXISTING pipeline:
 *  - exec:    the call carries a script payload — runs through the bash
 *             script path (judge, D11 content review, dspa auto-allow).
 *             The plugin must pass the FINAL payload, byte-identical to
 *             what the tool will execute (payload identity: the judge
 *             reviews exactly what runs).
 *  - file:    the call writes a filesystem path — prompted with the target
 *             (outside-cwd warning included), granted per tool.
 *  - consent: low-risk action — per-kind session consent (the JoplinGate
 *             pattern, rendered through the standard prompt).
 *
 * null = the call passes ungated (discovery actions, status checks).
 */
export type ToolGateRequest =
  | { kind: "exec"; label: string; script: string; argsPreview?: string; note?: string }
  | { kind: "file"; label: string; path: string; note?: string }
  | { kind: "consent"; label: string; consentKind: string; argsPreview?: string; note?: string };

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
