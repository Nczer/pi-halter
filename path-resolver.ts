/**
 * Path resolver — one-shot LLM fallback for statically unresolved tokens.
 *
 * When bash analysis cannot statically prove where an opaque reference
 * resolves at runtime (unbound variable, `$(…)` expansion, glob over an
 * unknown base), the prompt lists it as unresolved. When the judge is
 * enabled, this module asks the judge model (the same model settings as
 * the judge — this is a second use of it, not a new setting) to report the
 * concrete runtime directories for each unresolved token, grounded ONLY in
 * what the command text proves (assignments, loop in-lists, tool
 * semantics).
 *
 * The result is advisory display: a `→ LLM: dir1, dir2` line under each
 * token in the prompt. It becomes BINDING only when the user takes an
 * option that grants the LLM-suggested dirs (Always/Always (paths)) — the
 * prompt flow then persists them via store.confirmResolution, after which
 * the dspa gate resolves the same token DETERMINISTICALLY (no LLM call).
 * The gate never auto-allows on this module's output (Q1 — scope grants
 * are the user's call). Any failure (judge off, model unresolvable, auth,
 * timeout, bad reply, nothing known) resolves to null and the prompt looks
 * exactly as it did before.
 */
import { createHash } from "node:crypto";
import os from "node:os";
import type {
  AssistantMessage,
  Model,
  Tool,
  ToolCall,
} from "@earendil-works/pi-ai";
import { complete } from "@earendil-works/pi-ai/compat";
import { truncateToWidth } from "@earendil-works/pi-tui";
import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import type { BashPromptData } from "./decision-engine";
import {
  readJudgeSettings,
  resolveJudgeModel,
  resolveJudgeAuth,
  type CompleteFn,
  type JudgeSettings,
} from "./judge";
import { expandTilde } from "./analysis/path-util";

// ── Model call ──

const RESOLVE_SYSTEM_PROMPT = `You resolve unresolved path references in a shell command. The user message shows the command, its working directory, the shell home directory, and a numbered list of references that static analysis could not bind.

For EACH reference, report the absolute directories it points to at runtime, derived ONLY from what the command text proves: variable assignments made in the command, loop in-lists (for x in a b c), quoted literals, and the semantics of the invoked tool.

Rules:
- Report directories (where the reference lands), not files. For a glob, report the directory containing the matches.
- A reference is KNOWN only if every component of its location is proven by the command text. If it depends on data the command does not show (file contents, network, earlier shell state), report it as unknown.
- Never guess a path not grounded in the command text. An empty dirs list with known: false is the honest answer.
- Absolute paths only; expand ~ using the home directory given.
- At most 5 dirs per reference.`;

const RESOLVE_TOOL = {
  name: "report_paths",
  description: "Report the runtime directories for each numbered unresolved reference.",
  parameters: {
    type: "object",
    properties: {
      results: {
        type: "array",
        items: {
          type: "object",
          properties: {
            index: { type: "number" },
            known: { type: "boolean" },
            dirs: { type: "array", items: { type: "string" } },
          },
          required: ["index", "known", "dirs"],
        },
      },
    },
    required: ["results"],
  },
} as unknown as Tool;

// ── LRU cache (same pattern as judge.ts) ──

const CACHE_MAX = 64;
const cache = new Map<string, ResolutionMap>();

function cacheGet(key: string): ResolutionMap | undefined {
  const hit = cache.get(key);
  if (!hit) return undefined;
  cache.delete(key);
  cache.set(key, hit);
  return new Map(hit);
}

function cacheSet(key: string, map: ResolutionMap): void {
  if (cache.size >= CACHE_MAX) {
    const oldest = cache.keys().next().value;
    if (oldest !== undefined) cache.delete(oldest);
  }
  cache.set(key, map);
}

/** Drop all cached resolutions (tests). */
export function resetPathResolverCache(): void {
  cache.clear();
}

/** sha256 of model + command + token list — same operation bytes → same
 * resolutions; a changed command never reuses a stale map. */
function cacheKey(modelId: string, pd: BashPromptData, tokens: string[]): string {
  return createHash("sha256")
    .update(`${modelId}\u0000${pd.command}\u0000${tokens.join("\u0000")}`, "utf-8")
    .digest("hex");
}

// ── Entry point ──

/** Test seam: `complete` (the model call) and settings are injectable —
 * production uses the real `complete` from @earendil-works/pi-ai and
 * ~/.pi/agent/halter.json. */
export interface PathResolverDeps {
  complete?: CompleteFn;
  settings?: JudgeSettings;
}

/** token → absolute dirs the token points to at runtime (empty dirs means
 * the token is unresolved by the model too). */
export type ResolutionMap = Map<string, string[]>;

/**
 * Resolve a bash prompt's unresolved tokens via one judge-model call.
 * Returns null when there is nothing to resolve, the judge is off or
 * unresolvable, or the call produced no known dirs — the caller renders
 * the prompt without LLM lines. Never throws.
 */
export async function resolveUnresolvedPaths(
  pd: BashPromptData,
  ctx: ExtensionContext,
  deps: PathResolverDeps = {},
): Promise<ResolutionMap | null> {
  const unresolved = pd.unresolved;
  if (!unresolved || unresolved.length === 0) return null;

  let widgetShown = false;
  try {
    const settings = deps.settings ?? readJudgeSettings();
    if (!settings.enabled) return null;
    const model = resolveJudgeModel(settings, ctx.modelRegistry, ctx.model);
    if (!model) return null;
    const auth = await resolveJudgeAuth(model, ctx.modelRegistry);
    if (!auth) return null;

    const modelId = `${model.provider}/${model.id}`;
    const tokens = unresolved.map((u) => u.token);
    const key = cacheKey(modelId, pd, tokens);
    const hit = cacheGet(key);
    if (hit) return hit.size > 0 ? hit : null;

    try {
      ctx.ui.setWidget("resolver", (_tui, theme) => ({
        render: (width: number) => [
          truncateToWidth(theme.fg("muted", "⏳ Resolving paths…"), width),
        ],
        invalidate: () => {},
      }), { placement: "belowEditor" });
      widgetShown = true;
    } catch {
      /* the resolution still works without a widget */
    }

    const controller = new AbortController();
    const timeoutMs = settings.timeoutMs ?? 15000;
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    const streamOptions: Record<string, unknown> = {
      signal: controller.signal,
      apiKey: auth.apiKey,
      headers: auth.headers,
      // "auto" (judge.ts pattern): "required" is not portable across
      // providers; a reply without a tool call simply yields no
      // resolutions (handled below).
      toolChoice: "auto",
    };
    try {
      const reply: AssistantMessage = await (deps.complete ?? complete)(
        model,
        {
          systemPrompt: RESOLVE_SYSTEM_PROMPT,
          tools: [RESOLVE_TOOL],
          messages: [
            {
              role: "user",
              content: buildResolverPacket(pd, unresolved),
              timestamp: Date.now(),
            },
          ],
        },
        streamOptions,
      );
      if (reply.stopReason === "aborted" || reply.stopReason === "error") return null;

      // Read the tool call by position (the first one), not by name — under
      // OAuth the provider rewrites the registered name (judge.ts pattern).
      const call = reply.content.find(
        (part): part is ToolCall => part.type === "toolCall",
      );
      if (!call) return null;
      const results = (call.arguments ?? {}).results;
      if (!Array.isArray(results)) return null;

      const map: ResolutionMap = new Map();
      for (const r of results) {
        if (!r || typeof r.index !== "number" || !Number.isInteger(r.index)) continue;
        const token = tokens[r.index];
        if (token === undefined) continue;
        const dirs = sanitizeDirs(Array.isArray(r.dirs) ? r.dirs : []);
        if (dirs.length > 0) map.set(token, dirs);
        // known:false or empty dirs → the token stays unresolved (no entry).
      }
      if (map.size === 0) return null;
      cacheSet(key, new Map(map));
      return map;
    } catch {
      return null;
    } finally {
      clearTimeout(timer);
    }
  } catch {
    return null;
  } finally {
    if (widgetShown) {
      try {
        ctx.ui.setWidget("resolver", undefined);
      } catch {
        /* widget cleanup must never mask the result */
      }
    }
  }
}

const MAX_DIRS_PER_TOKEN = 5;

/**
 * Validate model-reported dirs: absolute paths only (a ~ is expanded with
 * the packet's home — the model was told to, but a lazy reply isn't a
 * grant; a RELATIVE path is dropped, never resolved — its base is not
 * provable), no sentinels ("<…>"), no empties, deduped, capped. Anything
 * else is dropped — an unverifiable dir must never end up in a grant.
 */
function sanitizeDirs(dirs: unknown[]): string[] {
  const out: string[] = [];
  for (const d of dirs) {
    if (typeof d !== "string") continue;
    let p = d.trim();
    if (p === "" || p.startsWith("<")) continue;
    if (p === "~" || p.startsWith("~/")) p = expandTilde(p);
    if (!p.startsWith("/")) continue;
    if (!out.includes(p)) out.push(p);
    if (out.length >= MAX_DIRS_PER_TOKEN) break;
  }
  return out;
}

/**
 * The numbered token list + command + cwd + home the model reasons over.
 * Tokens are numbered (the reply references indices, not token text —
 * long glob expansions would be mangled by a model echoing them).
 */
function buildResolverPacket(
  pd: BashPromptData,
  unresolved: Array<{ token: string; reason: "var" | "base" }>,
): string {
  const home = os.homedir();
  const lines = unresolved.map(
    (u, i) => `${i + 1}. ${u.token}${u.reason === "base" ? "  (unresolvable working directory)" : ""}`,
  );
  return [
    `Working directory: ${pd.cwd}`,
    `Home directory: ${home}`,
    ``,
    `Command:`,
    pd.command,
    ``,
    `Unresolved references (static analysis could not bind their runtime location):`,
    ...lines,
    ``,
    `Report the absolute directory each reference points to at runtime.`,
  ].join("\n");
}
