import type { ToolCallEvent } from "@earendil-works/pi-coding-agent";
import { findLoadedSlot } from "../plugins/loader";

/**
 * The per-script budget: how many gated calls ONE codemode script may attempt.
 *
 * A script's calls reach halter through the same `tool_call` hook as the
 * model's own — pi runs nested calls through the agent tool pipeline and marks
 * them with `parentToolCallId` — so every call is gated on its own merits. What
 * gating does NOT bound is VOLUME: a script's loop is unbounded, so
 * `while(true) await tools.bash(...)` is an unbounded number of prompts, judge
 * calls (seconds each), and side effects, none of which the model can see until
 * the script returns. The budget stops that at a ceiling: the call past it is
 * blocked fail-fast, BEFORE the gate, so both the cost and the blast radius
 * stop there. The script keeps running (each later gated call blocks cheaply)
 * and its result tells the model what happened.
 *
 * Counted: nested calls of the surface halter evaluates for permission —
 * `bash`, `write`, `edit`, `read`, and anything a plugin gates. Nested calls
 * outside that surface (a discovery call, an ungated ext tool) are not counted,
 * and neither is any call the model makes directly: the model's own turn is
 * bounded by the calls it declares, a script's is not.
 *
 * This is a RATE LIMITER, not a safety boundary — it bounds how much one script
 * can attempt, never what a single call may do. `/dsp` bypasses it along with
 * every other check (index.ts returns before the handlers).
 */

/** Gated calls one script may attempt. Generous on purpose: a corpus walk in
 *  one script is normal; a runaway loop is the thing being stopped. */
export const MAX_GATED_CALLS_PER_SCRIPT = 64;

/** Script keys remembered (one per running script); oldest evicted past this.
 *  Keys are freed by `resetScriptBudget()` at session boundaries; the cap just
 *  keeps a long-lived process from accumulating them. */
const MAX_TRACKED_SCRIPTS = 256;

/** Calls-per-script, keyed by the issuing call's id (parentToolCallId). */
const usedByScript = new Map<string, number>();

/** Forget every script's usage (session_start / session_shutdown). */
export function resetScriptBudget(): void {
  usedByScript.clear();
}

/** Tools halter evaluates for permission, i.e. whose calls can cost a prompt or
 *  a judge call. `read` counts because an outside-cwd read prompts per call. */
function isEvaluatedSurface(toolName: string): boolean {
  return (
    toolName === "bash" ||
    toolName === "write" ||
    toolName === "edit" ||
    toolName === "read" ||
    findLoadedSlot(toolName) !== undefined
  );
}

/**
 * pi sets `parentToolCallId` when another tool issued the call (a codemode
 * script today). Read defensively: harness builds that do not set it simply get
 * no budget — the per-call gate is unaffected (extensions/node_modules types
 * lag the installed pi, so the field is not in the declaration).
 */
function parentCallId(event: ToolCallEvent): string | undefined {
  const raw = (event as { parentToolCallId?: unknown }).parentToolCallId;
  return typeof raw === "string" && raw.length > 0 ? raw : undefined;
}

/**
 * Pre-gate check: block a nested gated call once its script has spent its
 * budget. Returns undefined to let the call through to the normal gate.
 */
export function checkScriptBudget(
  event: ToolCallEvent,
): { block: true; reason: string } | undefined {
  const parent = parentCallId(event);
  if (!parent) return undefined; // the model's own call — one turn, few calls
  const name = typeof event.toolName === "string" ? event.toolName : "";
  if (!isEvaluatedSurface(name)) return undefined;

  const used = usedByScript.get(parent) ?? 0;
  if (used >= MAX_GATED_CALLS_PER_SCRIPT) {
    return {
      block: true,
      reason:
        `[Permission Policy] halter: a single script may attempt at most ${MAX_GATED_CALLS_PER_SCRIPT} gated tool calls, ` +
        `and this one has reached that — '${name}' is blocked (fail fast: the loop, not this call, is the problem). ` +
        `Return the results you already have, or split the remaining work into a new call.`,
    };
  }

  usedByScript.set(parent, used + 1);
  if (usedByScript.size > MAX_TRACKED_SCRIPTS) {
    const oldest = usedByScript.keys().next();
    if (!oldest.done) usedByScript.delete(oldest.value);
  }
  return undefined;
}

/** Test hook: current usage for one script key. */
export function scriptBudgetUsed(parent: string): number {
  return usedByScript.get(parent) ?? 0;
}
