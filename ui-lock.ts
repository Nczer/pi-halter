/**
 * Shared interactive-UI mutex.
 *
 * pi runs all tool calls of one assistant message concurrently
 * (`agent/src/agent-loop.ts` — `Promise.all`) unless one declares
 * `executionMode: "sequential"`, and every interactive UI (select/confirm/
 * input/editor, `ctx.ui.custom`) is shown by clearing the editor container and
 * adding one component (`interactive-mode.ts` — `showExtensionSelector` and its
 * siblings, each first calling `disposeActiveSelector()`).
 *
 * Two dialogs opened at once therefore orphan each other. pi's own selector is
 * disposed on the way in, but a previous *extension* dialog is only dropped from
 * the container: its promise is settled by that component's own choose/cancel
 * callbacks, so nobody resolves it and the tool call that opened it never
 * returns. That is why halter's gate hangs if an ask dialog opens over its
 * permission prompt — the gate is waiting on a dialog the user can no longer see.
 *
 * Every extension that opens a dialog chains on the same `globalThis` key: a
 * module-local lock only serializes one extension against itself. Third-party
 * extensions that use the same key interoperate for free.
 */
const SHARED_UI_LOCK_KEY = "__piSharedUiLock";

function getSharedUiLock(): { withLock<T>(fn: () => T | Promise<T>): Promise<T> } {
  const g = globalThis as any;
  if (!g[SHARED_UI_LOCK_KEY]) {
    let chain: Promise<void> = Promise.resolve();
    g[SHARED_UI_LOCK_KEY] = {
      withLock<T>(fn: () => T | Promise<T>): Promise<T> {
        const prev = chain;
        let release: () => void;
        chain = new Promise<void>((r) => {
          release = r;
        });
        return prev.then(fn).finally(() => release!());
      },
    };
  }
  return g[SHARED_UI_LOCK_KEY];
}

const sharedUiLock = getSharedUiLock();

/**
 * Serialize one dialog interaction against every other interactive tool.
 *
 * Locked per interaction, not per prompt flow: a flow can loop (Back), and a
 * judge-style flow makes a model call between dialogs. Holding the lock across
 * a model call would block other UI for the whole call. Interleaving flows is
 * harmless — no two dialogs are ever open at once.
 */
export function withUILock<T>(fn: () => T | Promise<T>): Promise<T> {
  return sharedUiLock.withLock(fn);
}
