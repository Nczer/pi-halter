/**
 * Shared interactive-UI mutex.
 *
 * pi runs all tool calls of one assistant message concurrently
 * (`agent/src/agent-loop.ts` — `Promise.all`), and every interactive UI
 * (pi's built-in select/confirm/input/editor, `ctx.ui.custom`) is shown by
 * clearing the editor container and adding one component. Two dialogs open at
 * the same time therefore replace each other: the first is cancelled when the
 * second opens.
 *
 * halter's permission prompts are tool-call UIs, so they race against consult.
 * Both extensions chain on the same `globalThis` key — a
 * module-local lock only serializes one extension against itself.
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
 * Locked per interaction, not per prompt flow: a flow can loop (Back), and the
 * judge "Explain"/"Judge again" paths make a model call between dialogs.
 * Holding the lock across a model call would block other UI for the whole
 * call. Interleaving flows is harmless — no two dialogs are ever open at once.
 */
export function withUILock<T>(fn: () => T | Promise<T>): Promise<T> {
  return sharedUiLock.withLock(fn);
}
