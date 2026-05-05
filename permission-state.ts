import { store } from "./store";

export { updateWidget } from "./widget";

// ── Session lifecycle ──

/** Reset all permission state on session shutdown. */
export function resetState(): void {
  store.reset();
}
