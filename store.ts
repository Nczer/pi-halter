import { PROMPT_WARNING_THRESHOLD, ABORT_REMEMBER_MS } from "./config";

// ── Allow rules ──

/** Structured rules for what to auto-allow on "always" confirmation. */
export interface AllowRules {
  bashSigs?: string[];
  readDirs?: string[];
  writeDirs?: string[];
  readPaths?: string[];
  writePaths?: string[];
  mcpServers?: string[];
}

// ── Store (volatile, in-memory) ──

/**
 * Store: auto-allow sets, abort tracking, prompt counter.
 * Resets on session restart. No persistence.
 */
export interface Store {
  hasAllowedBash(signature: string): boolean;
  hasAllowedBashPrefix(signature: string): boolean;
  hasAllowedReadPath(path: string): boolean;
  hasAllowedWritePath(path: string): boolean;
  hasAllowedMcpServer(server: string): boolean;
  /** Check if a resolved path is inside a session-auto-allowed dir (no Set copy). */
  isInsideAllowedDir(resolved: string, kind: "read" | "write"): boolean;
  addAllowed(rules: AllowRules): void;
  recordAbort(command: string): void;
  getLastAbort(command: string): number | null;
  incrementPromptCount(): { over: boolean; count: number };
  listAllowedBash(): Set<string>;
  listAllowedReadDirs(): Set<string>;
  listAllowedWriteDirs(): Set<string>;
  listAllowedReadPaths(): Set<string>;
  listAllowedWritePaths(): Set<string>;
  listAllowedMcpServers(): Set<string>;

  /** Get current time (uses injected clock for testability). */
  now(): number;

  /** Clear all session state. */
  reset(): void;
}

/**
 * Create a Store backed by fresh collections.
 * Used for both the runtime singleton and test fakes — one implementation, zero duplication.
 */
export function createStore(nowFn = Date.now): Store {
  const bashSigs = new Set<string>();
  const readDirs = new Set<string>();
  const writeDirs = new Set<string>();
  const readPaths = new Set<string>();
  const writePaths = new Set<string>();
  const mcpServers = new Set<string>();
  const aborted = new Map<string, number>();
  let pcount = 0;

  // Normalize so trivial whitespace variations ("rm  -rf foo" vs "rm -rf foo")
  // can't evade the retry-loop block.
  const normalizeCmd = (cmd: string) => cmd.trim().replace(/\s+/g, " ");

  const pruneAborted = () => {
    if (aborted.size > 100) {
      const cutoff = nowFn() - ABORT_REMEMBER_MS;
      for (const [k, v] of aborted) {
        if (v < cutoff) aborted.delete(k);
      }
    }
  };

  return {
    now() { return nowFn(); },
    hasAllowedBash(s) { return bashSigs.has(s); },
    hasAllowedBashPrefix(s) {
      for (const allowed of bashSigs) {
        if (s.startsWith(allowed + " ")) return true;
      }
      return false;
    },
    hasAllowedReadPath(p) { return readPaths.has(p); },
    hasAllowedWritePath(p) { return writePaths.has(p); },
    hasAllowedMcpServer(s) { return mcpServers.has(s); },
    isInsideAllowedDir(resolved, kind) {
      // Write dirs imply read, so "read" checks both sets.
      const sets = kind === "read" ? [readDirs, writeDirs] : [writeDirs];
      for (const set of sets) {
        if (set.has(resolved)) return true;
        for (const d of set) {
          if (resolved === d || resolved.startsWith(d + "/")) return true;
        }
      }
      return false;
    },

    addAllowed(rules) {
      rules.bashSigs?.forEach(s => bashSigs.add(s));
      rules.readDirs?.forEach(d => readDirs.add(d));
      rules.writeDirs?.forEach(d => writeDirs.add(d));
      rules.readPaths?.forEach(p => readPaths.add(p));
      rules.writePaths?.forEach(p => writePaths.add(p));
      rules.mcpServers?.forEach(s => mcpServers.add(s));
    },

    recordAbort(cmd) {
      aborted.set(normalizeCmd(cmd), nowFn());
      pruneAborted();
    },
    getLastAbort(cmd) {
      pruneAborted();
      return aborted.get(normalizeCmd(cmd)) ?? null;
    },

    listAllowedBash() { return new Set(bashSigs); },
    listAllowedReadDirs() { return new Set(readDirs); },
    listAllowedWriteDirs() { return new Set(writeDirs); },
    listAllowedReadPaths() { return new Set(readPaths); },
    listAllowedWritePaths() { return new Set(writePaths); },
    listAllowedMcpServers() { return new Set(mcpServers); },

    incrementPromptCount() {
      pcount++;
      return { over: pcount > PROMPT_WARNING_THRESHOLD, count: pcount };
    },

    reset() {
      bashSigs.clear();
      readDirs.clear();
      writeDirs.clear();
      readPaths.clear();
      writePaths.clear();
      mcpServers.clear();
      aborted.clear();
      pcount = 0;
    },
  };
}

// ── Runtime singleton ──

/** The default store instance, used by handlers at runtime. */
export const store: Store = createStore();
