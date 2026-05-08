import { PROMPT_WARNING_THRESHOLD } from "./config";

// ── Interface ──

/** Mutates auto-allow state and tracks abort history. The seam between policy and persistence. */
export interface Store {
  /** Check if a bash command signature is auto-allowed. */
  hasAllowedBash(signature: string): boolean;
  /** Check if a directory is auto-allowed for read. */
  hasAllowedReadDir(dir: string): boolean;
  /** Check if a directory is auto-allowed for write. */
  hasAllowedWriteDir(dir: string): boolean;
  /** Check if a file path is auto-allowed for read. */
  hasAllowedReadPath(path: string): boolean;
  /** Check if a file path is auto-allowed for write. */
  hasAllowedWritePath(path: string): boolean;
  /** Check if a subagent name is auto-allowed. */
  hasAllowedSubagent(name: string): boolean;
  /** Check if an MCP server is auto-allowed. */
  hasAllowedMcpServer(server: string): boolean;
  /** Check if a specific MCP tool (server:tool) is auto-allowed. */
  hasAllowedMcpTool(tool: string): boolean;
  /** Add auto-allow rules in bulk. */
  addAllowed(rules: AllowRules): void;
  /** Record that a command was just aborted (for retry-loop prevention). */
  recordAbort(command: string): void;
  /** Get the timestamp of the last abort for a command, or null. */
  getLastAbort(command: string): number | null;
  /** Increment prompt counter. Returns whether threshold is exceeded. */
  incrementPromptCount(): { over: boolean; count: number };
  /** Get a copy of all auto-allowed bash signatures. */
  listAllowedBash(): Set<string>;
  /** Get a copy of all auto-allowed read directories. */
  listAllowedReadDirs(): Set<string>;
  /** Get a copy of all auto-allowed write directories. */
  listAllowedWriteDirs(): Set<string>;
  /** Get a copy of all auto-allowed read paths. */
  listAllowedReadPaths(): Set<string>;
  /** Get a copy of all auto-allowed write paths. */
  listAllowedWritePaths(): Set<string>;
  /** Get a copy of all auto-allowed subagent names. */
  listAllowedSubagent(): Set<string>;
  /** Get a copy of all auto-allowed MCP servers. */
  listAllowedMcpServers(): Set<string>;
  /** Get a copy of all auto-allowed MCP tools. */
  listAllowedMcpTools(): Set<string>;
  /** Reset all state (session shutdown). */
  reset(): void;
}

/** Structured rules for what to auto-allow on "always" confirmation. */
export interface AllowRules {
  bashSigs?: string[];
  readDirs?: string[];
  writeDirs?: string[];
  readPaths?: string[];
  writePaths?: string[];
  subagentNames?: string[];
  mcpServers?: string[];
  mcpTools?: string[];
}

// ── Factory ──

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
  const subagents = new Set<string>();
  const mcpServers = new Set<string>();
  const mcpTools = new Set<string>();
  const aborted = new Map<string, number>();
  let pcount = 0;

  return {
    hasAllowedBash(s) { return bashSigs.has(s); },
    hasAllowedReadDir(d) { return readDirs.has(d); },
    hasAllowedWriteDir(d) { return writeDirs.has(d); },
    hasAllowedReadPath(p) { return readPaths.has(p); },
    hasAllowedWritePath(p) { return writePaths.has(p); },
    hasAllowedSubagent(n) { return subagents.has(n); },
    hasAllowedMcpServer(s) { return mcpServers.has(s); },
    hasAllowedMcpTool(t) { return mcpTools.has(t); },

    addAllowed(rules) {
      rules.bashSigs?.forEach(s => bashSigs.add(s));
      rules.readDirs?.forEach(d => readDirs.add(d));
      rules.writeDirs?.forEach(d => writeDirs.add(d));
      rules.readPaths?.forEach(p => readPaths.add(p));
      rules.writePaths?.forEach(p => writePaths.add(p));
      rules.subagentNames?.forEach(n => subagents.add(n));
      rules.mcpServers?.forEach(s => mcpServers.add(s));
      rules.mcpTools?.forEach(t => mcpTools.add(t));
    },

    recordAbort(cmd) { aborted.set(cmd, nowFn()); },
    getLastAbort(cmd) { return aborted.get(cmd) ?? null; },

    listAllowedBash() { return new Set(bashSigs); },
    listAllowedReadDirs() { return new Set(readDirs); },
    listAllowedWriteDirs() { return new Set(writeDirs); },
    listAllowedReadPaths() { return new Set(readPaths); },
    listAllowedWritePaths() { return new Set(writePaths); },
    listAllowedSubagent() { return new Set(subagents); },
    listAllowedMcpServers() { return new Set(mcpServers); },
    listAllowedMcpTools() { return new Set(mcpTools); },

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
      subagents.clear();
      mcpServers.clear();
      mcpTools.clear();
      aborted.clear();
      pcount = 0;
    },
  };
}

// ── Runtime singleton ──

/** The default store instance, used by handlers at runtime. */
export const store: Store = createStore();

// ── Test helper ──

/** Create a store backed by fresh collections. For unit tests. */
export function createFakeStore(): Store {
  return createStore();
}
