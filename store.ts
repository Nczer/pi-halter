import { promises as fs } from "node:fs";
import path from "node:path";
import os from "node:os";
import { PROMPT_WARNING_THRESHOLD, ABORT_REMEMBER_MS } from "./config";

// ── Wildcard matching (inlined from wildcard.ts) ──

/** Compile a wildcard pattern into a RegExp (call once, reuse). */
function compilePattern(pattern: string): RegExp {
  return new RegExp(
    "^" + pattern
      .replace(/[.+^${}()|[\]\\]/g, "\\$&") // Escape regex special chars except * and ?
      .replace(/\*/g, ".*")                // * -> match any characters
      .replace(/\?/g, ".")                 // ? -> match one character
    + "$",
    "i",
  );
}

/** Strip trailing " *" from a pattern so "npm test *" also matches "npm test". */
function stripTrailingWildcard(pattern: string): string | null {
  const m = pattern.match(/^(.*) \*$/);
  return m ? m[1] : null;
}

// ── Persistence (inlined from persistence.ts) ──

export interface UserRule {
  pattern: string;
  action: "allow" | "deny";
}

export interface UserPermissions {
  bash: UserRule[];
  read: UserRule[];
  write: UserRule[];
}

let CONFIG_PATH = path.join(os.homedir(), ".pi", "agent", "permissions.json");

/** Override persistence path (for tests). */
export function setPersistencePath(newPath: string) {
  CONFIG_PATH = newPath;
}

async function loadUserPermissions(): Promise<UserPermissions> {
  try {
    const data = await fs.readFile(CONFIG_PATH, "utf8");
    return JSON.parse(data);
  } catch {
    return { bash: [], read: [], write: [] };
  }
}

async function saveUserPermissions(permissions: UserPermissions): Promise<void> {
  try {
    await fs.mkdir(path.dirname(CONFIG_PATH), { recursive: true });
    await fs.writeFile(CONFIG_PATH, JSON.stringify(permissions, null, 2), "utf8");
  } catch (e) {
    console.error(`Failed to save permissions to ${CONFIG_PATH}:`, e);
  }
}

/** Cached compiled pattern for a user rule. */
interface CompiledRule {
  regex: RegExp;
  strippedRegex: RegExp | null;
  action: "allow" | "deny";
}

// ── Interface ──

/** Mutates auto-allow state and tracks abort history. The seam between policy and persistence. */
export interface Store {
  /** Check if a bash command signature is auto-allowed. */
  hasAllowedBash(signature: string): boolean;
  /** Check if a signature starts with an allowed prefix (e.g. "npm test --coverage" matches "npm test "). */
  hasAllowedBashPrefix(signature: string): boolean;
  /** Check if a file path is auto-allowed for read. */
  hasAllowedReadPath(path: string): boolean;
  /** Check if a file path is auto-allowed for write. */
  hasAllowedWritePath(path: string): boolean;
  /** Check if an MCP server is auto-allowed. */
  hasAllowedMcpServer(server: string): boolean;
  /** Add auto-allow rules in bulk. */
  addAllowed(rules: AllowRules): void;
  /** Initialize store from disk. */
  init(): Promise<void>;
  /** Add a user-defined rule for persistent allow/deny. */
  addUserRule(type: "bash" | "read" | "write", rule: UserRule): Promise<void>;
  /** Check if a pattern matches a user-defined rule. Returns "allow", "deny", or null. */
  getUserRuleAction(type: "bash" | "read" | "write", pattern: string): "allow" | "deny" | null;
  /** List all permanent user rules. */
  listUserRules(): Promise<UserPermissions>;
  /** Sync snapshot of user rules for UI rendering (may be stale if not loaded). */
  listUserRulesSync(): UserPermissions;
  /** Remove a permanent user rule by type and index. */
  removeUserRule(type: "bash" | "read" | "write", index: number): Promise<void>;
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
  /** Get a copy of all auto-allowed MCP servers. */
  listAllowedMcpServers(): Set<string>;
  /** Reset volatile session state (auto-allow, abort history, prompt counter). Preserves user rules. */
  resetSessionState(): void;
  /** Reset all state including user rules (session shutdown only). */
  reset(): void;
}

/** Structured rules for what to auto-allow on "always" confirmation. */
export interface AllowRules {
  bashSigs?: string[];
  readDirs?: string[];
  writeDirs?: string[];
  readPaths?: string[];
  writePaths?: string[];
  mcpServers?: string[];
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
  const mcpServers = new Set<string>();
  const aborted = new Map<string, number>();
  let pcount = 0;

  // User rules cache
  let userPerms: UserPermissions = { bash: [], read: [], write: [] };
  let isLoaded = false;
  // Compiled rules cache — keyed by type, invalidated on rule change
  const compiledCache = new Map<"bash" | "read" | "write", CompiledRule[]>();

  const compileRules = (type: "bash" | "read" | "write") => {
    const rules = userPerms[type];
    compiledCache.set(type, rules.map(rule => {
      try {
        const stripped = stripTrailingWildcard(rule.pattern);
        return {
          regex: compilePattern(rule.pattern),
          strippedRegex: stripped ? compilePattern(stripped) : null,
          action: rule.action,
        };
      } catch (e) {
        console.error(`[permissions] Invalid pattern '${rule.pattern}': ${(e as Error).message}`);
        return {
          regex: new RegExp("^$"), // never matches — skip silently
          strippedRegex: null,
          action: rule.action,
        };
      }
    }));
  };

  const ensureLoaded = async () => {
    if (isLoaded) return;
    userPerms = await loadUserPermissions();
    for (const type of ["bash", "read", "write"] as const) compileRules(type);
    isLoaded = true;
  };

  return {
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

    addAllowed(rules) {
      rules.bashSigs?.forEach(s => bashSigs.add(s));
      rules.readDirs?.forEach(d => readDirs.add(d));
      rules.writeDirs?.forEach(d => writeDirs.add(d));
      rules.readPaths?.forEach(p => readPaths.add(p));
      rules.writePaths?.forEach(p => writePaths.add(p));
      rules.mcpServers?.forEach(s => mcpServers.add(s));
    },

    async init() {
      await ensureLoaded();
    },

    async addUserRule(type, rule) {
      // Validate pattern before saving — fail fast on malformed regex
      try {
        compilePattern(rule.pattern);
      } catch (e) {
        throw new Error(`Invalid pattern '${rule.pattern}': ${(e as Error).message}`);
      }
      await ensureLoaded();
      userPerms[type].push(rule);
      compileRules(type);
      await saveUserPermissions(userPerms);
    },

    async listUserRules() {
      await ensureLoaded();
      return { ...userPerms };
    },

    listUserRulesSync() {
      return { bash: [...userPerms.bash], read: [...userPerms.read], write: [...userPerms.write] };
    },

    async removeUserRule(type, index) {
      await ensureLoaded();
      if (userPerms[type][index]) {
        userPerms[type].splice(index, 1);
        compileRules(type);
        await saveUserPermissions(userPerms);
      }
    },

    getUserRuleAction(type, target) {
      // Note: This is sync. If not loaded yet, it returns null.
      // In practice, we will trigger ensureLoaded() at agent startup.
      const compiled = compiledCache.get(type);
      if (!compiled) return null;
      for (const rule of compiled) {
        if (rule.regex.test(target)) return rule.action;
        if (rule.strippedRegex?.test(target)) return rule.action;
      }
      return null;
    },

    recordAbort(cmd) {
      aborted.set(cmd, nowFn());
      // Bounded cleanup on write to prevent unbounded growth
      if (aborted.size > 100) {
        const cutoff = nowFn() - ABORT_REMEMBER_MS;
        for (const [k, v] of aborted) {
          if (v < cutoff) aborted.delete(k);
        }
      }
    },
    getLastAbort(cmd) {
      const ts = aborted.get(cmd) ?? null;
      // Lazy cleanup: prune entries older than ABORT_REMEMBER_MS
      if (aborted.size > 100) {
        const cutoff = nowFn() - ABORT_REMEMBER_MS;
        for (const [k, v] of aborted) {
          if (v < cutoff) aborted.delete(k);
        }
      }
      return ts;
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

    resetSessionState() {
      bashSigs.clear();
      readDirs.clear();
      writeDirs.clear();
      readPaths.clear();
      writePaths.clear();
      mcpServers.clear();
      aborted.clear();
      pcount = 0;
      // Preserve userPerms and compiledCache — they are persistent, not session-scoped
    },

    reset() {
      this.resetSessionState();
      compiledCache.clear();
      isLoaded = false;
      userPerms = { bash: [], read: [], write: [] };
    },
  };
}

// ── Runtime singleton ──

/** The default store instance, used by handlers at runtime. */
export const store: Store = createStore();


