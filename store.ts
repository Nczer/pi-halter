import { promises as fs } from "node:fs";
import path from "node:path";
import os from "node:os";
import { PROMPT_WARNING_THRESHOLD, ABORT_REMEMBER_MS } from "./config";

// ── Wildcard matching ──

/** Compile a wildcard pattern into a RegExp (call once, reuse). */
function compilePattern(pattern: string): RegExp {
  return new RegExp(
    "^" + pattern
      .replace(/[.+^${}()|[\]\\]/g, "\\$&")
      .replace(/\*/g, ".*")
      .replace(/\?/g, ".")
    + "$",
    "i",
  );
}

/** Strip trailing " *" from a pattern so "npm test *" also matches "npm test". */
function stripTrailingWildcard(pattern: string): string | null {
  const m = pattern.match(/^(.*) \*$/);
  return m ? m[1] : null;
}

// ── Persistence types ──

export interface UserRule {
  pattern: string;
  action: "allow" | "deny";
}

export interface UserPermissions {
  bash: UserRule[];
  read: UserRule[];
  write: UserRule[];
}

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

// ── SessionState (volatile, in-memory) ──

/**
 * Volatile session state: auto-allow sets, abort history, prompt counter.
 * Resets on session restart. No disk I/O.
 */
export interface SessionState {
  hasAllowedBash(signature: string): boolean;
  hasAllowedBashPrefix(signature: string): boolean;
  hasAllowedReadPath(path: string): boolean;
  hasAllowedWritePath(path: string): boolean;
  hasAllowedMcpServer(server: string): boolean;
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
  clear(): void;
}

function createSessionState(nowFn = Date.now): SessionState {
  const bashSigs = new Set<string>();
  const readDirs = new Set<string>();
  const writeDirs = new Set<string>();
  const readPaths = new Set<string>();
  const writePaths = new Set<string>();
  const mcpServers = new Set<string>();
  const aborted = new Map<string, number>();
  let pcount = 0;

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

    recordAbort(cmd) {
      aborted.set(cmd, nowFn());
      if (aborted.size > 100) {
        const cutoff = nowFn() - ABORT_REMEMBER_MS;
        for (const [k, v] of aborted) {
          if (v < cutoff) aborted.delete(k);
        }
      }
    },
    getLastAbort(cmd) {
      const ts = aborted.get(cmd) ?? null;
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

    clear() {
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

// ── RuleStore (persistent, disk-backed) ──

/** Cached compiled pattern for a user rule. */
interface CompiledRule {
  regex: RegExp;
  strippedRegex: RegExp | null;
  action: "allow" | "deny";
}

/**
 * Persistent user rules: disk-backed allow/deny patterns.
 * Survives session restarts. Owns compiled pattern cache.
 */
export interface RuleStore {
  init(): Promise<void>;
  addUserRule(type: "bash" | "read" | "write", rule: UserRule): Promise<void>;
  getUserRuleAction(type: "bash" | "read" | "write", pattern: string): "allow" | "deny" | null;
  listUserRules(): Promise<UserPermissions>;
  listUserRulesSync(): UserPermissions;
  removeUserRule(type: "bash" | "read" | "write", index: number): Promise<void>;
  reset(): void;
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

function createRuleStore(): RuleStore {
  let userPerms: UserPermissions = { bash: [], read: [], write: [] };
  let isLoaded = false;
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
          regex: new RegExp("^$"),
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
    async init() {
      await ensureLoaded();
    },

    async addUserRule(type, rule) {
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

    getUserRuleAction(type, target) {
      const compiled = compiledCache.get(type);
      if (!compiled) return null;
      for (const rule of compiled) {
        if (rule.regex.test(target)) return rule.action;
        if (rule.strippedRegex?.test(target)) return rule.action;
      }
      return null;
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

    reset() {
      compiledCache.clear();
      isLoaded = false;
      userPerms = { bash: [], read: [], write: [] };
    },
  };
}

// ── Store (composite facade) ──

/**
 * Composite store combining volatile session state and persistent user rules.
 * Delegates to SessionState for auto-allow/abort tracking and to RuleStore
 * for persistent allow/deny patterns.
 */
export interface Store {
  // Session state
  hasAllowedBash(signature: string): boolean;
  hasAllowedBashPrefix(signature: string): boolean;
  hasAllowedReadPath(path: string): boolean;
  hasAllowedWritePath(path: string): boolean;
  hasAllowedMcpServer(server: string): boolean;
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

  // Rule store
  init(): Promise<void>;
  addUserRule(type: "bash" | "read" | "write", rule: UserRule): Promise<void>;
  getUserRuleAction(type: "bash" | "read" | "write", pattern: string): "allow" | "deny" | null;
  listUserRules(): Promise<UserPermissions>;
  listUserRulesSync(): UserPermissions;
  removeUserRule(type: "bash" | "read" | "write", index: number): Promise<void>;

  // Lifecycle
  resetSessionState(): void;
  reset(): void;
}

/**
 * Create a Store backed by fresh collections.
 * Used for both the runtime singleton and test fakes — one implementation, zero duplication.
 */
export function createStore(nowFn = Date.now): Store {
  const session = createSessionState(nowFn);
  const rules = createRuleStore();

  return {
    // Session state delegation
    hasAllowedBash: s => session.hasAllowedBash(s),
    hasAllowedBashPrefix: s => session.hasAllowedBashPrefix(s),
    hasAllowedReadPath: p => session.hasAllowedReadPath(p),
    hasAllowedWritePath: p => session.hasAllowedWritePath(p),
    hasAllowedMcpServer: s => session.hasAllowedMcpServer(s),
    addAllowed: r => session.addAllowed(r),
    recordAbort: c => session.recordAbort(c),
    getLastAbort: c => session.getLastAbort(c),
    incrementPromptCount: () => session.incrementPromptCount(),
    listAllowedBash: () => session.listAllowedBash(),
    listAllowedReadDirs: () => session.listAllowedReadDirs(),
    listAllowedWriteDirs: () => session.listAllowedWriteDirs(),
    listAllowedReadPaths: () => session.listAllowedReadPaths(),
    listAllowedWritePaths: () => session.listAllowedWritePaths(),
    listAllowedMcpServers: () => session.listAllowedMcpServers(),

    // Rule store delegation
    init: () => rules.init(),
    addUserRule: (t, r) => rules.addUserRule(t, r),
    getUserRuleAction: (t, p) => rules.getUserRuleAction(t, p),
    listUserRules: () => rules.listUserRules(),
    listUserRulesSync: () => rules.listUserRulesSync(),
    removeUserRule: (t, i) => rules.removeUserRule(t, i),

    // Lifecycle
    resetSessionState() {
      session.clear();
    },
    reset() {
      session.clear();
      rules.reset();
    },
  };
}

// ── Runtime singleton ──

/** The default store instance, used by handlers at runtime. */
export const store: Store = createStore();
