import { createRequire } from "node:module";
import { pathAwareCommands } from "../config";
import { expandTilde, resolvePathReal } from "./path-analysis";

// ── Lazy tree-sitter parser ────────────────────────────────────────────────

interface TSNode {
  readonly type: string;
  readonly text: string;
  readonly childCount: number;
  child(index: number): TSNode | null;
}

interface TSParser {
  parse(input: string): { rootNode: TSNode; delete(): void } | null;
  delete(): void;
}

let parserPromise: Promise<TSParser> | null = null;

async function initParser(): Promise<TSParser> {
  const { Parser, Language } = await import("web-tree-sitter");
  const req = createRequire(import.meta.url);
  const wasm = req.resolve("web-tree-sitter/web-tree-sitter.wasm");
  await Parser.init({ locateFile: () => wasm });

  const parser = new Parser();
  const bash = await Language.load(req.resolve("tree-sitter-bash/tree-sitter-bash.wasm"));
  parser.setLanguage(bash);
  return parser as TSParser;
}

function getParser(): Promise<TSParser> {
  if (!parserPromise) parserPromise = initParser().catch((e) => {
    parserPromise = null; // Reset so next call retries instead of caching the failure
    throw e;
  });
  return parserPromise;
}

// ── AST helpers ─────────────────────────────────────────────────────────────

/** Node types whose subtrees are not command arguments. */
const SKIP_TYPES = new Set(["heredoc_body", "heredoc_end", "comment"]);
/** Node types that represent a shell word (for command name/argument detection). */
const WORD_TYPES = new Set(["word", "concatenation", "string", "raw_string"]);

/** Strip backslash escapes from a shell word (\X → X for any character). */
function stripBackslashEscapes(text: string): string {
  let result = "";
  for (let i = 0; i < text.length; i++) {
    if (text[i] === "\\" && i + 1 < text.length) {
      result += text[i + 1];
      i++; // skip the escaped character
    } else {
      result += text[i];
    }
  }
  return result;
}

/** Resolve the shell value of an argument node (quote removal, concatenation). */
function resolveNodeText(node: TSNode): string {
  switch (node.type) {
    case "word":
      return stripBackslashEscapes(node.text);
    case "raw_string": {
      const t = node.text;
      return t.length >= 2 && t[0] === "'" && t[t.length - 1] === "'"
        ? t.slice(1, -1)
        : t;
    }
    case "string_content":
    case "simple_expansion":
    case "expansion":
      return node.text;
    case "string":
    case "concatenation": {
      let result = "";
      for (let i = 0; i < node.childCount; i++) {
        const child = node.child(i);
        if (!child) continue;
        if (node.type === "string" && child.type === '"') continue;
        result += resolveNodeText(child);
      }
      return result;
    }
    default:
      return node.text;
  }
}

/** Extract argument text from a command node (skip command name). */
function extractCommandArgs(node: TSNode): string[] {
  const args: string[] = [];
  if (node.type !== "command") return args;

  let seenName = false;
  for (let i = 0; i < node.childCount; i++) {
    const child = node.child(i);
    if (!child) continue;

    if (child.type === "command_name") {
      seenName = true;
      continue;
    }
    if (child.type === "variable_assignment") continue;

    // First word-like child is the command name if no explicit command_name node
    if (!seenName && WORD_TYPES.has(child.type)) {
      seenName = true;
      continue;
    }

    if (WORD_TYPES.has(child.type)) {
      args.push(resolveNodeText(child));
      continue;
    }

    // Recurse (e.g., command substitution in args)
    for (let j = 0; j < child.childCount; j++) {
      const gc = child.child(j);
      if (gc) args.push(...extractFromNode(gc));
    }
  }
  return args;
}

/** Extract redirect destinations from a file_redirect node. */
function extractRedirectPaths(node: TSNode): string[] {
  const paths: string[] = [];
  if (node.type !== "file_redirect") return paths;

  for (let i = 0; i < node.childCount; i++) {
    const child = node.child(i);
    if (!child) continue;
    if (WORD_TYPES.has(child.type)) {
      paths.push(resolveNodeText(child));
    }
  }
  return paths;
}

/** Recursively collect argument text from an AST node. */
function extractFromNode(node: TSNode): string[] {
  if (SKIP_TYPES.has(node.type)) return [];

  if (node.type === "command") return extractCommandArgs(node);
  if (node.type === "file_redirect") return extractRedirectPaths(node);

  const results: string[] = [];
  for (let i = 0; i < node.childCount; i++) {
    const child = node.child(i);
    if (child) results.push(...extractFromNode(child));
  }
  return results;
}

// ── Path candidate classification ──────────────────────────────────────────

/** Paths that are universally safe and should never trigger checks. */
const SAFE_SYSTEM_PATHS = new Set([
  "/dev/null",
  "/dev/stdin",
  "/dev/stdout",
  "/dev/stderr",
]);

const URL_PATTERN = /^[a-z][a-z0-9+.-]*:\/\//i;
const BARE_SLASH_RE = /^\/\/+$/;

/** Check if a token looks like a filesystem path worth resolving. */
function isPathCandidate(token: string): boolean {
  if (!token) return false;
  if (URL_PATTERN.test(token)) return false; // URL

  // For flag values like --file=/etc/passwd or -f=/etc/passwd,
  // extract the value after = and check if that is a path.
  // Plain flags without = are never paths.
  if (token.startsWith("-")) {
    const eqIdx = token.indexOf("=");
    if (eqIdx === -1 || eqIdx >= token.length - 1) return false;
    token = token.slice(eqIdx + 1);
    if (!token) return false;
    // Fall through to path checks below
  } else {
    // Env assignment (FOO=/bar) — skip
    const eqIdx = token.indexOf("=");
    const slashIdx = token.indexOf("/");
    if (eqIdx !== -1 && (slashIdx === -1 || eqIdx < slashIdx)) return false;

    // @scope/package patterns
    if (token.startsWith("@") && !token.startsWith("@/")) return false;
  }

  // Bare slashes (// JS comments, lone /)
  if (BARE_SLASH_RE.test(token)) return false;

  // Must look like a path
  return (
    token.startsWith("/") ||
    token.startsWith("./") ||
    token.startsWith("~/") ||
    token.includes("..")
  );
}

// ── Command name extraction ────────────────────────────────────────────────

/** Get the command name from a command AST node. */
function getCommandName(node: TSNode): string | null {
  if (node.type !== "command") return null;

  for (let i = 0; i < node.childCount; i++) {
    const child = node.child(i);
    if (!child) continue;
    if (child.type === "command_name") {
      // command_name may contain multiple children (e.g., "npm" "run")
      // For our purposes, get the first word. Lowercase to match pathAwareCommands.
      if (child.childCount > 0) {
        const text = child.child(0)?.text;
        return text ? text.toLowerCase() : null;
      }
      return null;
    }
    // First word-like child is the command name
    if (WORD_TYPES.has(child.type)) {
      return resolveNodeText(child).toLowerCase();
    }
  }
  return null;
}

/** Collect all command nodes from the AST. */
function collectCommandNodes(node: TSNode): TSNode[] {
  if (SKIP_TYPES.has(node.type)) return [];
  if (node.type === "command") return [node];

  const results: TSNode[] = [];
  for (let i = 0; i < node.childCount; i++) {
    const child = node.child(i);
    if (child) results.push(...collectCommandNodes(child));
  }
  return results;
}

// ── Segment extraction ──────────────────────────────────────────────────────

/**
 * Segment of a bash command, split on &&, ||, ;, |, |&, &.
 * Each segment represents one logical command or pipeline.
 */
export interface BashSegment {
  /** Raw text of the segment. */
  text: string;
  /** Operators present within the segment (e.g. "|", ">", "2>"). */
  ops: string[];
  /** Whether this segment contains subshell constructs ($(), ``). */
  hasSubshell: boolean;
  /** Inner command texts of subshell $() and process >() substitutions (empty if none). */
  subshellTexts?: string[];
}

/** Node types that are shell operators (split points or internal ops). */
const OPERATOR_TYPES = new Set(["&&", "||", ";", "|", "|&", "&"]);

/**
 * Recursively walk the AST to extract segments.
 * - binary_expression (&&, ||) → split into separate segments
 * - command_list (;) → split into separate segments
 * - pipeline (|, |&) → group as one segment with pipe ops
 * - backgrounding (&) → split into separate segments
 * - command/file_redirect → leaf segment
 */
function extractSegmentsFromNode(node: TSNode): BashSegment[] {
  const segments: BashSegment[] = [];

  // ── Type handlers ──

  type Handler = (n: TSNode) => void;

  /** Recurse into all children (default handler). */
  const recurseAll: Handler = (n) => {
    for (let i = 0; i < n.childCount; i++) {
      const child = n.child(i);
      if (child) walk(child);
    }
  };

  /** Split on operator nodes (binary_expression, command_list, backgrounding). */
  const splitOnOp: Handler = (n) => {
    for (let i = 0; i < n.childCount; i++) {
      const child = n.child(i);
      if (child && !OPERATOR_TYPES.has(child.type)) {
        walk(child);
      }
    }
  };

  /** Group pipeline commands into one segment with pipe ops. */
  const handlePipeline: Handler = (n) => {
    const cmdTexts: string[] = [];
    const ops = new Set<string>();
    let segHasSubshell = false;
    for (let i = 0; i < n.childCount; i++) {
      const child = n.child(i);
      if (!child) continue;
      if (child.type === "|" || child.type === "|&") {
        ops.add(child.type);
      } else if (child.type === "command") {
        cmdTexts.push(child.text.trim());
        if (nodeHasSubshell(child)) segHasSubshell = true;
      } else {
        // redirected_statement, subshell, etc. — recurse to extract commands.
        // A compound child can produce multiple segments split on && / ; / & (e.g. a
        // redirected_statement wrapping "A && B", or a subshell). Only the LAST
        // newly-added segment is the pipeline stage feeding the next `|`; earlier
        // segments are separate commands (control operators) and must remain
        // top-level segments. Folding them in would hide them behind the last
        // stage's signature — e.g. "cd … && npx vitest 2>&1 | grep" collapsing to
        // a single "cd"-signed segment and auto-allowing the hidden npx.
        // (prevCount guard avoids stealing pre-existing segments — the bug that
        // the prior "merge all" loop was band-aiding.)
        const prevCount = segments.length;
        walk(child);
        if (segments.length > prevCount) {
          const last = segments.pop()!;
          cmdTexts.push(last.text);
          segHasSubshell = segHasSubshell || last.hasSubshell;
          for (const op of last.ops) ops.add(op);
        }
      }
    }
    if (cmdTexts.length > 0) {
      segments.push({ text: cmdTexts.join(" | "), ops: [...ops], hasSubshell: segHasSubshell, subshellTexts: extractSubshellInnerTexts(n) });
    }
  };

  /** Group command + its redirects as one segment. */
  const handleRedirectedStatement: Handler = (n) => {
    let hasCompoundChild = false;
    const cmdTexts: string[] = [];
    const redirectTexts: string[] = [];
    const ops = new Set<string>();
    let segHasSubshell = false;
    for (let i = 0; i < n.childCount; i++) {
      const child = n.child(i);
      if (!child) continue;
      if (child.type === "command") {
        cmdTexts.push(child.text.trim());
        if (nodeHasSubshell(child)) segHasSubshell = true;
      } else if (child.type === "file_redirect") {
        const redirText = child.text.trim();
        cmdTexts.push(redirText);
        redirectTexts.push(redirText);
        const redirectOps = detectOpsInNode(child);
        for (const op of redirectOps) ops.add(op);
      } else if (child.type === "heredoc_redirect") {
        // For heredoc, only include the operator + delimiter (e.g. "<< 'PYEOF'"), not the body.
        // The body is opaque data/code that the parser skips — including it would cause
        // dangerousContextPatterns to match content that isn't actually shell commands.
        const heredocParts: string[] = [];
        for (let j = 0; j < child.childCount; j++) {
          const gc = child.child(j);
          if (!gc) continue;
          if (gc.type === "<<" || gc.type === "<<<" || gc.type === "heredoc_start") {
            heredocParts.push(gc.text);
          }
          // Skip heredoc_body and heredoc_end — they are opaque to shell analysis
        }
        const heredocShort = heredocParts.join(" ").trim();
        if (heredocShort) {
          cmdTexts.push(heredocShort);
          redirectTexts.push(heredocShort);
        }
        const redirectOps = detectOpsInNode(child);
        for (const op of redirectOps) ops.add(op);
      } else {
        // list, binary_expression, pipeline, for_statement, while_statement, if_statement, etc.
        hasCompoundChild = true;
        walk(child);
      }
    }
    if (!hasCompoundChild && cmdTexts.length > 0) {
      segments.push({ text: cmdTexts.join(" "), ops: [...ops], hasSubshell: segHasSubshell, subshellTexts: extractSubshellInnerTexts(n) });
    } else if (hasCompoundChild && redirectTexts.length > 0) {
      if (segments.length > 0) {
        // Propagate redirects to the last segment so hasWriteRedirect can detect them
        segments[segments.length - 1].text += " " + redirectTexts.join(" ");
        for (const op of ops) segments[segments.length - 1].ops.push(op);
      } else {
        // Compound child walk produced no segments (e.g. empty subshell "() > out").
        // Create a redirect-only segment so write-redirect detection isn't silently lost.
        segments.push({ text: redirectTexts.join(" "), ops: [...ops], hasSubshell: false, subshellTexts: extractSubshellInnerTexts(n) });
      }
    }
  };

  /** Leaf: single command or redirect. */
  const handleLeaf: Handler = (n) => {
    const ops = detectOpsInNode(n);
    segments.push({ text: n.text.trim(), ops, hasSubshell: nodeHasSubshell(n), subshellTexts: extractSubshellInnerTexts(n) });
  };

  // ── Handler map ──

  const handlers: Map<string, Handler> = new Map([
    ["binary_expression", splitOnOp],
    ["command_list", splitOnOp],
    ["backgrounding", splitOnOp],
    ["pipeline", handlePipeline],
    ["redirected_statement", handleRedirectedStatement],
    ["command", handleLeaf],
    ["file_redirect", handleLeaf],
  ]);

  // ── Walk ──

  function walk(n: TSNode): void {
    if (SKIP_TYPES.has(n.type)) return;

    const handler = handlers.get(n.type);
    if (handler) {
      handler(n);
      return;
    }

    // for/if/while/case: recurse into body
    if (n.type.startsWith("for_") || n.type.startsWith("if_") || n.type.startsWith("while_") || n.type.startsWith("case_")) {
      recurseAll(n);
      return;
    }

    // default: recurse
    recurseAll(n);
  }

  walk(node);
  return segments;
}

/** Per-parse-session cache for nodeHasSubshell to avoid redundant subtree walks. */
let subshellCache: WeakMap<TSNode, boolean> | null = null;

/** Check if an AST node subtree contains subshell constructs (cached per parse session). */
function nodeHasSubshell(node: TSNode): boolean {
  if (subshellCache?.has(node)) return subshellCache.get(node)!;

  const result =
    node.type === "command_substitution" ||
    node.type === "process_substitution" ||
    [...Array(node.childCount)].some((_, i) => {
      const child = node.child(i);
      return child && nodeHasSubshell(child);
    });

  subshellCache?.set(node, result);
  return result;
}

/**
 * Extract inner command texts from all $() and `cmd` command substitutions,
 * and >()/ <() process substitutions in the subtree. Returns an empty array
 * if none are found.
 */
function extractSubshellInnerTexts(node: TSNode): string[] {
  const texts: string[] = [];
  function walk(n: TSNode): void {
    if (n.type === "command_substitution" || n.type === "process_substitution") {
      // The inner content could be a command, pipeline, or list node.
      // Walk children to find the executable content and extract its text.
      for (let i = 0; i < n.childCount; i++) {
        const child = n.child(i);
        if (child && (child.type === "command" || child.type === "pipeline" || child.type === "list")) {
          const inner = child.text.trim();
          if (inner) texts.push(inner);
          break;
        }
      }
    }
    for (let i = 0; i < n.childCount; i++) {
      const child = n.child(i);
      if (child) walk(child);
    }
  }
  walk(node);
  return texts;
}

/** Detect operators within a command/redirect node. */
function detectOpsInNode(node: TSNode): string[] {
  const ops = new Set<string>();
  function check(n: TSNode): void {
    if (SKIP_TYPES.has(n.type)) return;
    if (n.type === "|" || n.type === "|&") {
      ops.add(n.type);
    }
    if (n.type === "redirect_operator" || n.type === "<<" || n.type === "<<<") {
      ops.add(n.text);
    }
    for (let i = 0; i < n.childCount; i++) {
      const child = n.child(i);
      if (child) check(child);
    }
  }
  check(node);
  return [...ops];
}

// ── Public API ──────────────────────────────────────────────────────────────

/**
 * Single parse that extracts segments, paths, and subshell flags.
 */
export async function parseCommand(command: string, cwd: string): Promise<{ segments: BashSegment[]; paths: string[]; hasParseError: boolean }> {
  const parser = await getParser();
  const tree = parser.parse(command);
  if (!tree) return { segments: [], paths: [], hasParseError: false };

  try {
    // Check for ERROR nodes in the AST (malformed bash)
    let hasParseError = false;
    const checkError = (node: TSNode): void => {
      if (node.type === "ERROR") { hasParseError = true; return; }
      for (let i = 0; i < node.childCount; i++) {
        const child = node.child(i);
        if (child) checkError(child);
      }
    };
    checkError(tree.rootNode);
    // Cache subshell checks per parse session to avoid redundant subtree walks
    subshellCache = new WeakMap();

    // Extract segments (includes per-segment hasSubshell)
    const segments = extractSegmentsFromNode(tree.rootNode);

    // Extract paths from command nodes
    const commandNodes = collectCommandNodes(tree.rootNode);
    const allPaths: string[] = [];

    for (const cmdNode of commandNodes) {
      const cmdName = getCommandName(cmdNode);
      const args = extractCommandArgs(cmdNode);

      if (cmdName && pathAwareCommands.has(cmdName)) {
        for (const arg of args) {
          if (isPathCandidate(arg)) {
            // For flag values (--file=/path), resolve the value, not the flag itself.
            // isPathCandidate already accepts these; match its extraction logic.
            const resolveArg = arg.startsWith("-") && arg.includes("=")
              ? arg.slice(arg.indexOf("=") + 1)
              : arg;
            allPaths.push(resolvePathReal(expandTilde(resolveArg), cwd));
          }
        }
      }
    }

    // Extract redirect paths
    const redirectPaths: string[] = [];
    const extractRedirects = (node: TSNode): void => {
      if (SKIP_TYPES.has(node.type)) return;
      if (node.type === "file_redirect") {
        for (const p of extractRedirectPaths(node)) {
          if (isPathCandidate(p)) {
            redirectPaths.push(resolvePathReal(expandTilde(p), cwd));
          }
        }
      }
      for (let i = 0; i < node.childCount; i++) {
        const child = node.child(i);
        if (child) extractRedirects(child);
      }
    };
    extractRedirects(tree.rootNode);
    allPaths.push(...redirectPaths);

    // Deduplicate, filter safe system paths
    const seen = new Set<string>();
    const paths = allPaths.filter(p => {
      if (SAFE_SYSTEM_PATHS.has(p)) return false;
      if (seen.has(p)) return false;
      seen.add(p);
      return true;
    });

    return { segments, paths, hasParseError };
  } finally {
    subshellCache = null;
    tree.delete();
  }
}


