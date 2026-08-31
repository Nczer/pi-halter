import { createRequire } from "node:module";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { allowedReadPaths, allowedWritePaths, pathAwareCommands } from "../config";
import { expandTilde, resolvePathReal } from "./path-analysis";
import { OPAQUE_VAR_DIR } from "./path-util";
import { isCwdLocalWord } from "./cwd-local";
import type { ShellAssignment } from "./var-resolution";
import { decodeAnsiCEscapes } from "./tokenizer";

export { OPAQUE_VAR_DIR }; // Re-export for existing importers

// ── Lazy tree-sitter parser ────────────────────────────────────────────────

interface TSNode {
  readonly type: string;
  readonly text: string;
  readonly childCount: number;
  readonly parent: TSNode | null;
  /** Stable node identity within the tree (child(i) wrappers are fresh per call). */
  readonly id: number;
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
/** Node types that represent a shell word (for command name/argument detection).
 *  Expansion types (simple_expansion $X, expansion ${X:-y}, array_expansion $@)
 *  are words too: their text reaches the path/opaque checks (a bare `cat $X`
 *  must not silently vanish from the argument list). */
const WORD_TYPES = new Set([
  "word",
  "concatenation",
  "string",
  "raw_string",
  "ansi_c_string",
  "simple_expansion",
  "expansion",
  "array_expansion",
]);

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
    case "ansi_c_string": {
      // $'...' — decode runtime escapes (\xHH, \NNN, \n, ...) so decoded
      // paths/credentials are visible to path extraction.
      const t = node.text;
      if (t.startsWith("$")) {
        const content = t.endsWith("'") ? t.slice(2, -1) : t.slice(2);
        return decodeAnsiCEscapes(content);
      }
      return t;
    }
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

/** Extract arguments (text + source node) from a command node (skip command
 *  name). The node is kept so the caller can tell a multi-line LITERAL
 *  argument (a script body) apart from one that expands at runtime. */
function extractCommandArgPairs(node: TSNode): { text: string; node: TSNode }[] {
  const args: { text: string; node: TSNode }[] = [];
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
      args.push({ text: resolveNodeText(child), node: child });
      continue;
    }

    // Recurse (e.g., command substitution in args) — the pair keeps the
    // subtree root as its node (runtime-expansion checks walk the subtree).
    for (let j = 0; j < child.childCount; j++) {
      const gc = child.child(j);
      if (gc) for (const text of extractFromNode(gc)) args.push({ text, node: gc });
    }
  }
  return args;
}

/** Extract argument text from a command node (skip command name). */
function extractCommandArgs(node: TSNode): string[] {
  return extractCommandArgPairs(node).map(p => p.text);
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

/**
 * Statically resolvable variable-path tokens — a closed set. `$HOME`/`${HOME}`
 * expand to os.homedir() independent of any cd; any other variable or
 * expansion (`$D/x`, `${HOME:-/tmp}`) is a computed path and stays opaque
 * (its value is only knowable by running the shell).
 */
const HOME_TOKEN_RE = /^\$(?:\{HOME\}|HOME)(?:\/|(?![a-zA-Z0-9_]))/;

/** Expand a leading $HOME / ${HOME} to the home directory (no-op otherwise). */
function expandHomeToken(p: string): string {
  const m = p.match(/^\$(?:\{HOME\}|HOME)(?:\/(.*))?$/);
  if (!m) return p;
  return m[1] !== undefined ? path.join(os.homedir(), m[1]) : os.homedir();
}

/**
 * Opaque expansions in path position: $VAR / ${VAR…} / $(…) / backticks.
 * The runtime location is only knowable by executing the shell — fail closed
 * with a marker path outside every allowed dir (→ path approval).
 * Closed-set $HOME/${HOME} is excluded (resolved statically below).
 * Note: single-quoted literal arguments (`cat '$X'`) lose their literalness
 * at the text level and are over-flagged — the safe direction.
 * The parser no longer emits marker PATHS for these — it emits an OpaqueRef
 * (below), which the analysis layer (var-resolution) binds against the
 * command's assignments and the tracked effective cwd.
 */

/** Strip a leading flag (-f=, --file=) so the VALUE is inspected, not the flag. */
function flagValue(arg: string): string {
  return arg.startsWith("-") && arg.includes("=")
    ? arg.slice(arg.indexOf("=") + 1)
    : arg;
}

/** `$` introduces an expansion only when followed by a name char, `{`, `(`,
 *  or a special parameter (@ * # ? ! $ - %). A trailing `$` or a `$` before
 *  punctuation is a bash literal (the `grep 'foo$'` idiom) and carries no
 *  runtime path dependency. */
const DOLLAR_EXPANSION_RE = /\$[\w({@*#?!$%-]/;

/** True when the value is an expansion not resolvable at gate time.
 *  Closed-set $HOME/${HOME} is NOT opaque (it is resolved statically). */
function isOpaqueValue(val: string): boolean {
  if (val.includes("`")) return true; // command substitution — runtime value
  if (HOME_TOKEN_RE.test(val)) return false;
  return DOLLAR_EXPANSION_RE.test(val);
}

/** Node types whose presence in an argument subtree means the value is
 *  computed at runtime (a literal word/raw_string/ansi_c_string has none). */
const RUNTIME_EXPANSION_TYPES = new Set([
  "simple_expansion",
  "expansion",
  "array_expansion",
  "command_substitution",
  "process_substitution",
]);

/** True when the argument node's subtree contains a runtime shell expansion. */
function nodeHasRuntimeExpansion(n: TSNode): boolean {
  if (RUNTIME_EXPANSION_TYPES.has(n.type)) return true;
  for (let i = 0; i < n.childCount; i++) {
    const c = n.child(i);
    if (c && nodeHasRuntimeExpansion(c)) return true;
  }
  return false;
}

/**
 * A multi-line LITERAL argument — a script or data body (`node -e '…'`,
 * `python3 -c "…"`), never a path: it contains newlines but no runtime
 * expansion anywhere in its AST subtree, so its text is fixed at parse
 * time. Text-level checks can't tell a JS template literal's backticks from
 * a shell backtick substitution — the AST can. A multi-line argument that
 * DOES expand at runtime stays opaque (fail closed).
 */
function isMultiLineLiteralArg(text: string, node: TSNode): boolean {
  return text.includes("\n") && !nodeHasRuntimeExpansion(node);
}

/** Text-level variant for redirect targets (no node available): a newline
 *  with no `$`/backtick/backslash in the text is a literal script/data body.
 *  Any expansion char keeps the opaque classification (fail closed). */
function isMultiLineLiteralText(text: string): boolean {
  return text.includes("\n") && !/[`$\\]/.test(text);
}

/** A cwd-local bare name: no path separator, ~, expansion, or backtick, and not
 *  a lone `.`/`..` (`..` can escape the cwd). Globs of bare names (*.txt) count. */
function isBareName(w: string): boolean {
  if (w === "." || w === "..") return false;
  return !/[\/$`~]/.test(w);
}

/**
 * True when an absolute directory is under (or is) the session cwd or an
 * allowed read/write root — lexically, or through realpath (symlinked
 * roots). A non-existent directory fails closed.
 */
function underKnownRoots(p: string, cwd: string): boolean {
  const roots = [...allowedReadPaths, ...allowedWritePaths, path.resolve(cwd)];
  const under = (x: string) => roots.some(r => x === r || x.startsWith(r + "/"));
  if (under(p)) return true;
  try {
    return under(fs.realpathSync(p));
  } catch {
    return false;
  }
}

/**
 * True when an absolute in-list token can only expand inside the cwd or a
 * static allowed path root. Glob chars (*, ?, [) never cross `/`, so the
 * static (non-glob) prefix pins the root every expansion value lives under.
 * Trust is then verified against the REAL filesystem, not just the spelling:
 * a value under a trusted prefix can still escape through a symlink
 * (e.g. /tmp/evil -> /etc), so literal tokens are realpath'ed and glob tokens
 * are expanded (fs.globSync) with every match realpath'ed; anything resolving
 * outside the roots keeps the marker (fail closed).
 * Quoted tokens are unquoted first; a double-quoted expansion, any `..`
 * segment, or a prefix that is neither lexically nor (via realpath) under a
 * root keeps the marker.
 */
function isAllowedRootToken(w: string, cwd: string): boolean {
  let t = w;
  const q = w.match(/^(['"])(.*)\1$/);
  if (q) {
    if (q[1] === '"' && /[$`]/.test(q[2])) return false; // expansion inside double quotes
    t = q[2];
  } else if (/[$`]/.test(t)) {
    return false;
  }
  if (!t.startsWith("/") || t === "/" || /(^|\/)\.\.(\/|$)/.test(t)) return false;
  const globIdx = t.search(/[*?[[]/);
  const prefix = globIdx === -1 ? t : t.slice(0, globIdx);
  const base = prefix.endsWith("/") ? prefix.slice(0, -1) : path.dirname(prefix);
  if (base === "/" || base === "") return false; // the root itself would allow everything
  // Prefix under a root — lexically, or through realpath (symlinked roots).
  if (!underKnownRoots(base, cwd)) return false;
  const roots = [...allowedReadPaths, ...allowedWritePaths, path.resolve(cwd)];
  const underRoot = (p: string) => roots.some(r => p === r || p.startsWith(r + "/"));
  if (globIdx === -1) {
    // Literal path: verify where it really points.
    try {
      return underRoot(fs.realpathSync(t));
    } catch {
      return true; // doesn't exist yet — the literal stays under the root by construction
    }
  }
  // Glob: expand now and verify every match. (An unmatched pattern passes its
  // literal text through at runtime, which stays under the pinned prefix.)
  try {
    const pattern = t.endsWith("/") ? t.slice(0, -1) : t;
    const matches = fs.globSync(pattern);
    if (matches.length > 4096) return false; // too many to verify — fail closed
    for (const m of matches) {
      if (!underRoot(fs.realpathSync(m))) return false; // symlink escape
    }
  } catch {
    return false; // can't verify (bad pattern, unreadable dir) — fail closed
  }
  return true;
}

/**
 * The in-list words of the NEAREST enclosing for loop that binds `varName`,
 * or null when no such loop exists (a loop binding a different variable is
 * skipped — the reference may bind an outer loop).
 */
function enclosingLoopInList(node: TSNode, varName: string): string[] | null {
  let cur = node.parent;
  while (cur) {
    if (cur.type === "for_statement") {
      let loopVar: string | null = null;
      const inList: string[] = [];
      let afterIn = false;
      for (let i = 0; i < cur.childCount; i++) {
        const c = cur.child(i);
        if (!c) continue;
        if (c.type === "in") { afterIn = true; continue; }
        if (!afterIn) { if (c.type === "variable_name") loopVar = c.text; continue; }
        if (c.type === ";" || c.type === "do_group") break;
        inList.push(c.text);
      }
      if (loopVar === varName) return inList.length > 0 ? inList : null;
      // a different (outer/nested) loop variable — keep walking up
    }
    cur = cur.parent;
  }
  return null;
}

/**
 * For a `cd` command whose single target is a loop-bound variable reference
 * (`cd $d` / `cd ${d}` where `d` is bound by an enclosing for loop), return
 * the loop's in-list words so resolveCdTarget can thread a known local base.
 * Null in every other case: not a cd, extra/rejected args (bash would error —
 * no cd runs), `cd -` (OLDPWD), non-variable or substitution targets (the
 * tokenizer may split those anyway), or no binding loop.
 */
function extractLoopCdBinding(n: TSNode): string[] | null {
  if (n.type !== "command") return null;
  // The first child is a command_name node (wrapping the word); arguments
  // are WORD_TYPES — `cd $d` parses $d as simple_expansion, not word.
  const words: string[] = [];
  for (let i = 0; i < n.childCount; i++) {
    const c = n.child(i);
    if (!c) continue;
    if (c.type === "command_name" || WORD_TYPES.has(c.type)) words.push(c.text);
  }
  let ti = 0;
  while (ti < words.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(words[ti])) ti++; // env-assign prefix
  if (words[ti] !== "cd") return null;
  let target: string | null = null;
  let targetCount = 0;
  for (const w of words.slice(ti + 1)) {
    if (w === "--" || w === "-L" || w === "-P") continue;
    if (w !== "-" && w.startsWith("-")) return null; // unexpected flag → cd errors
    target = w;
    targetCount++;
  }
  if (targetCount !== 1 || !target) return null;
  if (target === "-") return null; // OLDPWD — not trackable
  const m = target.match(/^\$(\w+)$/) ?? target.match(/^\$\{(\w+)\}$/);
  if (!m) return null;
  return enclosingLoopInList(n, m[1]);
}

/**
 * A loop-variable reference whose expansions are statically safe paths:
 * `$d` (bare) or `$d/rest` / `${d}/rest` where `rest` is bare — no
 * expansion, ~, backslash, `..` segment, or absolute form — so the value
 * stays where the loop's in-list pins it (cwd-local or an allowed root).
 */
function loopBoundRef(val: string): { name: string; rest: string | null } | null {
  let m = val.match(/^\$(\w+)$/) || val.match(/^\$\{(\w+)\}$/);
  if (m) return { name: m[1], rest: null };
  m = val.match(/^\$(\w+)\/(.+)$/) || val.match(/^\$\{(\w+)\}\/(.+)$/);
  if (m && !/[$`~\\]/.test(m[2]) && !/(^|\/)\.\.(\/|$)/.test(m[2])) {
    return { name: m[1], rest: m[2] };
  }
  return null;
}

/**
 * An opaque expansion in path position, classified for the analysis layer's
 * resolution (var-resolution). Null when the token is not opaque or is
 * statically exempt (a loop-bound reference whose in-list is pinned to known
 * roots — base-independent, every expansion needs no path approval).
 *
 * Kinds (the parser only proves what the token text + loop binding show):
 *  - "pinned": `prefix/$var` (or `${var}`, with an expansion-free tail such
 *    as `prefix/$var/*.ts`) where the in-list is bounded — every expansion
 *    lands under prefixDir (see isBoundedInListWord).
 *  - "cwdLocal": a loop-bound reference whose in-list is cwd-local (bare
 *    names, globs, `$(find …)` words) — the value is relative to the
 *    RUNTIME cwd; the resolver must bound it against the tracked effective
 *    base (the old blanket exemption skipped that check entirely — the
 *    `cd /etc && for f in a b; do cat $f; done` hole).
 *  - "loopList": a loop-bound reference whose in-list is all LITERAL paths
 *    (no expansion, no glob, no `..`) — the value is exactly one of the
 *    words; the resolver names the concrete words (a `for d in /a /b` over
 *    outside dirs is two concrete outside locations, not an unresolvable
 *    sentinel).
 *  - "opaque": everything else — the resolver may still bind it through the
 *    command's own assignments (`f=x; cat $f`).
 *
 * Note: single-quoted literal arguments (`cat '$X'`) lose their literalness
 * at the text level and are over-flagged — the safe direction.
 */
export interface OpaqueRef {
  /** Dequoted shell text of the token ($f, ${d:-x}, $f/sub, $(find .)…). */
  raw: string;
  /** Index of the segment the token belongs to (-1: unidentifiable). */
  segIdx: number;
  /** segIdx -1: segments whose text contains the token's node text; the
   * resolver takes the worst case across them. */
  candidates?: number[];
  kind: "opaque" | "cwdLocal" | "pinned" | "loopList";
  /** kind "pinned": the directory every expansion lands under (realpath'd). */
  prefixDir?: string;
  /** kind "loopList": the literal in-list words (one expansion each). */
  words?: string[];
}

/**
 * A trailing loop reference: `staticPrefix/$var`, `staticPrefix/${var}`, or
 * the same with a tail (`staticPrefix/$var/*.ts`): one reference, everything
 * before it static. The tail (when present) must have no `$`, backtick, or
 * backslash (runtime expansion / escape) and no `..` segment — glob chars
 * and literal segments never cross `/`, so every expansion still lands under
 * the prefix.
 */
function trailingLoopRef(val: string): { prefix: string; name: string } | null {
  const m = val.match(/^(.+)\/\$(\w+)(?:\/(.+))?$/)
    ?? val.match(/^(.+)\/\$\{(\w+)\}(?:\/(.+))?$/);
  if (!m) return null;
  if (m[3] !== undefined && (/[\\`$]/.test(m[3]) || /(^|\/)\.\.(\/|$)/.test(m[3]))) {
    return null; // tail could escape the pin — keep the token opaque
  }
  return { prefix: m[1], name: m[2] };
}

/**
 * An in-list word whose expansion stays under a pinned prefix: non-empty, no
 * expansion (a $-word could name anything), no `..` segment. Globs and
 * embedded `/` stay under the prefix (a glob never crosses `/`; an embedded
 * `/` only goes deeper).
 */
function isBoundedInListWord(w: string): boolean {
  let t = w;
  const q = w.match(/^(['"])(.*)\1$/);
  if (q) {
    if (q[1] === '"' && /[$`]/.test(q[2])) return false; // expansion inside double quotes
    t = q[2];
  }
  if (!t) return false;
  if (/[`$]/.test(t)) return false;
  if (/(^|\/)\.\.(\/|$)/.test(t)) return false;
  return true;
}

/** Strip one outer quote pair (the resolver re-strips; the word must not
 *  carry an expansion inside double quotes). */
function dequoteInListWord(w: string): string | null {
  const q = w.match(/^(['"])(.*)\1$/);
  if (q) {
    if (q[1] === '"' && /[$`]/.test(q[2])) return null;
    return q[2];
  }
  return w;
}

/**
 * An in-list word that IS its own location: a literal path (absolute, ~/, or
 * base-relative) with no expansion, no glob, no `..` segment — a loop over
 * such words visits exactly these paths (the 2026-08-31 log case: `for d in
 * ~/.var/… ~/.local/share/joplin …; do … "$d" …` stopped as "runtime
 * location unresolvable" although every word was right there). Globs stay
 * out: their expansion set is filesystem-dependent (the pinned proof and the
 * allowed-root proof already cover the safe glob shapes).
 */
function isLiteralInListWord(w: string): boolean {
  const t = dequoteInListWord(w);
  if (!t) return false;
  if (/[`$*?[[]/.test(t)) return false;
  if (/(^|\/)\.\.(\/|$)/.test(t)) return false;
  return true;
}

/**
 * Resolve a static prefix that pins the token to a known root: absolute
 * (or ~/), no expansion/glob/`..`, and the prefix directory under the cwd or
 * an allowed read/write root (realpath'd). Returns the resolved directory,
 * or null when the prefix cannot prove containment.
 */
function resolvePinPrefix(prefix: string, cwd: string): string | null {
  if (!prefix) return null;
  if (/[\\`*?\[\]$]/.test(prefix)) return null;
  if (/(^|\/)\.\.(\/|$)/.test(prefix)) return null;
  const t = expandTilde(prefix);
  if (!path.isAbsolute(t)) return null;
  const dir = t.endsWith("/") ? t.slice(0, -1) : t;
  if (!dir || dir === "/") return null;
  if (!underKnownRoots(dir, cwd)) return null;
  return resolvePathReal(dir, os.homedir());
}

/** Segment indices whose text contains the token's node text (worst-case
 * bases for a token whose own segment is unidentifiable, e.g. a command
 * substitution inside a command argument). */
function containmentCandidates(nodeText: string, segments: BashSegment[]): number[] | undefined {
  const t = nodeText.trim();
  if (!t) return undefined;
  const c: number[] = [];
  for (let i = 0; i < segments.length; i++) {
    if (segments[i].text.includes(t)) c.push(i);
  }
  return c.length ? c : undefined;
}

/** Classify an opaque expansion in path position (see OpaqueRef). */
function opaqueRef(node: TSNode, arg: string, cwd: string, segIdx: number, segments: BashSegment[]): OpaqueRef | null {
  const val = flagValue(arg);
  if (!isOpaqueValue(val)) return null;
  const cands = segIdx < 0 ? containmentCandidates(node.text, segments) : undefined;
  const mk = (kind: OpaqueRef["kind"], prefixDir?: string, words?: string[]): OpaqueRef => {
    const r: OpaqueRef = { raw: val, segIdx, kind };
    if (prefixDir) r.prefixDir = prefixDir;
    if (words) r.words = words;
    if (cands) r.candidates = cands;
    return r;
  };
  // Leading form: $var or $var/rest, bound by an enclosing loop.
  const ref = loopBoundRef(val);
  if (ref !== null) {
    const inList = enclosingLoopInList(node, ref.name);
    if (inList !== null) {
      // Base-independent: every in-list word is pinned to a known root
      // (absolute, realpath/glob-verified) — no base needed at all.
      if (inList.every(w => !isBareName(w) && isAllowedRootToken(w, cwd))) return null;
      // Base-dependent: bare names and cwd-local finds — the values are
      // relative to the runtime cwd; the resolver bounds them against the
      // tracked effective base.
      if (inList.every(w => isBareName(w) || isCwdLocalWord(w))) {
        return mk("cwdLocal");
      }
      // Literal-path in-list (absolute, ~/, or base-relative, no expansion,
      // no glob, no ..): the value is exactly one of the words — concrete
      // locations the resolver can name.
      if (inList.every(isLiteralInListWord)) {
        return mk("loopList", undefined, inList);
      }
      // Mixed (bare + root-pinned) or expanded in-list — the value set spans
      // bases — opaque (the resolver may still bind a prefixed form below).
    }
  }
  // Trailing form: static prefix + loop-bound reference (+ expansion-free
  // tail) — pinned.
  const trail = trailingLoopRef(val);
  if (trail !== null) {
    const inList = enclosingLoopInList(node, trail.name);
    if (inList !== null && inList.every(isBoundedInListWord)) {
      const prefixDir = resolvePinPrefix(trail.prefix, cwd);
      if (prefixDir) return mk("pinned", prefixDir);
    }
  }
  return mk("opaque");
}

/** Check if a token looks like a filesystem path worth resolving. */
function isPathCandidate(token: string): boolean {
  if (!token) return false;
  if (HOME_TOKEN_RE.test(token)) return true; // $HOME/… / ${HOME}/… — expanded below
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
  /** Operator preceding this segment in the flat list ("&&", "||", ";", "&"). */
  precedingOp?: string;
  /** Segment runs in a background subshell (its cd does not persist into later segments). */
  backgrounded?: boolean;
  /**
   * Depth of enclosing `( )` subshell nodes (0 = top level). A subshell runs
   * in a child process: a cd inside it sets only the subshell's local base,
   * never the outer one. trackEffectiveCwd scopes its base stack by this
   * depth so inner cds don't leak into (or poison) the outer base.
   */
  subshellDepth?: number;
  /**
   * For a `cd $var` whose target is the variable of an enclosing for loop:
   * the loop's in-list words. resolveCdTarget uses them to thread a known
   * local base (single-candidate) instead of freezing to unknown.
   */
  loopCdInList?: string[];
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
 *
 * Side effects (document order, same walk that emits the segments):
 *  - `assignments` — top-level standalone assignments (`f=x`), with `at` =
 *    the segment count at the assignment's position (its visibility bound for
 *    var-resolution). Env-prefix and subshell-local assignments never reach
 *    the intercept (they are command children / inside a subshell node).
 *  - `segMap` — node id → segment index, so parseCommand can tell which
 *    segment an opaque token belongs to (var-resolution resolves it against
 *    that segment's visible assignments and effective cwd).
 */
function extractSegmentsFromNode(
  node: TSNode,
  assignments: ShellAssignment[],
  segMap: Map<number, number>,
): BashSegment[] {
  const segments: BashSegment[] = [];

  // Document-order slot: the operator seen so far belongs to the NEXT segment
  // pushed (operators and segments strictly interleave in walk order; a
  // segment push always consumes the slot, an operator always sets it).
  let pendingOp: string | null = null;
  // Depth of enclosing `( )` subshells during the walk (see BashSegment.subshellDepth).
  let subshellDepth = 0;
  const pushSeg = (seg: BashSegment): void => {
    if (pendingOp) seg.precedingOp = pendingOp;
    pendingOp = null;
    if (subshellDepth > 0) seg.subshellDepth = subshellDepth;
    segments.push(seg);
  };

  // ── Type handlers ──

  type Handler = (n: TSNode) => void;

  /** Recurse into all children (default handler). */
  const recurseAll: Handler = (n) => {
    for (let i = 0; i < n.childCount; i++) {
      const child = n.child(i);
      if (child) walk(child);
    }
  };

  /**
   * Split on operator nodes (program, list).
   * tree-sitter-bash 0.25 shapes: `a && b` → list[a, &&, b]; `a; b` / `a & b`
   * → program-level sibling operators. An `&` backgrounds its PRECEDING
   * sibling (which runs in a subshell) — mark those segments retroactively.
   */
  const splitOnOp: Handler = (n) => {
    let prevStart = 0; // index where the previous sibling's segments begin
    for (let i = 0; i < n.childCount; i++) {
      const child = n.child(i);
      if (!child) continue;
      if (OPERATOR_TYPES.has(child.type)) {
        if (child.type === "&" && segments.length > prevStart) {
          for (let j = prevStart; j < segments.length; j++) segments[j].backgrounded = true;
        }
        pendingOp = child.type; // "&&" | "||" | ";" | "&" — precedes the next segment
        prevStart = segments.length;
        continue;
      }
      walk(child);
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
      pushSeg({ text: cmdTexts.join(" | "), ops: [...ops], hasSubshell: segHasSubshell, subshellTexts: extractSubshellInnerTexts(n) });
      const idx = segments.length - 1;
      for (let i = 0; i < n.childCount; i++) {
        const child = n.child(i);
        if (child && child.type === "command") segMap.set(child.id, idx);
      }
      // Compound children (folded redirected_statements) recorded their inner
      // commands during the walk — the pop+push above keeps their index valid.
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
      pushSeg({ text: cmdTexts.join(" "), ops: [...ops], hasSubshell: segHasSubshell, subshellTexts: extractSubshellInnerTexts(n) });
      const idx = segments.length - 1;
      for (let i = 0; i < n.childCount; i++) {
        const child = n.child(i);
        if (child && (child.type === "command" || child.type === "file_redirect")) segMap.set(child.id, idx);
      }
    } else if (hasCompoundChild && redirectTexts.length > 0) {
      if (segments.length > 0) {
        // Propagate redirects to the last segment so hasWriteRedirect can detect them
        segments[segments.length - 1].text += " " + redirectTexts.join(" ");
        for (const op of ops) segments[segments.length - 1].ops.push(op);
        const idx = segments.length - 1;
        for (let i = 0; i < n.childCount; i++) {
          const child = n.child(i);
          if (child && child.type === "file_redirect") segMap.set(child.id, idx);
        }
      } else {
        // Compound child walk produced no segments (e.g. empty subshell "() > out").
        // Create a redirect-only segment so write-redirect detection isn't silently lost.
        pushSeg({ text: redirectTexts.join(" "), ops: [...ops], hasSubshell: false, subshellTexts: extractSubshellInnerTexts(n) });
        const idx = segments.length - 1;
        for (let i = 0; i < n.childCount; i++) {
          const child = n.child(i);
          if (child && child.type === "file_redirect") segMap.set(child.id, idx);
        }
      }
    }
  };

  /** Leaf: single command or redirect. */
  const handleLeaf: Handler = (n) => {
    const ops = detectOpsInNode(n);
    const seg: BashSegment = { text: n.text.trim(), ops, hasSubshell: nodeHasSubshell(n), subshellTexts: extractSubshellInnerTexts(n) };
    if (n.type === "command") {
      const inList = extractLoopCdBinding(n);
      if (inList) seg.loopCdInList = inList;
    }
    pushSeg(seg);
    segMap.set(n.id, segments.length - 1);
  };



  // ── Handler map ──

  const handlers: Map<string, Handler> = new Map([
    ["program", splitOnOp],
    ["list", splitOnOp],
    ["pipeline", handlePipeline],
    ["redirected_statement", handleRedirectedStatement],
    ["command", handleLeaf],
    ["file_redirect", handleLeaf],
  ]);

  // ── Walk ──

  function walk(n: TSNode): void {
    if (SKIP_TYPES.has(n.type)) return;

    // `( )` subshell: runs in a child process — every segment inside carries
    // the extra depth so cd threading stays scoped to the subshell.
    if (n.type === "subshell") {
      subshellDepth++;
      recurseAll(n);
      subshellDepth--;
      return;
    }

    // Standalone top-level assignment: not a segment, but data for the
    // resolver (f=x; cat $f). Qualifies in statement position: a direct
    // program/list child, or inside a declaration command (export/readonly/
    // declare) at statement position — an env prefix (command child) or a
    // subshell-local assignment must not leak into the parent scope — and it
    // must not be backgrounded (`f=a &` sets nothing in the parent shell).
    if (n.type === "variable_assignment" && subshellDepth === 0) {
      // Statement container (program/list) + the slot node that occupies the
      // statement slot (the assignment itself, or its declaration_command
      // wrapper for `export f=x`).
      const p = n.parent;
      let stmtParent: TSNode | null = null;
      let slot: TSNode = n;
      if (p && (p.type === "program" || p.type === "list")) {
        stmtParent = p;
      } else if (p && p.type === "declaration_command") {
        slot = p;
        const gp = p.parent;
        if (gp && (gp.type === "program" || gp.type === "list")) stmtParent = gp;
      }
      if (stmtParent) {
        for (let i = 0; i < stmtParent.childCount; i++) {
          if (stmtParent.child(i)?.id !== slot.id) continue;
          if (stmtParent.child(i + 1)?.type !== "&") {
            const m = n.text.match(/^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/s);
            if (m) assignments.push({ name: m[1], value: m[2], at: segments.length });
          }
          break;
        }
      }
      // Descend anyway: the value may embed a command substitution whose
      // inner commands become segments (D10: out=$(npx …) is gated like a
      // top-level run form).
      recurseAll(n);
      return;
    }

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
      // The inner content could be a command, pipeline, list, or a
      // redirected_statement (tree-sitter wraps bodies containing redirects:
      // `$(wc -c < file)` → redirected_statement > command + file_redirect).
      // Without this the body is invisible → fail-closed HIGH on every
      // read-only substitution that feeds its command from a file.
      for (let i = 0; i < n.childCount; i++) {
        const child = n.child(i);
        if (child && (child.type === "command" || child.type === "pipeline" || child.type === "list" || child.type === "redirected_statement")) {
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

/**
 * Check if an argument to `sed` looks like a pattern expression
 * (address, range, or substitution) rather than a file path.
 *
 * Sed patterns start with a delimiter (typically `/`) and have:
 * - A matching closing delimiter
 * - Optionally followed by a single-letter command (p, d, q, w, etc.)
 * - Or a range expression: /pat1/,/pat2/action
 *
 * Real file paths have multi-character directory/file segments.
 */
function isSedPatternArg(arg: string): boolean {
  // Sed substitution: s/pattern/replacement/flags
  if (arg.startsWith("s") && arg.length > 2 && arg[1] !== "/" && !arg[1].match(/[a-zA-Z0-9]/)) {
    return true;
  }

  if (!arg.startsWith("/")) return false;

  // Range pattern: /pat1/,/pat2/action, /pat1/,/pat2/, or /pat1/,+NNN
  // (GNU sed line-offset range end: /pat/,+120p). A real path containing
  // ",/" or with a segment starting ",+digit" is unheard of.
  if (/,,\//.test(arg) || /\/,\+\d/.test(arg)) return true;

  // Single address: /pattern/ or /pattern/p
  // Find the last `/` — if what follows is a short letter sequence (sed command)
  // or empty, it's a pattern, not a path.
  const lastSlashIdx = arg.lastIndexOf("/");
  if (lastSlashIdx > 0) {
    const afterLastSlash = arg.slice(lastSlashIdx + 1);
    // Empty → /pattern/ (address with no explicit command, defaults to print)
    if (afterLastSlash.length === 0) return true;
    // 1-3 letters → /pattern/p, /pattern/d, /pattern/gp, etc.
    if (afterLastSlash.length <= 3 && /^[a-zA-Z]+$/.test(afterLastSlash)) return true;
    // Line offset → /pattern/+5, /pattern/+5p, /pattern/+120p (GNU sed)
    if (/^\+\d+[a-zA-Z]{0,3}$/.test(afterLastSlash)) return true;
  }

  return false;
}

/**
 * Indices of `sed` script arguments: the first non-flag argument (sed's
 * grammar is `sed [flags] script [files…]`) and the value consumed by
 * -e / --expression. Flag tokens start with `-` and carry any value inline
 * (-i, -i.bak, --in-place=suffix). A bare literal path in script position
 * is still returned — the caller keeps it path-checked (fail closed).
 */
function sedScriptArgIndices(args: string[]): Set<number> {
  const idxs = new Set<number>();
  let scriptSeen = false;
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "-e" || a === "--expression") {
      if (i + 1 < args.length) idxs.add(i + 1);
      continue;
    }
    if (a.startsWith("--expression=")) continue; // self-contained flag
    if (a.startsWith("-")) continue; // flag (value inline, if any)
    if (!scriptSeen) { scriptSeen = true; idxs.add(i); }
  }
  return idxs;
}

/**
 * Indices of `grep` PATTERN arguments: the first non-flag argument (grep's
 * grammar is `grep [flags] PATTERN [files…]`) and the values consumed by
 * -e / --regexp / --regex. Unlike sed's script position (which can also be
 * a script FILE), grep's PATTERN position is never a file — the 2026-08-26
 * log case `grep -vE "//|\*" …` resolved the pattern as an absolute path
 * (a leading `//` is a network-prefix absolute) into a phantom root child
 * ("outside /"). -f / --file switches the grammar: its value IS a file
 * (pattern file — stays path-checked), and every later non-flag argument
 * is a plain file.
 */
function grepPatternArgIndices(args: string[]): Set<number> {
  const idxs = new Set<number>();
  let patternSeen = false;
  let filePatterns = false;
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "-e" || a === "--regexp" || a === "--regex") {
      if (i + 1 < args.length) idxs.add(i + 1);
      continue;
    }
    if (a.startsWith("--regexp=") || a.startsWith("--regex=")) continue;
    if (a === "-f" || a === "--file") {
      filePatterns = true;
      if (i + 1 < args.length) i++; // the pattern FILE — keep path-checked
      continue;
    }
    if (a === "--file=" || (a.startsWith("-f") && a.length > 2 && !a.startsWith("--"))) {
      filePatterns = true; // -fFILE inline, or --file= (stdin)
      continue;
    }
    if (a.startsWith("-") && a !== "-") {
      // Flag cluster (-vE, -ef, …): an f whose value is the next argument
      // (-ef FILE) makes it a pattern file; -fe consumes the rest of the
      // cluster as that value. Either way: later args are files, not patterns.
      if (a.endsWith("f")) { filePatterns = true; if (i + 1 < args.length) i++; }
      else if (a.includes("f")) filePatterns = true;
      continue;
    }
    if (!patternSeen && !filePatterns) { patternSeen = true; idxs.add(i); }
  }
  return idxs;
}

/**
 * Check if an argument to `awk` looks like an inline script rather than a file path.
 *
 * Awk scripts are typically the first non-flag argument. When they start with `/`,
 * they're regex address patterns like `/pattern/ {action}`. These get mistaken for
 * absolute paths because they begin with `/`.
 *
 * Detection: awk scripts that start with `/` contain awk action syntax:
 * spaces, braces { }, $NF, $0, print, etc. — characters never found in bare paths.
 */
function isAwkScriptArg(arg: string): boolean {
  // Rule blocks or function definitions anchored at the start of the arg —
  // `BEGIN {…}`, `END {…}`, `function f(…) {…}` — are program text, not paths
  // (the log case: `awk 'BEGIN{t=""} /re/{…} END{print t}' f`).
  if (/^(?:BEGIN|END)\s*[{(]/.test(arg) || /^function\s+\w+\s*\(/.test(arg)) return true;
  // Non-path tokens with an action block: paths never contain unquoted
  // braces here, and a token without a path-like prefix is not a candidate.
  if (!arg.startsWith("/") && arg.includes("{") && arg.includes("}")) return true;
  if (!arg.startsWith("/")) return false;
  // Awk scripts contain awk-specific syntax that never appears in file paths
  return /[\s{}\(\)\$\^\*\+\?\|\\!=;]/.test(arg) || /,\//.test(arg);
}

/**
 * A path-like literal inside SCRIPT BODY text (a heredoc body, a
 * multi-line literal argument — `python3 - << 'EOF' … open('/var/lib/…')
 * … EOF`). The shell never touches these paths, but the script does, and
 * the floor must see them (2026-08-31 D13 mining: the heredoc's open()
 * target was invisible to the static path set, so only the judge saw it).
 *
 * Shape: ~ or / start, ≥2 segments (one-segment tokens are almost always
 * regex/division noise), word chars only. The lookbehind rejects URL tails
 * (the second slash of http://…) and paths glued to a word char.
 */
const BODY_PATH_RE = /(?<![\w:/.-])(?:~\/)?\/[\w.-]+(?:\/[\w.-]+)+/g;

/** Scan script body text for path-like literals, resolved like any other
 *  extracted path (SAFE_SYSTEM_PATHS filter + dedup apply downstream). */
function bodyPaths(text: string, cwd: string, out: string[]): void {
  for (const m of text.matchAll(BODY_PATH_RE)) {
    out.push(resolvePathReal(expandTilde(m[0]), cwd));
  }
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
 * Single parse that extracts segments, paths, opaque refs, and assignments.
 */
export async function parseCommand(
  command: string,
  cwd: string,
): Promise<{
  segments: BashSegment[];
  paths: string[];
  opaque: OpaqueRef[];
  assignments: ShellAssignment[];
  hasParseError: boolean;
}> {
  const parser = await getParser();
  const tree = parser.parse(command);
  if (!tree) return { segments: [], paths: [], opaque: [], assignments: [], hasParseError: false };

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

    // Extract segments (includes per-segment hasSubshell); the walk also
    // records standalone assignments and the node→segment index map.
    const assignments: ShellAssignment[] = [];
    const segMap = new Map<number, number>();
    const segments = extractSegmentsFromNode(tree.rootNode, assignments, segMap);

    // Extract paths and opaque refs from command nodes
    const commandNodes = collectCommandNodes(tree.rootNode);
    const allPaths: string[] = [];
    const opaque: OpaqueRef[] = [];

    for (const cmdNode of commandNodes) {
      const cmdName = getCommandName(cmdNode);
      const args = extractCommandArgPairs(cmdNode);

      if (cmdName && pathAwareCommands.has(cmdName)) {
        // Sed: the script argument is not a file (sed [flags] script [files…])
        // — the `sed -n "$(grep … | cut …),+12p" f` line-range idiom must not
        // produce <unresolved-var>. File-position args keep the opaque marker.
        const sedScripts = cmdName === "sed" ? sedScriptArgIndices(args.map(a => a.text)) : null;
        // Grep: the PATTERN position is data, never a file (see
        // grepPatternArgIndices) — skipping it also keeps pattern-position
        // vars ($re in `grep -vE "$re" f`) out of the opaque ref set, where
        // they would floor-stop the command.
        const grepPatterns = cmdName === "grep" ? grepPatternArgIndices(args.map(a => a.text)) : null;
        for (let ai = 0; ai < args.length; ai++) {
          const { text: arg, node: argNode } = args[ai];
          // A multi-line LITERAL argument is a script/data body (`node -e '…'`),
          // not a path: classifying it would mint an opaque ref whose "token"
          // is the whole script, bloating the prompt and the decision log.
          // The shell never touches body paths — but the script does: scan
          // them into the path set (fail-closed, like every other path).
          if (isMultiLineLiteralArg(arg, argNode)) {
            bodyPaths(arg, cwd, allPaths);
            continue;
          }
          // Skip inline script/pattern expressions that look like paths but aren't:
          //   sed: script position, /pattern/p, /describe(...)/,/^});/p, s/foo/bar/
          //   awk: /pattern/ {print}, /foo/ {action}
          //   grep: PATTERN position, -e PATTERN
          if ((cmdName === "sed" && (
              (sedScripts !== null && sedScripts.has(ai) && !/^(?:\/|\.\/|~\/)/.test(arg)) ||
              isSedPatternArg(arg)
            )) ||
              (cmdName === "awk" && isAwkScriptArg(arg)) ||
              (cmdName === "grep" && grepPatterns !== null && grepPatterns.has(ai))) {
            continue;
          }

          // Opaque expansion in path position (cat $X, -f=$X, cat ./$Y) →
          // classified OpaqueRef, resolved by the analysis layer against the
          // command's assignments and the tracked effective cwd.
          const ref = opaqueRef(cmdNode, arg, cwd, segMap.get(cmdNode.id) ?? -1, segments);
          if (ref) opaque.push(ref);

          if (isPathCandidate(arg)) {
            // For flag values (--file=/path), resolve the value, not the flag itself.
            // isPathCandidate already accepts these; match its extraction logic.
            const resolveArg = arg.startsWith("-") && arg.includes("=")
              ? arg.slice(arg.indexOf("=") + 1)
              : arg;
            allPaths.push(resolvePathReal(expandHomeToken(expandTilde(resolveArg)), cwd));
          }
        }
      }

      // `sort -o FILE` / `--output=FILE` writes/truncates FILE — the target may
      // not look like a path (bare filename: `sort -o package.json x`), so it
      // would escape outside-cwd checks. Extract it explicitly.
      if (cmdName === "sort") {
        for (let i = 0; i < args.length; i++) {
          const arg = args[i].text;
          let target: string | null = null;
          if (arg === "-o" || arg === "--output") {
            target = args[i + 1]?.text ?? null;
          } else if (arg.startsWith("--output=")) {
            target = arg.slice("--output=".length);
          } else if (/^-[a-zA-Z]*o/.test(arg)) {
            // Short-option cluster: the first `o` consumes the rest of the
            // token as its argument (-ox → x); if it's the last char, the
            // argument is the next token (-ro FILE → FILE).
            const oIdx = arg.indexOf("o");
            target = oIdx === arg.length - 1 ? (args[i + 1]?.text ?? null) : arg.slice(oIdx + 1);
          }
          // `-` means stdout; skip it and bare flags (e.g. `sort -o -k 1`).
          if (target && target !== "-" && !target.startsWith("-")) {
            const ref = opaqueRef(cmdNode, target, cwd, segMap.get(cmdNode.id) ?? -1, segments);
            if (ref) opaque.push(ref);
            else allPaths.push(resolvePathReal(expandHomeToken(expandTilde(target)), cwd));
          }
        }
      }
    }

    // Script-body paths from heredocs (`python3 - << 'EOF' …`): the body is
    // opaque to the shell (SKIP_TYPES), but the script it feeds touches real
    // files — extract the path-like literals (fail-closed).
    const collectHeredocBodies = (node: TSNode): void => {
      if (node.type === "heredoc_body") {
        bodyPaths(node.text, cwd, allPaths);
        return;
      }
      for (let i = 0; i < node.childCount; i++) {
        const child = node.child(i);
        if (child) collectHeredocBodies(child);
      }
    };
    collectHeredocBodies(tree.rootNode);

    // Extract redirect paths
    const redirectPaths: string[] = [];
    const extractRedirects = (node: TSNode): void => {
      if (SKIP_TYPES.has(node.type)) return;
      if (node.type === "file_redirect") {
        for (const p of extractRedirectPaths(node)) {
          if (isMultiLineLiteralText(p)) continue; // script/data body, not a path
          if (isPathCandidate(p)) {
            redirectPaths.push(resolvePathReal(expandHomeToken(expandTilde(p)), cwd));
          } else {
            // `> $X` — write destination only knowable at runtime → opaque ref.
            const ref = opaqueRef(node, p, cwd, segMap.get(node.id) ?? -1, segments);
            if (ref) opaque.push(ref);
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

    return { segments, paths, opaque, assignments, hasParseError };
  } finally {
    subshellCache = null;
    tree.delete();
  }
}


