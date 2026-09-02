/**
 * script-payload.ts — the local script a command executes.
 *
 * "Which file does this operation run, and what does it contain" is a
 * property of the command itself (analysis), not of the judge. Two
 * consumers share the identification: the judge packet fences the content
 * as untrusted data (judge/verdict.ts), and the D3/D11 conversions
 * (gate/conversions.ts) convert a manual auto-allow into a judgeable prompt
 * on its presence. One identification, one behavior for both.
 */
import fs from "node:fs";
import path from "node:path";
import type {CommandAnalysis} from "./command-analysis";
import { expandTilde } from "./path-util";
import { tokenizeSegment } from "./tokenizer";
import { isTrustedScriptCommand } from "../config";

/** Extensions whose content is worth reviewing (text scripts). */
const SCRIPT_EXT_RE = /\.(sh|bash|zsh|py|js|mjs|cjs|ts|rb|pl|php|lua|exs?)$/i;
const SCRIPT_INTERPRETERS = new Set([
  "python", "python3", "python2", "py",
  "node", "nodejs",
  "ruby", "perl", "php", "lua",
  "deno", "bun",
  "bash", "sh", "zsh",
]);

/** The identified script: resolved absolute path + full content. */
export interface ExecutedScript {
  /** Resolved absolute path. */
  path: string;
  /** Full script text (read in full — no head cuts, D11). */
  content: string;
}

/**
 * Find the local script a command executes (if any) and read its content.
 * Null for interpreter forms without a resolvable file (`bash -c`,
 * `python3 -`, `python3 -m x`, computed paths), trusted skill scripts,
 * missing or non-regular files.
 */
export function findExecutedScript(
  analysis: CommandAnalysis,
  cwd: string,
): ExecutedScript | null {
  for (let i = 0; i < analysis.segments.length; i++) {
    const seg = analysis.segments[i].trim();
    if (!seg) continue;
    const tokens = tokenizeSegment(seg);
    if (tokens.length < 1) continue;
    // Raw first token (getFirstWord returns the basename — /bin/bash must
    // still count as an interpreter).
    const firstToken = tokens[0].toLowerCase();
    const isInterp = SCRIPT_INTERPRETERS.has(path.basename(firstToken));
    // Direct exec (./scripts/job.sh) or interpreter (python3 job.py).
    if (!isInterp && !(firstToken.includes("/") || firstToken.startsWith("~"))) continue;
    if (isTrustedScriptCommand(seg, analysis.effectiveCwds[i] ?? cwd)) continue;

    const base = analysis.effectiveCwds[i] ?? cwd;
    // First non-flag token that looks like a script file.
    const startIdx = isInterp ? 1 : 0;
    for (let j = startIdx; j < tokens.length; j++) {
      const token = tokens[j];
      if (token.startsWith("-")) continue;
      if (token.includes("$") || token.includes("`")) break; // computed — unresolvable
      if (!SCRIPT_EXT_RE.test(token)) break;
      const resolved = path.resolve(base, expandTilde(token));
      return readScriptFile(resolved);
    }
  }
  return null;
}

function readScriptFile(resolved: string): ExecutedScript | null {
  try {
    const stat = fs.statSync(resolved);
    if (!stat.isFile()) return null;
    // Full read (D11): the payload is write content — trimmed payloads made
    // the judge defer on safe long scripts.
    const content = fs.readFileSync(resolved, "utf-8");
    return { path: resolved, content };
  } catch {
    return null;
  }
}
