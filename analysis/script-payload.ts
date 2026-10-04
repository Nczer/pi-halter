/**
 * script-payload.ts — the local script a command executes.
 *
 * "Which file does this operation run, and what does it contain" is a
 * property of the command itself (analysis), not of the judge. Three
 * consumers share the identification: the judge packet fences the content
 * as untrusted data (judge/verdict.ts), the D3/D11 conversions
 * (gate/conversions.ts) convert a manual auto-allow into a judgeable prompt
 * on its presence, and the D13 paths ledger counts the executed path in
 * the floor's knowledge (executedScriptPaths — the floor saw the script
 * when it identified+trusted it; 2026-09-30 judge.jsonl floorMiss).
 * One identification, one behavior for all.
 */
import fs from "node:fs";
import path from "node:path";
import type {CommandAnalysis} from "./command-analysis";
import { expandTilde } from "./path-util";
import { tokenizeSegment } from "./tokenizer";
import { isTrustedScriptCommand } from "../config";

/** Extensions whose content is worth reviewing (text scripts). */
const SCRIPT_EXT_RE = /\.(sh|bash|zsh|py|pyi|js|mjs|cjs|mts|cts|ts|rb|pl|php|lua|exs?)$/i;
const SCRIPT_INTERPRETERS = new Set([
  "python", "python3", "python2", "py",
  "node", "nodejs",
  "ruby", "perl", "php", "lua",
  "deno", "bun", "tsx", "vite-node",
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
 * The raw identification — the script file ONE segment executes (if any):
 * resolved absolute path. Null for forms without a resolvable file
 * (`bash -c`, computed paths) and non-script tokens. Trusted scripts are
 * NOT excluded here (see scriptFilePathInSegment / executedScriptPaths —
 * each consumer decides what trust means for it).
 */
export function identifyScriptFile(seg: string, base: string): string | null {
  const tokens = tokenizeSegment(seg);
  if (tokens.length < 1) return null;
  // Raw first token (getFirstWord returns the basename — /bin/bash must
  // still count as an interpreter).
  const firstToken = tokens[0].toLowerCase();
  const isInterp = SCRIPT_INTERPRETERS.has(path.basename(firstToken));
  // Direct exec (./scripts/job.sh) or interpreter (python3 job.py).
  if (!isInterp && !(firstToken.includes("/") || firstToken.startsWith("~"))) return null;

  // First non-flag token that looks like a script file.
  const startIdx = isInterp ? 1 : 0;
  for (let j = startIdx; j < tokens.length; j++) {
    const token = tokens[j];
    if (token.startsWith("-")) continue;
    if (token.includes("$") || token.includes("`")) break; // computed — unresolvable
    if (!SCRIPT_EXT_RE.test(token)) {
      // A path-like first token with no script extension is a LAUNCHER, not
      // the payload (`…/node_modules/.bin/vite-node /tmp/x.mts` — 2026-10-04
      // judge.jsonl: no script identified, so the packet carried no content
      // and the judge had nothing to judge). Keep scanning; anywhere else a
      // non-script token ends the scan (`bash -c …`, `python3 -m x`).
      if (j === startIdx && !isInterp) continue;
      break;
    }
    return path.resolve(base, expandTilde(token));
  }
  return null;
}

/**
 * The script file ONE segment executes (if any): resolved absolute path.
 * The per-segment half of findExecutedScript, shared with the D19
 * intent-pass escalation (hasFileScriptOutsideCwd in gate/dspa-gate.ts
 * decides without reading the content). Null for forms without a
 * resolvable file (`bash -c`, computed paths), trusted scripts, and
 * non-script tokens.
 */
export function scriptFilePathInSegment(
  seg: string,
  base: string,
): string | null {
  const p = identifyScriptFile(seg, base);
  return p !== null && !isTrustedScriptCommand(seg, base) ? p : null;
}

/**
 * The scripts the analysis's segments execute (deduped, textual — no
 * existence check): every identified path INCLUDING trusted skill scripts.
 * Trust is a prompt-level exemption (the script is allowed to run
 * unreviewed), not knowledge absence — the floor DID see the path when it
 * identified and trusted the script, and the D13 ledger must say so
 * (2026-09-30 judge.jsonl: the judge reported the trusted script's path
 * and the floor logged floorMisses for it). Kept out of analysis.paths
 * deliberately: the outside-cwd prompt bar is store-based, and trusted
 * scripts are exactly the paths the manual bar allows — adding them to
 * analysis.paths would prompt on every trusted skill invocation.
 */
export function executedScriptPaths(
  analysis: CommandAnalysis,
  cwd: string,
): string[] {
  const out: string[] = [];
  for (let i = 0; i < analysis.segments.length; i++) {
    const seg = analysis.segments[i].trim();
    if (!seg) continue;
    const p = identifyScriptFile(seg, analysis.effectiveCwds[i] ?? cwd);
    if (p !== null && !out.includes(p)) out.push(p);
  }
  return out;
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
    const p = scriptFilePathInSegment(seg, analysis.effectiveCwds[i] ?? cwd);
    if (p) return readScriptFile(p);
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
