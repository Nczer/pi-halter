/**
 * dspa-gate.ts — deterministic hard gate for /dspa auto-allow.
 *
 * The code-enforced floor: an operation may only reach the judge (and be
 * auto-allowed) if it passes every check here. The LLM never has authority
 * over these — a wrong judge verdict can at most produce a prompt, never an
 * auto-allowed operation the gate would have forbidden.
 *
 * Checks (fail closed on any):
 *  - bash: parseable, no unsafe pattern (obfuscation/subshell/redirect — the
 *    same class that always prompts), halter's risk not "dangerous", no
 *    obscured command position (variable indirection — NOT flagged by
 *    halter's own analysis, checked here explicitly), no credential-pattern
 *    paths, no network egress, no paths outside the session base.
 *  - rm carve-out (dspa only): halter always flags rm as dangerous, and
 *    danger patterns always prompt even after Always grants. An rm command
 *    may reach the judge only when every rm target is explicit, not the
 *    working directory itself, and either inside the session base or part
 *    of a create-then-delete set (a path this same command writes via
 *    redirect/tee/touch/mkdir in an earlier segment AND rms). With -r/-R
 *    the target (if it exists) must be a directory or self-written.
 *    Non-rm danger reasons still block. The judge still approves.
 *  - file: inside the session base, no credential-pattern warning.
 *  - mcp: never auto-allowed — the gate has no model of server behavior, so
 *    the judge's word alone is not enough for automatic execution.
 */
import fs from "node:fs";
import path from "node:path";
import type { PromptData } from "./decision-engine";
import type { Store } from "./store";
import { analyzeCommand } from "./analysis/command-analysis";
import { expandTilde } from "./analysis/path-util";
import { resolvePathReal } from "./analysis/path-analysis";
import { findNetworkEgress } from "./config";

export type DspaGateResult = { ok: true } | { ok: false; reason: string };

/**
 * Command position obscured by variable indirection, subshell, or backtick
 * (e.g. `f=rm; $f -rf ./build`). halter's own analysis does not flag this,
 * so the gate checks it explicitly — an obscured command can never be
 * verified for auto-allow.
 */
const OBSCURED_CMD_RE = /^\s*(?:\$\w|\$\(|`)/;

function obscuredHit(segments: string[]): string | null {
  for (const seg of segments) {
    const t = seg.trim();
    if (OBSCURED_CMD_RE.test(t)) return t.split(/\s+/)[0].slice(0, 20);
  }
  return null;
}

/** First egress hit only (gate reason line); URLs truncated to 60 chars. */
function networkHit(command: string, segments: string[]): string | null {
  const { commands, urls } = findNetworkEgress(command, segments);
  return commands[0] ?? urls[0]?.slice(0, 60) ?? null;
}

export async function checkDspaGate(
  pd: PromptData,
  store: Store,
): Promise<DspaGateResult> {
  if (pd.type === "mcp") {
    return { ok: false, reason: "MCP calls are never auto-allowed (server behavior is outside the gate's model)" };
  }

  if (pd.type === "file") {
    if (pd.outsideDir) return { ok: false, reason: `outside base (${pd.outsideDir})` };
    if (pd.warnedRule) return { ok: false, reason: `credential pattern (${pd.warnedRule})` };
    return { ok: true };
  }

  // bash — trust the analysis the decision was made from (single analysis
  // per decision); re-analyze only for hand-constructed prompt data.
  const analysis =
    pd.analysis ??
    (await analyzeCommand(pd.command, pd.cwd, {
      isInsideAllowedDir: (p) => store.isInsideAllowedDir(p, "read"),
    }));
  if (analysis.hasParseError) return { ok: false, reason: "unparseable command" };

  const isInsideBase = (p: string) =>
    p === pd.cwd || p.startsWith(pd.cwd + "/") || store.isInsideAllowedDir(p, "write");

  let outsideExempt = new Set<string>();
  const hasRm = analysis.segments.some(isRmSegment);
  if (hasRm) {
    // rm carve-out: bounded, explicit targets only (see header).
    const rm = checkRmTargets(analysis.segments, pd.cwd, isInsideBase);
    if (rm.reason) return { ok: false, reason: rm.reason };
    outsideExempt = rm.exempt;
  } else {
    if (analysis.safety.hasUnsafePattern) return { ok: false, reason: "unsafe pattern (obfuscation/subshell/redirect)" };
    if (analysis.risk.dangerous) return { ok: false, reason: `dangerous: ${analysis.risk.reasons.join("; ").slice(0, 120)}` };
  }
  const obscured = obscuredHit(analysis.segments);
  if (obscured) return { ok: false, reason: `obscured command position (${obscured})` };
  if (pd.credentialRule) return { ok: false, reason: `credential pattern (${pd.credentialRule})` };
  const net = networkHit(pd.command, analysis.segments);
  if (net) return { ok: false, reason: `network egress (${net})` };
  const outside = (analysis.prompt.outsidePaths ?? []).filter((p) => !outsideExempt.has(p));
  if (outside.length > 0) {
    return { ok: false, reason: `touches paths outside base (${outside.slice(0, 2).join(", ")})` };
  }
  return { ok: true };
}

// ── rm carve-out ────────────────────────────────────────────────────────

/** Danger reasons that belong to rm (or its self-written redirect) — evaluated
 * by checkRmTargets instead of the blanket dangerous block. */
const RM_RISK_REASON_RE = /\brm\b|recursive delete|forced delete|shell output redirection/i;
/** Targets that can never be auto-allowed: globs, tildes, computed
 * (variable/substitution) paths. */
const RM_FORBIDDEN_TARGET_RE = /[*?[~$`]/;

function isRmSegment(seg: string): boolean {
  const first = seg.trim().split(/\s+/)[0]?.split("/").pop()?.toLowerCase();
  return first === "rm";
}

/** Write-redirect target (`> p` / `>> p` / `2> p`) in a raw segment. */
const REDIRECT_TARGET_RE = /\d*(?:>>?)\s*([A-Za-z0-9_./-]+|"[^"\s]+"|'[^'\s]+')/g;
const SELF_WRITE_CMDS = new Set(["tee", "touch", "mkdir"]);

/** Strip one pair of matching quotes from a raw token. */
function cleanToken(t: string): string {
  if (t.length >= 2 && ((t[0] === '"' && t.endsWith('"')) || (t[0] === "'" && t.endsWith("'")))) {
    return t.slice(1, -1);
  }
  return t;
}

/** /dev/* targets are not real writes (>/dev/null, /dev/stderr, …). */
function isDevNullish(resolved: string): boolean {
  return resolved === "/dev" || resolved.startsWith("/dev/");
}

/**
 * Validate every rm target in the command. Returns a block reason, or the
 * create-then-delete set (self-written paths that are also rm targets) to
 * exempt from the outside-base check.
 */
function checkRmTargets(
  segments: string[],
  cwd: string,
  isInsideBase: (p: string) => boolean,
): { reason: string | null; exempt: Set<string> } {
  const written = new Set<string>();
  const rmTargets = new Set<string>();
  const noPreserveRoot = () => ({ reason: "rm with --no-preserve-root" as string | null, exempt: new Set<string>() });

  // First pass: collect self-written paths (ordered by segment) and rm targets.
  for (let i = 0; i < segments.length; i++) {
    const seg = segments[i];
    const words = seg.trim().split(/\s+/);
    if (isRmSegment(seg)) {
      if (words.includes("--no-preserve-root")) return noPreserveRoot();
      const args = words.slice(1).filter((t) => !t.startsWith("-"));
      if (args.length === 0) return { reason: "rm without explicit targets", exempt: new Set() };
      const recursive = words.slice(1).some(
        (t) => t === "--recursive" || (t.startsWith("-") && !t.startsWith("--") && t !== "-" && /[rR]/.test(t)),
      );
      for (const a of args) {
        const target = cleanToken(a);
        if (RM_FORBIDDEN_TARGET_RE.test(target)) {
          return { reason: `rm target not explicit (${target.slice(0, 40)})`, exempt: new Set() };
        }
        if (target === "-") return { reason: "rm reading from stdin", exempt: new Set() };
        const resolved = resolvePathReal(expandTilde(target), cwd);
        if (resolved === cwd) return { reason: "rm target is the working directory itself", exempt: new Set() };
        if (recursive) {
          try {
            const st = fs.statSync(resolved);
            const selfWritten = written.has(resolved);
            if (!st.isDirectory() && !st.isFile() && !selfWritten) {
              return { reason: `rm -r target is not a file or directory (${a.slice(0, 60)})`, exempt: new Set() };
            }
            if (!st.isDirectory() && !st.isFile() && selfWritten) {
              /* self-written: trust the earlier segment */
            }
          } catch {
            /* doesn't exist — nothing to delete */
          }
        }
        rmTargets.add(resolved);
        if (!isInsideBase(resolved) && !written.has(resolved)) {
          return { reason: `rm target outside session base (${a.slice(0, 60)})`, exempt: new Set() };
        }
      }
    } else {
      // Self-written paths from this earlier segment.
      for (const m of seg.matchAll(REDIRECT_TARGET_RE)) {
        const raw = cleanToken(m[1]);
        if (RM_FORBIDDEN_TARGET_RE.test(raw)) continue;
        const resolved = resolvePathReal(expandTilde(raw), cwd);
        if (isDevNullish(resolved)) continue;
        written.add(resolved);
      }
      // Self-write commands per pipeline stage — `a | tee f` hides tee
      // behind the segment's first word.
      for (const stage of seg.split("|")) {
        const sw = stage.trim().split(/\s+/);
        const scmd = sw[0]?.split("/").pop()?.toLowerCase() ?? "";
        if (!SELF_WRITE_CMDS.has(scmd)) continue;
        for (const t of sw.slice(1)) {
          const target = cleanToken(t);
          if (t.startsWith("-") || /^[\d<>]/.test(t) || RM_FORBIDDEN_TARGET_RE.test(target)) continue;
          const resolved = resolvePathReal(expandTilde(target), cwd);
          if (isDevNullish(resolved)) continue;
          written.add(resolved);
        }
      }
    }
  }

  // Every self-written path must be in-base or cleaned up by this command.
  for (const w of written) {
    if (!isInsideBase(w) && !rmTargets.has(w)) {
      return { reason: `write-redirect outside base, not cleaned by this command (${w.slice(0, 60)})`, exempt: new Set() };
    }
  }

  return { reason: null, exempt: new Set([...rmTargets].filter((t) => written.has(t))) };
}
