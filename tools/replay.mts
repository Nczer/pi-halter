/**
 * Session replay probe — run a session's OWN bash and codemode calls through
 * the REAL /dspa decision path (gate → stage cascade → intent guards) and
 * print what it would decide NOW.
 *
 * Input: the current session by default (PI_SESSION_FILE). Another file only
 * through an explicit --session flag — the tool never scans the sessions
 * directory, so older sessions are never read by accident.
 *
 * Replayed, in session order, under the session header's cwd:
 *   • direct `bash` tool calls (assistant toolCall blocks);
 *   • bash calls a `codemode` script issued (the codemode toolResult's
 *     `message.nestedCalls.calls[]`).
 *
 * The store is FRESH per call (a first-encounter view); --carry keeps one
 * store so learned read grants accumulate, and --read-dir / --write-dir /
 * --confirm model a state the session actually had. Prompt answers are not
 * recorded in a session, so they cannot be replayed — this is a floor/judge
 * probe, not a session re-execution.
 *
 * DEFAULT IS FLOOR-ONLY (decide + gate, no model): a whole session's calls
 * cost milliseconds. --judge runs the real decision; with a local model
 * (concurrency 1–2) that is seconds per call, so select first with --filter /
 * --pick / --dedupe and cap it with --judge-limit.
 *
 * All three ledger seams are forced off: probing never writes .log/.
 *
 * usage: npx tsx tools/replay.mts [flags]
 *   --session FILE       replay another session (default: PI_SESSION_FILE)
 *   --judge              run the real dspa decision (default: floor only)
 *   --judge-limit N      stop calling the model after N calls (floor still runs)
 *   --pick 3,7-9         only these call indices (the # a floor pass prints)
 *   --dedupe             once per distinct command+cwd
 *   --model provider/id  judge model (default: settings judge, then PI_MODEL)
 *   --thinking LEVEL     judge thinking level (default: settings)
 *   --timeout MS         judge first-token deadline (default: settings)
 *   --carry              keep one store across calls
 *   --read-dir DIR       pre-grant a read dir (repeatable)
 *   --write-dir DIR      pre-grant a write dir (repeatable)
 *   --confirm TOK=DIR    pre-confirm a token's resolution (repeatable)
 *   --filter TEXT        only commands containing TEXT
 *   --limit N            stop after N replayed calls
 *   --no-cache           reset the judge/resolver caches before each call
 *   --judge-log FILE     write the judge diagnostics ledger here (default off)
 *   --packet             print the judge input (stage 1; stage 2 adds context)
 *   --json               one JSON object per call
 */

// Never write the real ledgers from a probe. Resolved per call by decision-log,
// so setting the seams before the first gate call is enough.
process.env.HALTER_DECISION_LOG = "off";
process.env.HALTER_UNRESOLVED_LOG = "off";
process.env.HALTER_JUDGE_LOG = "off";

import fs from "node:fs";
import path from "node:path";
import { performance } from "node:perf_hooks";
import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import { ModelRegistry, ModelRuntime } from "@earendil-works/pi-coding-agent";
import type { PermissionRequest } from "../decide/types";
import { gateDecide } from "../gate/gate";
import { applyDspaConversions } from "../gate/conversions";
import { tryDspaAutoAllow } from "../gate/fallthrough";
import type { DspaFallthrough } from "../gate/fallthrough";
import { createStore, type Store } from "../gate/store";
import { setDspaActive, resetDspa } from "../modes/dspa-mode";
import { readJudgeSettings, resetJudgeCache, type JudgeSettings } from "../judge/judge";
import { resetPathResolverCache } from "../judge/path-resolver";
import { buildJudgmentPacket } from "../judge/packet";
import { buildJudgmentInput, judgeStatus } from "../judge/verdict";

// ── CLI ──────────────────────────────────────────────────────────────────

interface Args {
  session: string;
  sessionExplicit: boolean;
  model: string | null;
  thinking: JudgeSettings["thinking"] | null;
  timeoutMs: number | null;
  judge: boolean;
  judgeLimit: number | null;
  pick: string | null;
  dedupe: boolean;
  carry: boolean;
  readDirs: string[];
  writeDirs: string[];
  confirms: Array<[string, string]>;
  filter: string | null;
  limit: number | null;
  noCache: boolean;
  judgeLog: string | null;
  packet: boolean;
  json: boolean;
  help: boolean;
}

function parseArgs(argv: string[]): Args {
  const a: Args = {
    session: process.env.PI_SESSION_FILE ?? "",
    sessionExplicit: false,
    model: null,
    thinking: null,
    timeoutMs: null,
    judge: false,
    judgeLimit: null,
    pick: null,
    dedupe: false,
    carry: false,
    readDirs: [],
    writeDirs: [],
    confirms: [],
    filter: null,
    limit: null,
    noCache: false,
    judgeLog: null,
    packet: false,
    json: false,
    help: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const f = argv[i];
    const val = (): string => {
      const v = argv[++i];
      if (v === undefined) fail(`${f} needs a value`);
      return v;
    };
    switch (f) {
      case "--session": a.session = val(); a.sessionExplicit = true; break;
      case "--model": a.model = val(); break;
      case "--thinking": a.thinking = val() as JudgeSettings["thinking"]; break;
      case "--timeout": a.timeoutMs = Number(val()); break;
      case "--judge": a.judge = true; break;
      case "--judge-limit": a.judgeLimit = Number(val()); break;
      case "--pick": a.pick = val(); break;
      case "--dedupe": a.dedupe = true; break;
      case "--carry": a.carry = true; break;
      case "--read-dir": a.readDirs.push(val()); break;
      case "--write-dir": a.writeDirs.push(val()); break;
      case "--confirm": {
        const raw = val();
        const eq = raw.indexOf("=");
        if (eq <= 0) fail("--confirm takes TOKEN=DIR");
        a.confirms.push([raw.slice(0, eq), raw.slice(eq + 1)]);
        break;
      }
      case "--filter": a.filter = val(); break;
      case "--limit": a.limit = Number(val()); break;
      case "--no-cache": a.noCache = true; break;
      case "--judge-log": a.judgeLog = val(); break;
      case "--packet": a.packet = true; break;
      case "--json": a.json = true; break;
      case "-h": case "--help": a.help = true; break;
      default: fail(`unknown flag: ${f}`);
    }
  }
  if (!a.help && !a.session) fail("no session: PI_SESSION_FILE is unset — pass --session FILE");
  if (a.limit !== null && (!Number.isInteger(a.limit) || a.limit < 1)) fail("--limit takes a positive integer");
  if (a.timeoutMs !== null && (!Number.isFinite(a.timeoutMs) || a.timeoutMs <= 0)) fail("--timeout takes milliseconds");
  if (a.judgeLimit !== null) {
    if (!a.judge) fail("--judge-limit needs --judge");
    if (!Number.isInteger(a.judgeLimit) || a.judgeLimit < 1) fail("--judge-limit takes a positive integer");
  }
  if (a.pick !== null) parsePick(a.pick); // validate early
  return a;
}

/** `3,7-9,12` → {3,7,8,9,12}. Absolute call indices — the # a floor pass prints. */
function parsePick(spec: string): Set<number> {
  const out = new Set<number>();
  for (const part of spec.split(",")) {
    const m = /^(\d+)(?:-(\d+))?$/.exec(part.trim());
    if (!m) fail(`--pick takes N or N-M (got ${part.trim()})`);
    const from = Number(m[1]);
    const to = m[2] === undefined ? from : Number(m[2]);
    if (from < 1 || to < from) fail(`--pick range ${part.trim()} is not ascending`);
    for (let i = from; i <= to; i++) out.add(i);
  }
  return out;
}

function fail(msg: string): never {
  console.error(`replay: ${msg}`);
  process.exit(2);
}

const USAGE = `usage: npx tsx tools/replay.mts [--session FILE] [--judge] [--judge-limit N]
       [--pick 3,7-9] [--dedupe] [--model provider/id]
       [--thinking LEVEL] [--timeout MS] [--carry]
       [--read-dir DIR] [--write-dir DIR] [--confirm TOKEN=DIR]
       [--filter TEXT] [--limit N] [--no-cache] [--judge-log FILE] [--packet] [--json]`;

// ── Session extraction ───────────────────────────────────────────────────

interface ReplayCall {
  /** 1-based, after filtering. */
  index: number;
  /** 1-based line in the session file. */
  line: number;
  id: string;
  source: "direct" | "codemode";
  command: string;
  cwd: string;
}

/**
 * Pull the replayed calls from a session JSONL. Only `bash`: direct calls are
 * assistant toolCall blocks; a codemode script's calls are recorded on its
 * toolResult (`message.nestedCalls.calls[]`, with a fallback to
 * `message.details.calls[].args`) after the script ran.
 */
function readSession(file: string): { cwd: string; id: string; calls: ReplayCall[] } {
  const raw = fs.readFileSync(file, "utf8");
  let cwd = process.cwd();
  let id = process.env.PI_SESSION_ID ?? "replay";
  const calls: ReplayCall[] = [];
  let lineNo = 0;
  for (const line of raw.split("\n")) {
    lineNo++;
    if (!line.trim()) continue;
    let d: any;
    try { d = JSON.parse(line); } catch { continue; }
    if (d?.type === "session") {
      if (typeof d.cwd === "string") cwd = d.cwd;
      if (typeof d.id === "string") id = d.id;
      continue;
    }
    const m = d?.message;
    if (!m) continue;
    if (m.role === "assistant" && Array.isArray(m.content)) {
      for (const c of m.content) {
        if (c?.type !== "toolCall" || c.name !== "bash") continue;
        const cmd = c.arguments?.command;
        if (typeof cmd === "string" && cmd.trim()) {
          calls.push({ index: 0, line: lineNo, id: String(c.id ?? ""), source: "direct", command: cmd, cwd });
        }
      }
      continue;
    }
    if (m.role === "toolResult" && m.toolName === "codemode") {
      const nested = m.nestedCalls?.calls ?? m.details?.calls ?? [];
      for (const c of nested) {
        if (c?.name !== "bash") continue;
        let args = c.arguments;
        if (!args && typeof c.args === "string") {
          try { args = JSON.parse(c.args); } catch { /* keep undefined */ }
        }
        const cmd = args?.command;
        if (typeof cmd === "string" && cmd.trim()) {
          calls.push({ index: 0, line: lineNo, id: String(c.id ?? ""), source: "codemode", command: cmd, cwd });
        }
      }
    }
  }
  calls.forEach((c, i) => { c.index = i + 1; });
  return { cwd, id, calls };
}

// ── Judge settings / model ───────────────────────────────────────────────

function splitModel(spec: string): [string, string] {
  const slash = spec.indexOf("/");
  if (slash <= 0 || slash === spec.length - 1) fail(`--model takes provider/id (got ${spec})`);
  return [spec.slice(0, slash), spec.slice(slash + 1)];
}

async function judgeSetup(a: Args): Promise<{
  settings: JudgeSettings;
  model: ReturnType<ModelRegistry["find"]> | null;
  registry: ModelRegistry | null;
}> {
  const base = readJudgeSettings();
  // Floor-only: no model, no auth, no registry — the stage functions return
  // before resolving a model when `enabled` is false, and the D3/D11
  // conversions skip exactly as they do when the real judge is off.
  if (!a.judge) {
    return {
      settings: { ...base, enabled: false, thinking: a.thinking ?? base.thinking, timeoutMs: a.timeoutMs ?? base.timeoutMs },
      model: null,
      registry: null,
    };
  }
  let provider = base.provider;
  let modelId = base.model;
  if (a.model) [provider, modelId] = splitModel(a.model);
  else if (provider === null || modelId === null) {
    // The session model — pi exports its identity into every tool process.
    provider = process.env.PI_PROVIDER ?? null;
    modelId = process.env.PI_MODEL ?? null;
  }
  if (provider === null || modelId === null) {
    fail("no judge model: pass --model provider/id (halter.judge is unset and PI_MODEL is absent)");
  }
  const settings: JudgeSettings = {
    ...base,
    enabled: true,
    provider,
    model: modelId,
    thinking: a.thinking ?? base.thinking,
    timeoutMs: a.timeoutMs ?? base.timeoutMs,
  };
  const runtime = await ModelRuntime.create();
  const registry = new ModelRegistry(runtime);
  const model = registry.find(provider, modelId);
  if (!model) {
    fail(`model not found: ${provider}/${modelId}\n  known providers: ${registry.getAll().map((m) => m.provider).filter((p, i, x) => x.indexOf(p) === i).join(", ")}`);
  }
  return { settings, model, registry };
}

// ── Report helpers ───────────────────────────────────────────────────────

const oneLine = (s: string, n: number): string => s.replace(/\s+/g, " ").trim().slice(0, n);

function verdictLine(f: DspaFallthrough | undefined): string | null {
  if (!f?.verdict) return null;
  const v = f.verdict;
  const ms = v.latencyMs > 0 ? ` ${Math.round(v.latencyMs)}ms` : "";
  return `${v.approve}/${v.risk ?? "-"} stage ${f.stage ?? "?"}${ms} — ${oneLine(v.explanation, 120)}`;
}

function missSummary(f: DspaFallthrough | undefined): string | null {
  const ledger = f?.missLedger;
  if (!ledger) return null;
  const toks = ledger.misses.map((m) => `${m.kind} ${m.token}`).join("; ");
  return `${oneLine(ledger.guard, 160)}${toks ? ` [${oneLine(toks, 120)}]` : ""}`;
}

// ── Main ─────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const a = parseArgs(process.argv.slice(2));
  if (a.help) { console.log(USAGE); return; }
  // opt-in judge diagnostics: a scratch ledger, never the real .log/judge.jsonl.
  if (a.judgeLog) process.env.HALTER_JUDGE_LOG = a.judgeLog;

  const { cwd, id: sessionId, calls: rawCalls } = readSession(a.session);
  let calls = rawCalls;
  // pick uses the ABSOLUTE # a floor pass printed, so it runs before the other
  // selectors; dedupe then filter then limit.
  if (a.pick !== null) {
    const pick = parsePick(a.pick);
    calls = calls.filter((c) => pick.has(c.index));
  }
  if (a.dedupe) {
    const seen = new Set<string>();
    calls = calls.filter((c) => {
      const key = `${c.cwd}\u0000${c.command}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }
  if (a.filter) calls = calls.filter((c) => c.command.includes(a.filter!));
  if (a.limit !== null) calls = calls.slice(0, a.limit);
  if (!calls.length) { console.log(`replay: no bash calls in ${a.session}`); return; }

  const { settings, model, registry } = await judgeSetup(a);
  const status = judgeStatus(
    { model, modelRegistry: registry, hasUI: true, cwd, ui: {} } as unknown as ExtensionContext,
    settings,
  );

  // Fake ctx: the same fields the real handlers see. UI calls are stubs —
  // nothing here may pop a dialog or a widget.
  const ctx = {
    cwd,
    hasUI: true,
    model,
    modelRegistry: registry,
    // The provider adapter routes on the session id (opencode-go requires its
    // header) — the replayed session's own id is the honest one.
    sessionManager: { getSessionId: () => sessionId },
    ui: {
      notify: () => {},
      setWidget: () => {},
      getToolsExpanded: () => false,
      setToolsExpanded: () => {},
    },
  } as unknown as ExtensionContext;

  if (!a.json) {
    if (a.sessionExplicit) {
      console.log(`session (explicit) ${a.session}`);
    } else {
      console.log(`session ${path.basename(a.session)}  (current)`);
    }
    console.log(`cwd ${cwd}`);
    console.log(`judge ${!a.judge ? "off (floor pass; --judge runs the model)" : status.state === "ok" ? `${status.modelLabel}${a.judgeLimit ? ` — limit ${a.judgeLimit} call(s)` : ""}` : `unavailable (${status.reason})`}`);
    console.log(`store ${a.carry ? "carried" : "fresh per call"}${a.readDirs.length || a.writeDirs.length || a.confirms.length ? " + flags" : ""}`);
    console.log(`${calls.length} call(s)\n`);
  }

  resetDspa();
  setDspaActive(true);
  const carried: Store | null = a.carry ? newStore(a) : null;
  let judged = 0;

  for (const call of calls) {
    const store = carried ?? newStore(a);
    const judgeOnce = a.judge && (a.judgeLimit === null || judged < a.judgeLimit);
    // Past the cap the stages still run but return immediately: the floor's
    // answer is unchanged, only the model call is skipped.
    const callSettings = judgeOnce ? settings : { ...settings, enabled: false };
    if (a.noCache) {
      resetJudgeCache();
      resetPathResolverCache();
    }
    const request: PermissionRequest = { type: "bash", command: call.command, cwd: call.cwd };
    // Print the call BEFORE the work: a local judge can take seconds, and a
    // silent run reads as a hang.
    if (!a.json) {
      console.log(`#${call.index}  line ${call.line}  ${call.source}${call.id ? `  ${call.id}` : ""}`);
      console.log(`  cmd    ${oneLine(call.command, 160)}`);
    }
    const t0 = performance.now();
    const decided = await gateDecide(request, store, ctx);
    const converted = await applyDspaConversions(request, decided, store, ctx);
    let dspa: Awaited<ReturnType<typeof tryDspaAutoAllow>> | null = null;
    if (converted.kind === "prompt") {
      dspa = await tryDspaAutoAllow(request, converted, ctx, store, { settings: callSettings });
      if (judgeOnce) judged++;
    }
    const elapsed = Math.round(performance.now() - t0);
    const pd = converted.kind === "prompt" ? converted.promptData : decided.kind === "prompt" ? decided.promptData : null;

    // The packet the judge saw (stage-1 base; stage 2 appends session context).
    let packet: string | null = null;
    if (a.packet && pd) {
      try {
        packet = buildJudgmentPacket(await buildJudgmentInput(pd, store));
      } catch (err) {
        packet = `(packet failed: ${String((err as Error)?.message ?? err)})`;
      }
    }

    if (a.json) {
      console.log(JSON.stringify({
        index: call.index,
        line: call.line,
        id: call.id,
        source: call.source,
        command: call.command,
        judge: judgeOnce,
        decide: decided.kind,
        converted: converted.kind,
        dspa: dspa && {
          autoAllowed: dspa.autoAllowed,
          stage: dspa.fallthrough.stage,
          gate: dspa.fallthrough.gate.ok ? null : dspa.fallthrough.gate.reason,
          guard: dspa.fallthrough.missLedger?.guard ?? null,
          misses: dspa.fallthrough.missLedger?.misses ?? null,
          verdict: dspa.fallthrough.verdict && {
            approve: dspa.fallthrough.verdict.approve,
            risk: dspa.fallthrough.verdict.risk,
            explanation: dspa.fallthrough.verdict.explanation,
            latencyMs: dspa.fallthrough.verdict.latencyMs,
            model: dspa.fallthrough.verdict.model,
          },
          judgeFail: dspa.fallthrough.judgeFail ?? null,
          note: dspa.fallthrough.note ?? null,
        },
        elapsedMs: elapsed,
        ...(packet !== null ? { packet } : {}),
      }));
      continue;
    }

    console.log(`  decide ${decided.kind}${converted.kind !== decided.kind ? ` → ${converted.kind}` : ""}  (${elapsed}ms)`);
    if (decided.kind === "block") {
      console.log(`  block  ${oneLine(decided.reason, 200)}`);
    } else if (converted.kind === "prompt") {
      const f = dspa?.fallthrough;
      const gate = f?.gate && !f.gate.ok ? oneLine(f.gate.reason, 180) : "ok";
      console.log(`  floor  ${gate}`);
      const guard = missSummary(f);
      if (guard) console.log(`  guard  ${guard}`);
      const v = verdictLine(f);
      if (v) console.log(`  judge  ${v}`);
      else if (f && judgeOnce) {
        const why = f.judgeFail ? ` (${f.judgeFail})` : f.note ? ` — ${oneLine(f.note, 160)}` : "";
        console.log(`  judge  none${why}`);
      }
      if (dspa?.autoAllowed) {
        console.log(`  dspa   AUTO-ALLOW (stage ${f?.stage ?? "?"})`);
      } else if (judgeOnce) {
        console.log(`  dspa   PROMPT`);
      } else {
        console.log(`  dspa   judge skipped (floor only)`);
      }
    } else {
      console.log(`  dspa   — (no gate/judge: decision is ${converted.kind})`);
    }
    if (packet !== null) {
      console.log("  packet:");
      for (const line of packet.split("\n")) console.log(`    ${line}`);
    }
    console.log("");
  }
  if (!a.json && a.judge && a.judgeLimit !== null && calls.length > judged) {
    console.log(`judge limit: ${judged}/${calls.length} call(s) judged; the rest were floor-only.`);
  }
}

function newStore(a: Args): Store {
  const store = createStore();
  if (a.readDirs.length || a.writeDirs.length) {
    store.addAllowed({ readDirs: a.readDirs, writeDirs: a.writeDirs });
  }
  for (const [token, dir] of a.confirms) store.confirmResolution(token, [dir]);
  return store;
}

main().catch((err) => {
  console.error(`replay: ${(err as Error)?.stack ?? String(err)}`);
  process.exit(1);
});
