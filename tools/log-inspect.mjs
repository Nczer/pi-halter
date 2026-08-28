#!/usr/bin/env node
/**
 * log-inspect.mjs — decision-log extraction for debugging halter.
 *
 * Zero-dependency reader/aggregator over .log/decisions.jsonl (the blast-
 * radius log, see decision-log.ts). Answers the recurring review questions:
 *
 *   summary   counts, prompt rate, top prompt reasons, every block, anomaly
 *             counts — the 30-second "what did the gate do" view
 *   list      filtered entries, one compact line each
 *   blocks    every block + internal-error entry, full reason
 *   dspa      every judge-regime entry (dspa/dspat) with stop tag
 *   dspa --paths   D13 parser-gap view: judge-regime entries whose stage-2
 *             path report has paths the static floor never saw
 *             (judgePathMisses) — each miss is a parser hole or a judge
 *             hallucination; both worth mining
 *   dspa --reasons   why judge-regime entries auto-allowed / stopped — the
 *             reason rollup (auto-allow reasons, stop tags, judge denials,
 *             each with counts + a first-seen example)
 *   stats     per-target aggregation — who prompts repeatedly, who auto-allows
 *   audit     anomaly scan: known bug classes (test-fixture pollution,
 *             contradictions, phantom root paths, misleading outside-base
 *             labels, the config-allowed-path floor hole, repeated prompts,
 *             dup lines), invariants that should never fire, and (with
 *             --since) novelty vs the earlier log — new prompt reasons,
 *             stop tags, auto-allowed first-words, file target dirs
 *   show N    full JSON of entry N (0-based, across the file)
 *
 * usage:
 *   node tools/log-inspect.mjs [summary|list|blocks|dspa|stats|audit|show N]
 *      [--file <path>] [--all]            --all: include decisions.jsonl.1
 *      [--since <iso>] [--until <iso>]    time window
 *      [--kind block|prompt|auto-allow|deny]
 *      [--mode dspa|dspat|manual]         manual = untagged (no mode key)
 *      [--tool bash|file|mcp]
 *      [--grep <substr>]                  case-insensitive over reason+dspa+target
 *      [--top N]                          default 10
 *      [--full]                           don't truncate targets
 *      [--json]                           list: raw JSON lines
 *
 * The log is fire-and-forget and append-only; lines may be truncated
 * (target cap 1000 chars) — treat targets as "what the user saw", not the
 * verbatim command.
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

// ── CLI ─────────────────────────────────────────────────────────────────

const here = path.dirname(fileURLToPath(import.meta.url));
const argv = process.argv.slice(2);
const flags = {};
const pos = [];
for (let i = 0; i < argv.length; i++) {
  const a = argv[i];
  if (a.startsWith("--")) {
    const eq = a.indexOf("=");
    if (eq !== -1) flags[a.slice(2, eq)] = a.slice(eq + 1);
    else if (i + 1 < argv.length && !argv[i + 1].startsWith("--")) flags[a.slice(2)] = argv[++i];
    else flags[a.slice(2)] = true;
  } else pos.push(a);
}
const cmd = pos[0] ?? "summary";
const top = Number(flags.top ?? 10);
const truncateLen = flags.full ? Infinity : 110;

const DEFAULT_FILE = path.join(here, "..", ".log", "decisions.jsonl");
const files = [];
const base = flags.file ? String(flags.file) : DEFAULT_FILE;
if (!fs.existsSync(base)) {
  console.error(`log file not found: ${base}`);
  process.exit(2);
}
if (flags.all) {
  const rotated = base + ".1";
  if (fs.existsSync(rotated)) files.push(rotated); // .1 is the OLDER rotation → first
}
files.push(base);

// ── Load ────────────────────────────────────────────────────────────────

const entries = [];
for (const f of files) {
  const lines = fs.readFileSync(f, "utf8").split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) continue;
    try {
      const e = JSON.parse(line);
      e.__idx = entries.length; // stable cross-file index
      e.__line = i + 1;
      e.__file = path.basename(f);
      entries.push(e);
    } catch {
      console.error(`warn: ${f}:${i + 1} is not valid JSON — skipped`);
    }
  }
}
// ── Filters ─────────────────────────────────────────────────────────────

function inFilter(e) {
  if (flags.since && e.ts < flags.since) return false;
  if (flags.until && e.ts > flags.until) return false;
  if (flags.kind && e.kind !== flags.kind) return false;
  if (flags.tool && e.tool !== flags.tool) return false;
  if (flags.mode) {
    const m = e.mode ?? "manual";
    if (m !== flags.mode) return false;
  }
  if (flags.grep) {
    const hay = `${e.reason ?? ""} ${e.dspa ?? ""} ${e.target ?? ""}`.toLowerCase();
    if (!hay.includes(String(flags.grep).toLowerCase())) return false;
  }
  return true;
}
const F = entries.filter(inFilter);

// ── Formatting helpers ──────────────────────────────────────────────────

const trunc = (s, n = truncateLen) => (s.length > n ? s.slice(0, n - 1) + "…" : s);
const firstLine = (s) => s.split("\n")[0];
const time = (ts) => ts.slice(11, 19);
const day = (ts) => ts.slice(0, 10);
const tag = (e) => e.mode ?? "manual";
const why = (e) => {
  const parts = [];
  if (e.dspa) parts.push(e.dspa);
  if (e.reason) parts.push(e.reason);
  return parts.join(" | ") || "-";
};

function line(e, extra = "") {
  return `[${e.__idx}] ${day(e.ts)} ${time(e.ts)} ${tag(e).padEnd(5)} ${e.kind.padEnd(10)} ${e.tool.padEnd(4)} ${trunc(firstLine(e.target))}${extra ? "  " + extra : ""}`;
}

// ── Commands ────────────────────────────────────────────────────────────

function counts(arr, keyFn) {
  const m = new Map();
  for (const e of arr) {
    const k = keyFn(e) ?? "(none)";
    m.set(k, (m.get(k) ?? 0) + 1);
  }
  return [...m.entries()].sort((a, b) => b[1] - a[1]);
}

function summary() {
  console.log(`# halter decision log — ${files.map((f) => path.basename(f)).join(", ")}`);
  console.log(`${entries.length} entries total${files.length > 1 ? " (incl. rotated)" : ""}, ${F.length} in filter window`);
  const span = F.length ? `${day(F[0].ts)} ${time(F[0].ts)} → ${day(F[F.length - 1].ts)} ${time(F[F.length - 1].ts)}` : "-";
  console.log(`window: ${span}\n`);

  console.log("## decisions (filtered)");
  for (const [k, n] of counts(F, (e) => `${tag(e)} / ${e.kind}`)) console.log(`  ${String(n).padStart(4)}  ${k}`);
  const total = F.length || 1;
  const promptN = F.filter((e) => e.kind === "prompt").length;
  const blockN = F.filter((e) => e.kind === "block").length;
  console.log(`  prompt rate: ${((promptN / total) * 100).toFixed(1)}%  (blocks: ${((blockN / total) * 100).toFixed(1)}%)\n`);

  console.log("## top prompt reasons");
  for (const [r, n] of counts(F.filter((e) => e.kind === "prompt"), (e) => e.reason).slice(0, top))
    console.log(`  ${String(n).padStart(4)}  ${trunc(r ?? "(null)", 100)}`);
  console.log("");

  console.log("## dspa stop tags (judge regime fall-throughs)");
  const stops = F.filter((e) => e.kind === "prompt" && e.dspa);
  if (!stops.length) console.log("  (none)");
  for (const [r, n] of counts(stops, (e) => e.dspa)) console.log(`  ${String(n).padStart(4)}  ${trunc(r, 100)}`);
  const pathMissN = F.filter((e) => e.judgePathMisses?.length).length;
  console.log(`  judge path misses (dspa --paths): ${pathMissN}`);
  console.log("");

  const blocks = F.filter((e) => e.kind === "block");
  console.log(`## blocks (${blocks.length})`);
  for (const e of blocks.slice(0, top)) console.log(`  ${line(e, trunc(e.reason ?? "", 90))}`);
  if (blocks.length > top) console.log(`  … ${blocks.length - top} more — use: blocks`);
  console.log("");

  const anomalies = runAudit(F);
  console.log(`## anomalies (${anomalies.length} classes)`);
  for (const a of anomalies) console.log(`  ${a.label.padEnd(28)} ${a.items.length}`);
  if (!anomalies.length) console.log("  (none)");
  console.log("\nuse 'audit' for details");
}

function listCmd() {
  if (flags.json) {
    for (const e of F) {
      const { __idx, __line, __file, ...clean } = e;
      console.log(JSON.stringify(clean));
    }
    return;
  }
  for (const e of F) console.log(line(e, trunc(why(e), 90)));
  console.error(`${F.length} entries — 'show <idx>' for full JSON`);
}

function blocksCmd() {
  const bs = F.filter((e) => e.kind === "block");
  console.log(`# blocks (${bs.length})`);
  for (const e of bs) {
    console.log(`\n[${e.__idx}] ${e.ts}  ${tag(e)}  ${e.tool}  cwd=${e.cwd ?? "-"}`);
    console.log(`  reason: ${e.reason ?? "-"}`);
    console.log(`  target: ${trunc(firstLine(e.target), 200)}`);
  }
}

function dspaCmd() {
  const ds = F.filter((e) => e.mode === "dspa" || e.mode === "dspat");
  console.log(`# judge-regime entries (${ds.length})`);
  for (const e of ds) {
    console.log(`\n[${e.__idx}] ${e.ts}  ${e.mode}  ${e.kind}`);
    if (e.dspa) console.log(`  stop:   ${e.dspa}`);
    if (e.reason) console.log(`  reason: ${trunc(e.reason, 160)}`);
    if (e.judgeDeny) console.log(`  judgeDeny: ${trunc(e.judgeDeny, 160)}`);
    if (e.judgePaths?.length) console.log(`  judgePaths: ${e.judgePaths.join(", ")}`);
    if (e.judgePathMisses?.length) console.log(`  pathMisses: ${e.judgePathMisses.join(", ")}`);
    console.log(`  target: ${trunc(firstLine(e.target), 160)}`);
  }
}

/** D13 parser-gap view: judge-regime entries with stage-2 path reports,
 *  flagged where the report contains paths the static floor never saw.
 *  The misses are the mining target — a miss is either a real
 *  static-analysis hole (fix the parser) or a judge hallucination (a
 *  reliability data point for the report field). */
function dspaPaths() {
  const ds = F.filter(
    (e) => (e.mode === "dspa" || e.mode === "dspat") && (e.judgePaths?.length || e.judgePathMisses?.length),
  );
  const withMisses = ds.filter((e) => e.judgePathMisses?.length);
  console.log(`# dspa --paths — ${withMisses.length} entries with floor mismatches, ${ds.length} with any stage-2 path report`);
  if (!ds.length) {
    console.log("(none — the judge reported no paths in this window)");
    return;
  }
  for (const e of ds) {
    console.log(`\n[@${e.__idx}] ${e.ts}  ${e.mode}  ${e.kind}  ${e.tool}`);
    if (e.dspa) console.log(`  stop:   ${e.dspa}`);
    if (e.reason) console.log(`  reason: ${trunc(e.reason, 160)}`);
    console.log(`  target: ${trunc(firstLine(e.target), 160)}`);
    if (e.judgePaths?.length) console.log(`  judge:  ${e.judgePaths.join(", ")}`);
    for (const m of e.judgePathMisses ?? []) console.log(`  MISS:   ${m}`);
  }
}

/** The reason rollup: WHY judge-regime entries auto-allowed or stopped.
 *  Groups auto-allow reasons ("dspa: judge approved (stage N, model)"),
 *  stop tags, and the judge's rejection words — each with a count and the
 *  first-seen example. "What did the judge do, and why?" in one view. */
function dspaReasons() {
  const ds = F.filter((e) => e.mode === "dspa" || e.mode === "dspat");
  console.log(`# dspa --reasons — ${ds.length} judge-regime entries`);
  const group = (arr, keyFn) => {
    const g = new Map();
    for (const e of arr) {
      const k = keyFn(e);
      if (!k) continue;
      const r = g.get(k) ?? { n: 0, ex: e };
      r.n++;
      g.set(k, r);
    }
    return [...g.entries()].sort((a, b) => b[1].n - a[1].n);
  };
  const section = (title, arr, keyFn) => {
    const g = group(arr, keyFn);
    console.log(`\n## ${title} (${arr.length})`);
    if (!g.length) console.log("  (none)");
    for (const [k, r] of g) {
      console.log(`  ${String(r.n).padStart(4)}  ${trunc(k, 90)}   e.g. [@${r.ex.__idx}] ${trunc(firstLine(r.ex.target), 50)}`);
    }
  };
  section("auto-allow reasons", ds.filter((e) => e.kind === "auto-allow"), (e) => e.reason ?? "(no reason)");
  section("stop tags (fall-through prompts)", ds.filter((e) => e.kind === "prompt"), (e) => e.dspa ?? "(no stop tag)");
  section("judge denials (the LLM's words)", ds, (e) => e.judgeDeny);
  section("D13 judge path misses (parser gaps)", ds, (e) => e.judgePathMisses?.join(", "));
}

function stats() {
  console.log(`# per-target stats (${F.length} filtered entries)`);
  for (const kind of ["prompt", "auto-allow"]) {
    console.log(`\n## top ${kind} targets (count, tools, span)`);
    const g = new Map();
    for (const e of F.filter((x) => x.kind === kind)) {
      const k = `${e.tool}  ${trunc(firstLine(e.target), 90)}`;
      const r = g.get(k) ?? { n: 0, first: e.ts, last: e.ts };
      r.n++;
      r.first = e.ts < r.first ? e.ts : r.first;
      r.last = e.ts > r.last ? e.ts : r.last;
      g.set(k, r);
    }
    for (const [k, r] of [...g.entries()].sort((a, b) => b[1].n - a[1].n).slice(0, top))
      console.log(`  ${String(r.n).padStart(4)}  ${k}   [${day(r.first)}→${day(r.last)}]`);
  }
}

// ── Audit ───────────────────────────────────────────────────────────────

/** Known synthetic shapes from the test suites (test/gate.test.ts,
 *  test/file-handler.test.ts). If the suites gain new fixtures, widen
 *  these — the audit's job is to keep the log honest. */
const TEST_FIXTURE_CWD = "/home/user/project";
const TEST_FIXTURE_RE = /\[INTERNAL ERROR\].*boom|cat \/etc\/passwd|'\.ssh' is a denied path/;
/** /tmp write via redirect/heredoc without an rm in the same command —
 *  the concrete-path floor hole (dspa-gate: outsidePaths is computed
 *  under the manual bar, /tmp is config write-allowed, so the floor
 *  never sees it). */
const TMP_ARG_RE = /(?:^|[\s;&|(`])(?:cat|tee|echo|printf|cp|mv)\s+(?:-[a-zA-Z]+\s+)*\/(?:private\/)?tmp\//;
/** redirect to /tmp (incl. fd form like 2>). The real instances of the
 *  floor hole are heredocs: `cat > /tmp/x.py <<EOF`. */
const TMP_REDIRECT_RE = /(?:^|[0-9\s;&|(`])>>?\s*\/(?:private\/)?tmp\//;
const HAS_RM_RE = /(?:^|[\s;&|(`])rm\s/;
/** "outside /" as the WHOLE path — a data token (grep pattern, redirect)
 *  that resolved to the filesystem root. The dspa variant catches the
 *  stop-tag form "gate: outside base (/)". */
const PHANTOM_ROOT_REASON_RE = /(^|\s)outside \/$/;
const PHANTOM_ROOT_DSPA_RE = new RegExp("gate: outside base \\(/\\)");

/**
 * The anomaly scan. Returns [{ label, items: string[] }] — items are
 * preformatted "[@idx] …" lines. Checks (in order):
 *  1  test-fixture lines      vitest runs writing through the real logger
 *  2  mixed-kind same target  same op auto-allowed and prompted (or blocked)
 *  3  phantom "outside /"     a data token resolved to the filesystem root
 *  4  outside-base label      the stop-tag dir IS the target's own parent
 *                             (outsideDir = grant-offer unit, not the base)
 *  5  dspa /tmp floor hole    config-allowed concrete write the floor never
 *                             saw (manual-bar outsidePaths, see dspa-gate)
 *  6  repeated prompts        same op prompted >=3 times
 *  7  duplicate entries       identical consecutive lines
 *  8  internal-error blocks   live fail-closed crashes (fixtures excluded)
 *  9  trust learning          untrusted-package stop → later judge-approve
 * 10  resolution mismatch     file prompt whose offered grant dir (promptDir)
 *                             does not contain the resolved target — a
 *                             path-resolution bug (the "@356 phantom" class)
 *
 *  11-14 invariants (should NEVER fire — a hit means the gate or the
 *      logger is broken, whatever the cause):
 *      auto-allow with a stop tag, risk:high auto-allowed, silent prompt
 *      (no reason, no stop tag), block without a reason
 *
 *  15 novelty (only with --since): vs the file history before the window,
 *      new prompt-reason verdicts, new stop tags, new auto-allowed
 *      first-words, new file target dirs — "what did the gate start doing
 *      since I changed the code?" Uses the full file, other filters ignored.
 */
function runAudit(scope) {  const out = [];
  const add = (label, items) => items.length && out.push({ label, items });

  add("test-fixture lines", scope.filter((e) => e.cwd === TEST_FIXTURE_CWD || (e.reason && TEST_FIXTURE_RE.test(e.reason)))
    .map((e) => `[@${e.__idx}] ${day(e.ts)} ${e.kind} ${e.tool}  ${trunc(e.reason ?? firstLine(e.target), 90)}`));

  {
    const g = new Map();
    for (const e of scope) {
      const k = `${e.mode ?? "manual"}|${e.tool}|${e.target}`;
      (g.get(k) ?? g.set(k, new Map()).get(k)).set(e.kind, (g.get(k).get(e.kind) ?? 0) + 1);
    }
    add("mixed-kind same target", [...g.entries()].filter(([, kinds]) => kinds.size > 1)
      .map(([k, kinds]) => { const [m, t, tgt] = k.split("|"); return `${m} ${t}: ${[...kinds].map(([k2, n2]) => `${k2}×${n2}`).join(", ")}  ::  ${trunc(tgt, 90)}`; }));
  }

  add('phantom "outside /"', scope.filter((e) => PHANTOM_ROOT_REASON_RE.test(e.reason ?? "") || PHANTOM_ROOT_DSPA_RE.test(e.dspa ?? ""))
    .map((e) => `[@${e.__idx}] ${trunc(firstLine(e.target), 100)}`));

  add("outside-base label = target's own dir", scope.filter((e) => {
    if (e.tool !== "file") return false;
    const m = `${e.reason ?? ""} ${e.dspa ?? ""}`.match(/outside (?:base \()?(\/[^\s()]+)/);
    return !!m && e.target.startsWith(m[1] + "/");
  }).map((e) => `[@${e.__idx}] ${trunc(e.target, 100)}`));

  // Resolution mismatch: the prompt offers "always write <promptDir>", so
  // promptDir must CONTAIN the resolved target. A containment miss means the
  // grant offer and the actual write location disagree — a resolution bug
  // (the "@356 phantom" class: a target resolved to a dir the prompt never
  // named). Targets log in display form (absolute, relative, or ~-prefixed).
  {
    const home = process.env.HOME ?? "/root";
    const resolveTarget = (e) => {
      const t = e.target ?? "";
      if (t.startsWith("~/")) return path.join(home, t.slice(2));
      if (path.isAbsolute(t)) return t;
      return e.cwd ? path.resolve(e.cwd, t) : null;
    };
    add("resolution mismatch (promptDir ⊉ target)", scope.filter((e) => {
      if (e.tool !== "file" || !e.promptDir) return false;
      const t = resolveTarget(e);
      if (!t) return false;
      return t !== e.promptDir && !t.startsWith(e.promptDir + "/");
    }).map((e) => `[@${e.__idx}] target=${trunc(e.target, 70)}  promptDir=${trunc(e.promptDir, 70)}`));
  }

  add("dspa: /tmp write passed floor", scope.filter((e) =>
    e.mode === "dspa" && e.kind === "auto-allow" && e.tool === "bash"
    && (TMP_ARG_RE.test(e.target) || TMP_REDIRECT_RE.test(e.target)) && !HAS_RM_RE.test(e.target))
    .map((e) => `[@${e.__idx}] ${trunc(firstLine(e.target), 100)}`));

  {
    const g = new Map();
    for (const e of scope.filter((x) => x.kind === "prompt")) {
      const k = `${e.tool}|${e.target}`;
      const r = g.get(k) ?? { n: 0, ts: [] };
      r.n++; r.ts.push(e.ts);
      g.set(k, r);
    }
    add("repeated prompts (>=3x)", [...g.entries()].filter(([, r]) => r.n >= 3)
      .map(([k, r]) => `${r.n}x  ${k.split("|")[0]}  ${trunc(k.split("|")[1], 90)}  [${day(r.ts[0])}→${day(r.ts.at(-1))}]`));
  }

  {
    const items = [];
    for (let i = 1; i < scope.length; i++) {
      const a = JSON.stringify({ ...scope[i - 1], __idx: 0, __line: 0, __file: "" });
      const b = JSON.stringify({ ...scope[i], __idx: 0, __line: 0, __file: "" });
      if (a === b) items.push(`[@${scope[i - 1].__idx}]≈[@${scope[i].__idx}]  ${trunc(firstLine(scope[i].target), 90)}`);
    }
    add("duplicate consecutive entries", items);
  }

  add("internal-error blocks (live)", scope.filter((e) => e.kind === "block" && /\[INTERNAL ERROR\]/.test(e.reason ?? "") && e.cwd !== TEST_FIXTURE_CWD)
    .map((e) => `[@${e.__idx}] ${trunc(e.reason, 100)}`));

  {
    const stopped = new Map();
    for (const e of scope) {
      const m = (e.dspa ?? "").match(/untrusted package \(([^)]*)\)/);
      if (!m) continue;
      for (const p of m[1].split(",").map((s) => s.trim())) stopped.set(p, e.__idx);
    }
    const items = [];
    for (const e of scope) {
      if (e.mode !== "dspa" || e.kind !== "auto-allow" || e.tool !== "bash") continue;
      for (const [pkg, at] of stopped) {
        // the stop tag already names the full run form ("npx vitest")
        const re = new RegExp("(?:^|[\\s;&|(`])" + pkg.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "\\b");
        if (re.test(e.target)) { items.push(`${pkg}: stopped [@${at}] → judge-approved [@${e.__idx}]`); stopped.delete(pkg); break; }
      }
    }
    add("trust learning (stop → later approve)", items);
  }

  // 11-14. Invariants — structural rules a correct gate+logger can never
  //  violate. Unlike the checks above (known bug classes), these catch
  //  whatever bug breaks the log's own contract.
  add("invariant: auto-allow with stop tag", scope.filter((e) => e.kind === "auto-allow" && e.dspa)
    .map((e) => `[@${e.__idx}] ${e.dspa}  ${trunc(firstLine(e.target), 80)}`));
  add("invariant: risk:high auto-allowed", scope.filter((e) => e.kind === "auto-allow" && /^risk:high/.test(e.reason ?? ""))
    .map((e) => `[@${e.__idx}] ${trunc(e.reason, 90)}`));
  add("invariant: silent prompt (no reason, no stop tag)", scope.filter((e) => e.kind === "prompt" && !e.reason && !e.dspa)
    .map((e) => `[@${e.__idx}] ${trunc(firstLine(e.target), 80)}`));
  add("invariant: block without reason", scope.filter((e) => e.kind === "block" && !e.reason)
    .map((e) => `[@${e.__idx}] ${trunc(firstLine(e.target), 80)}`));

  // 14. Novelty — the "I changed gate code, what's different?" loop.
  //  Baseline = everything in the file before --since; window = the rest.
  //  (Full file, other filters ignored — a --kind filter would empty the
  //  baseline and make everything "new".)
  if (flags.since) {
    const before = entries.filter((e) => e.ts < flags.since);
    const win = entries.filter((e) => e.ts >= flags.since);
    const uniq = (arr, f) => new Set(arr.map(f));
    // drop the "; cmd …" echo so verdicts group across commands
    const reasonKey = (e) => (e.reason ?? "").split(/; cmd\s/)[0].trim();
    const firstWord = (t) => t.replace(/^(?:cd\s+\S+\s*(?:&&|;)\s*)+/, "").split(/\s+/)[0] ?? "";
    const fileDir = (t) => t.slice(0, t.lastIndexOf("/") + 1) || ".";
    const newVals = (pick, basePred, winPred, f) => {
      const base = uniq(before.filter(basePred), f);
      const seen = new Set();
      const items = [];
      for (const e of win) {
        if (!winPred(e)) continue;
        const v = f(e);
        if (!v || base.has(v) || seen.has(v)) continue;
        seen.add(v);
        items.push(`[@${e.__idx}] ${trunc(v, 100)}`);
      }
      return items;
    };
    add("new prompt reasons since --since", newVals(null, (e) => e.kind === "prompt", (e) => e.kind === "prompt", reasonKey));
    add("new stop tags since --since", newVals(null, (e) => e.dspa, (e) => e.dspa, (e) => e.dspa));
    add("new auto-allowed first-words since --since", newVals(null, (e) => e.kind === "auto-allow" && e.tool === "bash", (e) => e.kind === "auto-allow" && e.tool === "bash", (e) => firstWord(e.target)));
    add("new file target dirs since --since", newVals(null, (e) => e.tool === "file", (e) => e.tool === "file", (e) => fileDir(e.target)));
  }

  return out;
}

function audit() {
  const res = runAudit(F);
  console.log(`# audit — ${F.length} filtered entries`);
  if (!res.length) {
    console.log("\nno anomalies");
    return;
  }
  for (const c of res) {
    console.log(`\n## ${c.label} (${c.items.length})`);
    for (const it of c.items.slice(0, 25)) console.log(`  ${it}`);
    if (c.items.length > 25) console.log(`  … ${c.items.length - 25} more`);
  }
}

function show() {
  const n = Number(pos[1]);
  if (!Number.isInteger(n) || n < 0 || n >= entries.length) {
    console.error(`usage: log-inspect.mjs show <0..${entries.length - 1}>`);
    process.exit(2);
  }
  const e = entries[n];
  const { __line, __file, ...clean } = e;
  console.log(`# entry ${n} (${__file}:${__line})`);
  console.log(JSON.stringify(clean, null, 1));
}

// ── Dispatch ────────────────────────────────────────────────────────────

switch (cmd) {
  case "summary": summary(); break;
  case "list": listCmd(); break;
  case "blocks": blocksCmd(); break;
  case "dspa": flags.reasons ? dspaReasons() : flags.paths ? dspaPaths() : dspaCmd(); break;
  case "stats": stats(); break;
  case "audit": audit(); break;
  case "show": show(); break;
  default:
    console.error(`unknown command: ${cmd}\nusage: node tools/log-inspect.mjs [summary|list|blocks|dspa|stats|audit|show N] [options]`);
    process.exit(2);
}
