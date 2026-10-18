/**
 * LIVE wire probe — the judge's per-sample tool-call rate on a real engine.
 *
 * Skipped unless HALTER_LIVE_WIRE=1: it spends real generations on the judge
 * model. Everything is production except one knob: the real `stream` seam is
 * wrapped to force `toolChoice` per arm, so the A/B measures what the ledger
 * never can — the ledger records only the LAST failing sample of a judge call
 * (judge() retries, gate/decision-log.ts), and never logs a successful call's
 * usage. Packets are real stage-2 commands from the 2026-10-17 ledger (an
 * untrusted-script payload + a session-context section).
 *
 *   HALTER_LIVE_WIRE=1 ../node_modules/.bin/vitest run test/live-judge-wire.test.ts
 *   HALTER_LIVE_WIRE_N=6 … samples per arm (default 4)
 *   HALTER_LIVE_WIRE_ARMS=auto,required … default both
 */
import { describe, it, expect } from "vitest";
import path from "node:path";
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { ModelRuntime, ModelRegistry } from "@earendil-works/pi-coding-agent";
import { stream } from "@earendil-works/pi-ai/compat";
import type { AssistantMessage } from "@earendil-works/pi-ai";
import {
  judge,
  JUDGE_STAGE2_SYSTEM_PROMPT,
  readJudgeSettings,
  resolveJudgeAuth,
  type JudgeStreamFn,
} from "../judge/judge";
import { buildJudgmentPacket, type JudgmentBashInput } from "../judge/packet";
import { buildSessionContext } from "../judge/session-context";
import { analyzeCommand } from "../analysis/command-analysis";
import { findExecutedScript } from "../analysis/script-payload";
import { expandTilde } from "../analysis/path-util";
import { createStore } from "../gate/store";

const LIVE = process.env.HALTER_LIVE_WIRE === "1";
const N = Number(process.env.HALTER_LIVE_WIRE_N ?? 4);
const ARMS = (process.env.HALTER_LIVE_WIRE_ARMS ?? "auto,required").split(",");

/** A real stage-2 command from the 2026-10-17 ledger: heredoc patch of an
 *  untrusted local script, then run it. cwd as recorded. */
const CMD =
  "cd /tmp && python3 - <<'EOF'\nsrc=open('mdan.py').read()\nsrc=src.replace(\"\"\"    try:\n        return b.split(b'\\\\0')[0].decode('utf-8')\n    except UnicodeDecodeError:\n        return b.decode('utf-16-le', 'replace')\"\"\",\n\"\"\"    s = b.decode('utf-16-le', 'replace')\n    if '\\\\x00' in s or len(s) > n:\n        s = b.decode('utf-8', 'replace')\n    return s.split('\\\\x00')[0]\"\"\")\nopen('mdan.py','w').write(src)\nEOF\npython3 /tmp/mdan.py /mnt/Ndr/crash_20261017203454_61.dmp > /tmp/out.txt 2>&1; tr -d '\\000' < /tmp/out.txt | sed -n '1,25p'";
const CWD = "/mnt/Ndr/Projects";

/** Session context in buildSessionContext's shape, sized like that session's. */
function fakeCtx() {
  const user = (text: string) => ({ type: "message", message: { role: "user", content: text } });
  const call = (name: string, args: Record<string, unknown>) => ({
    type: "message",
    message: { role: "assistant", content: [{ type: "toolCall", name, arguments: args }] },
  });
  return {
    sessionManager: {
      getBranch: () => [
        user("the steam client crashed again, /mnt/Ndr/crash_20261017203454_61.dmp — analyze it"),
        call("bash", { command: "ls -la /mnt/Ndr/crash_20261017203454_61.dmp" }),
        call("bash", { command: "file /mnt/Ndr/crash_20261017203454_61.dmp" }),
        user("it is a breakpad minidump, parse the streams yourself"),
        call("bash", { command: "cd /tmp && python3 mdparse.py /mnt/Ndr/crash_20261017203454_61.dmp" }),
        call("write", { path: "/tmp/mdan.py" }),
        call("bash", { command: "cd /tmp && python3 mdan.py /mnt/Ndr/crash_20261017203454_61.dmp" }),
        user("find which module the crash happened in"),
      ],
    },
  };
}

/** One generated reply, as the ledger would never show it. */
function describeReply(reply: AssistantMessage): string {
  const u = reply.usage;
  const bits = [
    `stop=${reply.stopReason}/${(reply as { rawStopReason?: string }).rawStopReason ?? "?"}`,
    (reply as { errorMessage?: string }).errorMessage
      ? `error="${String((reply as { errorMessage?: string }).errorMessage).replace(/\s+/g, " ").slice(0, 200)}"`
      : "",
    `parts=${reply.content.map((p) => p.type).join(",") || "none"}`,
    u ? `out=${u.output} in=${u.input} cache=${u.cacheRead}${u.reasoning !== undefined ? ` think=${u.reasoning}` : ""}` : "usage=none",
  ];
  const call = reply.content.find((p) => p.type === "toolCall") as
    | { name?: string; arguments?: Record<string, unknown> }
    | undefined;
  if (call) bits.push(`call=${call.name}(${Object.keys(call.arguments ?? {}).join(",")})`);
  for (const p of reply.content) {
    if (p.type === "toolCall") continue;
    const body = p.type === "text" ? p.text : p.type === "thinking" ? p.thinking : "";
    const head = body.replace(/\s+/g, " ").trim().slice(0, 60);
    if (head) bits.push(`${p.type}="${head}"`);
  }
  return bits.join(" ");
}

describe.runIf(LIVE)("live judge wire — toolChoice A/B", () => {
  it(
    "forces the verdict call or proves it cannot be forced",
    async () => {
      const settings = readJudgeSettings();
      // Halter follows the session model when provider/model are null; a
      // standalone probe has no session, so the target is named here. Default =
      // the model of every 2026-10-17 `no-tool-call` line.
      const [pid, mid] = (process.env.HALTER_LIVE_WIRE_MODEL ?? "llama-cpp-remote/Qwen3.8-Flash-Next").split("/");
      const runtime = await ModelRuntime.create();
      const registry = new ModelRegistry(runtime);
      // The local providers are registered by the llama-link extension, which
      // no extension host runs here; re-register from pi's persisted catalog so
      // the model object is the same one production resolves.
      if (!registry.find(pid, mid)) {
        const catalog = JSON.parse(
          readFileSync(join(homedir(), ".pi", "agent", "models-store.json"), "utf8"),
        ) as Record<string, { models: unknown[] }>;
        const entry = catalog[pid];
        if (entry) {
          // apiKey = llama-link's placeholder for auth-less local servers
          // (auth.json holds no credential for these providers).
          registry.registerProvider(pid, {
            baseUrl: (entry.models as { baseUrl?: string }[])[0]?.baseUrl,
            apiKey: "sk-placeholder",
            models: entry.models as never,
          });
        }
      }
      const model = registry.find(pid, mid) ?? null;
      expect(model, "judge model unresolved — the probe measured nothing").not.toBeNull();
      const auth = await resolveJudgeAuth(model!, registry as never);
      expect(auth, "judge auth failed — the probe measured nothing").not.toBeNull();

      // Same packet for every arm: production input shape (verdict.ts
      // buildJudgmentInput's bash branch).
      const store = createStore();
      const analysis = await analyzeCommand(CMD, CWD, {
        isInsideAllowedDir: () => false,
        getConfirmedResolution: () => null,
      });
      let effectiveBase: string | null = null;
      for (const b of analysis.effectiveCwds) {
        if (b !== null && b !== path.resolve(expandTilde(CWD))) effectiveBase = b;
      }
      const input: JudgmentBashInput = {
        command: CMD,
        cwd: CWD,
        segments: analysis.segments,
        riskReasons: analysis.risk.reasons,
        severity: analysis.risk.severity,
        hasUnsafePattern: analysis.safety.hasUnsafePattern,
        hasParseError: analysis.hasParseError,
        credentialRule: null,
        paths: analysis.paths,
        outsidePaths: analysis.prompt.outsidePaths ?? [],
        script: findExecutedScript(analysis, CWD),
        effectiveBase,
      };
      const extraPacket = buildSessionContext(fakeCtx() as never, store);
      console.log(`model=${model!.provider}/${model!.id} thinking=${settings.thinking} packet=${buildJudgmentPacket(input).length + extraPacket.length}ch`);

      const tally: Record<string, { samples: number; calls: number; fails: string[] }> = {};
      for (const choice of ARMS) {
        const seen: string[] = [];
        const seam: JudgeStreamFn = (m, ctx, opts) => {
          // pi's own ToolChoice type is only "auto"|"none"; the adapters
          // accept the wire's own vocabulary, so the option is untyped here.
          const s = stream(m, ctx, { ...opts, toolChoice: choice } as never);
          const orig = s.result.bind(s);
          s.result = (async () => {
            const r = await orig();
            seen.push(describeReply(r));
            return r;
          }) as typeof s.result;
          return s;
        };
        const stats = { samples: 0, calls: 0, fails: [] as string[] };
        for (let i = 0; i < N; i++) {
          seen.length = 0;
          const r = await judge(input, {
            model: model!,
            stream: seam,
            apiKey: auth!.apiKey,
            headers: auth!.headers,
            timeoutMs: settings.timeoutMs * 3, // STAGE2_TIMEOUT_FACTOR
            thinking: settings.thinking,
            systemPrompt: JUDGE_STAGE2_SYSTEM_PROMPT,
            extraPacket,
            uncached: true,
          });
          for (const s of seen) {
            stats.samples++;
            stats.calls += /parts=.*toolCall/.test(s) ? 1 : 0;
            console.log(`[${choice} #${stats.samples}] ${s}`);
          }
          if (r.failReason) stats.fails.push(`${r.failReason}${r.attempts ? `(a${r.attempts})` : ""}`);
        }
        tally[choice] = stats;
      }
      for (const choice of ARMS) {
        const s = tally[choice];
        expect(s.samples, `arm ${choice}: zero samples — no call reached the engine`).toBeGreaterThan(0);
        console.log(
          `SUMMARY ${choice}: tool-calls ${s.calls}/${s.samples} samples; judge-call fails: ${s.fails.join(", ") || "none"}`,
        );
      }
    },
    900_000,
  );
});
