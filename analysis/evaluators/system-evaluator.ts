import { EvaluationBuilder } from "./builder";
import { EvalCache, RiskEvaluator } from "./types";
import { getFirstWord } from "../segment-helpers";

/** Check if an arg contains a short flag character (exact match or composite like -if). Rejects long flags. */
function hasShortFlag(arg: string, flagChar: string): boolean {
  if (arg === "-" + flagChar) return true;
  if (arg.startsWith("-") && !arg.startsWith("--") && arg.includes(flagChar)) return true;
  return false;
}

// ── System command handlers ──

/** System command → handler (match, evaluate). */
const SYSTEM_HANDLERS: Array<{ match: (cmd: string) => boolean; evaluate: (cmd: string, rest: string[], b: EvaluationBuilder) => void }> = [
  // sudo
  { match: (c) => c === "sudo",
    evaluate: (_cmd, _rest, b) => { b.addHigh("sudo (privilege escalation)"); } },
  // rm/rmdir/unlink
  { match: (c) => ["rm", "rmdir", "unlink"].includes(c),
    evaluate: (cmd, rest, b) => {
      b.setHigh();
      b.markDanger();
      if (rest.some((a) => hasShortFlag(a, "r") || hasShortFlag(a, "R")))
        b.addReason("recursive delete (-r/-R)");
      if (rest.some((a) => hasShortFlag(a, "f")))
        b.addReason("forced delete (-f)");
    } },
  // chmod/chown
  { match: (c) => c === "chmod" || c === "chown",
    evaluate: (cmd, rest, b) => {
      b.markDanger();
      if (rest.includes("-R") || rest.includes("--recursive")) {
        b.addReason(`${cmd} -R (recursive ${cmd === "chmod" ? "permission" : "ownership"} changes)`);
        b.setHigh();
      } else {
        b.setMedium();
      }
    } },
  // mv/cp
  { match: (c) => c === "mv" || c === "cp",
    evaluate: (cmd, rest, b) => {
      b.markDanger();
      if (rest.some((a) => hasShortFlag(a, "f")) || rest.includes("--force")) {
        b.addMedium(`${cmd} --force/-f (can overwrite files)`);
      } else {
        b.setMedium();
      }
    } },
  // truncate
  { match: (c) => c === "truncate",
    evaluate: (_cmd, _rest, b) => { b.addReason("truncate (in-place size change, can erase contents)"); b.setHigh(); b.markDanger(); } },
  // dd of=
  { match: (c) => c === "dd",
    evaluate: (_cmd, rest, b) => {
      if (rest.some(a => a.startsWith("of="))) {
        b.addReason("dd with output file/device (can overwrite data)");
        b.setHigh();
        b.markDanger();
      }
    } },
  // kill/pkill/killall
  { match: (c) => ["kill", "pkill", "killall"].includes(c),
    evaluate: (cmd, rest, b) => {
      b.addReason(`${cmd} (process termination)`);
      if (rest.includes("-9")) {
        b.setHigh();
        b.markDanger();
        b.addReason("SIGKILL (-9)");
      }
    } },
  // shutdown/reboot
  { match: (c) => ["shutdown", "reboot"].includes(c),
    evaluate: (cmd, _rest, b) => { b.addReason(`${cmd} (system power operation)`); b.setHigh(); b.markDanger(); } },
  // systemctl
  { match: (c) => c === "systemctl",
    evaluate: (_cmd, rest, b) => {
      if (rest.includes("stop") || rest.includes("disable")) {
        b.addReason("systemctl stop/disable (service disruption)");
        b.setMedium();
        b.markDanger();
      }
    } },
];

/**
 * Evaluates system commands: sudo, rm, chmod, chown, mv, cp, kill, shutdown, systemctl, truncate, dd.
 */
export const SystemEvaluator: RiskEvaluator = {
  name: "system",
  evaluate(seg, cwd, cache): ReturnType<EvaluationBuilder["build"]> {
    const segment = seg.text;
    const firstWord = cache?.firstWord ?? getFirstWord(segment);
    const rest = segment.trim().split(/\s+/).slice(1);
    const b = new EvaluationBuilder();

    for (const handler of SYSTEM_HANDLERS) {
      if (handler.match(firstWord)) {
        handler.evaluate(firstWord, rest, b);
        return b.build();
      }
    }

    return b.build();
  },
};
