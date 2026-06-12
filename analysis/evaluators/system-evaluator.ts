import { EvaluatorResult, RiskEvaluator } from "./types";
import { getFirstWord } from "../segment-helpers";

/**
 * Evaluates system commands: sudo, rm, chmod, chown, mv, cp, kill, shutdown, systemctl, truncate, dd.
 */
export const SystemEvaluator: RiskEvaluator = {
  name: "system",
  evaluate(seg, cwd): EvaluatorResult {
    const segment = seg.text;
    const firstWord = getFirstWord(segment);
    const args = segment.trim().split(/\s+/);
    const rest = args.slice(1);
    const reasons: string[] = [];
    let severity: "high" | "medium" | null = null;
    let hasDanger = false;
    const setSeverity = (s: "high" | "medium") => {
      if (s === "high" || !severity) severity = s;
    };

    // sudo
    if (firstWord === "sudo") {
      reasons.push("sudo (elevated privileges)");
      setSeverity("high");
    }

    // rm/rmdir/unlink
    if (firstWord === "rm" || firstWord === "rmdir" || firstWord === "unlink") {
      setSeverity("high");
      if (rest.some((a) => a.includes("-r") || a.includes("-R"))) reasons.push("recursive delete (-r/-R)");
      if (rest.some((a) => a.includes("-f"))) reasons.push("forced delete (-f)");
    }

    // chmod/chown
    if (firstWord === "chmod" || firstWord === "chown") {
      if (rest.includes("-R") || rest.includes("--recursive")) {
        setSeverity("high");
        reasons.push(`${firstWord} -R (recursive ${firstWord === "chmod" ? "permission" : "ownership"} changes)`);
      } else {
        setSeverity("medium");
      }
    }

    // mv/cp
    if (firstWord === "mv" || firstWord === "cp") {
      if (rest.includes("-f") || rest.includes("--force")) {
        setSeverity("medium");
        reasons.push(`${firstWord} --force/-f (can overwrite files)`);
      } else {
        setSeverity("medium");
      }
    }

    // truncate
    if (firstWord === "truncate") {
      reasons.push("truncate (in-place size change, can erase contents)");
      setSeverity("high");
    }

    // dd of=
    if (firstWord === "dd" && anyArgStartsWith(rest, "of=")) {
      setSeverity("high");
      reasons.push("dd with output file/device (can overwrite data)");
    }

    // kill/shutdown/systemctl
    if (["kill", "pkill", "killall"].includes(firstWord)) {
      reasons.push(`${firstWord} (process termination)`);
      if (rest.includes("-9")) { setSeverity("high"); reasons.push("SIGKILL (-9)"); }
    }
    if (["shutdown", "reboot"].includes(firstWord)) {
      setSeverity("high");
      reasons.push(`${firstWord} (system power operation)`);
    }
    if (firstWord === "systemctl" && (rest.includes("stop") || rest.includes("disable"))) {
      reasons.push("systemctl stop/disable (service disruption)");
      setSeverity("medium");
    }

    return { reasons, severity, hasDanger, isSimple: undefined };
  },
};

function anyArgStartsWith(args: string[], prefix: string): boolean {
  return args.some(a => a.startsWith(prefix));
}
