import { EvaluatorResult, EvalCache, RiskEvaluator } from "./types";
import { getFirstWord } from "../segment-helpers";
import {
  getTmuxSubcommand,
  extractTmuxSendKeys,
  isTmuxSendKeysSafe,
  TMUX_SAFE_SUBCOMMANDS,
  TMUX_DANGEROUS_DESCRIPTIONS,
} from "../tmux-helpers";

/**
 * Evaluates tmux commands for dangerous operations.
 */
export const TmuxEvaluator: RiskEvaluator = {
  name: "tmux",
  evaluate(seg, cwd, cache): EvaluatorResult {
    const segment = seg.text;
    const firstWord = cache?.firstWord ?? getFirstWord(segment);
    const reasons: string[] = [];
    let severity: "high" | "medium" | null = null;
    let hasDanger = false;
    const setSeverity = (s: "high" | "medium") => {
      if (s === "high" || !severity) severity = s;
    };

    if (firstWord !== "tmux") return { reasons, severity, hasDanger, isSimple: undefined };

    const tmuxSub = getTmuxSubcommand(segment);
    const isDangerous = !tmuxSub || !TMUX_SAFE_SUBCOMMANDS.has(tmuxSub);
    if (isDangerous) {
      // send-keys inherits session auto-allow: safe keys → auto-allow, unsafe keys → prompt
      if (tmuxSub === "send-keys") {
        const keys = extractTmuxSendKeys(segment);
        if (!keys || !isTmuxSendKeysSafe(keys)) {
          hasDanger = true;
          setSeverity("high");
        }
      } else {
        hasDanger = true;
        setSeverity("high");
      }
      if (tmuxSub) {
        const desc = TMUX_DANGEROUS_DESCRIPTIONS[tmuxSub]
          || "not in safe allowlist — may execute code or modify sessions";
        let reason = `tmux ${tmuxSub} (${desc})`;
        if (tmuxSub === "send-keys") {
          const keys = extractTmuxSendKeys(segment);
          if (keys) reason += `\n  → ${keys}`;
        }
        reasons.push(reason);
      }
    }

    return { reasons, severity, hasDanger, isSimple: undefined };
  },
};
