import { EvaluationBuilder } from "./builder";
import { EvalCache, RiskEvaluator } from "./types";
import { getFirstWord } from "../segment-helpers";
import {
  getTmuxSubcommand,
  extractTmuxSendKeys,
  isTmuxSendKeysSafe,
  tmuxNewSessionRunsCommand,
  TMUX_SAFE_SUBCOMMANDS,
  TMUX_DANGEROUS_DESCRIPTIONS,
} from "../tmux-helpers";

/**
 * Evaluates tmux commands for dangerous operations.
 */
export const TmuxEvaluator: RiskEvaluator = {
  name: "tmux",
  evaluate(seg, cwd, cache): ReturnType<EvaluationBuilder["build"]> {
    const segment = seg.text;
    const firstWord = cache?.firstWord ?? getFirstWord(segment);
    const b = new EvaluationBuilder();

    if (firstWord !== "tmux") return b.build();

    const tmuxSub = getTmuxSubcommand(segment);
    let isDangerous = !tmuxSub || !TMUX_SAFE_SUBCOMMANDS.has(tmuxSub);

    // new-session/new are safe only when flag-only: an optional [shell-command]
    // argument (or the global -c option) executes code in the new session.
    if (!isDangerous && (tmuxSub === "new-session" || tmuxSub === "new")) {
      if (tmuxNewSessionRunsCommand(segment)) {
        isDangerous = true;
        b.setHigh();
        b.markDanger();
      }
    }

    if (isDangerous) {
      // send-keys inherits session auto-allow: safe keys → auto-allow, unsafe keys → prompt
      if (tmuxSub === "send-keys") {
        const keys = extractTmuxSendKeys(segment);
        if (!keys || !isTmuxSendKeysSafe(keys)) {
          b.setHigh();
          b.markDanger();
        }
      } else {
        b.setHigh();
        b.markDanger();
      }
      if (tmuxSub) {
        const desc = TMUX_DANGEROUS_DESCRIPTIONS[tmuxSub]
          || "not in safe allowlist — may execute code or modify sessions";
        let reason = `tmux ${tmuxSub} (${desc})`;
        if (tmuxSub === "send-keys") {
          const keys = extractTmuxSendKeys(segment);
          if (keys) reason += `\n  → ${keys}`;
        }
        b.addReason(reason);
      }
    }

    return b.build();
  },
};
