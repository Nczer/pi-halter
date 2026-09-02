import { EvaluationBuilder } from "./builder";
import { EvalCache, RiskEvaluator } from "./types";
import { getFirstWord } from "../segment-helpers";
import {
  parseTmuxCommand,
  tmuxNewSessionCommand,
  TMUX_SAFE_SUBCOMMANDS,
  TMUX_DANGEROUS_DESCRIPTIONS,
} from "../tmux";

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

    const tmux = parseTmuxCommand(segment);
    const tmuxSub = tmux.subcommand;

    // send-keys: the evaluator does NOT judge payload content. The payload is
    // analyzed by the full pipeline (analyzeTmuxSendKeysPayload in
    // command-analysis.ts) — each Enter-terminated chunk meets the same
    // auto-allow bar as a direct command, with per-chunk reasons folded into
    // the command risk tagged [TmuxPayload]. A send-keys with no payload is a
    // harmless no-op (tmux itself rejects it).
    if (tmuxSub === "send-keys") return b.build();

    let isDangerous = !tmuxSub || !TMUX_SAFE_SUBCOMMANDS.has(tmuxSub);

    // new-session (and its "new"/"start" aliases, canonicalized by the parse)
    // is safe only when flag-only: an optional [shell-command] argument (or
    // the global -c option) executes code in the new session.
    if (!isDangerous && tmuxNewSessionCommand(tmux) !== null) {
      isDangerous = true;
      b.setHigh();
      b.markDanger();
    }

    if (isDangerous) {
      b.setHigh();
      b.markDanger();
      if (tmuxSub) {
        const desc = TMUX_DANGEROUS_DESCRIPTIONS[tmuxSub]
          || "not in safe allowlist — may execute code or modify sessions";
        b.addReason(`tmux ${tmuxSub} (${desc})`);
      }
    }

    return b.build();
  },
};
