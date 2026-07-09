import { EvaluationBuilder } from "./builder";
import { EvalCache, RiskEvaluator } from "./types";
import {
  getFirstWord,
  isFindExecWrite,
  isFdExecWrite,
  isRgPreWrite,
} from "../segment-helpers";
import { dangerousFindFlags } from "../../config/bash-patterns";

/** Check if args contain subcommand chain (e.g. s3 rm), skipping global flags like --profile. */
function hasSubcommand(args: string[], ...subcommands: string[]): boolean {
  let idx = 0;
  for (const sub of subcommands) {
    idx = args.indexOf(sub, idx);
    if (idx < 0) return false;
    idx++;
  }
  return true;
}

// ── Tool command handlers ──

interface ToolSegment { text: string; firstWord: string; rest: string[]; ops: string[] }

/** Tool command → handler (match, evaluate). */
const TOOL_HANDLERS: Array<{ match: (seg: ToolSegment) => boolean; reason: string }> = [
  { match: (s) => s.firstWord === "find" && dangerousFindFlags.test(s.text), reason: "find with dangerous flags" },
  { match: (s) => s.firstWord === "find" && isFindExecWrite(s.text), reason: "find -exec with write operation" },
  { match: (s) => s.firstWord === "fd" && isFdExecWrite(s.text), reason: "fd -x with write operation" },
  { match: (s) => s.firstWord === "rg" && isRgPreWrite(s.text), reason: "rg --pre with write operation" },
  { match: (s) => ["curl", "wget"].includes(s.firstWord) && s.ops.includes("|"), reason: "curl/wget piped (possible remote code execution)" },
  { match: (s) => s.firstWord === "kubectl" && s.rest[0] === "delete", reason: "kubectl delete (resource deletion)" },
  { match: (s) => s.firstWord === "terraform" && s.rest[0] === "destroy", reason: "terraform destroy (infrastructure teardown)" },
  { match: (s) => s.firstWord === "aws" && hasSubcommand(s.rest, "s3", "rm") && s.rest.includes("--recursive"), reason: "aws s3 rm --recursive (bulk deletion)" },
  { match: (s) => s.firstWord === "gcloud" && s.rest.includes("delete"), reason: "gcloud delete (resource deletion)" },

  // curl/wget standalone (network access, even without pipe)
  { match: (s) => ["curl", "wget"].includes(s.firstWord), reason: "curl/wget (network access)" },

  // Script interpreters (code execution)
  { match: (s) => /^python[\d.]*$/.test(s.firstWord), reason: "python (script execution)" },
  { match: (s) => s.firstWord === "node", reason: "node (script execution)" },
  { match: (s) => s.firstWord === "ruby", reason: "ruby (script execution)" },
  { match: (s) => s.firstWord === "php", reason: "php (script execution)" },
  { match: (s) => s.firstWord === "lua", reason: "lua (script execution)" },
  { match: (s) => s.firstWord === "uv", reason: "uv (python package manager)" },
  { match: (s) => ["deno", "bun"].includes(s.firstWord), reason: "deno/bun (script execution)" },

  // Package managers/build tools
  { match: (s) => ["yarn", "cargo", "go"].includes(s.firstWord), reason: "yarn/cargo/go (package manager/build tool)" },

  // Archive operations
  { match: (s) => ["tar", "zip", "unzip", "gzip", "gunzip"].includes(s.firstWord),
    reason: "tar/zip/unzip/gzip/gunzip (archive operations)" },
];

/**
 * Evaluates tool commands: find/fd/rg exec, kubectl, terraform, aws, gcloud, curl/wget,
 * script interpreters, package managers, archive operations.
 */
export const ToolEvaluator: RiskEvaluator = {
  name: "tool",
  evaluate(seg, cwd, cache): ReturnType<EvaluationBuilder["build"]> {
    const segment = seg.text;
    const firstWord = cache?.firstWord ?? getFirstWord(segment);
    const rest = segment.trim().split(/\s+/).slice(1);
    const b = new EvaluationBuilder();

    const toolSeg: ToolSegment = { text: segment, firstWord, rest, ops: seg.ops };
    for (const handler of TOOL_HANDLERS) {
      if (handler.match(toolSeg)) {
        b.addHigh(handler.reason);
      }
    }

    return b.build();
  },
};
