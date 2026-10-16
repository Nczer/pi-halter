import { EvaluationBuilder } from "./builder";
import { EvalCache, EvaluatorResult, RiskEvaluator } from "./types";
import {
  getFirstWord,
  isFindExecWrite,
  isFdExecWrite,
  isRgPreWrite,
  stripQuotedStrings,
} from "../segment-helpers";
import { dangerousFindFlags } from "../../config/bash-patterns";
import { tokenizeSegment } from "../tokenizer";
import { sedScriptArgIndices } from "../bash-parser";

/**
 * sed -f / --file: the script comes from a FILE, which can contain `s///e`
 * (execute the pattern space as a shell command) and `w file` (arbitrary
 * write) — both invisible on the command line. Any -f form must prompt.
 * `-f` may sit in a flag cluster (last letter, value follows); long forms are
 * --file / --file=script.
 */
const SED_SCRIPT_FILE_FLAG_RE = /^(?:-[a-zA-Z]*f|--file(?:=\S+)?)$/;

/**
 * The sed `e` flag on an s command executes the replacement text as a shell
 * command (`sed 's/x/echo pwned/e' file`, `sed 's|x|id|e' file`,
 * `sed '1s/x/id/e' file`, `sed '{s/x/id/e}' file`). Any non-word/whitespace
 * delimiter may be used (`\1` backreference), and `e` must sit in the final
 * flag group after the closing delimiter. `s/a/b/bee/` does not match.
 */
const SED_S_EXEC_RE = /(?:^|[;\s{}0-9$,/!])s([^\w\s\\])(?:\\.|(?!\1)[\s\S])*?\1(?:\\.|(?!\1)[\s\S])*?\1[gipmI0-9]*e[gipmI0-9]*(?:$|[;\s}])/;

/**
 * GNU sed standalone `e` command (`sed 'e id' file`, `sed 'e' file`,
 * `sed '1e id' file`, `sed '/pat/e id' file`) — executes the command (or the
 * pattern space when no command follows) in `/bin/sh`. Checked on sed script
 * tokens only so a file operand named `e` is never mistaken for the command.
 */
const SED_E_CMD_RE = /(?:^|[;\n{])\s*(?:\d+|\/(?:\\.|[^/])*\/|\$)?\s*!?\s*e(?:\s+\S|$|[;\n}])/;

function hasSedExecCommand(segment: string): boolean {
  const tokens = tokenizeSegment(segment);
  if (tokens.some(t => SED_S_EXEC_RE.test(t))) return true;
  const args = tokens.slice(1);
  for (const idx of sedScriptArgIndices(args)) {
    let script = args[idx] ?? "";
    if (script.startsWith("--expression=")) script = script.slice("--expression=".length);
    else if (script.startsWith("-") && !script.startsWith("--")) {
      const eIdx = script.indexOf("e");
      if (eIdx > 0 && eIdx < script.length - 1) script = script.slice(eIdx + 1);
    }
    if (SED_S_EXEC_RE.test(script) || SED_E_CMD_RE.test(script)) return true;
  }
  return false;
}

/** Read-only interpreter invocation: `python3 --version` / `node --help`. */
function isVersionOnly(rest: string[]): boolean {
  return rest.length === 1 && (rest[0] === "--version" || rest[0] === "--help");
}

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
  { match: (s) => s.firstWord === "find" && dangerousFindFlags.test(stripQuotedStrings(s.text)), reason: "find with dangerous flags" },
  { match: (s) => s.firstWord === "find" && isFindExecWrite(s.text), reason: "find -exec with write operation" },
  { match: (s) => s.firstWord === "fd" && isFdExecWrite(s.text), reason: "fd -x with write operation" },
  { match: (s) => s.firstWord === "rg" && isRgPreWrite(s.text), reason: "rg --pre with write operation" },
  { match: (s) => s.firstWord === "sed" && tokenizeSegment(s.text).slice(1).some(t => SED_SCRIPT_FILE_FLAG_RE.test(t)), reason: "sed -f (script file can execute commands and write files)" },
  { match: (s) => s.firstWord === "sed" && hasSedExecCommand(s.text), reason: "sed s///e (executes replacement as a shell command)" },
  { match: (s) => ["curl", "wget"].includes(s.firstWord) && s.ops.includes("|"), reason: "curl/wget piped (possible remote code execution)" },
  { match: (s) => s.firstWord === "kubectl" && s.rest[0] === "delete", reason: "kubectl delete (resource deletion)" },
  { match: (s) => s.firstWord === "terraform" && s.rest[0] === "destroy", reason: "terraform destroy (infrastructure teardown)" },
  { match: (s) => s.firstWord === "aws" && hasSubcommand(s.rest, "s3", "rm") && s.rest.includes("--recursive"), reason: "aws s3 rm --recursive (bulk deletion)" },
  { match: (s) => s.firstWord === "gcloud" && s.rest.includes("delete"), reason: "gcloud delete (resource deletion)" },

  // curl/wget standalone (network access, even without pipe)
  { match: (s) => ["curl", "wget"].includes(s.firstWord), reason: "curl/wget (network access)" },

  // Script interpreters (code execution). `--version`/`--help` as the sole
  // argument is read-only (no -c, no script file) — exempted.
  { match: (s) => /^python[\d.]*$/.test(s.firstWord) && !isVersionOnly(s.rest), reason: "python (script execution)" },
  { match: (s) => s.firstWord === "node" && !isVersionOnly(s.rest), reason: "node (script execution)" },
  { match: (s) => s.firstWord === "ruby", reason: "ruby (script execution)" },
  // perl gets no exemption and no -i precondition: the program body (`-e`,
  // or a script file) is arbitrary code — `open`/`unlink`/`system` write
  // without any -i flag, and filter mode (-n/-p) is not a read-only
  // guarantee. The config layer already asserts this (perl is in
  // SCRIPT_INTERPRETERS → isWriteOperation is true for every invocation,
  // config/bash-patterns.ts); the risk layer had no matching rule, so a
  // bare `perl -e …` reached auto-allow and never met the gate.
  { match: (s) => /^perl[\d.]*$/.test(s.firstWord), reason: "perl (script execution)" },
  { match: (s) => s.firstWord === "php", reason: "php (script execution)" },
  { match: (s) => s.firstWord === "lua", reason: "lua (script execution)" },
  { match: (s) => s.firstWord === "uv" && !isVersionOnly(s.rest), reason: "uv (python package manager)" },
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
  evaluate(seg, cwd, cache): EvaluatorResult {
    const segment = seg.text;
    const firstWord = cache?.firstWord ?? getFirstWord(segment);
    const rest = segment.trim().split(/\s+/).slice(1);
    const b = new EvaluationBuilder();

    const toolSeg: ToolSegment = { text: segment, firstWord, rest, ops: seg.ops };
    for (const handler of TOOL_HANDLERS) {
      if (handler.match(toolSeg)) {
        b.high(handler.reason);
      }
    }

    return b.build();
  },
};
