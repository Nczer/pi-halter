import { EvaluationBuilder } from "./builder";
import { EvalCache, RiskEvaluator } from "./types";
import {
  getFirstWord,
  isFindExecWrite,
  isFdExecWrite,
  isRgPreWrite,
} from "../segment-helpers";
import {
  dangerousFindFlags,
} from "../../config";

/**
 * Evaluates tool commands: find/fd/rg exec, kubectl, terraform, aws, gcloud, curl/wget pipe.
 */
export const ToolEvaluator: RiskEvaluator = {
  name: "tool",
  evaluate(seg, cwd, cache): ReturnType<EvaluationBuilder["build"]> {
    const segment = seg.text;
    const firstWord = cache?.firstWord ?? getFirstWord(segment);
    const args = segment.trim().split(/\s+/);
    const rest = args.slice(1);
    const b = new EvaluationBuilder();

    // find/fd/rg exec write
    if (firstWord === "find" && dangerousFindFlags.test(segment)) {
      b.addHigh("find with dangerous flags");
    }
    if (firstWord === "find" && isFindExecWrite(segment)) {
      b.addHigh("find -exec with write operation");
    }
    if (firstWord === "fd" && isFdExecWrite(segment)) {
      b.addHigh("fd -x with write operation");
    }
    if (firstWord === "rg" && isRgPreWrite(segment)) {
      b.addHigh("rg --pre with write operation");
    }

    // Remote execution via pipe
    if ((firstWord === "curl" || firstWord === "wget") && seg.ops.includes("|")) {
      b.addHigh("curl/wget piped (possible remote code execution)");
    }

    // Infra deletes
    if (firstWord === "kubectl" && rest[0] === "delete") b.addHigh("kubectl delete (resource deletion)");
    if (firstWord === "terraform" && rest[0] === "destroy") b.addHigh("terraform destroy (infrastructure teardown)");
    if (firstWord === "aws" && awsHasSubcommand(rest, "s3", "rm") && rest.includes("--recursive"))
      b.addHigh("aws s3 rm --recursive (bulk deletion)");
    if (firstWord === "gcloud" && rest.includes("delete")) b.addHigh("gcloud delete (resource deletion)");

    return b.build();
  },
};

/** Check if AWS args contain subcommand chain (e.g. s3 rm), skipping global flags like --profile. */
function awsHasSubcommand(args: string[], ...subcommands: string[]): boolean {
  let idx = 0;
  for (const sub of subcommands) {
    idx = args.indexOf(sub, idx);
    if (idx < 0) return false;
    idx++;
  }
  return true;
}
