import { EvaluatorResult, RiskEvaluator } from "./types";
import { getFirstWord } from "../segment-helpers";
import {
  dangerousFindFlags,
  isWriteOperation,
} from "../../config";

/**
 * Evaluates tool commands: find/fd/rg exec, kubectl, terraform, aws, gcloud, curl/wget pipe.
 */
export const ToolEvaluator: RiskEvaluator = {
  name: "tool",
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

    // find/fd/rg exec write
    if (firstWord === "find" && dangerousFindFlags.test(segment)) {
      hasDanger = true;
      reasons.push("find with dangerous flags");
      setSeverity("high");
    }
    if (firstWord === "find" && isFindExecWrite(segment)) {
      hasDanger = true;
      reasons.push("find -exec with write operation");
      setSeverity("high");
    }
    if (firstWord === "fd" && isFdExecWrite(segment)) {
      hasDanger = true;
      reasons.push("fd -x with write operation");
      setSeverity("high");
    }
    if (firstWord === "rg" && isRgPreWrite(segment)) {
      hasDanger = true;
      reasons.push("rg --pre with write operation");
      setSeverity("high");
    }

    // Remote execution via pipe
    if ((firstWord === "curl" || firstWord === "wget") && seg.ops.includes("|")) {
      setSeverity("high");
      hasDanger = true;
      reasons.push("curl/wget piped (possible remote code execution)");
    }

    // Infra deletes
    if (firstWord === "kubectl" && rest[0] === "delete") { setSeverity("high"); reasons.push("kubectl delete (resource deletion)"); }
    if (firstWord === "terraform" && rest[0] === "destroy") { setSeverity("high"); reasons.push("terraform destroy (infrastructure teardown)"); }
    if (firstWord === "aws" && rest[0] === "s3" && rest[1] === "rm" && rest.includes("--recursive")) { setSeverity("high"); reasons.push("aws s3 rm --recursive (bulk deletion)"); }
    if (firstWord === "gcloud" && rest.includes("delete")) { setSeverity("high"); reasons.push("gcloud delete (resource deletion)"); }

    return { reasons, severity, hasDanger, isSimple: undefined };
  },
};

function isFindExecWrite(segment: string): boolean {
  const execMatch = segment.match(/-(?:exec|execdir)\b\s+(\S+)/);
  if (!execMatch) return false;
  const cmd = execMatch[1];
  return isWriteOperation(cmd, segment);
}

function isFdExecWrite(segment: string): boolean {
  const execMatch = segment.match(/-(?:x|X)\b\s+(\S+)/);
  if (!execMatch) return false;
  const cmd = execMatch[1];
  return isWriteOperation(cmd, segment);
}

function isRgPreWrite(segment: string): boolean {
  const preMatch = segment.match(/--pre\s+(\S+)/);
  if (!preMatch) return false;
  const cmd = preMatch[1];
  return isWriteOperation(cmd, segment);
}
