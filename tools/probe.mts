import { decide } from "../decision-engine";
import { createStore } from "../store";

const CWD = "/mnt/Ndr/Projects";
const cmds = process.argv.slice(2);
if (!cmds.length) {
  console.log("usage: npx tsx tools/probe.mts <command> [command2 ...]");
  process.exit(1);
}
for (const command of cmds) {
  const d = await decide({ type: "bash", command, cwd: CWD }, createStore());
  if (d.kind === "prompt") {
    const pd = d.promptData;
    console.log(`PROMPT   ${command}\n  outsideDirs=${JSON.stringify(pd.outsideDirs)} needsPath=${pd.needsPathApproval} needsCmd=${pd.needsCommandApproval} sigs=${JSON.stringify(pd.signatures)} risk=${pd.riskSeverity} danger=${pd.riskDangerous} unsafe=${pd.hasUnsafePattern}`);
  } else if (d.kind === "block") {
    console.log(`BLOCK    ${command}\n  ${d.reason}`);
  } else {
    console.log(`ALLOW    ${command}`);
  }
}
