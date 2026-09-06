import { parseCommand } from "../analysis/bash-parser";
const cmd = process.argv[2] ?? "echo A; echo B & echo C && echo D";
const p = await parseCommand(cmd, "/tmp");
for (const s of p.segments) console.log(JSON.stringify({ text: s.text, op: s.precedingOp, bg: s.backgrounded ?? false }));
