/**
 * The bytes a copy moves (D26).
 *
 * A file write carries its new content to the judge. `cp probe.test.ts test/`
 * has the same effect — this file's bytes appear at that path — and the packet
 * said nothing about them: the judge approved copies it had never seen (10 of
 * the 12 copy-class commands in one session's ledger) and deferred on the rest
 * for exactly that reason ("missing information"). Under the judge's own rule —
 * approve only what is fully verifiable — an invisible payload is not a
 * judgment either way.
 *
 * So when a command makes an existing local file's bytes appear at another
 * path, halter reads the source and the packet carries it WHOLE. Whole, per
 * D11: a trimmed payload made the judge defer on safe long writes, and half a
 * file is the same failure with more confidence. A file is either shown entire
 * or named with the reason it is not.
 *
 * What is never read (and says so in the packet):
 *   - a source the credential scan matches. The path plus the matched rule is
 *     the fact the judge needs; the bytes would put a secret in front of a
 *     model that cannot stop the copy anyway (a credential stop is advisory,
 *     and its packet is still sent).
 *   - pseudo-files (/proc, /sys, /dev): a read there can hang or balloon.
 *   - more than MAX_MOVED_FILE_BYTES in one file, or more than MAX_MOVED_FILES
 *     in one command — this read happens while the operator waits for a verdict.
 *   - folders and archives (`cp -r dir dest`, `tar x`): named with their file
 *     count. Their payload is not one file's bytes, and walking one reads far
 *     more material than the command's name suggests.
 *   - a source whose location the analysis cannot resolve — named as
 *     unresolvable, which is itself a fact worth a verdict.
 *
 * The read lives HERE, in the caller, not in the packet builder: the packet
 * must stay pure and deterministic — same input, same bytes (judge/packet.ts).
 * Which operand is the destination comes from the write-role table, and the
 * command identity from the parser's own wrapper-transparent walk, so one stage
 * is the same stage to the bar, the packet and the shell.
 */
import fs from "node:fs";
import path from "node:path";
import { expandTilde } from "./path-util";
import { tokenizeSegmentQuoted, type QuotedToken } from "./tokenizer";
import { stageCommand } from "./cwd-tracking";
import { locationOperandIndices, writeOperandIndices } from "./write-roles";
import { nonFileArgIndices } from "./bash-parser";
import { isPathWarnedResolved } from "./path-analysis";
import type { CommandAnalysis } from "./command-analysis";

/** The line the file pre-reads already use (handlers/file): above it a read
 *  stalls the TUI — and here it stalls a verdict. Named, not read. */
export const MAX_MOVED_FILE_BYTES = 1024 * 1024;
/** One command's worth of payload. A copy that moves more than this is bulk by
 *  any name, and bulk is the floor's business, not the packet's. */
export const MAX_MOVED_FILES = 8;

/** The verbs whose job is moving a file's bytes to a named destination — the
 *  write-role table's WRITE_LAST family, minus `ln`, which creates a name and
 *  moves no content at all. `split` belongs: it writes the source's bytes out
 *  again, in pieces named after its prefix argument. */
const CONTENT_MOVING = new Set(["cp", "mv", "install", "split"]);

/** A stage that writes a file's bytes to a redirect target unchanged. */
const PASTHROUGH = new Set(["cat", "dd"]);

/** Nothing useful (or safe) to read: device nodes, /proc/self/environ, fifos. */
const NEVER_READ_RE = /^\/(?:proc|sys|dev)(?:\/|$)/;

/** A glob or brace in an UNQUOTED token — the shell will expand it, so the
 *  sources are whatever matches (and `unquotedGlob` says it is not literal). */
const GLOB_RE = /[*?[\]{}]/;

/** `>`, `>>`, `2>`, `<`, `&>`: an operator token (a quoted one is an operand).
 *  A heredoc (`<<`, `<<-`) is deliberately NOT here — its body is already in
 *  the command text, which the packet carries in full. */
const REDIRECT_OP_RE = /^(?:\d*&?>{1,2}|\d*&?<)$/;

export interface MovedFile {
  /** The source as the disk spells it (a glob match is realpath'ed). */
  source: string;
  /** Where the bytes land. Null when the shell's rule does not make it certain
   *  (`split` names its outputs by prefix; an unresolvable destination too). */
  dest: string | null;
  /** Size on disk; null when there was nothing to stat. */
  bytes: number | null;
  /** The file's text, WHOLE — or null when it was not read (see `note`). */
  content: string | null;
  /** Why the content is absent, in the operator's words. */
  note: string | null;
  /** The destination already holds a file, which this replaces. */
  overwrites: boolean;
}

export interface MovedContent {
  files: MovedFile[];
  /** Sources past MAX_MOVED_FILES — counted, not named. */
  omitted: number;
}

/** A destination operand, resolved as far as the shell's rule goes. */
interface DestInfo {
  path: string | null;
  /** It names a directory (trailing slash, or a directory on disk): every
   *  source lands inside it under its own name. */
  isDir: boolean;
}

/**
 * What this command moves into existence, read from disk. Null — cheaply — for
 * a command that moves no file bytes, which is most of them: the fs work
 * happens only where a verdict would otherwise be blind.
 */
export function findMovedContent(analysis: CommandAnalysis, cwd: string): MovedContent | null {
  const files: MovedFile[] = [];
  let seen = 0;

  for (let i = 0; i < analysis.stageTexts.length; i++) {
    // A pipeline runs in one directory: the segment's effective base, which is
    // what the parser resolved its relatives against. A NULL base (an
    // unresolvable `cd`) is passed through as such: guessing the session cwd
    // here would show the judge some other file's bytes as this copy's payload.
    const base = i < analysis.effectiveCwds.length ? analysis.effectiveCwds[i] : cwd;
    for (const stageText of analysis.stageTexts[i]) {
      for (const moved of movedInStage(stageText, base)) {
        seen++;
        if (files.length < MAX_MOVED_FILES) files.push(moved);
      }
    }
  }

  return files.length > 0 ? { files, omitted: seen - files.length } : null;
}

/** The copies one stage performs. */
function movedInStage(stageText: string, base: string | null): MovedFile[] {
  const tokens = tokenizeSegmentQuoted(stageText);
  const stage = stageCommand(tokens.map((t) => t.text));
  if (stage.capped || !stage.cmd) return [];

  // Split the stage into the program's operands and the shell's redirects. A
  // redirect target is an operand of the SHELL, not of the program, so the role
  // table never sees it — and the role functions index the program's arguments.
  const operands: QuotedToken[] = [];
  let outTarget: QuotedToken | null = null;
  let inTarget: QuotedToken | null = null;
  for (let k = stage.index + 1; k < tokens.length; k++) {
    const t = tokens[k];
    if (!t.quoted && REDIRECT_OP_RE.test(t.text)) {
      const target = tokens[k + 1];
      if (target && !target.quoted) {
        if (t.text.includes(">")) outTarget = target;
        else inTarget = target;
        k++;
      }
      continue;
    }
    operands.push(t);
  }

  const args = operands.map((t) => t.text);
  const skip = nonFileArgIndices(stage.cmd, args);

  if (CONTENT_MOVING.has(stage.cmd)) {
    const destIdx = writeOperandIndices(stage.cmd, args, skip);
    const sources = locationOperandIndices(stage.cmd, args, skip).filter((k) => !destIdx.has(k));
    const dests = [...destIdx].map((k) => describeDest(operands[k], base));
    const out: MovedFile[] = [];
    for (const k of sources) out.push(...expandSource(operands[k], base, dests, stage.cmd));
    return out;
  }

  // `dd if=A of=B` names both ends in its own flags; `cat A > B` and
  // `cat < A > B` reach the file through the shell's redirect. Neither program
  // has a write-role entry, so the roles come from the flags and the shell.
  if (PASTHROUGH.has(stage.cmd)) {
    const dest = stage.cmd === "dd" ? ddToken(operands, "of") : outTarget;
    // A `dd` with no `if=` reads stdin: no file, nothing to show. `cat` with
    // neither a `<` nor a file operand is the same case.
    const source = stage.cmd === "dd"
      ? ddToken(operands, "if")
      : inTarget ?? operands.find((t, k) => !skip.has(k) && !t.text.startsWith("-"));
    if (!dest || !source) return [];
    return expandSource(source, base, [describeDest(dest, base)], stage.cmd);
  }

  return [];
}

/** `dd`'s `if=FILE` / `of=FILE`: the value is part of the token, so the token
 *  carries its own quoting and expansion facts with the sliced path. */
function ddToken(tokens: QuotedToken[], name: string): QuotedToken | null {
  for (const t of tokens) {
    if (t.text.startsWith(`${name}=`)) return { ...t, text: t.text.slice(name.length + 1) };
  }
  return null;
}

/** Resolve a destination operand: a directory (trailing slash, or one on disk)
 *  takes the source's basename; a plain name is the file itself. */
function describeDest(token: QuotedToken | undefined, base: string | null): DestInfo {
  if (!token || base === null) return { path: null, isDir: false };
  if (token.hasExpansion ?? false) return { path: null, isDir: false };
  const text = expandTilde(token.text);
  if (GLOB_RE.test(text) && !token.quotedWhole) return { path: null, isDir: false };
  const abs = path.resolve(base, text);
  let isDir = text.endsWith("/");
  try {
    isDir = isDir || fs.statSync(abs).isDirectory();
  } catch {
    /* the copy decides whether that is a failure; the destination is still named */
  }
  return { path: abs, isDir };
}

/** Turn one source operand into the files it names (one, or every glob match)
 *  and read each within the limits. */
function expandSource(token: QuotedToken, base: string | null, dests: DestInfo[], cmd: string): MovedFile[] {
  // A source the analysis cannot place is still a fact about the operation.
  if (token.hasExpansion ?? false) {
    return [record(token.text, null, null, null, "path not resolvable — content not shown", false)];
  }
  if (base === null) {
    return [record(token.text, null, null, null, "the directory this runs in is not known — content not shown", false)];
  }

  const abs = path.resolve(base, expandTilde(token.text));
  let paths: string[];
  let note: string | null = null;
  if (token.unquotedGlob && GLOB_RE.test(token.text)) {
    try {
      paths = [...new Set(fs.globSync(abs).map((m) => fs.realpathSync(m)))];
    } catch {
      paths = [];
      note = "glob could not be listed — content not shown";
    }
    if (paths.length === 0 && note === null) note = "nothing matches this pattern";
  } else {
    paths = [fs.existsSync(abs) ? fs.realpathSync(abs) : abs];
  }
  if (paths.length === 0) return [record(abs, null, null, null, note, false)];

  // One source, one file destination → that file. Many sources, or a directory
  // destination → each lands inside it, under its own name.
  const dest = dests.length === 1 ? dests[0] : null;
  const intoDir = paths.length > 1 || dest?.isDir === true || cmd === "split";
  return paths.map((p) => {
    const landed = dest?.path && cmd !== "split"
      ? (intoDir ? path.join(dest.path, path.basename(p)) : dest.path)
      : null;
    const f = readFile(p, landed);
    // The pattern itself was the unresolvable part; say it once per file.
    if (note && f.note === null) f.note = note;
    return f;
  });
}

/** Stat it, refuse what must not be read, otherwise read it whole. */
function readFile(source: string, dest: string | null): MovedFile {
  const over = overwrites(dest);
  let stat: fs.Stats;
  try {
    stat = fs.statSync(source);
  } catch {
    return record(source, dest, null, null, "nothing at this path", false);
  }
  if (stat.isDirectory()) {
    let count = 0;
    try {
      count = fs.readdirSync(source).length;
    } catch {
      /* an unreadable folder: the count was the useful part */
    }
    return record(source, dest, stat.size, null, `folder — ${count} files, contents not shown`, over);
  }
  if (NEVER_READ_RE.test(source)) {
    return record(source, dest, stat.size, null, "device or pseudo-file — not read", over);
  }
  const warned = isPathWarnedResolved(source, source);
  if (warned.warned) {
    return record(source, dest, stat.size, null, `credential file (${warned.matchedRule}) — content not shown`, over);
  }
  if (stat.size > MAX_MOVED_FILE_BYTES) {
    return record(source, dest, stat.size, null, `over the ${MAX_MOVED_FILE_BYTES / 1024 / 1024} MB limit — content not shown`, over);
  }
  let buf: Buffer;
  try {
    buf = fs.readFileSync(source);
  } catch {
    return record(source, dest, stat.size, null, "unreadable — content not shown", over);
  }
  if (buf.includes(0)) return record(source, dest, stat.size, null, "binary — content not shown", over);
  return record(source, dest, stat.size, buf.toString("utf8"), null, over);
}

function overwrites(dest: string | null): boolean {
  if (!dest) return false;
  try {
    return fs.statSync(dest).isFile();
  } catch {
    return false;
  }
}

function record(
  source: string,
  dest: string | null,
  bytes: number | null,
  content: string | null,
  note: string | null,
  over: boolean,
): MovedFile {
  return { source, dest, bytes, content, note, overwrites: over };
}
