/**
 * script-operand.ts — which file a command segment names as its payload.
 *
 * ONE scan, two consumers: identification (analysis/script-payload.ts —
 * the judge packet's fenced content, D3/D11 conversions, the D13 executed
 * paths) and trust (config/trusted-scripts.ts — the skills-dir bypass).
 * They must not drift: two parsers of the same command forms is how
 * `uv run --with <deps> python job.py` (the mandated skill-script form)
 * became trusted-but-unidentified — the bypass fired while the judge
 * packet carried no content (2026-10-14 judge.jsonl: "the script's
 * contents … are unverifiable" → DEFER on every wrapped run).
 *
 * The scan walks past WRAPPERS: env/assignment prefixes, pass-through
 * wrappers (wrapperCommands — `timeout 60 python3 job.py`, `nice -n5 node
 * job.js`, `env FOO=1 python3 job.py`) and package run forms
 * (FETCH_PKG_FORMS — `npx tsx job.mts`, `uvx python job.py`; plus the
 * local run form `uv run job.py`). For a package run form the package must
 * NAME a runner: `npx eslint a.ts` lints a.ts, it does not execute it —
 * naming a.ts as the payload would mislabel the packet and over-claim
 * executedScriptPaths ("the floor saw the executed path").
 *
 * The two fields answer the two consumers' different questions, so neither
 * behavior changes: `script` is the first operand that looks like a TEXT
 * script (an extension-less direct exec is a binary — reading it would
 * fence bytes as prose), `first` is the first operand of any kind (trust
 * covers an extension-less executable in the skills dir). A SHELL program
 * string is scanned too, but only for a hand-off to a file, and the result
 * fills `script` alone (inlineBodyScriptHandoff) — a path inside someone
 * else's code never becomes a trust operand.
 */
import { FETCH_PKG_FORMS, shellBodyStages, SHELL_INTERPRETERS, skipEnvPrefixes, stripPkgVersion, UV_VALUE_FLAGS, wrapperCommands } from "./bash-patterns";
import { tokenizeSegment } from "../analysis/tokenizer";

/** Extensions whose content is worth reviewing (text scripts). */
const SCRIPT_EXT_RE = /\.(sh|bash|zsh|py|pyi|js|mjs|cjs|mts|cts|ts|rb|pl|php|lua|exs?)$/i;

/**
 * Names that EXECUTE the file operand (a runner precedes its script). Not
 * config.SCRIPT_INTERPRETERS — that set answers "write-capable?" at three
 * risk sites (segment-analysis, cwd-tracking, WRITE_HANDLERS) and lacks
 * tsx/ts-node/vite-node and the shells; changing it here would reclassify
 * risk everywhere. Runner stems cover versioned names (`python3.12`).
 */
const RUNNER_NAMES = new Set([
  "python", "python3", "python2", "py", "pypy", "pypy3", "node", "nodejs",
  "tsx", "ts-node", "vite-node", "babel-node", "esr", "deno", "bun",
  "ruby", "rb", "irb", "perl", "php", "lua", "julia", "jruby", "graalvm",
  "bash", "sh", "zsh", "dash", "ksh", "fish",
]);
const RUNNER_STEM_RE = /^(python|pypy|node|ruby|php|lua|perl|deno|bun|jruby|graalvm)[\w.-]*$/;

/**
 * Flags that make the payload INLINE (a program string or a module), not a
 * file: the scan aborts rather than skipping them, so `bash -c 'x; y'` and
 * `python3 -c 'open("/etc/shadow")'` never name a script. `-` = stdin.
 * `-r` is php's (`php -r 'code'`; without it a later file operand was named as
 * the payload while php ran the string).
 * The one exception is the SHELL body hand-off (see inlineBodyScriptHandoff):
 * a shell program is itself a command list, so a stage of it can execute a
 * file. It fills `script` only — never `first` — so trust can still not fire
 * on a path inside a command string.
 */
const INLINE_CODE_FLAGS = new Set([
  "-c", "--command", "-m", "--module", "-e", "--eval", "-p", "--print", "-r", "-",
]);

/** uv run-form options that take a value — ONE arity table, in bash-patterns
 *  (skipping an option's own value is what keeps the operand findable in
 *  `uv run --color never python3 job.py`). */

/** Assignment prefix (`FOO=1 cmd`) — not a command name. */
const ASSIGNMENT_RE = /^[A-Za-z_][A-Za-z0-9_]*=/;

/** Never walk an unbounded chain (a token soup like `timeout timeout timeout …`). */
const MAX_WRAPPER_HOPS = 4;

/** How deep to follow inline program strings for a hand-off: one body. A `-c`
 *  inside a `-c` stays unidentified — the second body is data to the first. */
const MAX_BODY_DEPTH = 1;

export interface ScriptCandidate {
  /** The operand token as the tokenizer produced it (quotes stripped). */
  token: string;
  /** Its index in the token array. */
  index: number;
}

export interface ScriptOperand {
  /** First operand the segment names, script-extension or not (launcher). */
  first: ScriptCandidate | null;
  /** First operand that looks like a text script (the executable payload). */
  script: ScriptCandidate | null;
  /** Wrapper commands skipped to reach the operand (timeout, npx, uv run). */
  wrappers: string[];
}
/** Command name for set lookups: basename, lowercased (`/bin/bash` = `bash`). */
function nameOf(token: string): string {
  const t = token.toLowerCase();
  const slash = t.lastIndexOf("/");
  return slash >= 0 ? t.slice(slash + 1) : t;
}

function isRunner(name: string): boolean {
  return RUNNER_NAMES.has(name) || RUNNER_STEM_RE.test(name);
}

/** A token whose path is built at runtime (`$VAR`, backticks) — not knowable. */
function isComputed(token: string): boolean {
  return token.includes("$") || token.includes("`");
}

/**
 * The file an inline SHELL program hands off to (`sh -c 'sleep 15; sh job.sh'`).
 * 2026-10-28 decisions.jsonl: a detached launch stopped the model backend
 * inside `job.sh`; the packet carried no script, so the judge ruled on the
 * one-liner, and the executed-path ledger stayed empty while the floor's own
 * stage-2 report named the script and was logged as a floorMiss.
 *
 * A shell program is a command list, so its stages get the SAME scan as any
 * segment (config.shellBodyStages + the tokenizer — one parser for one body).
 * Only a shell verb qualifies: a python body's file operand is an argument,
 * not necessarily an exec (`python3 -c 'open("job.py")'`). An opaque body —
 * one the shell expands part of (`-c "sh $JOB"`) — yields nothing: what runs
 * is not knowable, and naming the wrong file is worse than naming none.
 * Relative operands resolve against the segment's effective base, which is
 * right unless the body itself cds; that re-basing is out of scope here (the
 * write-verb scan does not model it either).
 */
function inlineBodyScriptHandoff(
  body: string | undefined,
  at: number,
  wrappers: string[],
  depth: number,
): ScriptCandidate | null {
  if (!body || isComputed(body)) return null;
  for (const stage of shellBodyStages(body)) {
    const inner = findScriptOperand(tokenizeSegment(stage), depth + 1);
    if (inner?.script) return { token: inner.script.token, index: at };
  }
  return null;
}

/**
 * Scan for the operand at/after `start`. Aborts (no operand) on an inline
 * code flag or a computed token — a payload built at runtime is not
 * knowable statically, and naming the wrong token is worse than naming
 * none (the one exception: a SHELL body's hand-off to a file, below).
 * `launcher` = the token at `start` is the executable itself (a
 * path-like direct exec), which is reported as `first` while the scan
 * keeps looking for the text payload it hands off to
 * (`…/.bin/vite-node /tmp/x.mts` — 2026-10-04 judge.jsonl).
 */
function scanOperands(
  tokens: string[],
  start: number,
  wrappers: string[],
  launcher: boolean,
  verb: string,
  depth: number,
): ScriptOperand | null {
  let first: ScriptCandidate | null = null;
  let script: ScriptCandidate | null = null;
  if (launcher) {
    if (isComputed(tokens[start])) return null;
    first = { token: tokens[start], index: start };
    if (SCRIPT_EXT_RE.test(tokens[start])) {
      script = { token: tokens[start], index: start };
      return { first, script, wrappers };
    }
  }
  for (let j = launcher ? start + 1 : start; j < tokens.length; j++) {
    const t = tokens[j];
    if (t.startsWith("-")) {
      const flag = t.split("=")[0];
      if (INLINE_CODE_FLAGS.has(flag)) {
        // The payload is the program string — unless that string is a shell
        // one and a stage of it executes a file. The hand-off fills `script`
        // only, so a path inside a command string can never become the trust
        // operand (`first` stays whatever the segment itself named).
        const handoff =
          depth < MAX_BODY_DEPTH && (flag === "-c" || flag === "--command") && SHELL_INTERPRETERS.has(verb)
            ? inlineBodyScriptHandoff(t.length > flag.length ? t.slice(flag.length + 1) : tokens[j + 1], j, wrappers, depth)
            : null;
        if (!handoff) return null;
        return { first, script: handoff, wrappers };
      }
      continue;
    }
    if (isComputed(t)) return null;
    // A whole quoted multi-word token is code or data, not a path
    // (`watch -n 5 'python3 job.py'` — the payload runs in a subshell string).
    if (/\s/.test(t)) break;
    if (!first) first = { token: t, index: j };
    if (SCRIPT_EXT_RE.test(t)) {
      script = { token: t, index: j };
      break;
    }
    break; // a non-script operand ends the scan (`python3 -m x`, `cat data`)
  }
  if (!first && !script) return null;
  return { first, script, wrappers };
}

/** Index of the first token after `from` that is not a flag / K=V prefix. */function skipFlagsAndAssignments(tokens: string[], from: number): number {
  let i = from;
  while (i < tokens.length && (tokens[i].startsWith("-") || ASSIGNMENT_RE.test(tokens[i]))) i++;
  return i;
}

/**
 * The file operands one segment names, past its wrappers. Null when the
 * segment has no knowable file operand (inline code with no shell hand-off,
 * computed paths, a bare command, a package runner that is not a runner of
 * files). `depth` counts the inline programs already descended through; it
 * exists so a body's stages get the same scan without opening an unbounded
 * chain of `-c` inside `-c`.
 */
export function findScriptOperand(tokens: string[], depth = 0): ScriptOperand | null {
  let i = skipEnvPrefixes(tokens);
  const wrappers: string[] = [];

  for (let hop = 0; hop <= MAX_WRAPPER_HOPS; hop++) {
    if (i >= tokens.length) return null;
    const raw = tokens[i];
    const cmd = nameOf(raw);

    // Pass-through wrapper (`timeout 60 python3 job.py`, `nice -n5 node a.js`):
    // the inner command is the first real token after flags, K=V prefixes
    // and a bare duration (`timeout 60`, `watch -n 5`).
    if (wrapperCommands.has(cmd)) {
      let j = i + 1;
      while (
        j < tokens.length &&
        (tokens[j].startsWith("-") || ASSIGNMENT_RE.test(tokens[j]) || /^\d+(\.\d+)?s?$/.test(tokens[j]))
      ) {
        j++;
      }
      if (j >= tokens.length) return null;
      wrappers.push(cmd);
      i = j;
      continue;
    }

    // `uv run [flags] [runner] job.py` and `deno run [flags] job.ts` — LOCAL
    // run forms (deliberately absent from FETCH_PKG_FORMS: they run
    // repo-visible code, no registry fetch).
    if ((cmd === "uv" || cmd === "deno") && tokens[i + 1]?.toLowerCase() === "run") {
      let j = i + 2;
      while (j < tokens.length) {
        const t = tokens[j].toLowerCase();
        // A module run has no file operand at all — abort rather than name
        // the module as one.
        if (t === "-m" || t === "--module") return null;
        if (UV_VALUE_FLAGS.has(t)) {
          if (isComputed(tokens[j + 1] ?? "")) return null;
          j += 2;
          continue;
        }
        if (t.startsWith("-")) { j++; continue; }
        break;
      }
      if (j >= tokens.length) return null;
      if (isRunner(nameOf(tokens[j]))) {
        wrappers.push(`${cmd} run`);
        i = j + 1;
        continue;
      }
      return scanOperands(tokens, j, wrappers, false, nameOf(tokens[j]), depth);
    }

    // Runner with a file operand (`python3 job.py`, `/usr/bin/python3 job.py`,
    // `bun job.ts`). Checked before the package run forms so a local runner
    // that also has an `x` form (`bun job.ts` vs `bun x tsx job.ts`) still
    // resolves its own operand.
    if (isRunner(cmd)) return scanOperands(tokens, i + 1, wrappers, false, cmd, depth);

    // Package run forms (`npx tsx job.mts`, `uvx python job.py`, `npm exec
    // tsx job.mts`). Only a package that names a runner hands off to a file.
    const forms = FETCH_PKG_FORMS[cmd];
    if (forms) {
      let j = skipFlagsAndAssignments(tokens, i + 1);
      if (j >= tokens.length) return null;
      if (forms !== "all") {
        if (!forms.has(nameOf(tokens[j]))) return null; // `npm run build`, `uv sync`
        j = skipFlagsAndAssignments(tokens, j + 1);
        if (j >= tokens.length) return null;
      }
      const pkg = stripPkgVersion(nameOf(tokens[j])); // `tsx@5` → tsx, `@scope/t` kept
      if (!isRunner(pkg)) return null; // `npx eslint a.ts` lints a.ts, does not run it
      wrappers.push(cmd);
      i = j + 1;
      continue;
    }

    // Direct exec (`./scripts/job.sh`), or a path-like launcher that hands
    // off to a payload (`…/.bin/vite-node /tmp/x.mts`).
    if (raw.includes("/") || raw.startsWith("~")) {
      return scanOperands(tokens, i, wrappers, true, cmd, depth);
    }

    // After a wrapper hop the token at i is the INNER command, which may run
    // a file directly (`timeout ./job.sh`, `npx tsx job.mts` — the operand is
    // the token itself, not an argument of a command name here).
    if (wrappers.length && SCRIPT_EXT_RE.test(raw) && !/\s/.test(raw)) {
      return scanOperands(tokens, i, wrappers, true, cmd, depth);
    }

    return null; // a bare command that runs no file
  }
  return null;
}

/**
 * Arg positions whose value is INLINE CODE for this command: the operand of a
 * runner's `-c` / `-e` / `-m` / `-r` flag, plus a self-contained `--command=CODE`.
 *
 * Third consumer of this file's knowledge (see the header): the path extractor
 * must never mint a location token at a program position — the shell hands the
 * string to the interpreter and touches no path named inside it (the role rule;
 * 2026-10-15 unresolved.jsonl: 13 of 28 rows were `python3 -c` / `node -e`
 * bodies whose "token" was the whole mashed program). The same flags make this
 * scan refuse to name a script, so the two views cannot drift — with one
 * exception that does not touch the role rule: a SHELL body's hand-off fills
 * `script` (the payload whose CONTENT the judge reviews) and never `first`, so
 * no location token is ever minted at a program position.
 *
 * Empty set for a command that takes no inline program (`sed`/`awk`/`grep`
 * positions are the parser's own rules — the file-grained grammars differ).
 */
export function inlineCodeArgIndices(cmd: string, args: string[]): Set<number> {
  const idxs = new Set<number>();
  if (!isRunner(nameOf(cmd))) return idxs;
  for (let i = 0; i < args.length; i++) {
    const t = args[i];
    if (!t.startsWith("-")) continue;
    const flag = t.split("=")[0];
    if (!INLINE_CODE_FLAGS.has(flag)) continue;
    if (t.length > flag.length) {
      idxs.add(i); // `--command=CODE` (value glued): the token itself is code
      continue;
    }
    if (i + 1 < args.length) idxs.add(i + 1); // the operand the flag consumes
  }
  return idxs;
}
