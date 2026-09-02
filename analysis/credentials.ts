/**
 * Credential path detection for bash commands — a raw-text scan.
 *
 * Deliberately independent of the tree-sitter parse: it runs on the command
 * string itself, before/without analysis, so a parse failure can never hide
 * a credential read (fail-closed). Path operands are resolved through
 * path-analysis (resolvePathReal + the denied/warned pattern checks) — the
 * only dependency on the path side. Everything else is text-level credential
 * semantics: heredoc/comment stripping (data, not operands), quote-span
 * accounting, glob-expansion decoding, and bare-symlink checks.
 *
 * Interface:
 *  - checkCommandForCredentialPaths(command, cwd) — the single entry point
 *    (a deny wins; warns accumulate to the first).
 *  - checkBareSymlinkTokens(tokens, cwd) — bare relative tokens whose cwd
 *    symlink escapes cwd or points at a credential (must run even when the
 *    string pre-scan early-returns: a symlink's literal name carries no
 *    credential text).
 *  - CREDENTIAL_SCAN_RE — the fast pre-scan regex (FastAllowRule re-runs it
 *    on the dequoted form).
 *  - stripHeredocBodies / stripShellComments — text preprocessing (tests
 *    exercise them directly; the scanner is the only production caller).
 */
import path from "node:path";
import fs from "node:fs";
import { deniedPaths, warnPaths } from "../config";
import { expandTilde } from "./path-util";
import { tokenizeSegment } from "./tokenizer";
import {
  isChildOf,
  isPathDeniedResolved,
  isPathWarnedResolved,
  resolvePathReal,
} from "./path-analysis";


/**
 * Pre-compiled regex for fast credential pattern detection in bash commands.
 * Loose match — false positives just trigger the more expensive resolve+check.
 * Matches credential file/dir name roots: .ssh, .env, .aws, .docker/config.json,
 * standalone keyfile basenames (id_rsa), .envrc, and *.pem file names.
 */
export const CREDENTIAL_SCAN_RE = /\.(?:ssh|gnupg|gpg|vault|secret|secrets|env|envrc|aws|gcloud|azure|git-credentials|hg|netrc|npmrc|pypirc|docker|pem)\b|\bid_(?:rsa|ed25519|ecdsa|dsa)\b/;

/**
 * Strip heredoc BODIES from a command so credential scanning doesn't flag
 * credential-looking tokens that are merely DATA fed to stdin (the body of
 * `cat > x <<'EOF' … .ssh/id_rsa … EOF`). A real credential READ is always in
 * the command line (operand, redirect target), never in the body.
 *
 * Conservative by design: only the common form is stripped — the heredoc
 * operator ends the logical line (optionally followed by a comment or a
 * pipeline/background operator). Quoted pseudo-heredocs mid-line, here-strings
 * (`<<<`), and UNTERMINATED heredocs are left untouched (fail-closed: the
 * text is still scanned; an unterminated heredoc also fails the tree-sitter
 * parse and prompts anyway).
 *
 * A line is only treated as a heredoc START when bash unambiguously starts one:
 * `<<` is a standalone word (a glued `x<<EOF` is a literal word in bash), it
 * is not inside a comment, and it is not inside an unterminated quoted string.
 * When in doubt the body is KEPT and still scanned — every decline is
 * fail-closed, so a false start can never hide a live command line.
 */
export function stripHeredocBodies(cmd: string): string {
  const HEREDOC_START_RE = /<<(?!<)(-?)\s*(['"]?)([A-Za-z0-9_][A-Za-z0-9_.-]*)\2\s*(?:[#|&;].*)?$/;
  /** Return the heredoc delimiter if this line unambiguously starts one, else null. */
  const findHeredocStart = (line: string): string | null => {
    const m = line.match(HEREDOC_START_RE);
    if (!m) return null;
    const opIdx = line.lastIndexOf("<<");
    // `<<` must be a standalone word: start of line or preceded by whitespace.
    // Glued forms (x<<EOF, =<<EOF) are literal words in bash, not redirects.
    if (opIdx > 0 && !/\s/.test(line[opIdx - 1])) return null;
    const before = line.slice(0, opIdx);
    // A word-boundary `#` before the operator puts it inside a comment —
    // bash starts no heredoc there (covers `# c <<EOF` and `cmd;# c <<EOF`).
    if (/^#|[\s;|&(]#/.test(before)) return null;
    // Unbalanced unescaped quotes before the operator mean it sits inside a
    // multi-line string — literal text, not a redirect.
    const dq = (before.match(/(?<!\\)"/g) ?? []).length;
    const sq = (before.match(/(?<!\\)'/g) ?? []).length;
    if (dq % 2 || sq % 2) return null;
    return m[3];
  };
  const lines = cmd.split("\n");
  const drop = new Set<number>();
  const pending: string[] = [];
  const bodyStart = new Map<string, number>();
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (pending.length > 0) {
      const first = pending[0];
      if (line.trim() === first) {
        pending.shift();
        const start = bodyStart.get(first) ?? i;
        bodyStart.delete(first);
        for (let j = start; j < i; j++) drop.add(j);
      }
      continue;
    }
    const delim = findHeredocStart(line);
    if (delim) {
      if (!pending.includes(delim)) bodyStart.set(delim, i + 1);
      pending.push(delim);
    }
  }
  if (drop.size === 0) return cmd;
  return lines.filter((_, i) => !drop.has(i)).join("\n");
}

/**
 * Mask shell comments (word-boundary `#` to end of physical line) so the
 * credential scan doesn't flag credential-looking text that is merely a
 * comment (`# rotate the .env tomorrow\nls` must not block `ls`). Comments
 * never execute, so masking them can only remove false positives — a real
 * credential operand stays on a live line and is still scanned.
 *
 * Quote- and continuation-aware, mirroring bash:
 *  - `#` starts a comment only at a WORD START: line start, or after
 *    whitespace / `;|&(`. `x#y`, `${v#pat}`, `VAR=#x`, `echo "a"# b` keep
 *    their `#` (literal word content).
 *  - Inside '…' or "…" a `#` is literal; quotes may span lines.
 *  - A backslash-escaped `#` (`\#`) is literal.
 *  - Backslash+newline outside quotes splices the logical line: a `#` on the
 *    continuation line is judged against the character BEFORE the splice
 *    (`foo \<nl># x` → `foo # x` → comment; `foo\<nl># x` → `foo# x` →
 *    literal). A comment ends at its physical line even when it ends in `\\`
 *    (comments do not continue).
 *
 * Comment characters are replaced with spaces (offsets and newlines
 * preserved) so downstream line-based preprocessing sees the same shape.
 */
export function stripShellComments(cmd: string): string {
  const out = cmd.split("");
  let inSingle = false;
  let inDouble = false;
  let escaped = false;
  let comment = false;
  let prev = "\n"; // last significant char of the LOGICAL line (word-start check)
  for (let i = 0; i < cmd.length; i++) {
    const c = cmd[i];
    if (comment) {
      if (c === "\n") { comment = false; prev = "\n"; }
      else { out[i] = " "; }
      continue;
    }
    if (escaped) { escaped = false; continue; }
    if (inSingle) {
      if (c === "'") { inSingle = false; prev = c; }
      continue;
    }
    if (inDouble) {
      if (c === "\\") { escaped = true; continue; } // escapes next (incl. newline splice)
      if (c === '"') { inDouble = false; prev = c; }
      continue;
    }
    if (c === "'") { inSingle = true; prev = c; continue; }
    if (c === '"') { inDouble = true; prev = c; continue; }
    if (c === "\\") {
      if (cmd[i + 1] === "\n") {
        i++; // line splice: the logical line continues; `prev` keeps the
        // character before the backslash (word-start judged against it)
      } else {
        escaped = true;
      }
      continue;
    }
    if (c === "#" && (/[ \t\n;|&(]/.test(prev))) {
      comment = true;
      out[i] = " ";
      continue;
    }
    prev = c;
  }
  return out.join("");
}

/**
 * Check bare relative tokens for symlinks in cwd that point outside it.
 * A malicious repo can ship a symlink (often absolute, e.g. `link →
 * /home/<user>/.ssh/id_rsa` — the username is frequently in git history) so
 * `cat link` reads a credential although the command line only shows a
 * benign name. The literal name carries no credential text, so the string
 * pre-scan in checkCommandForCredentialPaths would early-return without ever
 * resolving it, and FastAllowRule passes bare relative tokens through.
 *
 * Only SYMLINKS are resolved: a regular file in cwd cannot escape cwd, and a
 * directory symlink used as `cat linkdir/f` contains a "/" so it goes
 * through the normal path resolution, which already follows the parent chain.
 * Quoted names are covered too — quoting prevents glob expansion but not
 * symlink following (`cat "link"` still reads the target).
 */
export function checkBareSymlinkTokens(
  tokens: string[],
  cwd: string,
): { denied: string | null; warned: string | null } {
  let denied: string | null = null;
  let warned: string | null = null;
  let cwdReal: string;
  try { cwdReal = fs.realpathSync(cwd); } catch { cwdReal = path.resolve(cwd); }

  const checkOne = (t: string): boolean => {
    if (!t || t === "." || t === "..") return false;
    if (t.startsWith("-")) return false;
    if (t.includes("/") || t.includes("=")) return false;
    if (/[*?\[\]]/.test(t)) return false; // glob — covered by the glob check
    const candidate = path.join(cwdReal, t);
    let st: fs.Stats;
    try { st = fs.lstatSync(candidate); } catch { return false; }
    if (!st.isSymbolicLink()) return false;
    // Resolve the target two ways:
    //  - real: follow the chain via realpath (works when the target exists;
    //    catches credential names anywhere along the chain)
    //  - lex: one-level textual readlink (works for DANGLING links, where
    //    realpath cannot follow — a link to a not-yet-existing id_rsa is
    //    still the attack shape and must be gated)
    const real = resolvePathReal(candidate, cwd);
    let lex: string | null = null;
    try {
      const tgt = fs.readlinkSync(candidate);
      lex = path.isAbsolute(tgt) ? path.resolve(tgt) : path.resolve(cwdReal, tgt);
    } catch { /* target vanished mid-flight — real path already checked */ }
    const candidates = [real, lex].filter((r): r is string => !!r);
    for (const resolved of candidates) {
      const deniedResult = isPathDeniedResolved(candidate, resolved);
      if (deniedResult.denied) { denied = deniedResult.matchedRule; return true; }
    }
    for (const resolved of candidates) {
      if (isChildOf(resolved, cwdReal)) continue;
      // Symlink escapes cwd → same approval bar as reading the target path
      // directly (the file tool resolves symlinks the same way).
      if (!warned) warned = resolved;
      return false;
    }
    for (const resolved of candidates) {
      const warnedResult = isPathWarnedResolved(candidate, resolved);
      if (warnedResult.warned && !warned) warned = warnedResult.matchedRule;
    }
    return false;
  };

  // Skip token 0 (the command name — a bare name is looked up in PATH, not
  // cwd). Mirror the scanner's operator split so `cat link;ls` and
  // `cat link>x` still see the bare name.
  for (let i = 1; i < tokens.length; i++) {
    const parts = tokens[i]
      .split(/[;&|<>]+/)
      .map(p => p.replace(/\)+$/, ""))
      .filter(Boolean);
    for (const p of parts) {
      if (checkOne(p)) return { denied, warned };
    }
  }
  return { denied, warned };
}

/**
 * Count quoted spans ('…', "…", $'…') per content string. A quoted token is
 * never glob-expanded by bash, so its glob characters can never reach a file:
 * `grep ".*" f` is a regex pattern, `cat ".s*sh"` is a literal name. The
 * caller compares these counts against token occurrences: the glob check is
 * skipped only when EVERY occurrence of a part is quoted. Unquoted globs keep
 * the full check (runtime-verified: an unquoted `.*` glob reaches .ssh).
 * ($'…' content is matched raw — escape-decoded variants simply stay checked,
 * which is conservative.)
 */
function countQuotedSpans(cmd: string): Map<string, number> {
  const counts = new Map<string, number>();
  const bump = (content: string) => counts.set(content, (counts.get(content) ?? 0) + 1);
  let i = 0;
  while (i < cmd.length) {
    const ch = cmd[i];
    if (ch === "'") {
      const end = cmd.indexOf("'", i + 1);
      if (end < 0) break;
      bump(cmd.slice(i + 1, end));
      i = end + 1;
      continue;
    }
    if (ch === '"') {
      let j = i + 1;
      while (j < cmd.length && !(cmd[j] === '"' && cmd[j - 1] !== "\\")) j++;
      if (j >= cmd.length) break;
      bump(cmd.slice(i + 1, j));
      i = j + 1;
      continue;
    }
    if (ch === "$" && cmd[i + 1] === "'" && (i === 0 || cmd[i - 1] !== "\\")) {
      const end = cmd.indexOf("'", i + 2);
      if (end < 0) break;
      bump(cmd.slice(i + 2, end));
      i = end + 1;
      continue;
    }
    i++;
  }
  return counts;
}

/**
 * Check a bash command string for credential path references.
 * Returns the first denied and/or warned pattern found.
 * Uses a fast regex pre-scan to skip the common case (no credential patterns).
 */
export function checkCommandForCredentialPaths(
  command: string,
  cwd: string,
): { denied: string | null; warned: string | null } {
  // Heredoc bodies and shell comments are DATA, not path operands — strip
  // them before scanning so credential names in the body / a comment don't
  // false-positive (`# check the .ssh dir\nls` must not block `ls`).
  const scanCmd = stripHeredocBodies(stripShellComments(command));

  // Quote-aware tokenization (strips quotes so '.env' is detected as .env).
  const tokens = tokenizeSegment(scanCmd);

  // Fast pre-scan: if no credential pattern appears in the command, skip entirely.
  // Also check the dequoted version to prevent quote-splitting bypasses (e.g., .en''v).
  // Also check the backslash-stripped version to prevent backslash-splitting (e.g., .s\sh).
  // Glob chars defeat the string regex (.s?sh ≠ .ssh) — run the precise per-token
  // glob check instead of trusting the pre-scan.
  const dequoted = tokens.join(" ");
  const unstripped = scanCmd.replace(/\\/g, "");
  const hasGlob = /[*?\[\]]/.test(scanCmd);
  // Bare-token symlink check — must run even when the pre-scan below would
  // early-return (a symlink's literal name carries no credential text).
  const symlinkCheck = checkBareSymlinkTokens(tokens, cwd);
  if (symlinkCheck.denied) return { denied: symlinkCheck.denied, warned: null };
  if (
    !hasGlob &&
    !CREDENTIAL_SCAN_RE.test(scanCmd) &&
    !CREDENTIAL_SCAN_RE.test(dequoted) &&
    !CREDENTIAL_SCAN_RE.test(unstripped)
  ) {
    return { denied: null, warned: symlinkCheck.warned };
  }
  let denied: string | null = null;
  let warned: string | null = symlinkCheck.warned;

  // Valid env-var name pattern: starts with letter/underscore, only alphanumeric/underscore.
  // Flags like `--output=path` have a leading dash, so they won't match.
  const ENV_VAR_NAME_RE = /^[a-zA-Z_][a-zA-Z0-9_]*$/;

  /** Check a path string against denied/warned patterns, returning the matched rule. */
  const checkPath = (pathStr: string): { denied: string | null; warned: string | null } => {
    const resolved = resolvePathReal(expandTilde(pathStr), cwd);
    const deniedResult = isPathDeniedResolved(pathStr, resolved);
    if (deniedResult.denied) return { denied: deniedResult.matchedRule, warned: null };
    const warnedResult = isPathWarnedResolved(pathStr, resolved);
    return { denied: null, warned: warnedResult.matchedRule };
  };

  /** Check one token (or value) against denied/warned path patterns. */
  const checkToken = (t: string): { denied: string | null; warned: string | null } | "skip" => {
    if (!t) return "skip";

    // Handle --flag=value syntax
    if (t.startsWith("-") || t.startsWith("--")) {
      const eqIdx = t.indexOf("=");
      if (eqIdx > 0 && eqIdx < t.length - 1) {
        const value = t.slice(eqIdx + 1);
        if (value) return checkPath(value);
      }
      return "skip";
    }

    // Env assignments (FOO=bar, FOO=/path): check the value, never skip it.
    // Pure assignment statements produce no parsed segments, so the value is
    // invisible to AST-based analysis; a credential path staged in a variable
    // (`X=~/.ssh && cat $X`) would otherwise auto-allow — the later `$VAR`
    // use is just a non-path token to the scanner. The assignment is the only
    // statically visible moment, so it must be blocked (denied) or prompted
    // (warned) itself.
    const eqIdx = t.indexOf("=");
    if (eqIdx !== -1) {
      const beforeEquals = t.slice(0, eqIdx);
      if (ENV_VAR_NAME_RE.test(beforeEquals)) {
        const value = t.slice(eqIdx + 1);
        if (value) return checkPath(value);
        return "skip"; // FOO= (empty value) — nothing to check
      }
    }

    return checkPath(t);
  };

  /** Check a token and accumulate denied/warned results. */
  const accumulateResult = (result: { denied: string | null; warned: string | null } | "skip"): boolean => {
    if (result === "skip") return false;
    if (result.denied) { denied = result.denied; return true; }
    if (result.warned && !warned) warned = result.warned;
    return false;
  };

  /**
   * Glob-aware token check: a globbed name can decode to a credential name
   * (~/.s*sh → ~/.ssh, id_rs? → id_rsa, *.env → .env). Convert each path
   * component into a regex (* → .*, ? and [..] → .) and test it against every
   * denied/warned pattern name. Returns "skip" if the token has no glob chars
   * or cannot match any pattern.
   */
  const checkTokenGlob = (t: string): { denied: string | null; warned: string | null } | "skip" => {
    if (!/[*?\[\]]/.test(t)) return "skip";
    for (const comp of t.split("/")) {
      if (!/[*?\[\]]/.test(comp)) continue;
      // A purely-wild component (*, ?, [x]) matches every name — must not
      // match any pattern. Require at least one literal character (e.g.
      // *.pem → ".pem").
      if (!comp.replace(/[*?\[\]]/g, "")) continue;
      const escaped = comp.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      const re = new RegExp(
        "^" + escaped
          .replace(/\\\*/g, ".*")
          .replace(/\\\?/g, ".")
          .replace(/\\\[[^\\\]]*\\\]/g, ".") +
        "$",
      );
      for (const pattern of deniedPaths) {
        if (re.test(pattern)) return { denied: pattern, warned: null };
      }
      for (const pattern of warnPaths) {
        if (re.test(pattern)) return { denied: null, warned: pattern };
      }
    }
    return "skip";
  };

  // Pre-split every token on shell operators: whitespace-only tokenization
  // leaves operators stuck to or inside tokens: `cat ~/.ssh;`,
  // `cat ~/.ssh|grep`, `cat ~/.ssh>/tmp/x`, `X=~/.ssh&& ls`, `$(cat ~/.ssh)`.
  // Unquoted, a path can never contain `;`, `&`, `|`, `<`, `>`, or end with
  // `)` — there they are always shell syntax — so check every part. Without
  // this, `cat ~/.ssh; ls` evades the scan entirely (token is `~/.ssh;`).
  const partsList: string[][] = [];
  const partCount = new Map<string, number>();
  for (const rawToken of tokens) {
    const parts = rawToken
      .split(/[;&|<>]+/)
      .map(p => p.replace(/\)+$/, ""))
      .filter(Boolean);
    partsList.push(parts);
    for (const p of parts) partCount.set(p, (partCount.get(p) ?? 0) + 1);
  }
  // Quoted occurrences are never glob-expanded at runtime (see countQuotedSpans).
  const spanCount = countQuotedSpans(scanCmd);

  for (const parts of partsList) {
    for (const token of parts) {
      // Check original token
      const result = checkToken(token);
      if (accumulateResult(result)) return { denied, warned };

      // Also check token with backslashes stripped to prevent backslash-splitting
      // bypasses (e.g., .s\sh instead of .ssh). Tokenizer preserves backslashes
      // outside quotes, so we handle it here.
      if (token.includes("\\")) {
        const unescaped = token.replace(/\\/g, "");
        const unescapedResult = checkToken(unescaped);
        if (accumulateResult(unescapedResult)) return { denied, warned };
      }

      // Also check glob-expanded variants (~/.s*sh → .ssh, id_rs? → id_rsa).
      // Skipped when every occurrence of this part is quoted — a quoted glob
      // cannot expand (grep ".*" is a pattern, cat ".s*sh" a literal name),
      // while unquoted globs keep the check (cat .*/id_rsa → .ssh/id_rsa).
      if ((spanCount.get(token) ?? 0) < (partCount.get(token) ?? 0)) {
        const globResult = checkTokenGlob(token);
        if (accumulateResult(globResult)) return { denied, warned };
      }
    }
  }

  return { denied, warned };
}
