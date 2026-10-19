import path from "node:path";

// ── Bash command patterns ──

/**
 * The single source of truth for the bash command allowlist.
 *
 * Every entry is allowlisted (`allowedBashCommands` — the full pipeline).
 * An entry WITHOUT an exclusion reason is additionally unconditionally safe
 * (`unconditionallySafeCommands` — the WASM-skip fast path in FastAllowRule).
 * An entry WITH a reason has flag-dependent write/exec behavior or delegates
 * to another command: the fast path must never decide for it, the full
 * pipeline does.
 *
 * Invariant (test/allow-invariant.test.ts): for every unconditionally-safe
 * entry the full pipeline auto-allows a bare invocation — the fast path may
 * never out-run SafetyRule.
 */
type AllowEntry = readonly [cmd: string, whyNotUnconditional?: string];

const ALLOW_TABLE: readonly AllowEntry[] = [
  // Inspection / read-only
  // `stat` — pure metadata display; GNU/BSD stat has no write/exec flags.
  ["find", "-delete / -exec / -fprint* perform writes and exec"],
  ["grep", "no known write/exec flag; kept on the full pipeline (conservative)"],
  ["ls"], ["cat"], ["head"], ["tail"], ["wc"], ["file"], ["stat"],
  ["sort", "-o / --output truncates or writes files"],
  ["uniq"], ["cut"], ["tr"], ["diff"],
  ["rg", "--pre executes a command per file"],
  ["fd", "-x / --exec executes a command per result"],
  // JSON querying (stdout only — no file writes, no exec capability;
  // output redirection is shell-level and flagged by the redirect checks)
  ["jq"],
  ["tac"], ["rev"], ["nl"], ["fold"], ["expand"], ["unexpand"], ["fmt"],
  ["join"], ["comm"], ["paste"], ["column"], ["seq"],
  // Text transform (safe stdout — guarded by dangerous flag checks)
  ["sed", "-i edits files in place"],
  ["perl", "program body runs arbitrary code (-i in-place edits) — ToolEvaluator flags every invocation"],
  // Hashing / binary inspection
  ["md5sum"], ["sha1sum"], ["sha256sum"], ["sha512sum"], ["cksum"],
  ["hexdump"], ["od"], ["strings"],
  // Strings / formatting
  // `read` — stdin-only shell builtin (no file access, no exec); keeps
  // `while read -r x; do …; done` loops from prompting on the builtin itself.
  ["echo"], ["printf"], ["basename"], ["dirname"], ["realpath"], ["readlink"],
  ["test"], ["true"], ["false"], ["read"],
  // System info (read-only, no file side effects)
  // NOTE: `printenv` is not in the table at all — with args it prints env
  // vars (often secrets: OPENAI_API_KEY) into the transcript; bare it dumps
  // ALL environment variables.
  ["pwd"], ["cd"], ["date"], ["whoami"], ["id"], ["uname"], ["hostname"],
  ["groups"], ["uptime"], ["tty"], ["tput"],
  // Disk / process inspection (read-only)
  ["df"], ["du"], ["free"], ["ps"], ["pgrep"], ["pidof"],
  // Command lookup
  ["which"],
  ["command", "-p runs the named command (command -p rm)"],
  ["type"], ["hash"], ["whence"],
  // Git (guarded by dangerous subcommand checks)
  ["git", "subcommands write/execute (push --force, reset --hard, clean -fd, …)"],
  // Tmux (guarded by dangerous subcommand checks)
  ["tmux", "send-keys / new-session can inject keystrokes or run shells"],
  // File/dir creation (writes — guarded by the no-redirect check)
  ["mkdir", "creates directories (write)"],
  ["touch", "creates files / updates mtimes (write)"],
  ["mktemp", "creates files (write)"],
  // Calculator
  ["bc"], ["expr"], ["factor"], ["yes"],
  // Process control (no fs/net/exec — a pure wait)
  ["sleep", "kept on the full pipeline (conservative)"],
  // Wrapper commands (guarded by isWrapperRunningWrite check)
  ["xargs", "delegates to an inner command (xargs rm)"],
  ["watch", "delegates to an inner command"],
  ["timeout", "delegates to an inner command (timeout rm)"],
  ["parallel", "delegates to an inner command"],
  ["nice", "delegates to an inner command"],
];

/** O(1) first-word allowlist — pre-built from the table. */
const allowedBashCommands = new Set(ALLOW_TABLE.map(([cmd]) => cmd));

/**
 * Unconditionally-safe subset: table entries without an exclusion reason.
 * Used for the fast pre-check that skips tree-sitter parsing (FastAllowRule).
 */
export const unconditionallySafeCommands = new Set(
  ALLOW_TABLE.filter((entry) => entry[1] === undefined).map(([cmd]) => cmd),
);

/** Commands whose arguments include file/dir paths. */
export const pathAwareCommands = new Set([
  // Inspection / read
  "ls", "cat", "head", "tail", "wc", "file", "stat", "touch",
  "tac", "rev", "nl", "fold", "expand", "unexpand", "fmt",
  "join", "comm", "paste", "column", "split", "shuf",
  "du", "df",
  "rg", "fd", "jq",
  // Hashing / binary
  "md5sum", "sha1sum", "sha256sum", "sha512sum", "cksum",
  "xxd", "hexdump", "od", "strings",
  // File/dir ops
  "mkdir", "rm", "cp", "mv", "chmod", "chown", "mktemp",
  // Dir/file ops the write bar (G3) must be able to name: without them the
  // operands are never minted, so a signature grant covered a write the user
  // never saw (`truncate -s 0 ~/Downloads/x`, `ln -s /etc/passwd ~/l`).
  "rmdir", "unlink", "truncate", "ln", "install",
  "find", "grep", "diff", "patch",
  // `cd` is NOT path-aware: a cd performs no file access — it is navigation,
  // modeled by the effective-cwd state machine (analysis/cwd-tracking.ts).
  // Credential checks see `cd ~/.s?sh` via the raw-text scan regardless; the
  // base a cd leaves for later segments is flagged by baseAccessPath.
  "pushd", "popd",
  "tar", "zip", "unzip", "gzip", "gunzip",
  "python", "python3", "node", "ruby", "perl", "php",
  "tsx", "bun", "deno", "vite-node",
  "sed", "awk", "sort", "uniq", "cut", "tr", "tee",
  "xargs", "watch", "timeout",
  "source", ".",
  "pip", "npm", "yarn", "cargo", "go",
  "uv",
]);

/** Flags on `find` that make it dangerous (excluding -exec which depends on the subcommand). */
export const dangerousFindFlags = /(?<![\w./-])-(?:delete|truncate|fprint|fprintf|fls)\b/;

/**
 * Flags that make `sed` dangerous (in-place editing). `-i` may carry a backup
 * suffix (the characters right after `i`: `-in`, `-i.bak`, `-i~`, `-i_bak`):
 * there is no "next-line" flag, so any short cluster containing `i` before an
 * inline-value `-e`/`-f` is in-place (incl. uppercase `-E` in `-Ei`).
 *
 * The lookbehind restricts the match to a real flag token (preceded by
 * whitespace or start of context). Unanchored, a mid-word dash inside a path
 * is misread as a flag: `agent-session.ts` matched `-[a-z]*i[a-z]*\.ts`
 * (the "i" in "session") and flagged read-only `sed -n` as in-place.
 * Long form only allows the valid GNU sed spellings `--in-place` / `--in-place=suffix`.
 */
export const dangerousSedFlags = /(?<![\w./-])-[a-bd-gj-zA-Z]*i[^\s/]*(?:\s|$)|(?<![\w./-])--in-place(?:=|\s|$)/;

/** Flags that make `perl` dangerous (in-place editing via -i, optional suffix). */
export const dangerousPerlFlags = /(?<![\w./-])-[a-bd-zA-Z]*i[^\s/]*(?:\s|$)/;

/** Command + subcommand pairs that are always safe (read-only, no side effects). */
const allowedBashSubcommands = new Set([
  "npm ls", "npm view", "npm info",
  "yarn ls", "yarn info",
  "pnpm ls",
  "tsc",
  "cargo check", "cargo clippy", "cargo doc",
]);

/** Check if a first word matches the static allowlist (O(1)). */
export function isAllowedCommand(firstWord: string): boolean {
  return allowedBashCommands.has(firstWord);
}

/**
 * Check if a segment is a safe command+subcommand pair (or safe standalone command).
 * e.g. "npm test -- --coverage" → "npm test" → match.
 *      "tsc" → match (standalone).
 *      "tsc --noEmit" → match (standalone + flags).
 */
export function isSafeSubcommand(segment: string): boolean {
  const tokens = segment.trim().split(/\s+/);
  const cmd = path.basename(tokens[0].toLowerCase());

  // Standalone command in allowlist (e.g. "tsc", "tsc --noEmit")
  if (allowedBashSubcommands.has(cmd)) {
    // If there's a second token and it's not a flag, it's a subcommand — require exact match
    if (tokens.length >= 2 && !tokens[1].startsWith("-")) {
      return allowedBashSubcommands.has(`${cmd} ${tokens[1].toLowerCase()}`);
    }
    return true;
  }

  // Command + subcommand pair (e.g. "npm test")
  if (tokens.length >= 2) {
    const sub = tokens[1].toLowerCase();
    return allowedBashSubcommands.has(`${cmd} ${sub}`);
  }

  return false;
}

/** Wrapper commands that delegate to another command (xargs sed -i, timeout rm, etc.).
 * `sudo` belongs here for the same reason `env` does: it sets credentials and
 * execs the rest, so every consumer keyed on "what does this segment run" must
 * see past it — without it the pattern tables never saw `sudo mkfs` and an
 * absolute bar could be stepped over by prefixing it (found by the D-b probe
 * 2026-10-19; the operator's caveat: in a non-interactive shell `sudo` usually
 * dies on the missing password, so the shapes that matter are NOPASSWD rules
 * and cached credentials). */
export const wrapperCommands = new Set([
  "xargs", "watch", "timeout", "parallel", "env", "nice", "ionice", "stdbuf", "sudo",
]);

/** Shell interpreters used by find -exec and similar constructs. */
export const SHELL_INTERPRETERS = new Set(["bash", "sh", "zsh", "fish", "dash", "ksh", "csh", "tcsh"]);

/** Script interpreters that execute arbitrary code (treated as write-capable). */
export const SCRIPT_INTERPRETERS = new Set([
  "python", "python3", "python2", "py",
  "node", "nodejs",
  "ruby", "rb",
  "perl", "php", "lua",
  "deno", "bun", "julia", "r",
  "go run", "rustc",
]);

/** Package manager commands that use subcommands (npm install, cargo check, etc.). */
export const PACKAGE_MANAGERS = new Set(["npm", "yarn", "pnpm", "npx", "cargo", "pip", "pip3", "uv", "go", "bun"]);

/**
 * First words that open a network connection — or fetch remote content that
 * can execute (package managers), or deploy (container/cloud CLIs). ONE
 * definition: the /dspa hard gate uses it to keep auto-allow offline, and the
 * judge packet uses it for the network line. They must not drift — a command
 * the gate calls network egress must not be annotated "network: none" in the
 * packet the judge sees.
 */
export const NETWORK_COMMANDS = new Set([
  "curl", "wget", "nc", "ncat", "ssh", "scp", "sftp", "ftp", "rsync",
  // package managers: install = fetch + execute (postinstall/build scripts)
  "npm", "npx", "pnpm", "yarn", "bun", "pip", "pip3", "uv",
  // container + cloud CLIs: pull/deploy surface
  "docker", "podman", "kubectl", "aws", "gcloud", "az",
]);

// ── D10: fetchable package run forms (docs/dspa-redesign.md) ──

/**
 * Run forms that may FETCH the package on cache miss — the same fetch class
 * the floor stops for fetch forms (arbitrary postinstall execution). Keyed by
 * first word; "all" = bare form (`npx <pkg>`), else the subcommand set
 * (`npm exec`, `pnpm dlx`, …). LOCAL run forms (`npm run`, `uv run`,
 * `bun <script>`) are deliberately absent — they execute repo-visible code
 * the judge already sees and are never trust-gated.
 *
 * ONE definition: the dspa floor (untrusted-package stop) and the bash
 * policy (trusted-package auto-allow) must not drift.
 */
export const FETCH_PKG_FORMS: Record<string, ReadonlySet<string> | "all"> = {
  npx: "all",
  uvx: "all",
  bunx: "all",
  npm: new Set(["exec", "x"]),
  pnpm: new Set(["dlx", "exec", "x"]),
  yarn: new Set(["dlx", "x"]),
  uv: new Set(["x"]),
  bun: new Set(["x"]),
};

/**
 * Flags whose VALUE is the package the run form fetches and executes
 * (`npx -p pkg cmd`, `npx --package=pkg cmd`, `uvx --from pkg cmd`,
 * `npm exec -p pkg -- cmd`). Per family, because one short flag means two
 * things: for the uv family `-p` is `--python` (an interpreter, answered by
 * UV_VALUE_FLAGS below and vetted in config/trusted-scripts), so it selects
 * no package there. Skipping these flags was the G7 hole: `npx --package=evil-pkg tsc`
 * installed evil-pkg while package trust vouched for `tsc` — a grant for a
 * package the command never fetched.
 */
const FETCH_PKG_SELECT: Record<string, ReadonlySet<string>> = {
  npx: new Set(["-p", "--package"]),
  npm: new Set(["-p", "--package"]),
  pnpm: new Set(["-p", "--package"]),
  yarn: new Set(["-p", "--package"]),
  bunx: new Set(["--package"]),
  bun: new Set(["--package"]),
  uvx: new Set(["--from"]),
  uv: new Set(["--from"]),
};

/**
 * uv's run-form options that TAKE A VALUE — arity only, not a verdict on what
 * they allow. Every option of `uv run`/`uvx` whose help line carries a value
 * placeholder (uv 0.13.x, all 83 options; `--from` is absent here because it
 * belongs to `uv tool run` and is a package-select flag above).
 *
 * ONE table, three consumers: the fetch-form package scan (`uvx --python 3.12
 * tsc` named `3.12` as the fetched package when the value was read as the
 * command word), the script-operand scan (`uv run --color never python3 s.py`
 * named `never` as the payload, so the trusted-script umbrella vanished), and
 * uv's own option walk in config/trusted-scripts. Guessing arity per site is
 * how those two prompts came to be wrong.
 */
export const UV_VALUE_FLAGS: ReadonlySet<string> = new Set([
  "-C", "-P", "-f", "-i", "-p", "-w",
  "--with", "--color", "--extra", "--group", "--index", "--python", "--package",
  "--project", "--env-file", "--no-extra", "--no-group", "--cache-dir",
  "--directory", "--index-url", "--link-mode", "--find-links", "--only-group",
  "--prerelease", "--resolution", "--config-file", "--default-index",
  "--exclude-newer", "--fork-strategy", "--upgrade-group", "--with-editable",
  "--config-setting", "--index-strategy", "--extra-index-url", "--python-platform",
  "--refresh-package", "--upgrade-package", "--keyring-provider",
  "--no-build-package", "--no-binary-package", "--reinstall-package",
  "--with-requirements", "--no-sources-package", "--prerelease-package",
  "--allow-insecure-host", "--no-editable-package", "--exclude-newer-package",
  "--config-settings-package", "--no-build-isolation-package",
]);

/** A select-flag value no grant can name: an expansion or a glob char. */
const OPAQUE_PKG_VALUE_RE = /[$`*?{]/;

/** What a fetchable run form fetches (see fetchFormScan). */
export interface FetchFormScan {
  /**
   * Every package the form fetches, verbatim (case-sensitive trust keys),
   * command order. With a select flag the trailing word is a command run from
   * INSIDE those packages, not a package of its own
   * (`npx -p typescript tsc` fetches typescript and runs its tsc).
   */
  pkgs: string[];
  /**
   * A select flag whose value the shell decides at run time (`-p "$PKG"`, an
   * unquoted glob), or a select flag with no value token. Nothing can be
   * vouched for it, so the form fails closed: no package trust covers it.
   */
  opaque: boolean;
}

/** Strip a `@version` pin (`tsc@5.0.0` → `tsc`); keeps scoped `@scope/name`. */
export function stripPkgVersion(pkg: string): string {
  const at = pkg.lastIndexOf("@");
  return at > 0 ? pkg.slice(0, at) : pkg;
}

/**
 * The packages a fetchable run form fetches, or null: not a fetch form, a
 * local form (`npm run …`), or no package token at all. Flags are skipped
 * EXCEPT the package-select flags, whose values ARE the fetch set; `K=V` env
 * prefixes are skipped and version pins stripped so trust keys are bare
 * package names. Only TOP-LEVEL segments are checked (indirection like
 * `out=$(npx foo)` stays judge-only by design).
 *
 * The package token is kept VERBATIM as the trust key: npm scoped names are
 * case-sensitive (`@org/tool` and `@Org/Tool` are different packages), so a
 * trust grant for one must not cover the other. Lowercasing is used only to
 * match the SUBCOMMAND of set forms (`npm run` vs `npm RUN` — git/npm treat
 * subcommands case-insensitively in practice, and the set is lowercase).
 */
export function fetchFormScan(first: string, words: string[]): FetchFormScan | null {
  const forms = FETCH_PKG_FORMS[first];
  if (!forms) return null;
  const select = FETCH_PKG_SELECT[first];
  // For the uv family the option arity is known, so an option's VALUE is
  // never the command word; other families' options are not modelled and fail
  // closed by being named as the package (`npx --cache /tmp/c tsc`).
  const arity = first === "uv" || first === "uvx" ? UV_VALUE_FLAGS : undefined;
  const setForms = forms === "all" ? null : forms;
  const pkgs: string[] = [];
  let opaque = false;
  // Set forms (`npm exec`) name their subcommand before the package; "all"
  // forms (`npx`) put the package first.
  let subSeen = forms === "all";
  let cmdWord: string | undefined;
  for (let i = 1; i < words.length; i++) {
    const w = words[i];
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(w)) continue;
    if (w.startsWith("-")) {
      const eq = w.indexOf("=");
      // Short flags are case-sensitive (`uvx -P` is not `-p`); long ones fold.
      const flag = eq === -1 ? w : w.slice(0, eq);
      const name = flag.startsWith("--") ? flag.toLowerCase() : flag;
      if (!select?.has(name)) {
        // A value-taking option's operand belongs to the option; an attached
        // value (`--python=3.12`) has no operand token to skip.
        if (arity?.has(name) && eq === -1) i++;
        continue;
      }
      const v = eq === -1 ? words[++i] : w.slice(eq + 1);
      // No value at all (end of command, or the next token is another flag):
      // nothing is selected, and nothing can be vouched for it.
      if (v === undefined || v.startsWith("-") || OPAQUE_PKG_VALUE_RE.test(v)) opaque = true;
      else pkgs.push(stripPkgVersion(v));
      continue;
    }
    if (!subSeen) {
      // `uv tool run` is uvx's two-word spelling — the set is per word, so the
      // pair is matched here (unmatched, the form named no package at all).
      if (first === "uv" && w === "tool" && words[i + 1]?.toLowerCase() === "run") {
        i++;
        subSeen = true;
        continue;
      }
      if (setForms && !setForms.has(w.toLowerCase())) return null; // a local form, never gated
      subSeen = true;
      continue;
    }
    if (cmdWord === undefined) cmdWord = w;
  }
  if (cmdWord !== undefined && pkgs.length === 0) pkgs.push(stripPkgVersion(cmdWord));
  if (pkgs.length === 0 && !opaque) return null;
  return { pkgs, opaque };
}

/**
 * The package a fetchable run form segment names, or null: not a fetch form,
 * a local form (`npm run …`), or no package token. Flags and `K=V` env
 * prefixes are skipped; version pins are stripped so trust keys are bare
 * package names. Only TOP-LEVEL segments are checked (indirection like
 * `out=$(npx foo)` stays judge-only by design).
 *
 * The package token is kept VERBATIM as the trust key: npm scoped names are
 * case-sensitive (`@org/tool` and `@Org/Tool` are different packages), so a
 * trust grant for one must not cover the other. Lowercasing is used only to
 * match the SUBCOMMAND of set forms (`npm run` vs `npm RUN` — git/npm treat
 * subcommands case-insensitively in practice, and the set is lowercase).
 */
export function fetchFormPackage(first: string, words: string[]): string | null {
  const forms = FETCH_PKG_FORMS[first];
  if (!forms) return null;
  let i = 1;
  let sub: string | undefined;
  let subLower: string | undefined;
  for (; i < words.length; i++) {
    const w = words[i];
    if (w.startsWith("-") || /^[A-Za-z_][A-Za-z0-9_]*=/.test(w)) continue;
    sub = w;
    subLower = w.toLowerCase();
    break;
  }
  if (forms === "all") {
    return sub ? stripPkgVersion(sub) : null;
  }
  if (!subLower || !forms.has(subLower)) return null;
  for (let j = i + 1; j < words.length; j++) {
    const w = words[j];
    if (w.startsWith("-") || /^[A-Za-z_][A-Za-z0-9_]*=/.test(w)) continue;
    return stripPkgVersion(w);
  }
  return null;
}

/** Leading inline env-assignment prefix (`FOO=bar cmd`) on raw words.
 *  One pair of surrounding quotes is ignored (`"FOO=bar" cmd` is the same). */
const ENV_PREFIX_RE = /^[A-Za-z_][A-Za-z0-9_]*=/;

function stripQuotes(w: string): string {
  return w.length >= 2 && ((w[0] === '"' && w.endsWith('"')) || (w[0] === "'" && w.endsWith("'")))
    ? w.slice(1, -1)
    : w;
}

/** Index of the first non-env-assignment word (0 when none lead). */
export function skipEnvPrefixes(words: string[]): number {
  let i = 0;
  while (i < words.length && ENV_PREFIX_RE.test(stripQuotes(words[i]))) i++;
  return i;
}

/** Git global flags that may precede the subcommand. Single definition —
 *  used by the risk layer (segment-helpers parseGitSubcommand) and both
 *  network-egress collectors below. */
export const GIT_GLOBAL_FLAGS = new Set(["-c", "-C", "--git-dir", "--work-tree", "--no-pager", "-p", "--paginate", "--no-replace-objects", "--literal-pathspec", "--no-optional-locks", "--bare", "--help"]);

/**
 * The git remote subcommand a segment names, or null: not git, env prefixes
 * skipped, and the subcommand resolved PAST global flags (`git -C dir push`
 * → push — the -C value is a location, not the subcommand). Raw words (no
 * re-tokenization): both network-egress collectors call this on their own
 * segment split, so the two stay in sync.
 */
export function gitNetworkSubcommand(words: string[]): string | null {
  const start = skipEnvPrefixes(words);
  // Quote-aware: the shell strips one pair of surrounding quotes, so
  // `"git" push` and `git "-C" dir push` are egress exactly like their
  // unquoted forms (the floor and the packet annotation share this).
  if (stripQuotes(words[start])?.toLowerCase() !== "git") return null;
  let i = start + 1;
  while (i < words.length) {
    const a = stripQuotes(words[i]);
    if (GIT_GLOBAL_FLAGS.has(a)) {
      // -c/-C and --git-dir/--work-tree consume a value argument.
      if (a === "-c" || a === "-C" || a.startsWith("--git-dir") || a.startsWith("--work-tree")) i++;
      i++;
      continue;
    }
    if (a.startsWith("--") && a.includes("=")) { i++; continue; } // --flag=value
    break;
  }
  if (i >= words.length) return null;
  const sub = stripQuotes(words[i]).toLowerCase();
  return GIT_NETWORK_SUBCOMMANDS.has(sub) ? sub : null;
}

/** git subcommands that talk to a remote. */
export const GIT_NETWORK_SUBCOMMANDS = new Set(["push", "fetch", "pull", "clone"]);

/** http(s) URL in command text (non-global). The bracket alternative keeps a
 *  bracketed IPv6 host whole (`http://[::1]:9931/x`): the plain class used to
 *  stop at `]`, so the host reached the loopback check truncated. */
export const NETWORK_URL_RE = /https?:\/\/(?:\[[0-9A-Fa-f:.]+\]|[^\s"'`)\]])+/;

export const NETWORK_URL_RE_GLOBAL = new RegExp(NETWORK_URL_RE.source, "g");

/** cargo subcommands that fetch from the crates registry. */
const CARGO_FETCH_SUBS = new Set(["fetch", "add", "update", "vendor"]);

/** go forms that fetch from the module proxy (`get`, `install`, and the
 *  `mod` two-word forms `download`/`tidy`). */
const GO_FETCH_FORMS = new Set(["get", "install", "mod download", "mod tidy"]);

/**
 * Explicit go/cargo fetch forms — the D8 fetch class (registry fetch +
 *  build-script execution) the floor stops for npm/pip. go/cargo THEMSELVES
 *  stay D1-judgeable dangerous commands (`cargo build` is pinned judgeable)
 *  — only the explicit fetch forms hit the egress floor. Quote-aware like
 *  gitNetworkSubcommand; go's `-C` consumes a value argument.
 */
export function goCargoFetchForm(words: string[]): string | null {
  const start = skipEnvPrefixes(words);
  const first = stripQuotes(words[start])?.toLowerCase();
  if (first !== "cargo" && first !== "go") return null;
  const sub: string[] = [];
  let i = start + 1;
  while (i < words.length && sub.length < 2) {
    const w = stripQuotes(words[i]);
    if (w.startsWith("-")) {
      if (w === "-C") i++; // -C dir consumes its value
      i++;
      continue;
    }
    sub.push(w.toLowerCase());
    i++;
  }
  if (first === "cargo") {
    return sub[0] && CARGO_FETCH_SUBS.has(sub[0]) ? `cargo ${sub[0]}` : null;
  }
  for (const n of [2, 1]) {
    const form = sub.slice(0, n).join(" ");
    if (GO_FETCH_FORMS.has(form)) return `go ${form}`;
  }
  return null;
}

/**
 * All network egress in a command: per-segment OPERATIVE first words that can
 * open a network (or fetch/deploy — see NETWORK_COMMANDS), `git` remote
 * subcommands (resolved past global flags), and http(s) URLs anywhere in the
 * text (deduped, in order).
 *
 * Shared with the /dspa hard gate (dspa-gate.ts networkHit — first hit),
 * which layers one exception on top: package-manager RUN forms (D8) are
 * judgeable there, though still annotated here. The operative-command and
 * git-subcommand resolution lives in the shared helpers above so the two
 * cannot drift: a command the gate treats as network egress must not be
 * annotated "network: none" in the packet the judge sees.
 */
export function findNetworkEgress(
  command: string,
  segments: string[],
): { commands: string[]; urls: string[] } {
  const commands: string[] = [];
  const add = (hit: string) => {
    if (!commands.includes(hit)) commands.push(hit);
  };
  for (const seg of segments) {
    const words = seg.trim().split(/\s+/);
    // stripQuotes: a quoted command word ("ssh" host) is the same egress to
    // the shell — the first word is judged dequoted (git subcommand
    // resolution is quote-aware in gitNetworkSubcommand).
    const first = stripQuotes(words[skipEnvPrefixes(words)])?.toLowerCase();
    if (!first) continue;
    if (NETWORK_COMMANDS.has(first)) {
      add(first);
      continue;
    }
    const sub = gitNetworkSubcommand(words);
    if (sub) add(`git ${sub}`);
    const gc = goCargoFetchForm(words);
    if (gc) add(gc);
  }
  const urls: string[] = [];
  for (const m of command.matchAll(NETWORK_URL_RE_GLOBAL)) {
    if (!urls.includes(m[0])) urls.push(m[0]);
  }
  return { commands, urls };
}

/** Pre-compiled regex for tee write check. */
const TEE_WRITE_RE = /\btee\b.*\S/;

/** Pre-compiled regex for sort -o / --output write target (space, `=`, attached
 *  -ox, and cluster -ro forms — getopt lets -o consume the rest of the token
 *  or the next token). */
export const SORT_OUTPUT_RE = /(?:^|\s)(?:--output(?:\s+|=)\S+|-[a-zA-Z]*o(?:\S+|\s+\S+))/;

/** Commands that always perform write operations (unconditional — no flag-dependent behavior). */
const ALWAYS_WRITE = new Set([
  "rm", "rmdir", "unlink", "mv", "cp", "chmod", "chown",
  "touch", "mkdir", "dd", "truncate", "patch", "install", "ln",
]);

/** Archive/package-manager commands that always write. */
const ALWAYS_WRITE_ARCHIVE_PKG = new Set([
  "tar", "zip", "unzip", "gzip", "gunzip",
  "pip", "npm", "yarn", "cargo", "go", "uv",
  // npx executes (and can fetch) arbitrary packages — wrapper delegation
  // (timeout npx …) must not treat it as benign.
  "npx",
]);

// ── Inline-code write evidence ───────────────────────────────────────────
//
// An interpreter used to be write-capable BY SHAPE: a `-c`/`-e` flag or a
// heredoc was enough. The 2026-10-16 ledger is what that costs — 8 of 74
// prompts said `write outside base` for commands that read
// (`cd ~/x && python3 -c "json.load(open('f.json'))"` under a re-based cwd),
// and the Always-Allow tier of those prompts stored a session WRITE grant for
// a read. Body evidence decides now: inspected code with no write primitive
// touches the base it runs in, it does not write it. The one direction that
// stays fail-closed is the body we cannot read — a program that arrives from
// a variable or a command substitution, a heredoc the shell expands, a
// decoded blob, or a body the caller never hands us.

/** One code body a segment hands to an interpreter, as the parser saw it. */
export interface CodeBody {
  text: string;
  /** True when the text is not what the interpreter ran: the shell expanded
   * part of it (`$f`, `$( )`, an unquoted heredoc), or it came from a
   * variable. An opaque body is write-capable — no argument about it. */
  opaque: boolean;
}

/** Write primitives in code (python / node / perl / ruby / php / shell-in-code). */
const CODE_WRITE_RES: RegExp[] = [
  // open(path, "w") / .open(p, "a") / mode="w+" — a bare open(path) is a read,
  // so the mode must be its own argument (`[^)]*` would match the path).
  /\bopen\s*\([\s\S]{0,200}?,\s*['"][rwaebxtn+]{1,4}['"]\s*[,)]/,
  /\bmode\s*=\s*['"][^'"\s]{1,6}[wa+]/,
  // handle / pathlib / node-fs writes.
  /\.(?:write_text|write_bytes|writelines|writeFileSync|appendFileSync|writeFile|appendFile)\s*\(/,
  /\b(?:write|append)File(?:Sync)?\s*\(/,
  /\.(?:touch|unlink|rmdir|mkdir|makedirs|rename)\s*\(/,
  // module-level filesystem mutations.
  /\b(?:os|shutil)\s*\.\s*(?:remove|rmdir|removedirs|renames?|replace|truncate|unlink|makedirs?|mkdir|move|copytree|copyfile|copy2?|chown|chmod|link|symlink|startfile|execl?p?[ec]?[vl]*|spawn[lv]\w*)\s*\(/,
  /\bfs(?:Promises)?\s*\.\s*(?:writeFile|appendFile|unlink|rm|mkdir|rmdir|rename|copyFile|cp|truncate|chmod|chown|symlink|link)\w*\s*\(/,
  /\b(?:unlinkSync|rmSync|mkdirSync|rmdirSync|renameSync|truncateSync|copyFileSync|cpSync|rimraf)\s*\(/,
  // code that runs a program: what that program does is not in this text.
  /\b(?:os\.system|os\.popen|subprocess|execSync|spawnSync|execFileSync|child_process|shell\s*=\s*True)\b/,
  // ruby / php write and exec primitives.
  /\b(?:FileUtils|Pathname)\s*\.\s*(?:mv|rm|rm_rf|cp|copy|remove)\b|\bFile\.(?:delete|write|open|rename|unlink|touch|mkdir)\b|\bIO\.write\b/,
  /\b(?:file_put_contents|fwrite|fputs|passthru|shell_exec|proc_open|popen|mkdir|rmdir|touch|rename|unlink|chmod|chown|copy)\s*\(/,
  // a shell command inside a string, in the verbs that create or change files.
  /(?:^|[\s;'"`])(?:rm|mv|cp|dd|tee|install|truncate|touch|chmod|chown|chgrp|ln|mkdir|rmdir|rename|unlink|patch)\s+[-'"$\w]/,
  // a mode string passed as an argument: perl `open(my $f, '>', $p)`, C-style
  // fopen. Python's open(f,'w') is caught above; a bare '>' only appears here.
  /,\s*['"][+<>]{1,2}r?['"]\s*[,)]/,
  /\bsed\s+(?:-[a-zA-Z]*[iI]\b|--in-place)/,
  /\bdd\s+if=/,
  // a redirect to something path-shaped (`x > 5` and `-> "T"` are not one).
  /(?:^|[\s;'"`])>{1,2}\s*['"]?(?=[./~$]|\w+[./])[\w./~$-]+/,
  // the body assembles more code.
  /\b(?:eval|exec)\s*\(/,
];

/** Body text that means we are not reading what runs: a substitution the shell
 * performed, a command substitution, a decoded blob, a pipe into a program. */
const OPAQUE_CODE_BODY_RE = /\$\(|`|\|\s*(?:sh|bash|zsh|dash|ksh|python\d*|node|perl|ruby|php)\b|base64\s+(?:-d|--decode)/;

/** An in-place flag on the invocation itself (`perl -pi -e`, `ruby -i`, the sed
 * form) writes its operand whatever the program body says. */
const IN_PLACE_FLAG_RE = /(?:^|\s)-[a-zA-Z]*i[a-zA-Z]*(?=\s)/;

/** An output redirect inside a shell body (`sh -c 'echo x > f'`) lands in the
 * effective cwd, which is the re-based base — the outer-command redirect scan
 * never sees it, because the whole payload is one quoted token. Same
 * exclusions as that scan: an fd dup (`2>&1`) and a numeric fd are not writes,
 * an absolute target is already in the path set. Anything else (including an
 * expansion or a truncated body) counts — fail-closed. */
function shellBodyRedirect(body: string): boolean {
  const re = /(?:\d*>>?|&>)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(body))) {
    const rest = body.slice(m.index + m[0].length).trimStart();
    // `&` stays part of the token: `>&2` / `>&-` are fd operations, not writes.
    const tok = (rest.match(/^[^\s'"`;|()]+/) ?? [""])[0];
    if (!tok) return true;
    if (tok.startsWith("&") || /^\d+$/.test(tok)) continue;
    if (tok.startsWith("/") || tok.startsWith("~")) continue;
    return true;
  }
  return false;
}

/** A shell body (`sh -c '…'`) is a list of shell commands, so its write-ness
 * is decided by the verbs it runs. The write-verb check runs before the set
 * check because `isAllowedCommand` is the auto-allow TABLE, not a read set —
 * `touch` is on it, and so is every entry whose allowance depends on segment-
 * level vetting (`git`, `grep`, `sort`, `timeout`). A body stage never gets
 * that vetting — it runs inside someone else's segment — so only the
 * unconditionally-safe subset (table entries with no exclusion reason) counts
 * as safe here. A stage with no model at all is assumed to write.
 * A python body has no such verb set — its write-ness comes from CODE_WRITE_RES. */
function shellBodyWrites(body: string): boolean {
  if (shellBodyRedirect(body)) return true;
  // Only fd operations and absolute-target redirects reach here (everything
  // else was a write above). Drop them so the verb scan sees real stages —
  // splitting on `&` would otherwise leave a stray `2` from `>&2`.
  const stages = body
    .replace(/(?:\d*>>?|&>|<)+\s*(?:&[\d-]+|(?:~|\/)[^\s'"`;|)]*)/g, " ")
    .split(/[;\n|&]+/)
    .map((s) => s.trim())
    .filter(Boolean);
  if (stages.length === 0) return false;
  for (const st of stages) {
    const raw = st.replace(/^['"`]+/, "").split(/[\s'"`]+/)[0].toLowerCase();
    if (!raw) return true;
    const verb = raw.includes("/") ? raw.slice(raw.lastIndexOf("/") + 1) : raw;
    if (isWriteOperation(verb, st)) return true;
    if (!unconditionallySafeCommands.has(verb)) return true;
  }
  return false;
}

/**
 * Does the code a segment hands to an interpreter write anything the shell
 * would not have written by itself?
 * @param bodies  the bodies the parser saw; an empty list means the caller
 *                knows the segment has inline code but has no text for it —
 *                not inspectable, so write-capable.
 * @param shell   the verb is a shell (`sh -c`), so decide by stage verbs.
 */
export function codeBodiesWrite(bodies: CodeBody[], shell = false): boolean {
  if (bodies.length === 0) return true;
  for (const b of bodies) {
    if (b.opaque || OPAQUE_CODE_BODY_RE.test(b.text)) return true;
    if (shell ? shellBodyWrites(b.text) : CODE_WRITE_RES.some((re) => re.test(b.text))) return true;
  }
  return false;
}

/**
 * Text-only form, for callers that have segment text and no body records
 * (`isWriteOperation`). Only an inline program the text itself carries is
 * inspectable: a script FILE's content was never handed over (`bash script.sh`
 * is opaque code), and a heredoc body does not appear in segment text at all.
 */
export function codeWriteCapable(command: string, text: string): boolean {
  if (IN_PLACE_FLAG_RE.test(text)) return true;
  const inline = text.match(/(?:^|\s)-[ce]\s+(["'])([\s\S]*?)\1/);
  if (!inline) return true; // no program text in hand
  const body = inline[2];
  if (OPAQUE_CODE_BODY_RE.test(body)) return true;
  return SHELL_INTERPRETERS.has(command) ? shellBodyWrites(body) : CODE_WRITE_RES.some((re) => re.test(body));
}

// ── Write operation handlers ──

/** Command → write check (match, evaluate). */
const WRITE_HANDLERS: Array<{ match: (cmd: string) => boolean; evaluate: (cmd: string, context: string) => boolean }> = [
  { match: (c) => ALWAYS_WRITE.has(c), evaluate: () => true },
  { match: (c) => ALWAYS_WRITE_ARCHIVE_PKG.has(c), evaluate: () => true },
  { match: (c) => c === "sed", evaluate: (_, ctx) => dangerousSedFlags.test(ctx) },
  { match: (c) => c === "tee", evaluate: (_, ctx) => TEE_WRITE_RE.test(ctx) },
  { match: (c) => c === "sort", evaluate: (_, ctx) => SORT_OUTPUT_RE.test(ctx) },
  // An interpreter is write-capable on the evidence of its code, not on the
  // shape of the call (see the body-evidence block above).
  { match: (c) => SHELL_INTERPRETERS.has(c), evaluate: (cmd, ctx) => codeWriteCapable(cmd, ctx) },
  { match: (c) => SCRIPT_INTERPRETERS.has(c), evaluate: (cmd, ctx) => codeWriteCapable(cmd, ctx) },
];

/**
 * Check whether a given command + surrounding context is a write operation.
 * Consolidates the duplicated logic from isWrapperRunningWrite and isFindExecWrite.
 *
 * @param command  The command name to check (lowercase).
 * @param context  The full segment text after the command (for flag-dependent checks like sed -i).
 */
export function isWriteOperation(command: string, context: string): boolean {
  for (const handler of WRITE_HANDLERS) {
    if (handler.match(command)) return handler.evaluate(command, context);
  }
  return false;
}
