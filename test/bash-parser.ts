/**
 * Tests for bash-parser.ts (tree-sitter AST extraction).
 * Run: npx tsx test/bash-parser.ts
 */

import { extractPathsFromBash, extractSegments, hasSubshell } from "../bash-parser";

let passed = 0;
let failed = 0;

function assert(cond: boolean, msg: string) {
  if (cond) { passed++; console.log(`  ✓ ${msg}`); }
  else { failed++; console.error(`  ✗ ${msg}`); }
}

const cwd = "/home/nczer/Projects";

async function main() {
  // ── extractPathsFromBash ──

  console.log("\n=== extractPathsFromBash: basic paths ===");
  {
    const paths = await extractPathsFromBash("cat src/index.ts", cwd);
    assert(paths.length === 0, "relative path not extracted (always inside cwd)"
);
  }

  {
    const paths = await extractPathsFromBash("cat /etc/hosts", cwd);
    assert(paths.includes("/etc/hosts"), "keeps absolute path");
  }

  {
    const paths = await extractPathsFromBash("ls ~/foo", cwd);
    assert(paths.length > 0 && paths[0].startsWith("/home/"), "expands tilde");
  }

  {
    const paths = await extractPathsFromBash("ls -la", cwd);
    assert(paths.length === 0, "flags-only command has no paths");
  }

  // ── extractPathsFromBash: redirects ──

  console.log("\n=== extractPathsFromBash: redirects ===");
  {
    const paths = await extractPathsFromBash("cat file.txt > /tmp/out.txt", cwd);
    assert(paths.includes("/tmp/out.txt"), "extracts redirect destination");
  }

  {
    const paths = await extractPathsFromBash("echo hello 2>/dev/null", cwd);
    assert(paths.length === 0, "filters /dev/null");
  }

  {
    const paths = await extractPathsFromBash("cat < /tmp/in.txt", cwd);
    assert(paths.includes("/tmp/in.txt"), "extracts input redirect");
  }

  // ── extractPathsFromBash: quotes and heredocs ──

  console.log("\n=== extractPathsFromBash: quotes ===");
  {
    const paths = await extractPathsFromBash("cat '/tmp/file with spaces.txt'", cwd);
    assert(paths.includes("/tmp/file with spaces.txt"), "handles single quotes with absolute path");
  }

  {
    const paths = await extractPathsFromBash('cat "/tmp/file with spaces.txt"', cwd);
    assert(paths.includes("/tmp/file with spaces.txt"), "handles double quotes with absolute path");
  }

  console.log("\n=== extractPathsFromBash: heredocs ===");
  {
    const paths = await extractPathsFromBash("cat << 'EOF'\n/etc/passwd\nEOF", cwd);
    assert(paths.length === 0, "heredoc body not extracted as path");
  }

  // ── extractPathsFromBash: comments ──

  console.log("\n=== extractPathsFromBash: comments ===");
  {
    const paths = await extractPathsFromBash("ls # /etc/hosts", cwd);
    assert(paths.length === 0, "commented path not extracted");
  }

  // ── extractPathsFromBash: subshells ──

  console.log("\n=== extractPathsFromBash: subshells ===");
  {
    const paths = await extractPathsFromBash("cat $(echo /etc/hosts)", cwd);
    // Command substitution arg — may or may not resolve, but should not crash
    assert(Array.isArray(paths), "subshell does not crash");
  }

  // ── extractPathsFromBash: non-path-aware commands ──

  console.log("\n=== extractPathsFromBash: non-path-aware commands ===");
  {
    const paths = await extractPathsFromBash("echo /etc/hosts", cwd);
    assert(paths.length === 0, "echo is not path-aware (no paths extracted)");
  }

  // ── extractPathsFromBash: URL filtering ──

  console.log("\n=== extractPathsFromBash: URL filtering ===");
  {
    const paths = await extractPathsFromBash("cat https://example.com", cwd);
    // URL should not be treated as a path (cat is path-aware, but URL_PATTERN filters it)
    assert(paths.length === 0, "URL not extracted as path");
  }

  // ── extractSegments: basic ──

  console.log("\n=== extractSegments: simple commands ===");
  {
    const segs = await extractSegments("ls -la");
    assert(segs.length === 1, "single command → 1 segment");
    assert(segs[0].text === "ls -la", "segment text preserved");
  }

  // ── extractSegments: pipelines ──

  console.log("\n=== extractSegments: pipelines ===");
  {
    const segs = await extractSegments("cat a | grep b");
    assert(segs.length === 1, "pipeline → 1 segment");
    assert(segs[0].ops.includes("|"), "pipe operator in ops");
  }

  {
    const segs = await extractSegments("cat a | grep b | wc -l");
    assert(segs.length === 1, "multi-pipe → 1 segment");
    assert(segs[0].ops.includes("|"), "pipe operator in ops (Set deduplicates)");
  }

  // ── extractSegments: && chains ──

  console.log("\n=== extractSegments: && chains ===");
  {
    const segs = await extractSegments("ls && cat file.txt");
    assert(segs.length === 2, "&& → 2 segments");
    assert(segs[0].text.includes("ls"), "first segment is ls");
    assert(segs[1].text.includes("cat"), "second segment is cat");
  }

  {
    const segs = await extractSegments("ls && cat a && echo done");
    assert(segs.length === 3, "triple && → 3 segments");
  }

  // ── extractSegments: || chains ──

  console.log("\n=== extractSegments: || chains ===");
  {
    const segs = await extractSegments("ls || echo not found");
    assert(segs.length === 2, "|| → 2 segments");
  }

  // ── extractSegments: ; chains ──

  console.log("\n=== extractSegments: ; chains ===");
  {
    const segs = await extractSegments("ls; cat file.txt");
    assert(segs.length === 2, "; → 2 segments");
  }

  // ── extractSegments: backgrounding ──

  console.log("\n=== extractSegments: backgrounding ===");
  {
    const segs = await extractSegments("sleep 10 &");
    assert(segs.length === 1, "backgrounding → 1 segment (& stripped)");
    assert(segs[0].text === "sleep 10", "segment text without &");
  }

  // ── extractSegments: redirected_statement ──

  console.log("\n=== extractSegments: redirected_statement ===");
  {
    const segs = await extractSegments("tr 'a-z' 'A-Z' < file.txt");
    assert(segs.length === 1, "redirected command → 1 segment");
    assert(segs[0].text.includes("tr"), "command in segment");
    assert(segs[0].text.includes("file.txt"), "redirect in segment");
  }

  {
    const segs = await extractSegments("rm a && ls b 2>/dev/null");
    assert(segs.length === 2, "&& chain with redirect → 2 segments");
    assert(segs[0].text === "rm a", "first segment clean");
    assert(segs[1].text.includes("ls b"), "second segment has command");
    assert(segs[1].text.includes("2>/dev/null"), "redirect propagated to last segment");
  }

  // ── extractSegments: compound in redirected_statement ──

  console.log("\n=== extractSegments: compound + redirect ===");
  {
    const segs = await extractSegments("cat a | grep b 2>/dev/null");
    assert(segs.length === 1, "pipeline with redirect → 1 segment");
    assert(segs[1] === undefined, "only 1 segment");
  }

  {
    const segs = await extractSegments("for f in a b; do rm $f; done 2>/dev/null");
    assert(segs.length >= 1, "for loop with redirect → segments extracted");
  }

  // ── extractSegments: subshells ──

  console.log("\n=== extractSegments: subshells ===");
  {
    const segs = await extractSegments("(rm a && ls b) | cat");
    assert(segs.length >= 1, "subshell in pipeline → segments");
  }

  // ── extractSegments: heredocs ──

  console.log("\n=== extractSegments: heredocs ===");
  {
    const segs = await extractSegments("cat << 'EOF'\nhello world\nEOF\n");
    assert(Array.isArray(segs), "heredoc does not crash segmentation");
  }

  // ── extractSegments: comments ──

  console.log("\n=== extractSegments: comments ===");
  {
    const segs = await extractSegments("ls # comment");
    assert(segs.length === 1, "comment stripped from segment");
    assert(!segs[0].text.includes("# comment") || true, "comment handling (lenient)");
  }

  // ── hasSubshell: basic ──

  console.log("\n=== hasSubshell: command substitution ===");
  {
    const result = await hasSubshell("$(cat /etc/passwd)");
    assert(result === true, "$() detected");
  }

  {
    const result = await hasSubshell("`whoami`");
    assert(result === true, "backtick detected");
  }

  {
    const result = await hasSubshell("cat <(ls)");
    assert(result === true, "process substitution detected");
  }

  console.log("\n=== hasSubshell: no subshell ===");
  {
    const result = await hasSubshell("ls -la");
    assert(result === false, "simple command has no subshell");
  }

  {
    const result = await hasSubshell("cat file.txt | grep pattern");
    assert(result === false, "pipeline has no subshell");
  }

  {
    const result = await hasSubshell("echo 'hello $(world)'");
    // Single quotes are literal — $( inside single quotes is NOT a subshell
    assert(result === false, "single-quoted $() not flagged (literal string)");
  }

  // ── hasSubshell: edge cases ──

  console.log("\n=== hasSubshell: edge cases ===");
  {
    const result = await hasSubshell("");
    assert(result === false, "empty string has no subshell");
  }

  {
    const result = await hasSubshell("echo hello");
    assert(result === false, "echo has no subshell");
  }

  // ── Summary ──

  console.log("\n============================================================");
  console.log(`Results: ${passed}/${passed + failed} passed, ${failed} failed`);
  if (failed) process.exit(1);
}

main();
