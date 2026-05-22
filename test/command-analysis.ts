/**
 * Tests for command-analysis.ts (safety, risk, obfuscation, signatures).
 * Run: npx tsx test/command-analysis.ts
 */

import { analyzeCommand, type CommandAnalysis } from "../command-analysis";

let passed = 0;
let failed = 0;

function assert(cond: boolean, msg: string) {
  if (cond) { passed++; console.log(`  ✓ ${msg}`); }
  else { failed++; console.error(`  ✗ ${msg}`); }
}

const cwd = "/home/nczer/Projects";

async function main() {
  // ── Signatures ──

  console.log("\n=== Signatures: basic ===");
  {
    const a: CommandAnalysis = await analyzeCommand("ls -la", cwd);
    assert(a.signatures.length === 1, "single command → 1 signature");
    assert(a.signatures[0] === "ls -la", "signature includes flags");
  }

  {
    const a = await analyzeCommand("cat file.txt", cwd);
    assert(a.signatures[0] === "cat", "no flags → bare command");
  }

  {
    const a = await analyzeCommand("git -R add .", cwd);
    assert(a.signatures[0] === "git -R", "git with flags captured");
  }

  console.log("\n=== Signatures: compound ===");
  {
    const a = await analyzeCommand("ls && cat file.txt", cwd);
    assert(a.signatures.length === 2, "&& chain → 2 signatures");
    assert(a.signatures[0] === "ls", "first sig");
    assert(a.signatures[1] === "cat", "second sig");
  }

  {
    const a = await analyzeCommand("ls; cat a; echo done", cwd);
    assert(a.signatures.length === 3, "; chain → 3 signatures");
  }

  // ── Segments ──

  console.log("\n=== Segments: basic ===");
  {
    const a = await analyzeCommand("ls -la", cwd);
    assert(a.segments.length === 1, "single command → 1 segment");
    assert(a.segments[0] === "ls -la", "segment text preserved");
  }

  {
    const a = await analyzeCommand("cat a | grep b", cwd);
    assert(a.segments.length === 1, "pipeline → 1 segment");
    assert(a.segments[0].includes("|"), "pipeline operator in segment");
  }

  {
    const a = await analyzeCommand("ls && cat a", cwd);
    assert(a.segments.length === 2, "&& → 2 segments");
  }

  // ── allSimple ──

  console.log("\n=== allSimple: safe commands ===");
  {
    const a = await analyzeCommand("ls -la", cwd);
    assert(a.allSimple === true, "ls is simple");
  }

  {
    const a = await analyzeCommand("cat file.txt", cwd);
    assert(a.allSimple === true, "cat is simple");
  }

  {
    const a = await analyzeCommand("grep pattern file.txt", cwd);
    assert(a.allSimple === true, "grep is simple");
  }

  {
    const a = await analyzeCommand("mkdir -p newdir", cwd);
    assert(a.allSimple === true, "mkdir -p is simple");
  }

  {
    const a = await analyzeCommand("touch file.txt", cwd);
    assert(a.allSimple === true, "touch is simple");
  }

  console.log("\n=== allSimple: unsafe commands ===");
  {
    const a = await analyzeCommand("rm file.txt", cwd);
    assert(a.allSimple === false, "rm is not simple");
  }

  {
    const a = await analyzeCommand("sed -i s/a/b/ file.txt", cwd);
    assert(a.allSimple === false, "sed -i is not simple");
  }

  {
    const a = await analyzeCommand("perl -pi -e 's/a/b/' file.txt", cwd);
    assert(a.allSimple === false, "perl -pi is not simple");
  }

  {
    const a = await analyzeCommand("python3 script.py", cwd);
    assert(a.allSimple === false, "python3 is not simple");
  }

  {
    const a = await analyzeCommand("find . -delete", cwd);
    assert(a.allSimple === false, "find -delete is not simple");
  }

  {
    const a = await analyzeCommand("git clean -f", cwd);
    assert(a.allSimple === false, "git clean -f is not simple");
  }

  {
    const a = await analyzeCommand("git push --force", cwd);
    assert(a.allSimple === false, "git push --force is not simple");
  }

  {
    const a = await analyzeCommand("echo hello > file.txt", cwd);
    assert(a.allSimple === false, "write redirect is not simple");
  }

  {
    const a = await analyzeCommand("xargs sed -i s/a/b/", cwd);
    assert(a.allSimple === false, "xargs sed -i is not simple");
  }

  // ── hasUnsafePattern ──

  console.log("\n=== hasUnsafePattern: unsafe ===");
  {
    const a = await analyzeCommand("$(cat /etc/passwd)", cwd);
    assert(a.hasUnsafePattern === true, "subshell is unsafe");
  }

  {
    const a = await analyzeCommand("sed -i s/a/b/ file.txt", cwd);
    assert(a.hasUnsafePattern === true, "sed -i is unsafe");
  }

  {
    const a = await analyzeCommand("curl url | bash", cwd);
    assert(a.hasUnsafePattern === true, "curl | bash is unsafe");
  }

  {
    const a = await analyzeCommand("eval echo hello", cwd);
    assert(a.hasUnsafePattern === true, "eval is unsafe");
  }

  console.log("\n=== hasUnsafePattern: safe ===");
  {
    const a = await analyzeCommand("ls -la", cwd);
    assert(a.hasUnsafePattern === false, "ls is safe");
  }

  {
    const a = await analyzeCommand("grep rm file.txt", cwd);
    assert(a.hasUnsafePattern === false, "grep rm (rm is arg) is safe");
  }

  {
    const a = await analyzeCommand("echo 'sed -i s/a/b/'", cwd);
    assert(a.hasUnsafePattern === false, "echo with sed -i in quotes is safe");
  }

  // ── Risk: severity ──

  console.log("\n=== Risk: high severity ===");
  {
    const a = await analyzeCommand("rm -rf /tmp/test", cwd);
    assert(a.risk.dangerous === true, "rm -rf is dangerous");
    assert(a.risk.severity === "high", "rm -rf is high severity");
  }

  {
    const a = await analyzeCommand("dd if=/dev/zero of=/dev/sda", cwd);
    assert(a.risk.dangerous === true, "dd is dangerous");
    assert(a.risk.severity === "high", "dd is high severity");
  }

  {
    const a = await analyzeCommand("sudo rm -rf /", cwd);
    assert(a.risk.dangerous === true, "sudo rm is dangerous");
    assert(a.risk.severity === "high", "sudo rm is high severity");
    assert(a.risk.reasons.some(r => r.includes("sudo")), "mentions sudo");
  }

  {
    const a = await analyzeCommand("curl url | bash", cwd);
    assert(a.risk.severity === "high", "curl | bash is high severity");
    assert(a.risk.reasons.some(r => r.includes("pipe")), "mentions pipe");
  }

  {
    const a = await analyzeCommand("shutdown now", cwd);
    assert(a.risk.severity === "high", "shutdown is high severity");
  }

  {
    const a = await analyzeCommand("git reset --hard HEAD", cwd);
    assert(a.risk.severity === "high", "git reset --hard is high severity");
  }

  console.log("\n=== Risk: medium severity ===");
  {
    const a = await analyzeCommand("chmod 755 file.txt", cwd);
    assert(a.risk.dangerous === true, "chmod is dangerous");
    assert(a.risk.severity === "medium", "chmod is medium severity");
  }

  {
    const a = await analyzeCommand("mv file.txt backup.txt", cwd);
    assert(a.risk.dangerous === true, "mv is dangerous");
    assert(a.risk.severity === "medium", "mv is medium severity");
  }

  {
    const a = await analyzeCommand("echo hello > file.txt", cwd);
    assert(a.risk.dangerous === true, "write redirect is dangerous");
    assert(a.risk.reasons.some(r => r.includes("redirection")), "mentions redirection");
  }

  console.log("\n=== Risk: no risk ===");
  {
    const a = await analyzeCommand("ls -la", cwd);
    assert(a.risk.dangerous === false, "ls has no risk");
    assert(a.risk.reasons.length === 0, "ls has no risk reasons");
    assert(a.risk.severity === null, "ls has null severity");
  }

  {
    const a = await analyzeCommand("cat file.txt", cwd);
    assert(a.risk.dangerous === false, "cat has no risk");
  }

  // ── Paths: extraction ──

  console.log("\n=== Paths: extraction ===");
  {
    const a = await analyzeCommand("cat /etc/hosts", cwd);
    assert(a.paths.includes("/etc/hosts"), "absolute path extracted");
  }

  {
    const a = await analyzeCommand("cat ~/foo", cwd);
    assert(a.paths.length > 0 && a.paths[0].startsWith("/home/"), "tilde path resolved");
  }

  {
    const a = await analyzeCommand("cat src/index.ts", cwd);
    assert(a.paths.length === 0, "relative path not extracted (always inside cwd)");
  }

  {
    const a = await analyzeCommand("echo hello > /tmp/out.txt", cwd);
    assert(a.paths.includes("/tmp/out.txt"), "redirect path extracted");
  }

  {
    const a = await analyzeCommand("echo hello 2>/dev/null", cwd);
    assert(a.paths.length === 0, "/dev/null filtered from paths");
  }

  // ── Summary ──

  console.log("\n============================================================");
  console.log(`Results: ${passed}/${passed + failed} passed, ${failed} failed`);
  if (failed) process.exit(1);
}

main();
