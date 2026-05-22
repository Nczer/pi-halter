/**
 * Tests for path analysis functions.
 * Run: npx tsx test/path-analysis.ts
 */

import path from "node:path";
import os from "node:os";
import {
  expandTilde,
  resolvePathReal,
  isInsideCwd,
  isInsideAutoAllowedDir,
  isAllowedReadPath,
  getOutsideCwdPaths,
  isProjectPiPath,
  isPathDenied,
} from "../path-analysis";

let passed = 0;
let failed = 0;

function assert(cond: boolean, msg: string) {
  if (cond) { passed++; console.log(`  ✓ ${msg}`); }
  else { failed++; console.error(`  ✗ ${msg}`); }
}

const home = os.homedir();
const cwd = "/home/nczer/Projects";

// ── expandTilde ──

console.log("\n=== expandTilde ===");
assert(expandTilde("~/foo") === path.join(home, "foo"), "expands ~/foo");
assert(expandTilde("~") === home, "expands ~");
assert(expandTilde("/absolute") === "/absolute", "leaves absolute alone");
assert(expandTilde("relative") === "relative", "leaves relative alone");

// ── resolvePathReal ──

console.log("\n=== resolvePathReal ===");
assert(resolvePathReal("src/index.ts", cwd) === path.join(cwd, "src/index.ts"), "resolves relative path");
assert(resolvePathReal("/etc/hosts", cwd) === "/etc/hosts", "resolves absolute path");

// Non-existent path: walks up to find existing parent
assert(
  resolvePathReal("/tmp/nonexistent/deep/file.txt", cwd) === "/tmp/nonexistent/deep/file.txt",
  "handles non-existent path gracefully",
);

// ── isInsideCwd ──

console.log("\n=== isInsideCwd ===");
assert(isInsideCwd(cwd, cwd), "cwd is inside itself");
assert(isInsideCwd(`${cwd}/src`, cwd), "subdir is inside cwd");
assert(isInsideCwd(`${cwd}/src/index.ts`, cwd), "file in subdir is inside cwd");
assert(!isInsideCwd("/etc/hosts", cwd), "/etc is outside cwd");
assert(!isInsideCwd("/home/nczer/Other", cwd), "sibling dir is outside cwd");
assert(!isInsideCwd("/home/nczer", cwd), "parent dir is outside cwd");

// ── isInsideAutoAllowedDir ──

console.log("\n=== isInsideAutoAllowedDir ===");
{
  const dirs = new Set(["/opt", "/var/log"]);
  assert(isInsideAutoAllowedDir("/opt", dirs), "exact match");
  assert(isInsideAutoAllowedDir("/opt/pi", dirs), "child of /opt");
  assert(isInsideAutoAllowedDir("/opt/pi/src", dirs), "deep child of /opt");
  assert(isInsideAutoAllowedDir("/var/log/syslog", dirs), "child of /var/log");
  assert(!isInsideAutoAllowedDir("/etc/hosts", dirs), "not in set");
  assert(!isInsideAutoAllowedDir("/optical/disk", dirs), "prefix mismatch (/optical ≠ /opt)");
}

// ── isAllowedReadPath ──

console.log("\n=== isAllowedReadPath ===");
assert(isAllowedReadPath("/tmp/foo"), "/tmp is allowed read path");
assert(isAllowedReadPath(path.join(home, ".pi/agent/foo")), ".pi is allowed read path");
assert(!isAllowedReadPath("/etc/hosts"), "/etc is not allowed read path");

// ── getOutsideCwdPaths ──

console.log("\n=== getOutsideCwdPaths ===");
{
  const autoRead = new Set<string>();
  const autoWrite = new Set<string>();

  // All inside cwd
  assert(
    getOutsideCwdPaths([`${cwd}/a`, `${cwd}/b`], cwd, autoRead, autoWrite).length === 0,
    "all inside cwd → empty",
  );

  // Mix
  const outside = getOutsideCwdPaths([`${cwd}/a`, "/etc/hosts"], cwd, autoRead, autoWrite);
  assert(outside.length === 1 && outside[0] === "/etc/hosts", "filters to outside only");

  // Auto-allowed dirs exclude paths
  autoRead.add("/opt");
  const outside2 = getOutsideCwdPaths([`${cwd}/a`, "/opt/pi", "/etc/hosts"], cwd, autoRead, autoWrite);
  assert(outside2.length === 1 && outside2[0] === "/etc/hosts", "auto-allowed dir excluded");

  // Allowed read paths exclude paths
  const outside3 = getOutsideCwdPaths([`${cwd}/a`, "/tmp/foo", "/etc/hosts"], cwd, autoRead, autoWrite);
  assert(outside3.length === 1 && outside3[0] === "/etc/hosts", "allowed read path excluded");
}

// ── isProjectPiPath ──

console.log("\n=== isProjectPiPath ===");
assert(isProjectPiPath(".pi/agent/foo", cwd), ".pi/agent/foo is project pi path");
assert(isProjectPiPath(".pi/extensions/bar", cwd), ".pi/extensions/bar is project pi path");
assert(!isProjectPiPath("src/index.ts", cwd), "src/index.ts is not pi path");
assert(!isProjectPiPath("~/other/.pi/foo", cwd), "~/.pi/foo is home pi, not project pi");

// ── isPathDenied ──

console.log("\n=== isPathDenied ===");
assert(isPathDenied(".env", cwd).denied === true, ".env is denied");
assert(isPathDenied(".env", cwd).matchedRule === ".env", ".env matched rule");
assert(isPathDenied(".env.local", cwd).denied === true, ".env.local is denied");
assert(isPathDenied(".env.production", cwd).denied === true, ".env.production is denied (glob)");
assert(isPathDenied(".env.production", cwd).matchedRule === ".env.*", ".env.production glob rule");
assert(isPathDenied("node_modules/pkg/index.js", cwd).denied === true, "node_modules is denied");
assert(isPathDenied("~/.ssh/id_rsa", cwd).denied === true, ".ssh is denied");
assert(isPathDenied("~/.aws/credentials", cwd).denied === true, ".aws is denied");
assert(isPathDenied("~/.netrc", cwd).denied === true, ".netrc is denied");
assert(isPathDenied("~/.npmrc", cwd).denied === true, ".npmrc is denied");
assert(isPathDenied("~/.docker/config.json", cwd).denied === true, ".docker/config.json is denied");
assert(isPathDenied("src/index.ts", cwd).denied === false, "src/index.ts is not denied");
assert(isPathDenied("README.md", cwd).denied === false, "README.md is not denied");

// ── Summary ──

console.log("\n============================================================");
console.log(`Results: ${passed}/${passed + failed} passed, ${failed} failed`);
if (failed) process.exit(1);
