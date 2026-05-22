/**
 * Tests for the Store (createStore, abort tracking, prompt counter).
 * Run: npx tsx test/store.ts
 */

import { createStore, Store } from "../store";

let passed = 0;
let failed = 0;

function assert(cond: boolean, msg: string) {
  if (cond) { passed++; console.log(`  ✓ ${msg}`); }
  else { failed++; console.error(`  ✗ ${msg}`); }
}

// ── Basic Store Operations ──

console.log("\n=== Store: Fresh state ===");
{
  const store = createStore();
  assert(store.hasAllowedBash("ls") === false, "no bash allowed initially");
  assert(store.hasAllowedReadPath("/foo") === false, "no read path allowed initially");
  assert(store.hasAllowedWritePath("/foo") === false, "no write path allowed initially");
  assert(store.hasAllowedMcpServer("exa") === false, "no mcp allowed initially");
  assert(store.getLastAbort("ls") === null, "no aborts initially");
}

console.log("\n=== Store: addAllowed (bash) ===");
{
  const store = createStore();
  store.addAllowed({ bashSigs: ["ls -la", "cat"] });
  assert(store.hasAllowedBash("ls -la") === true, "bash sig added");
  assert(store.hasAllowedBash("cat") === true, "bash sig added");
  assert(store.hasAllowedBash("rm") === false, "bash sig not added");
}

console.log("\n=== Store: addAllowed (readDirs) ===");
{
  const store = createStore();
  store.addAllowed({ readDirs: ["/opt", "/var/log"] });
  const dirs = store.listAllowedReadDirs();
  assert(dirs.has("/opt"), "read dir /opt listed");
  assert(dirs.has("/var/log"), "read dir /var/log listed");
  assert(dirs.size === 2, "read dirs count correct");
}

console.log("\n=== Store: addAllowed (writeDirs) ===");
{
  const store = createStore();
  store.addAllowed({ writeDirs: ["/tmp"] });
  const dirs = store.listAllowedWriteDirs();
  assert(dirs.has("/tmp"), "write dir /tmp listed");
  assert(dirs.size === 1, "write dirs count correct");
}

console.log("\n=== Store: addAllowed (readPaths) ===");
{
  const store = createStore();
  store.addAllowed({ readPaths: ["/etc/hosts", "/etc/resolv.conf"] });
  assert(store.hasAllowedReadPath("/etc/hosts") === true, "read path allowed");
  assert(store.hasAllowedReadPath("/etc/resolv.conf") === true, "read path allowed");
  assert(store.hasAllowedReadPath("/etc/passwd") === false, "read path not allowed");
}

console.log("\n=== Store: addAllowed (writePaths) ===");
{
  const store = createStore();
  store.addAllowed({ writePaths: ["/tmp/out.txt"] });
  assert(store.hasAllowedWritePath("/tmp/out.txt") === true, "write path allowed");
  assert(store.hasAllowedWritePath("/tmp/other.txt") === false, "write path not allowed");
}

console.log("\n=== Store: addAllowed (mcpServers) ===");
{
  const store = createStore();
  store.addAllowed({ mcpServers: ["exa", "context7"] });
  assert(store.hasAllowedMcpServer("exa") === true, "exa allowed");
  assert(store.hasAllowedMcpServer("context7") === true, "context7 allowed");
  assert(store.hasAllowedMcpServer("blender") === false, "blender not allowed");
}

console.log("\n=== Store: addAllowed (all at once) ===");
{
  const store = createStore();
  store.addAllowed({
    bashSigs: ["ls"],
    readDirs: ["/opt"],
    writeDirs: ["/tmp"],
    readPaths: ["/a"],
    writePaths: ["/b"],
    mcpServers: ["exa"],
  });
  assert(store.hasAllowedBash("ls") === true, "bash allowed");
  assert(store.listAllowedReadDirs().has("/opt"), "read dir allowed");
  assert(store.listAllowedWriteDirs().has("/tmp"), "write dir allowed");
  assert(store.hasAllowedReadPath("/a") === true, "read path allowed");
  assert(store.hasAllowedWritePath("/b") === true, "write path allowed");
  assert(store.hasAllowedMcpServer("exa") === true, "mcp allowed");
}

console.log("\n=== Store: addAllowed (partial — only some keys) ===");
{
  const store = createStore();
  store.addAllowed({ bashSigs: ["ls"] });
  assert(store.hasAllowedBash("ls") === true, "bash allowed");
}

// ── Abort Tracking ──

console.log("\n=== Store: Abort tracking ===");
{
  const now = Date.now();
  const store = createStore(() => now);

  store.recordAbort("rm -rf /");
  assert(store.getLastAbort("rm -rf /") === now, "abort recorded");
  assert(store.getLastAbort("ls") === null, "different command not recorded");

  // Second abort overwrites
  const later = now + 1000;
  const store2 = createStore(() => later);
  store2.recordAbort("rm -rf /");
  assert(store2.getLastAbort("rm -rf /") === later, "abort updated");
}

console.log("\n=== Store: Abort lazy cleanup ===");
{
  let currentTime = 0;
  const store = createStore(() => currentTime);

  // Add 101 entries (triggers cleanup threshold of 100)
  for (let i = 0; i < 101; i++) {
    currentTime = i * 1000;
    store.recordAbort(`cmd-${i}`);
  }

  // Advance time past ABORT_REMEMBER_MS (5 min = 300000ms) but keep cmd-99 recent
  currentTime = 99000 + 1000; // just after cmd-99
  // Trigger cleanup by calling getLastAbort
  store.getLastAbort("cmd-99");
  // Old entries should be pruned, recent retained
  assert(store.getLastAbort("cmd-0") === null, "old abort pruned");
  assert(store.getLastAbort("cmd-99") !== null, "recent abort retained");
}

// ── Prompt Counter ──

console.log("\n=== Store: Prompt counter ===");
{
  const store = createStore();
  assert(store.incrementPromptCount().count === 1, "count is 1");
  assert(store.incrementPromptCount().over === false, "not over threshold");

  // Pump it up: 2 (above) + 20 = 22, then one more = 23
  for (let i = 0; i < 20; i++) {
    store.incrementPromptCount();
  }
  const result = store.incrementPromptCount();
  assert(result.over === true, "over threshold after 23 increments");
  assert(result.count === 23, "count is 23");
}

// ── Reset ──

console.log("\n=== Store: Reset ===");
{
  const store = createStore();
  store.addAllowed({ bashSigs: ["ls"], readDirs: ["/opt"] });
  store.recordAbort("rm");
  store.incrementPromptCount();

  store.reset();

  assert(store.hasAllowedBash("ls") === false, "bash cleared");
  assert(store.listAllowedReadDirs().size === 0, "read dirs cleared");
  assert(store.listAllowedWriteDirs().size === 0, "write dirs cleared");
  assert(store.listAllowedReadPaths().size === 0, "read paths cleared");
  assert(store.listAllowedWritePaths().size === 0, "write paths cleared");
  assert(store.hasAllowedMcpServer("exa") === false, "mcp cleared");
  assert(store.getLastAbort("rm") === null, "abort cleared");
  assert(store.incrementPromptCount().count === 1, "prompt count reset");
}

// ── List methods return copies ──

console.log("\n=== Store: List methods return copies ===");
{
  const store = createStore();
  store.addAllowed({ bashSigs: ["ls"], readDirs: ["/opt"] });

  const bashList = store.listAllowedBash();
  bashList.add("injected");
  assert(store.hasAllowedBash("injected") === false, "bash list is a copy");

  const dirList = store.listAllowedReadDirs();
  dirList.add("injected");
  assert(store.listAllowedReadDirs().has("injected") === false, "read dir list is a copy");
}

// ── Summary ──

console.log("\n============================================================");
console.log(`Results: ${passed}/${passed + failed} passed, ${failed} failed`);
if (failed) process.exit(1);
