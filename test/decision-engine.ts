/**
 * Tests for the decision engine (file, mcp decisions).
 * Run: npx tsx test/decision-engine.ts
 */

import { decide, FileRequest, McpRequest } from "../decision-engine";
import { createStore } from "../store";

let passed = 0;
let failed = 0;

function assert(cond: boolean, msg: string) {
  if (cond) { passed++; console.log(`  ✓ ${msg}`); }
  else { failed++; console.error(`  ✗ ${msg}`); }
}

const cwd = "/home/nczer/Projects";

async function main() {
// ── File Decision Tests ──

console.log("\n=== File: Read inside cwd ===");
{
  const store = createStore();
  const req: FileRequest = { type: "file", toolName: "read", filePath: "src/index.ts", cwd };
  const d = await decide(req, store);
  assert(d.kind === "auto-allow", "read inside cwd auto-allowed");
}

console.log("\n=== File: Read outside cwd (first time) ===");
{
  const store = createStore();
  const req: FileRequest = { type: "file", toolName: "read", filePath: "/etc/hosts", cwd };
  const d = await decide(req, store);
  assert(d.kind === "prompt", "read outside cwd prompts");
  if (d.kind === "prompt") {
    assert(d.promptData.type === "file", "prompt data is file type");
    assert(d.promptData.isWriteOp === false, "read is not write op");
    assert(d.promptData.outsideDir !== null, "outside dir is set");
  }
}

console.log("\n=== File: Read outside cwd (after allow) ===");
{
  const store = createStore();
  store.addAllowed({ readDirs: ["/etc"] });
  const req: FileRequest = { type: "file", toolName: "read", filePath: "/etc/hosts", cwd };
  const d = await decide(req, store);
  assert(d.kind === "auto-allow", "read auto-allowed after adding dir");
}

console.log("\n=== File: Write inside cwd (first time) ===");
{
  const store = createStore();
  const req: FileRequest = { type: "file", toolName: "write", filePath: "src/output.txt", cwd };
  const d = await decide(req, store);
  assert(d.kind === "prompt", "write inside cwd prompts (not auto-allowed)");
  if (d.kind === "prompt") {
    assert(d.promptData.isWriteOp === true, "write is write op");
    assert(d.promptData.outsideDir === null, "inside cwd so outsideDir is null");
  }
}

console.log("\n=== File: Write outside cwd ===");
{
  const store = createStore();
  const req: FileRequest = { type: "file", toolName: "write", filePath: "/var/log/out.txt", cwd };
  const d = await decide(req, store);
  assert(d.kind === "prompt", "write outside cwd prompts");
  if (d.kind === "prompt") {
    assert(d.promptData.isWriteOp === true, "write op flag set");
    assert(d.promptData.outsideDir === "/var/log", "outside dir is /var/log");
  }
}

console.log("\n=== File: Edit inside cwd ===");
{
  const store = createStore();
  const req: FileRequest = { type: "file", toolName: "edit", filePath: "src/index.ts", cwd };
  const d = await decide(req, store);
  assert(d.kind === "prompt", "edit inside cwd prompts");
  if (d.kind === "prompt") {
    assert(d.promptData.isWriteOp === true, "edit is write op");
  }
}

console.log("\n=== File: Read .env (denied path, inside cwd) ===");
{
  const store = createStore();
  const req: FileRequest = { type: "file", toolName: "read", filePath: ".env", cwd };
  const d = await decide(req, store);
  assert(d.kind === "auto-allow", "reading .env inside cwd auto-allowed (denied is warning only)");
}

console.log("\n=== File: Read .env.local (denied path, inside cwd) ===");
{
  const store = createStore();
  const req: FileRequest = { type: "file", toolName: "read", filePath: ".env.local", cwd };
  const d = await decide(req, store);
  assert(d.kind === "auto-allow", "reading .env.local inside cwd auto-allowed");
}

console.log("\n=== File: Read .env.production (glob match, inside cwd) ===");
{
  const store = createStore();
  const req: FileRequest = { type: "file", toolName: "read", filePath: ".env.production", cwd };
  const d = await decide(req, store);
  assert(d.kind === "auto-allow", "reading .env.production inside cwd auto-allowed");
}

console.log("\n=== File: Read .ssh/id_rsa (denied path) ===");
{
  const store = createStore();
  const req: FileRequest = { type: "file", toolName: "read", filePath: "~/.ssh/id_rsa", cwd };
  const d = await decide(req, store);
  assert(d.kind === "prompt", "reading .ssh prompts");
  if (d.kind === "prompt") {
    assert(d.promptData.deniedRule === ".ssh", "denied rule matched");
  }
}

console.log("\n=== File: Read node_modules/package.json (denied, inside cwd) ===");
{
  const store = createStore();
  const req: FileRequest = { type: "file", toolName: "read", filePath: "node_modules/package.json", cwd };
  const d = await decide(req, store);
  assert(d.kind === "auto-allow", "reading in node_modules inside cwd auto-allowed (denied is warning only)");
}

console.log("\n=== File: Write allowed after adding path ===");
{
  const store = createStore();
  store.addAllowed({ writePaths: [`${cwd}/src/output.txt`] });
  const req: FileRequest = { type: "file", toolName: "write", filePath: "src/output.txt", cwd };
  const d = await decide(req, store);
  assert(d.kind === "auto-allow", "write auto-allowed after adding path");
}

console.log("\n=== File: allowRules for write inside cwd ===");
{
  const store = createStore();
  const req: FileRequest = { type: "file", toolName: "write", filePath: "src/out.txt", cwd };
  const d = await decide(req, store);
  if (d.kind === "prompt") {
    assert(d.allowRules.writeDirs === undefined, "inside cwd uses writePaths not writeDirs");
    assert(Array.isArray(d.allowRules.writePaths), "writePaths is array");
  }
}

console.log("\n=== File: allowFileRules for write outside cwd ===");
{
  const store = createStore();
  const req: FileRequest = { type: "file", toolName: "write", filePath: "/var/log/out.txt", cwd };
  const d = await decide(req, store);
  if (d.kind === "prompt") {
    assert(d.allowFileRules !== undefined, "outside cwd has allowFileRules");
    if (d.allowFileRules) {
      assert(d.allowFileRules.writePaths?.[0] === "/var/log/out.txt", "file rule targets specific file");
    }
  }
}

// ── MCP Decision Tests ──

console.log("\n=== MCP: First time ===");
{
  const store = createStore();
  const req: McpRequest = { type: "mcp", server: "context7", tool: "resolve-library-id" };
  const d = await decide(req, store);
  assert(d.kind === "prompt", "mcp first time prompts");
  if (d.kind === "prompt") {
    assert(d.promptData.type === "mcp", "prompt data is mcp type");
    assert(d.promptData.server === "context7", "server name correct");
    assert(d.promptData.tool === "resolve-library-id", "tool name correct");
  }
}

console.log("\n=== MCP: Auto-allow after approval ===");
{
  const store = createStore();
  store.addAllowed({ mcpServers: ["context7"] });
  const req: McpRequest = { type: "mcp", server: "context7", tool: "resolve-library-id" };
  const d = await decide(req, store);
  assert(d.kind === "auto-allow", "mcp auto-allowed after approval");
}

console.log("\n=== MCP: With argsPreview ===");
{
  const store = createStore();
  const req: McpRequest = {
    type: "mcp",
    server: "exa",
    tool: "web_search",
    argsPreview: "how to build a tree",
  };
  const d = await decide(req, store);
  if (d.kind === "prompt") {
    assert(d.promptData.argsPreview === "how to build a tree", "argsPreview passed through");
  }
}

console.log("\n=== MCP: Server extraction from tool name ===");
{
  const store = createStore();
  const req: McpRequest = { type: "mcp", server: "", tool: "joplin:get_notes" };
  const d = await decide(req, store);
  if (d.kind === "prompt") {
    assert(d.promptData.server === "joplin", "server extracted from tool name");
  }
}

console.log("\n=== MCP: allowRules ===");
{
  const store = createStore();
  const req: McpRequest = { type: "mcp", server: "blender", tool: "render" };
  const d = await decide(req, store);
  if (d.kind === "prompt") {
    assert(d.allowRules.mcpServers?.[0] === "blender", "allowRules includes server");
  }
}

// ── Summary ──

console.log("\n============================================================");
console.log(`Results: ${passed}/${passed + failed} passed, ${failed} failed`);
if (failed) process.exit(1);
}

main();
