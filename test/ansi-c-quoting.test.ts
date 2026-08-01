/**
 * ANSI-C quoting ($'...') security regression tests.
 *
 * Bash decodes escape sequences (\xHH, \NNN, \n, ...) inside $'...' at runtime.
 * The analyzer must decode them too — otherwise encoded paths/credentials are
 * invisible to the permission gate and dangerous commands auto-allow
 * (e.g. `cat $'\x2fhome\x2fuser\x2f.ssh\x2fid_rsa'` reads the SSH private key).
 */

import path from "node:path";
import os from "node:os";
import { describe, expect, it } from "vitest";
import { decide } from "../decision-engine";
import { createStore } from "../store";
import { decodeAnsiCEscapes, tokenizeSegment, splitOnPipe } from "../analysis/tokenizer";

const home = os.homedir();
const cwd = path.join(home, "Projects");

// ── decodeAnsiCEscapes: bash-verified escape semantics ──

describe("decodeAnsiCEscapes", () => {
  it("decodes simple escapes", () => {
    expect(decodeAnsiCEscapes("a\\nb")).toBe("a\nb");
    expect(decodeAnsiCEscapes("\\t\\r\\n")).toBe("\t\r\n");
    expect(decodeAnsiCEscapes("\\\\\\'\\\"")).toBe("\\'\"");
    expect(decodeAnsiCEscapes("\\a\\b\\e\\f\\v")).toBe("\x07\x08\x1b\x0c\x0b");
  });

  it("decodes hex escapes (max 2 digits)", () => {
    expect(decodeAnsiCEscapes("\\x2f")).toBe("/");
    expect(decodeAnsiCEscapes("\\x2fetc\\x2fpasswd")).toBe("/etc/passwd");
    expect(decodeAnsiCEscapes("\\x2fz")).toBe("/z"); // 3rd hex char is literal
  });

  it("decodes octal escapes (max 3 digits)", () => {
    expect(decodeAnsiCEscapes("\\057")).toBe("/");
    expect(decodeAnsiCEscapes("\\0")).toBe("\0");
  });

  it("decodes unicode escapes", () => {
    expect(decodeAnsiCEscapes("\\u002f")).toBe("/");
    expect(decodeAnsiCEscapes("\\U0000002f")).toBe("/");
    expect(decodeAnsiCEscapes("\\u002fz")).toBe("/z"); // max 4 hex digits
  });

  it("never throws on out-of-range unicode (gate crash defense)", () => {
    expect(decodeAnsiCEscapes("\\Uffffffff")).toBe("\ufffd");
    expect(decodeAnsiCEscapes("\\U00110000")).toBe("\ufffd");
    expect(decodeAnsiCEscapes("\\U0000D800")).toBe("\ud800"); // lone surrogate ok
  });

  it("never throws on structured fuzz of escape sequences", () => {
    // Every 1- and 2-char tail after a backslash, plus malformed/truncated forms.
    const alphabet = "xX0123456789abcdefABCDEFuUoctnrtvaeEf\\'\"?c ";
    for (const c1 of alphabet) {
      expect(() => decodeAnsiCEscapes("\\" + c1)).not.toThrow();
      for (const c2 of alphabet) {
        expect(() => decodeAnsiCEscapes("\\" + c1 + c2)).not.toThrow();
      }
    }
    // Boundary \U values.
    for (const v of ["10ffff", "110000", "ffffffff", "00000000", "d800", "1234567890abcdef"]) {
      expect(() => decodeAnsiCEscapes("\\U" + v)).not.toThrow();
      expect(() => decodeAnsiCEscapes("\\u" + v)).not.toThrow();
    }
    // Truncated / dangling escapes.
    expect(() => decodeAnsiCEscapes("\\")).not.toThrow();
    expect(() => decodeAnsiCEscapes("\\c")).not.toThrow();
    expect(() => decodeAnsiCEscapes("\\x")).not.toThrow();
    expect(() => decodeAnsiCEscapes("$'\\")).not.toThrow();
  });

  it("decodes control-char escapes", () => {
    expect(decodeAnsiCEscapes("\\cC")).toBe("\x03");
  });

  it("keeps backslash for unrecognized escapes (bash behavior)", () => {
    expect(decodeAnsiCEscapes("\\q")).toBe("\\q");
    expect(decodeAnsiCEscapes("\\z")).toBe("\\z");
    expect(decodeAnsiCEscapes("\\x")).toBe("\\x"); // no hex digits
  });

  it("leaves plain text untouched", () => {
    expect(decodeAnsiCEscapes("/etc/passwd")).toBe("/etc/passwd");
  });
});

// ── tokenizeSegment: decoded tokens ──

describe("tokenizeSegment ANSI decoding", () => {
  it("decodes $'...' arguments", () => {
    expect(tokenizeSegment("cat $'\\x2fetc\\x2fpasswd'")).toEqual(["cat", "/etc/passwd"]);
    expect(tokenizeSegment("cat $'/etc/passwd'")).toEqual(["cat", "/etc/passwd"]);
    expect(tokenizeSegment("cat $'\\057etc\\057passwd'")).toEqual(["cat", "/etc/passwd"]);
  });

  it("decodes $'...' into concatenated words", () => {
    expect(tokenizeSegment("ca$'t' /etc/passwd")).toEqual(["cat", "/etc/passwd"]);
    expect(tokenizeSegment("cat$'' x")).toEqual(["cat", "x"]);
  });

  it("handles escaped quotes inside $'...'", () => {
    expect(tokenizeSegment("echo $'a\\'b'")).toEqual(["echo", "a'b"]);
  });

  it("drops the $ prefix for $\"...\" (locale quoting)", () => {
    expect(tokenizeSegment('cat $"/etc/passwd"')).toEqual(["cat", "/etc/passwd"]);
    expect(tokenizeSegment('cat $"$HOME/.env"')).toEqual(["cat", "$HOME/.env"]);
  });

  it("does not treat escaped \\$' as ANSI-C (backslash retained, no decode)", () => {
    expect(tokenizeSegment("echo \\$'x'")).toEqual(["echo", "\\$x"]);
  });

  it("keeps other tokenizer modes undecoded (splits still quote-protected)", () => {
    expect(splitOnPipe("echo $'a|b'")).toEqual(["echo $'a|b'"]);
  });
});

// ── Permission gate regression tests ──

describe("ANSI-C quoting bypass regression", () => {
  it("baseline: cat ~/.ssh/id_rsa is blocked", async () => {
    const d = await decide({ type: "bash", command: "cat ~/.ssh/id_rsa", cwd }, createStore());
    expect(d.kind).toBe("block");
  });

  it("baseline: cat /etc/passwd prompts", async () => {
    const d = await decide({ type: "bash", command: "cat /etc/passwd", cwd }, createStore());
    expect(d.kind).not.toBe("auto-allow");
  });

  it("hex-escaped .ssh path is blocked", async () => {
    const d = await decide({ type: "bash", command: "cat $'\\x2fhome\\x2fuser\\x2f.ssh\\x2fid_rsa'", cwd }, createStore());
    expect(d.kind).toBe("block");
  });

  it("fully obfuscated .ssh path is blocked", async () => {
    const d = await decide({ type: "bash", command: "cat $'\\x2e\\x73\\x73\\x68\\x2fid_rsa'", cwd }, createStore());
    expect(d.kind).toBe("block");
  });

  it("plain $'/etc/passwd' prompts (outside cwd)", async () => {
    const d = await decide({ type: "bash", command: "cat $'/etc/passwd'", cwd }, createStore());
    expect(d.kind).not.toBe("auto-allow");
  });

  it("hex-escaped /etc/passwd prompts", async () => {
    const d = await decide({ type: "bash", command: "cat $'\\x2fetc\\x2fpasswd'", cwd }, createStore());
    expect(d.kind).not.toBe("auto-allow");
  });

  it("octal-escaped /etc/passwd prompts", async () => {
    const d = await decide({ type: "bash", command: "cat $'\\057etc\\057passwd'", cwd }, createStore());
    expect(d.kind).not.toBe("auto-allow");
  });

  it("unicode-escaped /etc/passwd prompts", async () => {
    const d = await decide({ type: "bash", command: "cat $'\\u002fetc\\u002fpasswd'", cwd }, createStore());
    expect(d.kind).not.toBe("auto-allow");
  });

  it("chained: ls && cat $'\\x2fetc\\x2fpasswd' prompts", async () => {
    const d = await decide({ type: "bash", command: "ls && cat $'\\x2fetc\\x2fpasswd'", cwd }, createStore());
    expect(d.kind).not.toBe("auto-allow");
  });

  it("quoted-escaped .env path prompts with credential warning", async () => {
    const d = await decide({ type: "bash", command: "cat $'\\x2fetc\\x2f.env'", cwd }, createStore());
    expect(d.kind).not.toBe("auto-allow");
    if (d.kind === "prompt") {
      expect(d.promptData.credentialRule).toBe(".env");
    }
  });

  it("tilde-escaped .ssh path is blocked", async () => {
    const d = await decide({ type: "bash", command: "cat $'~/.ssh/id_rsa'", cwd }, createStore());
    expect(d.kind).toBe("block");
  });

  it("$'...' as redirect target prompts (write redirect)", async () => {
    const d = await decide({ type: "bash", command: "echo hi > $'\\x2ftmp\\x2fevil'", cwd }, createStore());
    expect(d.kind).not.toBe("auto-allow");
  });

  it("escaped quote inside $'...' does not break detection", async () => {
    const d = await decide({ type: "bash", command: "cat $'\\x2fetc\\x2fpasswd\\x27\\x3brm\\x2drf\\x20\\x2f'", cwd }, createStore());
    expect(d.kind).not.toBe("auto-allow");
  });

  it("$'...' with dangerous decoded command still prompts", async () => {
    const d = await decide({ type: "bash", command: "echo $'x' && rm -rf /tmp/data", cwd }, createStore());
    expect(d.kind).not.toBe("auto-allow");
  });

  it("$'...' containing comment-looking text does not hide chained commands", async () => {
    const d = await decide({ type: "bash", command: "echo $'foo #bar' && rm -rf /tmp/data", cwd }, createStore());
    expect(d.kind).not.toBe("auto-allow");
  });

  it("harmless $'...' echo still auto-allows (no regression)", async () => {
    const d = await decide({ type: "bash", command: "echo $'hello world'", cwd }, createStore());
    expect(d.kind).toBe("auto-allow");
  });

  it("harmless quoted literal still auto-allows (no regression)", async () => {
    const d = await decide({ type: "bash", command: "ls -la $'/tmp'", cwd }, createStore());
    expect(d.kind).toBe("auto-allow");
  });
});
