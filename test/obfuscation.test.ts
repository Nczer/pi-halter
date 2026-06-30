import { describe, expect, it } from "vitest";
import { detectObfuscation } from "../analysis/obfuscation";

describe("detectObfuscation", () => {
  it("returns no techniques for normal commands", () => {
    const cmds = ["ls -la", "grep pattern file.txt", "cat file.txt", "echo hello"];
    for (const cmd of cmds) {
      const result = detectObfuscation(cmd);
      expect(result.detected, cmd).toBe(false);
      expect(result.techniques, cmd).toHaveLength(0);
    }
  });

  describe("variable indirection", () => {
    it("detects ${! prefix", () => {
      expect(detectObfuscation("${!cmd}").techniques).toContain("variable indirection (obfuscation)");
    });

    it("ignores normal variable usage", () => {
      expect(detectObfuscation("echo $HOME").detected).toBe(false);
    });
  });

  describe("variable holding command", () => {
    it("detects $VAR followed by word after semicolon", () => {
      // Regex: (?:^|;|\|\||&&)\s*\$[A-Z_][A-Z0-9_]*\s+\w
      // Requires uppercase var name + whitespace + word char (not a flag like -)
      expect(detectObfuscation("; $CMD file").techniques).toContain("variable holding command (obfuscation)");
    });

    it("detects after &&", () => {
      expect(detectObfuscation("&& $X file").techniques).toContain("variable holding command (obfuscation)");
    });

    it("detects after ||", () => {
      expect(detectObfuscation("|| $FOO bar").techniques).toContain("variable holding command (obfuscation)");
    });

    it("detects at start of string", () => {
      expect(detectObfuscation("$MYCMD arg").techniques).toContain("variable holding command (obfuscation)");
    });

    it("ignores lowercase variable names", () => {
      expect(detectObfuscation("; $cmd file").detected).toBe(false);
    });

    it("ignores normal variable assignment", () => {
      expect(detectObfuscation("FOO=bar").detected).toBe(false);
    });
  });

  describe("character concatenation", () => {
    it("detects double-quote concatenation", () => {
      expect(detectObfuscation("a\"b").techniques).toContain("character concatenation (obfuscation)");
    });

    it("detects single-quote concatenation", () => {
      expect(detectObfuscation("a'b").techniques).toContain("character concatenation (obfuscation)");
    });

    it("detects obfuscated command names", () => {
      expect(detectObfuscation("ec\"ho file").techniques).toContain("character concatenation (obfuscation)");
    });

    it("ignores normal quoted strings", () => {
      expect(detectObfuscation('echo "hello world"').detected).toBe(false);
    });

    it("ignores normal single-quoted arguments", () => {
      expect(detectObfuscation("echo 'hello world'").detected).toBe(false);
    });

    it("ignores English contractions (possessive)", () => {
      expect(detectObfuscation("beginner's guide").detected).toBe(false);
    });

    it("ignores English contractions (don't)", () => {
      expect(detectObfuscation("don't do that").detected).toBe(false);
    });

    it("ignores English contractions (it's)", () => {
      expect(detectObfuscation("it's fine").detected).toBe(false);
    });

    it("ignores English contractions (it'd)", () => {
      expect(detectObfuscation("it'd be nice").detected).toBe(false);
    });

    it("ignores git commit messages with contractions", () => {
      expect(detectObfuscation("git commit -m \"fix: beginner's guide\"").detected).toBe(false);
    });

    it("ignores chained commands with quoted args", () => {
      expect(detectObfuscation('cd /path && git add file && git commit -m "fix: update docs"').detected).toBe(false);
    });
  });

  describe("encoding/decoding", () => {
    it("detects base64 -d", () => {
      expect(detectObfuscation("echo foo | base64 -d").techniques).toContain("encoding/decoding (obfuscation)");
    });

    it("detects base64 -D (case insensitive)", () => {
      expect(detectObfuscation("base64 -D").techniques).toContain("encoding/decoding (obfuscation)");
    });

    it("detects printf with \\x hex escape", () => {
      expect(detectObfuscation("printf '\\x61\\x62'").techniques).toContain("encoding/decoding (obfuscation)");
    });

    it("ignores base64 encode (no -d)", () => {
      expect(detectObfuscation("echo foo | base64").detected).toBe(false);
    });
  });

  describe("indirect command via xargs", () => {
    it("detects xargs rm", () => {
      expect(detectObfuscation("find . -name '*.tmp' | xargs rm").techniques).toContain("indirect command via xargs (obfuscation)");
    });

    it("ignores xargs with safe commands", () => {
      expect(detectObfuscation("echo foo | xargs echo").detected).toBe(false);
    });
  });

  describe("xargs piping to shell interpreter", () => {
    it("detects xargs sh -c", () => {
      expect(detectObfuscation("echo rm | xargs sh -c").techniques).toContain("xargs piping to shell interpreter (obfuscation)");
    });

    it("detects xargs bash -c", () => {
      expect(detectObfuscation("echo rm | xargs bash -c").techniques).toContain("xargs piping to shell interpreter (obfuscation)");
    });

    it("ignores xargs without shell interpreter", () => {
      expect(detectObfuscation("echo foo | xargs echo").detected).toBe(false);
    });
  });

  describe("alias/function obfuscation", () => {
    it("detects alias to rm", () => {
      expect(detectObfuscation("alias safe=rm").techniques).toContain("alias/function obfuscation");
    });

    it("detects declare to sudo", () => {
      expect(detectObfuscation("declare x=sudo").techniques).toContain("alias/function obfuscation");
    });

    it("detects typeset to curl", () => {
      expect(detectObfuscation("typeset y=curl").techniques).toContain("alias/function obfuscation");
    });

    it("detects alias to wget (case insensitive)", () => {
      expect(detectObfuscation("ALIAS z=Wget").techniques).toContain("alias/function obfuscation");
    });

    it("ignores alias to safe commands", () => {
      expect(detectObfuscation("alias ll='ls -la'").detected).toBe(false);
    });
  });

  describe("multiple techniques", () => {
    it("detects multiple techniques in one command", () => {
      // base64 -d (encoding) + ${! (var indirection)
      const result = detectObfuscation("${!x} | base64 -d");
      expect(result.detected).toBe(true);
      expect(result.techniques.length).toBeGreaterThanOrEqual(2);
    });
  });
});
