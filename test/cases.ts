/**
 * Comprehensive test cases for the permissions extension.
 * Run: npx tsx test/cases.ts
 *
 * Agreed principles:
 *   1. Write → prompt (mkdir/touch are safe creation, auto-allow)
 *   2. Read inside cwd → auto-allow
 *   3. Code execution → prompt (unless trusted script)
 *   4. Outside cwd → prompt (first time), remembered → auto-allow
 *   5. Unsafe patterns → always prompt (DSP bypasses)
 *
 * Each case: { cmd, simple, unsafe, decision?, desc? }
 * - simple: should allSimple be true?
 * - unsafe: should hasUnsafePattern be true?
 * - decision: expected decision kind ("auto-allow" | "prompt" | "block")
 */

import { analyzeCommand } from "../command-analysis";
import { decide } from "../decision-engine";
import { store } from "../store";

const cwd = "/home/nczer/Projects";

type TestCase = {
  cmd: string;
  simple: boolean;
  unsafe: boolean;
  decision?: "auto-allow" | "prompt" | "block";
  desc?: string;
};

const cases: TestCase[] = [
  // ═══════════════════════════════════════════════════════════
  // sed
  // ═══════════════════════════════════════════════════════════
  { cmd: "sed 's/foo/bar/' file.txt", simple: true, unsafe: false, decision: "auto-allow", desc: "sed without -i (read)" },
  { cmd: "sed -n 's/foo/bar/' file.txt", simple: true, unsafe: false, decision: "auto-allow", desc: "sed -n (suppress output)" },
  { cmd: "sed -e 's/a/b/' -e 's/c/d/' file.txt", simple: true, unsafe: false, decision: "auto-allow", desc: "sed -e (multiple expressions)" },
  { cmd: "sed '1,5d' file.txt", simple: true, unsafe: false, decision: "auto-allow", desc: "sed delete range (stdout only)" },
  { cmd: "sed -i 's/foo/bar/' file.txt", simple: false, unsafe: true, decision: "prompt", desc: "sed -i (in-place write)" },
  { cmd: "sed -i '' 's/foo/bar/' file.txt", simple: false, unsafe: true, decision: "prompt", desc: "sed -i '' (macOS no-backup)" },
  { cmd: "sed -i.bak 's/foo/bar/' file.txt", simple: false, unsafe: true, decision: "prompt", desc: "sed -i.bak (backup suffix)" },
  { cmd: "sed -i.backup 's/foo/bar/' file.txt", simple: false, unsafe: true, decision: "prompt", desc: "sed -i.backup (long backup)" },
  { cmd: "sed --in-place 's/foo/bar/' file.txt", simple: false, unsafe: true, decision: "prompt", desc: "sed --in-place (long form)" },
  { cmd: "sed --in-place=.bak 's/foo/bar/' file.txt", simple: false, unsafe: true, decision: "prompt", desc: "sed --in-place=.bak" },
  { cmd: "sed -in 's/foo/bar/' file.txt", simple: true, unsafe: false, decision: "auto-allow", desc: "sed -in (next-line, NOT in-place)" },
  { cmd: "sed -i/s/foo/bar/ file.txt", simple: true, unsafe: false, decision: "auto-allow", desc: "sed -i/... (insert command, NOT in-place)" },

  // ═══════════════════════════════════════════════════════════
  // perl
  // ═══════════════════════════════════════════════════════════
  { cmd: "perl -p -e 's/foo/bar/' file.txt", simple: true, unsafe: false, decision: "auto-allow", desc: "perl -p (print, no -i)" },
  { cmd: "perl -ne 'print if /foo/' file.txt", simple: true, unsafe: false, decision: "auto-allow", desc: "perl -ne (no -i)" },
  { cmd: "perl -pi -e 's/foo/bar/' file.txt", simple: false, unsafe: true, decision: "prompt", desc: "perl -pi (combined)" },
  { cmd: "perl -i -p -e 's/foo/bar/' file.txt", simple: false, unsafe: true, decision: "prompt", desc: "perl -i -p (separate)" },
  { cmd: "perl -p -i -e 's/foo/bar/' file.txt", simple: false, unsafe: true, decision: "prompt", desc: "perl -p -i (reversed)" },
  { cmd: "perl -i.bak -pe 's/foo/bar/' file.txt", simple: false, unsafe: true, decision: "prompt", desc: "perl -i.bak (backup)" },
  { cmd: "perl -i -ne 'print' file.txt", simple: false, unsafe: true, decision: "prompt", desc: "perl -i -n (in-place, no print)" },

  // ═══════════════════════════════════════════════════════════
  // grep (always safe)
  // ═══════════════════════════════════════════════════════════
  { cmd: "grep -i pattern file.txt", simple: true, unsafe: false, decision: "auto-allow", desc: "grep -i (case insensitive)" },
  { cmd: "grep -r pattern .", simple: true, unsafe: false, decision: "auto-allow", desc: "grep -r (recursive)" },
  { cmd: "grep -l pattern *.txt", simple: true, unsafe: false, decision: "auto-allow", desc: "grep -l (file names)" },
  { cmd: "grep -c pattern file.txt", simple: true, unsafe: false, decision: "auto-allow", desc: "grep -c (count)" },
  { cmd: "grep -rn --include='*.ts' pattern .", simple: true, unsafe: false, decision: "auto-allow", desc: "grep -rn --include" },

  // ═══════════════════════════════════════════════════════════
  // find
  // ═══════════════════════════════════════════════════════════
  { cmd: "find . -name '*.txt'", simple: true, unsafe: false, decision: "auto-allow", desc: "find -name" },
  { cmd: "find . -type f -size +1M", simple: true, unsafe: false, decision: "auto-allow", desc: "find -type -size" },
  { cmd: "find . -exec grep -l pat {} \\;", simple: true, unsafe: false, decision: "auto-allow", desc: "find -exec grep (read-only)" },
  { cmd: "find . -exec cat {} \\;", simple: true, unsafe: false, decision: "auto-allow", desc: "find -exec cat (read-only)" },
  { cmd: "find . -print0 | xargs -0 ls", simple: true, unsafe: false, decision: "auto-allow", desc: "find -print0 | xargs ls" },
  { cmd: "find . -delete", simple: false, unsafe: true, decision: "prompt", desc: "find -delete" },
  { cmd: "find . -empty -delete", simple: false, unsafe: true, decision: "prompt", desc: "find -empty -delete" },
  { cmd: "find . -exec rm -f {} \\;", simple: false, unsafe: true, decision: "prompt", desc: "find -exec rm" },
  { cmd: "find . -exec sed -i s/a/b/ {} \\;", simple: false, unsafe: true, decision: "prompt", desc: "find -exec sed -i" },
  { cmd: "find . -execdir perl -pi -e 's/a/b/' {} \\;", simple: false, unsafe: true, decision: "prompt", desc: "find -execdir perl -pi" },
  { cmd: "find . -truncate", simple: false, unsafe: true, decision: "prompt", desc: "find -truncate" },
  { cmd: "find . -exec chmod 644 {} \\;", simple: false, unsafe: true, decision: "prompt", desc: "find -exec chmod" },
  { cmd: "find . -exec touch {} \\;", simple: false, unsafe: true, decision: "prompt", desc: "find -exec touch" },

  // ═══════════════════════════════════════════════════════════
  // wrapper commands: safe inner
  // ═══════════════════════════════════════════════════════════
  { cmd: "xargs grep -l pattern", simple: true, unsafe: false, decision: "auto-allow", desc: "xargs grep (read-only)" },
  { cmd: "timeout 30 ls -la", simple: true, unsafe: false, decision: "auto-allow", desc: "timeout ls" },
  { cmd: "watch ls -la", simple: true, unsafe: false, decision: "auto-allow", desc: "watch ls" },
  { cmd: "timeout 1h30m cat file.txt", simple: true, unsafe: false, decision: "auto-allow", desc: "timeout 1h30m cat" },
  { cmd: "nice cat file.txt", simple: true, unsafe: false, decision: "auto-allow", desc: "nice cat (not in allowlist, but safe)" },

  // ═══════════════════════════════════════════════════════════
  // wrapper commands: unsafe inner
  // ═══════════════════════════════════════════════════════════
  { cmd: "xargs sed -i s/a/b/", simple: false, unsafe: true, decision: "prompt", desc: "xargs sed -i" },
  { cmd: "timeout 30 rm -rf /tmp/test", simple: false, unsafe: true, decision: "prompt", desc: "timeout rm" },
  { cmd: "xargs perl -pi -e 's/a/b/'", simple: false, unsafe: true, decision: "prompt", desc: "xargs perl -pi" },
  { cmd: "timeout 10 chmod 777 file.txt", simple: false, unsafe: true, decision: "prompt", desc: "timeout chmod" },

  // ═══════════════════════════════════════════════════════════
  // read-only commands (allowedBashPatterns — auto-allow inside cwd)
  // ═══════════════════════════════════════════════════════════
  { cmd: "ls -la", simple: true, unsafe: false, decision: "auto-allow", desc: "ls" },
  { cmd: "cat file.txt", simple: true, unsafe: false, decision: "auto-allow", desc: "cat" },
  { cmd: "head -n 10 file.txt", simple: true, unsafe: false, decision: "auto-allow", desc: "head" },
  { cmd: "tail -f file.log", simple: true, unsafe: false, decision: "auto-allow", desc: "tail -f" },
  { cmd: "wc -l file.txt", simple: true, unsafe: false, decision: "auto-allow", desc: "wc" },
  { cmd: "file mystery.bin", simple: true, unsafe: false, decision: "auto-allow", desc: "file" },
  { cmd: "diff file1.txt file2.txt", simple: true, unsafe: false, decision: "auto-allow", desc: "diff" },
  { cmd: "sort file.txt", simple: true, unsafe: false, decision: "auto-allow", desc: "sort" },
  { cmd: "uniq file.txt", simple: true, unsafe: false, decision: "auto-allow", desc: "uniq" },
  { cmd: "cut -d: -f1 file.txt", simple: true, unsafe: false, decision: "auto-allow", desc: "cut" },
  { cmd: "tr 'a-z' 'A-Z' < file.txt", simple: true, unsafe: false, decision: "auto-allow", desc: "tr" },
  { cmd: "tac file.txt", simple: true, unsafe: false, decision: "auto-allow", desc: "tac" },
  { cmd: "rev file.txt", simple: true, unsafe: false, decision: "auto-allow", desc: "rev" },
  { cmd: "nl file.txt", simple: true, unsafe: false, decision: "auto-allow", desc: "nl" },
  { cmd: "fold -w 80 file.txt", simple: true, unsafe: false, decision: "auto-allow", desc: "fold" },
  { cmd: "expand file.txt", simple: true, unsafe: false, decision: "auto-allow", desc: "expand" },
  { cmd: "unexpand file.txt", simple: true, unsafe: false, decision: "auto-allow", desc: "unexpand" },
  { cmd: "fmt file.txt", simple: true, unsafe: false, decision: "auto-allow", desc: "fmt" },
  { cmd: "join file1.txt file2.txt", simple: true, unsafe: false, decision: "auto-allow", desc: "join" },
  { cmd: "comm file1.txt file2.txt", simple: true, unsafe: false, decision: "auto-allow", desc: "comm" },
  { cmd: "paste file1.txt file2.txt", simple: true, unsafe: false, decision: "auto-allow", desc: "paste" },
  { cmd: "column file.txt", simple: true, unsafe: false, decision: "auto-allow", desc: "column" },
  { cmd: "seq 1 10", simple: true, unsafe: false, decision: "auto-allow", desc: "seq" },
  // Hashing / binary inspection
  { cmd: "md5sum file.txt", simple: true, unsafe: false, decision: "auto-allow", desc: "md5sum" },
  { cmd: "sha256sum file.txt", simple: true, unsafe: false, decision: "auto-allow", desc: "sha256sum" },
  { cmd: "hexdump -C file.bin", simple: true, unsafe: false, decision: "auto-allow", desc: "hexdump" },
  { cmd: "od -c file.bin", simple: true, unsafe: false, decision: "auto-allow", desc: "od" },
  { cmd: "strings file.bin", simple: true, unsafe: false, decision: "auto-allow", desc: "strings" },
  // Strings / formatting
  { cmd: "echo hello", simple: true, unsafe: false, decision: "auto-allow", desc: "echo" },
  { cmd: "printf '%s\\n' hello", simple: true, unsafe: false, decision: "auto-allow", desc: "printf" },
  { cmd: "basename /path/to/file.txt", simple: true, unsafe: false, decision: "auto-allow", desc: "basename" },
  { cmd: "dirname /path/to/file.txt", simple: true, unsafe: false, decision: "auto-allow", desc: "dirname" },
  { cmd: "realpath file.txt", simple: true, unsafe: false, decision: "auto-allow", desc: "realpath" },
  { cmd: "readlink file.txt", simple: true, unsafe: false, decision: "auto-allow", desc: "readlink" },
  { cmd: "test -f file.txt", simple: true, unsafe: false, decision: "auto-allow", desc: "test" },
  { cmd: "true", simple: true, unsafe: false, decision: "auto-allow", desc: "true (no-op)" },
  { cmd: "false", simple: true, unsafe: false, decision: "auto-allow", desc: "false (no-op)" },
  // System info
  { cmd: "pwd", simple: true, unsafe: false, decision: "auto-allow", desc: "pwd" },
  { cmd: "cd /tmp", simple: true, unsafe: false, decision: "auto-allow", desc: "cd" },
  { cmd: "date", simple: true, unsafe: false, decision: "auto-allow", desc: "date" },
  { cmd: "whoami", simple: true, unsafe: false, decision: "auto-allow", desc: "whoami" },
  { cmd: "id", simple: true, unsafe: false, decision: "auto-allow", desc: "id" },
  { cmd: "uname -a", simple: true, unsafe: false, decision: "auto-allow", desc: "uname" },
  { cmd: "hostname", simple: true, unsafe: false, decision: "auto-allow", desc: "hostname" },
  { cmd: "groups", simple: true, unsafe: false, decision: "auto-allow", desc: "groups" },
  { cmd: "printenv", simple: true, unsafe: false, decision: "auto-allow", desc: "printenv" },
  { cmd: "uptime", simple: true, unsafe: false, decision: "auto-allow", desc: "uptime" },
  { cmd: "tty", simple: true, unsafe: false, decision: "auto-allow", desc: "tty" },
  { cmd: "tput cols", simple: true, unsafe: false, decision: "auto-allow", desc: "tput" },
  // Disk / process inspection
  { cmd: "df -h", simple: true, unsafe: false, decision: "auto-allow", desc: "df" },
  { cmd: "du -sh .", simple: true, unsafe: false, decision: "auto-allow", desc: "du" },
  { cmd: "free -m", simple: true, unsafe: false, decision: "auto-allow", desc: "free" },
  { cmd: "ps aux", simple: true, unsafe: false, decision: "auto-allow", desc: "ps" },
  { cmd: "pgrep node", simple: true, unsafe: false, decision: "auto-allow", desc: "pgrep" },
  { cmd: "pidof node", simple: true, unsafe: false, decision: "auto-allow", desc: "pidof" },
  // Command lookup
  { cmd: "which python3", simple: true, unsafe: false, decision: "auto-allow", desc: "which" },
  { cmd: "command -v python3", simple: true, unsafe: false, decision: "auto-allow", desc: "command -v" },
  { cmd: "type python3", simple: true, unsafe: false, decision: "auto-allow", desc: "type" },
  { cmd: "hash python3", simple: true, unsafe: false, decision: "auto-allow", desc: "hash" },
  // Safe file/dir creation
  { cmd: "mkdir -p newdir", simple: true, unsafe: false, decision: "auto-allow", desc: "mkdir -p" },
  { cmd: "touch file.txt", simple: true, unsafe: false, decision: "auto-allow", desc: "touch" },
  { cmd: "mktemp", simple: true, unsafe: false, decision: "auto-allow", desc: "mktemp" },
  // Calculator
  { cmd: "bc", simple: true, unsafe: false, decision: "auto-allow", desc: "bc" },
  { cmd: "expr 1 + 2", simple: true, unsafe: false, decision: "auto-allow", desc: "expr" },
  { cmd: "factor 100", simple: true, unsafe: false, decision: "auto-allow", desc: "factor" },
  { cmd: "yes", simple: true, unsafe: false, decision: "auto-allow", desc: "yes" },

  // ═══════════════════════════════════════════════════════════
  // dangerous commands (not in allowedBashPatterns → prompt)
  // ═══════════════════════════════════════════════════════════
  { cmd: "rm file.txt", simple: false, unsafe: true, decision: "prompt", desc: "rm" },
  { cmd: "rm -rf /tmp/test", simple: false, unsafe: true, decision: "prompt", desc: "rm -rf" },
  { cmd: "rmdir dir", simple: false, unsafe: true, decision: "prompt", desc: "rmdir" },
  { cmd: "unlink file.txt", simple: false, unsafe: true, decision: "prompt", desc: "unlink" },
  { cmd: "mv file.txt backup.txt", simple: false, unsafe: true, decision: "prompt", desc: "mv" },
  { cmd: "cp file.txt backup.txt", simple: false, unsafe: true, decision: "prompt", desc: "cp" },
  { cmd: "chmod 755 file.txt", simple: false, unsafe: true, decision: "prompt", desc: "chmod" },
  { cmd: "chmod -R 777 .", simple: false, unsafe: true, decision: "prompt", desc: "chmod -R" },
  { cmd: "chown user:user file.txt", simple: false, unsafe: true, decision: "prompt", desc: "chown" },
  { cmd: "chown -R user:user .", simple: false, unsafe: true, decision: "prompt", desc: "chown -R" },
  { cmd: "dd if=/dev/zero of=/dev/sda", simple: false, unsafe: true, decision: "prompt", desc: "dd" },
  { cmd: "dd of=/dev/sda", simple: false, unsafe: true, decision: "prompt", desc: "dd of= only (writes to raw device)" },
  { cmd: "dd if=/dev/zero", simple: false, unsafe: true, decision: "prompt", desc: "dd if= only (reads from raw device)" },
  { cmd: "truncate -s 0 file.txt", simple: false, unsafe: true, decision: "prompt", desc: "truncate" },
  { cmd: "patch file.txt < patch.diff", simple: false, unsafe: true, decision: "prompt", desc: "patch" },
  { cmd: "install -m 644 src dst", simple: false, unsafe: true, decision: "prompt", desc: "install" },
  { cmd: "ln -s target link", simple: false, unsafe: true, decision: "prompt", desc: "ln" },
  { cmd: "tee file.txt", simple: false, unsafe: true, decision: "prompt", desc: "tee" },
  // Archives
  { cmd: "tar czf archive.tar.gz .", simple: false, unsafe: true, decision: "prompt", desc: "tar (create)" },
  { cmd: "zip archive.zip file.txt", simple: false, unsafe: true, decision: "prompt", desc: "zip" },
  { cmd: "unzip archive.zip", simple: false, unsafe: true, decision: "prompt", desc: "unzip" },
  { cmd: "gzip file.txt", simple: false, unsafe: true, decision: "prompt", desc: "gzip" },
  { cmd: "gunzip file.txt.gz", simple: false, unsafe: true, decision: "prompt", desc: "gunzip" },
  // Package managers
  { cmd: "pip install requests", simple: false, unsafe: true, decision: "prompt", desc: "pip install" },
  { cmd: "npm install lodash", simple: false, unsafe: true, decision: "prompt", desc: "npm install" },
  { cmd: "yarn add lodash", simple: false, unsafe: true, decision: "prompt", desc: "yarn add" },
  { cmd: "cargo build", simple: false, unsafe: true, decision: "prompt", desc: "cargo build" },
  { cmd: "go build", simple: false, unsafe: true, decision: "prompt", desc: "go build" },
  { cmd: "uv pip install requests", simple: false, unsafe: true, decision: "prompt", desc: "uv pip install" },
  // Disk / system
  { cmd: "mkfs.ext4 /dev/sdb", simple: false, unsafe: true, decision: "prompt", desc: "mkfs" },
  { cmd: "mount /dev/sdb /mnt", simple: false, unsafe: true, decision: "prompt", desc: "mount" },
  { cmd: "sudo rm -rf /", simple: false, unsafe: true, decision: "prompt", desc: "sudo rm" },
  { cmd: "kill 1234", simple: false, unsafe: true, decision: "prompt", desc: "kill" },
  { cmd: "pkill node", simple: false, unsafe: true, decision: "prompt", desc: "pkill" },
  { cmd: "killall node", simple: false, unsafe: true, decision: "prompt", desc: "killall" },
  { cmd: "kill -9 1234", simple: false, unsafe: true, decision: "prompt", desc: "kill -9" },
  { cmd: "shutdown now", simple: false, unsafe: true, decision: "prompt", desc: "shutdown" },
  { cmd: "reboot", simple: false, unsafe: true, decision: "prompt", desc: "reboot" },
  { cmd: "systemctl stop nginx", simple: false, unsafe: true, decision: "prompt", desc: "systemctl stop" },
  { cmd: "systemctl disable nginx", simple: false, unsafe: true, decision: "prompt", desc: "systemctl disable" },
  // Network / remote
  { cmd: "curl https://example.com", simple: false, unsafe: true, decision: "prompt", desc: "curl" },
  { cmd: "wget https://example.com/file", simple: false, unsafe: true, decision: "prompt", desc: "wget" },
  { cmd: "ssh user@host", simple: false, unsafe: true, decision: "prompt", desc: "ssh" },
  { cmd: "scp file.txt user@host:", simple: false, unsafe: true, decision: "prompt", desc: "scp" },
  { cmd: "rsync -avz . user@host:", simple: false, unsafe: true, decision: "prompt", desc: "rsync" },
  // Scheduling / background
  { cmd: "crontab -e", simple: false, unsafe: true, decision: "prompt", desc: "crontab" },
  { cmd: "nohup python3 script.py &", simple: false, unsafe: true, decision: "prompt", desc: "nohup" },
  { cmd: "screen -dmS mysession", simple: false, unsafe: true, decision: "prompt", desc: "screen" },
  { cmd: "tmux new -s mysession", simple: false, unsafe: true, decision: "prompt", desc: "tmux" },
  // Code execution
  { cmd: "eval echo hello", simple: false, unsafe: true, decision: "prompt", desc: "eval" },
  { cmd: "bash -c 'echo hello'", simple: false, unsafe: true, decision: "prompt", desc: "bash -c" },
  { cmd: "bash -i", simple: false, unsafe: true, decision: "prompt", desc: "bash -i" },
  { cmd: "python3 script.py", simple: false, unsafe: true, decision: "prompt", desc: "python3 (code exec)" },
  { cmd: "node app.js", simple: false, unsafe: true, decision: "prompt", desc: "node (code exec)" },
  { cmd: "ruby script.rb", simple: false, unsafe: true, decision: "prompt", desc: "ruby (code exec)" },
  { cmd: "php script.php", simple: false, unsafe: true, decision: "prompt", desc: "php (code exec)" },
  { cmd: "lua script.lua", simple: false, unsafe: true, decision: "prompt", desc: "lua (code exec)" },
  // Trusted scripts — auto-allow when standalone, prompt when compound
  { cmd: "python3 ~/.pi/agent/skills/test.py", simple: true, unsafe: false, decision: "auto-allow", desc: "standalone trusted script auto-allows" },
  { cmd: "node ~/.pi/agent/skills/test.js", simple: true, unsafe: false, decision: "auto-allow", desc: "standalone trusted node script auto-allows" },
  { cmd: "python3.12 ~/.pi/agent/skills/test.py", simple: true, unsafe: false, decision: "auto-allow", desc: "python3.12 (versioned) trusted script auto-allows" },

  // ═══════════════════════════════════════════════════════════
  // subshells (always unsafe)
  // ═══════════════════════════════════════════════════════════
  { cmd: "$(cat /etc/passwd)", simple: false, unsafe: true, decision: "prompt", desc: "command substitution" },
  { cmd: "`whoami`", simple: false, unsafe: true, decision: "prompt", desc: "backtick substitution" },
  { cmd: "cat <(ls)", simple: false, unsafe: true, decision: "prompt", desc: "process substitution" },
  { cmd: "(rm a && ls b) | cat", simple: false, unsafe: true, decision: "prompt", desc: "subshell with rm in pipeline (subshell not dropped)" },
  { cmd: "(ls a && ls b) | cat", simple: true, unsafe: false, decision: "auto-allow", desc: "subshell with safe cmds in pipeline (segments extracted)" },
  { cmd: "(rm a && ls b 2>/dev/null) | cat", simple: false, unsafe: true, decision: "prompt", desc: "subshell with redirect in pipeline (redirect propagated)" },

  // ═══════════════════════════════════════════════════════════
  // write redirects
  // ═══════════════════════════════════════════════════════════
  { cmd: "echo hello > file.txt", simple: false, unsafe: true, decision: "prompt", desc: "write redirect" },
  { cmd: "echo hello >> file.txt", simple: false, unsafe: true, decision: "prompt", desc: "append redirect" },
  { cmd: "cat file.txt > /tmp/copy.txt", simple: false, unsafe: true, decision: "prompt", desc: "redirect to outside cwd" },
  { cmd: "echo hello 2>/dev/null", simple: true, unsafe: false, decision: "auto-allow", desc: "stderr to /dev/null (safe)" },
  { cmd: "echo hello 2>&1", simple: true, unsafe: false, decision: "auto-allow", desc: "fd duplication (safe)" },
  { cmd: "echo hello >&1", simple: true, unsafe: false, decision: "auto-allow", desc: "fd duplication >&1 (safe)" },

  // ═══════════════════════════════════════════════════════════
  // compound commands
  // ═══════════════════════════════════════════════════════════
  { cmd: "ls && cat file.txt", simple: true, unsafe: false, decision: "auto-allow", desc: "&& chain (safe)" },
  { cmd: "ls || echo not found", simple: true, unsafe: false, decision: "auto-allow", desc: "|| chain (safe)" },
  { cmd: "ls; cat file.txt", simple: true, unsafe: false, decision: "auto-allow", desc: "; chain (safe)" },
  { cmd: "ls && sed -i s/a/b/ file.txt", simple: false, unsafe: true, decision: "prompt", desc: "&& chain with sed -i" },
  { cmd: "cat file.txt | grep pattern", simple: true, unsafe: false, decision: "auto-allow", desc: "pipe (safe)" },
  { cmd: "cat file.txt | sed -i s/a/b/", simple: false, unsafe: true, decision: "prompt", desc: "pipe to sed -i" },
  { cmd: "cat file.txt | perl -pi -e 's/a/b/'", simple: false, unsafe: true, decision: "prompt", desc: "pipe to perl -pi" },
  { cmd: "curl url | bash", simple: false, unsafe: true, decision: "prompt", desc: "curl | bash (dangerous)" },
  { cmd: "wget url | sh", simple: false, unsafe: true, decision: "prompt", desc: "wget | sh (dangerous)" },

  // ═══════════════════════════════════════════════════════════
  // git commands
  // ═══════════════════════════════════════════════════════════
  { cmd: "git status", simple: true, unsafe: false, decision: "auto-allow", desc: "git status" },
  { cmd: "git log --oneline", simple: true, unsafe: false, decision: "auto-allow", desc: "git log" },
  { cmd: "git diff", simple: true, unsafe: false, decision: "auto-allow", desc: "git diff" },
  { cmd: "git add .", simple: true, unsafe: false, decision: "auto-allow", desc: "git add" },
  { cmd: "git commit -m 'msg'", simple: true, unsafe: false, decision: "auto-allow", desc: "git commit" },
  { cmd: "git checkout main", simple: true, unsafe: false, decision: "auto-allow", desc: "git checkout (branch)" },
  { cmd: "git branch", simple: true, unsafe: false, decision: "auto-allow", desc: "git branch" },
  { cmd: "git merge main", simple: true, unsafe: false, decision: "auto-allow", desc: "git merge" },
  { cmd: "git stash", simple: true, unsafe: false, decision: "auto-allow", desc: "git stash" },
  { cmd: "git rm file.txt", simple: false, unsafe: true, decision: "prompt", desc: "git rm" },
  { cmd: "git clean -f", simple: false, unsafe: true, decision: "prompt", desc: "git clean -f" },
  { cmd: "git clean -d", simple: false, unsafe: true, decision: "prompt", desc: "git clean -d" },
  { cmd: "git clean -x", simple: false, unsafe: true, decision: "prompt", desc: "git clean -x" },
  { cmd: "git clean -fd", simple: false, unsafe: true, decision: "prompt", desc: "git clean -fd" },
  { cmd: "git reset --hard HEAD", simple: false, unsafe: true, decision: "prompt", desc: "git reset --hard" },
  { cmd: "git push --force", simple: false, unsafe: true, decision: "prompt", desc: "git push --force" },
  { cmd: "git push --force-with-lease", simple: false, unsafe: true, decision: "prompt", desc: "git push --force-with-lease" },
  { cmd: "git push -f", simple: false, unsafe: true, decision: "prompt", desc: "git push -f" },
  { cmd: "git reflog expire --all", simple: false, unsafe: true, decision: "prompt", desc: "git reflog expire" },
  { cmd: "git gc --prune=now", simple: false, unsafe: true, decision: "prompt", desc: "git gc --prune" },

  // ═══════════════════════════════════════════════════════════
  // outside cwd, in allowedReadPaths (auto-allow)
  // ═══════════════════════════════════════════════════════════
  { cmd: "cat /tmp/other.txt", simple: true, unsafe: false, decision: "auto-allow", desc: "read /tmp (allowedReadPaths)" },
  { cmd: "ls /tmp", simple: true, unsafe: false, decision: "auto-allow", desc: "ls /tmp (allowedReadPaths)" },
  { cmd: "sed 's/a/b/' /tmp/file.txt", simple: true, unsafe: false, decision: "auto-allow", desc: "read /tmp (allowedReadPaths)" },
  { cmd: "grep pattern /tmp/file.txt", simple: true, unsafe: false, decision: "auto-allow", desc: "grep /tmp (allowedReadPaths)" },

  // ═══════════════════════════════════════════════════════════
  // outside cwd, NOT in allowedReadPaths (should prompt)
  // ═══════════════════════════════════════════════════════════
  { cmd: "cat /etc/passwd", simple: true, unsafe: false, decision: "prompt", desc: "cat, outside cwd" },
  { cmd: "ls /var/log", simple: true, unsafe: false, decision: "prompt", desc: "ls, outside cwd" },
  { cmd: "sed 's/a/b/' /etc/hosts", simple: true, unsafe: false, decision: "prompt", desc: "read (sed stdout), outside cwd" },
  { cmd: "sed -i s/a/b/ /etc/hosts", simple: false, unsafe: true, decision: "prompt", desc: "write (sed -i), outside cwd" },
  { cmd: "grep pattern /var/log/syslog", simple: true, unsafe: false, decision: "prompt", desc: "grep, outside cwd" },

  // ═══════════════════════════════════════════════════════════
  // compound commands with trailing redirects (redirected_statement wraps list/pipeline/loop)
  // regression: redirected_statement handler must recurse into compound children
  // ═══════════════════════════════════════════════════════════
  { cmd: "rm a && ls b 2>/dev/null", simple: false, unsafe: true, decision: "prompt", desc: "&& chain with trailing 2>/dev/null (unsafe cmd not dropped)" },
  { cmd: "rm a && rmdir b 2>/dev/null; echo done", simple: false, unsafe: true, decision: "prompt", desc: "rm && rmdir 2>/dev/null; echo (all segments present)" },
  { cmd: "ls a && ls b 2>/dev/null", simple: true, unsafe: false, decision: "auto-allow", desc: "&& chain safe cmds with trailing 2>/dev/null" },
  { cmd: "ls a || ls b 2>/dev/null", simple: true, unsafe: false, decision: "auto-allow", desc: "|| chain with trailing 2>/dev/null" },
  { cmd: "ls a; ls b 2>/dev/null", simple: true, unsafe: false, decision: "auto-allow", desc: "; chain with trailing 2>/dev/null" },
  { cmd: "rm a 2>/dev/null", simple: false, unsafe: true, decision: "prompt", desc: "single rm with 2>/dev/null" },
  { cmd: "rmdir a 2>/dev/null", simple: false, unsafe: true, decision: "prompt", desc: "single rmdir with 2>/dev/null" },
  { cmd: "cat a && rm b 2>/dev/null", simple: false, unsafe: true, decision: "prompt", desc: "safe && unsafe with trailing redirect" },
  { cmd: "rm a && cat b 2>/dev/null", simple: false, unsafe: true, decision: "prompt", desc: "unsafe && safe with trailing redirect" },
  { cmd: "rm a && rm b 2>/dev/null", simple: false, unsafe: true, decision: "prompt", desc: "unsafe && unsafe with trailing redirect" },
  { cmd: "ls a && ls b && ls c 2>/dev/null", simple: true, unsafe: false, decision: "auto-allow", desc: "triple safe && with trailing redirect" },
  { cmd: "ls a && rm b && ls c 2>/dev/null", simple: false, unsafe: true, decision: "prompt", desc: "safe && unsafe && safe with trailing redirect" },
  { cmd: "cat a 2>/dev/null && ls b", simple: true, unsafe: false, decision: "auto-allow", desc: "single redirect + && chain" },
  { cmd: "rm a && ls b >/dev/null", simple: false, unsafe: true, decision: "prompt", desc: "&& chain with >/dev/null" },
  { cmd: "rm a && ls b &>/dev/null", simple: false, unsafe: true, decision: "prompt", desc: "&& chain with &>/dev/null" },
  { cmd: "rm a && ls b 2>&1", simple: false, unsafe: true, decision: "prompt", desc: "&& chain with 2>&1 (fd dup, safe redirect but unsafe cmd)" },
  { cmd: "echo a && rm b 2>/dev/null; echo done", simple: false, unsafe: true, decision: "prompt", desc: "echo && rm 2>/dev/null; echo (real-world pattern)" },
  { cmd: "mkdir -p a && rm b 2>/dev/null; echo done", simple: false, unsafe: true, decision: "prompt", desc: "mkdir && rm 2>/dev/null; echo" },
  // pipeline with trailing redirect
  { cmd: "cat a | grep b 2>/dev/null", simple: true, unsafe: false, decision: "auto-allow", desc: "pipeline with trailing 2>/dev/null (pipeline not dropped)" },
  { cmd: "cat a | grep rm 2>/dev/null", simple: true, unsafe: false, decision: "auto-allow", desc: "pipeline with rm in arg + redirect (no false positive)" },
  { cmd: "cat a | sed -i s/x/y/ 2>/dev/null", simple: false, unsafe: true, decision: "prompt", desc: "pipeline to sed -i with redirect (unsafe not dropped)" },
  // loop constructs with trailing redirect
  { cmd: "for f in a b; do rm $f; done 2>/dev/null", simple: false, unsafe: true, decision: "prompt", desc: "for loop with redirect (loop body not dropped)" },
  { cmd: "while true; do ls; done 2>/dev/null", simple: true, unsafe: false, decision: "auto-allow", desc: "while loop with redirect (segments: true, ls — both simple)" },
  { cmd: "if true; then rm a; fi 2>/dev/null", simple: false, unsafe: true, decision: "prompt", desc: "if statement with redirect (body not dropped)" },
  // multiple redirects on compound
  { cmd: "rm a && ls b > out 2>&1", simple: false, unsafe: true, decision: "prompt", desc: "&& chain with multiple redirects" },
  { cmd: "ls a && ls b > out 2>&1", simple: false, unsafe: true, decision: "prompt", desc: "safe && chain with write redirect (prompts on redirect)" },

  // ═══════════════════════════════════════════════════════════
  // false positive defenses
  // ═══════════════════════════════════════════════════════════
  { cmd: "echo 'sed -i s/a/b/'", simple: true, unsafe: false, decision: "auto-allow", desc: "echo with sed -i in quotes" },
  { cmd: "echo \"grep -i test\"", simple: true, unsafe: false, decision: "auto-allow", desc: "echo with grep in quotes" },
  { cmd: "which python3", simple: true, unsafe: false, decision: "auto-allow", desc: "which python3 (lookup, not exec)" },
  { cmd: "type rm", simple: true, unsafe: false, decision: "auto-allow", desc: "type rm (lookup, not exec)" },
  { cmd: "printf '%s' 'rm -rf /'", simple: true, unsafe: false, decision: "auto-allow", desc: "printf with rm in quotes" },
  { cmd: "true", simple: true, unsafe: false, decision: "auto-allow", desc: "true (no-op)" },
  { cmd: "false", simple: true, unsafe: false, decision: "auto-allow", desc: "false (no-op)" },
  { cmd: "test -f file.txt", simple: true, unsafe: false, decision: "auto-allow", desc: "test" },
  // Dangerous command names in arguments — should NOT be flagged
  { cmd: "grep rm file.txt", simple: true, unsafe: false, decision: "auto-allow", desc: "grep rm (rm is arg, not command)" },
  { cmd: "cat file.txt | grep rm", simple: true, unsafe: false, decision: "auto-allow", desc: "cat | grep rm (rm is arg)" },
  { cmd: "grep -rn 'rm' .", simple: true, unsafe: false, decision: "auto-allow", desc: "grep -rn rm (rm is search pattern)" },
  { cmd: "sed -n /rm/p file.txt", simple: true, unsafe: false, decision: "prompt", desc: "sed /rm/p (rm in sed pattern; prompts because /rm/p looks like absolute path)" },
  { cmd: "find . -name '*.rm'", simple: true, unsafe: false, decision: "auto-allow", desc: "find -name *.rm (rm in filename)" },
  { cmd: "ps aux | grep python", simple: true, unsafe: false, decision: "auto-allow", desc: "ps | grep python (python is arg)" },
  { cmd: "grep pkill", simple: true, unsafe: false, decision: "auto-allow", desc: "grep pkill (pkill is arg)" },
  { cmd: "grep killall", simple: true, unsafe: false, decision: "auto-allow", desc: "grep killall (killall is arg)" },
  { cmd: "cat | grep systemctl", simple: true, unsafe: false, decision: "auto-allow", desc: "cat | grep systemctl (systemctl is arg)" },
  { cmd: "diff file1 file2", simple: true, unsafe: false, decision: "auto-allow", desc: "diff (safe, no dangerous pattern match)" },
  // No false positive pipe-to-shell
  { cmd: "echo bash | cat", simple: true, unsafe: false, decision: "auto-allow", desc: "echo bash | cat (not actually pipe to shell)" },
  { cmd: "grep fish file.txt | wc", simple: true, unsafe: false, decision: "auto-allow", desc: "grep fish | wc (not actually pipe to shell)" },
  { cmd: "ps aux | grep bash", simple: true, unsafe: false, decision: "auto-allow", desc: "ps | grep bash (bash is search term, not pipe target)" },

  // ═══════════════════════════════════════════════════════════
  // rm -r / rm -rf — MUST NEVER auto-allow in any situation
  // ═══════════════════════════════════════════════════════════
  // Basic recursive deletes
  { cmd: "rm -r dir", simple: false, unsafe: true, decision: "prompt", desc: "rm -r (recursive delete)" },
  { cmd: "rm -R dir", simple: false, unsafe: true, decision: "prompt", desc: "rm -R (recursive delete uppercase)" },
  { cmd: "rm -rf dir", simple: false, unsafe: true, decision: "prompt", desc: "rm -rf (recursive force)" },
  { cmd: "rm -fr dir", simple: false, unsafe: true, decision: "prompt", desc: "rm -fr (force recursive)" },
  { cmd: "rm -r -f dir", simple: false, unsafe: true, decision: "prompt", desc: "rm -r -f (separate flags)" },
  { cmd: "rm --recursive dir", simple: false, unsafe: true, decision: "prompt", desc: "rm --recursive (long form)" },
  // Trusted script compound bypass (Bug #1)
  { cmd: "python3 ~/.pi/agent/skills/test.py && rm -rf /tmp/data", simple: false, unsafe: true, decision: "prompt", desc: "trusted script && rm -rf (compound must NOT auto-allow)" },
  { cmd: "python3 ~/.pi/agent/skills/test.py ; rm -r /tmp/data", simple: false, unsafe: true, decision: "prompt", desc: "trusted script ; rm -r (compound must NOT auto-allow)" },
  { cmd: "node ~/.pi/agent/skills/test.js && rm -rf /tmp/data", simple: false, unsafe: true, decision: "prompt", desc: "trusted node script && rm -rf (compound must NOT auto-allow)" },
  // Wrapper command bypass (Bug #2)
  { cmd: "nice -n 10 rm -rf dir", simple: false, unsafe: true, decision: "prompt", desc: "nice -n 10 rm -rf (wrapper must not skip numeric arg)" },
  { cmd: "nice rm -rf dir", simple: false, unsafe: true, decision: "prompt", desc: "nice rm -rf (wrapper)" },
  { cmd: "env PATH=/usr/bin rm -rf dir", simple: false, unsafe: true, decision: "prompt", desc: "env VAR=val rm -rf (wrapper must not treat var as cmd)" },
  { cmd: "ionice -n 7 rm -rf dir", simple: false, unsafe: true, decision: "prompt", desc: "ionice -n 7 rm -rf (wrapper must not skip numeric arg)" },
  { cmd: "stdbuf -oL rm -rf dir", simple: false, unsafe: true, decision: "prompt", desc: "stdbuf -oL rm -rf (wrapper)" },
  { cmd: "xargs -0 rm -rf", simple: false, unsafe: true, decision: "prompt", desc: "xargs rm -rf (wrapper)" },
  { cmd: "timeout 30 rm -r dir", simple: false, unsafe: true, decision: "prompt", desc: "timeout rm -r (wrapper)" },
  // find -exec rm -r
  { cmd: "find . -exec rm -rf {} \\;", simple: false, unsafe: true, decision: "prompt", desc: "find -exec rm -rf" },
  { cmd: "find . -exec rm -r {} \\;", simple: false, unsafe: true, decision: "prompt", desc: "find -exec rm -r" },
  // Subshell with rm -r
  { cmd: "(rm -rf /tmp/data)", simple: false, unsafe: true, decision: "prompt", desc: "subshell rm -rf" },
  { cmd: "(ls && rm -r dir)", simple: false, unsafe: true, decision: "prompt", desc: "subshell ls && rm -r" },
  // rm -r with redirects
  { cmd: "rm -rf dir 2>/dev/null", simple: false, unsafe: true, decision: "prompt", desc: "rm -rf 2>/dev/null (redirect doesn't hide unsafe)" },
  { cmd: "rm -r dir >/dev/null 2>&1", simple: false, unsafe: true, decision: "prompt", desc: "rm -r with multiple redirects" },
  // rm -r in pipelines
  { cmd: "echo dir | xargs rm -rf", simple: false, unsafe: true, decision: "prompt", desc: "echo | xargs rm -rf (pipeline)" },
  { cmd: "ls | rm -rf", simple: false, unsafe: true, decision: "prompt", desc: "ls | rm -rf (pipeline)" },
  // Quoted rm -r in echo/printf — these ARE safe (just strings)
  { cmd: "echo 'rm -rf /'", simple: true, unsafe: false, decision: "auto-allow", desc: "echo with rm -rf in single quotes (safe string)" },
  { cmd: "echo \"rm -rf /\"", simple: true, unsafe: false, decision: "auto-allow", desc: "echo with rm -rf in double quotes (safe string)" },
  { cmd: "printf '%s' 'rm -rf /tmp'", simple: true, unsafe: false, decision: "auto-allow", desc: "printf with rm -rf in quotes (safe string)" },
  // rm -r with outside cwd paths
  { cmd: "rm -rf /etc/config", simple: false, unsafe: true, decision: "prompt", desc: "rm -rf outside cwd (double prompt: unsafe + path)" },
  { cmd: "rm -r /var/log/old", simple: false, unsafe: true, decision: "prompt", desc: "rm -r outside cwd" },
];


// ─── Run tests ───

async function runTests() {
  let passed = 0;
  let failed = 0;
  const failures: Array<{ cmd: string; desc: string; expected: string; actual: string }> = [];

  for (const { cmd, simple: expSimple, unsafe: expUnsafe, decision: expDecision, desc } of cases) {
    const analysis = await analyzeCommand(cmd, cwd);
    const decision = await decide({ type: "bash", command: cmd, cwd }, store);

    const simpleOk = analysis.allSimple === expSimple;
    const unsafeOk = analysis.hasUnsafePattern === expUnsafe;
    const decisionOk = expDecision ? decision.kind === expDecision : true;
    const ok = simpleOk && unsafeOk && decisionOk;

    if (ok) {
      passed++;
      console.log(`  ✓ ${desc || cmd}`);
    } else {
      failed++;
      const reasons: string[] = [];
      if (!simpleOk) reasons.push(`simple=${analysis.allSimple} (expected ${expSimple})`);
      if (!unsafeOk) reasons.push(`unsafe=${analysis.hasUnsafePattern} (expected ${expUnsafe})`);
      if (!decisionOk) reasons.push(`decision=${decision.kind} (expected ${expDecision})`);
      failures.push({
        cmd,
        desc: desc || cmd,
        expected: `simple=${expSimple}, unsafe=${expUnsafe}${expDecision ? `, decision=${expDecision}` : ""}`,
        actual: reasons.join(", "),
      });
      console.log(`  ✗ ${desc || cmd}`);
      console.log(`    ${reasons.join(" | ")}`);
    }
  }

  console.log(`\n${"=".repeat(60)}`);
  console.log(`Results: ${passed}/${cases.length} passed, ${failed} failed`);

  if (failures.length > 0) {
    console.log(`\nFailures:`);
    for (const f of failures) {
      console.log(`  ${f.desc}`);
      console.log(`    cmd:    ${f.cmd}`);
      console.log(`    expect: ${f.expected}`);
      console.log(`    actual: ${f.actual}`);
    }
  }

  return failed === 0;
}

runTests().then((ok) => process.exit(ok ? 0 : 1));
