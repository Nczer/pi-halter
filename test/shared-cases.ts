/**
 * Shared test cases used by both cases.test.ts and tmux.test.ts mirror suite.
 * Prevents drift between the bash command matrix and the send-keys mirror.
 */

export interface MirrorCase {
	cmd: string;
	safe: boolean;
}

export const MIRROR_CASES: MirrorCase[] = [
	// Read-only
	{ cmd: "tmux send-keys -t foo ls Enter", safe: true },
	{ cmd: "tmux send-keys -t foo cat file Enter", safe: true },
	{ cmd: "tmux send-keys -t foo head file Enter", safe: true },
	{ cmd: "tmux send-keys -t foo tail -f file Enter", safe: true },
	{ cmd: "tmux send-keys -t foo grep pattern file Enter", safe: true },
	{ cmd: "tmux send-keys -t foo wc file Enter", safe: true },
	{ cmd: "tmux send-keys -t foo diff a b Enter", safe: true },
	{ cmd: "tmux send-keys -t foo sort file Enter", safe: true },
	{ cmd: "tmux send-keys -t foo find . -name '*.txt' Enter", safe: true },
	{ cmd: "tmux send-keys -t foo md5sum file Enter", safe: true },
	{ cmd: "tmux send-keys -t foo sha256sum file Enter", safe: true },
	{ cmd: "tmux send-keys -t foo echo hello Enter", safe: true },
	{ cmd: "tmux send-keys -t foo printf '%s' hello Enter", safe: true },
	{ cmd: "tmux send-keys -t foo pwd Enter", safe: true },
	{ cmd: "tmux send-keys -t foo whoami Enter", safe: true },
	{ cmd: "tmux send-keys -t foo id Enter", safe: true },
	{ cmd: "tmux send-keys -t foo uname -a Enter", safe: true },
	{ cmd: "tmux send-keys -t foo df -h Enter", safe: true },
	{ cmd: "tmux send-keys -t foo du -sh . Enter", safe: true },
	{ cmd: "tmux send-keys -t foo free -m Enter", safe: true },
	{ cmd: "tmux send-keys -t foo ps aux Enter", safe: true },
	{ cmd: "tmux send-keys -t foo which python3 Enter", safe: true },
	{ cmd: "tmux send-keys -t foo command -v git Enter", safe: true },
	// Write-safe (mkdir, touch, mktemp)
	{ cmd: "tmux send-keys -t foo mkdir -p dir Enter", safe: true },
	{ cmd: "tmux send-keys -t foo touch file Enter", safe: true },
	{ cmd: "tmux send-keys -t foo mktemp Enter", safe: true },
	// Git safe
	{ cmd: "tmux send-keys -t foo git status Enter", safe: true },
	{ cmd: "tmux send-keys -t foo git log Enter", safe: true },
	{ cmd: "tmux send-keys -t foo git diff Enter", safe: true },
	{ cmd: "tmux send-keys -t foo git add . Enter", safe: true },
	{ cmd: "tmux send-keys -t foo git commit -m 'msg' Enter", safe: true },
	{ cmd: "tmux send-keys -t foo git branch Enter", safe: true },
	{ cmd: "tmux send-keys -t foo git merge branch Enter", safe: true },
	// Git dangerous
	{ cmd: "tmux send-keys -t foo git rm file Enter", safe: false },
	{ cmd: "tmux send-keys -t foo git clean -fd Enter", safe: false },
	{ cmd: "tmux send-keys -t foo git reset --hard Enter", safe: false },
	{ cmd: "tmux send-keys -t foo git push --force Enter", safe: false },
	// Dangerous
	{ cmd: "tmux send-keys -t foo rm -rf dir Enter", safe: false },
	{ cmd: "tmux send-keys -t foo mv a b Enter", safe: false },
	{ cmd: "tmux send-keys -t foo cp a b Enter", safe: false },
	{ cmd: "tmux send-keys -t foo chmod 755 file Enter", safe: false },
	{ cmd: "tmux send-keys -t foo chown user file Enter", safe: false },
	{ cmd: "tmux send-keys -t foo curl http://x.com Enter", safe: false },
	{ cmd: "tmux send-keys -t foo wget http://x.com Enter", safe: false },
	{ cmd: "tmux send-keys -t foo ssh host Enter", safe: false },
	{ cmd: "tmux send-keys -t foo python3 script.py Enter", safe: false },
	{ cmd: "tmux send-keys -t foo node app.js Enter", safe: false },
	{ cmd: "tmux send-keys -t foo sudo rm file Enter", safe: false },
	{ cmd: "tmux send-keys -t foo kill -9 1234 Enter", safe: false },
	{ cmd: "tmux send-keys -t foo shutdown now Enter", safe: false },
	{ cmd: "tmux send-keys -t foo eval echo Enter", safe: false },
	{ cmd: "tmux send-keys -t foo tar czf out.tar.gz dir Enter", safe: false },
	{ cmd: "tmux send-keys -t foo npm install Enter", safe: false },
	{ cmd: "tmux send-keys -t foo pip install flask Enter", safe: false },
	// sed
	{ cmd: "tmux send-keys -t foo sed -n '/foo/p' file Enter", safe: true },
	{ cmd: "tmux send-keys -t foo sed -i s/foo/bar/g file Enter", safe: false },
];
