import type { On } from 'claude-code'
import { describe, type Engine, expect, mock, test } from 'claude-code/testing'
import {
  addedLines, CHANGES_FOLDER, rulesFor, ghWrites, inScratch, isNewRequest, gitAction, githubRepo, languageOf, localPart, networkAllowed, type Paths, report, REPORT_BUGS, resolveDir, reviewPrompt, runOnlyScripts, scanDiff, scanLine, scanValue, settle, shellWrites, startFolder,
} from '../hooks/scan.ts'
import { churnRule, findScanners, homeFrom } from '../hooks/outgoing.ts'
import { churned, churnNote, historyFileName, historyFrom, withReview } from '../hooks/churn.ts'
import { REVIEW_AGENTS } from '../hooks/agents.ts'
import { afterHandOn, agentsListed, blankedSafely, cycleFrom, isWindows, ownFolderFrom, ownFolderOf, savedDamaged, recipient, reviewFailed, reviewHeldOpen, keyOf, samePath, say, stillOthers, underWayFor, whyOf } from '../hooks/register.ts'
import { statusFrom } from '../hooks/status.ts'
import { changedBetween, committedWrites, compareWithGuess, GIT_TIMEOUT_MS, gitSubcommands, headMove, isFullPath, normalPath, parseStatus, relativeTo, repoFor } from '../hooks/worktree.ts'
import { candidates, gitleaksFindings, scannerCommand, scannersFor, scannerSteps } from '../hooks/scanners.ts'

// The review prompt is wrapped at a fixed width; tests read it as one line so a rewrap breaks nothing.
const flat = (text: string) => text.replace(/\s+/g, ' ')

// Every value here is made up: fake key shapes, made-up addresses, placeholder names.
const PERSONAL = ['pat example', 'pat@example.org', 'patuser']
const FAKE_GH = 'ghp_' + 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8'
// Values the scanner must catch, built from pieces so this file never holds one whole (the mod checks
// its own pushes). Made up: 10.20.30.x is a private range, and no device has this MAC.
const LAN_A = ['10', '20', '30', '44'].join('.')
const LAN_B = ['10', '20', '30', '7'].join('.')
const LAN_C = ['10', '20', '30', '9'].join('.')
const MAC = ['00', '1a', '2b', '3c', '4d', '5e'].join(':')
const KEY_HEADER = '-----BEGIN OPENSSH ' + 'PRIVATE KEY-----'

describe('scanner', () => {
  test('finds keys, addresses and personal terms, never echoing them', async () => {
    const kinds = (line: string) => scanLine(line, 'f:1', PERSONAL).map(f => f.kind)
    expect(kinds(`token = "${FAKE_GH}"`)).toContain('GitHub token')
    expect(kinds(KEY_HEADER)).toContain('private key')
    expect(kinds(`host: ${LAN_A}`)).toContain('IP address')
    expect(kinds(`mac ${MAC}`)).toContain('MAC address')
    expect(kinds('Author: Pat Example <pat@example.org>').length).toBe(2)
    expect(kinds('C:\\Users\\PatUser\\file').some(k => k.startsWith('your personal info'))).toBe(true)
    const text = report(scanLine(`key=${FAKE_GH}`, 'a.py:3', PERSONAL), 'commit')
    expect(text.includes(FAKE_GH)).toBe(false)
    expect(text.includes('a.py:3')).toBe(true)
  })

  test('leaves harmless lookalikes alone', async () => {
    const kinds = (line: string) => scanLine(line, 'f:1', PERSONAL).map(f => f.kind)
    expect(kinds('listen on 127.0.0.1 and 0.0.0.0')).toEqual([])
    expect(kinds('version 2.16.0.1 released')).toEqual([])
    // Addresses set aside for documentation: no real network or device uses them.
    expect(kinds('docs: 192.0.2.10, 198.51.100.20 and 203.0.113.30')).toEqual([])
    expect(kinds('mac 00:00:5e:00:53:01 or 00-00-5E-00-53-FF')).toEqual([])
    expect(kinds(`but not ${LAN_A} or ${MAC}`)).toEqual(['MAC address', 'IP address'])
    // Just outside those ranges is caught (built from pieces: the mod checks its own pushes).
    for (const ip of [['192', '0', '20', '1'], ['192', '0', '3', '1'], ['198', '51', '101', '1'], ['203', '0', '114', '1']]) {
      expect(kinds('host ' + ip.join('.'))).toEqual(['IP address'])
    }
    for (const mac of [['00', '00', '5e', '00', '54', '01'].join(':'), ['00', '00', '5E', '00', '52', 'FF'].join('-')]) {
      expect(kinds('mac ' + mac)).toEqual(['MAC address'])
    }
    // A documentation address does not hide a real one on the same line.
    const both = scanLine('192.0.2.10 ' + LAN_A, 'f:1', [])
    expect(both.map(f => f.value)).toEqual([LAN_A])
    // ...nor when it runs straight into one.
    expect(kinds('00:00:5e:00:53:' + MAC)).toContain('MAC address')
    // "version" excuses only the number right after it.
    expect(kinds('"version": "2.16.0.1"')).toEqual([])
    expect(kinds(`{"version": "1.0", "host": "${LAN_A}"}`)).toEqual(['IP address'])
    expect(kinds('password = os.environ["APP_PASSWORD_HASH_VALUE"]')).toEqual([])
    expect(kinds('api_key = "<your key here 1234567890>"')).toEqual([])
  })

  test('reads only added lines of a diff, with their line numbers', async () => {
    const diff = [
      'diff --git a/app.py b/app.py',
      '--- a/app.py',
      '+++ b/app.py',
      '@@ -10,2 +10,3 @@',
      ' unchanged',
      `-old = "${FAKE_GH}"`,
      `+server = "${LAN_B}"`,
      '+ok = 1',
    ].join('\n')
    const found = scanDiff(diff, PERSONAL)
    expect(found.map(f => `${f.kind}@${f.where}`)).toEqual(['IP address@app.py:11'])
  })

  test('flags a .env file but not .env.example', async () => {
    const diff = (name: string) => `+++ b/${name}\n@@ -0,0 +1 @@\n+X=1`
    expect(scanDiff(diff('.env'), []).length).toBe(1)
    expect(scanDiff(diff('.env.example'), []).length).toBe(0)
  })

  test('network findings pass in allowed repos; allowValues clears a false alarm', async () => {
    const found = [...scanLine(`ip ${LAN_C}`, 'n:1', []), ...scanLine(`k=${FAKE_GH}`, 'k:1', [])]
    expect(settle(found, true).map(f => f.kind)).toEqual(['GitHub token'])
    expect(settle(found, false, [`${LAN_C}`]).map(f => f.kind)).toEqual(['GitHub token'])
  })

  test('an allowed value does not hide a second one on the same line', async () => {
    const found = scanLine(`hosts: ${LAN_C} ${LAN_B}`, 'n:1', [])
    expect(found.length).toBe(2)
    expect(settle(found, false, [`${LAN_C}`]).map(f => f.kind)).toEqual(['IP address'])
    expect(settle(found, false, [`${LAN_C}`, `${LAN_B}`])).toEqual([])
  })

  test('addresses pass only when every remote is a listed repo, by its exact name', async () => {
    expect(githubRepo('https://github.com/Pat/Notes.git')).toBe('pat/notes')
    expect(githubRepo('git@github.com:pat/notes.git')).toBe('pat/notes')
    expect(networkAllowed(['https://github.com/pat/notes.git'], ['pat/notes'])).toBe(true)
    expect(networkAllowed(['https://github.com/pat/notes-public.git'], ['pat/notes'])).toBe(false)
    expect(networkAllowed(['git@github.com:pat/notes.git', 'https://github.com/pat/other'], ['pat/notes'])).toBe(false)
    expect(networkAllowed([], ['pat/notes'])).toBe(false)
  })
})

describe('git commands', () => {
  test('finds commits and pushes, their folder and message', async () => {
    expect(gitAction('git status')).toBe(undefined)
    const a = gitAction('cd /c/Users/x/repo && git add -A && git commit -m "fix: thing"')
    expect(a?.kind).toBe('commit')
    expect(a?.dir).toBe('/c/Users/x/repo')
    expect(a?.addsFiles).toBe(true)
    expect(a?.message).toBe('fix: thing')
    expect(gitAction('git -C "D:/work/app" push -q origin main')?.kind).toBe('push')
    expect(gitAction('git -C "D:/work/app" push origin main')?.dir).toBe('D:/work/app')
    expect(gitAction('gh repo create me/x --private --source ./x --push')?.kind).toBe('push')
    expect(gitAction("git commit -q -F - <<'EOF'\nSubject\n\nBody line\nEOF")?.message).toBe('Subject\n\nBody line')
    const linux = gitAction('cd /home/pat/repo && git commit -m x')
    expect(linux?.kind).toBe('commit')
    expect(linux?.dir).toBe('/home/pat/repo')
    expect(linux?.message).toBe('x')
  })

  test('uses the folder in effect at the commit, and knows a command that does both', async () => {
    expect(gitAction('cd /c/work/app && git commit -am x && cd /c/Users/me')?.dir).toBe('/c/work/app')
    expect(gitAction('pushd /srv/app; git push')?.dir).toBe('/srv/app')
    expect(gitAction('Set-Location -Path "C:\\work\\app"; git commit -m x')?.dir).toBe('C:\\work\\app')
    const both = gitAction('git add -A && git commit -m x && git push')
    expect([both?.commits, both?.pushes, both?.kind, both?.addsFiles]).toEqual([true, true, 'push', true])
    expect(gitAction('git commit -m x')?.pushes).toBe(false)
  })

  test('reads what a push names', async () => {
    expect(gitAction('git push')?.refs).toEqual([])
    expect(gitAction('git push -u origin main 2>&1')?.refs).toEqual(['main'])
    expect(gitAction('git push origin +dev:main v1.0')?.refs).toEqual(['dev', 'v1.0'])
    expect(gitAction('git push origin --delete old')?.refs).toEqual([])
    expect(gitAction('git push "$REMOTE" "$BRANCH"')?.refs).toEqual([])
    const all = gitAction('git push --all --tags origin')
    expect([all?.allBranches, all?.tags, all?.addsFiles]).toEqual([true, true, false])
  })

  test('git commands in a heredoc written here count unless nothing else in the command runs shell code', async () => {
    // Each case is checked with its input in the result, so a failure names it.
    const seen = (c: string) => [c, gitAction(c) !== undefined]
    const hidden = (c: string) => expect(seen(c)).toEqual([c, false])
    const counts = (c: string) => expect(seen(c)).toEqual([c, true])
    // A Python test written with a heredoc and run with python: its git(...) calls are not a commit, in
    // any of the ways the command may be written.
    const body = "<<'PYEOF'\ngit(repo, 'add', 'a.txt')\ngit(repo, 'commit', '-q', '-m', 'first')\nPYEOF\n"
    const fix = `cat > /tmp/t/fix.py ${body}`
    for (const c of [
      `cd /c/proj && ${fix}python -I /tmp/t/fix.py .`,
      `cat > "/tmp/my dir/fix.py" ${body}python "/tmp/my dir/fix.py"`,
      `${fix}# run it\ntimeout 60 python3 /tmp/t/fix.py; true;# done`,
      `cat > /tmp/t/fix.mjs ${body}node /tmp/t/fix.mjs && rm /tmp/t/fix.mjs`,
      `mkdir -p /tmp/t && ${fix}diff /tmp/t/fix.py b; sha256sum /tmp/t/fix.py; md5sum /tmp/t/fix.py; python /tmp/t/fix.py`,
      `${fix}nohup python /tmp/t/fix.py`, `${fix}env python /tmp/t/fix.py`, `${fix}time python /tmp/t/fix.py`,
      `${fix}.venv/Scripts/python.exe /tmp/t/fix.py`, // a venv's python, spelled as a path
      `S=/tmp/t\nS+=/u\n${fix}python /tmp/t/fix.py`, // variables set alone
      `${fix}cat > /tmp/t/b.md <<'B'\nnotes\nB\npython /tmp/t/fix.py`, // two bodies, each on its own line
      `cat > /dev/null <<'EOF'\nnotes\nEOF\npython /tmp/t/fix.py`,
      `cat > /tmp/t/b.md <<'B'\ngit push origin main\nB\ncat /tmp/t/b.md`, // git text, but no script runs, so it is blanked
      `cat > src/hooks/use.js <<'EOF'\ngit(repo, 'push')\nEOF\nnode src/hooks/use.js`, // git runs hooks by exact name only
      "cat > /tmp/t/fix.py <<-'PYEOF'\n\tgit(repo, 'commit')\n\tPYEOF\npython /tmp/t/fix.py",
      "cat > /tmp/t/fix.py <<'PYEOF'\r\ngit(repo, 'commit')\r\nPYEOF\r\npython /tmp/t/fix.py\r\n",
      `${fix}python /tmp/t/exec.py --mode=exec`, // "exec" only as a word on its own is refused
      "cat <<'EOF'\nthen run git commit -m x\nEOF", // to the screen (blankDataBodies already)
      `cat > "$TMP/fix.py" ${body}python -I "$TMP/fix.py" .`, // the machine's own folders may be named
    ]) hidden(c)
    // Anything else may run the body as shell code, by name, redirect or not at all (make, a package
    // script, a preload, inline code): its commit counts. The body goes to a .py file, otherwise blanked.
    const shell = "cat > /tmp/t/x.py <<'EOF'\ncd /c/proj && git commit -am x && git push origin main\nEOF\n"
    const txt = "cat > /tmp/t/x.txt <<'EOF'\n#!/bin/sh\ngit commit -am x && git push origin main\nEOF\n"
    for (const run of [
      'bash /tmp/t/x.py', '. /tmp/t/x.py', 'sh < /tmp/t/x.py', 'cat /tmp/t/x.py | sh', '"bash" /tmp/t/x.py', 'b""ash /tmp/t/x.py',
      'nohup bash /tmp/t/x.py', 'env -i bash /tmp/t/x.py', 'sudo -u me bash /tmp/t/x.py', 'timeout 9 bash /tmp/t/x.py',
      'make', 'npm test', 'git status', 'rg --pre bash . /tmp/t/x.py', 'rg --pre=bash x /tmp/t/x.py',
      'python -c "import os"', 'python -c"import os" /tmp/t/a.py', 'python -Werror /tmp/t/a.py', 'python -m tox', 'python3.12 -m pip install .',
      'node -e 1', 'node -r /tmp/t/x.py a.js', 'node --run c', 'node /tmp/t/x.py',
      'bun run c', 'bun /tmp/t/x.sh', 'bun a.ts', 'py a.py', 'python a.sh', 'constructor a.py', 'python < /tmp/t/x.py',
      'python /tmp/t/fix.py "$(bash /tmp/t/x.py)"', 'python /tmp/t/fix.py "`bash /tmp/t/x.py`"', 'eval "$(cat /tmp/t/x.py)"',
      'cp /tmp/t/x.py .git/hooks/pre-commit', 'mv /tmp/t/x.py ~/bin/ls', 'chmod +x /tmp/t/x.py',
      './cat a.py', 'exec >~/bin/ls; ls', 'if true; then python /tmp/t/fix.py; fi', 'f() { bash "$1"; }; f /tmp/t/x.py',
      'PATH=/tmp/t python a.py', 'PATH+=:/tmp/t; python a.py', 'path=/tmp/t', 'export PATH=/tmp/t', 'readonly BASH_ENV=/tmp/t/x.py',
      'BASH_ENV=/tmp/t/x.py', 'X=1 python a.py', 'GIT_DIR=/c/p', 'APPDATA=/tmp/t', 'HOME=/tmp/t', 'NODE_OPTIONS=--require=/tmp/t/a.js',
      'PYTHONPATH=/tmp/t', 'LD_PRELOAD=/tmp/t/x.so', 'IFS=/', 'ENV=/tmp/t/x.py', 'PROMPT_COMMAND=x', 'PATHEXT=.PY', 'COMSPEC=/tmp/t/x.exe',
      // Setting any RUNS_WITH variable is refused. That is also why `$TMP`, `$PWD` and the other machine
      // folders can be trusted when read.
      'PWD=/x', 'OLDPWD=/x', 'TMP=/x', 'TEMP=/x', 'TMPDIR=/x', 'USERPROFILE=/x', 'LOCALAPPDATA=/x', 'PROGRAMDATA=/x', 'SHELLOPTS=x', 'BASHOPTS=x',
      'PS4=x', 'CDPATH=/x', 'DYLD_INSERT_LIBRARIES=/x', 'BUN_X=1', 'SHELL=/x', 'SYSTEMROOT=/x', 'WINDIR=/x', 'XDG_CONFIG_HOME=/x',
      // A carriage return, vertical tab, form feed or no-break space (U+00A0) before `#` starts no comment in bash.
      'true\r# ; bash /tmp/t/x.py', 'true\v# ; bash /tmp/t/x.py', 'true\f# ; bash /tmp/t/x.py', 'true # ; bash /tmp/t/x.py',
    ]) counts(shell + run)
    // A written file run by its path, even with a harmless name.
    counts("cat > /tmp/t/python <<'EOF'\ngit commit -am x\nEOF\n/tmp/t/python a.py")
    // Kept wherever a later shell or git may run it, even if nothing here does.
    for (const target of ['/tmp/t/x.sh', '~/bin/ls', '~/.bashrc', '.git/hooks/post-merge', '.git/hooks/pre-commit.py', '.git/config', 'package.json', 'tox.ini', 'Makefile']) {
      counts(`cat > ${target} <<'EOF'\ngit push origin main\nEOF\npython a.py`)
    }
    // Kept when it is unquoted (bash runs `$(...)` in it as it writes the file, and one with no `$` too),
    // read by anything but cat, piped on, shares its opener line, starts programs itself, or the split is a
    // guess; and the `py` launcher always counts (it follows a `#!/usr/bin/env bash` line, after a tab too).
    for (const c of [
      "cat > x.py <<EOF\nx=$(git commit -m x)\nEOF",
      "cat > /tmp/t/a.txt <<EOF\ngit push origin main\nEOF\npython /tmp/t/fix.py",
      "python /tmp/t/run.py <<'EOF'\ngit push origin main\nEOF",
      "cat <<'EOF' | bash\ngit commit -m x\nEOF",
      "cat <<'EOF' | python /tmp/t/run.py\ngit push origin main\nEOF",
      "cat <<'EOF' | grep x\ngit push origin main\nEOF",
      "cat > /tmp/t/a.txt <<'A'; cat > /tmp/t/b.md <<'B'\ngit push origin main\nA\nnotes\nB\npython /tmp/t/fix.py",
      "cat > /tmp/t/rel.py <<'EOF'\nimport subprocess\nsubprocess.run(['git', 'push', 'origin', 'main'], check=True)\nEOF\npython /tmp/t/rel.py",
      "cat > /tmp/t/rel.js <<'EOF'\nrequire('child_process').execSync('git push origin main')\nEOF\nnode /tmp/t/rel.js",
      "cat > /tmp/t/x.py <<-'EOF'\n\t#!/usr/bin/env bash\n\tgit commit -m x\n\tEOF\npy /tmp/t/x.py",
      "cat > /tmp/t/x.py <<'EOF'\r\ngit push origin main\r\nEOF\r\nbash /tmp/t/x.py\r\n",
      "cat > x.py <<'EOF'\ngit commit -m x", // no end line
      "true;#/cat <<'EOF'\ngit commit -m x\nEOF", // `;#` starts a comment: no heredoc, the line runs
      "mkdir -p ~/bin\nexec >~/bin/ls\ncat <<'EOF'\n#!/bin/sh\ngit commit -m x\nEOF\nls", // a screen heredoc sent to a file
      // A `\`-newline stays in a quoted body, so the body ends at the first EOF and the git line runs.
      "cat > /tmp/t/x.py <<'EOF'\nfoo \\\nEOF\ngit commit -am x && git push origin main\nEOF\npython /tmp/t/x.py",
      "cat <<'EOF' &>~/bin/python\n#!/bin/sh\ngit commit -am x\nEOF\npython a.py", // &> is a redirect too
      "cat <<'EOF' >&~/bin/python\ngit commit -am x\nEOF\npython a.py",
      // A body copied, on another line, to where a later command runs it.
      `${txt}cat /tmp/t/x.txt > ~/bin/python\npython a.py`,
      `${txt}head -n 99 /tmp/t/x.txt >> ~/bin/ls\nls`,
      `${txt}cat /tmp/t/x.txt > /tmp/t/python\n/tmp/t/python a.py`,
      // rg --pre in other spellings, and a variable that becomes a flag.
      `${txt}rg --p""re bash . /tmp/t/x.txt`, `${txt}rg --"pre" bash . /tmp/t/x.txt`, `${txt}rg --pr{e,e} bash . /tmp/t/x.txt`,
      `S="-c__import__('os').system('sh</tmp/t/x.txt')#"\n${txt}python $S.py`,
      `S="-c__import__('os').system('sh</tmp/t/x.txt')#"\n${txt}python "$S/a.py"`,
      `X=--p\n${txt}rg \${X}re=bash . /tmp/t/x.txt`,
      `${txt}printf -v BASH_ENV %s /tmp/t/x.txt\npython a.py`,
      // A body that may start programs, in other spellings.
      "cat > /tmp/t/r.py <<'EOF'\nfrom os import system as s\ns('git push origin main')\nEOF\npython /tmp/t/r.py",
      "cat > /tmp/t/r.py <<'EOF'\n__import__('os').system('git push origin main')\nEOF\npython /tmp/t/r.py",
      // `>|` writes like `>`, and `<>` opens a file for writing.
      `${txt}cat /tmp/t/x.txt >| ~/bin/python a.py\npython a.py`,
      `${txt}cd ~/bin && cat /tmp/t/x.txt >|ls; ls`,
      `${txt}cat /tmp/t/x.txt 1<>~/bin/python\npython a.py`,
      "cat <<'EOF' >|~/bin/ls\n#!/bin/sh\ngit commit -m x\nEOF\nls",
      "cat <<'EOF' &>~/bin/ls\n#!/bin/sh\ngit commit -m x\nEOF\nls", // a screen heredoc sent to a file with &>
      // A body with a git push or commit command line in its text, run by its script, is kept even when no
      // call STARTS_PROGRAMS lists runs it.
      "cat > /tmp/t/r.py <<'EOF'\nimport helpers\nhelpers.run('git push origin main')\nEOF\npython /tmp/t/r.py",
      "cat > /tmp/t/r.py <<'EOF'\nhelp('git -C /c/p commit -am x')\nEOF\npython /tmp/t/r.py",
      ...["git.exe push origin main", 'git -C "/c/my p" push', 'git -c "a=b c" commit -m x', 'git --work-tree /c/p push',
        'Git push', 'gh repo create x --source . --push'].map(t => `cat > /tmp/t/r.py <<'EOF'\nhelpers.run('${t}')\nEOF\npython /tmp/t/r.py`),
      // Notes that say "git push", written while a script runs: kept by mistake, only a check.
      "cat > notes.md <<'EOF'\nRun git push origin main to sync.\nEOF\npython -I .scripts/memory-map.py",
    ]) counts(c)
    // Names STARTS_PROGRAMS lists, some spelled inside longer names (`posix_spawn`, `create_subprocess_shell`,
    // `ptyprocess`), keep a body run by its script. Each body also holds a test helper's `git(repo, 'commit')`,
    // which alone would be blanked.
    const helper = "\ngit(repo, 'commit')"
    for (const code of [
      "import os\nos.system('x')", "import pty\npty.spawn(['sh'])", "import importlib\nimportlib.import_module('o' + 's')",
      "getattr(m, 'run')('x')", "eval('1')", "Popen(['x'])", "posix_spawn('x')", "execv('x', [])",
      "import asyncio\nasyncio.run(asyncio.create_subprocess_shell('x'))", "import pydoc\npydoc.pipepager('', 'x')",
      "import multiprocessing", "import ctypes", "import webbrowser", "import runpy", "import code\ncode.interact()",
      "import posix\nposix.system('x')", "import nt", "from os import system as s",
      "import cffi", "import _winapi", "startfile('x')", "fork()", "globals()['x']", "__import__('o' + 's')",
      "import ptyprocess", "import builtins\nbuiltins.__dict__['x']", "import pexpect", "from plumbum.cmd import ls",
      "import git\ngit.Repo('.').index.commit('wip')", "import pygit2", "import dulwich", "import sh\nsh.ls()",
    ]) counts(`cat > /tmp/t/r.py <<'EOF'\n${code}${helper}\nEOF\npython /tmp/t/r.py`)
    for (const code of [
      "process.getBuiltinModule('child_' + 'process')", "process.binding('spawn_sync')", "process['dlopen']({}, 'x')",
      "import('child_process')", "require('fs')", "const zx = 1", "execa('x')", "Bun.spawn(['x'])", "Deno.run({})",
      "process.linkedBinding('x')", "require('shelljs')", "import git from 'isomorphic-git'", "import { run } from './helpers.mjs'",
      "import simpleGit from 'simple-git'",
    ]) counts(`cat > /tmp/t/r.mjs <<'EOF'\n${code}${helper}\nEOF\nnode /tmp/t/r.mjs`)
    hidden(`cat > /tmp/t/r.py <<'EOF'\nimport json${helper}\nEOF\npython /tmp/t/r.py`) // the control: the helper alone is blanked
    hidden(`cat > /tmp/t/r.py <<'EOF'\nimport json${helper}\nEOF\npython /tmp/t/r.py --title café`) // a non-ASCII letter is fine
    hidden("cat > n.md <<'EOF'\ngit push origin main\nEOF\nls 'a b'") // a no-break space inside quotes is a plain character
    // Long bodies are read in linear time: blank lines, and a line of many `git ` words.
    const started = Date.now()
    gitAction(`cat > /tmp/t/r.py <<'EOF'\n${'\n'.repeat(60000)}x\nEOF\npython /tmp/t/r.py`)
    gitAction(`cat > /tmp/t/r.py <<'EOF'\n${'git '.repeat(30000)}\nEOF\npython /tmp/t/r.py`)
    expect(Date.now() - started).toBeLessThan(3000)
    // A real commit outside the bodies is still seen, and only a heredoc on its own line is its message.
    expect(gitAction("cat > n.py <<'EOF'\nprint(1)\nEOF\npython n.py && git commit -m done")?.message).toBe('done')
    for (const opener of ["<<'EOF'", "<<-'EOF'", '<<"EOF"', '<<EOF']) {
      const end = opener.includes('-') ? '\tEOF' : 'EOF'
      const c = `git commit -m "$(cat ${opener}\n${opener.includes('-') ? '\t' : ''}Subject\n${end}\n)"`
      expect([c, gitAction(c)?.message]).toEqual([c, opener.includes('-') ? '\tSubject' : 'Subject'])
    }
    expect(gitAction("git commit -m \"$(cat <<'END-MSG'\nSubject\nEND-MSG\n)\"")?.message).toBe('Subject')
    // `-F file`: a heredoc that wrote the file is read as the message too.
    expect(gitAction("cat > /tmp/msg.txt <<'EOF'\nSubject here\nEOF\ngit commit -F /tmp/msg.txt")?.message).toContain('Subject here')
    // Combined short flags carry the message too, so does `--file=`, and `--amend` is not `-am`.
    expect(gitAction("cat > /tmp/msg.txt <<'EOF'\nSubject here\nEOF\ngit commit -aF /tmp/msg.txt")?.message).toContain('Subject here')
    expect(gitAction("cat > /tmp/msg.txt <<'EOF'\nSubject here\nEOF\ngit commit --file=/tmp/msg.txt")?.message).toContain('Subject here')
    expect(gitAction('git commit -am "fix: thing"')?.message).toBe('fix: thing')
    expect(gitAction('git commit -qm "fix: thing"')?.message).toBe('fix: thing')
    expect(gitAction('git commit --amend --no-edit')?.message).toBe('')
    // A body ends only on a line that is exactly its terminator, tabs dropped for `<<-` alone, so every
    // line before that is message and scanned, or, with no such line, the rest of the command.
    expect(gitAction("git commit -F - <<'EOF'\nSubject\nEOF and more\nSECOND\nEOF")?.message).toBe('Subject\nEOF and more\nSECOND')
    expect(gitAction("git commit -F - <<'EOF'\nSubject\n\tEOF\nSECOND\nEOF")?.message).toBe('Subject\n\tEOF\nSECOND')
    expect(gitAction("git commit -F - <<-'EOF'\n\tSubject\n\tEOF\nnot message")?.message).toBe('\tSubject')
    expect(gitAction("git commit -F - <<'EOF'\nSubject\nno end line")?.message).toBe('Subject\nno end line')
    // Every heredoc on the commit's line counts, whatever stands between: a redirect, a quoted `&` or `;`,
    // a pipe into the commit, or another command after it (more text scanned, never less).
    for (const c of [
      "git commit -F - 2>&1 <<'EOF'\nSECRET\nEOF",
      "git commit --file=- >/dev/null 2>&1 <<'EOF'\nSECRET\nEOF",
      "git commit --author='R&D <a@b.c>' -F - <<'EOF'\nSECRET\nEOF",
      "git commit --trailer 'a;b' -F - <<'EOF'\nSECRET\nEOF",
      "cat <<'EOF' | git commit -F -\nSECRET\nEOF",
      "git commit -F - <<'END.MSG'\nSECRET\nEND.MSG",
      "git commit -F - <<\\EOF\nSECRET\nEOF",
      ": commit <<'Z'\nZ\ngit commit -F - <<'EOF'\nSECRET\nEOF", // not git's heredoc first
      "cat > commit.md <<'A'\nnotes\nA\ngit add commit.md && git commit -m \"$(cat <<'EOF'\nSECRET\nEOF\n)\"",
      'git commit -m "a & b" -m "$(cat <<\'EOF\'\nsay "hi" SECRET\nEOF\n)"',
      'git commit -m"SECRET"', "git commit -am'SECRET'",
    ]) expect([c, gitAction(c)?.message.includes('SECRET')]).toEqual([c, true])
    expect(gitAction("git commit -m done && cat > notes.md <<'EOF'\nsome notes\nEOF")?.message).toBe('done\nsome notes')
    // More message spellings: a heredoc on a later line, CRLF, `GIT`, a here-string, a bare attached value.
    for (const c of [
      "cd /c/p\ngit commit -F - <<'EOF'\nSECRET\nEOF", "git commit -F - <<'EOF'\r\nSECRET\r\nEOF\r\n",
      "GIT commit -F - <<'EOF'\nSECRET\nEOF", "git commit -F - <<<'SECRET'", 'git commit -mSECRET', 'git commit -amSECRET',
    ]) expect([c, gitAction(c)?.message.includes('SECRET')]).toEqual([c, true])
    expect(gitAction("git commit -F - <<'EOF'\r\nSubject\r\nEOF\r\n")?.message).toBe('Subject')
    expect(gitAction('git commit -m a && echo foo-m b')?.message).toBe('a') // `-m` only where a word starts
    // A quoted `&`, `;` or `|` between git and its command ends nothing.
    expect(gitAction("git -c user.name='A & B' commit -m x")?.commits).toBe(true)
    expect(gitAction("git -c 'alias.x=!a|b' push origin main")?.refs).toEqual(['main'])
    // An apostrophe in a note, a body or a comment pairs with no quote on a later line: the git lines after
    // it are found, and a push names what it names.
    const apostrophe = (c: string) => gitAction(c)
    expect(apostrophe("cat > n.md <<'EOF'\nit's\nEOF\ngit push origin feature && git branch -d old 'x'")?.refs).toEqual(['feature'])
    expect(apostrophe("cat <<'EOF' > n.txt\nwon't\nEOF\ngit -C /c/p push origin main\necho 'x'")?.dir).toBe('/c/p')
    expect(apostrophe("git commit -F - <<'EOF'\nDon't break\nEOF\ngit push origin main\necho 'done'")?.pushes).toBe(true)
    expect(apostrophe("cat >> Changes/log.md <<'EOF'\n- Fixed the user's thing\nEOF\ngit -C /c/v commit -am 'log' && git -C /c/v push origin main")?.commits).toBe(true)
    expect(apostrophe("git push origin main # don't\necho 'x'")?.refs).toEqual(['main'])
    expect(apostrophe("echo it\\'s; git push origin main; echo 'done'")?.refs).toEqual(['main'])
  })

  test('git commands in the strings and comments of Python code run from a heredoc are no commit, unless the code may run them', async () => {
    const seen = (c: string) => [c, gitAction(c) !== undefined]
    const hidden = (c: string) => expect(seen(c)).toEqual([c, false])
    const counts = (c: string) => expect(seen(c)).toEqual([c, true])
    const py = (code: string, opener = "python - <<'PY'", after = '') => `${opener}\n${code}\nPY${after}`
    // A script editing a test file whose cases name git commands. It also covers `replace` and an `open` of a
    // variable's path, which the allowlist takes here.
    const edit = `p = 'tests/a.test.ts'\ns = open(p, encoding='utf-8', newline='').read()\na = """  for (const c of ['git -C sub add x.py', 'git commit -m "x"']) {\n    expect(f(c)).toBe(true)\n  }"""\nassert s.count(a) == 1\nopen(p, 'w', encoding='utf-8', newline='').write(s.replace(a, a + 'x'))`
    for (const c of [
      py(edit), py(edit, "python3 -I - <<'PY'"), py(edit, "py -3 - <<'PY'"), // the launcher reads stdin as Python py(edit, ".venv/Scripts/python.exe <<'PY'"), py(edit, "cd /c/proj && python -X utf8 - <<'PY'"),
      py("print('git push origin main')", 'python - <<"PY"'),
      py("# don't: git commit -am x\nprint(1)"), // a comment, with an apostrophe
      py("s = 'it\\'s'\nprint(\"git push origin main\")"), // an escaped quote
      py("p = r'C:\\new\\x'\nprint(p, b'git push origin main')"), // raw and bytes strings
      py("x = '''\n'git commit -m x'\n'''\nprint(x)"), // a triple-quoted string over lines
      py("print('exec git push origin main')"), // a risky name (`exec`) inside a string is only text
      py("s = 'git push origin main'\nprint(s.replace('push', 'pull'))"), // `replace` is allowed here
      py("p = 'n.md'\nopen(p, 'w').write('git commit -m x')"), // and so is opening a variable's path
      py("x = 1\nif x: pass\nelif'git push origin main': print(1)"), // `elif` before a quote is a word, not an f-prefix
      // With no other script run, a data body beside it is blanked.
      py("print('git push origin main')", "python - <<'PY'", "\ncat > n.md <<'EOF'\ngit push origin main\nEOF"),
    ]) hidden(c)
    for (const c of [
      py("import subprocess\nsubprocess.run('git push origin main', shell=True)"),
      py("import os\nos.system('git push origin main')"),
      py("__import__('os').system('git push origin main')"),
      py("x = f\"{__import__('os').system('git push origin main')}\""), // an f-string's {...} runs
      py("import helpers\nhelpers.run('git push origin main')"), // a module not on the list
      py("run('git push origin main')"), // a name not on the list
      py("print('git push origin main')", "python - <<PY"), // unquoted: bash expands it first
      py("print('git push origin main')", "python - <<'PY' | bash"), // its output runs
      py("x = 'git push origin main\nprint(x)"), // a one-quote string cut off by a line break: not read for sure
      py("x = '\"\"\"'; exec('git push origin main'); y = '\"\"\"'"), // quotes in quotes are read as Python reads them
      // Another script runs, which this one may have written: its git text is kept.
      py("open('/tmp/t/r.py', 'w').write('git push origin main')", "python - <<'PY'", '\npython /tmp/t/r.py'),
      // Python that may run code keeps every body, a data body's too.
      `cat > n.md <<'EOF'\ngit push origin main\nEOF\n${py('import helpers')}`,
      "cat > n.md <<'EOF'\ngit push origin main\nEOF\npython - <<<'import helpers'", // a here-string is no heredoc
      "python - <<'PY'\nprint('git push origin main')", // no end line
      "python - <<'PY'\nprint('hi')\nPY\ngit commit -m x", // a real commit outside the body is still seen
      "cat > n.md <<'EOF'\ngit push origin main\nEOF\necho 'import helpers' | python -", // stdin from a pipe: not read here
      // A quote right after a keyword opens a string (`if''`), and only a whole prefix word joins one (`t''`
      // runs its {...} like an f-string): read wrong, the code after it would hide inside a string.
      py("x = 0 if'' else 1;import os;os.system('git push origin main') #'"),
      py("x = 'a' in'' ;import subprocess;subprocess.run(['git','commit','-am','x']) #'"),
      py("x = 1 if'#'else 0;__import__('os').system('git push origin main')"),
      py("x = t'';import os;os.system('git push') #'"),
      py("x = 'a\nimport os\nos.system('git push origin main') #'"), // a one-quote string ends on its line
      // What it writes, a script or module run after may load: its text is kept.
      py("open('x.py', 'w').write('import subprocess\\nsubprocess.run([\"git\", \"push\"])')", "python3 - <<'PY'", '\npython3 x.py'),
      py("open('json.py', 'w').write('import subprocess\\nsubprocess.run([\"git\",\"push\"])')", "python3 - <<'PY'", '\npython3 other.py'),
      `cat > json.py <<'EOF'\nimport helpers\nhelpers.run('git push origin main')\nEOF\n${py('import json\nprint(1)')}`, // a module it loads
      py("open('json.py', 'w').write('git push origin main')\nimport json"), // its own file, as a module
      `${py("open('sitecustomize.py', 'w').write('git push origin main')")}\n${py('print(1)')}`, // the next Python's startup file
      // Text Python reads another way than these rules: a lone `\r` ends a comment, an encoding line changes
      // the code, and fullwidth letters fold to ASCII names.
      py("# note\rexec(\"import os;os.system('git push origin main')\")\nprint(1)"),
      py("# coding: unicode_escape\nx = 1 # \\nimport os\nprint('git push origin main')"),
      py("#!/usr/bin/env python\n# -*- coding: utf-7 -*-\nprint('git push origin main')"),
      py("ｅｘｅｃ('import os;os.system(\"git push origin main\")')"),
      // Another stdin replaces the body as what Python reads.
      `cat > other.py <<'EOF'\nimport helpers\nhelpers.run('git push origin main')\nEOF\npython - <<'PY' < other.py\nprint(1)\nPY`,
      `cat > n.md <<'EOF'\ngit push origin main\nEOF\npython - <<'PY' <<<'import helpers'\nprint(1)\nPY`,
      // A comment ends on its line; f-prefixes in any order and case are refused; and a value that is a risky name.
      py("# note\nimport os\nos.system('git push origin main')"),
      py("x = fr'{__import__(\"os\").system(\"git push origin main\")}'"),
      py("x = Rf'{__import__(\"os\").system(\"git push origin main\")}'"),
      py("list(map(breakpoint, ['git push origin main']))"),
      // A Python spelled so it isn't read as one (`"python"`): its body is unchecked, so a data body is kept.
      `"python" - <<'PY'\nimport helpers\nPY\ncat > n.md <<'EOF'\ngit push origin main\nEOF`,
      // Unquoted, bash runs `$(...)` in it, which could run a data body.
      `cat > /tmp/t/x.md <<'EOF'\ngit push origin main\nEOF\npython - <<PY\nprint("$(bash /tmp/t/x.md)")\nPY`,
    ]) counts(c)
  })

  test('knows a gh command that writes from one that reads', async () => {
    for (const c of ['gh pr create --title x', 'gh issue comment 3 --body hi', 'gh release create v1', 'gh api repos/o/r/issues -f title=x', 'gh api -X POST /gists']) {
      expect(ghWrites(c)).toBe(true)
    }
    for (const c of ['gh pr view 3', 'gh pr list', 'gh api repos/o/r', 'gh run watch', 'git status']) expect(ghWrites(c)).toBe(false)
  })

  test('reads a tool call value by value, and a binary file by its name', async () => {
    const kinds = (v: unknown) => scanValue(v, 'the call', PERSONAL).map(f => f.kind)
    expect(kinds({ files: [{ path: 'a.py', content: `ok = 1\ntoken = "${FAKE_GH}"\n# version example` }] })).toContain('GitHub token')
    expect(kinds({ path: 'secrets/id_rsa' })).toContain('a sensitive file (keys, .env or credentials)')
    expect(kinds({ title: 'Fix the parser', draft: true, labels: ['bug'] })).toEqual([])
    const binary = 'diff --git a/keys/site.p12 b/keys/site.p12\nnew file mode 100644\nBinary files /dev/null and b/keys/site.p12 differ\n'
    expect(scanDiff(binary, []).map(f => f.where)).toEqual(['keys/site.p12'])
  })

  test('leaves alone what ssh runs on another machine, and only that', async () => {
    expect(gitAction("ssh box 'cd ~/repo && git commit -m x'")).toBe(undefined)
    expect(gitAction('/c/Windows/System32/OpenSSH/ssh.exe -o BatchMode=yes box "git push origin main" 2>&1')).toBe(undefined)
    expect(gitAction("ssh.exe box 'bash -s' <<'EOF'\ncd ~/repo && git add -A\ngit commit -m x\nEOF")).toBe(undefined)
    // What follows the ssh command runs here and is still seen.
    const after = gitAction("ssh box 'git commit -m remote' && cd /srv/app && git push")
    expect([after?.kind, after?.commits, after?.dir, after?.message]).toEqual(['push', false, '/srv/app', ''])
    const afterHeredoc = gitAction("ssh box 'bash -s' <<'EOF'\ngit commit -m remote\nEOF\ngit commit -m local")
    expect([afterHeredoc?.kind, afterHeredoc?.message]).toEqual(['commit', 'local'])
    expect(gitAction("ssh box 'true' <<'EOF' && git push\nls\nEOF")?.kind).toBe('push')
    expect(gitAction("ssh box 'a'; ssh box2 'git push'; git commit -m x")?.pushes).toBe(false)
    expect(gitAction('& "C:\\Program Files\\OpenSSH\\ssh.exe" box "cd repo; git push"')).toBe(undefined)
    // Not ssh at all.
    expect(gitAction('ssh-add ~/.ssh/key && git push')?.kind).toBe('push')
    expect(gitAction('git commit -m "fix ssh login"')?.kind).toBe('commit')
    // The word ssh inside another command's text hides nothing that runs here.
    expect(gitAction('echo "use ssh " && git push')?.kind).toBe('push')
    const message = gitAction('git commit -m "fix ssh login" && git push')
    expect([message?.commits, message?.pushes]).toEqual([true, true])
    expect(gitAction('GIT_SSH_COMMAND="ssh -i key" git push')?.kind).toBe('push')
    expect(gitAction('git -c core.sshCommand="ssh -i key" push origin main')?.refs).toEqual(['main'])
    expect(gitAction("printf 'ssh box\\n' ; git push")?.kind).toBe('push')
    // Odd input neither hangs the scanner nor hides a local push.
    expect(gitAction('C:\\Windows\\System32\\OpenSSH\\ssh.exe box "git push"')).toBe(undefined)
    expect(gitAction('cd "C:\\repo\\"; git push')?.kind).toBe('push')
    expect(gitAction("echo 'unterminated ; git push")?.kind).toBe('push')
    expect(gitAction('ssh box true || git push')?.kind).toBe('push')
    expect(gitAction('(cd /srv/app && git push)')?.dir).toBe('/srv/app')
    expect(localPart('')).toBe('')
    // `timeout [options] DURATION` comes before the program: an ssh after it is still remote, while
    // `timeout 90 git push` and a push after the ssh command are still local.
    expect(gitAction("timeout 90 ssh box 'cd ~/repo && git push origin refs/tags/v1'")).toBe(undefined)
    expect(gitAction("MSYS_NO_PATHCONV=1 timeout -s KILL 2m /c/Windows/System32/OpenSSH/ssh.exe box 'git push'")).toBe(undefined)
    expect(gitAction('timeout 90 git push origin main')?.refs).toEqual(['main'])
    // A script written here only to be sent to ssh runs its git commands there, not here.
    const sshScript = "S=/tmp/s\ncat > \"$S/run.sh\" <<'EOF'\nC=$(mktemp -d); git -C \"$C\" init -q\ngit -C \"$C\" commit -qm c\ngit push origin main\nEOF\n"
    expect(gitAction(sshScript + "ssh box 'bash -s' < \"$S/run.sh\"")).toBe(undefined)
    expect(gitAction(sshScript + "MSYS_NO_PATHCONV=1 timeout 600 ssh.exe box 'bash -s' < \"$S/run.sh\"")).toBe(undefined)
    // Kept on disk and run here, or a real push after the ssh line: still local. Written to a .md file
    // with nothing else here running shell code: only text (`blankWrittenScripts`). A later command that
    // runs such a file is not seen by this check either way.
    expect(gitAction(sshScript + 'bash "$S/run.sh"')?.pushes).toBe(true)
    expect(gitAction(sshScript.replace('cat > "$S/run.sh"', 'cat > /tmp/notes.md') + "ssh box 'bash -s' < \"$S/run.sh\"")).toBe(undefined)
    expect(gitAction(sshScript + "ssh box 'bash -s' < \"$S/run.sh\"\ngit push origin main")?.refs).toEqual(['main'])
    // ssh's ProxyCommand and LocalCommand run here, so such an ssh line hides nothing.
    expect(gitAction("ssh -o ProxyCommand='git push origin main' box true")?.pushes).toBe(true)
    expect(gitAction(sshScript.replace('/tmp/s', '/tmp/s') + "ssh -o ProxyCommand='sh /tmp/s/run.sh' box 'bash -s' < \"$S/run.sh\"")?.pushes).toBe(true)
    expect(gitAction("ssh -o LocalCommand='git commit -am x' -o PermitLocalCommand=yes box true")?.commits).toBe(true)
    expect(gitAction("timeout 90 ssh box 'uptime' && git push")?.kind).toBe('push')
    // Heredoc lookalikes and odd heredocs never hide the local push that follows.
    expect(gitAction('ssh box cat <<< "note"\ngit push origin main')?.kind).toBe('push')
    expect(gitAction("ssh box 'echo <<X'\ngit push")?.kind).toBe('push')
    expect(gitAction("ssh box 'echo $((1<<4))'\ngit push")?.kind).toBe('push')
    expect(gitAction("ssh box bash <<'END-OF'\nhostname\nEND-OF\ngit push")?.kind).toBe('push')
    expect(gitAction("ssh box bash <<'END-OF'\nhostname\nEND-OF\ngit push")?.commits).toBe(false)
    expect(gitAction("ssh box bash <<'EOF'\ngit commit -m remote\n")?.kind).toBe('commit') // no end line: checked
    expect(gitAction('ssh box uptime # don\'t wait\ngit push')?.kind).toBe('push')
    expect(gitAction('ssh box "dir C:\\temp\\"; git push origin main')?.kind).toBe('push') // PowerShell quoting
    expect(localPart("echo a; ssh box 'x y' ; echo b").length).toBe("echo a; ssh box 'x y' ; echo b".length)
  })

  test('turns the folder a command names into one git can open, per machine', async () => {
    // Windows: Git Bash paths become native, and ~ is the profile folder.
    expect(resolveDir('/c/Users/x/repo', 'C:/Users/x', true)).toBe('C:/Users/x/repo')
    expect(resolveDir('~/repo', 'C:/Users/x', true)).toBe('C:/Users/x/repo')
    // Linux: /d/work is a real folder and stays as it is.
    expect(resolveDir('/d/work/app', '/home/pat', false)).toBe('/d/work/app')
    expect(resolveDir(gitAction('cd ~/repo && git push')?.dir ?? '', '/home/pat', false)).toBe('/home/pat/repo')
    expect(resolveDir('$HOME/repo', '/home/pat', false)).toBe('/home/pat/repo')
    expect(resolveDir('${HOME}', '/home/pat', false)).toBe('/home/pat')
    expect(resolveDir('~other/repo', '/home/pat', false)).toBe('~other/repo')
  })
})

describe('review prompt', () => {
  test('names the reviewers and a security focus per language', async () => {
    expect(languageOf('src/app.py')).toBe('Python')
    expect(languageOf('web/Dockerfile')).toBe('Docker')
    expect(languageOf('notes/plan.md')).toBe(undefined)
    expect(languageOf('.venv/lib/x.py')).toBe(undefined)
    const prompt = reviewPrompt(new Map([['a.py', 'Python'], ['compose.yaml', 'Docker']]))
    for (const part of ['code-reviewer', 'silent-failure-hunter', 'pr-test-analyzer', 'Python:', 'docker-skills:docker-build-strategies', 'SearchPlugins']) {
      expect(prompt.includes(part)).toBe(true)
    }
    // The mod's own copies of the agents are named, and general-purpose agents are ruled out.
    expect(prompt.includes('review-guard:<name>')).toBe(true)
    expect(prompt.includes('Do not hand their work to general-purpose agents')).toBe(true)
  })

  test('every real bug is fixed, old and unsure ones included, unless one of four blockers applies; nits are left', async () => {
    const text = flat(reviewPrompt(new Map([['a.py', 'Python']])))
    // The agents get a sentence to pass on that overrides their own cutoffs, asks for old bugs too, and
    // leaves out nitpicks.
    expect(text.includes(`prompt word for word: "${REPORT_BUGS}"`)).toBe(true)
    expect(REPORT_BUGS.includes('overrides any confidence threshold')).toBe(true)
    expect(REPORT_BUGS.includes('including bugs that were already in the changed files before this change')).toBe(true)
    expect(REPORT_BUGS.includes('Name anything else (style, wording, naming, comments, missing tests, other nitpicks) as a nit in one line each, not as a bug')).toBe(true)
    // The test and comment reviewers still have bugs to report, and the mod's own agents' rules are overridden.
    expect(REPORT_BUGS.includes('a missing test or a wrong comment counts when it hides or would cause one')).toBe(true)
    expect(REPORT_BUGS.includes('overrides any confidence threshold, filter or reporting rule')).toBe(true)
    expect(text.includes('tell it to read them in full, not only the diff')).toBe(true)
    // The list may hold files held or handed back from earlier turns, so it is not called "this turn's".
    expect(text.includes('file(s) not yet reviewed')).toBe(true)
    expect(text.includes('this turn\'s own edits')).toBe(false)
    // The old way out for a large change in code the turn did not touch is gone, in any wording, and
    // "alone is never a reason" (which let a second excuse through) has not come back.
    expect(text.includes('large change')).toBe(false)
    expect(text.includes('alone is never a reason')).toBe(false)
    // Nits are no longer fixed.
    expect(text.includes('logging nits too')).toBe(false)
    expect(text.includes('fixed like high ones')).toBe(false)
    for (const part of [
      'Fix the real bugs: code in a file listed above that gives a wrong result, crashes, hangs, loses or leaks data, or opens a security hole',
      'including bugs that were already there before this change',
      '"Low confidence", "pre-existing", "unlikely to trigger" and "not in the changed lines" are no reasons to leave a real bug',
      'Do not fix style, wording, naming, comments, logging nits, refactors or missing tests unless one hides a real bug: name each in one line and leave it',
      'Fixed: say which file and line changed',
      'Does not hold up: show why in one line, with the code, path or output that proves it',
      'or that a security warning is about test-only code',
      // All four blockers, in one closed list, each with what it must show.
      'Holds up but is not fixed here, for one of these four blockers only: the fix would break something (say what, and the test, output or code that shows it), there is no fixed version of the package or tool yet, it needs the user\'s decision (write the exact question), or it is an older problem in a file not listed above (a break these changes caused in another file is fixed like any other).',
      'Name the blocker, offer a narrow suppression or a follow-up, and never count it as fixed',
      'Any other reason means fix it',
      'or changed code outside the changes under review, send them to code-reviewer once more',
      'a bug still open is never counted as fixed',
      'the files this review itself edited, and each question a blocker left for the user',
      'If the listed files are only ones the user told you not to review',
      'If an agent or scanner fails or returns nothing, say which one and why',
      'Rerun the tests (if the project has none, say so) and the scanners',
      'Stop after three rounds and list what is still open',
      'Tell the user every real bug and its outcome, then the other findings left alone in a short list',
      'Commit or push nothing as part of this review unless the user asked for that',
      'was itself this review, say so in one line and stop',
    ]) expect([part, text.includes(part)]).toEqual([part, true])
    // The steps come once each, in order.
    const at = ['1. Run the', '2. Security review', '3. Fix the real bugs', '4. Rerun', '5. Tell the user'].map(s => text.indexOf(s))
    expect(at.every((n, i) => n >= 0 && (i === 0 || n > (at[i - 1] ?? -1)))).toBe(true)
    // No file is cut from the list: a file left off would get no findings.
    const many = new Map(Array.from({ length: 12 }, (_, i) => [`f${i}.py`, 'Python']))
    expect(reviewPrompt(many).includes('f11.py')).toBe(true)
  })

  test("the mod's own reviewers report low findings too", async () => {
    const prompt = (name: string) => REVIEW_AGENTS.find(a => a.name === name)?.prompt ?? ''
    expect(prompt('code-reviewer').includes('Only report issues with confidence')).toBe(false)
    expect(prompt('code-reviewer').includes('Report every issue you find, at any confidence')).toBe(true)
    expect(prompt('code-reviewer').includes('filter aggressively')).toBe(false)
    expect(prompt('pr-test-analyzer').includes('**Minor Gaps**')).toBe(true)
    expect(prompt('pr-test-analyzer').includes('overly pedantic')).toBe(false)
    // Old issues are scored on their merits, not filed as likely false positives, and whole files are read.
    expect(prompt('code-reviewer').includes('Likely false positive or pre-existing issue')).toBe(false)
    expect(prompt('code-reviewer').includes('is not put here for being old: score it on its merits.')).toBe(true)
    expect(prompt('code-reviewer').includes('read each changed file in full')).toBe(true)
  })
})

test('registers the five review agents when the mod loads, for sessions already open', async ($, on) => {
  const names: string[] = []
  on('agent.register', (_$, e) => {
    names.push(e.name)
    expect(e.prompt.length > 1000).toBe(true)
    return { value: { agent: `review-guard:${e.name}` } }
  })
  on('session.start', () => ({ cwd: 'C:/proj' }))
  await $.session.start({ source: 'startup' } as never)
  expect(names.sort()).toEqual(['code-reviewer', 'comment-analyzer', 'pr-test-analyzer', 'silent-failure-hunter', 'type-design-analyzer'])
})

// --- the review cycle ----------------------------------------------------------------------

type Status = 'pending' | 'running' | 'waiting' | 'idle' | 'completed' | 'failed' | 'killed'

/**
 * Plays back what the mod's copy before a reload stored: the first read of the review state answers
 * `value` (as an unwritten key would, at version 0), and every later read goes to the kit's store.
 */
function seed(on: On, value: unknown) {
  let seeded = false
  on('state.get', ($, e, next) => {
    if (seeded || e.plugin !== 'review-guard' || e.key !== 'cycle') return next(e)
    seeded = true
    return { value: { value: value as never, version: 0 } }
  })
}

/**
 * Stands for the engine under the review cycle; `agents` is the session's agents, changed by the test.
 * Each gets the id `a<index>` unless the test gives one.
 */
function cycle($: Engine, on: On) {
  const out = { agents: [] as { status: Status; type?: string; id?: string }[] }
  on('tool.call', () => ({ result: {} }))
  on('classic.Stop', () => ({})) // no other Stop hook blocks
  on('prompt.submit', (_$, e) => ({ text: e.text })) // the prompt enters
  on('agent.list', () => ({ value: out.agents.map((a, i) => ({ id: `a${i}`, description: 'reviewer', type: 'review-guard:code-reviewer', ...a })) }))
  const edit = (file: string) => $.tool.call({ tool: 'Edit', file_path: file, old_string: 'a', new_string: 'b' })
  const stop = async (active = false) => (await $.classic.Stop({ stop_hook_active: active })).block
  return { out, edit, stop }
}

test('a turn that changed code is sent back for review once', async ($, on) => {
  const { edit, stop } = cycle($, on)
  await edit('C:/proj/app.py')
  expect((await stop())?.includes('app.py')).toBe(true)
  expect(await stop(true)).toBe(undefined) // the review turn ends: no second ask
  await edit('C:/proj/notes.md') // not code
  expect(await stop()).toBe(undefined)
})

test('fixes made during a review are not sent back, however the reports arrive', async ($, on) => {
  const { out, edit, stop } = cycle($, on)
  await edit('C:/proj/app.py')
  expect((await stop())?.includes('app.py')).toBe(true)
  // The review turn ends with two reviewers still out: the review stays open.
  out.agents = [{ status: 'running' }, { status: 'completed' }]
  expect(await stop(true)).toBe(undefined)
  // A report wakes the session in a turn of its own, the fix follows, a reviewer is still out.
  await $.prompt.submit({ text: 'reviewer report', wait: false, origin: { kind: 'peer' } })
  await edit('C:/proj/app.py')
  expect(await stop()).toBe(undefined)
  // The last report: another fix, nobody out. The review is over and its fixes are not re-queued.
  out.agents = [{ status: 'completed' }, { status: 'idle' }]
  await edit('C:/proj/app.py')
  expect(await stop()).toBe(undefined)
  // What comes next is tracked again, with no user prompt needed in between.
  await edit('C:/proj/other.py')
  const next = await stop()
  expect(next?.includes('other.py')).toBe(true)
  expect(next?.includes('app.py')).toBe(false)
})

test('a list that fails as a review starts is said, and every agent then counts as part of the review', async ($, on) => {
  const status: string[] = []
  on('ui.status', (_$, e) => {
    status.push(e.text ?? '')
    return { value: undefined }
  })
  let list: 'fails' | 'bg out' | 'none out' = 'fails'
  on('tool.call', () => ({ result: {} }))
  on('classic.Stop', () => ({}))
  on('agent.list', () => (list === 'fails' ? { deny: 'no list' }
    : { value: list === 'bg out' ? [{ id: 'bg', description: 'other work', type: 'general-purpose', status: 'running' as Status }] : [] }))
  await $.tool.call({ tool: 'Edit', file_path: 'C:/proj/app.py', old_string: 'a', new_string: 'b' })
  expect((await $.classic.Stop({ stop_hook_active: false })).block?.includes('app.py')).toBe(true)
  expect(status.some(s => s.includes('any agent already at work counts as part of this review'))).toBe(true)
  // The agent that was at work could not be seen as other work, so it holds the review open.
  list = 'bg out'
  expect((await $.classic.Stop({ stop_hook_active: true })).block).toBe(undefined)
  await $.tool.call({ tool: 'Edit', file_path: 'C:/proj/app.py', old_string: 'a', new_string: 'b' })
  expect((await $.classic.Stop({ stop_hook_active: false })).block).toBe(undefined) // its fix is not sent back
  // Once it hands back, the review is over and new work gets its own review.
  list = 'none out'
  expect((await $.classic.Stop({ stop_hook_active: false })).block).toBe(undefined)
  await $.tool.call({ tool: 'Edit', file_path: 'C:/proj/next.py', old_string: 'a', new_string: 'b' })
  expect((await $.classic.Stop({ stop_hook_active: false })).block?.includes('next.py')).toBe(true)
})

test('a list that fails when no review can start says nothing about a review', async ($, on) => {
  const status: string[] = []
  on('ui.status', (_$, e) => {
    status.push(e.text ?? '')
    return { value: undefined }
  })
  let lists = 0
  on('tool.call', () => ({ result: {} }))
  on('classic.Stop', () => ({}))
  on('agent.list', () => {
    lists++
    return { deny: 'no list' }
  })
  // Nothing queued, and a review turn ending: no list is asked for, and nothing is said.
  expect((await $.classic.Stop({ stop_hook_active: false })).block).toBe(undefined)
  expect((await $.classic.Stop({ stop_hook_active: true })).block).toBe(undefined)
  expect(lists).toBe(0)
  expect(status.some(s => s.includes('could not list'))).toBe(false)
})

test("what other work changes while a review runs is not taken for the review's fixes", async ($, on) => {
  const { out, edit, stop } = cycle($, on)
  out.agents = [{ id: 'bg', status: 'running', type: 'general-purpose' }]
  await edit('C:/proj/app.py')
  expect((await stop())?.includes('app.py')).toBe(true)
  out.agents = [{ id: 'bg', status: 'running' }, { id: 'r1', status: 'running' }]
  expect(await stop(true)).toBe(undefined)
  // The agent that was already at work changes a file; the main loop fixes app.py.
  await $.tool.call({ tool: 'Edit', file_path: 'C:/proj/other.py', old_string: 'a', new_string: 'b', agentId: 'bg' } as never)
  await $.tool.call({ tool: 'Bash', command: `sed -i x C:/proj/shell.py`, agentId: 'bg' } as never)
  await edit('C:/proj/app.py')
  // The review ends: its fix is not sent back, the other agent's files get a review of their own.
  out.agents = [{ id: 'bg', status: 'running' }, { id: 'r1', status: 'completed' }]
  expect(await stop()).toBe(undefined)
  const next = await stop()
  expect(next?.includes('other.py')).toBe(true)
  expect(next?.includes('shell.py')).toBe(true)
  expect(next?.includes('app.py')).toBe(false)
})

test('the agents at work when a review began, and what they changed, survive a reload', async ($, on) => {
  seed(on, { reviewing: true, held: false, changed: {}, underReview: { 'C:/proj/app.py': 'Python' }, othersAtStart: ['bg', 5], othersChanged: { 'C:/proj/bg.py': 'Python' } })
  const { out, edit, stop } = cycle($, on)
  // Only the agent from before the review is out: the review is over, and its fix is not sent back.
  out.agents = [{ id: 'bg', status: 'running' }]
  await edit('C:/proj/app.py')
  expect(await stop()).toBe(undefined)
  const next = await stop()
  expect(next?.includes('bg.py')).toBe(true)
  expect(next?.includes('app.py')).toBe(false)
  // A stored value is read with care: what is not text is dropped. With no review running, nothing
  // review-only stands and no file is lost; during one, a hold is dropped and no id is on both lists.
  expect(cycleFrom({ othersAtStart: ['a', 1, null], underReview: { 'u.py': 'Python' }, othersChanged: { 'x.py': 'Python', 'y.py': 3 }, joined: ['b'], promptPending: true })).toEqual(
    { reviewing: false, held: false, changed: { 'u.py': 'Python', 'x.py': 'Python' }, underReview: {}, othersAtStart: [], othersChanged: {}, joined: [], promptPending: false })
  expect(cycleFrom({ reviewing: true, held: true, othersAtStart: ['a', 'a'], joined: ['a', 'b', 'b', 2], promptPending: true })).toEqual(
    { reviewing: true, held: false, changed: {}, underReview: {}, othersAtStart: ['a'], othersChanged: {}, joined: ['b'], promptPending: true })
})

test('agents already at work when a review starts do not hold it open; any agent started during it does', async ($, on) => {
  const { out, edit, stop } = cycle($, on)
  // Other work is going on before the review: a general-purpose agent and a reviewer-named one.
  out.agents = [{ id: 'bg1', status: 'running', type: 'general-purpose' }, { id: 'bg2', status: 'waiting', type: 'acme:security-reviewer' }]
  await edit('C:/proj/app.py')
  expect((await stop())?.includes('app.py')).toBe(true)
  // The review starts agents of any type: a reviewer, a general-purpose one doing the security review, a fork.
  for (const [id, type, status] of [['r1', 'pr-review-toolkit:code-reviewer', 'running'], ['s1', 'general-purpose', 'pending'], ['f1', 'fork', 'waiting']] as const) {
    out.agents = [{ id: 'bg1', status: 'running', type: 'general-purpose' }, { id: 'bg2', status: 'waiting' }, { id, status, type }]
    expect(await stop(true)).toBe(undefined)
    await edit('C:/proj/app.py') // a fix while it is out: not sent back
    expect(await stop()).toBe(undefined)
  }
  // An agent with no id can't be told apart from the review's own, so it holds the review open too.
  out.agents = [{ id: 'bg1', status: 'running' }, { id: 'bg2', status: 'waiting' }, { id: '', status: 'running', type: 'general-purpose' }]
  await edit('C:/proj/app.py')
  expect(await stop()).toBe(undefined)
  // So does a status the engine may add later: only idle, completed, failed and killed have handed back.
  out.agents = [{ id: 'bg1', status: 'running' }, { id: 'bg2', status: 'waiting' }, { id: 'n1', status: 'queued' as Status }]
  expect(await stop()).toBe(undefined)
  // Only the work that was already going on is left, plus agents that handed back: the review is over.
  out.agents = [{ id: 'bg1', status: 'running' }, { id: 'bg2', status: 'running' }, { id: 'r1', status: 'completed' }, { id: 'f1', status: 'failed' }, { id: 's1', status: 'killed' }]
  expect(await stop()).toBe(undefined)
  await edit('C:/proj/next.py')
  const next = await stop()
  expect(next?.includes('next.py')).toBe(true)
  expect(next?.includes('app.py')).toBe(false)
  // That next review started with bg1 and bg2 at work, so they still don't hold it open.
  expect(await stop(true)).toBe(undefined)
  await edit('C:/proj/last.py')
  expect((await stop())?.includes('last.py')).toBe(true)
})

test('an agent from before a review that the review starts again or messages becomes part of it', async ($, on) => {
  mock.env(on, { USERPROFILE: 'C:/Users/pat' }) // Windows: `C:/...` is a full path only there
  const { out, edit, stop } = cycle($, on)
  on('agent.spawn', (_$, e) => ({ agentId: e.resume?.agentId ?? 'new1', model: 'm' }))
  on('session.send', () => ({ isDelivered: true }))
  on('session.receive', (_$, e) => ({ text: e.text }))
  const spawn = (input: object) => $.agent.spawn({ tool_use_id: 't', prompt: 'p', description: 'd', ...input } as never)
  // Other work before the review: bg (finishes later), tm (an idle teammate) and peer (keeps working).
  out.agents = [{ id: 'bg', status: 'running' }, { id: 'tm', status: 'idle', name: 'helper' } as never, { id: 'peer', status: 'running' }]
  await edit('C:/proj/app.py')
  expect((await stop())?.includes('app.py')).toBe(true)
  // The main loop starts bg again, and messages the idle teammate by its name: both are the review's now.
  await spawn({ resume: { agentId: 'bg' } })
  await $.session.send({ to: 'helper', text: 'fix the findings', origin: { kind: 'tool' } } as never)
  await $.session.receive({ origin: { kind: 'peer' }, text: 'fix the findings', agentId: 'tm' } as never)
  // peer, which is other work, starts a helper and messages it: both stay other work.
  await spawn({ parentAgentId: 'peer' })
  await $.session.send({ to: 'new1', text: 'help', origin: { kind: 'tool' }, agentId: 'peer' } as never)
  await $.session.receive({ origin: { kind: 'peer' }, text: 'help', agentId: 'new1' } as never)
  // A message from outside the session, with no send before it, changes nothing.
  await $.session.receive({ origin: { kind: 'peer' }, text: 'hi', agentId: 'peer' } as never)
  // bg and tm, now the review's, fix app.py (under review); bg also edits bgown.py, its own work.
  for (const [who, file] of [['bg', 'app.py'], ['tm', 'app.py'], ['bg', 'bgown.py'], ['peer', 'peer.py'], ['new1', 'helper.py']]) {
    await $.tool.call({ tool: 'Edit', file_path: `C:/proj/${file}`, old_string: 'a', new_string: 'b', agentId: who } as never)
  }
  // bg and tm are out: the review stays open while peer and its helper are not counted.
  out.agents = [{ id: 'bg', status: 'running' }, { id: 'tm', status: 'running' }, { id: 'peer', status: 'running' }, { id: 'new1', status: 'running' }]
  expect(await stop(true)).toBe(undefined)
  await edit('C:/proj/later.py')
  expect(await stop()).toBe(undefined) // still open: later.py is a fix, not new work
  // bg and tm hand back: the review is over. Their edits to app.py were fixes; bg's own file, peer's and
  // its helper's get a review.
  out.agents = [{ id: 'bg', status: 'completed' }, { id: 'tm', status: 'idle' }, { id: 'peer', status: 'running' }, { id: 'new1', status: 'running' }]
  expect(await stop()).toBe(undefined)
  const next = await stop()
  for (const f of ['peer.py', 'helper.py', 'bgown.py']) expect(next?.includes(f)).toBe(true)
  for (const f of ['later.py', 'app.py']) expect(next?.includes(f)).toBe(false)
})

test('an agent from before a review that finished and is started again unseen becomes part of it', async ($, on) => {
  mock.env(on, { USERPROFILE: 'C:/Users/pat' }) // Windows: a path in another case is the same file
  const { out, edit, stop } = cycle($, on)
  out.agents = [{ id: 'bg', status: 'running' }, { id: 'tm', status: 'idle' }]
  await edit('C:/proj/app.py')
  expect((await stop())?.includes('app.py')).toBe(true)
  // At one check bg has finished (and a reviewer is out); the idle teammate tm stays other work.
  out.agents = [{ id: 'bg', status: 'completed' }, { id: 'tm', status: 'idle' }, { id: 'r1', status: 'running' }]
  expect(await stop(true)).toBe(undefined)
  // bg runs again with no event this mod saw: it holds the review open now. tm wakes and does not.
  out.agents = [{ id: 'bg', status: 'running' }, { id: 'tm', status: 'running' }]
  await edit('C:/proj/app.py')
  // bg, joined: its fix to app.py (with another spelling) is the review's; its own file is not.
  await $.tool.call({ tool: 'Edit', file_path: 'c:\\proj\\app.py', old_string: 'a', new_string: 'b', agentId: 'bg' } as never)
  await $.tool.call({ tool: 'Edit', file_path: 'C:/proj/bgown.py', old_string: 'a', new_string: 'b', agentId: 'bg' } as never)
  expect(await stop()).toBe(undefined)
  out.agents = [{ id: 'bg', status: 'completed' }, { id: 'tm', status: 'running' }]
  expect(await stop()).toBe(undefined) // only tm, other work, is out: over
  await edit('C:/proj/next.py')
  const next = await stop()
  expect(next?.includes('next.py')).toBe(true)
  expect(next?.includes('bgown.py')).toBe(true)
  expect(next?.toLowerCase().includes('app.py')).toBe(false)
})

test('a refused message, work handed on outside a review, and a reload are handled', async ($, on) => {
  mock.env(on, { USERPROFILE: 'C:/Users/pat' }) // Windows: `C:/...` is a full path only there
  // A stored review from before a reload, with bg as other work: the first event after it still counts.
  seed(on, { reviewing: true, held: false, changed: {}, underReview: { 'C:/proj/app.py': 'Python' }, othersAtStart: ['bg', 'tm'], othersChanged: {} })
  const { out, edit, stop } = cycle($, on)
  let deliver = false
  on('agent.spawn', (_$, e) => (e.prompt === 'refuse' ? { deny: 'not now' } : { agentId: e.resume?.agentId ?? 'x', model: 'm' }) as never)
  on('session.send', () => (deliver ? { isDelivered: true } : { isDelivered: false, reason: 'no such agent' }) as never)
  on('session.receive', (_$, e) => ({ text: e.text }))
  await $.agent.spawn({ tool_use_id: 't', prompt: 'p', description: 'd', resume: { agentId: 'bg' } } as never)
  // A refused start of tm, and a refused message to it, leave tm other work; so does a delivery from outside.
  await $.agent.spawn({ tool_use_id: 't', prompt: 'refuse', description: 'd', resume: { agentId: 'tm' } } as never).catch(() => undefined)
  await $.session.send({ to: 'tm', text: 'x', origin: { kind: 'tool' } } as never).catch(() => undefined)
  await $.session.receive({ origin: { kind: 'peer' }, text: 'from elsewhere', agentId: 'tm' } as never)
  await $.tool.call({ tool: 'Edit', file_path: 'C:/proj/app.py', old_string: 'a', new_string: 'b', agentId: 'bg' } as never)
  await $.tool.call({ tool: 'Edit', file_path: 'C:/proj/bg.py', old_string: 'a', new_string: 'b', agentId: 'bg' } as never)
  await $.tool.call({ tool: 'Edit', file_path: 'C:/proj/tm.py', old_string: 'a', new_string: 'b', agentId: 'tm' } as never)
  // bg (the review's now) is out: the review stays open; tm (still other work) does not hold it.
  out.agents = [{ id: 'bg', status: 'running' }, { id: 'tm', status: 'running' }]
  expect(await stop(true)).toBe(undefined)
  out.agents = [{ id: 'bg', status: 'completed' }, { id: 'tm', status: 'running' }]
  expect(await stop()).toBe(undefined)
  const next = await stop()
  expect(next?.includes('tm.py')).toBe(true)
  expect(next?.includes('bg.py')).toBe(true) // bg joined after the reload: its own file gets a review
  expect(next?.includes('app.py')).toBe(false) // bg's fix to the file under review
  // Outside a review, starting or messaging an agent changes nothing: the next edit is queued as usual.
  expect(await stop(true)).toBe(undefined)
  out.agents = []
  expect(await stop()).toBe(undefined) // that review is over too
  deliver = true
  await $.agent.spawn({ tool_use_id: 't', prompt: 'p', description: 'd', resume: { agentId: 'tm' } } as never)
  await $.session.send({ to: 'tm', text: 'x', origin: { kind: 'tool' } } as never)
  await $.session.receive({ origin: { kind: 'peer' }, text: 'x', agentId: 'tm' } as never)
  await $.tool.call({ tool: 'Edit', file_path: 'C:/proj/after.py', old_string: 'a', new_string: 'b', agentId: 'tm' } as never)
  expect((await stop())?.includes('after.py')).toBe(true)
})

test('an agent that appears while a review starts is other work', async ($, on) => {
  let lists = 0
  on('tool.call', () => ({ result: {} }))
  on('classic.Stop', () => ({}))
  // The first read, as the review starts, misses "late"; it is there by the second read.
  let afterStart: { id: string; status: Status }[] = []
  on('agent.list', () => {
    lists++
    const now = lists === 1 ? [] : lists === 2 ? [{ id: 'late', status: 'running' as Status }] : afterStart
    return { value: now.map(a => ({ description: 'other work', type: 'general-purpose', ...a })) }
  })
  const stop = async (active = false) => (await $.classic.Stop({ stop_hook_active: active })).block
  await $.tool.call({ tool: 'Edit', file_path: 'C:/proj/app.py', old_string: 'a', new_string: 'b' })
  expect((await stop())?.includes('app.py')).toBe(true)
  // Only "late" is working: it is other work, so the review is over and its edit gets a review of its own.
  afterStart = [{ id: 'late', status: 'running' }]
  await $.tool.call({ tool: 'Edit', file_path: 'C:/proj/late.py', old_string: 'a', new_string: 'b', agentId: 'late' } as never)
  expect(await stop(true)).toBe(undefined)
  expect((await stop())?.includes('late.py')).toBe(true)
})

test('an agent started while the list is read keeps the review open until the next check', async ($, on) => {
  const out = { agents: [] as { id: string; status: Status }[] }
  let startDuringList = false
  on('tool.call', () => ({ result: {} }))
  on('classic.Stop', () => ({}))
  on('agent.spawn', () => ({ agentId: 'sub1', model: 'm' }))
  const edit = (file: string) => $.tool.call({ tool: 'Edit', file_path: file, old_string: 'a', new_string: 'b' })
  const stop = async (active = false) => (await $.classic.Stop({ stop_hook_active: active })).block
  on('agent.list', async () => {
    // A reviewer starts a helper while the list is being read: the list does not show it yet.
    if (startDuringList) {
      startDuringList = false
      await $.agent.spawn({ tool_use_id: 't', prompt: 'p', description: 'd', parentAgentId: 'r1' } as never)
    }
    return { value: out.agents.map(a => ({ description: 'x', type: 'x', ...a })) }
  })
  await edit('C:/proj/app.py')
  expect((await stop())?.includes('app.py')).toBe(true)
  // The reviewer has handed back and nothing else shows, but a start happened during the read: still open.
  out.agents = [{ id: 'r1', status: 'completed' }]
  startDuringList = true
  expect(await stop(true)).toBe(undefined)
  await edit('C:/proj/app.py') // a fix while the helper works: not sent back
  // Next check, the helper is listed and done, and nothing started meanwhile: the review is over.
  out.agents = [{ id: 'r1', status: 'completed' }, { id: 'sub1', status: 'completed' }]
  expect(await stop()).toBe(undefined)
  await edit('C:/proj/next.py')
  const next = await stop()
  expect(next?.includes('next.py')).toBe(true)
  expect(next?.includes('app.py')).toBe(false)
})

test('the second read as a review starts adds newcomers as other work, not finished ones', async ($, on) => {
  let lists = 0
  let later: { id: string; status: Status }[] = []
  on('tool.call', () => ({ result: {} }))
  on('classic.Stop', () => ({}))
  on('agent.list', () => {
    lists++
    const now = lists === 1 ? [{ id: 'bg', status: 'running' as Status }]
      : lists === 2 ? [{ id: 'bg', status: 'running' as Status }, { id: 'tm', status: 'idle' as Status }, { id: 'done', status: 'completed' as Status }]
      : later
    return { value: now.map(a => ({ description: 'x', type: 'x', ...a })) }
  })
  const stop = async (active = false) => (await $.classic.Stop({ stop_hook_active: active })).block
  const edit = (file: string, agentId?: string) => $.tool.call({ tool: 'Edit', file_path: file, old_string: 'a', new_string: 'b', ...(agentId ? { agentId } : {}) } as never)
  await edit('C:/proj/app.py')
  expect((await stop())?.includes('app.py')).toBe(true)
  // tm (idle at the second read) is other work. "done" had finished, so it is not: when it runs again
  // unseen it holds the review open.
  later = [{ id: 'bg', status: 'running' }, { id: 'tm', status: 'running' }, { id: 'done', status: 'running' }]
  await edit('C:/proj/tm.py', 'tm')
  expect(await stop(true)).toBe(undefined)
  later = [{ id: 'bg', status: 'running' }, { id: 'tm', status: 'running' }, { id: 'done', status: 'completed' }]
  expect(await stop()).toBe(undefined) // over: only other work is out
  const next = await stop()
  expect(next?.includes('tm.py')).toBe(true) // tm's edit was other work: a review of its own
  expect(next?.includes('app.py')).toBe(false)
})

test('a second read that fails as a review starts is said, and the first read still stands', async ($, on) => {
  const status: string[] = []
  on('ui.status', (_$, e) => {
    status.push(e.text ?? '')
    return { value: undefined }
  })
  let lists = 0
  on('tool.call', () => ({ result: {} }))
  on('classic.Stop', () => ({}))
  on('agent.list', () => {
    lists++
    return lists === 2 ? { deny: 'no list' } : { value: [{ id: 'bg', description: 'x', type: 'x', status: 'running' as Status }] }
  })
  const stop = async (active = false) => (await $.classic.Stop({ stop_hook_active: active })).block
  await $.tool.call({ tool: 'Edit', file_path: 'C:/proj/app.py', old_string: 'a', new_string: 'b' })
  expect((await stop())?.includes('app.py')).toBe(true) // the review still starts
  expect(status.some(s => s.includes("could not list the session's agents a second time as the review started (") && s.includes('ask for a review by hand'))).toBe(true)
  // bg, other work by the first read, does not hold it open: the review is over at the next check.
  expect(await stop(true)).toBe(undefined)
  await $.tool.call({ tool: 'Edit', file_path: 'C:/proj/next.py', old_string: 'a', new_string: 'b' })
  expect((await stop())?.includes('next.py')).toBe(true)
})

test('only a start that may be the review\'s keeps it open: not one by other work, a refused one or a workflow\'s', async ($, on) => {
  const out = { agents: [] as { id: string; status: Status }[] }
  let during: object | undefined
  on('tool.call', () => ({ result: {} }))
  on('classic.Stop', () => ({}))
  on('agent.spawn', (_$, e) => (e.prompt === 'refuse' ? { deny: 'not now' } : { agentId: 'h1', model: 'm' }) as never)
  on('agent.list', async () => {
    if (during) {
      const input = during
      during = undefined
      await $.agent.spawn({ tool_use_id: 't', prompt: 'p', description: 'd', ...input } as never).catch(() => undefined)
    }
    return { value: out.agents.map(a => ({ description: 'x', type: 'x', ...a })) }
  })
  const stop = async (active = false) => (await $.classic.Stop({ stop_hook_active: active })).block
  const edit = (file: string) => $.tool.call({ tool: 'Edit', file_path: file, old_string: 'a', new_string: 'b' })
  for (const input of [{ parentAgentId: 'bg' }, { prompt: 'refuse' }, { workflow: { runId: 'w', agentIndex: 0 } }]) {
    out.agents = [{ id: 'bg', status: 'running' }]
    await edit('C:/proj/app.py')
    expect((await stop())?.includes('app.py')).toBe(true)
    // Each of these starts during the read, and the review still ends at that check.
    during = input
    out.agents = [{ id: 'bg', status: 'running' }]
    expect(await stop(true)).toBe(undefined)
    await edit('C:/proj/next.py')
    expect([input, (await stop())?.includes('next.py')]).toEqual([input, true])
    expect(await stop(true)).toBe(undefined) // close that review too before the next round
    out.agents = []
    expect(await stop()).toBe(undefined)
  }
})

test('a refused start does not hide a real one in the same check', async ($, on) => {
  let startDuringList = false
  let listed: { id: string; status: Status }[] = []
  on('tool.call', () => ({ result: {} }))
  on('classic.Stop', () => ({}))
  on('agent.spawn', (_$, e) => (e.prompt === 'refuse' ? { deny: 'not now' } : { agentId: 'h1', model: 'm' }) as never)
  on('agent.list', async () => {
    if (startDuringList) {
      startDuringList = false
      await $.agent.spawn({ tool_use_id: 't', prompt: 'refuse', description: 'd' } as never).catch(() => undefined)
      await $.agent.spawn({ tool_use_id: 't', prompt: 'p', description: 'd', parentAgentId: 'r1' } as never)
    }
    return { value: listed.map(a => ({ description: 'x', type: 'x', ...a })) }
  })
  const stop = async (active = false) => (await $.classic.Stop({ stop_hook_active: active })).block
  await $.tool.call({ tool: 'Edit', file_path: 'C:/proj/app.py', old_string: 'a', new_string: 'b' })
  expect((await stop())?.includes('app.py')).toBe(true)
  startDuringList = true
  expect(await stop(true)).toBe(undefined) // the helper went through while the list was read: still open
  await $.tool.call({ tool: 'Edit', file_path: 'C:/proj/app.py', old_string: 'a', new_string: 'b' })
  listed = [{ id: 'h1', status: 'completed' }]
  expect(await stop()).toBe(undefined) // over now, and the fix made meanwhile is not sent back
  expect(await stop()).toBe(undefined)
})

test('a start still under way when the list is read keeps the review open', async ($, on) => {
  const out = { agents: [] as { id: string; status: Status }[] }
  let release: () => void = () => {}
  on('tool.call', () => ({ result: {} }))
  on('classic.Stop', () => ({}))
  // The start is entered before the check, and settles only after the list was read.
  on('agent.spawn', () => new Promise(done => { release = () => done({ agentId: 'h1', model: 'm' }) }) as never)
  on('agent.list', () => ({ value: out.agents.map(a => ({ description: 'x', type: 'x', ...a })) }))
  const stop = async (active = false) => (await $.classic.Stop({ stop_hook_active: active })).block
  await $.tool.call({ tool: 'Edit', file_path: 'C:/proj/app.py', old_string: 'a', new_string: 'b' })
  expect((await stop())?.includes('app.py')).toBe(true)
  const starting = $.agent.spawn({ tool_use_id: 't', prompt: 'p', description: 'd', parentAgentId: 'r1' } as never)
  for (let i = 0; i < 5; i++) await Promise.resolve() // let the start reach its hook beneath
  expect(await stop(true)).toBe(undefined) // nothing listed, but a start is under way: still open
  release()
  await starting
  await $.tool.call({ tool: 'Edit', file_path: 'C:/proj/app.py', old_string: 'a', new_string: 'b' })
  out.agents = [{ id: 'h1', status: 'completed' }]
  expect(await stop()).toBe(undefined) // now over, and the fix is not sent back
  expect(await stop()).toBe(undefined)
})

test('a start stuck for over two minutes no longer holds a review open', async ($, on) => {
  const clock = mock.clock(on, { now: 1_000_000 })
  const logged: string[] = []
  on('ui.log', (_$, e) => {
    logged.push(e.text)
    return { value: undefined }
  })
  on('tool.call', () => ({ result: {} }))
  on('classic.Stop', () => ({}))
  on('agent.list', () => ({ value: [] }))
  on('agent.spawn', () => new Promise(() => {}) as never) // a hook beneath that never answers
  const stop = async (active = false) => (await $.classic.Stop({ stop_hook_active: active })).block
  await $.tool.call({ tool: 'Edit', file_path: 'C:/proj/app.py', old_string: 'a', new_string: 'b' })
  expect((await stop())?.includes('app.py')).toBe(true)
  void $.agent.spawn({ tool_use_id: 't', prompt: 'p', description: 'd', parentAgentId: 'r1' } as never).catch(() => undefined)
  for (let i = 0; i < 5; i++) await Promise.resolve()
  expect(await stop(true)).toBe(undefined)
  // Just under two minutes: still under way, so the review stays open and a fix made now is not new work.
  await clock.advance(119_000)
  await $.tool.call({ tool: 'Edit', file_path: 'C:/proj/fix.py', old_string: 'a', new_string: 'b' })
  expect(await stop()).toBe(undefined)
  await clock.advance(2_000)
  expect(await stop()).toBe(undefined) // stuck: no longer counted, so the review is over now
  expect(await stop()).toBe(undefined) // and fix.py was a fix: not asked for
  await $.tool.call({ tool: 'Edit', file_path: 'C:/proj/next.py', old_string: 'a', new_string: 'b' })
  expect((await stop())?.includes('next.py')).toBe(true)
  expect(await stop(true)).toBe(undefined) // a check in the next review, with the same start still stuck
  expect(logged.filter(l => l.includes('under way for over two minutes no longer hold')).length).toBe(1) // said once
})

test('a review prompt still on its way survives a reload', async ($, on) => {
  seed(on, { reviewing: true, held: false, changed: {}, underReview: { 'C:/proj/app.py': 'Python' }, othersAtStart: [], othersChanged: {}, joined: [], promptPending: true })
  const { edit, stop } = cycle($, on)
  // The prompt was handed out before the reload; this stop is not its continuation: it never arrived.
  expect((await stop())?.includes('app.py')).toBe(true)
})

test('a new request right after a reload keeps a review whose prompt never arrived', async ($, on) => {
  seed(on, { reviewing: true, held: false, changed: {}, underReview: { 'C:/proj/app.py': 'Python' }, othersAtStart: [], othersChanged: {}, joined: [], promptPending: true })
  const { edit, stop } = cycle($, on)
  await $.prompt.submit({ text: 'new work', wait: false, origin: { kind: 'composer' } })
  await edit('C:/proj/other.py')
  const next = await stop()
  expect(next?.includes('other.py')).toBe(true)
  expect(next?.includes('app.py')).toBe(true)
})

test('a turn that ends without the review prompt puts its files back, before anything can drop them', async ($, on) => {
  const { edit, stop } = cycle($, on)
  on('turn.complete', () => ({ text: '' }))
  await edit('C:/proj/app.py')
  expect((await stop())?.includes('app.py')).toBe(true)
  // The block did not take: the turn ends with an answer. Then a turn started by something else gets a
  // message typed mid-turn: that is not proof the review prompt arrived, and app.py is still kept.
  await $.turn.complete({ reason: 'answer', answer: 'done', durationMs: 1, isAborted: false, turnId: 't1' })
  await $.prompt.submit({ text: 'and this', wait: true, origin: { kind: 'composer' }, turnId: 't2' } as never)
  await edit('C:/proj/other.py')
  const next = await stop()
  expect(next?.includes('app.py')).toBe(true)
  expect(next?.includes('other.py')).toBe(true)
})

test('a hook beneath that blocks while the review prompt is still on its way does not lose its files', async ($, on) => {
  const out = { agents: [] as { id: string; status: Status }[] }
  let beneathBlocks = false
  on('tool.call', () => ({ result: {} }))
  on('classic.Stop', () => (beneathBlocks ? { block: 'another hook wants more' } : {}))
  on('agent.list', () => ({ value: out.agents.map(a => ({ description: 'x', type: 'x', ...a })) }))
  const stop = async (active = false) => (await $.classic.Stop({ stop_hook_active: active })).block
  await $.tool.call({ tool: 'Edit', file_path: 'C:/proj/app.py', old_string: 'a', new_string: 'b' })
  expect((await stop())?.includes('app.py')).toBe(true)
  // The prompt is lost; the next stop is not its continuation, and a hook beneath blocks there.
  beneathBlocks = true
  expect(await stop()).toBe('another hook wants more')
  beneathBlocks = false
  // That block's continuation must not count as the review prompt arriving: app.py is asked for again.
  expect(await stop(true)).toBe(undefined)
  expect((await stop())?.includes('app.py')).toBe(true)
})

test('a joined agent messaging one of the review\'s own agents does not make it joined', async ($, on) => {
  seed(on, { reviewing: true, held: false, changed: {}, underReview: { 'C:/proj/app.py': 'Python' }, othersAtStart: [], othersChanged: {}, joined: ['bg'], promptPending: false, ownFolder: [] })
  const { out, stop } = cycle($, on)
  on('session.send', () => ({ isDelivered: true }))
  out.agents = [{ id: 'r1', status: 'running' }]
  await $.session.send({ to: 'r1', text: 'look here', origin: { kind: 'tool' }, agentId: 'bg' } as never)
  // r1, the review's own, adds a test file as a fix: it stays a fix.
  await $.tool.call({ tool: 'Edit', file_path: 'C:/proj/test_app.py', old_string: 'a', new_string: 'b', agentId: 'r1' } as never)
  out.agents = []
  expect(await stop(true)).toBe(undefined) // the review is over
  expect(await stop()).toBe(undefined) // and test_app.py was a fix: nothing to review
})

test('two spellings of one file compare equal', () => {
  const win = (p: string, folder?: string) => samePath(p, folder, 'windows-msys')
  expect(win('C:\\proj\\App.py')).toBe('c:/proj/App.py') // only the drive letter's case is folded
  expect(win('C:/proj/App.py') === win('C:/proj/app.py')).toBe(false) // a case-sensitive folder: two files
  expect(win('/c/proj/app.py')).toBe('c:/proj/app.py') // Git Bash
  expect(win('app.py', 'C:\\proj')).toBe('c:/proj/app.py') // relative, against the session's folder
  expect(win('./src/../app.py', 'C:/proj/')).toBe('c:/proj/app.py')
  expect(win('app.py')).toBe('app.py') // no folder known: left as it is (so it can only fail to match)
  expect(samePath('src/App.py', '/home/pat/proj', 'posix')).toBe('/home/pat/proj/src/App.py') // Linux keeps case
  expect(samePath('/c/x.py', undefined, 'posix')).toBe('/c/x.py') // and has no drive letters
  // `..` steps: one never cancels another, and nothing goes above the root.
  expect(win('a/../../b')).toBe('../b')
  expect(win('../../../a')).toBe('../../../a')
  expect(win('C:/../../b')).toBe('c:/b')
  expect(win('C:/x/../../proj/app.py')).toBe('c:/proj/app.py')
  expect(win('/c')).toBe('c:/') // a drive alone
  expect(win('app.py', '/')).toBe('/app.py') // a folder of `/` still joins
  expect(samePath('app.py', '/', 'posix')).toBe('/app.py')
  // Off Windows a `\` is part of a file name; from PowerShell, `/c/...` is a folder `c`, not drive C.
  expect(samePath('a\\b.py', '/home/pat', 'posix')).toBe('/home/pat/a\\b.py')
  expect(samePath('a\\b.py', '/home/pat', 'posix') === samePath('a/b.py', '/home/pat', 'posix')).toBe(false)
  expect(samePath('/c/proj/app.py', undefined, 'windows')).toBe('/c/proj/app.py')
  expect(samePath('C:\\proj\\App.py', undefined, 'windows')).toBe('c:/proj/App.py') // still Windows
  expect(samePath('app.py', '/c/proj', 'windows-msys')).toBe('/c/proj/app.py') // the session folder is native
  expect(keyOf('/c/proj/app.py', 'windows-msys')).toBe('C:/proj/app.py') // Git Bash on Windows: stored by drive
  expect(keyOf('/c/proj/app.py', 'windows')).toBe('/c/proj/app.py')
  expect(keyOf('/tmp/x.py', 'windows-msys')).toBe('/tmp/x.py')
  expect(keyOf('/c', 'windows-msys')).toBe('C:/')
})

test('how long a start has been under way is read on one clock only', () => {
  expect(underWayFor({ machine: 1000, engine: 5000 }, 125_000, 2000)).toBe(120_000) // both on the engine's
  expect(underWayFor({ machine: 1000 }, 125_000, 2000)).toBe(1000) // the start has no engine time: machine
  expect(underWayFor({ machine: 1000, engine: 5000 }, undefined, 2000)).toBe(1000) // no engine time now: machine
  // A clock that has stopped can't keep a stuck start from counting: the longer reading wins.
  expect(underWayFor({ machine: 0, engine: 5000 }, 5000, 200_000)).toBe(200_000)
})

test('a joined agent fixing a file under review through a relative shell path is a fix', async ($, on) => {
  mock.env(on, { USERPROFILE: 'C:/Users/pat' })
  on('session.cwd', () => ({ value: 'C:/proj' }))
  seed(on, { reviewing: true, held: false, changed: {}, underReview: { 'C:/proj/app.py': 'Python' }, othersAtStart: [], othersChanged: {}, joined: ['bg'], promptPending: false, ownFolder: [] })
  const { out, stop } = cycle($, on)
  await $.tool.call({ tool: 'Bash', command: 'sed -i s/a/b/ app.py', agentId: 'bg' } as never)
  await $.tool.call({ tool: 'Bash', command: 'sed -i s/a/b/ own.py', agentId: 'bg' } as never)
  out.agents = []
  expect(await stop(true)).toBe(undefined)
  const next = await stop()
  expect(next?.includes('own.py')).toBe(true) // its own work
  expect(next?.includes('app.py')).toBe(false) // its fix, though spelled another way
})

for (const [name, under, setup, command, agent] of [
  ['after a cd', 'C:/proj/app.py', false, 'cd sub && sed -i s/a/b/ app.py', 'bg'],
  ['from an agent with a folder of its own', 'C:/proj/app.py', true, 'sed -i s/a/b/ app.py', 'wt'],
  ['against a relative path under review', 'util.py', false, 'cd sub && sed -i s/a/b/ util.py', 'bg'],
] as const) {
  test(`a relative path is never taken for a file under review when its folder is not sure: ${name}`, async ($, on) => {
    mock.env(on, { USERPROFILE: 'C:/Users/pat' })
    on('session.cwd', () => ({ value: 'C:/proj' }))
    seed(on, { reviewing: true, held: false, changed: {}, underReview: { [under]: 'Python' }, othersAtStart: [], othersChanged: {}, joined: ['bg', 'wt'], promptPending: false, ownFolder: [] })
    const { out, stop } = cycle($, on)
    on('agent.spawn', () => ({ agentId: 'wt', model: 'm' }))
    // wt is started again in a folder of its own (a worktree).
    if (setup) await $.agent.spawn({ tool_use_id: 't', prompt: 'p', description: 'd', resume: { agentId: 'wt' }, cwd: 'C:/wt' } as never)
    await $.tool.call({ tool: 'Bash', command, agentId: agent } as never)
    out.agents = []
    expect(await stop(true)).toBe(undefined)
    // The file it wrote gets a review of its own: it was not taken for a fix to the file under review.
    const file = under.endsWith('util.py') ? 'util.py' : 'app.py'
    expect((await stop())?.includes(file)).toBe(true)
  })
}

for (const [name, ownFolder, steps] of [
  ['after a cd in an earlier command (a shell may keep the folder)', [], async ($: Engine) => {
    await $.tool.call({ tool: 'Bash', command: 'cd sub', agentId: 'bg' } as never)
  }],
  ['from an agent in a folder of its own, after a reload', ['bg'], async () => {}],
  ['from a helper an agent in a folder of its own started (it runs in that folder)', ['wt'], async ($: Engine) => {
    await $.agent.spawn({ tool_use_id: 't', prompt: 'p', description: 'd', parentAgentId: 'wt' } as never)
  }],
] as const) {
  test(`a relative path is never taken for a file under review: ${name}`, async ($, on) => {
    mock.env(on, { USERPROFILE: 'C:/Users/pat' })
    on('session.cwd', () => ({ value: 'C:/proj' }))
    seed(on, { reviewing: true, held: false, changed: {}, underReview: { 'C:/proj/app.py': 'Python' }, othersAtStart: [], othersChanged: {}, joined: ['bg', 'wt'], promptPending: false, ownFolder: [...ownFolder] })
    const { out, stop } = cycle($, on)
    on('agent.spawn', () => ({ agentId: 'bg', model: 'm' }))
    await steps($)
    await $.tool.call({ tool: 'Bash', command: 'sed -i s/a/b/ app.py', agentId: 'bg' } as never)
    out.agents = []
    expect(await stop(true)).toBe(undefined)
    expect((await stop())?.includes('app.py')).toBe(true) // not taken for a fix: reviewed
  })
}

test('agents in a folder of their own saved before a reload are kept when the first read fails', async ($, on) => {
  mock.env(on, { USERPROFILE: 'C:/Users/pat' })
  on('session.cwd', () => ({ value: 'C:/proj' }))
  let failing = true
  on('state.get', ($, e, next) => {
    if (e.plugin !== 'review-guard' || e.key !== 'cycle') return next(e)
    if (failing) return { deny: 'not yet' }
    return { value: { value: { reviewing: false, held: false, changed: {}, underReview: {}, othersAtStart: [], othersChanged: {}, joined: [], promptPending: false, ownFolder: ['wt'] } as never, version: 0 } }
  })
  const { out, edit, stop } = cycle($, on)
  let next = 'h'
  on('agent.spawn', () => ({ agentId: next, model: 'm' }))
  // While the saved state can't be read, this start changes the cycle (it marks h); then the read works.
  await $.agent.spawn({ tool_use_id: 't', prompt: 'p', description: 'd', cwd: 'C:/wt' } as never)
  failing = false
  out.agents = [{ id: 'wt', status: 'idle' }] // other work as the review starts: started again, it joins
  await edit('C:/proj/app.py')
  expect((await stop())?.includes('app.py')).toBe(true) // a review starts
  // wt, saved before the reload as in a folder of its own, is resumed (no cwd given) and joins the review.
  next = 'wt'
  await $.agent.spawn({ tool_use_id: 't2', prompt: 'p', description: 'd', resume: { agentId: 'wt' } } as never)
  await $.tool.call({ tool: 'Bash', command: 'sed -i s/a/b/ app.py', agentId: 'wt' } as never)
  out.agents = []
  expect(await stop(true)).toBe(undefined)
  expect((await stop())?.includes('app.py')).toBe(true) // not taken for a fix: reviewed
})

test('until the saved state is read back, no relative path is read against the session folder', async ($, on) => {
  mock.env(on, { USERPROFILE: 'C:/Users/pat' })
  on('session.cwd', () => ({ value: 'C:/proj' }))
  on('session.send', () => ({ isDelivered: true }))
  on('state.get', ($, e, next) => (e.plugin === 'review-guard' && e.key === 'cycle' ? { deny: 'not yet' } : next(e)))
  const { out, edit, stop } = cycle($, on)
  // A review starts in this load, with bg already at work; the main conversation then messages bg: it joins.
  out.agents = [{ id: 'bg', status: 'running' }]
  await edit('C:/proj/app.py')
  expect((await stop())?.includes('app.py')).toBe(true)
  await $.session.send({ to: 'bg', text: 'fix the findings', origin: { kind: 'tool' } } as never)
  await $.tool.call({ tool: 'Bash', command: 'sed -i s/a/b/ app.py', agentId: 'bg' } as never)
  out.agents = []
  expect(await stop(true)).toBe(undefined)
  expect((await stop())?.includes('app.py')).toBe(true) // the saved list may hold bg: not taken for a fix
})

test('a helper started before the saved state is read back counts as in a folder of its own', async ($, on) => {
  mock.env(on, { USERPROFILE: 'C:/Users/pat' })
  on('session.cwd', () => ({ value: 'C:/proj' }))
  on('session.send', () => ({ isDelivered: true }))
  let failing = true
  on('state.get', ($, e, next) => (e.plugin === 'review-guard' && e.key === 'cycle' && failing ? { deny: 'not yet' } : next(e)))
  const { out, edit, stop } = cycle($, on)
  on('agent.spawn', () => ({ agentId: 'h', model: 'm' }))
  out.agents = [{ id: 'bg', status: 'running' }]
  await edit('C:/proj/app.py')
  expect((await stop())?.includes('app.py')).toBe(true)
  await $.session.send({ to: 'bg', text: 'fix the findings', origin: { kind: 'tool' } } as never)
  await $.agent.spawn({ tool_use_id: 't', prompt: 'p', description: 'd', parentAgentId: 'bg' } as never)
  failing = false
  await $.tool.call({ tool: 'Bash', command: 'sed -i s/a/b/ app.py', agentId: 'h' } as never)
  out.agents = []
  expect(await stop(true)).toBe(undefined)
  expect((await stop())?.includes('app.py')).toBe(true)
})

test('an agent in a folder of its own stays so after a review ends, into the next one', async ($, on) => {
  mock.env(on, { USERPROFILE: 'C:/Users/pat' })
  on('session.cwd', () => ({ value: 'C:/proj' }))
  const { out, edit, stop } = cycle($, on)
  on('agent.spawn', () => ({ agentId: 'wt', model: 'm' }))
  await edit('C:/proj/app.py')
  expect((await stop())?.includes('app.py')).toBe(true) // review 1
  await $.agent.spawn({ tool_use_id: 't', prompt: 'p', description: 'd', cwd: 'C:/wt' } as never)
  out.agents = []
  expect(await stop(true)).toBe(undefined) // review 1 ends
  out.agents = [{ id: 'wt', status: 'idle' }] // other work as review 2 starts: started again, it joins
  await edit('C:/proj/app.py')
  expect((await stop())?.includes('app.py')).toBe(true) // review 2
  await $.agent.spawn({ tool_use_id: 't2', prompt: 'p', description: 'd', resume: { agentId: 'wt' } } as never) // no cwd now
  await $.tool.call({ tool: 'Bash', command: 'sed -i s/a/b/ app.py', agentId: 'wt' } as never)
  out.agents = []
  expect(await stop(true)).toBe(undefined)
  expect((await stop())?.includes('app.py')).toBe(true)
})

test('on Windows started from Git Bash, OS decides: Windows rules hold', async ($, on) => {
  mock.env(on, { OS: 'Windows_NT', HOME: '/c/Users/pat' })
  seed(on, { reviewing: true, held: false, changed: {}, underReview: { 'C:/proj/App.py': 'Python' }, othersAtStart: [], othersChanged: {}, joined: ['bg'], promptPending: false, ownFolder: [] })
  const { out, stop } = cycle($, on)
  await $.tool.call({ tool: 'Edit', file_path: 'c:\\proj\\App.py', old_string: 'a', new_string: 'b', agentId: 'bg' } as never)
  out.agents = []
  expect(await stop(true)).toBe(undefined)
  expect(await stop()).toBe(undefined) // a fix: the same file on Windows
})

test('a mark made before the saved state is read back does not end a saved review', async ($, on) => {
  mock.env(on, { USERPROFILE: 'C:/Users/pat' })
  const logged: string[] = []
  on('ui.log', (_$, e) => {
    logged.push(e.text ?? '')
    return { value: undefined }
  })
  let failing = true
  const bad = ['x', 7, null]
  on('state.get', ($, e, next) => {
    if (e.plugin !== 'review-guard' || e.key !== 'cycle') return next(e)
    if (failing) return { deny: 'not yet' }
    return { value: { value: { reviewing: true, held: false, changed: {}, underReview: { 'C:/proj/app.py': 'Python' }, othersAtStart: [], othersChanged: {}, joined: [], promptPending: false, ownFolder: bad } as never, version: 0 } }
  })
  const { out, stop } = cycle($, on)
  on('agent.spawn', () => ({ agentId: 'wt', model: 'm' }))
  await $.agent.spawn({ tool_use_id: 't', prompt: 'p', description: 'd', cwd: 'C:/wt' } as never) // marked, unread
  failing = false
  out.agents = []
  expect(await stop(true)).toBe(undefined) // the saved review stands, and ends here with its fixes
  expect(await stop()).toBe(undefined) // nothing put back in the queue
  expect(logged.some(l => l.includes('was damaged'))).toBe(true) // a non-text entry in the saved list
})

test('an environment variable that cannot be read is logged once, by name', async ($, on) => {
  const logged: string[] = []
  on('ui.log', (_$, e) => {
    logged.push(e.text ?? '')
    return { value: undefined }
  })
  on('env.get', (_$, e) => (e.name === 'OS' ? { deny: 'blocked' } : { value: e.name === 'USERPROFILE' ? 'C:/Users/pat' : undefined }))
  const { edit } = cycle($, on)
  await edit('C:/proj/a.py')
  await edit('C:/proj/b.py')
  expect(logged.filter(l => l.includes('could not read OS')).length).toBe(1)
})

test('an agent marked before the saved state is read back stays marked once it is', async ($, on) => {
  mock.env(on, { USERPROFILE: 'C:/Users/pat' })
  on('session.cwd', () => ({ value: 'C:/proj' }))
  let failing = true
  on('state.get', ($, e, next) => {
    if (e.plugin !== 'review-guard' || e.key !== 'cycle') return next(e)
    if (failing) return { deny: 'not yet' }
    return { value: { value: { reviewing: true, held: false, changed: {}, underReview: { 'C:/proj/app.py': 'Python' }, othersAtStart: [], othersChanged: {}, joined: ['wt'], promptPending: false, ownFolder: [] } as never, version: 0 } }
  })
  const { out, stop } = cycle($, on)
  on('agent.spawn', () => ({ agentId: 'wt', model: 'm' }))
  await $.agent.spawn({ tool_use_id: 't', prompt: 'p', description: 'd', resume: { agentId: 'wt' }, cwd: 'C:/wt' } as never) // marked, unread
  failing = false
  await $.tool.call({ tool: 'Bash', command: 'sed -i s/a/b/ app.py', agentId: 'wt' } as never)
  out.agents = []
  expect(await stop(true)).toBe(undefined)
  expect((await stop())?.includes('app.py')).toBe(true) // wt is still in a folder of its own: reviewed
})

test('the home folder is USERPROFILE first on Windows and HOME first elsewhere', () => {
  expect(homeFrom({ userProfile: 'C:\\Users\\pat', home: '/c/Users/pat', windows: true })).toBe('C:/Users/pat')
  expect(homeFrom({ userProfile: 'C:\\Users\\pat', home: '/home/pat', windows: false })).toBe('/home/pat') // WSL with USERPROFILE passed in
  expect(homeFrom({ home: '/home/pat', windows: true })).toBe('/home/pat')
  expect(homeFrom({ userProfile: 'C:\\Users\\pat', home: ' ', windows: false })).toBe('C:/Users/pat')
  expect(homeFrom({ userProfile: ' ', home: '/c/Users/pat/', windows: true })).toBe('/c/Users/pat') // blank: the other
  expect(homeFrom({ windows: true })).toBe(undefined)
})

test('each tool reads paths its own way', () => {
  expect(rulesFor('bash', true)).toEqual({ spelling: 'windows-msys', posixTmp: true })
  expect(rulesFor('edit', true)).toEqual({ spelling: 'windows-msys', posixTmp: false }) // /tmp is \tmp on the current drive
  expect(rulesFor('powershell', true)).toEqual({ spelling: 'windows', posixTmp: false })
  for (const w of ['bash', 'edit', 'powershell'] as const) expect(rulesFor(w, false)).toEqual({ spelling: 'posix', posixTmp: true })
})

test('a file changed under two spellings is queued once', async ($, on) => {
  mock.env(on, { USERPROFILE: 'C:/Users/pat' })
  const { stop } = cycle($, on)
  await $.tool.call({ tool: 'Edit', file_path: 'C:\\proj\\App.py', old_string: 'a', new_string: 'b' } as never)
  await $.tool.call({ tool: 'Bash', command: 'sed -i s/a/b/ /c/proj/App.py' } as never)
  await $.tool.call({ tool: 'Edit', file_path: 'C:/proj/other.py', old_string: 'a', new_string: 'b' } as never)
  const prompt = (await stop()) ?? ''
  expect(prompt).toContain('2 file(s)')
  expect(prompt).toContain('C:\\proj\\App.py') // the first spelling is kept
  expect(prompt).not.toContain('C:/proj/App.py')
})

test('a saved state that was damaged is said', async ($, on) => {
  const status: string[] = []
  on('ui.status', (_$, e) => {
    status.push(e.text ?? '')
    return { value: undefined }
  })
  seed(on, { reviewing: true, changed: { 'C:/proj/a.py': 7 }, othersAtStart: 'bg' })
  const { edit } = cycle($, on)
  await edit('C:/proj/b.py')
  expect(status.some(l => l.includes('saved review state was damaged'))).toBe(true)
  expect(savedDamaged(undefined)).toBe(false)
  expect(savedDamaged('x')).toBe(true)
  expect(savedDamaged({ reviewing: false, changed: {}, joined: [] })).toBe(false)
})

test('a saved list at its cap makes no agent relative path be read against the session folder', async ($, on) => {
  mock.env(on, { USERPROFILE: 'C:/Users/pat' })
  on('session.cwd', () => ({ value: 'C:/proj' }))
  seed(on, { reviewing: true, held: false, changed: {}, underReview: { 'C:/proj/app.py': 'Python' }, othersAtStart: [], othersChanged: {}, joined: ['bg'], promptPending: false, ownFolder: Array.from({ length: 500 }, (_, i) => `a${i}`) })
  const { out, stop } = cycle($, on)
  await $.tool.call({ tool: 'Bash', command: 'sed -i s/a/b/ app.py', agentId: 'bg' } as never) // bg may have been cut off the list
  out.agents = []
  expect(await stop(true)).toBe(undefined)
  expect((await stop())?.includes('app.py')).toBe(true) // not taken for a fix: reviewed
})

test('a mark made before the read is saved once the read works', async ($, on) => {
  mock.env(on, { USERPROFILE: 'C:/Users/pat' })
  const saved: unknown[] = []
  on('state.set', ($, e, next) => {
    saved.push((e as { value?: unknown }).value)
    return next(e)
  })
  let failing = true
  on('state.get', ($, e, next) => (e.plugin === 'review-guard' && e.key === 'cycle' && failing ? { deny: 'not yet' } : next(e)))
  on('agent.spawn', () => ({ agentId: 'wt', model: 'm' }))
  cycle($, on)
  await $.agent.spawn({ tool_use_id: 't', prompt: 'p', description: 'd', cwd: 'C:/wt' } as never)
  expect(saved.length).toBe(0) // nothing saved before the read
  failing = false
  // Reads the state back; the hook has nothing of its own to save (no folder of its own, no review), so
  // the save seen next is the earlier mark's.
  await $.agent.spawn({ tool_use_id: 't2', prompt: 'p', description: 'd' } as never)
  expect(ownFolderFrom(saved.at(-1))).toEqual(['wt'])
})

test('a failed save of the folder list goes to the log, not over a guard notice', async ($, on) => {
  mock.env(on, { USERPROFILE: 'C:/Users/pat' })
  const status: string[] = []
  const logged: string[] = []
  on('ui.status', (_$, e) => {
    status.push(e.text ?? '')
    return { value: undefined }
  })
  on('ui.log', (_$, e) => {
    logged.push(e.text ?? '')
    return { value: undefined }
  })
  on('state.set', () => ({ deny: 'disk full' }))
  on('agent.spawn', () => ({ agentId: 'wt', model: 'm' }))
  await $.agent.spawn({ tool_use_id: 't', prompt: 'p', description: 'd', cwd: 'C:/wt' } as never)
  expect(logged.some(l => l.includes("this agent's relative paths may be read"))).toBe(true)
  expect(status.some(l => l.includes('could not save'))).toBe(false)
})

test('two spellings through a .. step are not merged into one entry', async ($, on) => {
  const { stop } = cycle($, on)
  on('env.get', (_$, e) => ({ value: e.name === 'HOME' ? '/home/pat' : undefined }))
  await $.tool.call({ tool: 'Edit', file_path: '/proj/link/../b.py', old_string: 'a', new_string: 'b' } as never)
  await $.tool.call({ tool: 'Edit', file_path: '/proj/b.py', old_string: 'a', new_string: 'b' } as never)
  await $.tool.call({ tool: 'Edit', file_path: '/proj/c.py', old_string: 'a', new_string: 'b' } as never)
  await $.tool.call({ tool: 'Edit', file_path: '/proj/link/../c.py', old_string: 'a', new_string: 'b' } as never) // the other order
  expect((await stop()) ?? '').toContain('4 file(s)') // through a link they may be two files
})

test('the status file goes under USERPROFILE on Windows and HOME on Linux or WSL', async ($, on) => {
  const written: string[] = []
  let env: Record<string, string> = {}
  on('session.id', () => ({ value: 's-1' }))
  on('session.cwd', () => ({ value: 'C:/proj' }))
  on('env.get', (_$, e) => ({ value: env[e.name] }))
  on('fs.write', (_$, e) => {
    // The engine puts its own drive or folder before a path it reads as relative here: drop that part.
    // (Its own folder may start with /home/ too, so the match is on the status folder itself.)
    const path = e.path.replace(/\\/g, '/')
    written.push(/[A-Za-z]:\/Users\/pat\/\.claude\/.*|\/home\/pat\/\.claude\/.*/.exec(path)?.[0] ?? path)
    return { value: undefined }
  })
  const { edit } = cycle($, on)
  env = { USERPROFILE: 'C:\\Users\\pat', HOME: '/home/pat' } // WSL with USERPROFILE passed in
  await edit('/home/pat/proj/a.py')
  expect(written.at(-1)?.startsWith('/home/pat/.claude/review-guard/status/')).toBe(true)
  env = { OS: 'Windows_NT', USERPROFILE: 'C:\\Users\\pat', HOME: '/c/Users/pat' } // Windows started from Git Bash
  await edit('C:/proj/b.py')
  expect(written.at(-1)?.startsWith('C:/Users/pat/.claude/review-guard/status/')).toBe(true)
})

test('a PowerShell /c/... and a Git Bash /c/... are two files, listed apart', async ($, on) => {
  mock.env(on, { USERPROFILE: 'C:/Users/pat' })
  const { stop } = cycle($, on)
  await $.tool.call({ tool: 'PowerShell', command: 'Set-Content -Path /c/proj/app.py -Value x' } as never) // a folder c
  await $.tool.call({ tool: 'Bash', command: 'sed -i s/a/b/ /c/proj/app.py' } as never) // drive C
  const prompt = (await stop()) ?? ''
  expect(prompt).toContain('2 file(s)')
  expect(prompt).toContain('/c/proj/app.py')
  expect(prompt).toContain('C:/proj/app.py')
})

test('two relative spellings are never merged: their folders may differ', async ($, on) => {
  mock.env(on, { USERPROFILE: 'C:/Users/pat' })
  const { stop } = cycle($, on)
  await $.tool.call({ tool: 'Bash', command: 'sed -i s/a/b/ App.py' } as never)
  await $.tool.call({ tool: 'Bash', command: 'sed -i s/a/b/ app.py' } as never)
  expect((await stop()) ?? '').toContain('2 file(s)')
})

test('SystemRoot alone tells Windows to the hooks: slashes and the drive letter are ignored', async ($, on) => {
  mock.env(on, { SystemRoot: 'C:\\Windows' })
  seed(on, { reviewing: true, held: false, changed: {}, underReview: { 'C:/proj/App.py': 'Python' }, othersAtStart: [], othersChanged: {}, joined: ['bg'], promptPending: false, ownFolder: [] })
  const { out, stop } = cycle($, on)
  await $.tool.call({ tool: 'Edit', file_path: 'c:\\proj\\App.py', old_string: 'a', new_string: 'b', agentId: 'bg' } as never)
  out.agents = []
  expect(await stop(true)).toBe(undefined)
  expect(await stop()).toBe(undefined) // a fix to the file under review
})

test('a backslash \c\... from an edit tool is a folder c, not drive C', async ($, on) => {
  mock.env(on, { USERPROFILE: 'C:/Users/pat' })
  seed(on, { reviewing: true, held: false, changed: {}, underReview: { 'C:/proj/app.py': 'Python' }, othersAtStart: [], othersChanged: {}, joined: ['bg'], promptPending: false, ownFolder: [] })
  const { out, stop } = cycle($, on)
  await $.tool.call({ tool: 'Edit', file_path: String.raw`\c\proj\app.py`, old_string: 'a', new_string: 'b', agentId: 'bg' } as never)
  out.agents = []
  expect(await stop(true)).toBe(undefined)
  expect((await stop())?.includes(String.raw`\c\proj\app.py`)).toBe(true) // its own work, reviewed
  expect(inScratch(String.raw`\c\Users\pat\AppData\Local\Temp\claude\x.py`, ['C:/Users/pat/AppData/Local/Temp'], rulesFor('edit', true))).toBe(false)
})

test('a cut while joining the lists after a reload is doubted, and the doubt is saved', async ($, on) => {
  mock.env(on, { USERPROFILE: 'C:/Users/pat' })
  on('session.cwd', () => ({ value: 'C:/proj' }))
  const saved: unknown[] = []
  on('state.set', ($, e, next) => {
    saved.push((e as { value?: unknown }).value)
    return next(e)
  })
  let failing = true
  on('state.get', ($, e, next) => {
    if (e.plugin !== 'review-guard' || e.key !== 'cycle') return next(e)
    if (failing) return { deny: 'not yet' }
    return { value: { value: { reviewing: true, held: false, changed: {}, underReview: { 'C:/proj/app.py': 'Python' }, othersAtStart: [], othersChanged: {}, joined: ['bg'], promptPending: false, ownFolder: Array.from({ length: 499 }, (_, i) => `a${i}`) } as never, version: 0 } }
  })
  const { out, stop } = cycle($, on)
  let next = 0
  on('agent.spawn', () => ({ agentId: `m${next++}`, model: 'm' }))
  for (let i = 0; i < 2; i++) await $.agent.spawn({ tool_use_id: `t${i}`, prompt: 'p', description: 'd', cwd: 'C:/wt' } as never) // marked, unread
  failing = false
  await $.tool.call({ tool: 'Bash', command: 'sed -i s/a/b/ app.py', agentId: 'bg' } as never) // 501 joined: one cut
  out.agents = []
  expect(await stop(true)).toBe(undefined)
  expect((await stop())?.includes('app.py')).toBe(true) // doubted: not taken for a fix
  expect((saved.at(-1) as { ownFolderDoubtful?: unknown } | undefined)?.ownFolderDoubtful).toBe(true)
})

test('a damaged saved state after a failed read is not called safe', async ($, on) => {
  const status: string[] = []
  on('ui.status', (_$, e) => {
    status.push(e.text ?? '')
    return { value: undefined }
  })
  let failing = true
  on('state.get', ($, e, next) => {
    if (e.plugin !== 'review-guard' || e.key !== 'cycle') return next(e)
    return failing ? { deny: 'not yet' } : { value: { value: 'not a state' as never, version: 0 } }
  })
  const { stop } = cycle($, on)
  await stop() // the read fails: said
  failing = false
  await stop() // read, but damaged
  expect(status.some(l => l.includes('nothing waiting for review was lost'))).toBe(false)
  expect(status.at(-1)).toContain('saved review state was damaged')
})

test('a damaged saved list keeps every relative path from being read against the session folder', async ($, on) => {
  mock.env(on, { USERPROFILE: 'C:/Users/pat' })
  on('session.cwd', () => ({ value: 'C:/proj' }))
  seed(on, { reviewing: true, held: false, changed: {}, underReview: { 'C:/proj/app.py': 'Python' }, othersAtStart: [], othersChanged: {}, joined: ['bg'], promptPending: false, ownFolder: 'wt' })
  const { out, stop } = cycle($, on)
  await $.tool.call({ tool: 'Bash', command: 'sed -i s/a/b/ app.py', agentId: 'bg' } as never)
  out.agents = []
  expect(await stop(true)).toBe(undefined)
  expect((await stop())?.includes('app.py')).toBe(true)
})

test('a review cut short lists each file once, whatever spelling its fix used', async ($, on) => {
  mock.env(on, { USERPROFILE: 'C:/Users/pat' })
  const { edit, stop } = cycle($, on)
  on('turn.complete', () => ({ text: '' }))
  await edit('C:/proj/App.py')
  expect((await stop())?.includes('App.py')).toBe(true) // the review starts
  await $.tool.call({ tool: 'Bash', command: 'sed -i s/a/b/ /c/proj/App.py' }) // its fix, another spelling
  await $.turn.complete({ reason: 'aborted', answer: '', durationMs: 1, isAborted: true, turnId: 't1' })
  await edit('C:/proj/next.py')
  const prompt = (await stop()) ?? ''
  expect(prompt).toContain('2 file(s)')
  expect(prompt).toContain('C:/proj/App.py')
})

test('a review that ends lists each file other work changed once', async ($, on) => {
  mock.env(on, { USERPROFILE: 'C:/Users/pat' })
  seed(on, { reviewing: true, held: false, changed: {}, underReview: { 'C:/proj/x.py': 'Python' }, othersAtStart: [], othersChanged: { 'C:/proj/B.py': 'Python', 'c:\\proj\\B.py': 'Python' }, joined: [], promptPending: false, ownFolder: [] })
  const { edit, out, stop } = cycle($, on)
  await edit('C:/proj/x.py') // a fix (and how paths read here is known from now on)
  out.agents = []
  expect(await stop(true)).toBe(undefined) // the review ends
  const prompt = (await stop()) ?? ''
  expect(prompt).toContain('1 file(s)')
  expect(prompt).toContain('C:/proj/B.py')
})

test('a saved copy joined at load lists each file once', async ($, on) => {
  mock.env(on, { USERPROFILE: 'C:/Users/pat' })
  seed(on, { reviewing: false, held: false, changed: { 'c:\\proj\\A.py': 'Python' }, underReview: { 'C:/proj/A.py': 'Python' }, othersAtStart: [], othersChanged: {}, joined: [], promptPending: false, ownFolder: [] })
  const { edit, stop } = cycle($, on)
  await edit('C:/proj/z.py')
  const prompt = (await stop()) ?? ''
  expect(prompt).toContain('2 file(s)')
  expect(prompt).toContain('C:/proj/A.py') // the first list's spelling
})

test('on Windows two names that differ only in case stay two files: a folder can be case-sensitive', async ($, on) => {
  mock.env(on, { USERPROFILE: 'C:/Users/pat' })
  seed(on, { reviewing: true, held: false, changed: {}, underReview: { 'C:/proj/A.py': 'Python' }, othersAtStart: [], othersChanged: { 'C:/proj/b.py': 'Python', 'C:/proj/B.py': 'Python' }, joined: ['bg'], promptPending: false, ownFolder: [] })
  const { out, edit, stop } = cycle($, on)
  await edit('C:/proj/x.py')
  await $.tool.call({ tool: 'Edit', file_path: 'C:/proj/a.py', old_string: 'a', new_string: 'b', agentId: 'bg' } as never) // not A.py's fix
  out.agents = []
  expect(await stop(true)).toBe(undefined)
  const prompt = (await stop()) ?? ''
  expect(prompt).toContain('C:/proj/a.py') // its own work, reviewed
  expect(prompt).toContain('C:/proj/b.py')
  expect(prompt).toContain('C:/proj/B.py')
})

test('a known language is never replaced by other code when lists are joined', async ($, on) => {
  mock.env(on, { USERPROFILE: 'C:/Users/pat' })
  seed(on, { reviewing: false, changed: { [String.raw`c:\proj\n.ipynb`]: 'other code' }, underReview: { 'C:/proj/n.ipynb': 'Python' } })
  const { stop } = cycle($, on)
  const prompt = (await stop()) ?? ''
  expect(prompt).toMatch(/code changed in 1 file\(s\)/)
  expect(prompt).toContain('- Python: C:/proj/n.ipynb')
  expect(prompt).not.toContain('other code')
})

test('a file named __proto__ is kept when lists are joined', async ($, on) => {
  // Written as an own property, which this runtime does for a plain assignment too; Node's would not.
  seed(on, { reviewing: false, changed: { ['__proto__']: 'Python' }, underReview: { 'u.py': 'Python' } })
  const { stop } = cycle($, on)
  expect((await stop()) ?? '').toContain('__proto__')
})

test('a saved copy joined first thing after a reload lists each file once', async ($, on) => {
  mock.env(on, { USERPROFILE: 'C:/Users/pat' })
  // No edit first: the read itself must know how paths read here.
  seed(on, { reviewing: false, changed: { 'C:/proj/B.py': 'Python', [String.raw`c:\proj\B.py`]: 'Python' } })
  const { stop } = cycle($, on)
  expect((await stop()) ?? '').toMatch(/code changed in 1 file\(s\)/)
})

test('a review cut short keeps its fixes to other files and what other work changed', async ($, on) => {
  mock.env(on, { USERPROFILE: 'C:/Users/pat' })
  const { out, edit, stop } = cycle($, on)
  on('turn.complete', () => ({ text: '' }))
  out.agents = [{ id: 'bg', status: 'running' }] // other work, there as the review starts
  await edit('C:/proj/app.py')
  expect((await stop())?.includes('app.py')).toBe(true)
  await edit('C:/proj/other.py') // the review's own fix to another file
  await $.tool.call({ tool: 'Edit', file_path: 'C:/proj/o.py', old_string: 'a', new_string: 'b', agentId: 'bg' } as never)
  await $.turn.complete({ reason: 'aborted', answer: '', durationMs: 1, isAborted: true, turnId: 't1' })
  await edit('C:/proj/next.py')
  out.agents = []
  const prompt = (await stop()) ?? ''
  for (const f of ['app.py', 'other.py', 'o.py', 'next.py']) expect(prompt).toContain(`C:/proj/${f}`)
})

test('a late read keeps other work saved before the reload, each file once', async ($, on) => {
  mock.env(on, { USERPROFILE: 'C:/Users/pat' })
  let failing = true
  on('state.get', ($, e, next) => {
    if (e.plugin !== 'review-guard' || e.key !== 'cycle') return next(e)
    if (failing) return { deny: 'not yet' }
    return { value: { value: { reviewing: true, held: false, changed: {}, underReview: { 'C:/proj/A.py': 'Python' }, othersAtStart: ['bg'], othersChanged: { 'C:/proj/o.py': 'Python' }, joined: [], promptPending: false, ownFolder: [] } as never, version: 0 } }
  })
  const { edit, stop } = cycle($, on)
  on('turn.complete', () => ({ text: '' }))
  await edit(String.raw`c:\proj\A.py`) // changed before the saved copy could be read
  failing = false
  await $.turn.complete({ reason: 'aborted', answer: '', durationMs: 1, isAborted: true, turnId: 't1' })
  await edit('C:/proj/next.py')
  const prompt = (await stop()) ?? ''
  expect(prompt).toContain('C:/proj/o.py')
  expect(prompt).toMatch(/code changed in 3 file\(s\)/) // A.py once, o.py, next.py
})

test('a stored key can not be read with a tool spelling: the compiler refuses it', () => {
  const k = keyOf('/c/x.py', 'windows')
  // @ts-expect-error a FileKey is read only through keyPath (the validator reports this line if the guard breaks)
  expect(samePath(k, undefined, 'windows-msys')).toBe('c:/x.py')
})

test('a joined agent editing through a .. step is never taken for a fix: through a link it may be another file', async ($, on) => {
  on('env.get', (_$, e) => ({ value: e.name === 'HOME' ? '/home/pat' : undefined }))
  seed(on, { reviewing: true, held: false, changed: {}, underReview: { '/proj/b.py': 'Python' }, othersAtStart: [], othersChanged: {}, joined: ['bg'], promptPending: false, ownFolder: [] })
  const { out, stop } = cycle($, on)
  await $.tool.call({ tool: 'Edit', file_path: '/proj/link/../b.py', old_string: 'a', new_string: 'b', agentId: 'bg' } as never)
  out.agents = []
  expect(await stop(true)).toBe(undefined)
  expect((await stop()) ?? '').toContain('/proj/link/../b.py') // its own work, reviewed
})

test('a . step is always the same file: listed once', async ($, on) => {
  on('env.get', (_$, e) => ({ value: e.name === 'HOME' ? '/home/pat' : undefined }))
  const { stop } = cycle($, on)
  await $.tool.call({ tool: 'Edit', file_path: '/proj/./b.py', old_string: 'a', new_string: 'b' } as never)
  await $.tool.call({ tool: 'Edit', file_path: '/proj/b.py', old_string: 'a', new_string: 'b' } as never)
  expect((await stop()) ?? '').toMatch(/code changed in 1 file\(s\)/)
})

test('a saved list cut to its cap is logged', async ($, on) => {
  mock.env(on, { USERPROFILE: 'C:/Users/pat' })
  const logged: string[] = []
  on('ui.log', (_$, e) => {
    logged.push(e.text ?? '')
    return { value: undefined }
  })
  seed(on, { reviewing: false, ownFolder: Array.from({ length: 501 }, (_, i) => `a${i}`) })
  const { edit } = cycle($, on)
  await edit('C:/proj/a.py') // only reads the saved state back
  expect(logged.filter(l => l.includes('no longer remembered')).length).toBe(1)
})

test('an agent resumed from one in a folder of its own, or started before the saved list is read, is in one too', async ($, on) => {
  mock.env(on, { USERPROFILE: 'C:/Users/pat' })
  on('session.cwd', () => ({ value: 'C:/proj' }))
  seed(on, { reviewing: true, held: false, changed: {}, underReview: { 'C:/proj/app.py': 'Python' }, othersAtStart: [], othersChanged: {}, joined: ['wt', 'new'], promptPending: false, ownFolder: ['wt'] })
  const { out, stop } = cycle($, on)
  on('agent.spawn', () => ({ agentId: 'new', model: 'm' }))
  await $.agent.spawn({ tool_use_id: 't', prompt: 'p', description: 'd', resume: { agentId: 'wt' } } as never) // goes on as `new`
  await $.tool.call({ tool: 'Bash', command: 'sed -i s/a/b/ app.py', agentId: 'new' } as never)
  out.agents = []
  expect(await stop(true)).toBe(undefined)
  expect((await stop())?.includes('app.py')).toBe(true)
})

test('the list of agents in a folder of their own keeps each once, the last marked, and at most 500', () => {
  expect(ownFolderOf(['a', 'b', 'a'])).toEqual(['b', 'a'])
  for (const bad of [null, undefined, 'x', { ownFolder: 'x' }, { ownFolder: [1, null] }]) expect(ownFolderFrom(bad)).toEqual([])
  const many = Array.from({ length: 600 }, (_, i) => `a${i}`)
  expect(ownFolderOf([...many, 'a0'])).toEqual([...many.slice(101), 'a0'])
})

test('a command that runs in another folder by an option counts as changing folder', () => {
  for (const c of ['git -C sub add x.py', 'make -C sub', 'Start-Process python -WorkingDirectory sub', '[Environment]::CurrentDirectory = "sub"', 'npm --prefix sub run x', 'cd sub', 'Set-Location sub',
    'env --chdir=sub sed -i s/a/b/ app.py', 'sudo -D sub sed -i x app.py', 'make --directory=sub', 'pnpm --dir sub build', 'make -Csub', 'git -Csub add x.py',
    'python -c "import os; os.chdir(\'sub\')"', 'node -e "process.chdir(\'sub\')"']) {
    expect(CHANGES_FOLDER.test(c)).toBe(true)
  }
  for (const c of ['sed -i s/a/b/ app.py', 'python -c "print(1)"', 'git commit -m "x"', 'abcd x',
    'Copy-Item -Path a.py -Destination b.py', 'powershell -Command "Get-Date"', 'Remove-Item x.py -Confirm:$false']) {
    expect(CHANGES_FOLDER.test(c)).toBe(false)
  }
})

test('the agents in a folder of their own are saved, also outside a review', async ($, on) => {
  mock.env(on, { USERPROFILE: 'C:/Users/pat' })
  const saved: unknown[] = []
  on('state.set', ($, e, next) => {
    saved.push((e as { value?: unknown }).value)
    return next(e)
  })
  on('agent.spawn', () => ({ agentId: 'wt', model: 'm' }))
  await $.agent.spawn({ tool_use_id: 't', prompt: 'p', description: 'd', cwd: 'C:/wt' } as never)
  expect(ownFolderFrom(saved.at(-1))).toEqual(['wt'])
  expect(cycleFrom(saved.at(-1)).reviewing).toBe(false)
  expect(ownFolderFrom({ reviewing: false, ownFolder: ['wt', 'wt', 3] })).toEqual(['wt'])
  expect(ownFolderFrom({ ownFolder: Array.from({ length: 600 }, (_, i) => `a${i}`) })).toEqual(Array.from({ length: 500 }, (_, i) => `a${i + 100}`))
})

test('on Windows a path with no drive is never taken for a file under review', async ($, on) => {
  mock.env(on, { USERPROFILE: 'C:/Users/pat' })
  // `/proj/app.py` from Git Bash is Git's own folder; `\proj\app.py` in PowerShell is the current drive's.
  seed(on, { reviewing: true, held: false, changed: {}, underReview: { '/proj/app.py': 'Python' }, othersAtStart: [], othersChanged: {}, joined: ['bg'], promptPending: false, ownFolder: [] })
  const { out, stop } = cycle($, on)
  await $.tool.call({ tool: 'PowerShell', command: 'Set-Content -Path \\proj\\app.py -Value x', agentId: 'bg' } as never)
  out.agents = []
  expect(await stop(true)).toBe(undefined)
  expect((await stop())?.includes('\\proj\\app.py')).toBe(true) // its own work, reviewed
})

test('Windows is told by OS, else by HOME read against USERPROFILE and SystemRoot', () => {
  expect(isWindows({ os: 'Windows_NT' })).toBe(true)
  expect(isWindows({ os: 'Windows_NT', userProfile: 'C:\\Users\\pat', home: '/c/Users/pat' })).toBe(true)
  expect(isWindows({ userProfile: 'C:/Users/pat' })).toBe(true)
  expect(isWindows({ userProfile: 'C:\\Users\\pat', home: 'C:\\Users\\pat' })).toBe(true)
  expect(isWindows({ userProfile: 'C:\\Users\\pat', home: '/home/pat' })).toBe(false) // WSL or Linux with it passed in
  expect(isWindows({ userProfile: '/mnt/c/Users/pat' })).toBe(false)
  expect(isWindows({ userProfile: 'C:\\Users\\pat', home: '/c/Users/pat' })).toBe(true) // started from Git Bash
  expect(isWindows({ userProfile: 'C:\\Users\\pat', home: '/c/Users/pat/home' })).toBe(true) // Git Bash with its own HOME
  expect(isWindows({ userProfile: 'C:\\Users\\pat', home: ' /c/Users/pat ' })).toBe(true)
  expect(isWindows({ userProfile: 'C:\\Users\\pat\\', home: '/C/users/PAT/' })).toBe(true) // any case, trailing slash
  expect(isWindows({ userProfile: 'C:\\Users\\pat', home: '/u/pat' })).toBe(false) // drive U is not USERPROFILE's
  expect(isWindows({ systemRoot: 'C:\\Windows', userProfile: 'C:\\Users\\pat', home: '/home/pat' })).toBe(false) // WSL with both passed in
  expect(isWindows({ systemRoot: 'C:\\Windows' })).toBe(true)
  expect(isWindows({ systemRoot: 'C:\\Windows', home: '/c/Users/pat' })).toBe(true)
  expect(isWindows({ systemRoot: '/mnt/c/Windows', home: '/home/pat' })).toBe(false)
  expect(isWindows({ userProfile: 'D:\\Users\\pat', systemRoot: 'C:\\Windows', home: '/c/Users/pat' })).toBe(true) // either drive
  expect(isWindows({ os: 'Linux', userProfile: 'C:\\Users\\pat', home: '/home/pat' })).toBe(false)
  expect(isWindows({ home: '/home/pat' })).toBe(false)
  expect(isWindows({ userProfile: 'C:foo' })).toBe(false) // a drive-relative name is no profile folder
})

test('on Linux a USERPROFILE passed in does not make case count for nothing', async ($, on) => {
  mock.env(on, { USERPROFILE: 'C:\\Users\\pat', HOME: '/home/pat' })
  seed(on, { reviewing: true, held: false, changed: {}, underReview: { '/home/pat/proj/App.py': 'Python' }, othersAtStart: [], othersChanged: {}, joined: ['bg'], promptPending: false, ownFolder: [] })
  const { out, stop } = cycle($, on)
  await $.tool.call({ tool: 'Edit', file_path: '/home/pat/proj/app.py', old_string: 'a', new_string: 'b', agentId: 'bg' } as never)
  await $.tool.call({ tool: 'Edit', file_path: '/home/pat/proj/App.py', old_string: 'a', new_string: 'b', agentId: 'bg' } as never)
  out.agents = []
  expect(await stop(true)).toBe(undefined)
  const next = await stop()
  expect(next?.includes('/home/pat/proj/app.py')).toBe(true) // another file there: reviewed
  expect(next?.includes('/home/pat/proj/App.py')).toBe(false) // the file under review itself: a fix
})

test('a session folder that cannot be read is logged once, until a read works again, and its relative paths are not matched', async ($, on) => {
  mock.env(on, { USERPROFILE: 'C:/Users/pat' })
  const said: string[] = []
  on('ui.log', (_$, e) => {
    said.push(e.text ?? '')
    return { value: undefined }
  })
  let folder: unknown = { deny: 'no folder' }
  on('session.cwd', () => (typeof folder === 'object' && folder !== null ? folder as never : { value: folder as never }))
  seed(on, { reviewing: true, held: false, changed: {}, underReview: { 'C:/proj/app.py': 'Python' }, othersAtStart: [], othersChanged: {}, joined: ['bg'], promptPending: false, ownFolder: [] })
  const { out, stop } = cycle($, on)
  const sed = () => $.tool.call({ tool: 'Bash', command: 'sed -i s/a/b/ app.py', agentId: 'bg' } as never)
  const lines = () => said.filter(l => l.includes("could not read the session's folder"))
  await sed()
  await sed()
  expect(lines().length).toBe(1) // said once
  expect(lines()[0]).toContain('no folder') // with the reason
  expect(lines()[0]).toContain('relative paths are not matched')
  folder = 42 // not a folder: said as such, and never thrown on
  await sed()
  expect(lines().length).toBe(1) // still the same failure
  folder = 'C:/proj' // a read works again, and that is logged too
  await sed()
  expect(said.some(l => l.includes("read the session's folder again"))).toBe(true)
  folder = '  ' // and fails again: said again
  await sed()
  expect(lines().length).toBe(2)
  expect(lines()[1]).toContain('empty')
  out.agents = []
  expect(await stop(true)).toBe(undefined)
  expect((await stop())?.includes('app.py')).toBe(true) // a write with no sure folder is not taken for a fix: reviewed
})

test('a folder that is not text is logged with its kind and its paths are still reviewed', async ($, on) => {
  mock.env(on, { USERPROFILE: 'C:/Users/pat' })
  const said: string[] = []
  on('ui.log', (_$, e) => {
    said.push(e.text ?? '')
    return { value: undefined }
  })
  on('session.cwd', () => ({ value: {} as never }))
  seed(on, { reviewing: true, held: false, changed: {}, underReview: { 'C:/proj/app.py': 'Python' }, othersAtStart: [], othersChanged: {}, joined: ['bg'], promptPending: false, ownFolder: [] })
  const { out, stop } = cycle($, on)
  await $.tool.call({ tool: 'Bash', command: 'sed -i s/a/b/ app.py', agentId: 'bg' } as never)
  expect(said.some(l => l.includes("could not read the session's folder (the folder given was object)"))).toBe(true)
  out.agents = []
  expect(await stop(true)).toBe(undefined)
  expect((await stop())?.includes('app.py')).toBe(true)
})

test('a PowerShell path spelled /c/... is not taken for drive C', async ($, on) => {
  mock.env(on, { USERPROFILE: 'C:/Users/pat' })
  seed(on, { reviewing: true, held: false, changed: {}, underReview: { 'C:/proj/app.py': 'Python' }, othersAtStart: [], othersChanged: {}, joined: ['bg'], promptPending: false, ownFolder: [] })
  const { out, stop } = cycle($, on)
  await $.tool.call({ tool: 'PowerShell', command: 'Set-Content -Path /c/proj/app.py -Value x', agentId: 'bg' } as never)
  out.agents = []
  expect(await stop(true)).toBe(undefined)
  expect((await stop())?.includes('/c/proj/app.py')).toBe(true) // its own work, reviewed
})

test('a Git Bash path spelled /c/... is drive C: a fix to a file under review', async ($, on) => {
  mock.env(on, { USERPROFILE: 'C:/Users/pat' })
  seed(on, { reviewing: true, held: false, changed: {}, underReview: { 'C:/proj/app.py': 'Python' }, othersAtStart: [], othersChanged: {}, joined: ['bg'], promptPending: false, ownFolder: [] })
  const { out, stop } = cycle($, on)
  await $.tool.call({ tool: 'Bash', command: 'sed -i s/a/b/ /c/proj/app.py', agentId: 'bg' } as never)
  await $.tool.call({ tool: 'Bash', command: 'sed -i s/a/b/ /c/proj/other.py', agentId: 'bg' } as never)
  out.agents = []
  expect(await stop(true)).toBe(undefined)
  const next = await stop()
  expect(next?.includes('app.py')).toBe(false) // its fix
  expect(next?.includes('C:/proj/other.py')).toBe(true) // its own work, stored by its drive
})

test('a key from PowerShell spelled /c/... is a folder c, so a change to drive C is not its fix', async ($, on) => {
  mock.env(on, { USERPROFILE: 'C:/Users/pat' })
  seed(on, { reviewing: true, held: false, changed: {}, underReview: { '/c/proj/app.py': 'Python' }, othersAtStart: [], othersChanged: {}, joined: ['bg'], promptPending: false, ownFolder: [] })
  const { out, stop } = cycle($, on)
  await $.tool.call({ tool: 'Bash', command: 'sed -i s/a/b/ /c/proj/app.py', agentId: 'bg' } as never) // C:\proj\app.py
  out.agents = []
  expect(await stop(true)).toBe(undefined)
  expect((await stop())?.includes('C:/proj/app.py')).toBe(true) // another file: reviewed
})

test('the edit tools on Windows read /c/... as drive C, as the Write tool does', async ($, on) => {
  mock.env(on, { USERPROFILE: 'C:/Users/pat' })
  seed(on, { reviewing: true, held: false, changed: {}, underReview: { 'C:/proj/app.py': 'Python' }, othersAtStart: [], othersChanged: {}, joined: ['bg'], promptPending: false, ownFolder: [] })
  const { out, stop } = cycle($, on)
  await $.tool.call({ tool: 'Edit', file_path: '/c/proj/app.py', old_string: 'a', new_string: 'b', agentId: 'bg' } as never)
  await $.tool.call({ tool: 'Edit', file_path: '/c/proj/other.py', old_string: 'a', new_string: 'b', agentId: 'bg' } as never)
  out.agents = []
  expect(await stop(true)).toBe(undefined)
  const next = await stop()
  expect(next?.includes('app.py')).toBe(false) // a fix to the file under review
  expect(next?.includes('C:/proj/other.py')).toBe(true) // its own work, stored by its drive
})

test('off Windows a \\ is part of a file name, so a\\b.py is not a/b.py', async ($, on) => {
  on('session.cwd', () => ({ value: '/home/pat/proj' }))
  seed(on, { reviewing: true, held: false, changed: {}, underReview: { '/home/pat/proj/a/b.py': 'Python' }, othersAtStart: [], othersChanged: {}, joined: ['bg'], promptPending: false, ownFolder: [] })
  const { out, stop } = cycle($, on)
  await $.tool.call({ tool: 'Edit', file_path: '/home/pat/proj/a\\b.py', old_string: 'a', new_string: 'b', agentId: 'bg' } as never)
  out.agents = []
  expect(await stop(true)).toBe(undefined)
  expect((await stop())?.includes('a\\b.py')).toBe(true) // another file: reviewed
})

test('a helper started by an agent that joined the review joins it too', async ($, on) => {
  mock.env(on, { USERPROFILE: 'C:/Users/pat' }) // Windows: `C:/...` is a full path only there
  seed(on, { reviewing: true, held: false, changed: {}, underReview: { 'C:/proj/app.py': 'Python' }, othersAtStart: [], othersChanged: {}, joined: ['bg'], promptPending: false, ownFolder: [] })
  const { out, stop } = cycle($, on)
  on('agent.spawn', () => ({ agentId: 'h1', model: 'm' }))
  await $.agent.spawn({ tool_use_id: 't', prompt: 'p', description: 'd', parentAgentId: 'bg' } as never)
  for (const [who, file] of [['bg', 'own.py'], ['h1', 'helper.py'], ['h1', 'app.py']]) {
    await $.tool.call({ tool: 'Edit', file_path: `C:/proj/${file}`, old_string: 'a', new_string: 'b', agentId: who } as never)
  }
  out.agents = []
  expect(await stop(true)).toBe(undefined) // the review is over
  const next = await stop()
  for (const f of ['own.py', 'helper.py']) expect(next?.includes(f)).toBe(true) // their own work
  expect(next?.includes('app.py')).toBe(false) // the helper's fix
})

test('a review prompt that never reached Claude puts its files back, also when a new request comes first', async ($, on) => {
  const status: string[] = []
  on('ui.status', (_$, e) => {
    status.push(e.text ?? '')
    return { value: undefined }
  })
  const { edit, stop } = cycle($, on)
  await edit('C:/proj/app.py')
  expect((await stop())?.includes('app.py')).toBe(true)
  // The next end of a turn is not the prompt's continuation: it never arrived. Said, and asked for again.
  expect((await stop())?.includes('app.py')).toBe(true)
  expect(status.some(s => s.includes('the review prompt did not reach Claude'))).toBe(true)
  // Again lost, and this time a new request comes before any stop: its files are kept, not dropped.
  await $.prompt.submit({ text: 'something else', wait: false, origin: { kind: 'composer' } })
  await edit('C:/proj/other.py')
  const next = await stop()
  expect(next?.includes('app.py')).toBe(true)
  expect(next?.includes('other.py')).toBe(true)
  // Delivered this time: its continuation ends with stop_hook_active, and a new request then drops its fixes.
  expect(await stop(true)).toBe(undefined)
  await $.prompt.submit({ text: 'and now this', wait: false, origin: { kind: 'composer' } })
  await edit('C:/proj/last.py')
  const last = await stop()
  expect(last?.includes('last.py')).toBe(true)
  expect(last?.includes('app.py')).toBe(false)
})

test('who is other work after an agent is started or messaged', () => {
  expect(afterHandOn(['a', 'b'], undefined, 'a')).toEqual(['b']) // the main loop hands a work: the review's
  expect(afterHandOn(['a', 'b'], 'r1', 'b')).toEqual(['a']) // so does one of the review's agents
  expect(afterHandOn(['a', 'b'], 'a', 'c')).toEqual(['a', 'b', 'c']) // other work's helper is other work
  expect(afterHandOn(['a', 'b'], 'a', 'b')).toEqual(['a', 'b']) // other work messaging other work
  expect(afterHandOn([], undefined, 'x')).toEqual([])
  const listed = agentsListed([{ id: 'a', status: 'idle' }, { id: 'b', status: 'completed' }, { id: 'c', status: 'running' }, { id: 'd', status: 'killed' }])
  // Only finished agents leave; one the list does not show (a workflow's agent) stays other work.
  expect(stillOthers(['a', 'b', 'c', 'd', 'gone'], listed)).toEqual(['a', 'c', 'gone'])
  // A message's recipient by id, by name, by teammate address or bare name, with a listing's [ref].
  const agents = [{ id: 'a1', name: 'scout' }, { id: 'a2', teammateId: 'fixer@team' }, { id: 'a3', name: 'scout' }, null, { id: 4, name: 'x' }]
  expect(recipient('a1', agents)).toBe('a1')
  expect(recipient('scout', agents)).toBe('a3') // two carry the name: the newest is the one reached
  expect(recipient('fixer', agents)).toBe('a2')
  expect(recipient('fixer@team', agents)).toBe('a2')
  expect(recipient('fixer [ref1]', agents)).toBe('a2')
  for (const to of ['main', 'x', '', 5, undefined]) expect([to, recipient(to, agents)]).toEqual([to, undefined])
  expect(recipient('scout', 'not a list')).toBe(undefined)
})

test('which agents are working, finished, and holding a review open', () => {
  expect(() => agentsListed(null)).toThrow('the agent list was not a list')
  expect(agentsListed([null, 5, { id: 'a', status: 'running' }, { id: 'b', status: 'idle' }, { id: 'c', status: 'failed' }, { status: 'waiting' }, { id: 7 }])).toEqual([
    { id: 'a', out: true, finished: false }, { id: 'b', out: false, finished: false }, { id: 'c', out: false, finished: true },
    { id: '', out: true, finished: false }, { id: '', out: true, finished: false },
  ])
  const at = (id: string, out = true) => ({ id, out, finished: false })
  expect(reviewHeldOpen([], ['x'])).toBe(false)
  expect(reviewHeldOpen([at('x')], ['x'])).toBe(false)
  expect(reviewHeldOpen([at('y')], ['x'])).toBe(true)
  expect(reviewHeldOpen([at('y', false)], ['x'])).toBe(false) // idle: not working now
  expect(reviewHeldOpen([at('')], [''])).toBe(true)
})

test('a reload of the mod in the middle of a review does not send its fixes for another review', async ($, on) => {
  // The copy of the mod before the reload left this in the session's state; this copy starts fresh.
  seed(on, { reviewing: true, held: false, changed: {}, underReview: { 'C:/proj/app.py': 'Python' } })
  const { out, edit, stop } = cycle($, on)
  out.agents = [{ status: 'running' }]
  // The review's fix, made after the reload while a reviewer is still out.
  await edit('C:/proj/app.py')
  expect(await stop()).toBe(undefined)
  // The last report, and the review ends: still no second review of its fixes.
  out.agents = [{ status: 'completed' }]
  await edit('C:/proj/app.py')
  expect(await stop()).toBe(undefined)
  // New work after it is reviewed as usual.
  await edit('C:/proj/next.py')
  const prompt = await stop()
  expect(prompt?.includes('next.py')).toBe(true)
  expect(prompt?.includes('app.py')).toBe(false)
})

for (const [name, bad] of [['null', null], ['a list', []], ['text', 'x'], ['wrong types', { reviewing: 'yes', changed: ['x'], underReview: { 'a.py': 5 } }]] as const) {
  test(`a stored value that is ${name} is read as empty, and reviews carry on`, async ($, on) => {
    seed(on, bad)
    const { edit, stop } = cycle($, on)
    await edit('C:/proj/a.py')
    expect((await stop())?.includes('a.py')).toBe(true)
  })
}

test('a save that fails loses no edit and says so', async ($, on) => {
  const status: string[] = []
  on('state.set', () => ({ deny: 'refused' }))
  on('ui.status', (_$, e) => {
    status.push(e.text ?? '')
    return { value: undefined }
  })
  const { edit, stop } = cycle($, on)
  await edit('C:/proj/a.py')
  await edit('C:/proj/b.py')
  const prompt = await stop()
  expect(prompt?.includes('a.py')).toBe(true)
  expect(prompt?.includes('b.py')).toBe(true)
  expect(status.some(s => s.includes('could not save'))).toBe(true)
})

test('agents that cannot be listed end the review out loud', async ($, on) => {
  const status: string[] = []
  let listWorks = true
  on('ui.status', (_$, e) => {
    status.push(e.text ?? '')
    return { value: undefined }
  })
  on('tool.call', () => ({ result: {} }))
  on('classic.Stop', () => ({}))
  let lists = 0
  let broken: 'deny' | 'not a list' = 'deny'
  on('agent.list', () => {
    lists++
    // Nothing is at work as the review starts (both reads); then its reviewer is out.
    if (listWorks) return { value: lists <= 2 ? [] : [{ id: 'a0', description: 'reviewer', type: 'review-guard:code-reviewer', status: 'running' as Status }] }
    return broken === 'deny' ? { deny: 'no list' } : { value: null as never }
  })
  const edit = (file: string) => $.tool.call({ tool: 'Edit', file_path: file, old_string: 'a', new_string: 'b' })
  const stop = async (active = false) => (await $.classic.Stop({ stop_hook_active: active })).block
  await edit('C:/proj/app.py')
  expect((await stop())?.includes('app.py')).toBe(true)
  expect(lists).toBe(2) // read twice as the review starts, to know what other work is going on
  expect(await stop(true)).toBe(undefined) // a reviewer is still out: the review stays open
  expect(status.some(s => s.includes("could not list the session's agents"))).toBe(false)
  listWorks = false
  expect(await stop(true)).toBe(undefined)
  expect(status.some(s => s.includes("could not list the session's agents") && s.includes('the review counts as over'))).toBe(true)
  // The review is over, so the next change gets a review of its own, without the closed review's files.
  await edit('C:/proj/next.py')
  const next = await stop()
  expect(next?.includes('next.py')).toBe(true)
  expect(next?.includes('app.py')).toBe(false)
  // A list that comes back as something other than a list ends the review the same way, out loud.
  status.length = 0
  broken = 'not a list'
  expect(await stop(true)).toBe(undefined)
  expect(status.some(s => s.includes("could not list the session's agents (the agent list was not a list)"))).toBe(true)
  await edit('C:/proj/last.py')
  expect((await stop())?.includes('last.py')).toBe(true)
})

test('a failure beneath at the end of a turn is not blamed on review-guard, and the files wait', async ($, on) => {
  const status: string[] = []
  let broken = true
  on('ui.status', (_$, e) => {
    status.push(e.text ?? '')
    return { value: undefined }
  })
  on('tool.call', () => ({ result: {} }))
  on('agent.list', () => ({ value: [] }))
  on('classic.Stop', () => {
    if (broken) throw new Error('boom beneath')
    return {}
  })
  await $.tool.call({ tool: 'Edit', file_path: 'C:/proj/app.py', old_string: 'a', new_string: 'b' })
  // The failure is passed on as the turn would have ended; it is not review-guard's, so it says nothing.
  await $.classic.Stop({ stop_hook_active: false }).catch(() => undefined)
  expect(status.some(s => s.includes('end-of-turn check failed'))).toBe(false)
  broken = false
  expect((await $.classic.Stop({ stop_hook_active: false })).block?.includes('app.py')).toBe(true)
})

test("a failure's reason is one short line, from an Error, the engine's HookFailure, or anything", () => {
  expect(whyOf(new Error('one\n  two'))).toBe('one two')
  expect(whyOf({ kind: 'throw', message: 'boom', budget: 1000 })).toBe('boom')
  expect(whyOf({ kind: 'timeout', budget: 1000 })).toBe('timeout') // a timeout carries no message
  expect(whyOf(undefined)).toBe('no message')
  expect(whyOf(new Error(''))).toBe('no message')
  expect(whyOf('x'.repeat(300))).toBe('x'.repeat(200))
  expect(whyOf('😀'.repeat(300))).toBe('😀'.repeat(200)) // cut by characters: no half of one is left
  const circular: Record<string, unknown> = {}
  circular.self = circular
  expect(whyOf(circular)).toBe('a failure that could not be put into words') // never a second failure
  expect(whyOf({ other: 1 })).toBe('{"other":1}')
  // review-guard's own end-of-turn failure, as the status line shows it.
  const status: string[] = []
  reviewFailed({ ui: { status: (t: string) => { status.push(t) } } } as never, new Error('scan blew up'))
  expect(status).toEqual(['review-guard: its end-of-turn check failed (scan blew up); any changed files stay queued for the next turn that ends'])
})

test('a status line that fails to show goes to the log instead, and never fails twice', () => {
  const logged: string[] = []
  let onRejected: unknown
  const engine = (show: (text: string) => unknown, log = (text: string) => { logged.push(text) }) => ({ ui: { status: show, log } }) as never
  // It throws at once: the line goes to the log.
  say(engine(() => { throw new Error('no status line') }), 'first')
  expect(logged).toEqual(['first'])
  // It hands back a promise: a rejection is handled, and that line goes to the log too.
  say(engine(() => ({ then: (_ok: unknown, bad: unknown) => { onRejected = bad } })), 'second')
  expect(typeof onRejected).toBe('function')
  ;(onRejected as () => void)()
  expect(logged).toEqual(['first', 'second'])
  // Both fail: nothing is thrown.
  expect(() => say(engine(() => { throw new Error('a') }, () => { throw new Error('b') }), 'third')).not.toThrow()
})

test('a review state that cannot be read back is said once, retried, and never written over', async ($, on) => {
  const status: string[] = []
  let reads = 0
  let sets = 0
  let storeUp = false
  on('ui.status', (_$, e) => {
    status.push(e.text ?? '')
    return { value: undefined }
  })
  on('state.get', ($$, e, next) => {
    reads++
    return storeUp ? next(e) : { deny: 'store offline' }
  })
  on('state.set', ($$, e, next) => {
    sets++
    return next(e)
  })
  const { edit, stop } = cycle($, on)
  await edit('C:/proj/a.py') // read fails: remembered in memory, nothing saved over the stored copy
  await edit('C:/proj/b.py') // read fails again: said only once
  expect(reads >= 2).toBe(true) // tried again
  expect(sets).toBe(0)
  expect(status.filter(s => s.includes('could not read back its review state')).length).toBe(1)
  expect(status.some(s => s.includes('store offline'))).toBe(true)
  expect(status.some(s => s.includes('it tries again at the next step'))).toBe(true)
  // The next try works: both edits are still there, saving starts, and the recovery is said.
  storeUp = true
  const prompt = await stop()
  expect(prompt?.includes('a.py')).toBe(true)
  expect(prompt?.includes('b.py')).toBe(true)
  expect(sets > 0).toBe(true)
  expect(status.some(s => s.includes('read back its review state after all'))).toBe(true)
})

test('a stored review read back late is joined to what this load did meanwhile, never undoing it', async ($, on) => {
  let storeUp = false
  // The copy a load before this one left: a review running over old.py, and queued.py waiting.
  const stored = { reviewing: true, held: true, changed: { 'C:/proj/queued.py': 'Python' }, underReview: { 'C:/proj/old.py': 'Python' } }
  on('state.get', ($$, e, next) => (storeUp ? { value: { value: stored as never, version: 1 } } : { deny: 'store offline' }))
  const { edit, stop } = cycle($, on)
  // While the copy can't be read, the user asks for something new and it is edited.
  await $.prompt.submit({ text: 'new request', wait: false, origin: { kind: 'composer' } })
  await edit('C:/proj/new.py')
  storeUp = true
  // What this load decided stands (no review running, no hold), and every stored file is queued again.
  const prompt = await stop()
  for (const f of ['new.py', 'queued.py', 'old.py']) expect(prompt?.includes(f)).toBe(true)
})

test('a review held after an interrupt says so on the status line, even if that line fails', async ($, on) => {
  const status: string[] = []
  let statusWorks = true
  on('ui.status', (_$, e) => {
    if (!statusWorks) throw new Error('no status line')
    status.push(e.text ?? '')
    return { value: undefined }
  })
  on('ui.log', () => ({ value: undefined }))
  const { edit, stop } = cycle($, on)
  on('turn.complete', () => ({ text: '' }))
  await edit('C:/proj/half.py')
  await $.turn.complete({ reason: 'aborted', answer: '', durationMs: 1, isAborted: true, turnId: 't1' })
  await edit('C:/proj/half.py')
  await $.turn.complete({ reason: 'aborted', answer: '', durationMs: 1, isAborted: true, turnId: 't2' })
  expect(await stop()).toBe(undefined)
  expect(status.some(s => s.includes('review of 1 changed file(s) held after your interrupt'))).toBe(true)
  statusWorks = false
  expect(await stop()).toBe(undefined) // the turn still ends normally
  // (The kit skips a status hook that throws, so the log fallback is checked in the say() test.)
})

test('edits that finish at the same moment are all remembered', async ($, on) => {
  const { edit, stop } = cycle($, on)
  await Promise.all(['a.py', 'b.py', 'c.py', 'd.py'].map(f => edit(`C:/proj/${f}`)))
  const prompt = await stop()
  for (const f of ['a.py', 'b.py', 'c.py', 'd.py']) expect(prompt?.includes(f)).toBe(true)
})

test('a new request in the middle of a review gets its own review', async ($, on) => {
  const { out, edit, stop } = cycle($, on)
  await edit('C:/proj/app.py')
  expect((await stop())?.includes('app.py')).toBe(true)
  out.agents = [{ status: 'running' }]
  expect(await stop(true)).toBe(undefined) // the review prompt arrived and its turn ended
  await $.prompt.submit({ text: 'also change the other file', wait: false, origin: { kind: 'composer' } })
  await edit('C:/proj/other.py')
  const next = await stop()
  expect(next?.includes('other.py')).toBe(true)
  expect(next?.includes('app.py')).toBe(false) // reviewed already: not again
})

test('a request typed while the review prompt\'s turn still runs shows the prompt arrived', async ($, on) => {
  const { out, edit, stop } = cycle($, on)
  await edit('C:/proj/app.py')
  expect((await stop())?.includes('app.py')).toBe(true)
  out.agents = [{ status: 'running' }]
  // Typed mid-turn (the turn that carries the review prompt): the review was delivered, so it is dropped.
  await $.prompt.submit({ text: 'also this', wait: true, origin: { kind: 'composer' }, turnId: 't1' } as never)
  await edit('C:/proj/other.py')
  const next = await stop()
  expect(next?.includes('other.py')).toBe(true)
  expect(next?.includes('app.py')).toBe(false)
})

test('an interrupted turn asks for no review until work on code picks up again', async ($, on) => {
  const { edit, stop } = cycle($, on)
  on('turn.complete', () => ({ text: '' }))
  const interrupt = () => $.turn.complete({ reason: 'aborted', answer: '', durationMs: 1, isAborted: true, turnId: 't1' })
  await edit('C:/proj/half.py')
  await interrupt()
  // The user says something, Claude answers without touching code: still no review.
  await $.prompt.submit({ text: 'wait', wait: false, origin: { kind: 'composer' } })
  expect(await stop()).toBe(undefined)
  expect(await stop()).toBe(undefined)
  // Work resumes: the review comes at the end of that turn and covers the earlier file too.
  await edit('C:/proj/rest.py')
  const prompt = await stop()
  expect(prompt?.includes('half.py')).toBe(true)
  expect(prompt?.includes('rest.py')).toBe(true)
  // A subagent that is stopped does not hold anything.
  expect(await stop(true)).toBe(undefined) // the review above ends
  await edit('C:/proj/more.py')
  await $.turn.complete({ reason: 'aborted', answer: '', durationMs: 1, isAborted: true, turnId: 't2', agentId: 'a1' })
  expect((await stop())?.includes('more.py')).toBe(true)
})

test('a review that is interrupted keeps its files for later', async ($, on) => {
  const { edit, stop } = cycle($, on)
  on('turn.complete', () => ({ text: '' }))
  await edit('C:/proj/app.py')
  expect((await stop())?.includes('app.py')).toBe(true)
  await $.turn.complete({ reason: 'aborted', answer: '', durationMs: 1, isAborted: true, turnId: 't1' })
  expect(await stop()).toBe(undefined)
  await edit('C:/proj/next.py')
  const prompt = await stop()
  expect(prompt?.includes('app.py')).toBe(true)
  expect(prompt?.includes('next.py')).toBe(true)
})

test('code changed from a shell is sent for review too', async ($, on) => {
  const { stop } = cycle($, on)
  await $.tool.call({ tool: 'Bash', command: "sed -i 's/a/b/' src/app.py" })
  await $.tool.call({ tool: 'PowerShell', command: "'x' | Set-Content -Path C:\\proj\\tool.ps1" })
  await $.tool.call({ tool: 'Bash', command: 'grep -n todo src/other.py' }) // only reads
  const prompt = await stop()
  expect(prompt?.includes('src/app.py')).toBe(true)
  expect(prompt?.includes('tool.ps1')).toBe(true)
  expect(prompt?.includes('other.py')).toBe(false)
})

test('a shell command that was stopped or failed queues nothing, and a commit that passes still queues its edits', async ($, on) => {
  const seen = world(on, { '--cached': { stdout: added('app.py', `key = "${FAKE_GH}"`) } })
  on('classic.Stop', () => ({}))
  on('agent.list', () => ({ value: [] }))
  const stopped = await $.tool.call({ tool: 'Bash', command: "sed -i 's/a/b/' src/denied.py && git commit -m x" })
  expect(stopped.deny?.includes('GitHub token')).toBe(true)
  expect((await $.classic.Stop({ stop_hook_active: false })).block).toBe(undefined)
  seen.git = {}
  await $.tool.call({ tool: 'Bash', command: "sed -i 's/a/b/' src/kept.py && git commit -m x" })
  const prompt = (await $.classic.Stop({ stop_hook_active: false })).block
  expect(prompt?.includes('src/kept.py')).toBe(true)
  expect(prompt?.includes('denied.py')).toBe(false)
})

// --- scratch files and scripts that are only run ---------------------------------------------

const TEMP = 'C:/Users/pat/AppData/Local/Temp'
const WIN: Paths = { windows: true, home: 'C:/Users/pat', userProfile: 'C:/Users/pat' }
const LINUX: Paths = { windows: false, home: '/home/pat' }
// Notes written by a here-document, then a script in the vault is run: the script is only run.
const RUN_AFTER_NOTES = "cd \"$USERPROFILE/vault\"; python -I - <<'EOF'\nimport io\nio.open('log.md', 'a').write('x')\nEOF\npython -I .scripts/memory-map.py && git status --short"
const MAP = 'C:/Users/pat/vault/.scripts/memory-map.py'
// A here-document that writes, so the command counts as writing and its named code files are checked.
const WRITES = "python - <<'EOF'\nopen(n, 'w').write('x')\nEOF\n"

type FileState = { mtimeMs: number; size: number; text: string }

/**
 * A Windows machine (USERPROFILE and TEMP set) whose files are in `files` (path to modified time; each is
 * 10 bytes of "print('x')"). A path in `changes` reads as in `files` before the command and with those
 * fields changed after it: the command changed it. A path in `links` is a symbolic link. Any other path is
 * missing. Returns the status lines shown.
 */
function disk(on: On, files: Record<string, number>, changes: Record<string, Partial<FileState>> = {}, links: string[] = [], dirs: string[] = [], realPaths: Record<string, string> = {}, locked: string[] = []) {
  mock.env(on, { USERPROFILE: 'C:/Users/pat', TEMP, LOCALAPPDATA: 'C:/Users/pat/AppData/Local' })
  // A file is "after" once it has been looked at: its first stat (and read) are the snapshot before.
  const looked = new Set<string>()
  // On Linux the engine reads a Windows path as relative and puts its own folder first: drop that part.
  const norm = (raw: string) => raw.replace(/\\/g, '/').replace(/^.*?(?=[A-Za-z]:\/)/, '')
  const state = (raw: string, first: boolean): FileState | undefined => {
    const path = norm(raw)
    const t = files[path]
    if (t === undefined) return undefined
    const base = { mtimeMs: t, size: 10, text: "print('x')" }
    return first || !(path in changes) ? base : { ...base, ...changes[path] }
  }
  on('fs.stat', (_$, e) => {
    // `folder/.` is the folder, reached only with the right to pass through it (none for a `locked` one).
    const inner = norm(e.path).endsWith('/.') ? norm(e.path).slice(0, -2) : undefined
    if (inner !== undefined && locked.includes(inner)) throw Object.assign(new Error(`EACCES: ${e.path}`), { code: 'EACCES' })
    const path = inner ?? norm(e.path)
    // A folder, as the engine answers (`dir`), with where it really is when asked.
    if (dirs.includes(path)) return { value: { kind: 'dir' as const, size: 0, mtimeMs: 0, isLink: path in realPaths, realPath: realPaths[path] ?? path } }
    if (path === TEMP) return { value: { kind: 'dir' as const, size: 0, mtimeMs: 0, isLink: false, realPath: TEMP } }
    const s = state(path, !looked.has(path))
    if (s === undefined) throw Object.assign(new Error(`ENOENT: ${e.path}`), { code: 'ENOENT' })
    return { value: { kind: 'file' as const, size: s.size, mtimeMs: s.mtimeMs, isLink: links.includes(path) } }
  })
  on('fs.read', (_$, e) => {
    const path = norm(String(e.path))
    const s = state(path, !looked.has(path))
    looked.add(path) // the snapshot reads after its stat; the next look is after the command
    if (s === undefined) throw Object.assign(new Error(`ENOENT: ${e.path}`), { code: 'ENOENT' })
    return { value: s.text }
  })
  const status: string[] = []
  on('ui.status', (_$, e) => {
    status.push(e.text ?? '')
    return { value: undefined }
  })
  return status
}

test("Claude's scratch files are left out of the review, other temp files are not", async ($, on) => {
  const status = disk(on, {})
  const { edit, stop } = cycle($, on)
  await edit(`${TEMP.replace(/\//g, '\\')}\\claude\\abc\\scratchpad\\notes.py`) // the Write tool's Windows path
  await $.tool.call({ tool: 'Bash', command: "sed -i 's/a/b/' /c/Users/pat/AppData/Local/Temp/claude/x/build.mjs" }) // Git Bash
  expect(await stop()).toBe(undefined)
  expect(status.some(s => s.includes('not reviewed (scratch notes.py)'))).toBe(true) // never silent
  await edit(`${TEMP}/pip-build/setup.py`) // in TEMP but not Claude's
  await $.tool.call({ tool: 'Bash', command: "sed -i 's/a/b/' /tmp/clone/app.py" }) // a repo cloned to /tmp
  await $.tool.call({ tool: 'PowerShell', command: "'x' | Set-Content /tmp/claude-1/tool.ps1" }) // C:\tmp in PowerShell
  const prompt = await stop()
  for (const f of ['setup.py', '/tmp/clone/app.py', 'tool.ps1']) expect(prompt?.includes(f)).toBe(true)
})

test('an edit only to scratch files does not lift a hold', async ($, on) => {
  disk(on, {})
  on('turn.complete', () => ({ text: '' }))
  const { edit, stop } = cycle($, on)
  await edit('C:/proj/app.py')
  await $.turn.complete({ reason: 'aborted', answer: '', durationMs: 1, isAborted: true, turnId: 't1' })
  await edit(`${TEMP}/claude/x/scratchpad/n.py`)
  expect(await stop()).toBe(undefined) // still held
  await edit('C:/proj/app.py')
  expect((await stop())?.includes('app.py')).toBe(true)
})

test('a script a command only runs is left out; one it changed, or may have, is reviewed', async ($, on) => {
  const T = 1_700_000_000_000
  const status = disk(
    on,
    { [MAP]: T, 'C:/tools/gen.py': T, 'C:/tools/size.py': T, 'C:/tools/text.py': T, 'C:/tools/link.py': T, 'C:/proj/sub/gen.py': T },
    {
      'C:/tools/gen.py': { mtimeMs: T - 86_400_000 }, // changed to an older time (`cp -p`, `touch -d`)
      'C:/tools/size.py': { size: 11 }, // same time, new size
      'C:/tools/text.py': { text: "print('y')" }, // same time and size, new text (`cp -p` of a twin)
    },
    ['C:/tools/link.py'],
  )
  const { stop } = cycle($, on)
  await $.tool.call({ tool: 'Bash', command: RUN_AFTER_NOTES })
  expect(await stop()).toBe(undefined)
  expect(status.some(s => s.includes('only run .scripts/memory-map.py'))).toBe(true) // never silent
  for (const [command, script] of <[string, string][]>[
    [`${WRITES}python C:/tools/gen.py`, 'C:/tools/gen.py'], // changed while it ran, even to an older time
    [`${WRITES}python C:/tools/size.py`, 'C:/tools/size.py'],
    [`${WRITES}python C:/tools/text.py`, 'C:/tools/text.py'],
    [`${WRITES}python C:/tools/link.py`, 'C:/tools/link.py'], // a link: its target's time proves nothing
    ['sed -i x gen.py; cd /c/proj/sub && python gen.py', 'gen.py'], // named twice, and the cd is not first
    ['cd /c/proj/sub && sed -i x gen.py && python gen.py', 'gen.py'], // named twice
    [`cd /c/proj/sub; cd .. ; ${WRITES}python gen.py`, 'gen.py'], // two moves
    [`${WRITES}python gen.py; cd /c/proj/sub`, 'gen.py'], // the move comes after
    [`${WRITES}python gen.py`, 'gen.py'], // no cd: where the shell stands is unknown
    [`cd /c/proj/sub && ${WRITES}python gen.py & sleep 1`, 'gen.py'], // a background job may write later
    [`cd /c/proj/sub && nohup cp n.py x.py; ${WRITES}python gen.py`, 'gen.py'], // so may a detached one
    [`cd /c/proj/sub && python - <<'EOF'\nopen('gen.py', 'w').write('x')\nEOF\npython gen.py`, 'gen.py'], // a body names it
  ]) {
    await $.tool.call({ tool: 'Bash', command })
    const python = (await stop())?.split('\n').find(l => l.startsWith('- Python: ')) ?? ''
    expect([command, python.slice('- Python: '.length).split(', ').includes(script)]).toEqual([command, true])
    await stop(true)
  }
  // In the background the command has not finished when the hook looks, so nothing is left out.
  await $.tool.call({ tool: 'Bash', command: RUN_AFTER_NOTES, run_in_background: true })
  expect((await stop())?.includes('memory-map.py')).toBe(true)
})

/** A Stop that asks for nothing else, and the shell's answer to every command. */
function shellAnswers($: Engine, on: On, answer: Record<string, unknown>) {
  on('classic.Stop', () => ({}))
  on('agent.list', () => ({ value: [] }))
  on('tool.call', () => answer as never)
  return async () => (await $.classic.Stop({ stop_hook_active: false })).block
}

test('a command put in the background part way still has its run scripts reviewed', async ($, on) => {
  disk(on, { [MAP]: 1 })
  // Ctrl+B or a timeout: the result comes back while the command still runs, so its files can't be compared.
  const stop = shellAnswers($, on, { result: { stdout: '', stderr: '', interrupted: false, backgroundTaskId: 'b1' } })
  await $.tool.call({ tool: 'Bash', command: RUN_AFTER_NOTES })
  expect((await stop())?.includes('memory-map.py')).toBe(true)
})

test('a command that failed may have written before it failed, so its writes are reviewed', async ($, on) => {
  disk(on, {})
  const stop = shellAnswers($, on, { result: { stdout: '', stderr: 'tests failed', interrupted: false }, isError: true })
  await $.tool.call({ tool: 'Bash', command: "sed -i 's/a/b/' src/app.py && pytest" })
  expect((await stop())?.includes('src/app.py')).toBe(true)
})

test('a scratch file a command copies or moves is kept: it may be going into the project', async ($, on) => {
  disk(on, {})
  const { stop } = cycle($, on)
  await $.tool.call({ tool: 'Bash', command: `cp ${TEMP}/claude/x/scratchpad/app.py /c/proj/` })
  expect((await stop())?.includes('app.py')).toBe(true)
  await stop(true)
  await $.tool.call({ tool: 'PowerShell', command: `Copy-Item ${TEMP}/claude/x/scratchpad/tool.ps1 C:/proj/` })
  expect((await stop())?.includes('tool.ps1')).toBe(true)
})

test('a command that only writes and runs scratch scripts writes nothing their text names, and says so', async ($, on) => {
  const status = disk(on, {})
  const files: string[] = []
  on('session.id', () => ({ value: 's-1' }))
  on('fs.write', (_$, e) => {
    files.push(e.text)
    return { value: undefined }
  })
  const { stop } = cycle($, on)
  const S = `${TEMP}/claude/x/scratchpad`
  // A probe written to scratch and run: its text names a project file, as a test case, that nothing here
  // writes. Read as the command's own text, that line would be a write of /c/proj/other.py.
  const probe = 'sed -i s/a/b/ /c/proj/other.py'
  for (const command of [
    `cat > ${S}/p.sh <<'EOF'\n${probe}\nEOF\nbash ${S}/p.sh`,
    `S=${S}; cat > "$S/p.sh" <<'EOF'\n${probe}\nEOF\nbash "$S/p.sh" 2>&1 | head -50`, // a plain variable set first
  ]) {
    await $.tool.call({ tool: 'Bash', command })
    expect([command, await stop()]).toEqual([command, undefined])
    // Never silent: the status line and the status file name it.
    expect([command, status.at(-1)?.includes('with a scratch script /c/proj/other.py')]).toEqual([command, true])
    const saved = statusFrom(JSON.parse(files.at(-1) ?? '{}'))
    expect([command, saved?.leftOut.some(l => l.path === '/c/proj/other.py' && l.why === 'scratch script')]).toEqual([command, true])
  }
  for (const command of [
    `cat > ${S}/p.sh <<'EOF'\n${probe}\nEOF\ncp ${S}/p.sh /c/proj/p.sh`, // copied on: it may go into the project
    `cat > ${S}/p.sh <<'EOF'\n${probe}\nEOF\nmv ${S}/* /c/proj/`, // moved on by a glob
    `cd ${S} && cat > p.sh <<'EOF'\n${probe}\nEOF\nbash p.sh`, // relative: the cd may have failed
    `cat > claude/x/p.sh <<'EOF'\n${probe}\nEOF\nbash claude/x/p.sh`, // relative, from nowhere known
    `cat > "$TEMP/claude/x/p.sh" <<'EOF'\n${probe}\nEOF\nbash "$TEMP/claude/x/p.sh"`, // the shell may set TEMP otherwise
    `X=a; cat > ${S}/$X/../../../../../../c/proj/p.sh <<'EOF'\n${probe}\nEOF`, // out of scratch by `..`
  ]) {
    await $.tool.call({ tool: 'Bash', command })
    expect([command, (await stop())?.includes('other.py')]).toEqual([command, true])
    expect(await stop(true)).toBe(undefined) // the review ends: nothing carries to the next case
  }
  // PowerShell has no here-document: nothing in its text is read as a scratch script.
  await $.tool.call({ tool: 'PowerShell', command: `cat > ${S}/p.sh <<'EOF'\n${probe}\nEOF\nbash ${S}/p.sh` })
  expect((await stop())?.includes('other.py')).toBe(true)
})

test('a scratch check that throws keeps every write, and says why in the log', () => {
  const logged: string[] = []
  const engine = { ui: { log: (text: string) => { logged.push(text) } } } as never
  const all = ['/s/p.sh', 'a.py']
  expect(blankedSafely(engine, "cat > /s/p.sh <<'EOF'\nsed -i x a.py\nEOF", () => { throw new Error('no') }, all)).toEqual(all)
  expect(logged).toEqual(["review-guard: a scratch script's text was kept in the review: it could not be read (no)"])
})

test('what is left out goes after a guard notice on the status line, never over it', async ($, on) => {
  const status = disk(on, { [MAP]: 1 })
  const { stop } = cycle($, on)
  await $.tool.call({ tool: 'Bash', command: `${RUN_AFTER_NOTES}; ssh box 'git push'` })
  expect(await stop()).toBe(undefined)
  const last = status.at(-1) ?? ''
  expect(last.includes('sent over SSH') && last.includes('was NOT checked here')).toBe(true)
  expect(last.includes('Not reviewed: only run .scripts/memory-map.py')).toBe(true)
})

test("this session's own commands: the review lists what they edited, not what they ran or only named", async ($, on) => {
  const R = 'C:/Users/pat/proj'
  const T = 1_700_000_000_000
  disk(
    on,
    { [`${R}/hooks/a.ts`]: T, [`${R}/tests/m.node.mjs`]: T, [`${R}/scripts/build.mjs`]: T, [`${R}/tests/t.test.ts`]: T },
    { [`${R}/hooks/a.ts`]: { size: 11 }, [`${R}/tests/t.test.ts`]: { size: 12 } },
  )
  const { stop } = cycle($, on)
  // A sed on one file, with a command substitution, then tests run on two others.
  await $.tool.call({ tool: 'Bash', command: `cd "${R}" && n=$(grep -n "x" hooks/a.ts | cut -d: -f1) && sed -i "\${n}s/a/b/" hooks/a.ts && claude plugin test . 2>&1 | grep -E "^\\(fail\\)|pass$"; node --test tests/m.node.mjs 2>&1 | grep -E "^i (pass|fail)"; node scripts/build.mjs --check 2>/dev/null && echo OK` })
  const first = (await stop()) ?? ''
  expect([first.includes('hooks/a.ts'), first.includes('m.node.mjs'), first.includes('build.mjs')]).toEqual([true, false, false])
  await stop(true)
  // A Python script editing a test file whose new case names app.py.
  await $.tool.call({ tool: 'Bash', command: [
    `cd "${R}" && python - <<'PY'`,
    "t='tests/t.test.ts'",
    "s=open(t,encoding='utf-8').read()",
    `s=s.replace("})", "  await edit('C:/proj/app.py')\\n})", 1)`,
    "open(t,'w',encoding='utf-8').write(s)",
    'PY',
    `grep -c 'app' tests/t.test.ts`,
  ].join('\n') })
  const second = (await stop()) ?? ''
  expect([second.includes('tests/t.test.ts'), second.includes('app.py')]).toEqual([true, false])
})

test('writes after a cd into the scratch folder by its variable are scratch, if that folder is there', async ($, on) => {
  const S = `${TEMP}/claude/x/scratchpad`
  const status = disk(on, {}, {}, [], [S])
  const { stop } = cycle($, on)
  const cd = 'cd "$LOCALAPPDATA/Temp/claude/x/scratchpad"'
  // This session's two commands (the web call swapped for a stand-in).
  for (const command of [
    `${cd} && render README.md > body.html 2>err.txt; echo "exit=$?"; wc -c body.html`,
    `${cd} && grep -o 'src' body.html | head -3; { printf '<html>'; sed "s#a#b#" body.html; printf '</html>'; } > readme-preview.html && grep -c demo readme-preview.html`,
  ]) {
    await $.tool.call({ tool: 'Bash', command })
    expect([command, await stop()]).toEqual([command, undefined])
  }
  expect(status.some(s => s.includes('readme-preview.html'))).toBe(true) // never silent: named as scratch
  // A folder that is not there (the cd failed, the write landed here), a command that sets the variable,
  // or a folder that is not Claude's: reviewed.
  for (const command of [
    'cd "$LOCALAPPDATA/Temp/claude/y/scratchpad"; render > body.html',
    'cd "$LOCALAPPDATA/Temp/claude/y/scratchpad"; mkdir -p "$LOCALAPPDATA/Temp/claude/y/scratchpad"; render > body.html', // made after the cd failed
    `LOCALAPPDATA=C:/proj; ${cd}; render > body.html`,
    'cd "$LOCALAPPDATA/Temp/other" && render > body.html',
    `${cd} && render > ../../../../../../proj/body.html`,
    // A cd the shell would not take there: single quotes expand nothing, double quotes no `~`.
    "cd '$LOCALAPPDATA/Temp/claude/x/scratchpad'; render > body.html",
    'cd "~/AppData/Local/Temp/claude/x/scratchpad"; render > body.html',
    // A change of folder after the cd.
    `${cd} && python -c "import os; os.chdir('C:/proj'); open('body.html', 'w')" && render > body.html`,
    `${cd} && git -C C:/proj apply x.diff > body.html`,
    `${cd} && npm --prefix C:/proj run build > body.html`,
    `${cd} | render > body.html`, // a piped cd moves only a subshell
    `${cd} || render > body.html`,
    `${cd} && render > D:body.html`, // a drive-relative name is on that drive
    `${cd} && render > link/body.html`, // a folder inside may be a link out of scratch
    `${cd} && patch -d C:/proj -p1 body.html < x.diff`, // programs given a folder to write in
    `${cd} && c=c && d=d && $c$d C:/proj && render > body.html`, // a cd by variable
  ]) {
    await $.tool.call({ tool: 'Bash', command })
    expect([command, (await stop())?.includes('body.html')]).toEqual([command, true])
    await stop(true)
  }
})

test('names written after a cd into another folder are reviewed as that folder\'s files, not the session\'s', async ($, on) => {
  const R = 'C:/Users/pat/Tools/repo'
  disk(on, {}, {}, [], [R, 'C:/Users/pat/Tools/locked'], {}, ['C:/Users/pat/Tools/locked'])
  const { stop } = cycle($, on)
  // The session is in C:/proj; the command works in another repo, as this session's own commands did.
  for (const [command, file] of [
    [`cd "${R}" && sed -i 's/a/b/' hooks/churn.ts`, `${R}/hooks/churn.ts`],
    [`cd ${R} && python - <<'PY'\nopen('tests/t.test.ts','w').write('x')\nPY`, `${R}/tests/t.test.ts`],
    [`cd "${R}" && sed -i 's/a/b/' ./app.py`, `${R}/app.py`],
    // The folder is there and can be read, so the cd can't fail: a write after `;` lands there too.
    [`cd "${R}"; sed -i 's/a/b/' lib.py`, `${R}/lib.py`],
  ]) {
    await $.tool.call({ tool: 'Bash', command })
    const prompt = (await stop()) ?? ''
    expect([command, prompt.includes(file)]).toEqual([command, true])
    await stop(true)
  }
  // A folder that is not there (the cd failed, the write landed in the session's folder) or can't be read
  // (the cd may fail), a name with a `..` step or a drive, a cd piped on, or a change of folder after it
  // (a program run with `cwd=` too): the name stays as written.
  for (const [command, name] of [
    ['cd "C:/Users/pat/Tools/gone" && sed -i s/a/b/ app.py', 'app.py'],
    ['cd "C:/Users/pat/Tools/locked"; sed -i s/a/b/ app.py', 'app.py'],
    [`cd "${R}" && sed -i s/a/b/ app.py && python -c "run(['make'], cwd='C:/proj')"`, 'app.py'],
    [`cd "${R}" && sed -i s/a/b/ app.py && python -c "run(['make'], **{'cwd': 'C:/proj'})"`, 'app.py'],
    [`cd "${R}" && sed -i s/a/b/ app.py && node -e "execSync('make', { cwd })"`, 'app.py'],
    [`cd "${R}" && sed -i s/a/b/ ../other/app.py`, '../other/app.py'],
    [`cd "${R}" && sed -i s/a/b/ D:app.py`, 'D:app.py'],
    [`cd "${R}" | sed -i s/a/b/ app.py`, 'app.py'],
    [`cd "${R}" && git -C C:/proj apply x.diff && sed -i s/a/b/ app.py`, 'app.py'],
  ]) {
    await $.tool.call({ tool: 'Bash', command })
    const prompt = (await stop()) ?? ''
    // Nothing placed under the folder at all (`R/../other/app.py` and `R/D:app.py` would still hold the name).
    expect([command, prompt.includes(name), prompt.includes(`${R}/`)]).toEqual([command, true, false])
    await stop(true)
  }
})

test('in PowerShell a Set-Location places cmdlet writes there, but never .NET ones, which keep the process folder', async ($, on) => {
  const R = 'C:/Users/pat/Tools/repo'
  disk(on, {}, {}, [], [R])
  const { stop } = cycle($, on)
  await $.tool.call({ tool: 'PowerShell', command: `Set-Location "${R}"; Set-Content -Path hooks/a.ps1 -Value x` } as never)
  expect(((await stop()) ?? '').includes(`${R}/hooks/a.ps1`)).toBe(true)
  await stop(true)
  // A backslash outside quotes is not read here (a shell may read it otherwise): the name stays as written.
  await $.tool.call({ tool: 'PowerShell', command: `Set-Location "${R}" && Set-Content -Path hooks\\b.ps1 -Value x` } as never)
  const kept = (await stop()) ?? ''
  expect([kept.includes('b.ps1'), kept.includes(`${R}/hooks`)]).toEqual([true, false])
  await stop(true)
  await $.tool.call({ tool: 'PowerShell', command: `Set-Location "${R}" && [IO.File]::WriteAllText('a.py', 'x')` } as never)
  const prompt = (await stop()) ?? ''
  expect([prompt.includes('a.py'), prompt.includes(`${R}/a.py`)]).toEqual([true, false])
})

test('a cd into a folder spelled as scratch that leads out of it places nothing, so nothing is dropped as scratch', async ($, on) => {
  const S = `${TEMP}/claude/x/scratchpad`
  disk(on, {}, {}, [], [S], { [S]: 'C:/proj' })
  const { stop } = cycle($, on)
  // By its variable: a full path with `Local/Temp` in it is refused anyway (`startFolder` reads it as setting TEMP).
  const cd = 'cd "$LOCALAPPDATA/Temp/claude/x/scratchpad"'
  for (const command of [`${cd} && render > a.py`, `${cd} && render > sub/a.py`]) {
    await $.tool.call({ tool: 'Bash', command })
    const prompt = (await stop()) ?? ''
    expect([command, prompt.includes('a.py'), prompt.includes(`${S}/`)]).toEqual([command, true, false])
    await stop(true)
  }
})

test('in the scratch folder a name with folders is reviewed under its full name, never left out as scratch', async ($, on) => {
  const S = `${TEMP}/claude/x/scratchpad`
  disk(on, {}, {}, [], [S])
  const { stop } = cycle($, on)
  await $.tool.call({ tool: 'Bash', command: 'cd "$LOCALAPPDATA/Temp/claude/x/scratchpad" && render > link/a.py' })
  expect(((await stop()) ?? '').includes(`${S}/link/a.py`)).toBe(true)
})

test('the scratch folder must be there before the command, not made by it; and never for a background run', async ($, on) => {
  const S = `${TEMP}/claude/x/scratchpad`
  const dirs: string[] = []
  disk(on, {}, {}, [], dirs)
  on('classic.Stop', () => ({}))
  on('agent.list', () => ({ value: [] }))
  // The command makes the folder as it runs (`cd X; mkdir -p X; ...`): only after the check.
  on('tool.call', () => {
    dirs.push(S)
    return { result: {} }
  })
  const stop = async (active = false) => (await $.classic.Stop({ stop_hook_active: active })).block
  await $.tool.call({ tool: 'Bash', command: `cd "$LOCALAPPDATA/Temp/claude/x/scratchpad"; mkdir -p "$LOCALAPPDATA/Temp/claude/x/scratchpad"; render > body.html` })
  expect((await stop())?.includes('body.html')).toBe(true)
  await stop(true)
  // Now it is there, but a command run in the background can't be judged.
  await $.tool.call({ tool: 'Bash', command: 'cd "$LOCALAPPDATA/Temp/claude/x/scratchpad" && render > body.html', run_in_background: true })
  expect((await stop())?.includes('body.html')).toBe(true)
  await stop(true)
  await $.tool.call({ tool: 'Bash', command: 'cd "$LOCALAPPDATA/Temp/claude/x/scratchpad" && render > body.html' })
  expect(await stop()).toBe(undefined)
  // PowerShell: `$env:LOCALAPPDATA` is the environment's; `$LOCALAPPDATA` is the session's own variable.
  await $.tool.call({ tool: 'PowerShell', command: "cd $env:LOCALAPPDATA/Temp/claude/x/scratchpad; 'x' | Set-Content a.ps1" })
  expect(await stop()).toBe(undefined)
  for (const command of ["cd $LOCALAPPDATA/Temp/claude/x/scratchpad; 'x' | Set-Content a.ps1", "cd $env:LOCALAPPDATA/Temp/claude/x/scratchpad; Set-Content -Path 'FileSystem::C:/proj/a.ps1' -Value x", "cd $env:LOCALAPPDATA/Temp/claude/x/scratchpad; 'x' > D:a.ps1"]) {
    await $.tool.call({ tool: 'PowerShell', command })
    expect([command, (await stop())?.includes('a.ps1')]).toEqual([command, true])
    await stop(true)
  }
})

test('a temp-folder variable is filled in only where the shell fills it in', () => {
  const vars = { TEMP: 'C:/T', LOCALAPPDATA: 'C:/L', TMPDIR: '/var/folders/x/T/' }
  const WINV = { windows: true, home: 'C:/Users/pat', userProfile: 'C:/Users/pat', vars }
  const LINV = { windows: false, home: '/home/pat', vars }
  expect(startFolder('cd "${TEMP}/a" && x', WINV)).toBe('C:/T/a')
  expect(startFolder('cd $temp/a && x', WINV)).toBe(undefined) // Bash keeps a variable's case
  expect(startFolder('cd $TMP/a && x', WINV)).toBe(undefined) // not set
  expect(startFolder('cd $env:TEMP/a && x', WINV)).toBe(undefined) // PowerShell's spelling, in Bash
  expect(startFolder('cd $env:temp/a; x', WINV, true)).toBe('C:/T/a')
  expect(startFolder('cd $TEMP/a; x', WINV, true)).toBe(undefined) // a session variable in PowerShell
  expect(startFolder('cd $env:tmpdir/a; x', LINV, true)).toBe(undefined) // off Windows names keep their case
  expect(startFolder('cd "$TMPDIR/claude/s" && x', LINV)).toBe('/var/folders/x/T/claude/s') // no doubled slash
  // Braces inside quotes are text, and `echo { x }` prints braces: neither is a group.
  expect(startFolder('cd "C:/a { b }" && x', WINV)).toBe('C:/a { b }')
  expect([...runOnlyScripts('cd C:/p && echo { python gen.py }', WINV)]).toEqual([])
})

test('a script only run is left out at every shell call site, the git-checked ones too', async ($, on) => {
  world(on)
  on('fs.stat', () => ({ value: { kind: 'file' as const, size: 10, mtimeMs: 1, isLink: false } })) // world() answers fs.read
  on('classic.Stop', () => ({}))
  on('agent.list', () => ({ value: [] }))
  const stop = async () => (await $.classic.Stop({ stop_hook_active: false })).block
  // A push to GitHub goes through the guard first, then its writes are remembered.
  await $.tool.call({ tool: 'Bash', command: `${RUN_AFTER_NOTES} && git push origin main` })
  expect(await stop()).toBe(undefined)
  await $.tool.call({ tool: 'PowerShell', command: `cd C:/Users/pat/vault; 'x' | Set-Content n.md; python .scripts/memory-map.py` })
  expect(await stop()).toBe(undefined)
})

test('the review state is written where the MCP server reads it, and a failed write changes nothing', async ($, on) => {
  disk(on, { [MAP]: 1 })
  mock.clock(on) // the exit's one-second wait, held until the test moves the clock
  on('session.id', () => ({ value: 's-1' }))
  on('session.cwd', () => ({ value: 'C:/proj' }))
  on('session.end', () => ({ sessionId: 's-1' })) // the engine's own end step
  const writes: { path: string; text: string }[] = []
  let failWrites = false
  on('fs.write', (_$, e) => {
    if (failWrites) throw new Error('disk full')
    // Only the status files: a project's review history (churn) is written here too.
    if (e.path.replace(/\\/g, '/').includes('/review-guard/status/')) writes.push({ path: e.path, text: e.text })
    return { value: undefined }
  })
  const { edit, stop } = cycle($, on)
  await edit('C:/proj/app.py')
  await $.tool.call({ tool: 'Bash', command: RUN_AFTER_NOTES })
  const last = writes.at(-1)
  expect(last?.path.replace(/\\/g, '/').replace(/^.*?(?=[A-Za-z]:\/)/, '')).toBe('C:/Users/pat/.claude/review-guard/status/s-1.json')
  const latest = () => statusFrom(JSON.parse(writes.at(-1)?.text ?? '{}'))
  const status = latest()
  expect(status === undefined).toBe(false) // the shape the server reads
  expect(status?.folder).toBe('C:/proj')
  expect(status?.phase).toBe('idle')
  expect(status?.queued).toEqual(['C:/proj/app.py'])
  expect(status?.leftOut.some(l => l.path === '.scripts/memory-map.py' && l.why === 'only run')).toBe(true)
  // A review: running, with what it covers; when it ends, nothing is shown as under review any more.
  expect((await stop())?.includes('app.py')).toBe(true)
  expect(latest()?.phase).toBe('reviewing')
  expect(latest()?.underReview).toEqual(['C:/proj/app.py'])
  await stop(true)
  await stop()
  expect(latest()?.phase).toBe('idle')
  expect(latest()?.underReview).toEqual([])
  // A failed write: the review goes on, and the next file written says the one before failed.
  failWrites = true
  await edit('C:/proj/b.py')
  expect((await stop())?.includes('b.py')).toBe(true)
  failWrites = false
  await edit('C:/proj/c.py')
  expect(latest()?.writeFailed === undefined).toBe(false) // the kit words the failure its own way
  await edit('C:/proj/d.py')
  expect(latest()?.writeFailed).toBe(undefined)
  // The session's end is written too, so it isn't shown as still running.
  await $.session.end({ reason: 'exit' } as never)
  expect(latest()?.phase).toBe('ended')
})

test('a session id that is not a plain name is made one for the status file name', async ($, on) => {
  disk(on, {})
  on('session.id', () => ({ value: 'a/b:..\\c' }))
  on('session.cwd', () => ({ value: 'C:/proj' }))
  const paths: string[] = []
  on('fs.write', (_$, e) => {
    paths.push(e.path.replace(/\\/g, '/'))
    return { value: undefined }
  })
  const { edit } = cycle($, on)
  await edit('C:/proj/app.py')
  // Each other character is coded, % too, so "a.b" and "a_b" can't share a file.
  expect(paths.at(-1)?.endsWith('/.claude/review-guard/status/a%002fb%003a%002e%002e%005cc.json')).toBe(true)
})

test('a session with nothing to report writes no status file, and one that has a file keeps it current', async ($, on) => {
  disk(on, {})
  mock.clock(on)
  on('session.id', () => ({ value: 's-2' }))
  on('session.end', () => ({ sessionId: 's-2' }))
  let fileThere = false
  on('fs.exists', (_$, e) => ({ value: e.path.replace(/\\/g, '/').endsWith('/status/s-2.json') && fileThere }))
  const writes: string[] = []
  on('fs.write', (_$, e) => {
    writes.push(e.text)
    return { value: undefined }
  })
  const { stop } = cycle($, on)
  await $.prompt.submit({ text: 'what is 2 + 2?', wait: false, origin: { kind: 'composer' } })
  expect(await stop()).toBe(undefined)
  await $.session.end({ reason: 'exit' } as never)
  expect(writes).toEqual([])
  // A file from an earlier load of the mod is there: its end is written, so it doesn't look open.
  fileThere = true
  await $.session.end({ reason: 'exit' } as never)
  expect(statusFrom(JSON.parse(writes.at(-1) ?? '{}'))?.phase).toBe('ended')
})

test('an exit waits at most a second for the status file', async ($, on) => {
  disk(on, {})
  const clock = mock.clock(on)
  on('session.id', () => ({ value: 's-3' }))
  on('session.end', () => ({ sessionId: 's-3' }))
  on('fs.exists', () => ({ value: true }))
  on('fs.write', () => new Promise<never>(() => {})) // a write that never finishes
  let ended = false
  const exit = $.session.end({ reason: 'exit' } as never).then(() => { ended = true })
  await clock.advance(999)
  expect(ended).toBe(false)
  await clock.advance(1)
  await exit
  expect(ended).toBe(true)
})

test('an exit whose clock fails does not wait for the status file', async ($, on) => {
  disk(on, {})
  on('clock.sleep', () => { throw new Error('no clock') })
  on('session.id', () => ({ value: 's-4' }))
  on('session.end', () => ({ sessionId: 's-4' }))
  on('fs.exists', () => ({ value: true }))
  on('fs.write', () => new Promise<never>(() => {}))
  // Waiting for the write would hang to the hook's ten-second budget; the exit must come well before.
  const started = Date.now()
  await $.session.end({ reason: 'exit' } as never)
  expect(Date.now() - started < 3000).toBe(true)
})

test("the review's scanner lookup names the ones it could not check, and why", async () => {
  const host = (home: string | undefined, exists: (p: string) => Promise<boolean>) => ({
    run: async () => { throw new Error('not on PATH') },
    read: async () => undefined,
    exists,
    home: async () => home,
    pluginRoot: 'C:/mod',
  }) as never
  // A place that can't be checked is a problem with a reason, never "not installed".
  const blocked = await findScanners(host('C:/Users/pat', async () => { throw new Error('access denied') }))
  expect(blocked.found.size).toBe(0)
  expect([...blocked.problems.values()].every(p => p.includes("can't be checked: access denied"))).toBe(true)
  // With no home folder, the usual places were never searched: said so for each.
  const homeless = await findScanners(host(undefined, async () => false))
  expect(homeless.problems.get('bandit')).toBe('the home folder is not known, so only PATH was searched')
  // A home folder, and nothing anywhere: simply not installed.
  const none = await findScanners(host('C:/Users/pat', async () => false))
  expect(none.problems.size).toBe(0)
})

test('status files with a bad time in them are not read', () => {
  const good = { v: 1, session: 's', updated: '2026-01-01T00:00:00Z', phase: 'idle', queued: [], underReview: [], leftOut: [], leftOutSince: '2026-01-01T00:00:00Z' }
  expect(statusFrom(good) === undefined).toBe(false)
  expect(statusFrom({ ...good, leftOutSince: 'soon' })).toBe(undefined)
  expect(statusFrom({ ...good, leftOut: [{ path: 'a.py', why: 'scratch', at: 'later' }] })).toBe(undefined)
  for (const why of ['scratch', 'only run', 'scratch script', 'a reason from a newer mod']) {
    expect(statusFrom({ ...good, leftOut: [{ path: 'a.py', why, at: '2026-01-01T00:00:00Z' }] })?.leftOut[0]?.why).toBe(why)
  }
  for (const why of ['', 'x'.repeat(41), 3]) {
    expect(statusFrom({ ...good, leftOut: [{ path: 'a.py', why, at: '2026-01-01T00:00:00Z' }] })).toBe(undefined)
  }
})

test('a failed lookup never leaves a file out', async ($, on) => {
  on('env.get', () => { throw new Error('no env') }) // a throw, not a rejection
  on('fs.stat', () => { throw new Error('EACCES') })
  const { edit, stop } = cycle($, on)
  await edit(`${TEMP}/claude/x/a.py`) // TEMP can't be read: not known to be scratch
  await $.tool.call({ tool: 'Bash', command: RUN_AFTER_NOTES })
  const prompt = await stop()
  expect(prompt?.includes('a.py')).toBe(true)
  expect(prompt?.includes('memory-map.py')).toBe(true)
})

test('knows scratch folders, and which scripts a command only runs and where', async () => {
  const temp = [TEMP]
  expect(inScratch(`${TEMP.replace(/\//g, '\\')}\\claude\\a\\s.py`, temp, { spelling: 'windows-msys', posixTmp: true })).toBe(true)
  expect(inScratch('/c/Users/pat/AppData/Local/Temp/claude/a.py', temp, { spelling: 'windows-msys', posixTmp: true })).toBe(true) // Git Bash
  expect(inScratch('c:/Users/pat/AppData/Local/Temp/claude/a.py', temp, { spelling: 'windows', posixTmp: false })).toBe(true) // the drive letter's case only
  expect(inScratch('/c/users/PAT/appdata/local/temp/CLAUDE/a.py', temp, { spelling: 'windows-msys', posixTmp: true })).toBe(false) // other case counts: a folder can be case-sensitive
  expect(inScratch('/c/users/pat/appdata/local/temp/claude/a.py', temp, { spelling: 'windows', posixTmp: false })).toBe(false) // PowerShell: a folder c
  // The edit tools on Windows: `/c/...` is drive C, but `/tmp` is `\tmp` on the current drive.
  expect(inScratch('/c/Users/pat/AppData/Local/Temp/claude/a.py', temp, rulesFor('edit', true))).toBe(true)
  expect(inScratch('/tmp/claude/x/b.py', temp, rulesFor('edit', true))).toBe(false)
  expect(inScratch('/tmp\\claude-1/a.py', [], { spelling: 'posix', posixTmp: true })).toBe(false) // off Windows a \ is part of a name
  expect(inScratch('/tmp/claude-1000/a.py', [], { spelling: 'posix', posixTmp: true })).toBe(true)
  expect(inScratch('/TMP/claude-1000/a.py', [], { spelling: 'posix', posixTmp: true })).toBe(false) // Linux names keep their case
  expect(inScratch('/tmp/claude-1/a.py', [], { spelling: 'windows', posixTmp: false })).toBe(false) // PowerShell: /tmp is C:\tmp
  expect(inScratch(`${TEMP}/a.py`, temp, { spelling: 'windows-msys', posixTmp: true })).toBe(false) // temp, but not Claude's
  expect(inScratch(`${TEMP}/claude`, temp, { spelling: 'windows-msys', posixTmp: true })).toBe(false) // the folder itself
  expect(inScratch('/tmp/claude/../../home/pat/app.py', [], { spelling: 'posix', posixTmp: true })).toBe(false) // `..` climbs out
  expect(inScratch('C:/claude/a.py', ['C:/', '/', 'C:'], { spelling: 'windows', posixTmp: false })).toBe(false) // a root is no temp folder
  expect(inScratch('C:/proj/claude/a.py', ['proj', 'tmp'], { spelling: 'windows', posixTmp: false })).toBe(false) // nor a relative one
  expect(inScratch('C:/Users/pat/AppData/Local/TempX/claude/a.py', temp, { spelling: 'windows-msys', posixTmp: true })).toBe(false)

  expect([...runOnlyScripts(RUN_AFTER_NOTES, WIN)]).toEqual([['.scripts/memory-map.py', MAP]])
  expect([...runOnlyScripts('cd ~/proj && python3 -I gen.py 2>&1 | tail -3', LINUX)]).toEqual([['gen.py', '/home/pat/proj/gen.py']])
  expect([...runOnlyScripts('node "C:/tools/b.mjs" out.html', WIN)]).toEqual([['C:/tools/b.mjs', 'C:/tools/b.mjs']])
  // `/c/...` is drive C in Git Bash only: in PowerShell it is a folder `c` on the current drive.
  expect([...runOnlyScripts('python /c/tools/gen.py', WIN).values()]).toEqual(['C:/tools/gen.py'])
  expect([...runOnlyScripts('python /c/tools/gen.py', WIN, true).values()].includes('C:/tools/gen.py')).toBe(false)
  // With a start folder known: a rooted path with no drive is not joined onto it, nor read as drive C.
  expect([...runOnlyScripts('cd C:/proj && python /c/tools/gen.py', WIN, true).values()]).toEqual([])
  expect([...runOnlyScripts('cd C:/proj && python /tools/gen.py', WIN).values()]).toEqual([])
  // `chdir` is no Bash builtin; in PowerShell it is Set-Location, as `sl` is.
  expect([...runOnlyScripts('chdir C:/p; python gen.py', WIN)]).toEqual([])
  for (const cd of ['chdir', 'Set-Location', 'sl', 'CD']) {
    expect([cd, [...runOnlyScripts(`${cd} C:/p; python gen.py`, WIN, true)]]).toEqual([cd, [['gen.py', 'C:/p/gen.py']]])
  }
  expect([...runOnlyScripts('CD C:/p; python gen.py', WIN)]).toEqual([]) // Bash's cd is lower case
  // A backslash can escape a quote the here-document split can't follow: with a here-document, no candidates.
  expect([...runOnlyScripts("node \"C:\\tools\\b.mjs\" out.html; cat <<'E'\nx\nE", WIN)]).toEqual([])
  // With none, the command's lines are all its own, and bash keeps `\t` inside double quotes.
  expect([...runOnlyScripts('node "C:\\tools\\b.mjs" out.html', WIN)]).toEqual([['C:\\tools\\b.mjs', 'C:/tools/b.mjs']])
  // A command substitution runs in a subshell: it moves no folder and hides no run. This session's own
  // command (a sed on one file, tests run on two others) leaves the two run scripts as candidates.
  const R = 'C:/Users/pat/proj'
  const session = `cd "${R}" && n=$(grep -n "JSON.parse" hooks/a.ts | cut -d: -f1) && sed -i "\${n}s/\\xef\\xbb\\xbf/x/" hooks/a.ts && sed -n "\${n}p" hooks/a.ts | cat -A && claude plugin test . 2>&1 | grep -E "^\\(fail\\)|pass$"; node --test tests/m.node.mjs 2>&1 | grep -E "^i (pass|fail)"; node scripts/build.mjs --check 2>/dev/null && echo OK; echo "exit=$?"`
  expect([...runOnlyScripts(session, WIN)]).toEqual([['tests/m.node.mjs', `${R}/tests/m.node.mjs`], ['scripts/build.mjs', `${R}/scripts/build.mjs`]])
  expect([...runOnlyScripts('cd C:/p && x=`date` && python gen.py', WIN)]).toEqual([['gen.py', 'C:/p/gen.py']])
  // But a script also named inside a substitution, a cd there, or one that never ends: no candidate or place.
  expect([...runOnlyScripts('cd C:/p && python gen.py; x=$(sed -i y gen.py)', WIN)]).toEqual([])
  expect([...runOnlyScripts('cd C:/p && x=$(cd sub; pwd) && python gen.py', WIN)]).toEqual([])
  expect([...runOnlyScripts('cd C:/p && x=$(pwd && python gen.py', WIN)]).toEqual([])
  expect([...runOnlyScripts('cd C:/p && x="$(echo ")")" && python gen.py', WIN)]).toEqual([['gen.py', 'C:/p/gen.py']])
  // `node --test` takes exactly one file here; with none it runs every test file it finds.
  expect([...runOnlyScripts('cd C:/p && node --test', WIN)]).toEqual([])
  expect([...runOnlyScripts('cd C:/p && node --test a.mjs b.mjs', WIN)]).toEqual([])
  expect([...runOnlyScripts('cd C:/p && node --test --watch a.mjs', WIN)]).toEqual([])
  // PowerShell's `~` is the profile folder, not HOME.
  expect([...runOnlyScripts('cd ~/p; python gen.py', { windows: true, home: 'D:/h', userProfile: 'C:/Users/pat' }, true)])
    .toEqual([['gen.py', 'C:/Users/pat/p/gen.py']])
  expect([...runOnlyScripts('cd ~/p; python gen.py', { windows: true, home: 'D:/h', userProfile: 'C:/Users/pat' })])
    .toEqual([['gen.py', 'D:/h/p/gen.py']])
  expect([...runOnlyScripts('python /d/work/gen.py', LINUX)]).toEqual([['/d/work/gen.py', '/d/work/gen.py']]) // a real Linux folder
  expect([...runOnlyScripts('python /d/work/gen.py', WIN)]).toEqual([['/d/work/gen.py', 'D:/work/gen.py']])
  // A Bash brace group runs in this same shell; a PowerShell one is a script block, which may run anywhere.
  expect([...runOnlyScripts('cd C:/p && { python gen.py; } > out.txt', WIN)]).toEqual([['gen.py', 'C:/p/gen.py']])
  expect([...runOnlyScripts('cd C:/p; & { python gen.py }', WIN, true)]).toEqual([])
  for (const command of [
    'python gen.py', // no starting folder
    'cd sub && python gen.py', // a relative folder
    'cd "$DIR" && python gen.py', // a variable
    'cd ~ && python gen.py', // `~` is HOME, which this machine lacks
    'Push-Location C:/p; python gen.py', // not a plain cd
    'cd C:/p; Pop-Location; python gen.py',
    'cd C:/p && echo "x" > gen.py && python gen.py', // written by a redirect
    'cd C:/p && python gen.py && cp gen.py b.py', // named again
    'cd C:/p && python $D/gen.py', // a variable
    'cd C:/p && python `x`', // a backtick
    'cd C:/p && { python gen.py; } &', // a group in the background
    'cd C:/p && { cd sub; python gen.py; }', // a cd inside a group moves this shell
    'cd C:/p && python -c "import gen"', // inline code
    "cd C:/p && cat <<'EOF'\npython gen.py\nEOF", // a body is not a command
    'cd C:/p && source env.sh && python gen.py', // `source` runs a file in this shell: it may move it
    'cd C:/p && . env.sh && python gen.py',
    'cd C:/p && python gen.py & cp n.py gen.py', // a background job
    'cd C:/p && nohup sh -c "cp n.py gen.py" && python gen.py', // a detached one, and named inside a word
    'cd C:/p && Start-Process cp; python gen.py',
  ]) {
    expect([...runOnlyScripts(command, { windows: true, userProfile: 'C:/Users/pat' })]).toEqual([])
  }
})

test('Python that writes only the files its open() calls name: its other strings are only text', () => {
  // This session's own command, as it ran: a script editing a test file whose new case names app.py.
  const session = [
    `cd "C:/Users/pat/proj" && python - <<'PY'`,
    'import io',
    "p='hooks/register.ts'",
    "s=open(p,encoding='utf-8').read()",
    `s=s.replace("a", "b")`,
    "open(p,'w',encoding='utf-8',newline='').write(s)",
    "t='tests/review-guard.test.ts'",
    "s=open(t,encoding='utf-8').read()",
    `new='''  test('x', async () => {\n    await edit('C:/proj/app.py')\n  })\n'''`,
    's=s.replace("})", new, 1)',
    "open(t,'w',encoding='utf-8').write(s)",
    'PY',
    `grep -c 'x' hooks/register.ts`,
  ].join('\n')
  expect(shellWrites(session).sort()).toEqual(['hooks/register.ts', 'tests/review-guard.test.ts'])
  // As it really ran, with the tests after it: they may run what it wrote, so its strings count again.
  expect(shellWrites(`${session}; claude plugin test . 2>&1 | grep -E "^\\(fail\\)|pass$"`)).toContain('C:/proj/app.py')
  const py = (code: string, opener = "python - <<'PY'") => `${opener}\n${code}\nPY`
  // Every real write still counts: a name bound by a loop, built from parts, bound twice, a Path move, a
  // module that starts programs, an unquoted or piped body.
  for (const [code, opener] of [
    ["for n in ['a.py']:\n    open(n, 'w').write('x')"],
    ["base = 'src/'\nopen(base + 'a.py', 'w').write('x')"],
    ["p = 'x.ts'\np = 'a.py'\nopen(p, 'w').write('x')"],
    ["p = 'n.txt'\np = p.replace('n.txt', 'a.py')\nopen(p, 'w').write('x')"],
    ["p = 'n.txt'\nopen(p, 'w').write(open('a.py').read())\nopen('a.py', 'w')"],
    ["from pathlib import Path\nPath('a.py').write_text('x')\nopen('n.txt', 'w')"],
    ["import subprocess\nsubprocess.run('sed -i x a.py', shell=True)"],
    ["p = 'n.py'\nopen(p, 'w').write('x')\nx = 'a.py'", 'python - <<PY'],
    ["p = 'n.py'\nopen(p, 'w').write('x')\nx = 'a.py'", "python - <<'PY' | cat"],
    // `open` used without a call opens what no call names.
    ["len = open\nlen('a.py', 'w').write('x')"],
    ["[h.write('x') for h in map(open, ['a.py'], ['w'])]\nopen('n.py', 'w')"],
    ["def f(p):\n    open(p, 'w')\np = 'n.txt'\nf('a.py')"],
  ] as [string, string?][]) {
    expect([code, shellWrites(py(code, opener)).some(w => w.endsWith('a.py'))]).toEqual([code, true])
  }
  // A string that only says a name is text: here the script writes n.txt alone.
  expect(shellWrites(py("open('n.txt', 'w').write('see a.py')"))).toEqual([])
  expect(shellWrites(py("p = 'n.py'\nopen(p, 'w').write('see a.py')"))).toEqual(['n.py'])
  // A read-only command after it may name what it wrote.
  expect(shellWrites(`${py("p = 'n.py'\nopen(p, 'w').write('see a.py')")}\ngrep -c x n.py`)).toEqual(['n.py'])
  // But a script it writes that the same command then runs: what that script's text does is a write.
  const writesAndRuns = (after: string) => `${py("open('fix.py', 'w').write('''\nopen('src/app.py', 'w').write('x')\n''')")}\n${after}`
  for (const after of ['python fix.py', 'S=.; python "$S/fix.py"', "python - <<'P2'\nexec(open('fix.py').read())\nP2", 'cat fix.py | python']) {
    expect([after, shellWrites(writesAndRuns(after)).includes('src/app.py')]).toEqual([after, true])
  }
  // A note or data file it writes may be run later, so nothing is proven and its strings count as before.
  expect(shellWrites(py("p = 'n.txt'\nopen(p, 'w').write('sed -i x a.py')\nx = 'b.py'")).includes('b.py')).toBe(true)
  // `io` loads no program: `io.open` is an `open` like any other, so a code file it opens counts.
  expect(shellWrites(py("import io\nio.open('app.py', 'w').write('x')"))).toEqual(['app.py'])
  // The git guard is as before: a body that loads any module keeps its text, `io` included.
  expect(gitAction(py("import io\nprint('git push origin main')"))?.kind).toBe('push')
  expect(gitAction(py("print('git push origin main')"))).toBe(undefined)
})

test('a proven Python body never hides a file the same command may run, print into, or spell oddly', () => {
  const py = (code: string, opener = "python - <<'PY'") => `${opener}\n${code}\nPY`
  const has = (cmd: string, name: string) => shellWrites(cmd).some(w => w.endsWith(name))
  const writesFix = py(`open('fix.py', 'w').write("open('src/app.py', 'w').write('x')")`)
  // Anything after it that runs something, whether or not it spells the file's name.
  for (const after of ['python -m fix', 'python -c "import fix"', 'python f*.py', 'for f in *.py; do python "$f"; done', 'pytest -q', 'make', 'npm test', 'python "fi"x.py', `python - <<'P2'\nimport fix\nP2`]) {
    expect([after, has(`${writesFix}\n${after}`, 'src/app.py')]).toEqual([after, true])
  }
  // What it prints, sent to a file, into a substitution, or by exec.
  const prints = `print("cp x src/app.py; true")`
  for (const cmd of [`${py(prints, "python - <<'PY' > gen.sh")}\nbash gen.sh`, `eval $(${py(prints)}\n)`, `exec > gen.sh\n${py(prints)}`, `echo "$(python fix.py)"\n${py("open('n.py', 'w')\nx = 'src/app.py'")}`]) {
    expect([cmd, has(cmd, 'src/app.py')]).toEqual([cmd, true])
  }
  // A proven target that starts with `-` is a name, not a flag.
  expect(shellWrites(py("open('-x.py', 'w').write('1')"))).toEqual(['-x.py'])
  // Escapes: `\N{...}` is not read, so nothing is proven and the strings count; a `\` before a line break goes.
  expect(has(py("open('\\N{LATIN SMALL LETTER A}pp.py', 'w')\nx = 'src/app.py'"), 'src/app.py')).toBe(true)
  expect(shellWrites(py("open('a\\\npp.py', 'w').write('x')"))).toContain('app.py')
  expect(shellWrites(py("open(b'\\u0061pp.py', 'w').write(b'x')"))).not.toContain('app.py')
  // Python writes by other calls count (they did not before): copies, moves, a mode by name, FileIO, programs.
  for (const code of ["import shutil\nshutil.copy('/tmp/x.py', 'src/app.py')", "import os\nos.replace('/tmp/x.py', 'src/app.py')",
    "f = open('src/app.py', mode='w')\nprint('x', file=f)", "import io\nio.FileIO('src/app.py', 'w')",
    "from pathlib import Path\nPath('/tmp/x.py').rename('src/app.py')", "import subprocess\nsubprocess.run(['sed', '-i', 'x', 'src/app.py'])"]) {
    expect([code, has(py(code), 'src/app.py')]).toEqual([code, true])
  }
  // Windows opens `app.py.`, `app.py ` and `app.py::$DATA` as app.py; `C:app.py` is a drive-relative name.
  for (const name of ['src/app.py.', 'src/app.py ', 'src/app.py::$DATA', 'src/app.py:s', 'C:app.py']) expect([name, languageOf(name)]).toEqual([name, 'Python'])
  // Off Windows a colon is part of a name: `notes:fix.py` is a Python file there.
  expect(languageOf('/home/u/notes:fix.py')).toBe('Python')
  expect(shellWrites("echo x > 'notes:fix.py'")).toEqual(['notes:fix.py'])
  // A body that writes Python and imports anything may run what it wrote (`python -` looks here first).
  expect(has(py("open('json.py', 'w').write(\"open('app.py', 'w').write('x')\")\nimport json"), 'app.py')).toBe(true)
  // A variable set for a program, a program by path, `rg --pre`: none is read-only.
  for (const after of ['X=/cat python gen.py', './bin/cat gen.py', 'PATH=. cat gen.py', 'rg --pre python x gen.py', 'rg --pre=python x gen.py']) {
    const cmd = `${py("open('gen.py', 'w').write(\"open('app.py', 'w').write('x')\")")}\n${after}`
    expect([after, has(cmd, 'app.py')]).toEqual([after, true])
  }
})

test('the start folder and run scripts are read only where the shell reads them the same way', () => {
  const WIN = { windows: true, home: 'C:/Users/pat', userProfile: 'C:/Users/pat' }
  expect(startFolder('cd C:/p && x=$(pwd) && python gen.py', WIN)).toBe('C:/p')
  // Inside double quotes a doubled `\` keeps the quotes where they are; `\"` moves where one ends.
  expect(startFolder('cd "C:/p" && echo "a\\\\b" && python gen.py', WIN)).toBe('C:/p')
  expect(startFolder('cd C:/p && echo "a\\"; . x.sh; echo \\"" && python gen.py', WIN)).toBe(undefined)
  for (const cmd of [
    'cd C:/proj/$(date +%F) && python gen.py && cp a b', // a substitution in the folder's name
    'cd "C:/p$(echo /sub)" && python gen.py && cp a b',
    'cd C:/a\\;b && python gen.py && cp a b', // bash reads `C:/a;b`
    'cd C:/p && echo \\\' && . ./go.sh && python gen.py', // an escaped quote hides a source
    "cd C:/p; echo $'\\'' '$(' ; . x.sh ; echo ')' #'", // an ANSI-C string
    'cd C:/p && "c"d sub && python gen.py', // a quoted cd
    "cd C:/p && c''d sub && python gen.py",
    'cd C:/p && eval "c""d sub" && python gen.py',
    'cd C:/p && x=$(nohup y) && python gen.py', // detaches, inside a substitution
  ]) {
    expect([cmd, startFolder(cmd, WIN)]).toEqual([cmd, undefined])
  }
  expect([...runOnlyScripts('cd C:/p && python $(x).py', WIN)]).toEqual([])
  expect([...runOnlyScripts('cd C:/p; echo `pwd`; python gen.py', WIN, true)]).toEqual([]) // PowerShell's backtick escapes
  // PowerShell's `$()` runs in the same session, so it may move it; and `iex` and aliases run text as a cd.
  for (const cmd of ["cd C:/p; $(iex ('c'+'d C:/other')); python gen.py", "cd C:/p; $a='c'+'d C:/o'; iex $a; python gen.py", "cd C:/p; Invoke-Expression $a; python gen.py", 'cd C:/p; sal x Set-Location; x C:/o; python gen.py']) {
    expect([cmd, startFolder(cmd, WIN, true)]).toEqual([cmd, undefined])
  }
  // A quote inside a `#` comment opens nothing in bash, but would swallow lines here; an alias makes a new cd.
  expect(startFolder("cd C:/p\ntrue # '\n\"c\"d C:/o\ntrue # '\npython gen.py", WIN)).toBe(undefined)
  expect(startFolder("cd C:/p\nalias x='c''d'\nx C:/o\npython gen.py", WIN)).toBe(undefined)
})

test('knows which code files a shell command writes', async () => {
  // PowerShell's and cmd's own copies, moves and writes count, as commands; the same words in a note don't.
  for (const c of ['copy a.py b.py', 'cpi a.py b.py', 'mi a.py b.py', 'ren a.py b.py', 'rni a.py b.py', 'Rename-Item a.py b.py',
    "x; sc b.py 'v'", 'ForEach-Object {copy a.py b.py}', 'iwr https://x -OutFile b.py', "New-Item b.py -Value 'x'"]) {
    expect(shellWrites(c).includes('b.py')).toBe(true)
  }
  expect(shellWrites("cat > n.md <<'EOF'\nMove scan.ts later, then copy it\nEOF")).toEqual([])
  expect(shellWrites("sed -i 's/a/b/' src/app.py")).toEqual(['src/app.py'])
  expect(shellWrites("cat > hooks/scan.ts <<'EOF'\nconst a = 1\nEOF")).toEqual(['hooks/scan.ts'])
  expect(shellWrites('echo "x = 1" >> "my app/settings.py"')).toEqual(['my app/settings.py'])
  expect(shellWrites("python - <<'PY'\nimport pathlib\npathlib.Path('tests/a.test.ts').write_text('x')\nPY")).toEqual(['tests/a.test.ts'])
  // In Python code a raw, bytes or unicode string's prefix is not part of the name; in bash it is.
  const edits = (name: string) => `s = open(${name}).read()\nopen(${name}, 'w').write(s.replace('a', 'b'))`
  expect(shellWrites(`python - <<'PY'\np = r'C:\\proj\\hooks\\register.ts'\n${edits('p')}\nPY`)).toEqual(['C:\\proj\\hooks\\register.ts'])
  expect(shellWrites(`python3 -I - <<'PY'\n${edits(`Rb"src/app.py"`)}\nPY`)).toEqual(['src/app.py'])
  expect(shellWrites(`py - <<'PY'\np = r'C:\\proj\\register.ts'\n${edits('p')}\nPY`)).toEqual(['C:\\proj\\register.ts']) // the launcher
  expect(shellWrites(`cat > fix.py <<'EOF'\n${edits(`u'src/app.py'`)}\nEOF\npython fix.py`)).toEqual(['fix.py', 'src/app.py'])
  expect(shellWrites(`python - <<'PY'\nopen(f'src/a.py', 'w').write('x')\nPY`)).toEqual(['src/a.py'])
  expect(shellWrites(`python - <<'PY'\np = 0 or'src/a.py'\n${edits('p')}\nPY`)).toEqual(['src/a.py']) // a keyword glued on
  expect(shellWrites(`python - <<'PY'\n${edits(`'src/app\\x2epy'`)}\nPY`)).toContain('src/app.py') // a string's escapes are read
  expect(shellWrites(`python - <<'PY'\n${edits(`'C:\\\\proj\\\\a.py'`)}\nPY`)).toContain('C:\\proj\\a.py')
  expect(shellWrites(`python - <<'PY'\nd = {'k':r'src/a.py'}\n${edits("d['k']")}\nPY`)).toContain('src/a.py') // a string anywhere
  expect(shellWrites(`python - <<'PY'\nbase = 'src/'\n${edits("base+'b.py'")}\nPY`)).toContain('b.py')
  expect(shellWrites(`cat > fix.pyw <<'EOF'\n${edits(`r'src/app.py'`)}\nEOF\npython fix.pyw`)).toContain('src/app.py') // .pyw too
  expect(shellWrites("sed -i s/a/b/ r'app.py'")).toEqual(['rapp.py']) // bash's own word
  // A command that only writes and runs scratch scripts (`scratchFile` says which targets are scratch)
  // writes nothing their text names. A stand-in for `scratchTargets`: a full path with no variable, `~` or
  // backtick left (`inScratch` also refuses `..`).
  const scratch = (t: string) => !/[$`~]/.test(t) && t.startsWith('/s/') && !t.split('/').includes('..')
  const body = "\nsed -i x a.py && cp b.py c.py\nEOF\n"
  expect(shellWrites(`cat > /s/p.sh <<'EOF'${body}bash /s/p.sh`)).toContain('a.py') // no scratch check given: as before
  // Blanked: what is left is each target.
  for (const [cmd, want] of [
    [`cat > /s/p.sh <<'EOF'${body}bash /s/p.sh`, ['/s/p.sh']], // the target is still a write
    [`cat > "/s/p.sh" <<'EOF'${body}bash -x "/s/p.sh" a.py 'x y' 2>&1 | tail -20`, ['/s/p.sh']], // flags, arguments, a tail
    [`cat >> /s/p.py <<-'EOF'${body}python3 -I /s/p.py`, ['/s/p.py']], // appended to, `<<-`
    [`cat <<"EOF" > /s/p.mjs${body}node --no-warnings /s/p.mjs && deno run --allow-read /s/p.mjs`, ['/s/p.mjs']],
    [`cat.exe > /s/a.sh <<'EOF'${body}cat > /s/b.sh <<'EOF'${body}bash /s/a.sh; bash /s/b.sh`, ['/s/a.sh', '/s/b.sh']], // two scripts
    [`S=/s\ncat > $S/p.sh <<'EOF'${body}bash $S/p.sh`, []], // (a variable target is no name)
    [`S='/s'; cat > \${S}/p.sh <<'EOF'${body}bash "\${S}/p.sh"`, []], // on its line, read braced
    [`S="/s" && T=/s/x\ncat > $T.sh <<'EOF'${body}`, []], // two, and the last value set is the one
  ] as const) {
    expect([cmd, shellWrites(cmd, scratch).sort()]).toEqual([cmd, [...want].sort()])
  }
  // Kept: the same as with no scratch check. Each case breaks one of the forms.
  for (const cmd of [
    `cat > /s/p.sh <<EOF${body}`, // unquoted: bash runs its $(...) as it writes
    `cat > /proj/p.sh <<'EOF'${body}`, // not scratch
    `cat > /s/p.sh > /proj/q.sh <<'EOF'${body}`, // a second target
    `cat > "/s/a;b.sh" <<'EOF'${body}`, // a `;` in the name
    `cat <<'EOF' | tee /s/p.sh${body}`, // piped on
    `cat <<'EOF' 2>/s/e | bash${body}`, // a redirect of stderr only, and piped on
    `{\ncat 2>/s/e <<'EOF'${body}} | bash`, // in a group
    `(cat > /s/p.sh <<'EOF'${body})`, // in a subshell
    `bash > /s/log <<'EOF'${body}`, // read by bash, which runs it
    `cat /proj/a.sh - > /s/p.sh <<'EOF'${body}`, // cat reads a file too
    `cat > /s/p.sh <<'EOF'; echo hi${body}`, // something after it on its line
    `cat > /s/p.sh <<'A' 3<<'B'\nsed -i x a.py\nA\nx\nB\n`, // two here-documents on one line
    `cat > /s/p.sh <<'EOF'\nsed -i x a.py\n`, // no end line: the split is a guess
    `echo a\\ b; cat > /s/p.sh <<'EOF'${body}`, // a backslash in the command's own text
    `cat > /s/x\u00a0/../../proj/fix.sh <<'EOF'${body}`, // a no-break space, which bash takes for part of the name
    `cat > '/s/q'/../../proj/fix.sh <<'EOF'${body}`, // a name in parts
    `cat > /s/p* <<'EOF'${body}`, // a glob
    `cat <<'EOF' > /s/p.sh &> /proj/x.sh${body}`, // `&>`
    `cat <<'EOF' > /s/p.sh 1<>/proj/x.sh${body}`, // `<>`
    `cat > /s/p.sh <<'EOF'${body}bash <<'X'\nsed -i x a.py\nX\n`, // another here-document, run
    `cat > /s/list <<'EOF'${body}python - <<'PY'\nopen('a.py', 'a')\nPY\n`,
    // Variables
    `cat > $S/p.sh <<'EOF'${body}S=/s`, // set after
    `S=/s cat > $S/p.sh <<'EOF'${body}`, // set for cat alone
    `S=/s | true\ncat > $S/p.sh <<'EOF'${body}`, // set in a pipe's subshell
    `S=/s & cat > $S/p.sh <<'EOF'${body}`, // set in the background
    `if [ -d /x ]; then S=/s; fi\ncat > $S/p.sh <<'EOF'${body}`, // set on one branch
    `S=/s\nprintf -v S /proj\ncat > $S/p.sh <<'EOF'${body}`, // set again by a command
    `UID=/s\ncat > $UID/p.sh <<'EOF'${body}`, // bash keeps its own value
    `PATH=/proj/bin\ncat > /s/p.sh <<'EOF'${body}`, // `cat` may be another program
    `S=$HOME/s\ncat > $S/p.sh <<'EOF'${body}`, // set to a variable's value
    `cat > $X/p.sh <<'EOF'${body}`, // never set
    `S=/s/x\ncat > \${S:+/proj}/fix.sh <<'EOF'${body}`, // not a plain read of S
    `S=/s\ncat > '$S'/p.sh <<'EOF'${body}`, // a `$` in single quotes is no variable
    // What runs
    `cat > /s/list <<'EOF'${body}cat /s/list | while read f; do sed -i x "$f"; done`, // its text read as a list
    `cat > /s/list <<'EOF'${body}xargs sed -i x < /s/list`,
    `cat > /s/list <<'EOF'${body}bash -c 'cat /s/list' | sh`, // code given to bash -c
    `cat > /s/list <<'EOF'${body}perl -pe1 /s/list | sh`, // code glued to a flag
    `cat > /s/p.sh <<'EOF'${body}bash /s/p.sh | bash`, // its output run
    `cat > /s/p.sh <<'EOF'${body}bash /s/p.sh > /proj/x.sh`, // its output written
    `cat > /s/p.sh <<'EOF'${body}bash /proj/p.sh`, // a project script run
    `cat > /s/p.sh <<'EOF'${body}cp /s/p.sh /proj/`, // copied on
    `cat > /s/p.sh <<'EOF'${body}git apply /s/*.diff`,
    `ln -s /proj/src /s/link\ncat > /s/link/x.sh <<'EOF'${body}`, // written through a link
    `alias cat=bash\ncat > /s/p.sh <<'EOF'${body}`,
    `cat() { bash; }\ncat > /s/p.sh <<'EOF'${body}`,
    `source /proj/env.sh\ncat > /s/p.sh <<'EOF'${body}`,
    `cat > /s/p.sh <<'EOF'${body}# a comment`,
  ]) {
    expect([cmd, shellWrites(cmd, scratch), shellWrites(cmd).includes('a.py')]).toEqual([cmd, shellWrites(cmd), true])
  }
  // A scratch check that throws throws on (`blankedSafely` keeps every write then).
  expect(() => shellWrites(`cat > /s/p.sh <<'EOF'${body}`, () => { throw new Error('no') })).toThrow()
  // Notes written with `time` and `textwrap`, then a script only run: that script is not a write.
  for (const [mod, use] of [['textwrap', "textwrap.dedent('x')"], ['textwrap', "textwrap.indent('x', ' ')"], ['time', 'str(time.time())']]) {
    expect(shellWrites(`python - <<'PY'\nimport ${mod}\nopen('notes.md', 'w').write(${use})\nPY\npython gen.py`)).toEqual([])
  }
  expect(shellWrites(`bash <<'EOF'\nsed -i s/a/b/ r'app.py'\nEOF`)).toEqual(['rapp.py']) // a shell's body too
  expect(shellWrites('cp old.py new.py')).toEqual(['old.py', 'new.py'])
  expect(shellWrites('Get-Content a.ps1 | Out-File b.ps1')).toEqual(['a.ps1', 'b.ps1'])
  expect(shellWrites('npx prettier --write src/a.ts src/b.ts')).toEqual(['src/a.ts', 'src/b.ts'])
  expect(shellWrites('ruff check --fix app.py && black app.py')).toEqual(['app.py'])
  // Wildcards, variables and sed patterns are not file names.
  expect(shellWrites('cp "$SRC"/hooks/*.ts "$DST/hooks/" && cp a.ts b.ts')).toEqual(['a.ts', 'b.ts'])
  expect(shellWrites("sed -i 's/old/hooks\\/agents.ts/' notes/NOTICE.md")).toEqual([])
  expect(shellWrites('Copy-Item C:\\proj\\a.ps1 C:\\proj\\b.ps1')).toEqual(['C:\\proj\\a.ps1', 'C:\\proj\\b.ps1'])
  expect(shellWrites('cp "$DST"/hooks/register.ts "$DEV/hooks/register.ts"')).toEqual([])
  expect(shellWrites('cat > "$S/t.ts" <<\'EOF\'\nx\nEOF')).toEqual([])
  expect(shellWrites("ssh box \"sed -i 's/a/b/' app.py\"")).toEqual([]) // written on another machine
  // `>|` writes like `>`, and so do numbered and `&` redirects; `2>&1` writes no file.
  for (const r of ['>|', '1>', '&>', '&>>', '2>|', '>>']) expect([r, shellWrites(`echo x ${r} src/app.py`)]).toEqual([r, ['src/app.py']])
  expect(shellWrites('python g.py 2>&1')).toEqual([])
  // A quoted test case with a line break or a `\n`/`\r` escape is not a file name; the names in it are.
  // One with only a spaced operator may be a real name, so it counts whole and in pieces.
  const probe = "cat > \"$S/p.mjs\" <<'EOF'\nconst c = ['true\\r# ; bash /tmp/t/x.py', 'cat x >| ~/bin/python\\npython a.py', \"x &&git.py\", 'one\ntwo.py']\nwriteFileSync(f, c)\nEOF\nnode \"$S/p.mjs\""
  expect(shellWrites(probe).sort()).toEqual(['/tmp/t/x.py', 'a.py', 'git.py', 'two.py', 'x &&git.py'])
  // A space alone, `&` or `#` with no space, and a Windows path's `\t` or `\n` keep the name whole.
  expect(shellWrites('cp "my file.py" "R&D/#1.py" "C:\\tools\\new.py" x')).toEqual(['my file.py', 'R&D/#1.py', 'C:\\tools\\new.py'])
  // A real name with a spaced operator or `# ` is kept whole, a Windows one too.
  for (const name of ['R & D/app.py', 'notes # 2.py', 'x ; y.py', 'a > b.py', 'C:\\R & D\\new.py']) {
    expect([name, shellWrites(`cp a.txt "${name}"`).includes(name)]).toEqual([name, true])
  }
  // A quoted line of code holding the other quote (a script's text), not a name: the names in it count.
  const codeLine = `sed -i x a.txt; python fix.py "import { a, b } from '../hooks/register.ts'" 'x = open("lib/util.py")'`
  const named = shellWrites(codeLine)
  expect(named.includes('../hooks/register.ts')).toBe(true)
  expect(named.includes('lib/util.py')).toBe(true)
  expect(named.some(n => n.includes('import') || n.includes('open('))).toBe(false)
  // A real name with an apostrophe is still one name, with a space in it too, a Windows one as well.
  for (const name of ["pat's/app.py", "pat's notes/app.py", "C:\\Users\\pat\\Pat's Files\\app.py"]) {
    expect([name, shellWrites(`cp a.txt "${name}"`)]).toEqual([name, [name]])
  }
  // Quoted parts are read one by one, as bash reads them, and quotes left around a name are dropped.
  expect(shellWrites(`cp a.txt "src"' my'"/x.py"`)).toEqual(['src my/x.py'])
  expect(shellWrites(`cp a.txt "'app.py'"`)).toEqual(['app.py'])
  // Windows paths whose `\n` or `\r` is a folder's first letter, and `<>` writes, count as before.
  for (const [c, name] of <[string, string][]>[
    ['Copy-Item a.py src\\new.py', 'src\\new.py'], ['Copy-Item a.py .\\src\\new.py', '.\\src\\new.py'],
    ['Move-Item tmp.ts hooks\\register.ts', 'hooks\\register.ts'], ['cp a.py scripts\\release.py', 'scripts\\release.py'],
    ['Copy-Item "a.py" "lib\\nodes.py"', 'lib\\nodes.py'], ['Set-Content -Path scripts\\release.py -Value x', 'scripts\\release.py'],
    ['echo x 1<>src/a.py', 'src/a.py'], ['exec 3<>src/a.py', 'src/a.py'], ['cat <>src/a.py', 'src/a.py'],
  ]) expect([c, shellWrites(c).includes(name)]).toEqual([c, true])
  // Each trigger alone splits a snippet: a `\n` escape (the whole is then no name), and `# `.
  expect(shellWrites("cp a.txt b.txt; echo 'x ; /tmp/y\\na.py'")).toEqual(['a.py'])
  expect(shellWrites("cp a.txt b.txt; echo 'x # a.py'").sort()).toEqual(['a.py', 'x # a.py'])
  // The names in a snippet are split at the outer word pattern's own delimiters too.
  expect(shellWrites('cp a.txt b.txt; python -c "open(\'x.py\',\'w\')\nprint(1)"')).toContain('x.py')
  // A script run after here-documents that only write notes is not written (the one exception).
  const notes = "python -I - <<'EOF'\nimport pathlib\npathlib.Path('notes.md').write_text('x')\nEOF\n"
  expect(shellWrites(notes + 'python -I .scripts/memory-map.py 2>&1 | tail -2')).toEqual([])
  expect(shellWrites(notes + '.venv/bin/python run.py && node build.js; pwsh -NoProfile -File deploy.ps1')).toEqual([])
  expect(shellWrites(notes.replace("'notes.md'", "'Changes/Change log.md'") + 'python -I .scripts/memory-map.py')).toEqual([])
  expect(shellWrites(notes.replace(/\n/g, '\r\n') + 'python run.py')).toEqual([]) // CRLF
  expect(shellWrites("cat > notes.md <<'EOF'\nsee app.py\nEOF\npython app.py")).toEqual([]) // nothing writes code; the target is a note
  // `cat` passes data on, and what a trusted body says is not a mention of the script.
  expect(shellWrites("cat > plan.md <<'EOF'\nrun app.py\nEOF\n" + notes + 'python app.py')).toEqual([])
  expect(shellWrites("cat <<'EOF' >> plan.md\nrun app.py\nEOF\n" + notes + 'python app.py')).toEqual([])
  expect(shellWrites("cat <<'A' > n.md\nhello\nA\n" + notes + 'python app.py')).toEqual([])
  expect(shellWrites(notes.replace("python -I -", 'py -3 -') + 'py -3 app.py')).toEqual([])
  expect(shellWrites(notes.replace("python -I -", 'python') + 'python -X utf8 -W ignore app.py')).toEqual([])
  expect(shellWrites("python -I - <<'EOF'\nimport sys, re\nsys.stdout.reconfigure(encoding='utf-8')\nopen('n.md', 'w').write(re.sub('a', 'b', 'x'))\nEOF\npython app.py")).toEqual([])
  expect(shellWrites(notes.replace(/\n(?!EOF)/g, '\n\t').replace('<<', '<<-').replace('\nEOF', '\n\tEOF') + 'python app.py')).toEqual([])
  expect(shellWrites("node - <<'EOF'\nrequire('fs').writeFileSync('notes.md', 'x')\nEOF\nnode build.js")).toEqual([])
  // Realistic notes scripts still pass: appending a log line, a JSON file, several writes.
  expect(shellWrites("python -I - <<'EOF'\nfrom datetime import datetime\nwith open('Changes/Change log.md', 'a', encoding='utf-8') as f:\n    f.write(datetime.now().isoformat() + ' done')\nEOF\npython -I .scripts/memory-map.py")).toEqual([])
  expect(shellWrites("python -I - <<'EOF'\nimport json\njson.dump({'ok': True}, open('state.json', 'w'))\nopen('notes.md', 'a').write('x')\nEOF\npython run.py")).toEqual([])
  expect(shellWrites("python -I - <<'EOF'\nfrom datetime import datetime\nnow = datetime.now()\nlines = ['Edited hooks/scan.ts', 'costs $5']\n" +
    "with open('Changes/Change log.md', 'a', encoding='utf-8') as f:\n    f.write(f'\\n## {now:%Y-%m-%d %H:%M} - x\\n' + '\\n'.join(lines))\nEOF\npython -I .scripts/memory-map.py 2>&1 | tail -2")).toEqual([])
  // Outside that shape the script still counts: an extra review beats a missed edit.
  expect(shellWrites("sed -i 's/a/b/' app.py && python run.py")).toEqual(['app.py', 'run.py'])
  expect(shellWrites("sed -i 's/a/b/' run.py && python run.py")).toEqual(['run.py'])
  expect(shellWrites('python gen.py > gen.py')).toEqual(['gen.py'])
  expect(shellWrites("perl -pi -e 's/a/b/' app.py")).toEqual(['app.py']) // perl -i edits, it is not a run
  for (const [c, file] of [
    ['black . && python app.py', 'app.py'], // formatters, fixers and patches change files they never name
    ['npx prettier --write . && node server.js', 'server.js'],
    ['git apply fix.patch && python app.py', 'app.py'],
    ['cp -r tpl/ src/ && python src/app.py', 'src/app.py'],
    ["sed -i 's/a/b/' src/*.py && python src/app.py", 'src/app.py'], // a glob
    ['cp -r node app.js', 'app.js'], // a writer outside any heredoc trusts nothing
    [`python -c "open('app.py','w').write('x')" && python app.py`, 'app.py'],
    [notes.replace("'notes.md'", "'gen' + '.py'") + 'python gen.py', 'gen.py'], // a built file name
    [notes.replace('notes.md', 'app.py') + 'python app.py', 'app.py'], // the heredoc writes code
    [notes + "sed -i 's/a/b/' gen.py && git commit -am \"fix: python gen.py works\"", 'gen.py'],
    // Inline code or a module next to the heredoc can write files it never names.
    [notes + `python -c "import subprocess; subprocess.run(['ruff','format'])"\npython app.py`, 'app.py'],
    [notes + 'python -m black . && python app.py', 'app.py'],
    [notes + "node -e \"require('child_process').execSync('npx prettier -w .')\" && node build.js", 'build.js'],
    [notes + 'bash -c "black ." && python app.py', 'app.py'],
    // Interpreter flags are a short list: any other spelling might be inline code.
    ...[`python -Ic "print('x', file=open('app.py', mode='a'))"`, `node --eval "require('fs').appendFileSync('app.py', 'x')"`,
      `node -pe "require('fs').copyFileSync('a', 'app.py')"`, `deno eval "Deno.writeTextFileSync('app.py', 'x')"`]
      .map(c => [notes + c + '\npython -I app.py', 'app.py'] as const),
    ["node --input-type=module - <<'EOF'\nimport fs from 'child_process'\nEOF\n" + notes + 'python app.py', 'app.py'],
    // Only Python or Node reading stdin is trusted: not a flag that takes code or a module.
    [notes.replace('python -I -', 'python -c "import sys; exec(sys.stdin.read())"') + 'python app.py', 'app.py'],
    // A writer and an interpreter-like word in plain text: `cp node app.js` copies, it runs nothing.
    [notes + "echo 'python app.py' >> plan.md && cp -r node app.js", 'app.js'],
    // Every file-opening call must take a plain literal: a slice, `%`, data or a listing may name code.
    [notes.replace("pathlib.Path('notes.md')", "pathlib.Path('app.pyc'[:-1])") + 'python app.py', 'app.py'],
    ["python - <<'EOF'\nopen('app.%s' % 'py', 'w').write('x')\nEOF\npython app.py", 'app.py'],
    ["python - <<'EOF'\nopen(open('target.txt').read().strip(), 'w').write('x')\nEOF\npython app.py", 'app.py'],
    ["python - <<'EOF'\nimport os\nfor e in os.scandir('.'):\n    open(e.path, 'a').write('#')\nEOF\npython app.py", 'app.py'],
    ["python - <<'EOF'\nimport os\nopen(os.environ['TARGET'], 'w').write('x')\nEOF\npython app.py", 'app.py'],
    ["python - <<'EOF'\nopen(bytes.fromhex('6170702e7079').decode(), 'w').write('x')\nEOF\npython app.py", 'app.py'],
    ["python - <<'EOF'\no = open\no('notes.md', 'w').write('x')\nEOF\npython app.py", 'app.py'],
    [notes + "python - <<'EOF'\neval(compile(open('gen.txt').read(), 'g', 'exec'))\nEOF\npython app.py", 'app.py'],
    ["node - <<'EOF'\nrequire('fs').writeFileSync('app.js_'.slice(0, -1), 'x')\nEOF\nnode app.js", 'app.js'],
    ["node - <<'EOF'\nconst fs = require('fs'); fs['writeFileSync']('notes.md', 'x')\nEOF\nnode app.js", 'app.js'],
    ["py -3 - <<'EOF'\nfrom pathlib import Path\nPath('app.pyc'[:-1]).write_text('x')\nEOF\npy -3 app.py", 'app.py'],
    // Only listed calls are trusted: an opener nobody listed may write anything.
    ["python - <<'EOF'\nimport io\nio.FileIO(bytes([97,112,112,46,112,121]).decode(),'w').write(b'print(1)')\nEOF\npython app.py", 'app.py'],
    ["node - <<'EOF'\nconst fs = require('fs')\nfs.WriteStream(String.fromCharCode(97,112,112,46,106,115)).write('x')\nEOF\nnode app.js", 'app.js'],
    ["node - <<'EOF'\nrequire('fs').truncateSync(String.fromCharCode(97,112,112,46,106,115))\nEOF\ncat > n.md <<'EOF'\nsed -i\nEOF\nnode app.js", 'app.js'],
    ["node - <<'EOF'\nconst {truncateSync: t} = require('fs'); t('notes.md')\nEOF\n" + notes + 'node app.js', 'app.js'],
    ["python - <<'EOF'\nfrom os import truncate\nopen('notes.md','w').write('x')\nEOF\npython app.py", 'app.py'],
    ["python - <<'EOF'\ndef w(n):\n    open('notes.md','w').write(n)\nw('x')\nEOF\npython app.py", 'app.py'],
    ["cat > notes.md <<'EOF'\nuse sed -i here\nEOF\nsort -oapp.py data.txt; python app.py", 'app.py'], // sort -o writes
    // A written name must be plain ASCII and not code: no escapes, no extension-less code files.
    ["python -I - <<'EOF'\nopen('Dockerfile','w').write('FROM x')\nEOF\npython -I app.py", 'Dockerfile'],
    ["python -I - <<'EOF'\nopen('app\\x2epy','w').write('x')\nEOF\npython -I app.py", 'app.py'],
    ["node - <<'EOF'\nrequire('fs').writeFileSync('app\\x2ejs','x')\nEOF\nnode app.js", 'app.js'],
    ["python -I - <<'EOF'\nopen('café.py','w').write('x')\nEOF\npython -I app.py", 'app.py'],
    ["python - <<'EOF'\nopen('app.py.', 'w').write('print(1)')\nEOF\npython app.py", 'app.py'], // Windows drops the dot
    ["python - <<'EOF'\nopen('app.py ', 'w').write('print(1)')\nEOF\npython app.py", 'app.py'],
    ["python - <<'EOF'\nimport pathlib\npathlib.Path(\"src\", \"..\", \"app.py\").write_text(\"print(1)\")\nEOF\npython app.py", 'app.py'],
    ['cat -"\\" <<EOF -\\""\nsed -i s/a/b/ app.py\nEOF\npython app.py', 'app.py'], // an escaped quote: bash sees no heredoc
    ["python -I - <<'EOF'\nimport runpy\nopen('notes.md','w').write('x')\nrunpy.run_path('gen.txt')\nEOF\npython app.py", 'app.py'],
    ["python -I - <<'EOF'\nimport os\nopen('notes.md','w').write('x')\nEOF\npython app.py", 'app.py'], // os is not a listed module
    ["python - <<EOF\nopen('notes.md','w').write('`id`')\nEOF\npython app.py", 'app.py'], // an unquoted body is expanded
    // Running what a body wrote, however it is spelled or fed in.
    [notes + "cat > gen.txt <<'EOF'\nblack .\nEOF\nbash < gen.txt\npython app.py", 'app.py'],
    [notes.replace('notes.md', 'gen.txt') + 'python -X utf8 gen.txt && python app.py', 'app.py'],
    [notes.replace('notes.md', './gen.txt') + 'python gen.txt && python app.py', 'app.py'],
    // What a body writes and the command then runs is new code.
    [notes + "cat <<'EOF' > gen.txt\nprint(1)\nEOF\npython gen.txt\npython app.py", 'app.py'],
    [notes + "cat > gen <<'EOF'\necho hi\nEOF\nsh gen && python app.py", 'app.py'],
    [notes.replace('notes.md', 'gen.txt') + 'python gen.txt && python app.py', 'app.py'],
    [notes + "python <(cat <<'EOF'\nprint(1)\nEOF\n)\npython app.py", 'app.py'], // process substitution
    ["cat <<'EOF' | bash && python app.py\nblack .\nEOF", 'app.py'], // a body piped on, same line
    ['echo "black ." | bash\n' + notes + 'python app.py', 'app.py'], // an interpreter reading a pipe
    [notes.replace("'notes.md'", "'$F'") + 'python app.py', 'app.py'], // a variable in an unquoted heredoc
    // Commands outside the heredocs must be interpreters or read-only tools.
    ...['git checkout other -- tools', 'unzip -o tools.zip', 'rsync -a staging/ tools/', 'robocopy staging tools /E',
      'ruff format .', 'isort .', 'chmod +x gen && ./gen'].map(w => [notes + w + '\npython -I tools/map.py', 'tools/map.py'] as const),
    // The heredoc split follows bash: only an exact terminator ends a body, and an open quote trusts nothing.
    ["python - <<'EOF'\nopen('notes.md','w').write('x')\ns = '''\nEOF \n'''\nimport shutil; shutil.copytree('s', 't')\nEOF\npython app.py", 'app.py'],
    ['echo "\ncat <<EOF\n"\nsed -i s/a/b/ tools/*.py\n' + notes + 'python -I tools/map.py', 'tools/map.py'],
    [notes + 'echo "x;cat <<END" >> n.md\nblack .\nEND\npython app.py', 'app.py'], // a terminated fake heredoc
    ["cat > n.md <<A; python - <<B\nnote\nA\nimport subprocess\nsubprocess.run('black .', shell=True)\nB\npython app.py", 'app.py'],
    // A shell heredoc runs its commands, so writers in there count like writers outside.
    ["bash <<'EOF'\nblack .\nEOF\npython app.py", 'app.py'],
    ["bash <<'EOF'\ngit apply fix.patch\nEOF\npython app.py", 'app.py'],
    ["sh <<'EOF'\npatch -p1 < fix.diff\nEOF\npython app.py", 'app.py'],
    ["bash <<'EOF'\ncp -r ../template/. .\nEOF\nnode index.js", 'index.js'],
    ["bash <<'EOF'\ntar -xzf release.tgz -C .\necho done | tee NOTES.md\nEOF\nnode server.js", 'server.js'],
    ["cat <<'EOF' | bash\nruff check --fix .\nEOF\npython app.py", 'app.py'],
    ["pwsh -NoProfile -Command - <<'EOF'\nSet-Content notes.md x\nEOF\npwsh -File build.ps1", 'build.ps1'],
    // Code that runs a process, copies, unpacks or builds a path writes files it never names.
    ["python - <<'EOF'\nimport subprocess\nsubprocess.run('git apply fix.patch', shell=True)\nEOF\npython app.py", 'app.py'],
    ["python - <<'EOF'\nimport subprocess\nsubprocess.run(['git', 'apply', 'fix.patch'])\nopen('NOTES.md','w').write('x')\nEOF\npython app.py", 'app.py'],
    ["python - <<'EOF'\nimport os\nos.system('black .')\nEOF\npython app.py", 'app.py'],
    ["python - <<'EOF'\nimport shutil\nshutil.copytree('staging', '.', dirs_exist_ok=True)\nopen('notes.md','w').write('x')\nEOF\npython app.py", 'app.py'],
    ["python - <<'EOF'\nimport zipfile\nzipfile.ZipFile('p.zip').extractall('.')\nopen('NOTES.md','w').write('ok')\nEOF\npython app.py", 'app.py'],
    ["node - <<'EOF'\nconst fs=require('fs');fs.cpSync('staging','.',{recursive:true});fs.writeFileSync('notes.md','x')\nEOF\nnode build.js", 'build.js'],
    ["python - <<'EOF'\nfrom pathlib import Path\nPath('tools/gen').with_suffix('.py').write_text('print(1)')\nEOF\npython tools/gen.py", 'tools/gen.py'],
    ["python - <<'EOF'\nopen('app.p' 'y','w').write('x')\nEOF\npython app.py", 'app.py'],
    ["python gen.py <<'EOF'\nopen('notes.md','w').write('x')\nEOF\npython app.py", 'app.py'], // a script reads the body
    // A `<<WORD` in quotes or a comment opens nothing, and an unterminated heredoc trusts nothing.
    ['python scripts/run.py\necho "tip: write notes with cat <<EOF" >> NOTES.md\ncp -r ../template/. scripts/', 'scripts/run.py'],
    ["python app.py\necho 'note: std::cout << endl flushes' >> NOTES.md\ngit apply fix.patch", 'app.py'],
    ['python app.py  # feed it <<EOF later\nruff check --fix .', 'app.py'],
    ["python app.py\npython - <<'EOF'\nopen('notes.md','w').write('x')", 'app.py'],
  ] as const) {
    expect(shellWrites(c)).toContain(file)
  }
  // A file named in one place and written in another still counts (continuations, loops, variables, pipes).
  expect(shellWrites("sed -i 's/a/b/' \\\n  app.py")).toEqual(['app.py'])
  expect(shellWrites('Copy-Item a.ps1 `\n  b.ps1')).toEqual(['a.ps1', 'b.ps1'])
  expect(shellWrites("for f in a.py b.py; do sed -i 's/x/y/' \"$f\"; done")).toEqual(['a.py', 'b.py'])
  expect(shellWrites('f=app.py; sed -i s/a/b/ "$f"')).toEqual(['app.py'])
  expect(shellWrites("git ls-files src/app.py | xargs sed -i 's/x/y/'")).toEqual(['src/app.py'])
  expect(shellWrites("Get-ChildItem src/app.ps1 | ForEach-Object { (Get-Content $_) -replace 'a','b' | Set-Content $_ }")).toEqual(['src/app.ps1'])
  expect(shellWrites("cat > a.md <<EOF; python - <<'PY'\nnote\nEOF\nimport pathlib\np = pathlib.Path('w.py')\np.write_text('x')\nPY")).toEqual(['w.py'])
  // A `cat` heredoc with a quoted terminator is data: what its text says runs nowhere here, as long as
  // every other command here only reads (the file may go to ssh, which runs it on another machine).
  const script = "S=/tmp/s\ncat > \"$S/scan.sh\" <<'EOF'\ncp a b\nprint('airplay patch in:')\ndocker run --ignorefile /cfg/ignore.yaml img\nEOF\n"
  expect(shellWrites(script + "ssh.exe box 'bash -s' < \"$S/scan.sh\"")).toEqual([])
  expect(shellWrites(script + "MSYS_NO_PATHCONV=1 timeout 600 /c/Windows/System32/OpenSSH/ssh.exe box 'bash -s' < \"$S/scan.sh\"")).toEqual([])
  expect(shellWrites("cat <<'EOF'\nsed -i s/a/b/ app.py\nEOF")).toEqual([]) // printed, not run
  // A body written to a file that stays here may run later (`bash /tmp/fix`, `make`, a git hook): its text still counts.
  for (const c of ["cat > note.md <<'EOF'\nrun: sed -i s/a/b/ app.py\nEOF", "cat > /tmp/fix <<'EOF'\nsed -i s/a/b/ app.py\nEOF",
    "mkdir -p b\ncat > b/Makefile <<'EOF'\nall:\n\tsed -i s/a/b/ app.py\nEOF", "cat > .git/hooks/pre-commit <<'EOF'\nsed -i s/a/b/ app.py\nEOF",
    script.replace('cp a b', 'cp a b app.py') + "ssh box 'bash -s' < \"$S/other.sh\""]) {
    expect(shellWrites(c)).toContain('app.py')
  }
  expect(shellWrites("cat > /dev/null <<'EOF'\nsed -i s/a/b/ app.py\nEOF")).toEqual([])
  // A `<<` the heredoc parser can't read makes its split a guess: a fake opener inside can't hide a line bash runs.
  for (const open of ["<<'EO F'", "<<'EOF.'", "<<'1E'", "<<$'EOF'"]) {
    const end = open === "<<$'EOF'" ? 'EOF' : open.slice(3, -1)
    expect(shellWrites(`cat ${open}\ncat > n.md <<'Z'\n${end}\nsed -i s/a/b/ app.py\nZ`)).toContain('app.py')
  }
  expect(shellWrites("cat <<EOF.\nEOF\ncat > n.md <<'Z'\nEOF.\nsed -i s/a/b/ app.py\nZ")).toContain('app.py')
  // Each guard on its own: the body goes to ssh (so the target check would blank it), and something else
  // here still runs it, or bash runs part of it here, or the split is a guess.
  const sent = script.replace('cp a b', 'cp a b app.py') + "ssh box 'bash -s' < \"$S/scan.sh\"\n"
  for (const run of ['bash "$S/scan.sh"', 'make', 'npm run build', '. "$S/scan.sh"', 'ls "$S" | xargs -n1 bash', 'unknown-tool "$S"',
    'timeout 60 bash "$S/scan.sh"', 'timeout -k 5 60 bash "$S/x"', 'echo "$(bash "$S/scan.sh")"']) {
    expect(shellWrites(sent + run)).toContain('app.py')
  }
  expect(shellWrites("cat <<EOF\n$(sed -i s/a/b/ app.py)\nEOF")).toEqual(['app.py']) // unquoted bodies run `$(...)` here
  expect(shellWrites("cat <<EOF\n`sed -i s/a/b/ app.py`\nEOF")).toEqual(['app.py'])
  expect(shellWrites("S=/tmp/s\ncat > \"$S/a.sh\" <<EOF\n$(cp a.py b.py)\nEOF\nssh box 'bash -s' < \"$S/a.sh\"")).toEqual(['a.py', 'b.py'])
  for (const c of ["cat <<'EO F'\ncat <<'Z'\nEO F\nsed -i s/a/b/ app.py\nZ", "cat <<'EOF.'\ncat <<'Z'\nEOF.\nsed -i s/a/b/ app.py\nZ",
    "cat <<$'EOF'\ncat <<'Z'\nEOF\nsed -i s/a/b/ app.py\nZ", "cat <<EOF.\nEOF\ncat <<'Z'\nEOF.\nsed -i s/a/b/ app.py\nZ",
    "cat <<'EOF'\necho x > app.py\n", "cat <<'EOF'\necho x > app.py\nEOF\necho \"a\\\" b\"", "export PATH=/tmp/x\ncat <<'EOF'\necho x > app.py\nEOF"]) {
    expect(shellWrites(c)).toEqual(['app.py'])
  }
  // timeout's spaced long options, a path or .exe, and a cut-off timeout before the next command.
  const tscript = script.replace('cp a b', 'cp a b app.py')
  for (const t of ['timeout -k 5 60', 'timeout --kill-after 5 --signal KILL 60', 'timeout -s KILL 60']) {
    expect(shellWrites(tscript + `${t} ssh box 'bash -s' < "$S/scan.sh"`)).toEqual([])
  }
  for (const c of ["timeout --kill-after 5 60 ssh box 'sed -i s/a/b/ app.py'", "timeout --signal KILL 60 ssh box 'sed -i s/a/b/ app.py'",
    "/usr/bin/timeout 60 ssh box 'sed -i s/a/b/ app.py'", "timeout.exe 60 ssh box 'sed -i s/a/b/ app.py'",
    "timeout\nssh box 'sed -i s/a/b/ app.py'", "timeout -s; ssh box 'sed -i s/a/b/ app.py'", "timeout -k\nssh box 'sed -i s/a/b/ app.py'"]) {
    expect(shellWrites(c)).toEqual([])
  }
  expect(gitAction("timeout --signal KILL 60 ssh box 'git push origin main'")).toBe(undefined)
  expect(gitAction('timeout\ngit push origin main')?.kind).toBe('push')
  expect(shellWrites('truncate -s 0 app.py')).toEqual(['app.py'])
  expect(shellWrites('sort -n app.py; grep -o x app.py')).toEqual([])
  // `rg --pre bash` runs a program on what it searches, so rg is not read-only then.
  expect(shellWrites(script.replace('cp a b', 'cp a b app.py') + "ssh box 'bash -s' < \"$S/scan.sh\"\nrg --pre bash x /tmp/s")).toContain('app.py')
  expect(shellWrites("python -I - <<'EOF'\nopen('notes.md', 'w').write('x')\nEOF\nrg --pre=bash -l x . && python app.py")).toContain('app.py')
  expect(shellWrites(script + 'for n in a b; do echo "$n"; ssh box \'bash -s\' < "$S/scan.sh"; done\nmkdir -p out; date')).toEqual([])
  // Anything here that might run the file keeps the body: named, globbed, built, looped, or another heredoc's code.
  for (const run of ['bash "$S/scan.sh"', 'cd "$S" && bash scan.sh', 'bash "$S"/*.sh', 'bash "$(ls -t "$S" | head -1)"', 'eval "$(cat "$S/x")"',
    'ls "$S" | xargs -n1 bash', 'ls "$S" | while read f; do bash "$S/$f"; done', 'N=scan; bash "$S/$N.sh"', 'bash "$S"/{scan,x}.sh',
    `python - <<'PY'\nimport subprocess\nsubprocess.run(["bash", "/tmp/s/scan.sh"])\nPY`, '. "$S/scan.sh"', 'source "$S/scan.sh"',
    'X=1 sh "$S/scan.sh"', 'sudo bash "$S/scan.sh"', 'ssh box true; bash "$S/scan.sh"', 'unknown-tool "$S"',
    "bash <<'X'\nbash /tmp/s/scan.sh\nX", "bash /tmp/s/sc''an.sh", "sh -c 'for f in /tmp/s/*; do sh \"$f\"; done'",
    'find /tmp/s -type f -execdir bash {} +', 'make', 'npm run build', 'timeout 60 bash "$S/scan.sh"', 'timeout -k 5 60 make']) {
    expect(shellWrites(script.replace('cp a b', 'cp a b app.py') + run)).toContain('app.py')
  }
  expect(shellWrites("cat > n.md <<EOF\n$(sed -i s/a/b/ app.py)\nEOF")).toContain('app.py') // unquoted: bash runs `$(...)` here
  // Only `cat` itself reads a data body: not a lookalike name, nor `cat` remade by a function, an alias or PATH.
  for (const c of ["cat() { bash; }; cat > n.txt <<'EOF'\necho x > app.py\nEOF", "cat () { bash; }\ncat > n.txt <<'EOF'\necho x > app.py\nEOF",
    "function cat { bash; }\ncat > n.txt <<'EOF'\necho x > app.py\nEOF", "alias cat=bash\ncat > n.txt <<'EOF'\necho x > app.py\nEOF",
    "PATH=/tmp/x:$PATH cat > n.txt <<'EOF'\necho x > app.py\nEOF", "/tmp/rcat > n.txt <<'EOF'\necho x > app.py\nEOF"]) {
    expect(shellWrites(c)).toContain('app.py')
  }
  expect(shellWrites("/usr/bin/cat <<'EOF'\necho x > app.py\nEOF")).toEqual([]) // cat by its full path is still cat
  expect(shellWrites("cat > n.md <<'EOF' && cp a.py b.py\nx\nEOF")).toEqual(['a.py', 'b.py']) // the opener's own line still counts
  // `timeout` and its options come before the program, so the ssh after it is still a remote command.
  expect(shellWrites("timeout 60 ssh box \"sed -i 's/a/b/' app.py\"")).toEqual([])
  expect(shellWrites("timeout -k 5 --signal=TERM 1m ssh box 'cp a.py b.py'")).toEqual([])
  expect(shellWrites("timeout 60 sed -i 's/a/b/' app.py")).toEqual(['app.py'])
  for (const c of ['sort -o app.py app.py', 'sort -uo app.py app.py', 'sort --output=app.py app.py']) expect(shellWrites(c)).toEqual(['app.py'])
  // Reading, running, and writing something that is not code leave nothing to review.
  for (const c of ['cat src/app.py', 'pytest tests/test_app.py 2>&1 | tail -5', 'python build.py > out.log 2>/dev/null', "sed -n '1,5p' app.py",
    'git diff -- app.py', 'echo done > notes.md', 'ls > /dev/null']) {
    expect(shellWrites(c)).toEqual([])
  }
})

test('only the user asking for something is a new request', async () => {
  for (const kind of ['composer', 'bridge', 'sdk', 'scheduled-trigger']) expect(isNewRequest(kind, false)).toBe(true)
  for (const kind of ['task-notification', 'peer', 'peer-send-message', 'plugin', 'unclassified', 'coordinator', 'some-new-kind']) {
    expect(isNewRequest(kind, false)).toBe(false)
  }
  expect(isNewRequest('composer', true)).toBe(false) // a message the person never typed
  expect(isNewRequest('plugin', false, true)).toBe(true) // a plugin speaking as the person
})

test("a report of a kind the mod doesn't know keeps the review going, and the reviewers' scratch files are not new work", async ($, on) => {
  const { out, edit, stop } = cycle($, on)
  await edit('C:/proj/app.py')
  expect((await stop())?.includes('app.py')).toBe(true)
  out.agents = [{ status: 'running' }, { status: 'running' }]
  expect(await stop(true)).toBe(undefined)
  // A reviewer writes a scratch file from its shell, and its report arrives unlabelled.
  await $.tool.call({ tool: 'Bash', command: "cat > t.ts <<'EOF'\nconst a = 1\nEOF" })
  await $.prompt.submit({ text: 'report', wait: false, origin: { kind: 'unclassified' } })
  expect(await stop()).toBe(undefined)
  out.agents = [{ status: 'completed' }, { status: 'failed' as Status }]
  expect(await stop()).toBe(undefined) // the review ends here, and its scratch file with it
  await edit('C:/proj/next.py')
  const prompt = await stop()
  expect(prompt?.includes('next.py')).toBe(true)
  expect(prompt?.includes('t.ts')).toBe(false)
})

test('a Stop hook continuation that is not a review asks for nothing, and the next stop does', async ($, on) => {
  const { edit, stop } = cycle($, on)
  await edit('C:/proj/app.py')
  expect(await stop(true)).toBe(undefined) // another hook sent Claude back: not the moment to ask
  expect((await stop())?.includes('app.py')).toBe(true)
})

test('an interrupt during a review with reviewers still out keeps the files, and a report does not lift the hold', async ($, on) => {
  const { out, edit, stop } = cycle($, on)
  on('turn.complete', () => ({ text: '' }))
  await edit('C:/proj/a.py')
  expect((await stop())?.includes('a.py')).toBe(true)
  out.agents = [{ status: 'running' }]
  await $.turn.complete({ reason: 'aborted', answer: '', durationMs: 1, isAborted: true, turnId: 't1' })
  await $.prompt.submit({ text: 'report', wait: false, origin: { kind: 'peer' } })
  expect(await stop()).toBe(undefined)
  // Work picks up again from a shell edit: one review, naming the first file too.
  await $.tool.call({ tool: 'Bash', command: "sed -i 's/x/y/' src/b.py" })
  const prompt = await stop()
  expect(prompt?.includes('a.py')).toBe(true)
  expect(prompt?.includes('src/b.py')).toBe(true)
})

test('a review whose turn dies on an error keeps its files, and an answered turn changes nothing', async ($, on) => {
  const { out, edit, stop } = cycle($, on)
  on('turn.complete', () => ({ text: '' }))
  await edit('C:/proj/a.py')
  expect((await stop())?.includes('a.py')).toBe(true)
  out.agents = [{ status: 'running' }]
  expect(await stop(true)).toBe(undefined) // the review prompt's own turn ends: still the same review
  await $.turn.complete({ reason: 'answer', answer: 'ok', durationMs: 1, isAborted: false, turnId: 't1' })
  await $.turn.complete({ reason: 'error', answer: '', durationMs: 1, isAborted: false, turnId: 't2' })
  await edit('C:/proj/b.py')
  const prompt = await stop() // no hold after an error: the next stop asks, for both files
  expect(prompt?.includes('a.py')).toBe(true)
  expect(prompt?.includes('b.py')).toBe(true)
})

test('one agent that fails to register does not stop the others, and the status names it', async ($, on) => {
  const names: string[] = []
  const status: string[] = []
  on('agent.register', (_$, e) => {
    if (e.name === 'comment-analyzer') throw new Error('refused')
    names.push(e.name)
    return { value: { agent: `review-guard:${e.name}` } }
  })
  on('ui.status', (_$, e) => {
    status.push(e.text ?? '')
    return { value: undefined }
  })
  on('session.start', () => ({ cwd: 'C:/proj' }))
  await $.session.start({ source: 'startup' } as never)
  expect(names.length).toBe(4)
  expect(status.some(s => s.includes('comment-analyzer'))).toBe(true)
})

// --- the git guard, with git, the config file and the engine stood in for --------------------

type Run = { exitCode?: number; stdout?: string; stderr?: string; isStdoutTruncated?: boolean }
const REMOTE = 'origin\thttps://github.com/pat/notes.git (fetch)\norigin\thttps://github.com/pat/notes.git (push)\n'
const CONFIG = JSON.stringify({ personal: PERSONAL, allowNetworkInfo: [], allowValues: [] })
const added = (file: string, line: string) => `diff --git a/${file} b/${file}\n--- a/${file}\n+++ b/${file}\n@@ -0,0 +1 @@\n+${line}\n`

/**
 * `git` maps a piece of a git command line to what git answers; the first piece found wins, and
 * anything else succeeds with no output. `config` is the config file's text, or undefined for none.
 */
function world(on: On, git: Record<string, Run> = {}, config: string | undefined = CONFIG, files: Record<string, string> = {}) {
  // `git` and `config` can be changed between calls: hooks are registered once, before the first call.
  // Programs in the scanners folder exist; `stdin` and `cwd` record what gitleaks was given.
  const seen = {
    ran: false, status: [] as string[], calls: [] as string[], git, config: config as string | undefined,
    stdin: [] as string[], cwd: [] as (string | undefined)[], missing: [] as string[], // scanners not installed at all
    configUnreadable: false, // the config file is there but can't be read
    existsFails: [] as string[], // path endings whose existence can't be told (no permission)
  }
  mock.env(on, { USERPROFILE: 'C:/Users/pat' })
  on('process.run', (_$, e) => {
    const line = e.argv.join(' ')
    seen.calls.push(line)
    if (seen.missing.includes(e.argv[0] ?? '')) throw new Error(`spawn ${e.argv[0]} ENOENT`) // not on PATH either
    if (e.init?.stdin !== undefined) {
      seen.stdin.push(e.init.stdin)
      seen.cwd.push(e.init.cwd)
    }
    const key = Object.keys(seen.git).find(k => line.includes(k))
    // gitleaks writes "[]" when it finds nothing.
    const base = { exitCode: 0, stdout: line.includes('remote -v') ? REMOTE : line.includes(' stdin ') ? '[]' : '', stderr: '', isStdoutTruncated: false, isStderrTruncated: false }
    return { value: { ...base, ...(key ? seen.git[key] : {}) } }
  })
  on('fs.exists', (_$, e) => {
    const p = e.path.replace(/\\/g, '/') // the engine may hand over a Windows path
    if (seen.existsFails.some(m => p.endsWith(m))) throw new Error('EPERM: operation not permitted')
    if (p.endsWith('/.claude/review-guard.json')) return { value: seen.config !== undefined }
    return { value: p.includes('/Tools/scanners/bin/') && !seen.missing.some(m => p.endsWith(`/${m}.exe`)) }
  })
  on('fs.read', (_$, e) => {
    const file = Object.keys(files).find(f => e.path.replace(/\\/g, '/').endsWith(`/${f}`))
    if (file) return { value: files[file] ?? '' }
    if (seen.config === undefined) throw new Error('no such file')
    if (seen.configUnreadable) throw new Error('EACCES: permission denied')
    return { value: seen.config }
  })
  on('ui.status', (_$, e) => {
    seen.status.push(e.text ?? '')
    return { value: undefined }
  })
  on('tool.call', () => {
    seen.ran = true
    return { result: {} }
  })
  return seen
}

describe('outside scanners', () => {
  // A made-up value in the shape gitleaks reports; built from pieces like the others in this file.
  const LEAK = ['k9Qz', 'Xw2L', 'pR7v', 'Tn4Y', 'bH8s'].join('')
  const report = (line: number) => JSON.stringify([{ RuleID: 'generic-api-key', StartLine: line, Secret: LEAK, Match: `key=${LEAK}` }])

  test('a commit gitleaks finds a secret in is stopped, naming the rule and place but never the secret', async ($, on) => {
    // gitleaks reads the commit message first (line 1), then the added lines: line 3 is cfg.py:1.
    const seen = world(on, { '--cached': { stdout: added('app.py', 'x = 1') + added('cfg.py', 'y = 2') }, ' stdin ': { stdout: report(3) } })
    const r = await $.tool.call({ tool: 'Bash', command: 'git commit -m x' })
    expect(r.deny?.includes('a secret gitleaks found (generic-api-key) at cfg.py:1')).toBe(true)
    expect(r.deny?.includes(LEAK)).toBe(false)
    expect(seen.ran).toBe(false)
    // It ran the program found in the scanners folder, in stdin mode.
    expect(seen.calls.some(l => l.startsWith('C:/Users/pat/Tools/scanners/bin/gitleaks.exe stdin '))).toBe(true)
  })

  test('a gitleaks finding the user allowed passes, like any other', async ($, on) => {
    const seen = world(on, { '--cached': { stdout: added('app.py', 'x = 1') }, ' stdin ': { stdout: report(1) } },
      JSON.stringify({ personal: PERSONAL, allowNetworkInfo: [], allowValues: [LEAK] }))
    expect((await $.tool.call({ tool: 'Bash', command: 'git commit -m x' })).deny).toBe(undefined)
    expect(seen.ran).toBe(true)
  })

  test('without gitleaks the built-in checks still run, and the status says gitleaks was skipped', async ($, on) => {
    const seen = world(on, { '--cached': { stdout: added('app.py', 'x = 1') } })
    seen.missing.push('gitleaks')
    expect((await $.tool.call({ tool: 'Bash', command: 'git commit -m x' })).deny).toBe(undefined)
    expect(seen.ran).toBe(true)
    expect(seen.status.at(-1)?.includes('gitleaks is not installed')).toBe(true)
    expect(seen.calls.some(l => l.includes(' stdin '))).toBe(false)
  })

  test('gitleaks that is installed but fails stops the commit, as any check that could not run', async ($, on) => {
    const seen = world(on, { '--cached': { stdout: added('app.py', 'x = 1') }, ' stdin ': { exitCode: 2, stderr: 'boom' } })
    const r = await $.tool.call({ tool: 'Bash', command: 'git commit -m x' })
    expect(r.deny?.includes('could not check')).toBe(true)
    expect(r.deny?.includes('gitleaks failed (exit 2): boom')).toBe(true)
    expect(seen.ran).toBe(false)
  })

  test('gitleaks reads exactly what goes out, in a folder of its own, with its own ways to wave findings through shut', async ($, on) => {
    const seen = world(on, { '--cached': { stdout: added('app.py', 'x = 1') + added('cfg.py', 'y = 2') } })
    await $.tool.call({ tool: 'Bash', command: 'git commit -m x' })
    expect(seen.stdin).toEqual(['x\nx = 1\ny = 2']) // the message, then the added lines in order
    const run = seen.calls.find(l => l.includes(' stdin ')) ?? ''
    for (const flag of ['--exit-code 0', '--report-path -', '--report-format json', '--ignore-gitleaks-allow', '--gitleaks-ignore-path']) {
      expect(run.includes(flag)).toBe(true)
    }
    expect(seen.cwd[0] !== undefined && seen.cwd[0] !== '').toBe(true) // never the session's folder
  })

  test('a push sends its commits and their messages through gitleaks', async ($, on) => {
    const log = `COMMIT abc1234\nAUTHOR bot <bot@example.com>\nCOMMITTER bot <bot@example.com>\nadd config\n${added('cfg.py', 'y = 2')}`
    const seen = world(on, { ' log ': { stdout: log }, ' stdin ': { stdout: report(2) } })
    const r = await $.tool.call({ tool: 'Bash', command: 'git push origin main' })
    expect(seen.stdin[0]?.includes('y = 2')).toBe(true)
    expect(r.deny?.includes('at cfg.py:1')).toBe(true)
    seen.git[' stdin '] = { stdout: report(1) }
    expect((await $.tool.call({ tool: 'Bash', command: 'git push origin main' })).deny?.includes("at commit abc1234's message")).toBe(true)
  })

  test('git add -A sends the working tree and new files through gitleaks too', async ($, on) => {
    const seen = world(on, {
      '--cached': { stdout: '' }, ' diff --no-color': { stdout: added('edit.py', 'z = 3') }, // first match wins: staged first
      'ls-files --others': { stdout: 'new.py\n' }, ' stdin ': { stdout: report(4) },
    }, CONFIG, { 'new.py': 'a = 1\nb = 2' })
    const r = await $.tool.call({ tool: 'Bash', command: 'git add -A && git commit -m x' })
    expect(seen.stdin[0]).toBe('x\nz = 3\na = 1\nb = 2')
    expect(r.deny?.includes('at new.py:2')).toBe(true)
  })

  test('a push with nothing new runs no gitleaks', async ($, on) => {
    const seen = world(on)
    expect((await $.tool.call({ tool: 'Bash', command: 'git push origin main' })).deny).toBe(undefined)
    expect(seen.calls.some(l => l.includes(' stdin '))).toBe(false)
  })

  test('gitleaks that is there but will not run, gives no report, or is cut short stops the commit', async ($, on) => {
    const seen = world(on, { '--cached': { stdout: added('app.py', 'x = 1') }, 'gitleaks.exe version': { exitCode: 3, stderr: 'dll missing' } })
    let r = await $.tool.call({ tool: 'Bash', command: 'git commit -m x' })
    expect(r.deny?.includes('gitleaks is installed but would not run')).toBe(true)
    delete seen.git['gitleaks.exe version']
    seen.git[' stdin '] = { stdout: '' }
    r = await $.tool.call({ tool: 'Bash', command: 'git commit -m x' })
    expect(r.deny?.includes('gitleaks gave no report')).toBe(true)
    seen.git[' stdin '] = { stdout: '[', isStdoutTruncated: true }
    r = await $.tool.call({ tool: 'Bash', command: 'git commit -m x' })
    expect(r.deny?.includes('its report was cut short')).toBe(true)
    expect(seen.ran).toBe(false)
  })

  test('a refusal says gitleaks was skipped, since the status line would be overwritten', async ($, on) => {
    const seen = world(on, { '--cached': { stdout: added('app.py', `key = "${FAKE_GH}"`) } })
    seen.missing.push('gitleaks')
    const r = await $.tool.call({ tool: 'Bash', command: 'git commit -m x' })
    expect(r.deny?.includes('GitHub token')).toBe(true)
    expect(r.deny?.includes('Also: gitleaks is not installed')).toBe(true)
  })

  test('GitHub MCP writes go through gitleaks too', async ($, on) => {
    const seen = world(on, { ' stdin ': { stdout: report(2) } })
    const r = await $.tool.call({ tool: 'mcp__plugin_github_github__create_or_update_file', path: 'cfg.py', content: 'x = 1\ny = 2', message: 'add' } as never)
    expect(r.deny?.includes('a secret gitleaks found')).toBe(true)
    expect(seen.stdin.length).toBe(1)
  })

  test('each machine has its own places to look, then PATH', async () => {
    expect(candidates('gitleaks', 'C:/Users/pat', true)).toEqual(
      ['C:/Users/pat/Tools/scanners/bin/gitleaks.exe', 'C:/Users/pat/Tools/scanners/venv/Scripts/gitleaks.exe', 'gitleaks'])
    expect(candidates('bandit', '/home/pat', false)[0]).toBe('/home/pat/.local/bin/bandit')
    expect(candidates('trivy', undefined, false)).toEqual(['trivy'])
  })

  test('each changed file goes to the scanners that understand it', async () => {
    const changed = new Map([['a.py', 'Python'], ['b.ts', 'TypeScript'], ['.github/workflows/ci.yml', 'GitHub Actions'],
      ['requirements.txt', 'dependencies'], ['Dockerfile', 'Docker'], ['site.css', 'CSS'], ['app.toml', 'config']])
    const got = Object.fromEntries(scannersFor(changed))
    expect(got).toEqual({
      bandit: ['a.py'], semgrep: ['a.py', 'b.ts', 'Dockerfile'], zizmor: ['.github/workflows/ci.yml'], trivy: ['requirements.txt', 'Dockerfile'],
    })
    expect(scannersFor(new Map([['x.css', 'CSS']])).size).toBe(0)
    // Every code language gets semgrep (Python bandit as well); trivy gets one run per file, as it takes one path.
    for (const lang of ['JavaScript', 'HTML templates', 'C#', 'C/C++', 'Shell', 'Go', 'Rust', 'Java/Kotlin', 'other code']) {
      expect(scannersFor(new Map([['f', lang]])).get('semgrep')).toEqual(['f'])
    }
    expect(scannerCommand('trivy', 'trivy', ['package.json', 'package-lock.json'])).toBe(
      "'trivy' fs --scanners vuln,misconfig,secret --quiet 'package.json'; 'trivy' fs --scanners vuln,misconfig,secret --quiet 'package-lock.json'")
  })

  test('the review gets a command per installed scanner and names the ones that are missing', async () => {
    const changed = new Map([['my app/a.py', 'Python'], ['.github/workflows/ci.yml', 'GitHub Actions']])
    const steps = scannerSteps(changed, new Map([['bandit', 'C:/Tools/bandit.exe']]))
    expect(steps.some(s => s.includes("'C:/Tools/bandit.exe' -q 'my app/a.py'"))).toBe(true) // quoted, spaces kept
    expect(steps.at(-1)?.includes('Not installed here, so skipped')).toBe(true)
    expect(steps.at(-1)?.includes('semgrep, zizmor')).toBe(true)
    expect(scannerCommand('zizmor', 'zizmor', ['w.yml'])).toBe("'zizmor' --offline 'w.yml'")
    // Bash expands nothing in single quotes; a quote inside is closed, escaped and reopened.
    expect(scannerCommand('bandit', 'bandit', ["it's $HOME/a.py"])).toBe("'bandit' -q 'it'\\''s $HOME/a.py'")
    expect(scannerCommand('semgrep', 'semgrep', ['a.py']).includes('--metrics=off')).toBe(true)
    const prompt = reviewPrompt(changed, steps)
    expect(flat(prompt).includes('What they report is a finding like any other')).toBe(true)
    // The commands come before the step that says to fix what they find.
    expect(flat(prompt).indexOf("'C:/Tools/bandit.exe'") < flat(prompt).indexOf('3. Fix the real bugs')).toBe(true)
    expect(reviewPrompt(changed).includes('Scanners for these files')).toBe(false)
    // With none installed, the prompt still names them as skipped and does not claim any are installed.
    const none = reviewPrompt(changed, scannerSteps(changed, new Map()))
    expect(none.includes('Not installed here')).toBe(true)
    expect(none.includes('installed on this machine')).toBe(false)
    // One that is there but would not run, or could not be looked for, is named with why, never as
    // "not installed"; a reason on several lines is put on one.
    const failed = scannerSteps(changed, new Map([['bandit', 'bandit']]), new Map([['semgrep', 'C:/x/semgrep.exe would not run: spawn\nEPERM'], ['zizmor', 'looking for it failed: boom']]))
    expect(failed.length).toBe(2) // bandit's command, then the line for the other two
    expect(failed[1]?.includes('There but would not run, or could not be checked, so skipped')).toBe(true)
    expect(failed[1]?.includes('semgrep (C:/x/semgrep.exe would not run: spawn EPERM); zizmor (looking for it failed: boom)')).toBe(true)
    expect(failed.some(l => l.includes('Not installed here'))).toBe(false)
    // A problem for a scanner these files don't need adds nothing.
    expect(scannerSteps(new Map([['a.css', 'CSS']]), new Map(), new Map([['bandit', 'x']]))).toEqual([])
  })

  test("gitleaks' report becomes findings at the right place; an empty or broken report is handled", async () => {
    const places = ['the commit message', 'app.py:3']
    expect(gitleaksFindings(report(2), places)).toEqual([{ kind: 'a secret gitleaks found (generic-api-key)', where: 'app.py:3', value: LEAK }])
    expect(gitleaksFindings(report(9), places)[0]?.where).toBe('the changes')
    expect(() => gitleaksFindings('', places)).toThrow() // gitleaks always writes "[]": nothing at all means it failed
    expect(gitleaksFindings('[]', places)).toEqual([])
    expect(() => gitleaksFindings('{"a":1}', places)).toThrow()
  })

  test('the added lines of a diff keep their file and line, and dependency files are reviewable', async () => {
    const diff = 'diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n@@ -1,2 +1,3 @@\n keep\n-old\n+new\n+more\n'
    expect(addedLines(diff)).toEqual([{ text: 'new', where: 'a.py:2' }, { text: 'more', where: 'a.py:3' }])
    for (const f of ['requirements.txt', 'requirements-dev.in', 'pyproject.toml', 'uv.lock', 'frontend/package-lock.json', 'App/App.csproj', 'Cargo.lock',
      'package.json', 'go.mod', 'go.sum', 'Gemfile.lock']) {
      expect(languageOf(f)).toBe('dependencies')
    }
    for (const f of ['mypackage.json', 'notrequirements.txt']) expect(languageOf(f)).not.toBe('dependencies')
    expect(languageOf('settings.toml')).toBe('config')
  })
})

describe('the git guard', () => {
  test('stops a commit with a key in it and lets a clean one through', async ($, on) => {
    const seen = world(on, { '--cached': { stdout: added('app.py', `key = "${FAKE_GH}"`) } })
    const r = await $.tool.call({ tool: 'Bash', command: 'cd /c/proj/app && git commit -m x' })
    expect(r.deny?.includes('GitHub token at app.py:1')).toBe(true)
    expect(r.deny?.includes(FAKE_GH)).toBe(false)
    expect(seen.ran).toBe(false)
    expect(seen.calls[0]?.startsWith('git -C C:/proj/app ')).toBe(true)
    expect(seen.calls[0]?.endsWith(' remote -v')).toBe(true)
    // The repository's own config can't run a command or rewrite what is scanned: every git call turns
    // off its file system monitor, and every diff and log turns off its textconv drivers.
    const git = seen.calls.filter(c => c.startsWith('git '))
    expect(git.length > 2 && git.every(c => c.includes('-c core.fsmonitor=false'))).toBe(true)
    expect(git.filter(c => / (?:diff|log) /.test(c)).every(c => c.includes('--no-textconv'))).toBe(true)
    // Nor take the index lock, which would make a commit the user runs at that moment fail.
    expect(git.every(c => c.includes(' --no-optional-locks '))).toBe(true)
  })

  test("the repository's filter drivers are turned off before git reads the working tree", async ($, on) => {
    const seen = world(on, {
      'get-regexp': { stdout: 'filter.lfs.clean\nfilter.My.Odd.process\n' },
      ' diff ': { stdout: added('app.py', 'x = 1') },
    })
    expect((await $.tool.call({ tool: 'Bash', command: 'git add -A && git commit -m x' })).deny).toBe(undefined)
    const diffs = seen.calls.filter(c => c.startsWith('git ') && c.includes(' diff '))
    expect(diffs.length).toBe(2) // staged, and the working tree
    for (const d of diffs) {
      for (const k of ['lfs.clean', 'lfs.smudge', 'lfs.process', 'lfs.required=false', 'My.Odd.clean', 'My.Odd.process']) {
        expect(d.includes(`-c filter.${k}`)).toBe(true)
      }
    }
    // A filter name git can't be told to turn off stops the command: the check can't run safely.
    seen.git = { 'get-regexp': { stdout: 'filter.a=b.clean\n' } }
    expect((await $.tool.call({ tool: 'Bash', command: 'git commit -m x' })).deny?.includes('could not be turned off')).toBe(true)
  })

  test('a scanner whose file can not be looked at counts as broken, not missing', async ($, on) => {
    const seen = world(on, { '--cached': { stdout: added('app.py', 'x = 1') } })
    seen.existsFails.push('/gitleaks.exe')
    const r = await $.tool.call({ tool: 'Bash', command: 'git commit -m x' })
    expect(r.deny?.includes("gitleaks is installed but would not run")).toBe(true)
  })

  test('a Python test written with a heredoc and run is not a commit: no check, no stop', async ($, on) => {
    const seen = world(on)
    const r = await $.tool.call({ tool: 'Bash', command: "cd /c/proj && cat > /tmp/t/fix.py <<'PYEOF'\ngit(repo, 'commit', '-q', '-m', 'first')\nPYEOF\npython -I /tmp/t/fix.py ." })
    // The shadow look may ask which repository the folder is in (`rev-parse`): that is no commit check.
    expect([r.deny, seen.ran, seen.calls.filter(c => c.startsWith('git ') && !c.includes(' rev-parse --show-toplevel')).length]).toEqual([undefined, true, 0])
  })

  test('a clean commit runs', async ($, on) => {
    const seen = world(on, { '--cached': { stdout: added('app.py', 'x = 1') } })
    expect((await $.tool.call({ tool: 'Bash', command: 'git commit -m x' })).deny).toBe(undefined)
    expect(seen.ran).toBe(true)
    expect(seen.status.at(-1)?.includes('nothing personal or secret found')).toBe(true)
  })

  test('the PowerShell tool is guarded too', async ($, on) => {
    const seen = world(on, { '--cached': { stdout: added('notes.txt', 'Pat Example was here') } })
    const r = await $.tool.call({ tool: 'PowerShell', command: 'Set-Location C:\\proj\\app; git commit -m x' })
    expect(r.deny?.includes('your personal info')).toBe(true)
    expect(seen.ran).toBe(false)
  })

  test('a commit and push in one command checks the staged changes as well', async ($, on) => {
    const seen = world(on, { '--cached': { stdout: added('app.py', `host = "${LAN_B}"`) } })
    const r = await $.tool.call({ tool: 'Bash', command: 'git add -A && git commit -m x && git push' })
    expect(r.deny?.includes('IP address at app.py:1')).toBe(true)
    expect(r.deny?.includes('commit and push')).toBe(true)
    expect(seen.calls.some(l => l.includes(' log '))).toBe(true)
  })

  test('a push is checked for the commits it sends, by author and content', async ($, on) => {
    const log = `COMMIT abc1234\nAUTHOR Pat Example <pat@example.org>\nCOMMITTER bot <bot@example.com>\nfix\n${added('a.py', 'x = 1')}`
    world(on, { ' log ': { stdout: log } })
    const r = await $.tool.call({ tool: 'Bash', command: 'git push origin main' })
    expect(r.deny?.includes("commit abc1234's author")).toBe(true)
  })

  test('a push that names a branch is checked for that branch', async ($, on) => {
    const seen = world(on)
    await $.tool.call({ tool: 'Bash', command: 'git push -u origin feature 2>&1' })
    expect(seen.calls.some(l => l.endsWith('feature --not --remotes'))).toBe(true)
    expect(seen.ran).toBe(true)
  })

  test('when git cannot be asked, the command is stopped; outside a repository it is left alone', async ($, on) => {
    const seen = world(on, { 'remote -v': { exitCode: 128, stderr: "fatal: cannot change to 'C:/proj/app': No such file or directory" } })
    const r = await $.tool.call({ tool: 'Bash', command: 'git -C C:/proj/app commit -m x' })
    expect(r.deny?.includes('could not check')).toBe(true)
    expect(r.deny?.includes('cannot change to')).toBe(true)
    expect(seen.ran).toBe(false)
  })

  test('outside a repository there is nothing to check', async ($, on) => {
    const seen = world(on, { 'remote -v': { exitCode: 128, stderr: 'fatal: not a git repository (or any of the parent directories): .git' } })
    expect((await $.tool.call({ tool: 'Bash', command: 'git commit -m x' })).deny).toBe(undefined)
    expect(seen.ran).toBe(true)
  })

  test('a failed or cut-off diff stops the commit', async ($, on) => {
    world(on, { '--cached': { exitCode: 1, stderr: 'fatal: bad object' } })
    expect((await $.tool.call({ tool: 'Bash', command: 'git commit -m x' })).deny?.includes('could not check')).toBe(true)
  })

  test('a diff too large to read stops the commit', async ($, on) => {
    world(on, { '--cached': { stdout: added('a.py', 'x = 1'), isStdoutTruncated: true } })
    expect((await $.tool.call({ tool: 'Bash', command: 'git commit -m x' })).deny?.includes('more staged changes')).toBe(true)
  })

  test('more new files than can be read stops an add-and-commit', async ($, on) => {
    const names = Array.from({ length: 301 }, (_, i) => `f${i}.txt`).join('\n')
    world(on, { 'ls-files': { stdout: names }, 'show-toplevel': { stdout: 'C:/proj/app\n' } })
    const r = await $.tool.call({ tool: 'Bash', command: 'git add -A && git commit -m x' })
    expect(r.deny?.includes('more new files')).toBe(true)
  })

  test('new files are listed from the top of the repository', async ($, on) => {
    const seen = world(on, { 'show-toplevel': { stdout: 'C:/proj/app\n' } })
    await $.tool.call({ tool: 'Bash', command: 'cd /c/proj/app/sub && git add -A && git commit -m x' })
    expect(seen.calls.some(l => l.startsWith('git -C C:/proj/app ') && l.includes('ls-files'))).toBe(true)
  })

  test('a config with a typo stops the command and says why', async ($, on) => {
    const w = world(on)
    for (const bad of ['{"personnal":[]}', '[]', '{"personal":"pat"}', '{not json']) {
      w.config = bad
      const r = await $.tool.call({ tool: 'Bash', command: 'git commit -m x' })
      expect(r.deny?.includes('could not check')).toBe(true)
    }
    w.config = '{"personnal":[]}'
    expect((await $.tool.call({ tool: 'Bash', command: 'git commit -m x' })).deny?.includes('personnal')).toBe(true)
  })

  test('a config that is there but unreadable or wrong stops the command, and its error never quotes it', async ($, on) => {
    const w = world(on)
    // JSON's own error quotes the text around the mistake: the message must not.
    w.config = `{"personal": ["${PERSONAL[0]}", }`
    const bad = await $.tool.call({ tool: 'Bash', command: 'git commit -m x' })
    expect(bad.deny?.includes('review-guard.json is not valid JSON')).toBe(true) // a line number only where the runtime gives one
    expect(bad.deny?.toLowerCase().includes(PERSONAL[0] ?? '?')).toBe(false)
    w.config = '{"allowNetworkInfo": ["not a repo"]}' // ignored without a word before: now an error
    expect((await $.tool.call({ tool: 'Bash', command: 'git commit -m x' })).deny?.includes('allowNetworkInfo')).toBe(true)
    w.config = CONFIG
    w.configUnreadable = true // there, but locked: not the same as missing
    expect((await $.tool.call({ tool: 'Bash', command: 'git commit -m x' })).deny?.includes("can't be read")).toBe(true)
    w.configUnreadable = false
    w.config = `﻿${CONFIG}` // Windows PowerShell's byte-order mark is fine
    expect((await $.tool.call({ tool: 'Bash', command: 'git commit -m x' })).deny).toBe(undefined)
  })

  test('a push that names refs falls back to the current branch only when one does not exist yet', async ($, on) => {
    const w = world(on, { 'new-branch --not': { exitCode: 128, stderr: "fatal: ambiguous argument 'new-branch': unknown revision" } })
    expect((await $.tool.call({ tool: 'Bash', command: 'git push -u origin new-branch' })).deny).toBe(undefined)
    expect(w.status.at(-1)?.includes('does not exist yet, so only the current branch was checked')).toBe(true)
    // Any other failure stops the push: falling back would leave what it names unchecked.
    w.git = { '--branches': { exitCode: 128, stderr: 'fatal: bad object refs/heads/x' } }
    w.ran = false
    const r = await $.tool.call({ tool: 'Bash', command: 'git push --all origin' })
    expect(r.deny?.includes('git log failed')).toBe(true)
    expect(w.ran).toBe(false)
  })

  test("a commit's author that can't be read is said, never skipped quietly", async ($, on) => {
    const w = world(on, { '--cached': { stdout: added('app.py', 'x = 1') }, 'var GIT_AUTHOR_IDENT': { exitCode: 1, stderr: 'bad config' } })
    expect((await $.tool.call({ tool: 'Bash', command: 'git commit -m x' })).deny).toBe(undefined)
    expect(w.status.at(-1)?.includes("the commit's author could not be read")).toBe(true)
  })

  test('with no config the secret checks still run and the status says what was skipped', async ($, on) => {
    const seen = world(on)
    seen.config = undefined // passing undefined would take the default config
    expect((await $.tool.call({ tool: 'Bash', command: 'git commit -m x' })).deny).toBe(undefined)
    expect(seen.status.at(-1)?.includes('NOT checked')).toBe(true)
  })

  test('addresses pass only into a repository the config lists', async ($, on) => {
    const git = { '--cached': { stdout: added('hosts.md', `nas ${MAC}`) } }
    const w = world(on, git, JSON.stringify({ allowNetworkInfo: ['pat/notes'] }))
    expect((await $.tool.call({ tool: 'Bash', command: 'git commit -m x' })).deny).toBe(undefined)
    w.config = JSON.stringify({ allowNetworkInfo: ['pat/other'] })
    expect((await $.tool.call({ tool: 'Bash', command: 'git commit -m x' })).deny?.includes('MAC address')).toBe(true)
  })

  test('a commit sent over ssh is let through, with a notice that it was not checked', async ($, on) => {
    const seen = world(on)
    const r = await $.tool.call({ tool: 'Bash', command: `ssh box 'cd ~/repo && git commit -m "by Pat Example" && git push'` })
    expect(r.deny).toBe(undefined)
    expect(seen.ran).toBe(true)
    expect(seen.calls.length).toBe(0) // no local git was asked about a remote folder
    expect(seen.status.at(-1)?.includes('NOT checked')).toBe(true)
    // The local half of a mixed command is still stopped.
    seen.git = { ' log ': { stdout: 'COMMIT abc1234\nAUTHOR Pat Example <pat@example.org>\nCOMMITTER bot <bot@example.com>\nfix\n' } }
    const mixed = await $.tool.call({ tool: 'Bash', command: "ssh box 'git pull' && git push" })
    expect(mixed.deny?.includes("commit abc1234's author")).toBe(true)
  })

  test('text sent with gh is checked, and a gh read is not', async ($, on) => {
    const seen = world(on)
    const r = await $.tool.call({ tool: 'Bash', command: 'gh pr create --title "Fix" --body "by Pat Example"' })
    expect(r.deny?.includes('your personal info')).toBe(true)
    expect((await $.tool.call({ tool: 'Bash', command: 'gh pr view 12 --json author' })).deny).toBe(undefined)
    expect(seen.calls.length).toBe(0)
  })

  test('GitHub MCP writes are checked line by line, and reads are left alone', async ($, on) => {
    world(on)
    const body = `intro\ntoken = "${FAKE_GH}"\nversion 1 example`
    const write = await $.tool.call({ tool: 'mcp__plugin_github_github__create_pull_request', title: 'x', body } as never)
    expect(write.deny?.includes('GitHub token')).toBe(true)
    const file = await $.tool.call({ tool: 'mcp__plugin_github_github__push_files', files: [{ path: 'deploy/.env', content: 'A=1' }] } as never)
    expect(file.deny?.includes('a sensitive file')).toBe(true)
    const read = await $.tool.call({ tool: 'mcp__plugin_github_github__get_file_contents', path: '.env' } as never)
    expect(read.deny).toBe(undefined)
  })
})


describe('churn', () => {
  const RULE = { reviews: 3, hours: 24 }
  const NOW = new Date('2026-11-24T12:00:00Z')
  const hoursAgo = (h: number) => new Date(NOW.getTime() - h * 3_600_000)
  const throws = (v: unknown) => {
    try {
      churnRule(v)
      return 'ok'
    } catch {
      return 'threw'
    }
  }

  test('the "churn" config value: default, off, a rule, and a bad value never stops a commit', async ($, on) => {
    expect(churnRule(undefined)).toEqual({ reviews: 4, hours: 24 })
    expect(churnRule(true)).toEqual({ reviews: 4, hours: 24 })
    expect(churnRule(false)).toBe(false)
    expect(churnRule({ reviews: 5 })).toEqual({ reviews: 5, hours: 24 })
    expect(churnRule({ hours: 2.5 })).toEqual({ reviews: 4, hours: 2.5 })
    for (const bad of [null, 'x', [], { reviews: 1 }, { reviews: 2.5 }, { reviews: 201 }, { hours: 0 }, { hours: -1 }, { other: 1 }]) {
      expect([bad, throws(bad)]).toEqual([bad, 'threw'])
    }
    // In the config file a bad churn value gives the default rule and a problem, and the commit check runs.
    const seen = world(on, { '--cached': { stdout: added('app.py', 'x = 1') } },
      JSON.stringify({ personal: PERSONAL, churn: { reviews: 1 } }))
    expect((await $.tool.call({ tool: 'Bash', command: 'git commit -m x' })).deny).toBe(undefined)
    expect(seen.ran).toBe(true)
  })

  test('the history file name stays in its folder, keeps folders apart, and stays short', () => {
    expect(historyFileName('C:\\proj\\')).toBe(historyFileName('c:/proj'))
    expect(historyFileName('C:/proj')).not.toBe(historyFileName('C:/Proj'))
    expect(historyFileName('/a/b')).not.toBe(historyFileName('/a%002fb'))
    for (const f of ['C:/proj', '/home/pat/../x', `C:/${'deep/'.repeat(80)}proj`]) {
      const name = historyFileName(f)
      expect([f, /^[\w%~-]+\.json$/.test(name) && name.length <= 130]).toEqual([f, true])
    }
    const deep = (n: number) => `C:/${'deep/'.repeat(80)}proj${n}`
    expect(historyFileName(deep(1))).not.toBe(historyFileName(deep(2)))
  })

  test('a history is read back sorted, with bad entries dropped and a wrong shape restarted', () => {
    const good = { at: hoursAgo(1).toISOString(), files: ['C:/proj/a.py', 'C:/proj/a.py'] }
    const older = { at: hoursAgo(5).toISOString(), files: ['C:/proj/b.py'] }
    const read = historyFrom({ v: 1, folder: 'C:/proj', reviews: [good, { at: 'never', files: [] }, { at: good.at, files: [1] }, older] }, 'C:/proj')
    expect(read.damaged).toBe(false)
    expect(read.dropped).toBe(2)
    expect(read.history.reviews).toEqual([older, { ...good, files: ['C:/proj/a.py'] }])
    expect(historyFrom(undefined, 'C:/proj')).toEqual({ history: { v: 1, folder: 'C:/proj', reviews: [] }, damaged: false, dropped: 0 })
    for (const bad of [null, [], 'x', { v: 2, reviews: [] }, { v: 1 }]) expect(historyFrom(bad, 'C:/proj').damaged).toBe(true)
  })

  test('a review is added, and only reviews in the window before now are kept, the newest 200 at most', () => {
    const start = historyFrom(undefined, 'C:/proj').history
    const h = { ...start, reviews: [hoursAgo(30), hoursAgo(10), hoursAgo(-2)].map(at => ({ at: at.toISOString(), files: ['x'] })) }
    const next = withReview(h, ['a', 'a'], NOW, NOW, RULE)
    // Older than 24 hours, and dated after now (a clock moved back), are dropped.
    expect(next.reviews).toEqual([{ at: hoursAgo(10).toISOString(), files: ['x'] }, { at: NOW.toISOString(), files: ['a'] }])
    let many = start
    for (let i = 0; i < 250; i++) many = withReview(many, [`f${i}`], new Date(NOW.getTime() - (250 - i) * 1000), NOW, RULE)
    expect(many.reviews.length).toBe(200)
    expect(many.reviews.at(-1)?.files).toEqual(['f249'])
  })

  test('a file of this review churns at the rule\'s count of reviews in the window, most-reviewed first', () => {
    const review = (h: number, files: string[]) => ({ at: hoursAgo(h).toISOString(), files })
    const history = {
      v: 1 as const, folder: 'C:/proj', reviews: [
        review(30, ['a', 'b', 'c']), // outside the window
        review(-1, ['b']), // dated after now
        review(20, ['a', 'b', 'c', 'd']), review(10, ['a', 'b', 'c', 'd']), review(5, ['a', 'c', 'd']), review(0, ['a', 'b', 'c']),
      ],
    }
    // a: 4, b: 3 (the one at -1 h does not count); c: 4 and d: 3 are not in this review.
    expect(churned(history, ['b', 'a', 'a', 'x'], RULE, NOW)).toEqual([{ path: 'a', reviews: 4 }, { path: 'b', reviews: 3 }])
    expect(churned(history, ['b'], { reviews: 4, hours: 24 }, NOW)).toEqual([])
    expect(churned(history, ['c'], { reviews: 2, hours: 6 }, NOW)).toEqual([{ path: 'c', reviews: 2 }])
  })

  test('the prompt note names each churning file and asks for tests and a design check, no new features', () => {
    const text = flat(churnNote([{ path: 'C:/proj/a.py', reviews: 5 }], RULE))
    expect(text.includes('C:/proj/a.py (5 reviews)')).toBe(true)
    expect(text.includes('3 or more reviews in the last 24 hours')).toBe(true)
    expect(text.includes('Add no new features to these files')).toBe(true)
    expect(text.includes('ask whether their design needs another look')).toBe(true)
  })

  test('with the design question, the note asks Claude for its own redesign recommendation and leaves the call to the user', () => {
    const text = flat(churnNote([{ path: 'C:/proj/a.py', reviews: 5 }], RULE))
    expect(text.includes('give your own recommendation')).toBe(true)
    expect(text.includes('redesign yes, no, or not yet')).toBe(true)
    // Grounded in what Claude saw: the history has no findings, so it must not claim any from it.
    expect(text.includes('a one- or two-line reason grounded in the bugs you have seen in these reviews')).toBe(true)
    expect(text.includes('the history keeps only which files were reviewed and when, not what was found')).toBe(true)
    expect(text.includes('The same kind of bug coming back in one area points to yes')).toBe(true)
    expect(text.includes('unrelated one-off bugs in a busy file point to no')).toBe(true)
    expect(text.includes('too little seen to tell points to not yet')).toBe(true)
    expect(text.includes('When yes, sketch the smallest redesign that would stop those bugs coming back')).toBe(true)
    expect(text.endsWith('Then the user decides.')).toBe(true)
    // The recommendation comes with the question, not in place of it.
    expect(text.includes('write the exact question')).toBe(true)
    expect(text.indexOf('write the exact question')).toBeLessThan(text.indexOf('give your own recommendation'))
  })

  /**
   * A Windows session in C:/proj whose history files live in `files`; `written` lists each write to one,
   * `logged` each log line. `config`: the config file's text (none: no file). `readFails`: history reads fail.
   * `reads`: the texts history reads give, in turn, before `files` (a write landing between them, say).
   * `readHangs`: history reads never answer. `writeHangs`: history writes never answer.
   */
  function project(
    on: On,
    opts: { config?: string; readFails?: boolean; reads?: string[]; readHangs?: boolean; writeHangs?: boolean } = {},
    files: Record<string, string> = {},
  ) {
    const written: string[] = []
    const logged: string[] = []
    // On Linux the engine reads a Windows path as relative and puts its own folder first: drop that part.
    const norm = (p: string) => p.replace(/\\/g, '/').replace(/^.*?(?=[A-Za-z]:\/)/, '')
    const inHistory = (p: string) => norm(p).includes('/.claude/review-guard/history/')
    const isConfig = (p: string) => norm(p).endsWith('/.claude/review-guard.json')
    mock.env(on, { USERPROFILE: 'C:/Users/pat' })
    on('session.cwd', () => ({ value: 'C:/proj' }))
    on('session.id', () => ({ value: 's-1' }))
    on('ui.log', (_$, e) => {
      logged.push(String(e.text))
      return { value: undefined }
    })
    on('ui.status', () => ({ value: undefined }))
    on('fs.exists', (_$, e, next) => {
      if (isConfig(e.path)) return { value: opts.config !== undefined }
      return inHistory(e.path) ? { value: norm(e.path) in files } : next(e)
    })
    on('fs.read', (_$, e, next) => {
      if (isConfig(e.path) && opts.config !== undefined) return { value: opts.config }
      if (!inHistory(e.path)) return next(e)
      if (opts.readFails) throw new Error('EBUSY: locked')
      if (opts.readHangs) return new Promise<never>(() => {})
      const queued = opts.reads?.shift()
      if (queued !== undefined) return { value: queued }
      const text = files[norm(e.path)]
      if (text === undefined) throw new Error('ENOENT')
      return { value: text }
    })
    on('fs.write', (_$, e, next) => {
      if (!inHistory(e.path)) return next(e)
      if (opts.writeHangs) return new Promise<never>(() => {})
      files[norm(e.path)] = e.text
      written.push(norm(e.path))
      return { value: undefined }
    })
    const reviews = () => Object.values(files).flatMap(t => historyFrom(JSON.parse(t), 'C:/proj').history.reviews)
    return { files, written, logged, reviews }
  }

  test('a review is recorded once its prompt has arrived, under one spelling per file', async ($, on) => {
    const { reviews, logged } = project(on)
    const { edit, stop } = cycle($, on)
    await edit('c:\\proj\\app.py')
    expect((await stop())?.includes('app.py')).toBe(true)
    expect(reviews()).toEqual([]) // asked for, not yet known to have arrived
    expect(await stop(true)).toBe(undefined) // the review's own turn ends: it arrived
    expect([reviews().map(r => r.files), logged.filter(l => /churn|history/.test(l))]).toEqual([[['c:/proj/app.py']], []])
    // The same file under another spelling counts as the same file.
    await edit('C:/proj/app.py')
    await stop()
    await stop(true)
    expect(reviews().map(r => r.files)).toEqual([['c:/proj/app.py'], ['c:/proj/app.py']])
  })

  test('a review prompt that never arrived is not counted, and its files are counted once when asked again', async ($, on) => {
    const { reviews } = project(on)
    const { edit, stop } = cycle($, on)
    await edit('C:/proj/app.py')
    expect((await stop())?.includes('app.py')).toBe(true)
    // The next stop is no continuation: the prompt was lost, and the review is asked for again.
    expect((await stop())?.includes('app.py')).toBe(true)
    expect(reviews()).toEqual([])
    await stop(true)
    expect(reviews().length).toBe(1)
  })

  test('a history that cannot be read is left alone, said once in the log, and the review goes out all the same', async ($, on) => {
    const path = `C:/Users/pat/.claude/review-guard/history/${historyFileName('C:/proj')}`
    const { files, written, logged } = project(on, { readFails: true }, { [path]: '{"v":1,"reviews":[]}' })
    const { edit, stop } = cycle($, on)
    await edit('C:/proj/app.py')
    expect((await stop())?.includes('app.py')).toBe(true)
    await stop(true)
    expect(written).toEqual([])
    expect(files[path]).toBe('{"v":1,"reviews":[]}')
    expect(logged.filter(l => l.includes('churn check could not run')).length).toBe(1)
  })

  test('with churn off in the config, no history is written', async ($, on) => {
    const { written } = project(on, { config: '{"churn": false}' })
    const { edit, stop } = cycle($, on)
    await edit('C:/proj/app.py')
    expect((await stop())?.includes('app.py')).toBe(true)
    await stop(true)
    expect(written).toEqual([])
  })

  test('a file that keeps coming back gets the churn note in its review prompt, and only then', async ($, on) => {
    const { reviews, logged } = project(on, { config: '{"churn": {"reviews": 3, "hours": 1}}' })
    const { edit, stop } = cycle($, on)
    for (let i = 1; i <= 2; i++) {
      await edit('C:/proj/app.py')
      const prompt = await stop()
      expect([i, prompt?.includes('app.py'), prompt?.includes('keep coming back')]).toEqual([i, true, false])
      await stop(true)
    }
    // The third review in the hour: the note names the file, and says what to do.
    await edit('C:/proj/app.py')
    await edit('C:/proj/other.py')
    const third = flat((await stop()) ?? '')
    expect(third.includes('keep coming back')).toBe(true)
    expect(third.includes('c:/proj/app.py (3 reviews)')).toBe(true)
    expect(third.includes('other.py (')).toBe(false)
    expect(third.includes('Add no new features to these files')).toBe(true)
    expect(third.includes('redesign yes, no, or not yet')).toBe(true)
    expect(logged.some(l => l.includes('1 file(s) keep coming back'))).toBe(true)
    await stop(true)
    expect(reviews().length).toBe(3)
  })

  test('a history file that is not JSON is logged and started again, and the review goes out', async ($, on) => {
    const path = `C:/Users/pat/.claude/review-guard/history/${historyFileName('C:/proj')}`
    const { files, logged } = project(on, {}, { [path]: 'not json' })
    const { edit, stop } = cycle($, on)
    await edit('C:/proj/app.py')
    expect((await stop())?.includes('app.py')).toBe(true)
    await stop(true)
    expect(historyFrom(JSON.parse(files[path] ?? ''), 'C:/proj').history.reviews.map(r => r.files)).toEqual([['c:/proj/app.py']])
    expect(logged.filter(l => l.includes('history was damaged')).length).toBe(1)
  })

  test('a history caught part-way through a write by another session is read again, not started again', async ($, on) => {
    const path = `C:/Users/pat/.claude/review-guard/history/${historyFileName('C:/proj')}`
    const theirs = JSON.stringify({ v: 1, folder: 'C:/proj', reviews: [{ at: new Date().toISOString(), files: ['c:/proj/lib.py'] }] })
    // The check reads it whole; the read before the write finds it cut off; the second read whole again.
    const { files, logged } = project(on, { reads: [theirs, theirs.slice(0, 20)] }, { [path]: theirs })
    const { edit, stop } = cycle($, on)
    await edit('C:/proj/app.py')
    expect((await stop())?.includes('app.py')).toBe(true)
    await stop(true)
    expect(historyFrom(JSON.parse(files[path] ?? ''), 'C:/proj').history.reviews.map(r => r.files)).toEqual([['c:/proj/lib.py'], ['c:/proj/app.py']])
    expect(logged.filter(l => l.includes('history was damaged'))).toEqual([])
  })

  test('the second read of a part-written history waits a quarter second first', async ($, on) => {
    const clock = mock.clock(on)
    const path = `C:/Users/pat/.claude/review-guard/history/${historyFileName('C:/proj')}`
    const theirs = JSON.stringify({ v: 1, folder: 'C:/proj', reviews: [{ at: new Date().toISOString(), files: ['c:/proj/lib.py'] }] })
    const { files } = project(on, { reads: [theirs, theirs.slice(0, 20)] }, { [path]: theirs })
    const { edit, stop } = cycle($, on)
    await edit('C:/proj/app.py')
    await stop()
    const ended = stop(true)
    await clock.advance(249)
    expect(files[path]).toBe(theirs) // still waiting to read it again
    await clock.advance(1)
    await ended
    expect(historyFrom(JSON.parse(files[path] ?? ''), 'C:/proj').history.reviews.map(r => r.files)).toEqual([['c:/proj/lib.py'], ['c:/proj/app.py']])
  })

  test('a history another version wrote is left alone, and why is logged', async ($, on) => {
    const path = `C:/Users/pat/.claude/review-guard/history/${historyFileName('C:/proj')}`
    const theirs = '{"v":2,"reviews":[]}'
    const { files, written, logged } = project(on, {}, { [path]: theirs })
    const { edit, stop } = cycle($, on)
    await edit('C:/proj/app.py')
    expect((await stop())?.includes('app.py')).toBe(true)
    await stop(true)
    expect([written, files[path]]).toEqual([[], theirs])
    expect(logged.some(l => l.includes('another version of review-guard (v2)'))).toBe(true)
  })

  test('a slow history write is logged once past two seconds, and the turn ends without it', async ($, on) => {
    const clock = mock.clock(on)
    const { logged } = project(on, { writeHangs: true })
    const { edit, stop } = cycle($, on)
    await edit('C:/proj/app.py')
    await stop()
    const ended = stop(true)
    await clock.advance(2000)
    expect(await ended).toBe(undefined)
    expect(logged.filter(l => l.includes('took over two seconds')).length).toBe(1)
  })

  test('a history damaged again is logged again: each time loses entries', async ($, on) => {
    const path = `C:/Users/pat/.claude/review-guard/history/${historyFileName('C:/proj')}`
    const { files, logged } = project(on, {}, { [path]: 'not json' })
    const { edit, stop } = cycle($, on)
    for (let i = 0; i < 2; i++) {
      files[path] = 'not json'
      await edit('C:/proj/app.py')
      await stop()
      await stop(true)
    }
    expect(logged.filter(l => l.includes('history was damaged')).length).toBe(2)
  })

  test('a fast history write never logs that it took over two seconds', async ($, on) => {
    const clock = mock.clock(on)
    const { reviews, logged } = project(on)
    const { edit, stop } = cycle($, on)
    await edit('C:/proj/app.py')
    await stop()
    await stop(true)
    await clock.advance(5000)
    expect(reviews().length).toBe(1)
    expect(logged.filter(l => l.includes('over two seconds') || l.includes('over five seconds'))).toEqual([])
  })

  test('a fast churn check never logs that it took over five seconds, even with a history to read', async ($, on) => {
    const clock = mock.clock(on)
    const path = `C:/Users/pat/.claude/review-guard/history/${historyFileName('C:/proj')}`
    const { reviews, logged } = project(on, {}, { [path]: '{"v":1,"reviews":[]}' })
    const { edit, stop } = cycle($, on)
    for (let i = 0; i < 2; i++) {
      await edit('C:/proj/app.py')
      await stop()
      await clock.advance(6000)
      await stop(true)
      await clock.advance(6000)
    }
    expect(reviews().length).toBe(2)
    expect(logged.filter(l => l.includes('over five seconds') || l.includes('over two seconds'))).toEqual([])
  })

  test('a churn check past five seconds is logged each time, and the review goes out without it', async ($, on) => {
    const clock = mock.clock(on)
    // A history file is there, so the check reads it, and that read never answers.
    const path = `C:/Users/pat/.claude/review-guard/history/${historyFileName('C:/proj')}`
    const { logged } = project(on, { readHangs: true }, { [path]: '{"v":1,"reviews":[]}' })
    const { edit, stop } = cycle($, on)
    for (let i = 1; i <= 2; i++) {
      await edit('C:/proj/app.py')
      const asked = stop()
      await clock.advance(5000)
      expect((await asked)?.includes('app.py')).toBe(true)
      expect(logged.filter(l => l.includes('churn check took over five seconds')).length).toBe(i)
      await stop(true)
    }
  })

  test('a config that cannot be read skips the churn check rather than turn it back on', async ($, on) => {
    const { written, logged } = project(on, { config: '{"churn": false' })
    const { edit, stop } = cycle($, on)
    await edit('C:/proj/app.py')
    expect((await stop())?.includes('app.py')).toBe(true)
    await stop(true)
    expect(written).toEqual([])
    expect(logged.some(l => l.includes('churn check is skipped until the config can be read'))).toBe(true)
  })

  test('a review exactly at the edge of the window still counts; empty input gives nothing', () => {
    const history = { v: 1 as const, folder: 'C:/proj', reviews: [hoursAgo(24), hoursAgo(1), NOW].map(at => ({ at: at.toISOString(), files: ['a'] })) }
    expect(churned(history, ['a'], RULE, NOW)).toEqual([{ path: 'a', reviews: 3 }])
    expect(churned(history, [], RULE, NOW)).toEqual([])
    expect(churned({ ...history, reviews: [] }, ['a'], RULE, NOW)).toEqual([])
  })

  test('a bad churn value is logged and the default rule used', async ($, on) => {
    const { reviews, logged } = project(on, { config: '{"churn": {"reviews": 1}}' })
    const { edit, stop } = cycle($, on)
    await edit('C:/proj/app.py')
    await stop()
    await stop(true)
    expect(reviews().length).toBe(1)
    expect(logged.some(l => l.includes('"churn" must be') && l.includes('default rule'))).toBe(true)
  })
})

describe('shadow look', () => {
  const C = ['git', 'commit'].join(' ') // spelled apart, so the guard never reads this file's commands as one
  const rec = (letters: string, path: string) => `1 ${letters} N... 100644 100644 100644 h1 h2 ${path}`
  const status = (head: string, ...records: string[]) => [`# branch.oid ${head}`, '# branch.head main', ...records].map(r => `${r}\0`).join('')
  const snap = (out: string, stats: Record<string, number>, texts: Record<string, string> = {}) => {
    const state = parseStatus(out)
    return { repo: 'C:/r', state, stats: new Map([...state.entries.keys()].map(p => [p, p in stats ? { mtimeMs: stats[p] ?? 0, size: 1, text: texts[p] } : undefined])) }
  }

  test('git status v2 is read: each kind of record, a renamed file\'s old path skipped, a name with spaces, no commit yet', () => {
    const out = status('abc', rec('.M', 'src/a b.ts'), '2 R. N... 100644 100644 100644 h1 h2 R100 new.ts', 'old.ts',
      'u UU N... 100644 100644 100644 100644 h1 h2 h3 both.ts', '? notes.py', '! build/x.js', rec('D.', 'f.py'), '? f.py')
    const { head, entries } = parseStatus(out)
    // A path listed twice (`git rm --cached`) keeps its tracked record.
    expect([head, [...entries]]).toEqual(['abc', [['src/a b.ts', '.M'], ['new.ts', 'R.'], ['both.ts', 'UU'], ['notes.py', '??'], ['f.py', 'D.']]])
    expect(parseStatus(status('(initial)', '? a.py')).head).toBe(undefined)
    expect(() => parseStatus(status('abc', 'X what'))).toThrow()
    expect(() => parseStatus(`${rec('.M', 'a.ts')}\0`)).toThrow() // no commit named
  })

  test('only work-tree evidence is a write: new, newly changed, or changed again; not staging, not a deletion', () => {
    const before = snap(status('h', rec('.M', 'again.ts'), rec('.M', 'same.ts'), rec('.M', 'staged.ts'), rec('.M', 'copied.ts')),
      { 'again.ts': 1, 'same.ts': 1, 'staged.ts': 1, 'copied.ts': 1 }, { 'copied.ts': 'old' })
    const after = snap(status('h', rec('.M', 'again.ts'), rec('.M', 'same.ts'), rec('M.', 'staged.ts'), rec('.M', 'copied.ts'), rec('.M', 'edited.ts'), '? new.py', rec('.D', 'gone.ts'), rec('.M', 'nolonger.ts')),
      { 'again.ts': 2, 'same.ts': 1, 'staged.ts': 1, 'copied.ts': 1, 'edited.ts': 5, 'new.py': 5, 'gone.ts': 5 }, { 'copied.ts': 'new' })
    // copied.ts kept its time and size (`cp -p`), but its text changed.
    expect(changedBetween(before, after)).toEqual(['again.ts', 'copied.ts', 'edited.ts', 'new.py'])
  })

  test('a commit counts only what the command itself wrote, never a file changed before it and untouched', () => {
    const before = snap(status('a', rec('.M', 'earlier.ts'), rec('.M', 'formatted.ts')), { 'earlier.ts': 1, 'formatted.ts': 1 })
    const now = (t: number) => ({ mtimeMs: t, size: 1 })
    expect(committedWrites(before, [['earlier.ts', now(1)], ['formatted.ts', now(2)], ['fresh.ts', now(1)], ['gone.ts', undefined]])).toEqual(['formatted.ts', 'fresh.ts'])
  })

  test('HEAD moved by a commit counts the commit\'s files; any git command that moves it or brings in work is not compared', () => {
    expect(headMove(`${C} -am x`, 'a', 'a')).toBe('none')
    expect(headMove(`sed -i s/a/b/ x.py && git add -A && ${C} -am x`, 'a', 'b')).toBe('commit')
    expect(headMove(`git -C /r ${C.slice(4)} -qm x`, 'a', 'b')).toBe('commit')
    // The usual way to commit: add, commit, push (push and fetch leave the work tree alone).
    expect(headMove(`git add -A && ${C} -m x && git push && git fetch`, 'a', 'b')).toBe('commit')
    expect(headMove(`git pull && ${C} -am x`, 'a', 'b')).toBe('other')
    expect(headMove('git pull', 'a', 'b')).toBe('other')
    expect(headMove(`${C} -m first`, undefined, 'b')).toBe('other') // the first commit
    expect(headMove('git -C /r am < fix.patch', 'a', 'b')).toBe('other')
    // Other work brought in with HEAD where it was.
    expect(headMove('git stash pop', 'a', 'a')).toBe('other')
    expect(headMove('git checkout main -- src/a.ts', 'a', 'a')).toBe('other')
    // An alias, a quoted folder with a space, `gh pr checkout`: not read as only a commit.
    expect(headMove(`git co main && ${C} -am x`, 'a', 'b')).toBe('other')
    expect(headMove(`git -C "/a b" pull && ${C} -am x`, 'a', 'b')).toBe('other')
    expect(headMove(`gh pr checkout 5 && ${C} -am x`, 'a', 'b')).toBe('other')
    // A long line of options is read word by word, never by a pattern that could take exponential time.
    const long = `git ${'-C -C '.repeat(5_000)}x`
    const t0 = Date.now()
    expect(headMove(long, 'a', 'b')).toBe('other')
    expect(Date.now() - t0 < 1_000).toBe(true)
  })

  test('the git commands of a line are found after git\'s own options, never in a command\'s options', () => {
    expect(gitSubcommands(`cd /r && git -C /r -c a=b --no-pager --git-dir x/.git ${C.slice(4)} -am x; /usr/bin/git pull`)).toEqual(['commit', 'pull'])
    expect(gitSubcommands('git -C "C:/my repo" status')).toEqual(['status'])
    expect(gitSubcommands('echo digit && gitk')).toEqual([])
  })

  test('paths are compared as the platform reads them: slashes, Git Bash drives, `.` and `..` steps, case on Windows', () => {
    expect(normalPath('/c/Work//Repo/./src/../a.ts', true)).toBe('c:/work/repo/a.ts')
    expect(normalPath('C:\\Work\\Repo\\a.ts', true, false)).toBe('C:/Work/Repo/a.ts')
    expect(normalPath('/home/u/./x/../a.py', false)).toBe('/home/u/a.py')
    expect(relativeTo('C:/R', 'c:/r//src/a.ts', true)).toBe('src/a.ts')
    expect(relativeTo('C:/R', 'C:/R/../x.ts', true)).toBe(undefined)
    expect(relativeTo('C:/R', '/c/R/sub/b.py', true)).toBe('sub/b.py')
    expect(relativeTo('/r', '/R/a.py', false)).toBe(undefined)
    // A network path keeps its two slashes; a `..` above a root is dropped, as the system does.
    expect(normalPath('\\\\srv\\share\\repo\\a.ts', true, false)).toBe('//srv/share/repo/a.ts')
    expect(isFullPath('\\\\srv\\share\\a.ts', true)).toBe(true)
    expect(normalPath('C:/../a.ts', true, false)).toBe('C:/a.ts')
    expect(normalPath('/../a.py', false)).toBe('/a.py')
    expect(normalPath('//home/u/a.py', false)).toBe('/home/u/a.py') // `//` is a network path on Windows only
    expect(relativeTo('C:', 'C:/a.ts', true)).toBe('a.ts')
    // A file of a repository nested in another goes to the inner one.
    expect(repoFor(['C:/R', 'C:/R/vendor/lib'], 'C:/R/vendor/lib/a.ts', true)).toBe('C:/R/vendor/lib')
  })

  test('the comparison counts code files only, by their place in the repository, and nothing under .claude on either side', () => {
    const isCode = (p: string) => /\.(?:ts|py)$/.test(p) && !/(^|\/)build\//.test(p)
    // A repository inside a `build` folder still has code.
    const r = compareWithGuess('C:/build/R', ['src/A.ts', 'run.log', '.claude/x.py', 'new.py'], ['c:\\build\\r\\src\\a.ts', 'C:/build/R/b.ts', 'C:/build/R/.claude/y.py'], true, isCode)
    expect(r).toEqual({ gitOnly: ['C:/build/R/new.py'], guessOnly: ['C:/build/R/b.ts'] })
  })

  // Repositories at R (the session's) and O, as git and the disk show them, with the shadow record kept in
  // `written` (its texts as written, and read back). A file's first look is before the command, each later
  // one after: only src/dirty.ts's time changes.
  function repoWorld(on: On, statuses: Record<string, string[]>, opts: { fail?: string; ignored?: string; diff?: string; record?: string; oneAtATime?: boolean; together?: boolean; hang?: boolean; failOther?: boolean } = {}) {
    const R = 'C:/work/repo'
    const O = 'C:/work/other'
    mock.env(on, { USERPROFILE: 'C:/Users/pat', TEMP, LOCALAPPDATA: 'C:/Users/pat/AppData/Local' })
    const files = [R, O].flatMap(root => ['src/dirty.ts', 'src/a.ts', 'src/new.py', 'logs/run.log', '.claude/x.py', 'src/b.ts', 'src/committed.ts'].map(f => `${root}/${f}`))
    const looks = new Map<string, number>()
    const norm = (raw: unknown) => String(raw).replace(/\\/g, '/').replace(/^.*?(?=[A-Za-z]:\/)/, '')
    const SHADOW = 'C:/Users/pat/.claude/review-guard/shadow.jsonl'
    on('fs.stat', (_$, e) => {
      const path = norm(e.path).replace(/\/\.$/, '')
      if (path === R || path === O || path === TEMP) return { value: { kind: 'dir' as const, size: 0, mtimeMs: 0, isLink: false, realPath: path } }
      if (!files.includes(path)) throw Object.assign(new Error(`ENOENT: ${e.path}`), { code: 'ENOENT' })
      const n = (looks.get(path) ?? 0) + 1
      looks.set(path, n)
      return { value: { kind: 'file' as const, size: 10, mtimeMs: path.endsWith('dirty.ts') && n > 1 ? 2 : 1, isLink: false } }
    })
    on('session.cwd', () => ({ value: R }))
    const seen = { calls: [] as string[], timeouts: [] as (number | undefined)[], written: [] as string[], logged: [] as string[], overlapped: [] as boolean[] }
    let otherAsked = 0
    const record = () => seen.written.at(-1) ?? opts.record ?? ''
    on('fs.read', (_$, e) => {
      if (norm(e.path) === SHADOW) return { value: record() }
      if (files.includes(norm(e.path))) return { value: 'x = 1' }
      throw Object.assign(new Error(`ENOENT: ${e.path}`), { code: 'ENOENT' })
    })
    on('fs.exists', (_$, e) => ({ value: norm(e.path) === SHADOW && record() !== '' }))
    on('fs.write', (_$, e) => {
      if (norm(e.path) === SHADOW) seen.written.push(e.text)
      return { value: undefined }
    })
    on('process.run', async (_$, e) => {
      const line = e.argv.join(' ')
      seen.calls.push(line)
      seen.timeouts.push(e.init?.timeoutMs)
      const ok = (stdout: string, exitCode = 0, stderr = '') => ({ value: { exitCode, stdout, stderr, isStdoutTruncated: false, isStderrTruncated: false } })
      const root = line.includes(O) ? O : R
      if (line.includes('rev-parse --show-toplevel')) return ok(`${root}\n`)
      if (line.includes('get-regexp')) return ok('', 1)
      if (line.includes(' status ')) {
        if (opts.fail) return ok('', 128, `fatal: ${opts.fail}`)
        if (opts.failOther && root === O) return ok('', 128, 'fatal: cannot read (other test)')
        // A git status that never answers: the look runs out of time while it is still running.
        if (opts.hang) return new Promise<never>(() => {})
        if (opts.together && root === O) otherAsked++
        if (opts.together && root === R) {
          // The session's repository answers late: was the other one asked meanwhile (side by side)?
          const asked = otherAsked
          await new Promise(r => setTimeout(r, 50))
          seen.overlapped.push(otherAsked > asked)
        }
        return ok(statuses[root]?.shift() ?? '')
      }
      if (line.includes('check-ignore')) {
        const names = String(e.init?.stdin ?? '').split('\0').filter(n => n !== '')
        // As for a name in a submodule: git refuses the whole call.
        if (opts.oneAtATime && names.length > 1) return ok('', 128, 'fatal: Pathspec is in submodule')
        const hits = (opts.ignored ?? '').split('\0').filter(n => names.includes(n))
        return ok(hits.map(h => `${h}\0`).join(''), hits.length > 0 ? 0 : 1)
      }
      if (line.includes(' diff ')) return ok(opts.diff ?? '')
      return ok('')
    })
    on('ui.log', (_$, e) => {
      seen.logged.push(String(e.text))
      return { value: undefined }
    })
    const lines = () => record().trim().split('\n').filter(l => l !== '').map(l => JSON.parse(l))
    return { R, O, seen, lines }
  }

  test('a command the guess cannot be sure of is looked at with git, and the record says where the two differ; the review is unchanged', async ($, on) => {
    const before = status('h', rec('.M', 'src/dirty.ts'), rec('.M', 'src/a.ts'))
    const after = status('h', rec('.M', 'src/dirty.ts'), rec('.M', 'src/a.ts'), '? src/new.py', '? logs/run.log', '? .claude/x.py')
    const { R, seen, lines } = repoWorld(on, { 'C:/work/repo': [before, after] }, { ignored: 'src/b.ts\0' })
    const { stop } = cycle($, on)
    await $.tool.call({ tool: 'Bash', command: `cd "${R}" && npm run fix && sed -i s/a/b/ src/b.ts` })
    const prompt = (await stop()) ?? ''
    // The review is the guess's: b.ts, not what only git saw.
    expect([prompt.includes(`${R}/src/b.ts`), prompt.includes('src/a.ts'), prompt.includes('new.py')]).toEqual([true, false, false])
    const list = (...paths: string[]) => ({ count: paths.length, paths })
    expect(lines().at(-1)?.repos).toEqual([{ repo: R, agree: false, gitOnly: list(`${R}/src/dirty.ts`, `${R}/src/new.py`), guessOnly: list(), ignored: list(`${R}/src/b.ts`) }])
    expect(lines().at(-1)?.unplaced).toBe(0)
    // Every git run the look makes is held to its short limit, the filter check included.
    const gitRuns = seen.timeouts.filter((_t, i) => seen.calls[i]?.startsWith('git '))
    expect(gitRuns.length > 0 && gitRuns.every(t => t !== undefined && t <= GIT_TIMEOUT_MS)).toBe(true)
  })

  test('a commit adds what it took in that the command wrote, not files changed before it; a pull is not compared', async ($, on) => {
    const { R, lines } = repoWorld(on, { 'C:/work/repo': [status('a', rec('.M', 'src/a.ts')), status('b'), status('b'), status('c')] }, { diff: 'src/a.ts\0src/committed.ts\0' })
    cycle($, on)
    await $.tool.call({ tool: 'Bash', command: `cd "${R}" && git add -A && ${C} -qm x` })
    await $.tool.call({ tool: 'Bash', command: `cd "${R}" && git pull` })
    const [committed, pulled] = lines().slice(-2).map(l => l.repos)
    expect(committed?.[0]?.gitOnly?.paths).toEqual([`${R}/src/committed.ts`])
    expect(pulled?.[0]?.skipped).toContain('moves HEAD')
  })

  test('a cd into another repository looks at both, and each guessed name is compared in its own', async ($, on) => {
    const { R, O, lines } = repoWorld(on, { 'C:/work/repo': [status('h'), status('h')], 'C:/work/other': [status('h'), status('h', rec('.M', 'src/b.ts'))] })
    cycle($, on)
    await $.tool.call({ tool: 'Bash', command: `cd "${O}" && npm run fix && sed -i s/a/b/ src/b.ts` })
    const repos = lines().at(-1)?.repos ?? []
    expect(repos.map((r: { repo: string; agree: boolean }) => [r.repo, r.agree])).toEqual([[R, true], [O, true]])
  })

  test('both repositories are looked at side by side, and each step of the look is timed in the record', async ($, on) => {
    const { R, O, seen, lines } = repoWorld(on, { 'C:/work/repo': [status('h'), status('h')], 'C:/work/other': [status('h'), status('h')] }, { together: true })
    cycle($, on)
    await $.tool.call({ tool: 'Bash', command: `cd "${O}" && npm run fix` })
    // Before and after the command, the other repository's status was asked while the session's waited.
    expect(seen.overlapped).toEqual([true, true])
    const last = lines().at(-1)
    expect(last?.repos?.map((r: { repo: string }) => r.repo)).toEqual([R, O])
    type Step = { what: string; in?: string; at: number; ms?: number }
    const timed = (steps: Step[] | undefined, what: string, where: string) =>
      (steps ?? []).some(s => s.what === what && s.in === where && s.at >= 0 && s.at < 60_000 && typeof s.ms === 'number' && s.ms >= 0)
    const { before, after } = last?.steps ?? {}
    // The filter check runs after the command too: it may have set a filter up without running it.
    expect([R, O].flatMap(where => [timed(before, 'git status', where), timed(before, 'git config', where), timed(before, 'look', where), timed(after, 'git status', where), timed(after, 'git config', where), timed(after, 'look', where)]))
      .toEqual(Array(12).fill(true))
  })

  test('a repository git cannot open is recorded and logged, and the other is still compared', async ($, on) => {
    const { R, O, seen, lines } = repoWorld(on, { 'C:/work/repo': [status('h'), status('h'), status('h'), status('h')] }, { failOther: true })
    cycle($, on)
    for (let i = 0; i < 2; i++) await $.tool.call({ tool: 'Bash', command: `cd "${O}" && npm run fix` })
    // The one that failed comes first (it failed before the command), then each compared one.
    const repos = lines().at(-1)?.repos ?? []
    expect(repos.map((r: { repo: string; agree?: boolean; failed?: string }) => [r.repo, r.agree ?? r.failed?.includes('(other test)')])).toEqual([[O, true], [R, true]])
    // Recorded each time, logged once.
    expect(seen.logged.filter(l => l.includes('(other test)')).length).toBe(1)
  })

  test('a look that runs out of time is recorded with its steps, the one still running with no time', async ($, on) => {
    const clock = mock.clock(on)
    const { R, lines } = repoWorld(on, {}, { hang: true })
    cycle($, on)
    const call = $.tool.call({ tool: 'Bash', command: `cd "${R}" && npm run fix` })
    for (let i = 0; i < 10 && !lines().some(l => l.failed); i++) await clock.advance(1000)
    await call
    const late = lines().find(l => String(l.failed ?? '').includes('took over 4 seconds'))
    const steps: { what: string; in?: string; ms?: number }[] = late?.steps?.before ?? []
    expect(steps.some(s => s.what === 'git status' && s.in === R && s.ms === undefined)).toBe(true)
    expect(steps.some(s => s.what === 'git config' && s.in === R && typeof s.ms === 'number')).toBe(true)
  })

  test('a guessed name outside the repository or with a `..` step loses no record; a name the guess could not place is only counted', async ($, on) => {
    const { R, lines } = repoWorld(on, { 'C:/work/repo': [status('h'), status('h'), status('h'), status('h')] })
    cycle($, on)
    await $.tool.call({ tool: 'Bash', command: `cd "${R}" && npm run fix && sed -i s/a/b/ /tmp/x.py ../x.ts` })
    expect(lines().at(-1)?.repos?.[0]?.agree).toBe(true)
    // A second cd the guess can't follow: its relative name is not compared against the session's folder.
    await $.tool.call({ tool: 'Bash', command: `cd "${R}" && cd sub && npm run fix && sed -i s/a/b/ lib.py` })
    expect([lines().at(-1)?.repos?.[0]?.agree, lines().at(-1)?.unplaced]).toEqual([true, 1])
  })

  test('when git refuses to say which of several names it ignores, each is asked on its own', async ($, on) => {
    const { R, lines } = repoWorld(on, { 'C:/work/repo': [status('h'), status('h')] }, { ignored: 'src/b.ts\0', oneAtATime: true })
    cycle($, on)
    await $.tool.call({ tool: 'Bash', command: `cd "${R}" && npm run fix && sed -i s/a/b/ src/b.ts src/a.ts` })
    const repo = lines().at(-1)?.repos?.[0]
    expect([repo?.ignored?.paths, repo?.guessOnly?.paths]).toEqual([[`${R}/src/b.ts`], [`${R}/src/a.ts`]])
  })

  test('a commit beside a script or tool that may pull is not compared; a background command marks later records', async ($, on) => {
    const { R, lines } = repoWorld(on, { 'C:/work/repo': [status('a'), status('b'), status('b'), status('b')] }, { diff: 'src/committed.ts\0' })
    cycle($, on)
    await $.tool.call({ tool: 'Bash', command: `cd "${R}" && npm run update && ${C} -am x` })
    expect(lines().at(-1)?.repos?.[0]?.skipped).toContain('moves HEAD')
    await $.tool.call({ tool: 'Bash', command: `cd "${R}" && npm run watch`, run_in_background: true })
    await $.tool.call({ tool: 'Bash', command: `cd "${R}" && npm run fix` })
    expect(lines().at(-1)?.othersWriting).toBe(true)
  })

  test('PowerShell is looked at too', async ($, on) => {
    const { R, lines } = repoWorld(on, { 'C:/work/repo': [status('h'), status('h')] })
    cycle($, on)
    await $.tool.call({ tool: 'PowerShell', command: `Set-Location "${R}"; npx prettier --write .` })
    expect(lines().at(-1)?.shell).toBe('powershell')
  })

  test('plain commands and background ones are not looked at: no git runs', async ($, on) => {
    const { R, seen } = repoWorld(on, {})
    cycle($, on)
    await $.tool.call({ tool: 'Bash', command: `ls ${R} && sed -i s/a/b/ ${R}/src/b.ts && echo "make sure"` })
    await $.tool.call({ tool: 'Bash', command: `cd "${R}" && npm run fix`, run_in_background: true })
    expect(seen.calls.filter(c => c.startsWith('git '))).toEqual([])
  })

  test('a look that fails is logged once for its reason and recorded each time, and the review goes on', async ($, on) => {
    const { R, seen, lines } = repoWorld(on, {}, { fail: 'git timed out (shadow test)' })
    const { stop } = cycle($, on)
    await $.tool.call({ tool: 'Bash', command: `cd "${R}" && npm run fix && sed -i s/a/b/ src/b.ts` })
    await $.tool.call({ tool: 'Bash', command: `cd "${R}" && npm run fix` })
    expect((await stop())?.includes(`${R}/src/b.ts`)).toBe(true)
    expect(seen.logged.filter(l => l.includes('(shadow test)')).length).toBe(1)
    expect(lines().filter(l => String(l.failed ?? '').includes('(shadow test)')).length).toBe(2)
  })

  test('the record keeps only its last megabyte, so it can always be read back', async ($, on) => {
    const old = `${JSON.stringify({ at: 'x', pad: 'y'.repeat(1_000) })}\n`.repeat(3_000) // about 3 MB
    const { R, seen, lines } = repoWorld(on, { 'C:/work/repo': [status('h'), status('h')] }, { record: old })
    cycle($, on)
    await $.tool.call({ tool: 'Bash', command: `cd "${R}" && npm run fix` })
    expect((seen.written.at(-1)?.length ?? 0) <= 1024 * 1024).toBe(true)
    expect(lines().at(-1)?.shell).toBe('bash')
  })
})
