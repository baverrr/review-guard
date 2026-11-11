import type { On } from 'claude-code'
import { describe, type Engine, expect, mock, test } from 'claude-code/testing'
import {
  ghWrites, isNewRequest, gitAction, githubRepo, languageOf, localPart, networkAllowed, report, resolveDir, reviewPrompt, scanDiff, scanLine, scanValue, settle, shellWrites,
} from '../hooks/scan'

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

type Status = 'pending' | 'running' | 'waiting' | 'idle' | 'completed'

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

/** Stands for the engine under the review cycle; `agents` is what is still out, changed by the test. */
function cycle($: Engine, on: On) {
  const out = { agents: [] as { status: Status }[] }
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
  await $.prompt.submit({ text: 'also change the other file', wait: false, origin: { kind: 'composer' } })
  await edit('C:/proj/other.py')
  expect((await stop())?.includes('other.py')).toBe(true)
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

test('knows which code files a shell command writes', async () => {
  expect(shellWrites("sed -i 's/a/b/' src/app.py")).toEqual(['src/app.py'])
  expect(shellWrites("cat > hooks/scan.ts <<'EOF'\nconst a = 1\nEOF")).toEqual(['hooks/scan.ts'])
  expect(shellWrites('echo "x = 1" >> "my app/settings.py"')).toEqual(['my app/settings.py'])
  expect(shellWrites("python - <<'PY'\nimport pathlib\npathlib.Path('tests/a.test.ts').write_text('x')\nPY")).toEqual(['tests/a.test.ts'])
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
  // A script run after here-documents that only write notes is not written (the one exception).
  const notes = "python -I - <<'EOF'\nimport pathlib\npathlib.Path('notes.md').write_text('x')\nEOF\n"
  expect(shellWrites(notes + 'python -I .scripts/memory-map.py 2>&1 | tail -2')).toEqual([])
  expect(shellWrites(notes + '.venv/bin/python run.py && node build.js; pwsh -NoProfile -File deploy.ps1')).toEqual([])
  expect(shellWrites(notes.replace("'notes.md'", "'Changes/Change log.md'") + 'python -I .scripts/memory-map.py')).toEqual([])
  expect(shellWrites(notes.replace('\r', '').replace(/\n/g, '\r\n') + 'python run.py')).toEqual([]) // CRLF
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
  await $.turn.complete({ reason: 'answer', answer: 'ok', durationMs: 1, isAborted: false, turnId: 't1' })
  expect(await stop()).toBe(undefined) // still the same review
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
function world(on: On, git: Record<string, Run> = {}, config: string | undefined = CONFIG) {
  // `git` and `config` can be changed between calls: hooks are registered once, before the first call.
  const seen = { ran: false, status: [] as string[], calls: [] as string[], git, config: config as string | undefined }
  mock.env(on, { USERPROFILE: 'C:/Users/pat' })
  on('process.run', (_$, e) => {
    const line = e.argv.join(' ')
    seen.calls.push(line)
    const key = Object.keys(seen.git).find(k => line.includes(k))
    const base = { exitCode: 0, stdout: line.includes('remote -v') ? REMOTE : '', stderr: '', isStdoutTruncated: false, isStderrTruncated: false }
    return { value: { ...base, ...(key ? seen.git[key] : {}) } }
  })
  on('fs.read', () => {
    if (seen.config === undefined) throw new Error('no such file')
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

describe('the git guard', () => {
  test('stops a commit with a key in it and lets a clean one through', async ($, on) => {
    const seen = world(on, { '--cached': { stdout: added('app.py', `key = "${FAKE_GH}"`) } })
    const r = await $.tool.call({ tool: 'Bash', command: 'cd /c/proj/app && git commit -m x' })
    expect(r.deny?.includes('GitHub token at app.py:1')).toBe(true)
    expect(r.deny?.includes(FAKE_GH)).toBe(false)
    expect(seen.ran).toBe(false)
    expect(seen.calls[0]?.startsWith('git -C C:/proj/app remote -v')).toBe(true)
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

