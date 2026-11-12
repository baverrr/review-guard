import type { On } from 'claude-code'
import { describe, type Engine, expect, mock, test } from 'claude-code/testing'
import {
  addedLines, ghWrites, inScratch, isNewRequest, gitAction, githubRepo, languageOf, localPart, networkAllowed, type Paths, report, REPORT_EVERYTHING, resolveDir, reviewPrompt, runOnlyScripts, scanDiff, scanLine, scanValue, settle, shellWrites,
} from '../hooks/scan'
import { REVIEW_AGENTS } from '../hooks/agents'
import { candidates, gitleaksFindings, scannerCommand, scannersFor, scannerSteps } from '../hooks/scanners'

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
    // Kept on disk and run here, written somewhere ssh doesn't read, or a real push after the ssh line: still local.
    expect(gitAction(sshScript + 'bash "$S/run.sh"')?.pushes).toBe(true)
    expect(gitAction(sshScript.replace('cat > "$S/run.sh"', 'cat > /tmp/notes.md') + "ssh box 'bash -s' < \"$S/run.sh\"")?.pushes).toBe(true)
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

  test('every finding is acted on, low ones included, and each ends in one stated outcome', async () => {
    const text = flat(reviewPrompt(new Map([['a.py', 'Python']])))
    // The agents get a sentence to pass on that overrides their own cutoffs.
    expect(text.includes(`prompt word for word: "${REPORT_EVERYTHING}"`)).toBe(true)
    expect(REPORT_EVERYTHING.includes('overrides any confidence threshold')).toBe(true)
    for (const part of [
      'Act on every finding, whatever its severity: low, info and style ones',
      '"Minor", "style" or "fine here" alone is never a reason to leave one',
      'Fixed: say which file and line changed',
      'Does not hold up: show why in one line, with the code, path or output that proves it',
      'Holds up but is not fixed here',
      'never count it as fixed',
      'If an agent or scanner fails or returns nothing, say which one and why',
      'Rerun the tests (if the project has none, say so) and the scanners',
      'Stop after three rounds and list what is still open',
      'Tell the user every finding and its outcome',
      'Commit or push nothing as part of this review unless the user asked for that',
      'was itself this review, say so in one line and stop',
    ]) expect(text.includes(part)).toBe(true)
    // The steps come once each, in order.
    const at = ['1. Run the', '2. Security review', '3. Act on every finding', '4. Rerun', '5. Tell the user'].map(s => text.indexOf(s))
    expect(at.every((n, i) => n >= 0 && (i === 0 || n > at[i - 1]))).toBe(true)
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
function disk(on: On, files: Record<string, number>, changes: Record<string, Partial<FileState>> = {}, links: string[] = []) {
  mock.env(on, { USERPROFILE: 'C:/Users/pat', TEMP })
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
    const path = norm(e.path)
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
  for (const [command, script] of [
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
    expect(python.slice('- Python: '.length).split(', ').includes(script)).toBe(true)
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

test('what is left out goes after a guard notice on the status line, never over it', async ($, on) => {
  const status = disk(on, { [MAP]: 1 })
  const { stop } = cycle($, on)
  await $.tool.call({ tool: 'Bash', command: `${RUN_AFTER_NOTES}; ssh box 'git push'` })
  expect(await stop()).toBe(undefined)
  const last = status.at(-1) ?? ''
  expect(last.includes('sent over SSH') && last.includes('was NOT checked here')).toBe(true)
  expect(last.includes('Not reviewed: only run .scripts/memory-map.py')).toBe(true)
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
  expect(inScratch(`${TEMP.replace(/\//g, '\\')}\\claude\\a\\s.py`, temp, true, true)).toBe(true)
  expect(inScratch('/c/users/PAT/appdata/local/temp/CLAUDE/a.py', temp, true, true)).toBe(true) // Git Bash, any case on Windows
  expect(inScratch('/tmp/claude-1000/a.py', [], false, true)).toBe(true)
  expect(inScratch('/TMP/claude-1000/a.py', [], false, true)).toBe(false) // Linux names keep their case
  expect(inScratch('/tmp/claude-1/a.py', [], true, false)).toBe(false) // PowerShell: /tmp is C:\tmp
  expect(inScratch(`${TEMP}/a.py`, temp, true, true)).toBe(false) // temp, but not Claude's
  expect(inScratch(`${TEMP}/claude`, temp, true, true)).toBe(false) // the folder itself
  expect(inScratch('/tmp/claude/../../home/pat/app.py', [], false, true)).toBe(false) // `..` climbs out
  expect(inScratch('C:/claude/a.py', ['C:/', '/', 'C:'], true, false)).toBe(false) // a root is no temp folder
  expect(inScratch('C:/proj/claude/a.py', ['proj', 'tmp'], true, false)).toBe(false) // nor a relative one
  expect(inScratch('C:/Users/pat/AppData/Local/TempX/claude/a.py', temp, true, true)).toBe(false)

  expect([...runOnlyScripts(RUN_AFTER_NOTES, WIN)]).toEqual([['.scripts/memory-map.py', MAP]])
  expect([...runOnlyScripts('cd ~/proj && python3 -I gen.py 2>&1 | tail -3', LINUX)]).toEqual([['gen.py', '/home/pat/proj/gen.py']])
  expect([...runOnlyScripts('node "C:/tools/b.mjs" out.html', WIN)]).toEqual([['C:/tools/b.mjs', 'C:/tools/b.mjs']])
  // A backslash anywhere can escape a quote the here-document split can't follow: no candidates, so reviewed.
  expect([...runOnlyScripts('node "C:\\tools\\b.mjs" out.html', WIN)]).toEqual([])
  // PowerShell's `~` is the profile folder, not HOME.
  expect([...runOnlyScripts('cd ~/p; python gen.py', { windows: true, home: 'D:/h', userProfile: 'C:/Users/pat' }, true)])
    .toEqual([['gen.py', 'C:/Users/pat/p/gen.py']])
  expect([...runOnlyScripts('cd ~/p; python gen.py', { windows: true, home: 'D:/h', userProfile: 'C:/Users/pat' })])
    .toEqual([['gen.py', 'D:/h/p/gen.py']])
  expect([...runOnlyScripts('python /d/work/gen.py', LINUX)]).toEqual([['/d/work/gen.py', '/d/work/gen.py']]) // a real Linux folder
  expect([...runOnlyScripts('python /d/work/gen.py', WIN)]).toEqual([['/d/work/gen.py', 'D:/work/gen.py']])
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
    'cd C:/p && { python gen.py; }', // a group
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
function world(on: On, git: Record<string, Run> = {}, config: string | undefined = CONFIG, files: Record<string, string> = {}) {
  // `git` and `config` can be changed between calls: hooks are registered once, before the first call.
  // Programs in the scanners folder exist; `stdin` and `cwd` record what gitleaks was given.
  const seen = {
    ran: false, status: [] as string[], calls: [] as string[], git, config: config as string | undefined,
    stdin: [] as string[], cwd: [] as (string | undefined)[], missing: [] as string[], // scanners not installed at all
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
    return { value: p.includes('/Tools/scanners/bin/') && !seen.missing.some(m => p.endsWith(`/${m}.exe`)) }
  })
  on('fs.read', (_$, e) => {
    const file = Object.keys(files).find(f => e.path.replace(/\\/g, '/').endsWith(`/${f}`))
    if (file) return { value: files[file] ?? '' }
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
    expect(r.deny?.includes('gitleaks failed: boom')).toBe(true)
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
    expect(steps.at(-1)?.includes('Not installed here (or would not run), so skipped')).toBe(true)
    expect(steps.at(-1)?.includes('semgrep, zizmor')).toBe(true)
    expect(scannerCommand('zizmor', 'zizmor', ['w.yml'])).toBe("'zizmor' --offline 'w.yml'")
    // Bash expands nothing in single quotes; a quote inside is closed, escaped and reopened.
    expect(scannerCommand('bandit', 'bandit', ["it's $HOME/a.py"])).toBe("'bandit' -q 'it'\\''s $HOME/a.py'")
    expect(scannerCommand('semgrep', 'semgrep', ['a.py']).includes('--metrics=off')).toBe(true)
    const prompt = reviewPrompt(changed, steps)
    expect(flat(prompt).includes('What they report is a finding like any other')).toBe(true)
    // The commands come before the step that says to act on what they find.
    expect(prompt.indexOf("'C:/Tools/bandit.exe'") < prompt.indexOf('3. Act on every finding')).toBe(true)
    expect(reviewPrompt(changed).includes('Scanners for these files')).toBe(false)
    // With none installed, the prompt still names them as skipped and does not claim any are installed.
    const none = reviewPrompt(changed, scannerSteps(changed, new Map()))
    expect(none.includes('Not installed here')).toBe(true)
    expect(none.includes('installed on this machine')).toBe(false)
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

