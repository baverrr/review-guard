// Tests for the MCP server (mcp/server.mjs, mcp/host.mjs) and its build (scripts/build-mcp.mjs), run with
// Node's own runner on Node 22 or newer:
//   node --test tests/mcp-server.node.mjs
// (Named .node.mjs so `claude plugin test`, which runs the engine tests, leaves it alone.)
// Each test starts the real server with a made-up home folder, so the user's own config and status
// files are never read, and with gitleaks taken off PATH unless a test puts a fake one in place. Every
// value here is made up; values the check must catch are built from pieces, so this file never holds one
// whole (the mod checks its own pushes). The personal term is made up too.
import assert from 'node:assert/strict'
import { execFileSync, spawn, spawnSync } from 'node:child_process'
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { delimiter, dirname, join } from 'node:path'
import { after, test } from 'node:test'
import { fileURLToPath } from 'node:url'
import { MAX_BYTES, run } from '../mcp/host.mjs'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')
const WINDOWS = process.platform === 'win32'
const FAKE_GH = 'ghp_' + 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8'
const FAKE_IP = ['10', '20', '30', '44'].join('.')
const PERSONAL = 'pat example'
const STRIPS = Number(process.versions.node.split('.')[0]) > 22 || (process.versions.node.startsWith('22.') && Number(process.versions.node.split('.')[1]) >= 13)

const made = []
after(() => made.forEach(d => rmSync(d, { recursive: true, force: true })))
const tempDir = (name = 'rg-mcp-') => {
  const d = mkdtempSync(join(tmpdir(), name))
  made.push(d)
  return d
}

// PATH without any folder holding gitleaks, so a test decides whether the server finds one.
const PATH = (process.env.PATH ?? process.env.Path ?? '').split(delimiter)
  .filter(d => d && !existsSync(join(d, WINDOWS ? 'gitleaks.exe' : 'gitleaks'))).join(delimiter)

/** A made-up home folder with `config` as its review-guard.json (null: none), and status files. */
function fakeHome({ config = { personal: [PERSONAL] }, status = {}, raw } = {}) {
  const home = tempDir()
  mkdirSync(join(home, '.claude', 'review-guard', 'status'), { recursive: true })
  if (raw !== undefined) writeFileSync(join(home, '.claude', 'review-guard.json'), raw)
  else if (config !== null) writeFileSync(join(home, '.claude', 'review-guard.json'), JSON.stringify(config))
  for (const [name, value] of Object.entries(status)) {
    writeFileSync(join(home, '.claude', 'review-guard', 'status', `${name}.json`), typeof value === 'string' ? value : JSON.stringify(value))
  }
  return home
}

/** A fake gitleaks in the home folder's scanner folder: a file that won't run, or a script. */
function fakeGitleaks(home, kind) {
  const dir = join(home, 'Tools', 'scanners', 'bin')
  mkdirSync(dir, { recursive: true })
  const path = join(dir, WINDOWS ? 'gitleaks.exe' : 'gitleaks')
  writeFileSync(path, 'not a program\n', { mode: kind === 'broken' ? 0o644 : 0o755 })
  return path
}

/**
 * Starts the server in `root` with `home` as the home folder. `call` sends one request and waits for its
 * answer (rejecting if the server exits first), `raw` sends a line as it is, and `exit` resolves with the
 * exit code.
 */
function server(home, root = ROOT, env = {}) {
  const child = spawn(process.execPath, [join(root, 'mcp', 'server.mjs')], {
    env: { ...process.env, HOME: home, USERPROFILE: WINDOWS ? home : '', PATH, Path: PATH, ...env },
    stdio: ['pipe', 'pipe', 'pipe'],
  })
  const lines = []
  let buffer = ''
  const waiting = new Map()
  let exited
  const exit = new Promise(done => child.on('exit', code => {
    exited = code
    for (const fail of [...waiting.values()].map(w => w.fail)) fail(new Error(`server exited (${code}) before answering`))
    done(code)
  }))
  child.stdout.on('data', chunk => {
    buffer += chunk
    let at
    while ((at = buffer.indexOf('\n')) >= 0) {
      const line = buffer.slice(0, at)
      buffer = buffer.slice(at + 1)
      let msg
      try {
        msg = JSON.parse(line)
      } catch {
        lines.push({ notJson: line })
        continue
      }
      lines.push(msg)
      waiting.get(msg.id)?.done(msg)
      waiting.delete(msg.id)
    }
  })
  let next = 1
  const call = (method, params) => new Promise((done, fail) => {
    if (exited !== undefined) return fail(new Error('server has exited'))
    const id = next++
    waiting.set(id, { done, fail })
    child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, params })}\n`)
  })
  const tool = async (name, args) => (await call('tools/call', { name, arguments: args })).result
  return { call, tool, raw: line => child.stdin.write(`${line}\n`), lines, exit, end: () => child.stdin.end(), stop: () => child.kill() }
}

const git = (dir, ...args) => execFileSync('git', ['-C', dir, ...args], { encoding: 'utf8' })
function fakeRepo(name = 'repo') {
  const dir = join(tempDir(), name)
  mkdirSync(dir)
  git(dir, 'init', '-q')
  git(dir, 'config', 'user.name', 'Test')
  git(dir, 'config', 'user.email', 'test@example.invalid')
  git(dir, 'config', 'core.autocrlf', 'false')
  return dir
}
const text = r => r.content[0].text

// --- protocol -------------------------------------------------------------------------------------

test('starts as an MCP server and lists its three read-only tools', async () => {
  const s = server(fakeHome())
  try {
    const init = await s.call('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 't', version: '1' } })
    assert.equal(init.result.serverInfo.name, 'review-guard')
    assert.equal(init.result.protocolVersion, '2025-06-18')
    // A version it doesn't know gets its newest one, not an echo.
    assert.equal((await s.call('initialize', { protocolVersion: '2099-01-01' })).result.protocolVersion, '2025-06-18')
    assert.equal((await s.call('initialize')).result.protocolVersion, '2025-06-18')
    const { tools } = (await s.call('tools/list')).result
    assert.deepEqual(tools.map(t => t.name).sort(), ['check_outgoing', 'check_text', 'review_status'])
    assert.ok(tools.every(t => t.annotations.readOnlyHint === true))
    assert.equal((await s.call('no/such/method')).error.code, -32601)
    assert.equal((await s.call('tools/call', { name: 'no_such_tool' })).error.code, -32602)
    assert.equal((await s.call('ping')).error, undefined)
    for (const args of [null, 'x', { text: 'a', extra: 1 }]) {
      const r = await s.tool('check_text', args)
      assert.equal(r.isError, true, `arguments ${JSON.stringify(args)} must be a tool error`)
    }
  } finally {
    s.stop()
  }
})

test('bad input never ends the server, and messages that need no answer get none', async () => {
  const s = server(fakeHome())
  try {
    for (const line of ['null', '5', '"x"', 'not json', '[{"jsonrpc":"2.0","id":9,"method":"ping"}]']) s.raw(line)
    s.raw('{"jsonrpc":"2.0","id":77,"result":{}}') // a response, not a request: no answer
    s.raw('{"jsonrpc":"2.0","method":"notifications/initialized"}') // a notification: no answer
    assert.equal((await s.call('ping')).error, undefined) // still running
    const errors = s.lines.filter(l => l.error).map(l => l.error.code)
    assert.deepEqual(errors, [-32600, -32600, -32600, -32700, -32600])
    assert.ok(!s.lines.some(l => l.id === 77 || l.id === 9))
  } finally {
    s.stop()
  }
})

test('a call still running when the input closes is answered before the server exits', async () => {
  const repo = fakeRepo()
  const s = server(fakeHome())
  const answer = s.call('tools/call', { name: 'check_outgoing', arguments: { repo } })
  s.end()
  assert.ok((await answer).result.content[0].text.length > 0)
  assert.equal(await s.exit, 0)
})

// --- check_text -----------------------------------------------------------------------------------

test('check_text names what it finds and where, never the value, and says what was not checked', async () => {
  const s = server(fakeHome())
  try {
    const found = await s.tool('check_text', { text: `token ${FAKE_GH}\nhost ${FAKE_IP}\nby Pat Example`, label: 'the PR\ndescription' })
    const t = text(found)
    assert.equal(found.isError, undefined)
    assert.match(t, /GitHub token/)
    assert.match(t, /IP address/)
    assert.match(t, /personal info/)
    assert.match(t, /the PR description/) // the label on one line
    assert.ok(!t.includes(FAKE_GH) && !t.includes(FAKE_IP) && !/pat example/i.test(t), 'a value was shown')
    // Without gitleaks the answer is PARTIAL and says why, never a plain "nothing found".
    const clean = text(await s.tool('check_text', { text: 'Nothing to see here.' }))
    assert.match(clean, /^PARTIAL check/)
    assert.match(clean, /Not checked: gitleaks is not installed/)
    for (const args of [{}, { text: 5 }, { text: 'x', label: {} }, { text: 'x', toString: 'y' }]) {
      assert.equal((await s.tool('check_text', args)).isError, true, JSON.stringify(args))
    }
  } finally {
    s.stop()
  }
})

test('the config decides like the guard: allowValues, no addresses in free text, and a bad config is an error', async () => {
  const allowed = server(fakeHome({ config: { personal: [PERSONAL], allowValues: [FAKE_GH.toUpperCase()], allowNetworkInfo: ['o/r'] } }))
  try {
    const t = text(await allowed.tool('check_text', { text: `token ${FAKE_GH}\nhost ${FAKE_IP}` }))
    assert.ok(!/GitHub token/.test(t), 'an allowed value was reported') // allowValues, any case
    assert.match(t, /IP address/) // allowNetworkInfo never covers free text
  } finally {
    allowed.stop()
  }
  const none = server(fakeHome({ config: null }))
  try {
    assert.match(text(await none.tool('check_text', { text: 'hello' })), /Not checked: personal details were NOT checked/)
  } finally {
    none.stop()
  }
  const bom = server(fakeHome({ raw: `﻿${JSON.stringify({ personal: [PERSONAL] })}` }))
  try {
    assert.match(text(await bom.tool('check_text', { text: 'by Pat Example' })), /personal info/) // a byte-order mark is fine
  } finally {
    bom.stop()
  }
  for (const raw of [`{"personal": ["${PERSONAL}", }`, '{"personal": "x"}', '{"persnal": []}', '{"allowNetworkInfo": ["not a repo"]}']) {
    const s = server(fakeHome({ raw }))
    try {
      const r = await s.tool('check_text', { text: 'hello' })
      assert.equal(r.isError, true, `config ${raw} must be an error`)
      assert.ok(!/pat example/i.test(text(r)), 'the error showed a personal term')
    } finally {
      s.stop()
    }
  }
})

test('a gitleaks that is there but would not run is an error, never "not installed"', async () => {
  const home = fakeHome()
  fakeGitleaks(home, 'broken')
  const s = server(home)
  try {
    const r = await s.tool('check_text', { text: 'hello' })
    assert.equal(r.isError, true)
    assert.match(text(r), /gitleaks is installed but would not run/)
  } finally {
    s.stop()
  }
})

// --- check_outgoing -------------------------------------------------------------------------------

test('check_outgoing checks staged changes and unpushed commits like the guard', async () => {
  const repo = fakeRepo()
  const s = server(fakeHome())
  try {
    // Nothing staged leaves nothing unchecked: a note, not a reason for PARTIAL.
    assert.match(text(await s.tool('check_outgoing', { repo, what: 'commit' })), /\n- Note: nothing is staged/)
    writeFileSync(join(repo, 'ok.txt'), 'hello\n')
    git(repo, 'add', 'ok.txt')
    assert.match(text(await s.tool('check_outgoing', { repo })), /^PARTIAL check: nothing found/) // gitleaks is off PATH
    git(repo, 'commit', '-q', '-m', 'first')
    writeFileSync(join(repo, 'conf.py'), `HOST = "${FAKE_IP}"\n`)
    git(repo, 'add', 'conf.py')
    writeFileSync(join(repo, 'later.py'), `KEY = "${FAKE_GH}"\n`) // not staged
    const staged = text(await s.tool('check_outgoing', { repo, what: 'commit', message: 'thanks Pat Example' }))
    assert.match(staged, /IP address at conf\.py:1/)
    assert.match(staged, /personal info .* at the commit message/)
    assert.match(staged, /1 changed or new file\(s\) are not staged/)
    assert.ok(!/GitHub token/.test(staged))
    assert.match(staged, /no GitHub remote/)
    assert.ok(!staged.includes(FAKE_IP))
    assert.match(text(await s.tool('check_outgoing', { repo, what: 'commit', includeUnstaged: true })), /GitHub token at later\.py:1/)
    git(repo, 'commit', '-q', '-m', 'second')
    assert.match(text(await s.tool('check_outgoing', { repo, what: 'push' })), /IP address at conf\.py:1/) // the commit no remote has yet
    for (const args of [{}, { repo: 'relative/path' }, { repo, what: 'merge' }, { repo, includeUnstaged: 'yes' }, { repo, message: 5 }, { repo, extra: 1 }, { repo, constructor: 1 }]) {
      assert.equal((await s.tool('check_outgoing', args)).isError, true)
    }
    assert.equal((await s.tool('check_outgoing', { repo: tempDir() })).isError, true) // not a repository
  } finally {
    s.stop()
  }
})

test('addresses pass only into a repo the config lists, as in the guard', async () => {
  const repo = fakeRepo()
  git(repo, 'remote', 'add', 'origin', 'https://github.com/o/r.git') // only read, never contacted
  writeFileSync(join(repo, 'hosts.txt'), `${FAKE_IP}\n`)
  git(repo, 'add', 'hosts.txt')
  for (const [allow, reported] of [[['o/r'], false], [['o/other'], true]]) {
    const s = server(fakeHome({ config: { personal: [PERSONAL], allowNetworkInfo: allow } }))
    try {
      const t = text(await s.tool('check_outgoing', { repo, what: 'commit' }))
      assert.equal(/IP address/.test(t), reported, `allowNetworkInfo ${allow}`)
      assert.match(t, /has a GitHub remote/)
    } finally {
      s.stop()
    }
  }
})

test("the repo's own git config can't hide a change or run a command", async () => {
  const repo = fakeRepo()
  const marks = tempDir()
  const marker = join(marks, 'fsmonitor-ran')
  const touch = name => `touch '${join(marks, name).replace(/\\/g, '/')}'`
  // Filter drivers: git diff and git status run a file's clean (or process) command to compare it.
  writeFileSync(join(repo, 'a.txt'), 'one\n')
  writeFileSync(join(repo, 'b.dat'), 'one\n')
  git(repo, 'add', 'a.txt', 'b.dat')
  git(repo, 'commit', '-q', '-m', 'first')
  writeFileSync(join(repo, 'a.txt'), 'two\n')
  writeFileSync(join(repo, 'b.dat'), 'two\n')
  // A textconv driver that turns every change into nothing, and a file system monitor that leaves a mark.
  writeFileSync(join(repo, '.gitattributes'), '*.py diff=hide\n*.txt filter=evilc\n*.dat filter=evilp\n')
  git(repo, 'config', 'diff.hide.textconv', "sh -c 'true'")
  writeFileSync(join(repo, 'fsmon.sh'), `#!/bin/sh\ntouch '${marker.replace(/\\/g, '/')}'\n`, { mode: 0o755 })
  git(repo, 'config', 'core.fsmonitor', join(repo, 'fsmon.sh').replace(/\\/g, '/'))
  writeFileSync(join(repo, 'conf.py'), `HOST = "${FAKE_IP}"\n`)
  git(repo, '-c', 'core.fsmonitor=false', 'add', 'conf.py', '.gitattributes')
  // Set only now, so nothing but the server can have run them (git add may compare a.txt too).
  git(repo, 'config', 'filter.evilc.clean', touch('clean-ran'))
  git(repo, 'config', 'filter.evilp.process', touch('process-ran'))
  const s = server(fakeHome())
  try {
    assert.match(text(await s.tool('check_outgoing', { repo, what: 'commit' })), /IP address at conf\.py:1/)
    const all = text(await s.tool('check_outgoing', { repo, what: 'commit', includeUnstaged: true }))
    assert.match(all, /IP address at conf\.py:1/, all)
    for (const m of ['fsmonitor-ran', 'clean-ran', 'process-ran']) assert.equal(existsSync(join(marks, m)), false, `the repo's ${m} command ran`)
    assert.equal(existsSync(join(repo, '.git', 'index.lock')), false)
  } finally {
    s.stop()
  }
  // The filter is real: a plain git diff runs it.
  spawnSync('git', ['-C', repo, '-c', 'core.fsmonitor=false', 'diff', '--', 'a.txt'])
  assert.equal(existsSync(join(marks, 'clean-ran')), true, 'the test filter never runs, so it shows nothing')
})

test('paths and file names never show the home folder or a personal term', async () => {
  const home = fakeHome()
  const repo = join(home, 'pat example notes')
  mkdirSync(repo)
  git(repo, 'init', '-q')
  git(repo, 'config', 'user.name', 'Test')
  git(repo, 'config', 'user.email', 'test@example.invalid')
  writeFileSync(join(repo, 'a.txt'), `${FAKE_IP}\n`)
  git(repo, 'add', 'a.txt')
  const s = server(home)
  try {
    const t = text(await s.tool('check_outgoing', { repo, what: 'commit' }))
    assert.match(t, /IP address at a\.txt:1/)
    assert.ok(!t.includes(home) && !t.includes(home.replace(/\\/g, '/')), 'the home folder was shown')
    assert.ok(!/pat example/i.test(t), 'a personal term was shown')
    assert.match(t, /~[\\/]\[a personal term\] notes/)
    // The home folder in each way it is written, and only whole: a longer name is another folder.
    const fwd = home.replace(/\\/g, '/')
    const label = async l => text(await s.tool('check_text', { text: 'hello', label: l }))
    for (const spelling of [fwd, fwd.replace(/\//g, '\\'), JSON.stringify(fwd.replace(/\//g, '\\')).slice(1, -1), ...(WINDOWS ? [fwd.replace(/^([A-Za-z]):/, (_, d) => `/${d.toLowerCase()}`)] : [])]) {
      const t2 = await label(`${spelling}/x.md`)
      assert.ok(t2.includes('~/x.md'), t2)
    }
    assert.ok(!(await label(`${fwd}y/x.md`)).includes('~y'), 'a longer folder name was masked as the home folder')
  } finally {
    s.stop()
  }
})

test('personal terms are masked whole, even short ones and ones that overlap', async () => {
  const s = server(fakeHome({ config: { personal: ['term', 'pat', 'atkins'] } }))
  try {
    const label = async l => text(await s.tool('check_text', { text: 'hello', label: l }))
    const short = await label('my term paper')
    assert.ok(short.includes('my [a personal term] paper'), short)
    assert.ok(!short.includes('[a personal [a'), short)
    const overlap = await label('by patkins')
    assert.ok(overlap.includes('by [a personal term]') && !overlap.includes('kins'), overlap)
    assert.ok((await label('İpat')).includes('İ[a personal term]')) // a letter whose lower case is longer
  } finally {
    s.stop()
  }
})

test('a Git Bash path works on Windows', { skip: !WINDOWS }, async () => {
  const repo = fakeRepo()
  writeFileSync(join(repo, 'a.txt'), 'hello\n')
  git(repo, 'add', 'a.txt')
  const bash = repo.replace(/\\/g, '/').replace(/^([A-Za-z]):/, (_, d) => `/${d.toLowerCase()}`)
  const s = server(fakeHome())
  try {
    const r = await s.tool('check_outgoing', { repo: bash, what: 'commit' })
    assert.equal(r.isError, undefined, text(r))
  } finally {
    s.stop()
  }
})

// --- review_status --------------------------------------------------------------------------------

const status = (session, over = {}) => ({
  v: 1, session, folder: '/proj', updated: new Date().toISOString(), phase: 'idle', queued: [], underReview: [], leftOut: [],
  leftOutSince: new Date().toISOString(), ...over,
})

test('review_status lists recent sessions, newest first, and says which files it could not read', async () => {
  const old = new Date(Date.now() - 48 * 3600_000).toISOString()
  const home = fakeHome({
    status: {
      a: status('a', { phase: 'held', queued: ['src/app.py'], leftOut: [{ path: '.scripts/map.py', why: 'only run', at: old }, { path: 'src/db.py', why: 'scratch script', at: old }], updated: new Date(Date.now() - 60_000).toISOString() }),
      b: status('b', { phase: 'reviewing', underReview: ['b.py'], writeFailed: 'disk full' }),
      c: '{not json',
      d: status('d', { queued: 'a.py' }), // a field of the wrong type
      e: status('e', { updated: old, queued: ['old.py'] }),
    },
  })
  const s = server(home)
  try {
    const t = text(await s.tool('review_status', {}))
    assert.ok(t.indexOf('Session b') < t.indexOf('Session a'), 'not newest first')
    assert.match(t, /Session a in \/proj, updated 1 min ago: reviews are held after an interrupt/)
    assert.match(t, /src\/app\.py/)
    assert.match(t, /\.scripts\/map\.py \(only run\)/)
    assert.match(t, /src\/db\.py \(scratch script\)/)
    assert.match(t, /Session b .*a review is running/)
    assert.match(t, /under review now:\n {4}- b\.py/)
    assert.match(t, /last update before this one failed/)
    assert.match(t, /can't be read: (c, d|d, c)/)
    assert.ok(!t.includes('old.py'))
    assert.match(t, /1 session\(s\) older than 24 h still had files waiting/)
  } finally {
    s.stop()
  }
  const empty = server(tempDir())
  try {
    assert.match(text(await empty.tool('review_status', {})), /^No review status yet/)
  } finally {
    empty.stop()
  }
  // A config that can't be used: the list still shows, and says personal terms are not masked.
  const bad = server(fakeHome({ raw: '{bad', status: { a: status('a', { queued: ['a.py'] }) } }))
  try {
    const t = text(await bad.tool('review_status', {}))
    assert.match(t, /^Personal terms are NOT masked below/)
    assert.match(t, /Session a/)
  } finally {
    bad.stop()
  }
})

// --- the built copy -------------------------------------------------------------------------------

/** A copy of the mod's server parts to change. */
function modCopy() {
  const root = tempDir()
  for (const part of ['mcp', 'hooks', 'scripts', '.claude-plugin']) cpSync(join(ROOT, part), join(root, part), { recursive: true })
  return root
}

test('the home folder is USERPROFILE on Windows and HOME elsewhere, and both are masked', async () => {
  const fromHome = fakeHome({ status: { h: status('h') } })
  const fromProfile = fakeHome({ status: { u: status('u') } })
  for (const [h, u] of [[fromHome, 'h'], [fromProfile, 'u']]) {
    writeFileSync(join(h, '.claude', 'review-guard', 'status', `${u}.json`), JSON.stringify(status(u, { folder: `${fromHome}/a and ${fromProfile}/b` })))
  }
  const s = server(fromHome, ROOT, { HOME: fromHome, USERPROFILE: fromProfile })
  try {
    const t = text(await s.tool('review_status', {}))
    assert.match(t, WINDOWS ? /Session u / : /Session h /) // the status folder under the home in use
    assert.ok(!t.includes(WINDOWS ? 'Session h ' : 'Session u '))
    for (const h of [fromHome, fromProfile]) assert.ok(!t.includes(h) && !t.includes(h.replace(/\\/g, '/')), 'a home folder showed')
  } finally {
    s.stop()
  }
})

test('a home folder that is a bare root or drive masks nothing', async () => {
  const home = fakeHome({ status: { r: status('r', { folder: 'C:/proj/x and /c/proj/z and /proj/y' }) } })
  // The home in use is a real folder; the other one is a bare drive, which names nobody.
  for (const bare of ['C:/', '/c/']) {
    const s = server(home, ROOT, WINDOWS ? { USERPROFILE: home, HOME: bare } : { HOME: home, USERPROFILE: bare })
    try {
      assert.match(text(await s.tool('review_status', {})), /in C:\/proj\/x and \/c\/proj\/z and \/proj\/y,/, bare) // nothing masked
    } finally {
      s.stop()
    }
  }
})

test('a built copy that does not match hooks/*.ts is refused, not run', async () => {
  for (const [file, change, why] of [
    ['hooks/scan.ts', t => `${t}\n// changed after the build\n`, /mcp\/lib\/scan\.mjs does not match hooks\/scan\.ts/],
    ['hooks/status.ts', t => `${t}\n// changed\n`, /mcp\/lib\/status\.mjs does not match/],
    ['mcp/lib/outgoing.mjs', t => t.replace('const MAX_NEW_FILES = 300', 'const MAX_NEW_FILES = 3'), /outgoing\.mjs was changed after it was built/],
  ]) {
    const root = modCopy()
    writeFileSync(join(root, file), change(readFileSync(join(root, file), 'utf8')))
    const s = server(fakeHome(), root)
    try {
      const r = await s.tool('check_text', { text: 'hello' })
      assert.equal(r.isError, true, file)
      assert.match(text(r), why)
    } finally {
      s.stop()
    }
  }
  // Windows line endings in hooks/*.ts are the same source.
  const crlf = modCopy()
  for (const n of ['scan', 'scanners', 'outgoing', 'status']) {
    const p = join(crlf, 'hooks', `${n}.ts`)
    writeFileSync(p, readFileSync(p, 'utf8').replace(/\r?\n/g, '\r\n'))
  }
  const s = server(fakeHome(), crlf)
  try {
    assert.equal((await s.tool('check_text', { text: 'hello' })).isError, undefined)
  } finally {
    s.stop()
  }
})

test('the build check passes on the mod and fails on a changed copy', { skip: !STRIPS && 'needs Node 22.13 or newer' }, () => {
  const check = root => spawnSync(process.execPath, [join(root, 'scripts', 'build-mcp.mjs'), '--check'], { encoding: 'utf8' })
  assert.equal(check(ROOT).status, 0, check(ROOT).stderr)
  const root = modCopy()
  const lib = join(root, 'mcp', 'lib', 'scan.mjs')
  writeFileSync(lib, `${readFileSync(lib, 'utf8')}\n// edited\n`)
  const r = check(root)
  assert.equal(r.status, 1)
  assert.match(r.stderr, /mcp\/lib\/scan\.mjs was changed after it was built/)
  rmSync(join(root, 'mcp', 'lib', 'outgoing.mjs'))
  assert.match(check(root).stderr, /outgoing\.mjs can't be read/)
})

// --- the Node host --------------------------------------------------------------------------------

test('the host runs like the engine: a timeout rejects, output is cut cleanly per stream', async () => {
  const node = process.execPath
  await assert.rejects(run([node, '-e', 'setTimeout(() => {}, 100000)'], { timeoutMs: 300 }), /timed out after 300 ms/)
  const big = await run([node, '-e', `process.stdout.write('a'.repeat(${MAX_BYTES + 1000})); process.stderr.write('e')`], { timeoutMs: 30_000 })
  assert.equal(big.stdout.length, MAX_BYTES)
  assert.equal(big.isStdoutTruncated, true)
  assert.equal(big.stderr, 'e')
  assert.equal(big.isStderrTruncated, false)
  const errs = await run([node, '-e', `process.stderr.write('e'.repeat(${MAX_BYTES + 1000})); process.stdout.write('ok')`], { timeoutMs: 30_000 })
  assert.equal(errs.stdout, 'ok')
  assert.equal(errs.isStdoutTruncated, false) // a flood on stderr doesn't cut stdout
  assert.equal(errs.isStderrTruncated, true)
  const echo = await run([node, '-e', 'process.stdin.pipe(process.stdout); process.stdout.write(process.env.RG_T)'], { stdin: 'in', env: { RG_T: 'env' } })
  assert.equal(echo.stdout, 'envin')
  await assert.rejects(run(['rg-no-such-program-here'], {}))
})

// hooks/agents.ts is edited by hand alongside agents/*.md, so check the two still say the same thing.
test('each agent prompt in hooks/agents.ts matches its agents/*.md file', () => {
  const ts = readFileSync(join(ROOT, 'hooks', 'agents.ts'), 'utf8')
  const entries = [...ts.matchAll(/name: ("[^"]+"),\s*description: ("(?:[^"\\]|\\.)*"),\s*model: ("[^"]+"),\s*prompt: ("(?:[^"\\]|\\.)*")/g)]
  assert.equal(entries.length, 5)
  for (const [, name, description, model, prompt] of entries) {
    const md = readFileSync(join(ROOT, 'agents', `${JSON.parse(name)}.md`), 'utf8').replace(/\r\n/g, '\n')
    const [, front, body] = md.match(/^---\n([\s\S]*?)\n---\n([\s\S]*)$/) ?? []
    assert.ok(body !== undefined, `${JSON.parse(name)}.md has no frontmatter`)
    assert.equal(JSON.parse(prompt).trim(), body.trim(), `${JSON.parse(name)}: prompt differs from the .md body`)
    assert.ok(front.includes(`description: ${JSON.parse(description)}`), `${JSON.parse(name)}: description differs`)
    assert.ok(front.includes(`model: ${JSON.parse(model)}`), `${JSON.parse(name)}: model differs`)
  }
})
