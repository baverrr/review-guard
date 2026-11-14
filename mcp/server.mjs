// review-guard's MCP server: the guard's check on demand, and what the review queue holds.
// Plain Node, no packages: MCP over stdio is one JSON-RPC message per line.
//
// Tools:
//   check_outgoing  what is staged for a commit, and the current branch's unpushed commits, checked the
//                   way the guard checks a real commit or push
//   check_text      any text (a PR description, an issue comment), checked the same way
//   review_status   the files waiting for review in recent sessions, and the ones left out and why
//
// Results name the kind and place of each finding, never the matched text, and everything it prints has
// the user's personal terms and home folder masked. It writes nothing and changes nothing, and it has no
// way to pause the reviews, which stay the user's to turn off (in settings.json).
import { createHash } from 'node:crypto'
import { readdir, readFile, stat } from 'node:fs/promises'
import { dirname, join, resolve } from 'node:path'
import { createInterface } from 'node:readline'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { exists, read, run } from './host.mjs'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
// Same list as scripts/build-mcp.mjs: the hooks/*.ts files the server uses a built copy of.
const SOURCES = ['scan', 'scanners', 'outgoing', 'status']
const STATUS_HOURS = 24
const PROTOCOLS = ['2025-06-18', '2025-03-26', '2024-11-05'] // newest first

// Only shown, so a missing or bad file must not stop the server.
const version = await readFile(join(ROOT, '.claude-plugin', 'plugin.json'), 'utf8')
  .then(t => {
    const v = JSON.parse(t)?.version
    return typeof v === 'string' ? v : 'unknown'
  })
  .catch(() => 'unknown')

// --- the guard's own check, from mcp/lib (built from hooks/*.ts) ----------------------------------

const sha256 = text => createHash('sha256').update(text).digest('hex')

/**
 * Each built file's source fingerprint, or why the built copy can't be used: a file missing, built from
 * another version of its hooks/*.ts, or edited by hand since it was built. A copy that doesn't match
 * would run another check than the guard, so the tools refuse rather than answer.
 */
async function builtState() {
  const sources = {}
  for (const name of SOURCES) {
    let source, built
    try {
      source = await readFile(join(ROOT, 'hooks', `${name}.ts`), 'utf8')
      built = await readFile(join(ROOT, 'mcp', 'lib', `${name}.mjs`), 'utf8')
    } catch (err) {
      return { problem: `can't read hooks/${name}.ts or mcp/lib/${name}.mjs (${err.code ?? err.message})` }
    }
    // As scripts/build-mcp.mjs: line endings made LF first, so either kind of checkout matches.
    const header = /^\/\/ Generated .* source-sha256: (\w+) built-sha256: (\w+)\r?\n/.exec(built)
    const want = sha256(source.replace(/\r\n/g, '\n'))
    if (!header || header[1] !== want) {
      return { problem: `mcp/lib/${name}.mjs does not match hooks/${name}.ts: run \`node scripts/build-mcp.mjs\` in the mod's folder (Node 22.13 or newer), then start a new session` }
    }
    if (header[2] !== sha256(built.slice(header[0].length).replace(/\r\n/g, '\n'))) {
      return { problem: `mcp/lib/${name}.mjs was changed after it was built: run \`node scripts/build-mcp.mjs\` in the mod's folder, then start a new session` }
    }
    sources[name] = want
  }
  return { sources }
}

let check // the modules this process imported, and the fingerprints they were built from
async function loadCheck() {
  const state = await builtState()
  if (state.problem) throw new Error(`review-guard's MCP server is out of date: ${state.problem}`)
  if (!check) {
    const load = name => import(pathToFileURL(join(ROOT, 'mcp', 'lib', `${name}.mjs`)).href)
    const [scan, outgoing, status] = await Promise.all([load('scan'), load('outgoing'), load('status')])
    check = { scan, outgoing, status, sources: state.sources }
  } else if (SOURCES.some(n => check.sources[n] !== state.sources[n])) {
    // Node keeps the modules it imported, so a rebuild can't take effect in this process.
    throw new Error("review-guard's tools were rebuilt after this session started: start a new session to use them")
  }
  return check
}

// --- the check's host: Node's own ways to run a program and read a file ---------------------------

/**
 * The home folder, as the check's `homeFrom` gives it. Before the check has loaded (or when it can't
 * load), the same rules written out here, so even that error is masked.
 */
function homeHere() {
  // Node knows; the hooks tell it from the environment (`isWindows`), which gives the same answer on a
  // normal Windows, Linux or WSL setup.
  const windows = process.platform === 'win32'
  if (check) return check.outgoing.homeFrom({ windows, home: process.env.HOME, userProfile: process.env.USERPROFILE })
  const order = windows ? [process.env.USERPROFILE, process.env.HOME] : [process.env.HOME, process.env.USERPROFILE]
  const value = order.find(v => v !== undefined && v.trim() !== '')
  return value?.trim().replace(/\\/g, '/').replace(/(?<=.)\/+$/, '')
}

const host = { run, read, exists, home: async () => homeHere(), pluginRoot: ROOT }

/**
 * Every home folder spelling there is (the one in use, USERPROFILE and HOME), so a mask hides each: on
 * WSL the home is HOME, and a USERPROFILE passed in from Windows names the user too.
 */
function homesHere() {
  const plain = v => (v === undefined || v.trim() === '' ? undefined : v.trim().replace(/\\/g, '/').replace(/(?<=.)\/+$/, ''))
  return [...new Set([homeHere(), plain(process.env.USERPROFILE), plain(process.env.HOME)].filter(Boolean))]
}

// --- what the tools print -------------------------------------------------------------------------

/**
 * Lower case, one UTF-16 unit at a time, keeping any unit whose lower case is longer (such as İ): the
 * result is as long as the text, so a place found in it is the same place in the text.
 */
const fold = text => text.split('').map(c => {
  const lower = c.toLowerCase()
  return lower.length === 1 ? lower : c
}).join('')

/**
 * The text with the home folder shown as ~ and each personal term from the config as [a personal term]:
 * a file name, a repo path or an error message must not show what the check exists to keep private.
 * Matches are found in the original text in one pass, in any case, and overlapping ones are masked as
 * one piece, so no part of a term is left showing and a short term can't match inside a mask. The home
 * folder matches in each way it is written (C:/Users/x, C:\Users\x, JSON's C:\\Users\\x, Git Bash's
 * /c/Users/x), and only whole: C:/Users/xy is another folder.
 */
function masker(homes, personal = []) {
  const rules = []
  for (const home of homes) {
    const forward = home.replace(/\\/g, '/')
    if (/^(?:[A-Za-z]:|\/[A-Za-z])?\/?$/.test(forward)) continue // a bare root or drive names nobody, and would mask every path on it
    const spellings = [forward, forward.replace(/\//g, '\\'), forward.replace(/\//g, '\\\\')]
    if (/^[A-Za-z]:\//.test(forward)) spellings.push(`/${forward[0].toLowerCase()}${forward.slice(2)}`)
    for (const s of new Set(spellings)) rules.push({ needle: fold(s), to: '~', whole: true })
  }
  for (const term of personal) if (term) rules.push({ needle: fold(term), to: '[a personal term]', whole: false })
  return text => {
    const folded = fold(text)
    const hits = []
    for (const { needle, to, whole } of rules) {
      for (let at = folded.indexOf(needle); at !== -1; at = folded.indexOf(needle, at + 1)) {
        const end = at + needle.length
        if (whole && /[\w.-]/.test(text[end] ?? '')) continue // a longer name that starts the same way
        hits.push({ at, end, to })
      }
    }
    hits.sort((a, b) => a.at - b.at || b.end - a.end)
    let out = ''
    let from = 0 // where the text not masked yet starts
    let open // the piece being masked: overlapping hits join it
    const close = () => {
      out += text.slice(from, open.at) + open.to
      from = open.end
    }
    for (const h of hits) {
      if (open && h.at < open.end) open.end = Math.max(open.end, h.end)
      else {
        if (open) close()
        open = { ...h }
      }
    }
    if (open) close()
    return out + text.slice(from)
  }
}

/** Findings as text: kinds and places only, never the value found. */
function listFindings(found) {
  const shown = found.slice(0, 50).map(f => `- ${f.kind} at ${f.where}`)
  return [...shown, ...(found.length > 50 ? [`- and ${found.length - 50} more`] : [])].join('\n')
}

/**
 * The verdict: what was found, or nothing, and whether every part of the check ran. `notes` are parts
 * that did not run (the result is PARTIAL); `info` is worth knowing but left nothing unchecked.
 */
function verdict(left, notes, whatWasChecked, info = []) {
  const lines = left.length > 0
    ? [`Found ${left.length} thing(s) that must not be shared in ${whatWasChecked}:`, listFindings(left)]
    : notes.length > 0
      ? [`PARTIAL check: nothing found in ${whatWasChecked} by the parts that ran, but not everything was checked:`]
      : [`Nothing personal or secret found in ${whatWasChecked}.`]
  return [...lines, ...notes.map(n => `- Not checked: ${n}.`), ...info.map(n => `- Note: ${n}.`)]
}

/** An optional text argument: its value, or `fallback` when not given. */
function textArg(value, name, fallback) {
  if (value === undefined) return fallback
  if (typeof value !== 'string') throw new Error(`${name}: text is needed`)
  return value
}

// --- the tools ------------------------------------------------------------------------------------

/**
 * Counts in `git status`: files staged, and files changed or new but not staged. Run as the check runs
 * git, so the repository's config can't run a command and the index is not locked.
 */
async function stagedAndNot(outgoing, repo) {
  const r = await outgoing.git(host, repo, ['status', '--porcelain=v1', '--untracked-files=normal']).catch(() => undefined)
  if (!r || r.exitCode !== 0) return undefined
  const lines = r.stdout.split('\n').filter(Boolean)
  return {
    staged: lines.filter(l => l[0] !== ' ' && l[0] !== '?').length,
    notStaged: lines.filter(l => l[1] !== ' ' || l[0] === '?').length,
  }
}

async function checkOutgoing({ repo, what = 'both', message, includeUnstaged = false }) {
  if (typeof repo !== 'string' || !repo.trim()) throw new Error('repo: the absolute path of a git repository is needed')
  const commitMessage = textArg(message, 'message', '')
  const { scan, outgoing } = await loadCheck()
  // Git Bash spells C:\x as /c/x, which git.exe on Windows can't open.
  const dir = process.platform === 'win32' ? scan.nativePath(repo.trim().replace(/\\/g, '/')) : repo.trim()
  if (!/^(?:[A-Za-z]:\/|\/)/.test(dir.replace(/\\/g, '/'))) throw new Error(`repo: give an absolute path (got "${repo.trim()}")`)
  if (!['commit', 'push', 'both'].includes(what)) throw new Error('what: one of "commit", "push" or "both"')
  if (typeof includeUnstaged !== 'boolean') throw new Error('includeUnstaged: true or false')
  const { config, note } = await outgoing.loadConfig(host)
  const mask = masker(homesHere(), config.personal)
  const notes = note ? [note] : []
  const remotes = await outgoing.githubRemotes(host, dir)
  const commits = what !== 'push'
  const action = {
    kind: what === 'commit' ? 'commit' : 'push',
    commits,
    pushes: what !== 'commit',
    dir,
    addsFiles: commits && includeUnstaged,
    message: commitMessage,
    refs: [],
    allBranches: false,
    tags: false,
  }
  const found = await outgoing.findingsFor(host, action, config, notes)
  const left = scan.settle(found, scan.networkAllowed(remotes, config.allowNetworkInfo), config.allowValues)
  const info = []
  if (commits) {
    const counts = await stagedAndNot(outgoing, dir)
    if (!counts) notes.push("which files are staged could not be read (git status failed)")
    else {
      if (counts.staged === 0 && !includeUnstaged) info.push('nothing is staged, so there were no changes to check for a commit')
      if (counts.notStaged > 0 && !includeUnstaged) notes.push(`${counts.notStaged} changed or new file(s) are not staged (pass includeUnstaged to check them too)`)
    }
  }
  const checked = [
    ...(commits ? [includeUnstaged ? 'all changes, staged or not, and new files' : 'the staged changes'] : []),
    ...(action.pushes ? ["the current branch's commits not pushed yet"] : []),
  ].join(' and ')
  return mask([
    ...verdict(left, notes, `${checked} of ${dir}`, info),
    remotes.length > 0
      ? 'It has a GitHub remote, so the guard checks a real commit or push here too.'
      : 'It has no GitHub remote, so the guard does not check a real commit or push here.',
  ].join('\n'))
}

async function checkText({ text, label }) {
  if (typeof text !== 'string') throw new Error('text: the text to check is needed')
  const where = textArg(label, 'label', '').replace(/\s+/g, ' ').trim().slice(0, 100) || 'the text'
  const { scan, outgoing } = await loadCheck()
  const { config, note } = await outgoing.loadConfig(host)
  const mask = masker(homesHere(), config.personal)
  const notes = note ? [note] : []
  const found = [
    ...scan.scanValue(text, where, config.personal),
    ...(await outgoing.gitleaksScan(host, scan.valueLines(text, where), notes)),
  ]
  // Addresses are allowed only into repos the config lists; free text goes nowhere known, so not here.
  const left = scan.settle(found, false, config.allowValues)
  return mask(verdict(left, notes, where).join('\n'))
}

const ago = iso => {
  const minutes = Math.max(0, Math.round((Date.now() - Date.parse(iso)) / 60_000))
  return minutes < 60 ? `${minutes} min ago` : `${Math.round(minutes / 60)} h ago`
}

async function reviewStatus() {
  const { status, outgoing } = await loadCheck()
  const home = await host.home()
  if (!home) throw new Error('the home folder is not known (neither USERPROFILE nor HOME is set)')
  // The list still shows when the config can't be read, but says its personal terms were not masked.
  const { personal, unmasked } = await outgoing.loadConfig(host).then(
    r => ({ personal: r.config.personal }),
    err => ({ personal: [], unmasked: `Personal terms are NOT masked below: ~/.claude/review-guard.json could not be used (${messageOf(err)}).` }),
  )
  const mask = text => masker(homesHere(), personal)(unmasked ? `${unmasked}\n${text}` : text)
  const dir = status.statusDir(home)
  let names
  try {
    names = (await readdir(dir)).filter(n => n.endsWith('.json'))
  } catch (err) {
    if (err.code === 'ENOENT') return mask('No review status yet: a session writes one once it has code waiting for review or leaves a file out.')
    throw new Error(`can't read ${dir}: ${err.code ?? err.message}`)
  }
  const since = Date.now() - STATUS_HOURS * 3600_000
  const recent = []
  const broken = []
  let olderWaiting = 0
  for (const name of names) {
    const path = join(dir, name)
    let parsed
    try {
      parsed = status.statusFrom(JSON.parse(await readFile(path, 'utf8')))
    } catch {
      parsed = undefined
    }
    if (!parsed) {
      // Listed only while recent: an old broken file is noise, not news.
      const modified = await stat(path).then(s => s.mtimeMs, () => 0)
      if (modified >= since) broken.push(name.replace(/\.json$/, ''))
      continue
    }
    if (Date.parse(parsed.updated) >= since) recent.push(parsed)
    else if (parsed.phase !== 'ended' && (parsed.queued.length > 0 || parsed.phase === 'held')) olderWaiting++
  }
  recent.sort((a, b) => b.updated.localeCompare(a.updated))
  const list = (title, items) => (items.length ? [`  ${title}:`, ...items.map(i => `    - ${i}`)] : [])
  const phase = {
    reviewing: 'a review is running',
    held: 'reviews are held after an interrupt',
    idle: 'no review running',
    ended: 'the session has ended',
  }
  const lines = recent.flatMap(s => [
    `Session ${s.session} in ${s.folder ?? 'an unknown folder'}, updated ${ago(s.updated)}: ${phase[s.phase]}`,
    ...(s.writeFailed ? [`  (its last update before this one failed, so this may be behind: ${s.writeFailed})`] : []),
    ...list('waiting for review', s.queued),
    ...list('under review now', s.underReview),
    ...list(`left out since ${s.leftOutSince} (newest last)`, s.leftOut.map(l => `${l.path} (${l.why})`)),
  ])
  if (recent.length === 0) lines.push(`No session has changed code in the last ${STATUS_HOURS} hours.`)
  if (broken.length > 0) lines.push(`Status file(s) that can't be read: ${broken.join(', ')}.`)
  if (olderWaiting > 0) lines.push(`${olderWaiting} session(s) older than ${STATUS_HOURS} h still had files waiting when last updated (may be stale).`)
  return mask(lines.join('\n'))
}

const TOOLS = [
  {
    name: 'check_outgoing',
    description: "Check what is staged for a commit, and the current branch's commits not pushed yet, the way review-guard checks a real commit or push: keys, tokens, private keys, IP and MAC addresses, sensitive file names, and the personal terms in ~/.claude/review-guard.json, in the changes, commit authors and messages, and the git identity a commit would use (plus gitleaks when installed). Unstaged and new files are included only with includeUnstaged. Reports the kind and place of each finding, never the matched text, and says when a part could not be checked. Changes nothing.",
    inputSchema: {
      type: 'object',
      properties: {
        repo: { type: 'string', description: 'Absolute path of the git repository (or a folder in it).' },
        what: { type: 'string', enum: ['commit', 'push', 'both'], description: "commit: the staged changes. push: the current branch's commits not pushed yet. both (default)." },
        message: { type: 'string', description: 'A commit message to check too (optional).' },
        includeUnstaged: { type: 'boolean', description: 'Also check changed and new files not staged yet, as `git add -A && git commit` would send (default false).' },
      },
      required: ['repo'],
      additionalProperties: false,
    },
    annotations: { readOnlyHint: true, openWorldHint: false },
    call: checkOutgoing,
  },
  {
    name: 'check_text',
    description: 'Check any text before it is shared (a PR description, an issue comment, a message) for keys, tokens, private keys, IP and MAC addresses and the personal terms in ~/.claude/review-guard.json (plus gitleaks when installed). Reports the kind and place of each finding, never the matched text, and says when a part could not be checked.',
    inputSchema: {
      type: 'object',
      properties: {
        text: { type: 'string', description: 'The text to check.' },
        label: { type: 'string', description: 'What the text is, used in the report (optional, one short line).' },
      },
      required: ['text'],
      additionalProperties: false,
    },
    annotations: { readOnlyHint: true, openWorldHint: false },
    call: checkText,
  },
  {
    name: 'review_status',
    description: `List, for sessions active in the last ${STATUS_HOURS} hours, the code files waiting for review-guard's review, any review running or held, and the files left out of review and why (Claude's scratch files, scripts a command only ran).`,
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
    annotations: { readOnlyHint: true, openWorldHint: false },
    call: reviewStatus,
  },
]

// --- MCP over stdio -------------------------------------------------------------------------------

const send = message => process.stdout.write(`${JSON.stringify({ jsonrpc: '2.0', ...message })}\n`)
const messageOf = err => (err instanceof Error ? err.message : String(err))

/** Masks an error message as the results are masked, as far as the config can be read. */
async function maskError(text) {
  const personal = check ? await check.outgoing.loadConfig(host).then(r => r.config.personal, () => []) : []
  return masker(homesHere(), personal)(text)
}

async function handle(msg) {
  const { id, method, params } = msg
  if (method === 'initialize') {
    const asked = params?.protocolVersion
    return {
      protocolVersion: PROTOCOLS.includes(asked) ? asked : PROTOCOLS[0],
      capabilities: { tools: {} },
      serverInfo: { name: 'review-guard', version },
      instructions: 'review-guard already checks every git commit and push to GitHub, and every GitHub write, by itself. Use check_outgoing when the user asks what a commit or push would send (or for a repo the guard does not watch), check_text before text goes out some other way (a chat, an email, a web form), and review_status to see what is waiting for review and what was left out. Results name the kind and place of each finding, never the value; a PARTIAL result means part of the check could not run.',
    }
  }
  if (method === 'ping') return {}
  if (method === 'tools/list') return { tools: TOOLS.map(({ call, ...tool }) => tool) }
  if (method === 'tools/call') {
    const tool = TOOLS.find(t => t.name === params?.name)
    if (!tool) throw Object.assign(new Error(`no tool named ${params?.name}`), { code: -32602 })
    const args = params?.arguments ?? {}
    try {
      if (typeof args !== 'object' || Array.isArray(args)) throw new Error('arguments must be an object')
      const extra = Object.keys(args).filter(k => !Object.hasOwn(tool.inputSchema.properties, k))
      if (extra.length > 0) throw new Error(`unknown argument(s): ${extra.join(', ')}`)
      return { content: [{ type: 'text', text: await tool.call(args) }] }
    } catch (err) {
      // A failed check is a tool error the model sees, never an empty "clean" answer.
      return { content: [{ type: 'text', text: await maskError(`review-guard could not run ${tool.name}: ${messageOf(err)}`) }], isError: true }
    }
  }
  if (id === undefined) return undefined // a notification (initialized, cancelled): nothing to answer
  throw Object.assign(new Error(`method not found: ${method}`), { code: -32601 })
}

async function answer(line) {
  let msg
  try {
    msg = JSON.parse(line)
  } catch {
    send({ id: null, error: { code: -32700, message: 'parse error' } })
    return
  }
  if (Array.isArray(msg)) {
    send({ id: null, error: { code: -32600, message: 'batches are not supported: send one message per line' } })
    return
  }
  if (typeof msg !== 'object' || msg === null) {
    send({ id: null, error: { code: -32600, message: 'invalid request: a message is a JSON object' } })
    return
  }
  if (typeof msg.method !== 'string') return // a response to a request of ours (none are sent): nothing to answer
  try {
    const result = await handle(msg)
    if (msg.id !== undefined && result !== undefined) send({ id: msg.id, result })
  } catch (err) {
    if (msg.id !== undefined) send({ id: msg.id, error: { code: Number.isInteger(err?.code) ? err.code : -32603, message: messageOf(err) } })
  }
}

// One bad message must never end the server: its tools would just vanish from the session.
process.on('unhandledRejection', err => process.stderr.write(`review-guard: ${messageOf(err)}\n`))
process.on('uncaughtException', err => process.stderr.write(`review-guard: ${messageOf(err)}\n`))

const inFlight = new Set()
const lines = createInterface({ input: process.stdin })
lines.on('line', line => {
  if (!line.trim()) return
  const work = answer(line).catch(err => process.stderr.write(`review-guard: ${messageOf(err)}\n`))
  inFlight.add(work)
  void work.finally(() => inFlight.delete(work))
})
// Input closed: answer every call still running, then let the process end once its output is written.
lines.on('close', () => {
  void Promise.allSettled([...inFlight]).then(() => process.stdout.end())
})
