import type { EngineInterface, Register } from 'claude-code'
import { REVIEW_AGENTS } from './agents'
import type { Cycle } from '../types'
import {
  isNewRequest,
  type Finding,
  ghWrites,
  gitAction,
  type GitAction,
  inScratch,
  languageOf,
  type Paths,
  runOnlyScripts,
  COPIES,
  localPart,
  networkAllowed,
  report,
  resolveDir,
  addedLines,
  type SentLine,
  valueLines,
  reviewPrompt,
  scanDiff,
  scanFile,
  scanLine,
  scanValue,
  settle,
  shellWrites,
} from './scan'
import { candidates, gitleaksFindings, type Scanner, SCANNERS, scannerSteps, VERSION_ARGS } from './scanners'

// review-guard:
// 1. Remembers the code files Claude changes in a turn (not its own scratch files, nor a script a shell
//    command only ran, which the status line names). When the turn ends, sends Claude back
//    to review them with the pr-review-toolkit agents plus a security review for each language.
//    The review also names the outside scanners installed here that suit the files (bandit, semgrep,
//    zizmor, trivy), with commands to run.
// 2. Stops a git commit or push (and GitHub MCP writes) that would send secrets, keys, MAC or
//    IP addresses, or the person's own details to a repository with a GitHub remote. When gitleaks
//    is installed, what a commit or push sends also goes through it.
//
// The person's own details live in ~/.claude/review-guard.json, never in this code:
//   { "personal": ["name", "email", ...], "allowNetworkInfo": ["owner/repo"], "allowValues": [] }

type Config = { personal: string[]; allowNetworkInfo: string[]; allowValues: string[] }

const CONFIG_NAME = '.claude/review-guard.json'

// The review cycle. The module keeps it in memory, where changes cannot clash (the module runs one
// thing at a time), and copies each change to the session's state, which outlives a reload: the
// engine reloads the module whenever its files change, and a reload in the middle of a review used
// to forget the review was running, so its own fixes were reviewed again. After a reload the first
// hook reads the copy back. A failed copy loses nothing now; it only risks that after a reload.
const CYCLE = { plugin: 'review-guard', key: 'cycle' } as const
const EMPTY: Cycle = { reviewing: false, held: false, changed: {}, underReview: {} }

let cycle: Cycle = copyOf(EMPTY)
let loaded: Promise<void> | undefined // reading the copy back, once per load of the module
let saving: Promise<void> = Promise.resolve() // the copies, written one after another

function copyOf(c: Cycle): Cycle {
  return { reviewing: c.reviewing, held: c.held, changed: { ...c.changed }, underReview: { ...c.underReview } }
}

/** A stored value as a cycle, with anything missing or malformed (null, wrong types) read as empty. */
export function cycleFrom(value: unknown): Cycle {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return copyOf(EMPTY)
  const v = value as Record<string, unknown>
  const files = (x: unknown): Record<string, string> =>
    typeof x === 'object' && x !== null && !Array.isArray(x)
      ? Object.fromEntries(Object.entries(x).filter((kv): kv is [string, string] => typeof kv[1] === 'string'))
      : {}
  return { reviewing: v.reviewing === true, held: v.held === true, changed: files(v.changed), underReview: files(v.underReview) }
}

/** Reads the copy back after a reload; every hook waits for it before using the cycle. */
function ensureLoaded($: EngineInterface): Promise<void> {
  loaded ??= $.state.get(CYCLE).then(
    ({ value }) => { cycle = cycleFrom(value) },
    () => { $.ui.status('review-guard: could not read back its review state; a review running before the reload may be asked for again') },
  )
  return loaded
}

/** Copies the cycle as it stands when the write runs, after any earlier write; says so if it fails. */
function save($: EngineInterface): Promise<void> {
  saving = saving.then(() => $.state.set(CYCLE, copyOf(cycle))).then(
    () => undefined,
    () => { $.ui.status('review-guard: could not save its review state; if the mod reloads now, a running review may be asked for again') },
  )
  return saving
}

/** Applies `change` to the cycle once it is loaded, saves the copy, and resolves what `change` returned. */
async function updateCycle<T>($: EngineInterface, change: (c: Cycle) => T): Promise<T> {
  await ensureLoaded($)
  const result = change(cycle)
  await save($)
  return result
}

// An environment variable read so that it can't fail: undefined when unset or unreadable (a throw
// included). Every caller treats undefined as "not known", which keeps a file in the review. Each call
// names its variable as a literal, as the engine asks.
const safely = (read: () => Promise<string | undefined>) => Promise.resolve().then(read).catch(() => undefined)

/** How paths are spelled here. Windows is told by USERPROFILE, which Windows always sets. */
async function pathsHere($: EngineInterface): Promise<Paths> {
  const userProfile = await safely(() => $.env.get('USERPROFILE'))
  return { windows: userProfile !== undefined, home: await safely(() => $.env.get('HOME')), userProfile }
}

/** The machine's temp folders (TEMP, TMP, TMPDIR). One that can't be read is left out. */
async function tempDirs($: EngineInterface): Promise<string[]> {
  const dirs = [await safely(() => $.env.get('TEMP')), await safely(() => $.env.get('TMP')), await safely(() => $.env.get('TMPDIR'))]
  return dirs.filter((d): d is string => d !== undefined && d.trim() !== '')
}

/** Says on the status line which files were left out of the review and why, so no skip is silent. */
function sayLeftOut($: EngineInterface, scratch: string[], onlyRun: string[], said?: string): void {
  const parts = [
    ...(scratch.length ? [`scratch ${scratch.map(p => p.replace(/^.*[\\/]/, '')).join(', ')}`] : []),
    ...(onlyRun.length ? [`only run ${onlyRun.join(', ')}`] : []),
  ]
  if (parts.length === 0) return
  try {
    // After a line the guard just put there (a security notice), so that line is never hidden.
    $.ui.status(said ? `${said}. Not reviewed: ${parts.join('; ')}` : `review-guard: not reviewed (${parts.join('; ')})`)
  } catch { /* the status line is best effort */ }
}

/**
 * Code files were just changed: they wait for a review, and an interrupted task has picked up again.
 * Files in Claude's scratch folders (`inScratch`) are throwaway: they are left out, and an edit only to
 * them does not count as work picking up again. `posixTmp`: whether /tmp means the Unix temp folder
 * (not for the PowerShell tool). `keepScratch`: keep them too (a copy or move may have taken them into
 * the project). Returns the scratch files left out.
 */
async function remember($: EngineInterface, changed: [string, string][], posixTmp: boolean, keepScratch = false): Promise<string[]> {
  if (changed.length === 0) return []
  if (keepScratch) {
    await updateCycle($, c => {
      for (const [path, lang] of changed) c.changed[path] = lang
      c.held = false
    })
    return []
  }
  const temp = await tempDirs($)
  const { windows } = await pathsHere($)
  const scratch = changed.filter(([path]) => inScratch(path, temp, windows, posixTmp)).map(([path]) => path)
  const files = changed.filter(([path]) => !scratch.includes(path))
  if (files.length === 0) return scratch
  await updateCycle($, c => {
    for (const [path, lang] of files) c.changed[path] = lang
    c.held = false
  })
  return scratch
}

/** What the end of a turn asks for: a review, a word that one is held, or nothing. */
type StopAsk = { kind: 'review'; prompt: string } | { kind: 'held'; files: number } | undefined

const BUSY = new Set(['pending', 'running', 'waiting']) // an agent that has not handed back yet

async function homeDir($: EngineInterface): Promise<string | undefined> {
  const home = (await $.env.get('USERPROFILE')) ?? (await $.env.get('HOME'))
  return home?.replace(/\\/g, '/')
}

// The outside scanners installed here, found once per load of the module: a scanner to its program.
/** A scanner's program (`exe`), or why one that is there would not run (`broken`); neither: not installed. */
type Located = { exe?: string; broken?: string }

// Scanners found so far. Only a working one is kept: a missing or broken one is looked for again next
// time, so one installed (or unblocked) later is used without reloading the mod.
const located = new Map<Scanner, Promise<Located>>()

/**
 * Where a scanner is. A file that is there but does not run (blocked, half downloaded, too slow on its
 * first start) is `broken`, never "not installed"; only nothing at any place, and nothing on PATH, is.
 */
function locate($: EngineInterface, tool: Scanner): Promise<Located> {
  let found = located.get(tool)
  if (!found) {
    found = (async (): Promise<Located> => {
      const home = await homeDir($).catch(() => undefined)
      const windows = /^[A-Za-z]:\//.test(home ?? '')
      for (const exe of candidates(tool, home, windows)) {
        const isPath = exe.includes('/')
        if (isPath && !(await $.fs.exists(exe).catch(() => false))) continue
        try {
          const r = await $.process.run([exe, ...VERSION_ARGS[tool]], { timeoutMs: 30_000 })
          if (r.exitCode === 0) return { exe }
          return { broken: `${exe} exited ${r.exitCode}: ${r.stderr.trim().slice(0, 150) || 'no message'}` }
        } catch (err) {
          // A file that is there but would not start is broken; a bare name that would not start is not on PATH.
          if (isPath) return { broken: `${exe} would not start: ${err instanceof Error ? err.message : String(err)}` }
        }
      }
      return {}
    })()
    located.set(tool, found)
    void found.then(l => { if (!l.exe) located.delete(tool) }, () => located.delete(tool))
  }
  return found
}

/** The review scanners that run here, a scanner to its program. Never throws. */
async function findScanners($: EngineInterface): Promise<Map<Scanner, string>> {
  const tools = SCANNERS.filter(t => t !== 'gitleaks')
  const found = await Promise.all(tools.map(t => locate($, t).catch((): Located => ({}))))
  return new Map(tools.flatMap((t, i) => (found[i]?.exe ? [[t, found[i].exe] as const] : [])))
}

/**
 * gitleaks on what a commit or push sends: commit messages, added lines and new files' text. Not
 * installed: nothing, and a note. There but broken, failing, or with no full report: throws, so the
 * command stops. Its own ways to wave a finding through are shut, so allowValues stays the only one:
 * `--ignore-gitleaks-allow` for `gitleaks:allow` comments, the mod's own folder as the working folder
 * and ignore path (no `.gitleaks.toml` or `.gitleaksignore` there), and the config variables emptied.
 */
async function gitleaksScan($: EngineInterface, sent: readonly SentLine[], notes: string[]): Promise<Finding[]> {
  const { exe, broken } = await locate($, 'gitleaks')
  if (broken) throw new Error(`gitleaks is installed but would not run (${broken})`)
  if (!exe) {
    notes.push('gitleaks is not installed, so only the built-in checks ran')
    return []
  }
  if (sent.length === 0) return []
  const root = $.plugin.root
  const r = await $.process.run(
    [exe, 'stdin', '--no-banner', '--exit-code', '0', '--report-format', 'json', '--report-path', '-', '--log-level', 'error',
      '--ignore-gitleaks-allow', '--gitleaks-ignore-path', root],
    { stdin: sent.map(s => s.text).join('\n'), cwd: root, env: { GITLEAKS_CONFIG: '', GITLEAKS_CONFIG_TOML: '' }, timeoutMs: 120_000 },
  )
  if (r.exitCode !== 0 || r.isStdoutTruncated) throw new Error(`gitleaks failed: ${(r.stderr || 'its report was cut short').slice(0, 200)}`)
  return gitleaksFindings(r.stdout, sent.map(s => s.where))
}

async function configPath($: EngineInterface): Promise<string | undefined> {
  const home = await homeDir($)
  return home ? `${home}/${CONFIG_NAME}` : undefined
}

const CONFIG_KEYS = ['personal', 'allowNetworkInfo', 'allowValues'] as const

/**
 * The user's config. With no file to read, the secret checks still run and `note` says what was skipped.
 * A file that is there but wrong (bad JSON, a misspelt key, a value that is not a list of text) throws,
 * which stops the command: a typo must not quietly turn the personal checks off.
 */
async function loadConfig($: EngineInterface): Promise<{ config: Config; note?: string }> {
  const empty: Config = { personal: [], allowNetworkInfo: [], allowValues: [] }
  const note = 'personal details were NOT checked (no readable ~/.claude/review-guard.json)'
  const path = await configPath($)
  if (!path) return { config: empty, note }
  let text: string
  try {
    text = await $.fs.read(path)
  } catch {
    return { config: empty, note }
  }
  const raw: unknown = JSON.parse(text)
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) throw new Error('review-guard.json must be a JSON object')
  const fields = raw as Record<string, unknown>
  const unknown = Object.keys(fields).filter(k => !(CONFIG_KEYS as readonly string[]).includes(k))
  if (unknown.length > 0) throw new Error(`review-guard.json has a key it does not know: ${unknown.join(', ')}`)
  const list = (key: (typeof CONFIG_KEYS)[number]): string[] => {
    const v = fields[key]
    if (v === undefined) return []
    if (!Array.isArray(v) || v.some(x => typeof x !== 'string')) throw new Error(`review-guard.json: "${key}" must be a list of text values`)
    return (v as string[]).filter(x => x.trim() !== '')
  }
  return { config: { personal: list('personal'), allowNetworkInfo: list('allowNetworkInfo'), allowValues: list('allowValues') } }
}

async function git($: EngineInterface, dir: string | undefined, args: string[], timeoutMs = 60_000) {
  return $.process.run(dir ? ['git', '-C', dir, ...args] : ['git', ...args], { timeoutMs })
}

/** The repository's GitHub remote URLs, or [] when it has none (then nothing goes to GitHub). */
async function githubRemotes($: EngineInterface, dir: string | undefined): Promise<string[]> {
  const r = await git($, dir, ['remote', '-v'])
  if (r.exitCode !== 0) {
    // Not a repository: git itself will refuse the commit or push. Any other failure (a folder this
    // check could not open) must not pass as "no GitHub remote", so it stops the command.
    if (/not a git repository/i.test(r.stderr)) return []
    throw new Error(`git remote failed in ${dir ?? 'the session folder'}: ${r.stderr.slice(0, 200)}`)
  }
  return [...new Set(r.stdout.split('\n').map(l => l.split(/\s+/)[1] ?? '').filter(u => /github\.com/i.test(u)))]
}

const MAX_NEW_FILES = 300

/** Runs git and throws when it fails: a check that could not run must stop the command, not pass it. */
async function gitOk($: EngineInterface, dir: string | undefined, args: string[], what: string, timeoutMs = 60_000) {
  const r = await git($, dir, args, timeoutMs)
  if (r.exitCode !== 0) throw new Error(`${what} failed: ${r.stderr.slice(0, 200)}`)
  return r
}

const TOO_MUCH = (what: string): Finding => ({ kind: `more ${what} than can be checked at once (do it in smaller steps)`, where: 'this command' })

/** `notes` collects what could only be partly checked, for the user to see. */
async function findingsFor($: EngineInterface, action: GitAction, config: Config, notes: string[]): Promise<Finding[]> {
  const { dir } = action
  const out: Finding[] = []
  // What goes out, for gitleaks: one entry per line it reads, with where that line came from. Each text is
  // one line (every source is split on newlines first), so gitleaks' line i + 1 is `sent[i]`.
  const sent: SentLine[] = []
  const send = (diff: string) => sent.push(...addedLines(diff))
  // Who the commits will say made them.
  for (const v of ['GIT_AUTHOR_IDENT', 'GIT_COMMITTER_IDENT']) {
    const r = await git($, dir, ['var', v])
    if (r.exitCode === 0) out.push(...scanLine(r.stdout, `the commit's ${v === 'GIT_AUTHOR_IDENT' ? 'author' : 'committer'}`, config.personal))
  }
  if (action.message) {
    action.message.split('\n').forEach(l => {
      out.push(...scanLine(l, 'the commit message', config.personal))
      sent.push({ text: l, where: 'the commit message' })
    })
  }

  // A command can do both (`git commit ... && git push`): then the staged changes and the commits
  // already waiting are each checked.
  if (action.commits) {
    const diffArgs = ['-c', 'core.quotePath=false', 'diff', '--no-color', '--no-ext-diff', '-U0']
    const staged = await gitOk($, dir, [...diffArgs, '--cached'], 'git diff --cached')
    if (staged.isStdoutTruncated) out.push(TOO_MUCH('staged changes'))
    out.push(...scanDiff(staged.stdout, config.personal))
    send(staged.stdout)
    if (action.addsFiles) {
      // The same command stages more first: scan the working tree's changes and new files too.
      const tracked = await gitOk($, dir, diffArgs, 'git diff')
      if (tracked.isStdoutTruncated) out.push(TOO_MUCH('changes'))
      out.push(...scanDiff(tracked.stdout, config.personal))
      send(tracked.stdout)
      // New files are listed from the top of the repository, not the command's folder: `git add -A`
      // stages all of them, and the names git prints are then relative to where they are read from.
      const top = (await gitOk($, dir, ['rev-parse', '--show-toplevel'], 'git rev-parse')).stdout.trim()
      const untracked = await gitOk($, top, ['-c', 'core.quotePath=false', 'ls-files', '--others', '--exclude-standard'], 'git ls-files')
      const files = untracked.stdout.split('\n').filter(Boolean)
      if (untracked.isStdoutTruncated || files.length > MAX_NEW_FILES) out.push(TOO_MUCH('new files'))
      let nameOnly = 0
      for (const rel of files.slice(0, MAX_NEW_FILES)) {
        try {
          const text = await $.fs.read(`${top}/${rel}`)
          out.push(...scanFile(rel, text, config.personal))
          text.split('\n').forEach((l, i) => sent.push({ text: l, where: `${rel}:${i + 1}` }))
        } catch {
          // Over 4 MiB or unreadable: still check its name, and say so.
          out.push(...scanFile(rel, '', config.personal))
          nameOnly++
        }
      }
      if (nameOnly > 0) notes.push(`${nameOnly} new file(s) too large or unreadable were checked by name only`)
    }
  }
  if (action.pushes) {
    // What the push sends: the commits no remote has yet, with their metadata. A push that names
    // what to send (`origin main`, `--all`, `--tags`) is checked for exactly that.
    const logArgs = ['-c', 'core.quotePath=false', 'log', '-p', '--no-color', '--no-ext-diff', '-U0',
      '--format=COMMIT %h%nAUTHOR %an <%ae>%nCOMMITTER %cn <%ce>%n%B']
    const upstream = await git($, dir, ['rev-parse', '--abbrev-ref', '--symbolic-full-name', '@{u}'])
    const current = upstream.exitCode === 0 ? ['@{u}..HEAD'] : ['HEAD', '--not', '--remotes']
    const named = action.refs.length > 0 || action.allBranches || action.tags
    const heads = action.refs.length > 0 ? action.refs : action.allBranches ? [] : ['HEAD']
    const wanted = [...heads, ...(action.allBranches ? ['--branches'] : []), ...(action.tags ? ['--tags'] : []), '--not', '--remotes']
    let log = await git($, dir, [...logArgs, ...(named ? wanted : current)], 120_000)
    // A branch the same command creates does not exist yet: check the current one instead.
    if (log.exitCode !== 0 && named) log = await git($, dir, [...logArgs, ...current], 120_000)
    if (log.exitCode !== 0) {
      // A repository with no commit yet has nothing waiting; the commit this command makes was checked above.
      const empty = /does not have any commits yet|unknown revision|bad revision/i.test(log.stderr)
      if (!(empty && action.commits)) throw new Error(`git log failed: ${log.stderr.slice(0, 200)}`)
      log = { ...log, stdout: '' }
    }
    if (log.isStdoutTruncated) out.push({ kind: 'more history than can be checked at once (push in smaller steps)', where: 'the push' })
    // Each commit is: COMMIT, AUTHOR, COMMITTER, its message, then its diff.
    let commit = '?'
    let inMessage = false
    for (const line of log.stdout.split('\n')) {
      const c = /^COMMIT (\w+)$/.exec(line)
      if (c) {
        commit = c[1] ?? '?'
        inMessage = false
      } else if (/^(AUTHOR|COMMITTER) /.test(line)) {
        out.push(...scanLine(line, `commit ${commit}'s ${line.startsWith('A') ? 'author' : 'committer'}`, config.personal))
        inMessage = line.startsWith('COMMITTER')
      } else if (line.startsWith('diff --git')) {
        inMessage = false
      } else if (inMessage) {
        out.push(...scanLine(line, `commit ${commit}'s message`, config.personal))
        sent.push({ text: line, where: `commit ${commit}'s message` })
      }
    }
    out.push(...scanDiff(log.stdout, config.personal))
    send(log.stdout)
  }
  out.push(...(await gitleaksScan($, sent, notes)))
  return out
}

/** A run script's file as it was just before the command: its spelling in the command, place, time and size. */
type Snapshot = { script: string; place: string; mtimeMs: number; size: number; text?: string }

/** A plain file's time and size, or undefined for a link, a folder, or one that can't be found or read. */
async function fileState($: EngineInterface, place: string): Promise<{ mtimeMs: number; size: number } | undefined> {
  const stat = await Promise.resolve().then(() => $.fs.stat(place)).catch(() => undefined)
  return stat?.kind === 'file' && !stat.isLink ? { mtimeMs: stat.mtimeMs, size: stat.size } : undefined
}

// A script up to this size is also compared by its text, so a copy that keeps both time and size
// (`cp -p`, `rsync -a`, `touch -r` after a write) still shows. Larger ones are compared by time and size.
const COMPARE_TEXT_UP_TO = 512 * 1024

/** A run script's text, when it is small enough to keep; undefined otherwise or when it can't be read. */
async function scriptText($: EngineInterface, place: string, size: number): Promise<string | undefined> {
  if (size > COMPARE_TEXT_UP_TO) return undefined
  return Promise.resolve().then(() => $.fs.read(place)).then(t => (typeof t === 'string' ? t : undefined)).catch(() => undefined)
}

/**
 * Before a shell command runs: the files of the scripts it only runs (`runOnlyScripts`), as they are now.
 * None for a command run in the background, which has not finished when the hook looks again. Never
 * throws: a failure means no snapshots, so nothing is left out of the review.
 */
async function snapshotRunScripts($: EngineInterface, command: string, background: boolean, powershell: boolean): Promise<Snapshot[]> {
  if (background) return []
  try {
    const out: Snapshot[] = []
    for (const [script, place] of runOnlyScripts(command, await pathsHere($), powershell)) {
      const state = await fileState($, place)
      if (state) out.push({ script, place, ...state, text: await scriptText($, place, state.size) })
    }
    return out
  } catch {
    return []
  }
}

/**
 * After the command: the scripts from `before` whose file is as it was (same time and size, the same text
 * when it is small, still a plain file). The command only ran those. Comparing a file with itself needs no
 * clock, so a network share's clock can't fool it, and a copy, move, link, download or `touch` that
 * changed the file shows. (A copy of exactly the same text over it would not, and needs no review.)
 */
async function untouched($: EngineInterface, before: readonly Snapshot[]): Promise<Set<string>> {
  const out = new Set<string>()
  for (const b of before) {
    const now = await fileState($, b.place)
    if (!now || now.mtimeMs !== b.mtimeMs || now.size !== b.size) continue
    if (b.size <= COMPARE_TEXT_UP_TO && (b.text === undefined || (await scriptText($, b.place, now.size)) !== b.text)) continue
    out.add(b.script)
  }
  return out
}

// A shell result that came back while its command may still run: put in the background by the user,
// by a timeout, by a turn abort or to deliver a message. Its files can't be compared yet.
const STILL_RUNNING = ['backgroundTaskId', 'backgroundedByUser', 'backgroundedByTurnAbort', 'backgroundedToDeliverMessage', 'timedOutAfterMs', 'interrupted'] as const
const mayStillRun = (result: { result?: unknown }) => {
  const r = result.result
  return typeof r === 'object' && r !== null && STILL_RUNNING.some(k => Boolean((r as Record<string, unknown>)[k]))
}

/**
 * Code is also changed from a shell (sed -i, a redirect, a script that writes files). Once a shell
 * command has run, the code files it wrote are remembered for the review, less the scripts it only ran
 * (`before` holds them as they were) and Claude's scratch files. A command that failed may still have
 * written, so it counts; one that was refused never ran. What is left out is named on the status line,
 * after `said` when the guard already put a line there. Never throws: it only remembers.
 */
async function rememberShellWrites<R extends { deny?: unknown; result?: unknown }>($: EngineInterface, result: R, command: string, before: readonly Snapshot[], powershell: boolean, said?: string): Promise<R> {
  try {
    if (result.deny === undefined) {
      const written = shellWrites(command)
      const compare = written.length > 0 && before.length > 0 && !mayStillRun(result)
      const onlyRun = compare ? await untouched($, before).catch(() => new Set<string>()) : new Set<string>()
      const kept = written.filter(path => !onlyRun.has(path))
      // A scratch file named by a copy or move may be the source of a write into the project: keep it.
      const scratch = await remember($, kept.map(path => [path, languageOf(path) ?? 'other code']), !powershell, COPIES.test(command))
      sayLeftOut($, scratch, written.filter(path => onlyRun.has(path)), said)
    }
  } catch (err) {
    // A command whose writes could not be read or recorded is one fewer file in the review, not a stopped command, but say so.
    try {
      $.ui.status(`review-guard: could not record the files a shell command wrote (${err instanceof Error ? err.message : String(err)}); ask for a review by hand`)
    } catch { /* the status line is best effort */ }
  }
  return result
}

export const register: Register = on => {
  // --- 0. the review agents, in every session ------------------------------------------------

  // A new session reads them from agents/*.md. A session that was already open when the mod loaded
  // does not, so they are registered here too, at each load: the same names, so nothing doubles.
  on('session.start', async ($, e, next) => {
    const failed: string[] = []
    for (const agent of REVIEW_AGENTS) {
      try {
        await $.agent.register(agent)
      } catch {
        failed.push(agent.name)
      }
    }
    if (failed.length > 0) $.ui.status(`review-guard: could not load its review agents (${failed.join(', ')}); a new session will have them`)
    return next(e)
  }).catch(($, e, next) => next(e)) // a session must start whether or not the agents load

  // --- 1. remember the code a turn changes --------------------------------------------------

  on('prompt.submit', async ($, e, next) => {
    // A new request from the user in the middle of a review ends it early, so the edits that follow
    // get a review of their own. Reports, notices and anything unlabelled are part of the review.
    const asUser = e.origin.kind === 'plugin' && e.origin.asUser === true
    if (isNewRequest(e.origin.kind, e.isMeta === true, asUser)) {
      await updateCycle($, c => {
        if (!c.reviewing) return
        c.reviewing = false
        c.changed = {} // what the review's own agents wrote (scratch files, fixes) is not new work
      })
    }
    return next(e)
  }).catch(($, e, next) => next(e)) // only keeps a flag: a failure must never stop a prompt

  on('tool.call', { tool: ['Edit', 'Write', 'NotebookEdit'] }, async ($, e, next) => {
    const result = await next(e)
    if (result.deny === undefined && result.isError !== true) {
      const path = e.tool === 'NotebookEdit' ? e.notebook_path : e.file_path
      const lang = languageOf(path) ?? (/\.ipynb$/i.test(path) ? 'Python' : undefined)
      // The edit tools take a native path, so /tmp is the Unix temp folder only off Windows.
      if (lang) sayLeftOut($, await remember($, [[path, lang]], !(await pathsHere($)).windows), [])
    }
    return result
  }).catch(($, e, next) => next(e)) // only remembers: a failure must never stop an edit

  // The user stopped the main turn part way: the work is unfinished, so no review is asked for yet.
  // A review that was itself interrupted gives its files back to the queue.
  // A review whose turn died on an API error or a refusal also gives its files back, without the hold.
  on('turn.complete', async ($, e, next) => {
    if (e.agentId === undefined && e.reason !== 'answer') {
      await updateCycle($, c => {
        if (c.reviewing) for (const [path, lang] of Object.entries(c.underReview)) c.changed[path] ??= lang
        c.reviewing = false
        if (e.reason === 'aborted') c.held = true
      })
    }
    return next(e)
  }).catch(($, e, next) => next(e)) // only keeps flags: a failure must never change how a turn ends

  // --- 2. at the end of the turn, send Claude back to review it ------------------------------

  on('classic.Stop', async ($, e, next) => {
    const settled = await next(e)
    if (settled.block) return settled
    await ensureLoaded($)
    // The scanners installed here, for the review's commands (found once; none is fine).
    const found = await findScanners($).catch(() => new Map<Scanner, string>())
    // If the agents cannot be listed, the review ends here rather than holding every later review back.
    const busy = cycle.reviewing && (await $.agent.list().catch(() => [])).some(a => BUSY.has(a.status))
    const ask = await updateCycle($, (c): StopAsk => {
      if (c.reviewing) {
        // The review is over at the first stop with no agent still out. Until then the reviewers'
        // reports come back as turns of this review. Its own fixes are not sent for another review.
        if (!busy) {
          c.reviewing = false
          c.changed = {}
        }
        return undefined
      }
      // After an interrupt the files stay queued, and the review comes with the next turn that changes code.
      const files = Object.keys(c.changed).length
      if (c.held && files > 0) return { kind: 'held', files }
      if (e.stop_hook_active || files === 0) return undefined
      const changed = new Map(Object.entries(c.changed))
      const prompt = reviewPrompt(changed, scannerSteps(changed, found))
      c.underReview = c.changed
      c.changed = {}
      c.reviewing = true
      return { kind: 'review', prompt }
    })
    if (ask?.kind === 'held') {
      // The status line says so, so the queue is never silent.
      $.ui.status(`review-guard: review of ${ask.files} changed file(s) held after your interrupt; it runs when work on code resumes`)
      return settled
    }
    return ask === undefined ? settled : { ...settled, block: ask.prompt }
  }).catch(($, e, next) => next(e)) // a failed check lets the turn end as it would have

  // --- 3. keep secrets and personal data out of GitHub ---------------------------------------

  // Both shells: on Windows the PowerShell tool runs git as often as Bash does.
  on('tool.call', { tool: ['Bash', 'PowerShell'] }, async ($, e, next) => {
    // The scripts this command only runs, as they are before it runs, to compare afterwards.
    const powershell = e.tool === 'PowerShell'
    const before = await snapshotRunScripts($, e.command, e.run_in_background === true, powershell)
    // What ssh runs on another machine is left alone (the user's choice): it cannot be checked from here.
    const local = localPart(e.command)
    const action = gitAction(e.command)
    const gh = ghWrites(local)
    if (!action && !gh) {
      let said: string | undefined
      if (local !== e.command && /\bgit\b[^;&|\n]*\b(?:commit|push)\b/.test(e.command)) {
        said = 'review-guard: a git commit or push sent over SSH runs on another machine and was NOT checked here'
        $.ui.status(said)
      }
      return rememberShellWrites($, await next(e), e.command, before, powershell, said)
    }
    let remotes: string[] = []
    let toGitHub = false
    if (action) {
      const home = await homeDir($)
      if (action.dir) action.dir = resolveDir(action.dir, home, /^[A-Za-z]:\//.test(home ?? ''))
      remotes = await githubRemotes($, action.dir)
      // The command itself can name GitHub: `gh repo create`, a push to a URL, a remote added just before the push.
      toGitHub = remotes.length > 0 || /\bgh\s+repo\s+create\b|github\.com/i.test(local)
    }
    if (!toGitHub && !gh) return rememberShellWrites($, await next(e), e.command, before, powershell)
    const { config, note } = await loadConfig($)
    const notes = note ? [note] : []
    const found: Finding[] = []
    if (gh) found.push(...scanValue(local, 'the gh command', config.personal))
    if (action && toGitHub) found.push(...(await findingsFor($, action, config, notes)))
    const left = settle(found, networkAllowed(remotes, config.allowNetworkInfo), config.allowValues)
    const what = action && toGitHub ? (action.commits && action.pushes ? 'commit and push' : action.kind) : 'gh command'
    // What could only be partly checked goes with the refusal too: the status line would be overwritten.
    if (left.length > 0) return { deny: report(left, what) + (notes.length > 0 ? `\nAlso: ${notes.join('; ')}.` : '') }
    const said = notes.length > 0
      ? `review-guard: ${what} checked, but ${notes.join('; ')}`
      : `review-guard: ${what} checked, nothing personal or secret found`
    $.ui.status(said)
    return rememberShellWrites($, await next(e), e.command, before, powershell, said)
  }).catch(($, e, next) =>
    next.called ? next(e) : {
      deny: `review-guard could not check this command, so it stopped it (${next.error.message ?? next.error.kind}). If the command names ` +
        'its folder with a variable or a relative path, run it again with `git -C <absolute path>`. If the reason is about ' +
        'review-guard.json, tell the user what is wrong in it. Otherwise tell the user: the check itself failed.',
    },
  )

  // GitHub MCP tools that write (files, pull requests, issues, comments, reviews) send their text
  // straight to GitHub: check all of it. The ones that only read are left alone.
  on('tool.call', { tool: /^mcp__.*github.*__(?!get_|list_|search_|issue_read$|pull_request_read$)\w+$/ }, async ($, e, next) => {
    const { config, note } = await loadConfig($)
    const notes = note ? [note] : []
    const where = `the ${String(e.tool).split('__').pop()} call`
    // What the write sends goes through gitleaks too, value by value, like a commit's added lines.
    const raw = [...scanValue(e, where, config.personal), ...(await gitleaksScan($, valueLines(e, where), notes))]
    const found = settle(raw, false, config.allowValues)
    if (found.length > 0) return { deny: report(found, 'GitHub write') + (notes.length > 0 ? `\nAlso: ${notes.join('; ')}.` : '') }
    if (notes.length > 0) $.ui.status(`review-guard: GitHub write checked, but ${notes.join('; ')}`)
    return next(e)
  }).catch(($, e, next) =>
    next.called ? next(e) : { deny: `review-guard could not check this GitHub write, so it stopped it (${next.error.message ?? next.error.kind}).` },
  )

  // The allowlist is the user's to edit, not Claude's.
  on('tool.call', { tool: ['Edit', 'Write'] }, ($, e, next) =>
    /(^|[\\/])\.claude[\\/]review-guard\.json$/i.test(e.file_path)
      ? { deny: 'review-guard: ~/.claude/review-guard.json is the user\'s to edit. Tell them what to change instead.' }
      : next(e),
  ).catch(($, e, next) => (next.called ? next(e) : { deny: 'review-guard: its guard failed.' }))
}
