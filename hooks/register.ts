import type { EngineInterface, Register } from 'claude-code'
import { REVIEW_AGENTS } from './agents.ts'
import type { Cycle } from '../types'
import {
  isNewRequest,
  type Finding,
  ghWrites,
  gitAction,
  inScratch,
  languageOf,
  type Paths,
  runOnlyScripts,
  COPIES,
  localPart,
  networkAllowed,
  report,
  resolveDir,
  valueLines,
  reviewPrompt,
  scanValue,
  settle,
  shellWrites,
} from './scan.ts'
import { type Scanner, scannerSteps } from './scanners.ts'
import { type Config, findingsFor, findScanners, githubRemotes, gitleaksScan, homeFrom, type Host, loadConfig } from './outgoing.ts'
import { type LeftOut, type StatusFile, statusDir, statusFileName } from './status.ts'

// review-guard:
// 1. Remembers the code files Claude changes in a turn (not its own scratch files, nor a script a shell
//    command only ran, which the status line names). When the turn ends, sends Claude back
//    to review them with the pr-review-toolkit agents plus a security review for each language.
//    The review also names the outside scanners installed here that suit the files (bandit, semgrep,
//    zizmor, trivy), with commands to run.
// 2. Stops a git commit or push (and GitHub MCP writes) that would send secrets, keys, MAC or
//    IP addresses, or the person's own details to a repository with a GitHub remote. When gitleaks
//    is installed, what a commit or push sends also goes through it. The check itself is in
//    outgoing.ts, shared with the MCP server (mcp/server.mjs).
// 3. Writes each session's review state to ~/.claude/review-guard/status/ (status.ts) for the MCP
//    server's review_status tool.
//
// The person's own details live in ~/.claude/review-guard.json (read by loadConfig in outgoing.ts),
// never in this code:
//   { "personal": ["name", "email", ...], "allowNetworkInfo": ["owner/repo"], "allowValues": [] }

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
  await writeStatus($)
  return result
}

// The files left out of the review this session, newest last, for the status file. In memory only: a
// reload of the mod empties the list, so the file says since when it holds them (`leftOutSince`).
const leftOut: LeftOut[] = []
const LEFT_OUT_KEPT = 30
const leftOutSince = new Date().toISOString()
let statusWrites: Promise<void> = Promise.resolve() // the status writes, one after another
let statusFailed: string | undefined // why the last write failed, said once and kept in the next file

/**
 * Writes this session's review state to ~/.claude/review-guard/status/ (status.ts), where the MCP
 * server's `review_status` reads it: the server is another process and can't see the engine's state.
 * Kept on this machine only. One file per session, never deleted (the engine can't delete files;
 * review_status shows only recent ones). Writes run one after another, each with the state as it is
 * then. A failed write never stops anything, but it is said once in the log, and the next
 * file that is written says the one before it failed.
 */
function writeStatus($: EngineInterface, ended = false): Promise<void> {
  statusWrites = statusWrites.then(async () => {
    try {
      await ensureLoaded($)
      const home = await homeDir($)
      if (!home) throw new Error('the home folder is not known (neither USERPROFILE nor HOME is set)')
      const session = await $.session.id()
      const path = `${statusDir(home)}/${statusFileName(session)}`
      // A session with nothing to report gets no file: review_status lists the sessions that have
      // something. Once a file is there (from this load or an earlier one), it is kept current.
      const nothing = !cycle.reviewing && !cycle.held && Object.keys(cycle.changed).length === 0 && leftOut.length === 0
      if (nothing && !(await $.fs.exists(path))) {
        statusFailed = undefined
        return
      }
      const folder = await safely(() => $.session.cwd())
      const status: StatusFile = {
        v: 1,
        session,
        ...(folder ? { folder } : {}),
        updated: new Date().toISOString(),
        phase: ended ? 'ended' : cycle.reviewing ? 'reviewing' : cycle.held ? 'held' : 'idle',
        queued: Object.keys(cycle.changed),
        underReview: cycle.reviewing ? Object.keys(cycle.underReview) : [],
        leftOut: [...leftOut],
        leftOutSince,
        ...(statusFailed ? { writeFailed: statusFailed } : {}),
      }
      await $.fs.write(path, `${JSON.stringify(status, null, 2)}\n`)
      statusFailed = undefined
    } catch (err) {
      const first = statusFailed === undefined
      statusFailed = err instanceof Error ? err.message.slice(0, 200) : String(err)
      if (first) {
        // In the log, not on the status line: that line may hold a guard notice that must stay seen.
        try {
          $.ui.log(`review-guard: could not update its status file, so review_status may be behind (${statusFailed})`)
        } catch { /* the log is best effort */ }
      }
    }
  })
  return statusWrites
}

// A value read so that it can't fail: undefined when unset or unreadable (a throw included). Every caller
// treats undefined as "not known", which keeps a file in the review. An environment read names its
// variable as a literal, as the engine asks.
const safely = <T>(read: () => Promise<T | undefined>): Promise<T | undefined> => Promise.resolve().then(read).catch(() => undefined)

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

/**
 * Says on the status line which files were left out of the review and why, so no skip is silent, and
 * adds them to the status file. Never throws.
 */
async function sayLeftOut($: EngineInterface, scratch: string[], onlyRun: string[], said?: string): Promise<void> {
  const parts = [
    ...(scratch.length ? [`scratch ${scratch.map(p => p.replace(/^.*[\\/]/, '')).join(', ')}`] : []),
    ...(onlyRun.length ? [`only run ${onlyRun.join(', ')}`] : []),
  ]
  if (parts.length === 0) return
  try {
    // After a line the guard just put there (a security notice), so that line is never hidden.
    $.ui.status(said ? `${said}. Not reviewed: ${parts.join('; ')}` : `review-guard: not reviewed (${parts.join('; ')})`)
  } catch { /* the status line is best effort */ }
  const at = new Date().toISOString()
  leftOut.push(...scratch.map((path): LeftOut => ({ path, why: 'scratch', at })), ...onlyRun.map((path): LeftOut => ({ path, why: 'only run', at })))
  leftOut.splice(0, Math.max(0, leftOut.length - LEFT_OUT_KEPT))
  await writeStatus($)
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

/** The home folder (`homeFrom`: USERPROFILE, else HOME), or undefined. Never throws. */
async function homeDir($: EngineInterface): Promise<string | undefined> {
  return homeFrom(await safely(() => $.env.get('USERPROFILE')), await safely(() => $.env.get('HOME')))
}

/**
 * The engine as the outgoing check's `Host` (hooks/outgoing.ts): the same check the MCP server runs
 * through Node, here through `$`.
 */
function hostOf($: EngineInterface): Host {
  return {
    run: (argv, init) => $.process.run(argv, init),
    read: path => $.fs.read(path),
    exists: path => $.fs.exists(path),
    home: () => homeDir($),
    pluginRoot: $.plugin.root,
  }
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

/** A run script's text, when it is small enough to compare; undefined otherwise or when it can't be read. */
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
      if (!state) continue
      const text = await scriptText($, place, state.size)
      // A small script whose text can't be read can't be shown unchanged: it stays in the review.
      if (state.size <= COMPARE_TEXT_UP_TO && text === undefined) continue
      out.push({ script, place, ...state, text })
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
    if (b.size <= COMPARE_TEXT_UP_TO && (await scriptText($, b.place, now.size)) !== b.text) continue
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
      await sayLeftOut($, scratch, written.filter(path => onlyRun.has(path)), said)
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
  // The session's status file says it ended, so review_status doesn't show it as still running.
  on('session.end', async ($, e, next) => {
    let timer: ReturnType<typeof setTimeout> | undefined
    await Promise.race([writeStatus($, true), new Promise(done => { timer = setTimeout(done, 1000) })])
    clearTimeout(timer)
    return next(e)
  }).catch(($, e, next) => next(e)) // an exit must never wait on or fail for the status file

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
        c.underReview = {}
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
      if (lang) await sayLeftOut($, await remember($, [[path, lang]], !(await pathsHere($)).windows), [])
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
        c.underReview = {}
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
    const found = await findScanners(hostOf($)).catch(() => new Map<Scanner, string>())
    // If the agents cannot be listed, the review ends here rather than holding every later review back.
    const busy = cycle.reviewing && (await $.agent.list().catch(() => [])).some(a => BUSY.has(a.status))
    const ask = await updateCycle($, (c): StopAsk => {
      if (c.reviewing) {
        // The review is over at the first stop with no agent still out. Until then the reviewers'
        // reports come back as turns of this review. Its own fixes are not sent for another review.
        if (!busy) {
          c.reviewing = false
          c.underReview = {}
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
      remotes = await githubRemotes(hostOf($), action.dir)
      // The command itself can name GitHub: `gh repo create`, a push to a URL, a remote added just before the push.
      toGitHub = remotes.length > 0 || /\bgh\s+repo\s+create\b|github\.com/i.test(local)
    }
    if (!toGitHub && !gh) return rememberShellWrites($, await next(e), e.command, before, powershell)
    const { config, note } = await loadConfig(hostOf($))
    const notes = note ? [note] : []
    const found: Finding[] = []
    if (gh) found.push(...scanValue(local, 'the gh command', config.personal))
    if (action && toGitHub) found.push(...(await findingsFor(hostOf($), action, config, notes)))
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
    const { config, note } = await loadConfig(hostOf($))
    const notes = note ? [note] : []
    const where = `the ${String(e.tool).split('__').pop()} call`
    // What the write sends goes through gitleaks too, value by value, like a commit's added lines.
    const raw = [...scanValue(e, where, config.personal), ...(await gitleaksScan(hostOf($), valueLines(e, where), notes))]
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
