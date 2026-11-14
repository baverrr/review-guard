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
  CHANGES_FOLDER,
} from './scan.ts'
import { scannerSteps } from './scanners.ts'
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
const EMPTY: Cycle = { reviewing: false, held: false, changed: {}, underReview: {}, othersAtStart: [], othersChanged: {}, joined: [], promptPending: false, ownFolder: [] }

const OWN_FOLDER_KEPT = 500 // agents remembered in `ownFolder`: the 500 marked last

/** The strings in a stored list; anything else (or no list) gives none. */
function texts(x: unknown): string[] {
  return Array.isArray(x) ? x.filter((y): y is string => typeof y === 'string') : []
}

/** `ownFolder` as kept: each agent once, at its last place, and only the last `OWN_FOLDER_KEPT`. */
export function ownFolderOf(ids: readonly string[]): string[] {
  const last = [...new Set([...ids].reverse())].reverse()
  return last.slice(-OWN_FOLDER_KEPT)
}

let cycle: Cycle = copyOf(EMPTY)
let loaded: Promise<void> | undefined // reading the copy back, once per load of the module
let saving: Promise<void> = Promise.resolve() // the copies, written one after another

function copyOf(c: Cycle): Cycle {
  return { reviewing: c.reviewing, held: c.held, changed: { ...c.changed }, underReview: { ...c.underReview }, othersAtStart: [...c.othersAtStart], othersChanged: { ...c.othersChanged }, joined: [...c.joined], promptPending: c.promptPending, ownFolder: [...c.ownFolder] }
}

/** A stored value as a cycle, with anything missing or malformed (null, wrong types) read as empty. */
export function cycleFrom(value: unknown): Cycle {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return copyOf(EMPTY)
  const v = value as Record<string, unknown>
  const files = (x: unknown): Record<string, string> =>
    typeof x === 'object' && x !== null && !Array.isArray(x)
      ? Object.fromEntries(Object.entries(x).filter((kv): kv is [string, string] => typeof kv[1] === 'string'))
      : {}
  // A copy from before 0.3.4 has no list of other agents: then every agent still out holds the review open.
  const ids = texts(v.othersAtStart)
  const c: Cycle = {
    reviewing: v.reviewing === true, held: v.held === true, changed: files(v.changed), underReview: files(v.underReview),
    othersAtStart: [...new Set(ids)], othersChanged: files(v.othersChanged), joined: [...new Set(texts(v.joined))], promptPending: v.promptPending === true,
    // Kept outside a review too: an agent may join a later one. Only the newest are kept.
    ownFolder: ownFolderOf(texts(v.ownFolder)),
  }
  // Put right what a stored copy may hold wrongly (written by hand, damaged, or by another version).
  if (!c.reviewing) {
    // No review is running: nothing review-only stands, and no file it held is lost.
    c.changed = { ...c.underReview, ...c.othersChanged, ...c.changed }
    c.underReview = {}
    c.othersAtStart = []
    c.othersChanged = {}
    c.joined = []
    c.promptPending = false
  } else {
    c.held = false // a hold is only ever set with no review running
    c.joined = c.joined.filter(id => !c.othersAtStart.includes(id))
  }
  return c
}

let readBack = false // the stored copy has been read back (or there was none): saving it is safe
let readFailSaid = false // a failed read back is said once, not on every hook that retries it
let changedUnread = false // the cycle was changed in memory while the stored copy could not be read

/**
 * Reads the copy back after a reload; every hook waits for it before using the cycle. A read that fails
 * is tried again by the next hook, and until one works nothing is saved, so the stored review is never
 * written over with an empty one. If this load changed the cycle meanwhile, what it decided (a review
 * running or over, a hold) stands, and every file the stored copy still had waiting or under review is
 * queued again: more review, never less.
 */
function ensureLoaded($: EngineInterface): Promise<void> {
  loaded ??= $.state.get(CYCLE).then(
    ({ value }) => {
      const stored = cycleFrom(value)
      // `ownFolder` is only ever added to, so both lists are kept: an agent marked before the reload stays
      // marked, and one marked meanwhile (which alone does not count as a change, so a saved review stands).
      const ownFolder = ownFolderOf([...stored.ownFolder, ...cycle.ownFolder])
      cycle = changedUnread
        ? {
            ...cycle,
            changed: { ...stored.underReview, ...stored.othersChanged, ...stored.changed, ...cycle.changed },
            underReview: { ...cycle.underReview },
            ownFolder,
          }
        : { ...stored, ownFolder }
      readBack = true
      const saved: unknown = typeof value === 'object' && value !== null ? (value as { ownFolder?: unknown }).ownFolder : undefined
      const damaged = saved !== undefined && (!Array.isArray(saved) || saved.some(x => typeof x !== 'string'))
      if (damaged) logLine($, "review-guard: its saved list of agents in a folder of their own was damaged, so earlier agents' relative paths may be read against the session's folder")
      if (new Set([...stored.ownFolder, ...cycle.ownFolder]).size > ownFolder.length || texts(saved).length > OWN_FOLDER_KEPT) ownFolderCut($)
      if (readFailSaid) {
        readFailSaid = false
        say($, 'review-guard: read back its review state after all; nothing waiting for review was lost')
      }
    },
    err => {
      loaded = undefined
      if (readFailSaid) return
      readFailSaid = true
      say($, `review-guard: could not read back its review state (${whyOf(err)}); it tries again at the next step, and a review running before the reload may be asked for again`)
    },
  )
  return loaded
}

/** Copies the cycle as it stands when the write runs, after any earlier write; says so if it fails. */
function save($: EngineInterface): Promise<void> {
  if (!readBack) return saving
  saving = saving.then(() => $.state.set(CYCLE, copyOf(cycle))).then(
    () => undefined,
    err => say($, `review-guard: could not save its review state (${whyOf(err)}); if the mod reloads now, a running review may be asked for again`),
  )
  return saving
}

/** Applies `change` to the cycle once it is loaded, saves the copy, and resolves what `change` returned. */
async function updateCycle<T>($: EngineInterface, change: (c: Cycle) => T): Promise<T> {
  await ensureLoaded($)
  const result = change(cycle)
  if (!readBack) changedUnread = true
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
      const folder = await sessionFolder($)
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
      statusFailed = whyOf(err)
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

/**
 * A failure's message on one line, short enough for the status line: an Error's message, the engine's
 * HookFailure (`message`, else its `kind`, such as "timeout"), or the thrown value as text.
 */
export function whyOf(err: unknown): string {
  let text: string
  try {
    if (err instanceof Error) text = err.message
    else if (typeof err === 'object' && err !== null) {
      const { message, kind } = err as { message?: unknown; kind?: unknown }
      text = typeof message === 'string' && message.trim() ? message : typeof kind === 'string' ? kind : JSON.stringify(err) ?? ''
    } else text = err === undefined ? '' : String(err)
  } catch {
    text = 'a failure that could not be put into words' // a circular object, a BigInt, a getter that throws
  }
  // Cut by characters, not code units, so a cut never splits one in two.
  return Array.from(text.replace(/\s+/g, ' ').trim()).slice(0, 200).join('') || 'no message'
}

/**
 * Says that review-guard's own end-of-turn check failed. The queue is changed only after the review
 * prompt is built, and the hook leaves it alone once its dispatch is over, so any queued files wait for
 * the next turn that ends. `failure` is anything thrown.
 */
export function reviewFailed($: EngineInterface, failure: unknown): void {
  hookFailed($, 'its end-of-turn check failed', failure, 'any changed files stay queued for the next turn that ends')
}

/** Says that one of the mod's hooks failed, why, and what to do about it. */
function hookFailed($: EngineInterface, what: string, failure: unknown, advice: string): void {
  say($, `review-guard: ${what} (${whyOf(failure)}); ${advice}`)
}

/**
 * Puts a line on the status line. A failure to show it never stops anything: the line goes to the log
 * instead, so it still leaves a trace. (`ui.status` and `ui.log` are typed to return nothing; a promise
 * from either is handled all the same.)
 */
export function say($: EngineInterface, text: string): void {
  try {
    const shown: unknown = $.ui.status(text)
    if (typeof (shown as { then?: unknown } | undefined)?.then === 'function') (shown as PromiseLike<unknown>).then(undefined, () => logLine($, text))
  } catch {
    logLine($, text)
  }
}

/**
 * Puts a line in the log only, for what never means less review: the status line may hold a guard
 * notice that must stay seen. A failure to log is dropped, as there is nowhere left to say it.
 */
export function logLine($: EngineInterface, text: string): void {
  try {
    const logged: unknown = $.ui.log(text)
    if (typeof (logged as { then?: unknown } | undefined)?.then === 'function') (logged as PromiseLike<unknown>).then(undefined, () => undefined)
  } catch { /* nowhere left to say it */ }
}

const envFailSaid = new Set<string>() // environment variables that could not be read, each logged once

/**
 * An environment variable read by `read` (the engine wants each name written out at its call), or
 * undefined when unset or unreadable; a read that fails is logged once, by `name`.
 */
async function envValue($: EngineInterface, name: string, read: () => Promise<string | undefined>): Promise<string | undefined> {
  try {
    return await read()
  } catch (err) {
    if (!envFailSaid.has(name)) {
      envFailSaid.add(name)
      logLine($, `review-guard: could not read ${name} (${whyOf(err)}), so how paths are spelled here may be misread`)
    }
    return undefined
  }
}

/** How paths are spelled here (see `isWindows`). A variable that can't be read is logged once. */
async function pathsHere($: EngineInterface): Promise<Paths> {
  const userProfile = await envValue($, 'USERPROFILE', () => $.env.get('USERPROFILE'))
  const home = await envValue($, 'HOME', () => $.env.get('HOME'))
  const os = await envValue($, 'OS', () => $.env.get('OS'))
  return { windows: isWindows({ os, userProfile, home }), home, userProfile }
}

/**
 * Whether these environment values are Windows'. OS is `Windows_NT` on Windows, always. Without it: a
 * USERPROFILE with a drive letter, and a HOME that is missing, a Windows path, or Git Bash's `/c/...`.
 * Linux and WSL normally have a HOME like `/home/pat`, and may have a USERPROFILE passed in from Windows.
 */
export function isWindows(env: { os?: string; userProfile?: string; home?: string }): boolean {
  if (env.os === 'Windows_NT') return true
  if (env.userProfile === undefined || !/^[a-zA-Z]:[\\/]/.test(env.userProfile)) return false
  const home = env.home ?? ''
  return !home.startsWith('/') || /^\/[a-zA-Z](?:\/|$)/.test(home)
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
  // After a line the guard just put there (a security notice), so that line is never hidden.
  say($, said ? `${said}. Not reviewed: ${parts.join('; ')}` : `review-guard: not reviewed (${parts.join('; ')})`)
  const at = new Date().toISOString()
  leftOut.push(...scratch.map((path): LeftOut => ({ path, why: 'scratch', at })), ...onlyRun.map((path): LeftOut => ({ path, why: 'only run', at })))
  leftOut.splice(0, Math.max(0, leftOut.length - LEFT_OUT_KEPT))
  await writeStatus($)
}

let folderFailSaid = false // a session folder that could not be read is logged once, until a read works again

/**
 * The session's folder, or undefined. A failure to read it, or an empty answer, leaves relative paths
 * unresolved (they then never count as a file under review: more review, never less). It is logged once,
 * not put on the status line, which may hold a guard notice; a read that works again is logged too, so a
 * later failure is logged again.
 */
async function sessionFolder($: EngineInterface): Promise<string | undefined> {
  try {
    const folder: unknown = await $.session.cwd()
    if (typeof folder === 'string' && folder.trim() !== '') {
      if (folderFailSaid) logLine($, "review-guard: read the session's folder again; relative paths are matched again")
      folderFailSaid = false
      return folder
    }
    throw new Error(`the folder given was ${typeof folder === 'string' ? 'empty' : typeof folder}`)
  } catch (err) {
    if (!folderFailSaid) {
      folderFailSaid = true
      logLine($, `review-guard: could not read the session's folder (${whyOf(err)}), so relative paths are not matched to files under review`)
    }
    return undefined
  }
}

/**
 * A path spelled so that two spellings of one file compare equal: on Windows `/` for `\` and case ignored
 * (elsewhere a `\` is part of a file name and stays), Git Bash's `/c/...` as `C:/...` when `gitBash` (the
 * path came from Git Bash on Windows: in PowerShell `/c/...` is a folder `c` on the current drive), a
 * relative path (a shell command's own spelling, `sed -i x app.py`) resolved against `folder` when one is
 * given, and `.` and `..` steps taken. `gitBash` has no default: a stored key or a native path is read
 * with it false. The caller gives no folder when it can't be sure which one a relative path is from (a
 * command that changes folder, an agent in `ownFolder`, a session folder that could not be read, or a
 * review state not yet read back): then a relative path stays relative and can only fail to match a
 * full one, which means more review, never less.
 */
export function samePath(path: string, folder: string | undefined, windows: boolean, gitBash: boolean): string {
  let p = windows ? path.replace(/\\/g, '/') : path
  if (windows && gitBash) p = p.replace(/^\/([a-zA-Z])(?=\/|$)/, (_m, drive: string) => `${drive.toUpperCase()}:`)
  const absolute = (windows && /^[a-zA-Z]:(\/|$)/.test(p)) || p.startsWith('/')
  if (!absolute && folder) {
    const base = samePath(folder, undefined, windows, false) // the session's folder is a native path
    if (base !== '') p = base.endsWith('/') ? `${base}${p}` : `${base}/${p}`
  }
  const rooted = (windows && /^[a-zA-Z]:(\/|$)/.test(p)) || p.startsWith('/')
  const parts: string[] = []
  for (const [i, part] of p.split('/').entries()) {
    if (i === 0 && rooted) { parts.push(part); continue } // the root: '' for `/`, or a drive
    if (part === '' || part === '.') continue
    if (part === '..') {
      const top = parts.at(-1)
      if (rooted && parts.length === 1) continue // nothing above the root
      if (top !== undefined && top !== '..' && !(rooted && parts.length === 1)) { parts.pop(); continue }
    }
    parts.push(part)
  }
  const joined = rooted && parts.length === 1 ? `${parts[0]}/` : parts.join('/')
  return windows ? joined.toLowerCase() : joined
}

let ownFolderCutSaid = false // the list of agents in a folder of their own grew past its cap: logged once

/** Says once, in the log, that the list of agents in a folder of their own was cut to its cap. */
function ownFolderCut($: EngineInterface): void {
  if (ownFolderCutSaid) return
  ownFolderCutSaid = true
  logLine($, `review-guard: more than ${OWN_FOLDER_KEPT} agents worked in a folder of their own; the oldest are no longer remembered`)
}

/**
 * From now on, `id`'s relative paths are not read against the session's folder: saved, so a reload keeps
 * it. Only the last `OWN_FOLDER_KEPT` agents marked are kept, so an agent marked again moves to the end;
 * one dropped past the cap is logged once. Before the saved state is read back, the mark is kept in memory
 * only and joined to the saved list when it is read, so a mark alone never ends a saved review.
 */
async function inOwnFolder($: EngineInterface, id: string): Promise<void> {
  await ensureLoaded($)
  if (cycle.ownFolder.at(-1) === id) return
  const mark = (c: Cycle) => {
    const before = c.ownFolder.filter(x => x !== id).length + 1
    c.ownFolder = ownFolderOf([...c.ownFolder, id])
    return before > c.ownFolder.length
  }
  const cut = readBack ? await updateCycle($, mark) : mark(cycle)
  if (cut) ownFolderCut($)
}

/**
 * How a changed file is stored: as it was spelled, except that Git Bash's `/c/...` on Windows
 * (`gitBashOnWindows`) is stored as `C:/...`. A key still spelled `/c/...` then came from PowerShell or
 * an edit tool, where it is a folder `c` on the current drive, or from a copy saved before 0.3.7; either
 * way it never matches a drive C path, which means more review, never less.
 */
export function keyOf(path: string, gitBashOnWindows: boolean): string {
  return gitBashOnWindows ? path.replace(/^\/([a-zA-Z])(?=\/|$)/, (_m, drive: string) => `${drive.toUpperCase()}:`) : path
}

/**
 * Code files were just changed: they wait for a review, and an interrupted task has picked up again.
 * Files in Claude's scratch folders (`inScratch`) are throwaway: they are left out, and an edit only to
 * them does not count as work picking up again. `posixTmp`: whether /tmp means the Unix temp folder
 * (not for the PowerShell tool); on Windows it is true only for Git Bash, whose `/c/...` is drive C (see
 * `keyOf`). `keepScratch`: keep them too (a copy or move may have taken them into the project).
 * `agentId`: the agent that made the change, when not the main loop. During a review, an
 * agent that is other work (`othersAtStart`) has its files wait for a review of their own instead of
 * counting as the review's fixes, and so does one that joined the review (`joined`) for any file not
 * under review. Returns the scratch files left out.
 */
async function remember($: EngineInterface, changed: [string, string][], posixTmp: boolean, keepScratch = false, agentId?: string, sameFolder = true): Promise<string[]> {
  if (changed.length === 0) return []
  // During a review: other work's edits wait for their own review, and so do an agent's that joined the
  // review, except to the files under review (those are its fixes). Paths are compared as `samePath`
  // spells them, so another spelling of a file under review still counts as that file.
  const { windows: onWindows } = await pathsHere($)
  // Relative paths are read against the session's folder only when that is surely where they are from:
  // not when the command changes folder (`sameFolder` false), nor for an agent in `ownFolder` (started in
  // a folder of its own, by such an agent, or after an earlier `cd`), nor before the saved state is read
  // back (the saved `ownFolder` is not known yet). Read only when a joined agent's edit needs it.
  await ensureLoaded($)
  const needed = agentId !== undefined && cycle.reviewing && cycle.joined.includes(agentId)
  const folder = needed && sameFolder && readBack && !cycle.ownFolder.includes(agentId) ? await sessionFolder($) : undefined
  // Only full paths can match: a relative one (a stored key, or a path that could not be resolved) never
  // does, as the folder it was relative to may not be the one seen now.
  // On Windows a path must have a drive: `/proj/x.py` is the current drive's root in PowerShell but under
  // Git's install folder in Git Bash, so it is not sure which file it names.
  const full = (x: string) => (onWindows ? /^[a-z]:\//i.test(x) : x.startsWith('/'))
  // On Windows, `posixTmp` is true only for a path from Git Bash (not PowerShell, nor the edit tools).
  // Stored keys are spelled by `keyOf`, so one still spelled `/c/...` is a folder `c`, not drive C.
  const path0 = (path: string) => samePath(path, folder, onWindows, posixTmp)
  const underReview = (c: Cycle, path: string) => {
    const p = path0(path)
    return full(p) && Object.keys(c.underReview).some(k => samePath(k, undefined, onWindows, false) === p)
  }
  const key = (path: string) => keyOf(path, onWindows && posixTmp)
  const queueFor = (c: Cycle, path: string) =>
    c.reviewing && agentId !== undefined && (c.othersAtStart.includes(agentId) || (c.joined.includes(agentId) && !underReview(c, path)))
      ? c.othersChanged
      : c.changed
  if (keepScratch) {
    await updateCycle($, c => {
      for (const [path, lang] of changed) queueFor(c, path)[key(path)] = lang
      c.held = false
    })
    return []
  }
  const temp = await tempDirs($)
  const scratch = changed.filter(([path]) => inScratch(path, temp, onWindows, posixTmp)).map(([path]) => path)
  const files = changed.filter(([path]) => !scratch.includes(path))
  if (files.length === 0) return scratch
  await updateCycle($, c => {
    for (const [path, lang] of files) queueFor(c, path)[key(path)] = lang
    c.held = false
  })
  return scratch
}

/** What the end of a turn asks for: a review, a word that one is held, or nothing. */
type StopAsk = { kind: 'review'; prompt: string } | { kind: 'held'; files: number } | undefined

// An agent that is done for good. `idle` is not: a teammate waits for its next message that way.
const FINISHED = new Set(['completed', 'failed', 'killed'])

/**
 * An agent as `$.agent.list()` gives it, read so that nothing throws. `out`: it is working now (anything
 * but idle or finished, a status the engine adds later included). `finished`: it is done for good.
 */
type Listed = { id: string; out: boolean; finished: boolean }

/** The session's agents, from what `$.agent.list()` resolved. Anything that is not a list throws. */
export function agentsListed(list: unknown): Listed[] {
  if (!Array.isArray(list)) throw new Error('the agent list was not a list')
  return list
    .filter((a): a is { id?: unknown; status?: unknown } => typeof a === 'object' && a !== null)
    .map(a => {
      const status = typeof a.status === 'string' ? a.status : ''
      return { id: typeof a.id === 'string' ? a.id : '', out: status !== 'idle' && !FINISHED.has(status), finished: FINISHED.has(status) }
    })
}

/**
 * Whether one of these agents holds the running review open: one working now that is not other work
 * (`othersAtStart`). Whatever its type, an agent started during the review is part of it: a reviewer, a
 * general-purpose agent doing the security review, a fork fixing findings. An agent with no id can't be
 * told apart, so it counts.
 */
export function reviewHeldOpen(listed: readonly Listed[], othersAtStart: readonly string[]): boolean {
  return listed.some(a => a.out && (a.id === '' || !othersAtStart.includes(a.id)))
}

/**
 * The agents that are still other work at a check: all but those listed as finished. One that has
 * finished leaves, so if it is started again it counts as part of the review (the `agent.spawn` hook sees
 * a restart at once and judges it by who started it; this catches one it could not see). An agent the list
 * does not show stays: a workflow's agents are never listed, and a missing entry proves nothing.
 */
export function stillOthers(othersAtStart: readonly string[], listed: readonly Listed[]): string[] {
  return othersAtStart.filter(id => !listed.some(a => a.id === id && a.finished))
}

/**
 * Who is other work after one agent starts or wakes another during a review. `by` is the agent that did
 * it (undefined for the main loop), `id` the one started or woken. Work that other work hands on stays
 * other work; work the main loop or the review's own agents hand to an earlier agent makes it the review's.
 */
export function afterHandOn(othersAtStart: readonly string[], by: string | undefined, id: string): string[] {
  if (by !== undefined && othersAtStart.includes(by)) return othersAtStart.includes(id) ? [...othersAtStart] : [...othersAtStart, id]
  return othersAtStart.filter(other => other !== id)
}

/**
 * The id of the agent a message goes to, from what `$.agent.list()` resolved: `to` as SendMessage spells
 * it (an id, the agent's name, a teammate's `name@team` or bare name, with or without a listing's " [ref]").
 * When two agents carry the name, the one listed last, the newest, is the one a name reaches. Undefined
 * for a recipient that is not an agent of this session (the main conversation, another session).
 */
export function recipient(to: unknown, list: unknown): string | undefined {
  if (typeof to !== 'string' || to.trim() === '') return undefined
  const name = to.trim().replace(/\s+\[[^\]]*\]$/, '')
  const agents = Array.isArray(list)
    ? list.filter((a): a is { id: string; name?: unknown; teammateId?: unknown } => typeof a === 'object' && a !== null && typeof a.id === 'string')
    : []
  if (agents.some(a => a.id === name)) return name
  const named = agents.filter(a => a.name === name || a.teammateId === name || (typeof a.teammateId === 'string' && a.teammateId.startsWith(`${name}@`)))
  return named.at(-1)?.id
}

// Agent starts (new or again) that may be a review's, so an end-of-turn check can tell whether one began
// or was under way while it read the agent list: `startsUnderWay` holds those not yet settled, and
// `agentStarts` counts those that went through (it only ever goes up, so a check that compares two
// readings never misses one). Not counted: a start by other work (settled as other work when it goes
// through), a workflow's agent (never listed, so it could never let a review end), and a refused start.
// Starts the engine raises no event for are not seen at all. Kept in memory only: a reload starts again
// from 0, and a check compares two readings from the same load.
let agentStarts = 0
// The starts under way, each with when it began: on the machine's clock at once, and on the engine's
// clock once that answers. One under way longer than STUCK_MS (a hook beneath that hangs) no longer holds
// a review open, so a stuck start can't keep one open for good. Two times are only ever compared on the
// same clock. `stuckSaid`: those already named in the log.
type Began = { machine: number; engine?: number }
const startsUnderWay = new Map<number, Began>()
const stuckSaid = new Set<number>()
const stuckEndSaid = new Set<number>()
let startTokens = 0
const STUCK_MS = 120_000

/**
 * The time now in milliseconds on the engine's clock, when it answers within a second with a real number;
 * undefined otherwise. Never throws and never waits long.
 */
async function engineNow($: EngineInterface): Promise<number | undefined> {
  const timers = globalThis as { setTimeout?: (run: () => void, ms: number) => unknown; clearTimeout?: (id: unknown) => void }
  if (typeof timers.setTimeout !== 'function') return undefined // no way to bound the wait
  let timer: unknown
  try {
    const late = new Promise<undefined>(done => { timer = timers.setTimeout?.(() => done(undefined), 1000) })
    const t = await Promise.race([safely(() => $.clock.now()), late])
    return typeof t === 'number' && Number.isFinite(t) ? t : undefined
  } catch {
    return undefined
  } finally {
    try { timers.clearTimeout?.(timer) } catch { /* nothing to clear */ }
  }
}

/**
 * How long a start has been under way: the longer of what the engine's clock and the machine's clock say,
 * each compared only with itself (the engine's when both readings have it). A clock that has stopped can
 * so never keep a stuck start from counting as stuck.
 */
export function underWayFor(began: Began, engine: number | undefined, machine: number): number {
  const onMachine = machine - began.machine
  return engine !== undefined && began.engine !== undefined ? Math.max(engine - began.engine, onMachine) : onMachine
}
// How many reviews this load has started, so a start that began before the running review is told apart.
let reviewsStarted = 0
/**
 * Whether the running review's prompt is still on its way (handed out, not yet seen to arrive). A prompt
 * that arrives makes the next end of a turn a Stop hook continuation (`stop_hook_active`); a stop that is
 * not one, or the turn ending with an answer, means it never arrived, and its files go back in the queue.
 */
const reviewNotDelivered = () => cycle.reviewing && cycle.promptPending

/**
 * Records, during a review, that `by` (undefined: the main loop) started, started again or messaged `id`.
 * `beforeReview`: the start began before this review did, so it can only be other work.
 */
async function handOn($: EngineInterface, by: string | undefined, id: string, beforeReview = false, newStart = false): Promise<void> {
  await ensureLoaded($)
  if (!cycle.reviewing) return
  const others = (list: readonly string[]) =>
    beforeReview ? (list.includes(id) ? [...list] : [...list, id]) : afterHandOn(list, by, id)
  // A new helper started by an agent that joined the review joins it too (not one it only messages or
  // starts again, which may be the review's own).
  const helperOfJoined = newStart && !beforeReview && by !== undefined && cycle.joined.includes(by) && !cycle.joined.includes(id)
  // Both only ever add one id or take ids away, so an unchanged length means nothing changed.
  if (others(cycle.othersAtStart).length === cycle.othersAtStart.length && !helperOfJoined) return
  await updateCycle($, c => {
    if (!c.reviewing) return
    const next = others(c.othersAtStart)
    // An earlier agent the review took on: remembered, so its edits outside the review stay its own.
    for (const left of c.othersAtStart) if (!next.includes(left) && !c.joined.includes(left)) c.joined.push(left)
    if (helperOfJoined && by !== undefined && c.joined.includes(by) && !next.includes(id) && !c.joined.includes(id)) c.joined.push(id)
    c.othersAtStart = next
    c.joined = c.joined.filter(j => !next.includes(j)) // other work again: never on both lists
  })
}

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
async function rememberShellWrites<R extends { deny?: unknown; result?: unknown }>($: EngineInterface, result: R, command: string, before: readonly Snapshot[], powershell: boolean, said?: string, agentId?: string): Promise<R> {
  try {
    if (result.deny === undefined) {
      // A command that changes folder (`CHANGES_FOLDER`): its relative paths are not the session's. A shell
      // may keep the new folder, so neither are those of the same agent's later commands: that agent goes
      // into `ownFolder`. A word that is not really a command (in a message, say) only means more review.
      // A failure is logged, not shown: the status line may hold the guard's notice (`said`).
      if (agentId !== undefined && CHANGES_FOLDER.test(command)) {
        await inOwnFolder($, agentId).catch(err => {
          logLine($, `review-guard: could not record an agent that changed folder (${whyOf(err)}); its relative paths may be matched against the wrong folder`)
        })
      }
      const written = shellWrites(command)
      const compare = written.length > 0 && before.length > 0 && !mayStillRun(result)
      const onlyRun = compare ? await untouched($, before).catch(() => new Set<string>()) : new Set<string>()
      const kept = written.filter(path => !onlyRun.has(path))
      // A scratch file named by a copy or move may be the source of a write into the project: keep it.
      const scratch = await remember($, kept.map(path => [path, languageOf(path) ?? 'other code']), !powershell, COPIES.test(command), agentId, !CHANGES_FOLDER.test(command))
      await sayLeftOut($, scratch, written.filter(path => onlyRun.has(path)), said)
    }
  } catch (err) {
    // A command whose writes could not be read or recorded is one fewer file in the review, not a stopped command, but say so.
    say($, `review-guard: could not record the files a shell command wrote (${whyOf(err)}); ask for a review by hand`)
  }
  return result
}

/**
 * Ends the running review. `fixes`: what to do with the files changed while it ran, its own fixes: drop
 * them (the review is over), or queue them with the files it covered (it was cut short). Files other
 * agents changed meanwhile are queued either way.
 */
function endReview(c: Cycle, fixes: 'drop' | 'requeue'): void {
  if (fixes === 'drop') c.changed = {}
  else for (const [path, lang] of Object.entries(c.underReview)) c.changed[path] ??= lang
  Object.assign(c.changed, c.othersChanged)
  c.reviewing = false
  c.underReview = {}
  c.othersAtStart = []
  c.othersChanged = {}
  c.joined = []
  c.promptPending = false
}

/**
 * What the end of a turn asks for, once nothing beneath has blocked it. A dispatch that is already over
 * (an interrupt, or the hook's time ran out) takes no files off the queue: the review prompt would
 * never reach Claude.
 */
async function stopAsk($: EngineInterface, hookActive: boolean, signal: AbortSignal): Promise<StopAsk> {
  await ensureLoaded($)
  if (signal.aborted) return undefined
  // The scanners installed here, for the review's commands, and why any that is there would not run
  // or could not be looked for: the prompt names those, never as "not installed".
  const { found, problems } = await findScanners(hostOf($))
  // The session's agents: while a review runs, to see whether it is over; before one starts, to know
  // which agents are other work. (Background shell commands and a workflow's agents are not in this list,
  // so they never hold a review open; nor are a workflow's agent starts counted below.)
  let listFailed: string | undefined
  let listed: Listed[] = []
  const reviewing = cycle.reviewing
  // An agent started while the list is read may be missing from it: counted, so the check can tell.
  const startsBefore = agentStarts
  if (reviewing || (!hookActive && !cycle.held && Object.keys(cycle.changed).length > 0)) {
    try {
      listed = agentsListed(await $.agent.list())
    } catch (err) {
      listFailed = whyOf(err)
    }
  }
  if (listFailed !== undefined && reviewing && !(reviewNotDelivered() && !hookActive)) {
    // While a review runs, it ends here rather than holding every later review back: reports still to come
    // then count as new work.
    say($, `review-guard: could not list the session's agents (${listFailed}), so the review counts as over; fixes from reports still to come get a review of their own`)
  }
  if (signal.aborted) return undefined
  const engine = startsUnderWay.size > 0 ? await engineNow($) : undefined
  if (signal.aborted) return undefined
  const machine = Date.now()
  const isStuck = (began: Began) => underWayFor(began, engine, machine) >= STUCK_MS
  const underWay = [...startsUnderWay.values()].filter(b => !isStuck(b)).length
  const stuckNow = [...startsUnderWay].filter(([, b]) => isStuck(b)).map(([token]) => token)
  let keptOpenByStart = false
  let endedPastStuck = false
  let promptLost = false
  const ask = await updateCycle($, (c): StopAsk => {
    // The running review's prompt was handed out at an earlier stop: this stop shows whether it arrived.
    if (c.reviewing && c.promptPending && !hookActive) {
      promptLost = true
      endReview(c, 'requeue')
    }
    if (c.reviewing && hookActive) c.promptPending = false
    if (c.reviewing) {
      // The review is over at the first stop with none of its agents still out. Until then the reviewers'
      // reports come back as turns of this review. Its own fixes are not sent for another review.
      // An agent started while or since the list was read may be one of the review's, still working: the
      // review stays open until a check where none started meanwhile.
      const startedMeanwhile = agentStarts !== startsBefore || underWay > 0
      const heldOpen = reviewHeldOpen(listed, c.othersAtStart)
      if (listFailed !== undefined || (!startedMeanwhile && !heldOpen)) {
        endReview(c, 'drop')
        // A stuck start made the difference only when it is all that could have held the review open.
        if (listFailed === undefined && stuckNow.some(token => !stuckEndSaid.has(token))) {
          endedPastStuck = true
          for (const token of stuckNow) stuckEndSaid.add(token)
        }
      } else {
        const still = stillOthers(c.othersAtStart, listed)
        // One that finished leaves other work: if it runs again it is the review's, as joined.
        for (const left of c.othersAtStart) if (!still.includes(left) && !c.joined.includes(left)) c.joined.push(left)
        c.othersAtStart = still
        if (!heldOpen) keptOpenByStart = true
      }
      return undefined
    }
    // After an interrupt the files stay queued, and the review comes with the next turn that changes code.
    const files = Object.keys(c.changed).length
    if (c.held && files > 0) return { kind: 'held', files }
    if (hookActive || files === 0) return undefined
    const changed = new Map(Object.entries(c.changed))
    const prompt = reviewPrompt(changed, scannerSteps(changed, found, problems))
    c.underReview = c.changed
    c.changed = {}
    c.reviewing = true
    c.promptPending = true
    reviewsStarted++
    // Other work: every agent not finished, an idle teammate waiting for its next message included.
    c.othersAtStart = listed.filter(a => !a.finished && a.id !== '').map(a => a.id)
    c.othersChanged = {}
    c.joined = []
    return { kind: 'review', prompt }
  })
  const sayLost = (askedAgain: boolean) => {
    if (!promptLost) return
    say($, askedAgain
      ? 'review-guard: the review prompt did not reach Claude (the turn ended another way), so it is asked for again'
      : 'review-guard: the review prompt did not reach Claude (the turn ended another way), so its files are queued again')
  }
  // Said once per start, and only while this check judged a running review by its agents.
  const newlyStuck = stuckNow.filter(token => !stuckSaid.has(token))
  if (newlyStuck.length > 0 && reviewing && !promptLost && listFailed === undefined) {
    for (const token of newlyStuck) stuckSaid.add(token)
    try {
      $.ui.log(newlyStuck.length === 1
        ? 'review-guard: an agent start under way for over two minutes no longer holds the review open'
        : `review-guard: ${newlyStuck.length} agent starts under way for over two minutes no longer hold the review open`)
    } catch { /* the log is best effort */ }
  }
  if (endedPastStuck) say($, 'review-guard: the review counts as over; an agent start stuck for over two minutes was not waited for')
  if (keptOpenByStart) {
    // Not on the status line, which may hold a guard notice: a trace in the log is enough for this.
    try {
      $.ui.log('review-guard: the review stays open: an agent start was under way or went through while the agent list was read')
    } catch { /* the log is best effort */ }
  }
  // The dispatch ended while the queue was being moved: put the files back, as no review was asked for.
  const thisReview = reviewsStarted
  const putBack = async () => {
    sayLost(false)
    // Only if the review still running is this one: another may have ended it (and put its files back).
    let skipped = false
    await updateCycle($, c => {
      if (c.reviewing && reviewsStarted === thisReview) endReview(c, 'requeue')
      else skipped = true
    })
    try {
      $.ui.log(skipped
        ? 'review-guard: the turn ended as a review started, but that review had already ended'
        : 'review-guard: the turn ended as a review started, so its files are queued again')
    } catch { /* the log is best effort */ }
    return undefined
  }
  if (ask?.kind === 'review' && signal.aborted) return putBack()
  if (ask?.kind === 'review' && listFailed !== undefined) {
    // The review started without knowing what other work is going on: every agent at work counts as its own.
    say($, `review-guard: could not list the session's agents (${listFailed}); any agent already at work counts as part of this review`)
  }
  if (ask?.kind === 'review' && listFailed === undefined) {
    // An agent that appeared after the list was read, before the review prompt reaches Claude, can't be one
    // of the review's: none exists yet, as the prompt goes out only when this hook returns. Read the list
    // once more and count any newcomer as other work.
    let again: Listed[] | undefined
    try {
      again = agentsListed(await $.agent.list())
    } catch (err) {
      hookFailed($, "could not list the session's agents a second time as the review started", err,
        'an agent started just then counts as part of the review: it holds it open while it works, and its changes are not reviewed, so ask for a review by hand if one started')
    }
    if (again !== undefined) {
      const newcomers = again
      try {
        await updateCycle($, c => {
          if (!c.reviewing) return
          for (const a of newcomers) if (!a.finished && a.id !== '' && !c.othersAtStart.includes(a.id)) c.othersAtStart.push(a.id)
          c.joined = c.joined.filter(j => !c.othersAtStart.includes(j))
        })
      } catch (err) {
        hookFailed($, 'could not record the agents that started as the review began', err,
          'they count as part of the review, so ask for a review by hand if one of them changed code')
      }
    }
    if (signal.aborted) return putBack()
  }
  sayLost(ask?.kind === 'review')
  return ask
}

export const register: Register = on => {
  // --- 0. the review agents, in every session ------------------------------------------------

  // A new session reads them from agents/*.md. A session that was already open when the mod loaded
  // does not, so they are registered here too, at each load: the same names, so nothing doubles.
  // The session's status file says it ended, so review_status doesn't show it as still running.
  on('session.end', async ($, e, next) => {
    // At most a second, on the engine's own clock. An exit never waits longer for the status file: if the
    // clock itself fails, the exit goes ahead at once, and review_status may then show the session open.
    await Promise.race([writeStatus($, true), $.clock.sleep(1000, { signal: next.signal }).catch(() => undefined)])
    return next(e)
  }).catch(($, e, next) => {
    // An exit must never wait on or fail for the status file; the log keeps a trace.
    if (!next.called) {
      try {
        $.ui.log(`review-guard: could not mark this session as ended in its status file (${whyOf(next.error)})`)
      } catch { /* nowhere left to say it */ }
    }
    return next(e)
  })

  on('session.start', async ($, e, next) => {
    const failed: string[] = []
    for (const agent of REVIEW_AGENTS) {
      try {
        await $.agent.register(agent)
      } catch {
        failed.push(agent.name)
      }
    }
    if (failed.length > 0) say($, `review-guard: could not load its review agents (${failed.join(', ')}); a new session will have them`)
    return next(e)
  }).catch(($, e, next) => {
    // A session must start whether or not the agents load, but not quietly.
    if (!next.called) hookFailed($, 'could not load its review agents', next.error, 'a new session will have them')
    return next(e)
  })

  // --- 1. remember the code a turn changes --------------------------------------------------

  on('prompt.submit', async ($, e, next) => {
    // A new request from the user in the middle of a review ends it early, so the edits that follow
    // get a review of their own. Reports, notices and anything unlabelled are part of the review.
    const asUser = e.origin.kind === 'plugin' && e.origin.asUser === true
    if (isNewRequest(e.origin.kind, e.isMeta === true, asUser)) {
      // Decided on the stored copy (read back first after a reload), inside the update. A turn that ended
      // without the review prompt has already put its files back (turn.complete), so a review still
      // waiting here is one whose turn still runs (typed mid-turn: it arrived) or one with no turn yet.
      let requeued = false
      await updateCycle($, c => {
        if (!c.reviewing) return
        // What the review's own agents wrote (scratch files, fixes) is not new work. But a review whose
        // prompt never reached Claude had no agents and no fixes: its files go back in the queue.
        requeued = c.promptPending && e.turnId === undefined
        endReview(c, requeued ? 'requeue' : 'drop')
      })
      if (requeued) say($, 'review-guard: the review asked for at the last stop had not started; its files are queued again with this request')
    }
    return next(e)
  }).catch(($, e, next) => {
    // Only keeps a flag: a failure must never stop a prompt. Said, because a review left running would
    // count the edits for this request as its own fixes.
    if (!next.called) {
      hookFailed($, 'could not check whether this new request ends a running review', next.error,
        'if one was running, the edits for this request may go unreviewed, so ask for a review by hand')
    }
    return next(e)
  })

  on('tool.call', { tool: ['Edit', 'Write', 'NotebookEdit'] }, async ($, e, next) => {
    const result = await next(e)
    // Only remembers: a failure here must never stop an edit, but a file left out of the review is said.
    // (A failure beneath, in the edit itself, is not this mod's to report.)
    try {
      if (result.deny === undefined && result.isError !== true) {
        const path = e.tool === 'NotebookEdit' ? e.notebook_path : e.file_path
        const lang = languageOf(path) ?? (/\.ipynb$/i.test(path) ? 'Python' : undefined)
        // The edit tools take a native path, so /tmp is the Unix temp folder only off Windows.
        if (lang) await sayLeftOut($, await remember($, [[path, lang]], !(await pathsHere($)).windows, false, e.agentId), [])
      }
    } catch (err) {
      hookFailed($, 'could not record an edited file for review', err, 'ask for a review by hand')
    }
    return result
  }).catch(($, e, next) => {
    // Only this hook running out of time is said: an edit that failed beneath is not this mod's to report.
    if (next.called && next.error.kind === 'timeout') hookFailed($, 'ran out of time recording an edited file for review', next.error, 'ask for a review by hand')
    return next(e)
  })

  // The user stopped the main turn part way: the work is unfinished, so no review is asked for yet.
  // A review that was itself interrupted gives its files back to the queue.
  // A review whose turn died on an API error or a refusal also gives its files back, without the hold.
  on('turn.complete', async ($, e, next) => {
    if (e.agentId === undefined && e.reason !== 'answer') {
      await updateCycle($, c => {
        if (c.reviewing) endReview(c, 'requeue')
        if (e.reason === 'aborted') c.held = true
      })
    } else if (e.agentId === undefined) {
      // The main turn ended with an answer while the review prompt was still on its way: a delivered prompt
      // keeps the turn going (its continuation's stop marks it arrived first), so this one never arrived.
      let lost = false
      await updateCycle($, c => {
        if (!c.reviewing || !c.promptPending) return
        lost = true
        endReview(c, 'requeue')
      })
      if (lost) say($, 'review-guard: the review prompt did not reach Claude (the turn ended another way), so its files are queued again')
    }
    return next(e)
  }).catch(($, e, next) => {
    // Only keeps flags: a failure must never change how a turn ends, but lost files are said.
    if (!next.called) {
      hookFailed($, 'could not record that this turn ended early', next.error,
        "if a review was running, its files may not come back to the queue, so ask for a review by hand")
    }
    return next(e)
  })

  // During a review, who is other work follows the engine's own events: an agent started or started again
  // (`agent.spawn`, with the loop that did it), and a message one loop sends to an agent of this session
  // (`session.send`, with the sender). A refused start or an undelivered message changes nothing. Review
  // or not, `agent.spawn` also records the agents that work in a folder of their own (`ownFolder`).
  on('agent.spawn', async ($, e, next) => {
    // Counted before the start, as the agent may show in the list while it happens, and under way until it
    // settles, so a check that reads the list in between keeps the review open.
    const reviewsBefore = reviewsStarted
    await ensureLoaded($) // after a reload, to know who is other work
    const counted = e.workflow === undefined && !(e.parentAgentId !== undefined && cycle.othersAtStart.includes(e.parentAgentId))
    const token = ++startTokens
    let result: Awaited<ReturnType<typeof next>>
    try {
      if (counted) {
        // Under way from now, on the machine's clock; the engine's time follows without holding the start up.
        const began: Began = { machine: Date.now() }
        startsUnderWay.set(token, began)
        void engineNow($).then(at => { if (at !== undefined) began.engine = at }, () => undefined)
      }
      result = await next(e)
    } finally {
      startsUnderWay.delete(token)
      stuckSaid.delete(token)
      stuckEndSaid.delete(token)
    }
    if (result.deny === undefined && counted) agentStarts++
    // For a resume, `next` settles with the id the run continues under.
    const id = result.deny === undefined ? (result.agentId ?? e.resume?.agentId) : undefined
    try {
      if (id) await handOn($, e.parentAgentId, id, reviewsStarted !== reviewsBefore, e.resume === undefined)
    } catch (err) {
      hookFailed($, 'could not record an agent started during the review', err,
        'its work may be counted on the wrong side of the review')
    }
    try {
      await ensureLoaded($) // a read that failed before the start is tried again: the saved list is needed
      // In a folder of its own, review or not: started (or started again) with one, started by an agent on
      // the list (by the engine, no `cwd` is the parent's folder; for an agent there after a `cd` this is
      // only careful), resumed from one on the list, or started before the saved list could be read.
      const listed = (x: string | undefined) => x !== undefined && cycle.ownFolder.includes(x)
      const own = typeof (e as { cwd?: unknown }).cwd === 'string' || listed(e.parentAgentId) || listed(e.resume?.agentId)
        || (!readBack && e.parentAgentId !== undefined)
      if (id && own) await inOwnFolder($, id)
    } catch (err) {
      hookFailed($, 'could not record a started agent', err, "its relative paths may be read against the session's folder")
    }
    return result
  }).catch(($, e, next) => {
    // Only this hook running out of time is said: a start that failed beneath is not this mod's to report.
    if (next.called && next.error.kind === 'timeout') {
      hookFailed($, 'ran out of time recording an agent start', next.error, 'if a review is running, that agent may be counted on the wrong side of it')
    }
    return next(e)
  })

  on('session.send', async ($, e, next) => {
    const result = await next(e)
    try {
      if ((result as { isDelivered?: unknown }).isDelivered === true) {
        await ensureLoaded($)
        if (cycle.reviewing) {
          // Settled here, at the send, with the recipient looked up by the names a message may use.
          let list: unknown
          try {
            list = await $.agent.list()
            if (!Array.isArray(list)) throw new Error('the agent list was not a list')
          } catch (err) {
            hookFailed($, "could not list the session's agents to record a message during the review", err,
              'its work may be counted on the wrong side of the review')
            list = undefined
          }
          // Without a list, only a recipient given by its id can be recorded: use what `to` says as it is.
          const id = recipient(e.to, Array.isArray(list) ? list : typeof e.to === 'string' ? [{ id: e.to.trim() }] : [])
          if (id !== undefined) await handOn($, e.agentId, id)
        }
      }
    } catch (err) {
      hookFailed($, 'could not record a message to an agent during the review', err,
        'its work may be counted on the wrong side of the review')
    }
    return result
  }).catch(($, e, next) => {
    // Only this hook running out of time is said: a message that failed beneath is not this mod's to report.
    if (next.called && next.error.kind === 'timeout') {
      hookFailed($, 'ran out of time recording a message to an agent', next.error, 'if a review is running, that agent may be counted on the wrong side of it')
    }
    return next(e)
  })

  // --- 2. at the end of the turn, send Claude back to review it ------------------------------

  on('classic.Stop', async ($, e, next) => {
    // A Stop hook continuation is proof the review prompt reached Claude: noted first, before anything
    // that could end this hook early.
    if (e.stop_hook_active) {
      try {
        await ensureLoaded($)
        if (cycle.promptPending) await updateCycle($, c => { c.promptPending = false })
      } catch (err) {
        hookFailed($, 'could not note that the review prompt arrived', err, 'the review may be asked for again')
      }
    }
    const settled = await next(e)
    // A hook beneath blocks, or stops the session: no review prompt could be delivered now. One still
    // waiting from an earlier stop never arrived (this stop is not its continuation): its files go back.
    if (settled.block || settled.preventContinuation) {
      if (!e.stop_hook_active) {
        try {
          let lost = false
          await updateCycle($, c => {
            if (c.reviewing && c.promptPending) {
              lost = true
              endReview(c, 'requeue')
            }
          })
          if (lost) say($, 'review-guard: the review prompt did not reach Claude (the turn ended another way), so its files are queued again')
        } catch (err) {
          reviewFailed($, err)
        }
      }
      return settled
    }
    // review-guard's own part. A failure in it lets the turn end as it would have, but never quietly; a
    // failure beneath, in the end of the turn itself, is not this mod's to report.
    try {
      const ask = await stopAsk($, e.stop_hook_active, next.signal)
      if (ask?.kind === 'held') {
        // The status line says so, so the queue is never silent.
        say($, `review-guard: review of ${ask.files} changed file(s) held after your interrupt; it runs when work on code resumes`)
        return settled
      }
      return ask === undefined ? settled : { ...settled, block: ask.prompt }
    } catch (err) {
      reviewFailed($, err)
      return settled
    }
  }).catch(($, e, next) => {
    // This hook's own failure, or its running out of time, is said; the files stay queued (or come back at
    // the next stop). A failure beneath, in the end of the turn itself, is not this mod's to report.
    if (!next.called || next.error.kind === 'timeout') reviewFailed($, next.error)
    return next(e)
  })


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
        say($, said)
      }
      return rememberShellWrites($, await next(e), e.command, before, powershell, said, e.agentId)
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
    if (!toGitHub && !gh) return rememberShellWrites($, await next(e), e.command, before, powershell, undefined, e.agentId)
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
    say($, said)
    return rememberShellWrites($, await next(e), e.command, before, powershell, said, e.agentId)
  }).catch(($, e, next) =>
    next.called ? next(e) : {
      deny: `review-guard could not check this command, so it stopped it (${whyOf(next.error)}). If the command names ` +
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
    if (notes.length > 0) say($, `review-guard: GitHub write checked, but ${notes.join('; ')}`)
    return next(e)
  }).catch(($, e, next) =>
    next.called ? next(e) : { deny: `review-guard could not check this GitHub write, so it stopped it (${whyOf(next.error)}).` },
  )

  // The allowlist is the user's to edit, not Claude's.
  on('tool.call', { tool: ['Edit', 'Write'] }, ($, e, next) =>
    /(^|[\\/])\.claude[\\/]review-guard\.json$/i.test(e.file_path)
      ? { deny: 'review-guard: ~/.claude/review-guard.json is the user\'s to edit. Tell them what to change instead.' }
      : next(e),
  ).catch(($, e, next) => (next.called ? next(e) : {
    deny: `review-guard: its guard for review-guard.json failed (${whyOf(next.error)}), so it stopped this edit. Tell the user.`,
  }))
}
