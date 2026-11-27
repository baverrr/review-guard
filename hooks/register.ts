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
  startFolder,
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
  type FileKey,
  nativePath,
  nativeSpelling,
  type NotFileKey,
  rulesFor,
  windowsSpelling,
  type Spelling,
  type Writer,
} from './scan.ts'
import { scannerSteps } from './scanners.ts'
import { type ChurnRule, type Config, findingsFor, findScanners, githubRemotes, gitleaksScan, homeFrom, type Host, loadConfig } from './outgoing.ts'
import { churned, churnNote, historyDir, historyFileName, historyFrom, withReview } from './churn.ts'
import { type LeftOut, type StatusFile, statusDir, statusFileName } from './status.ts'
import {
  changedBetween,
  committedFiles,
  committedWrites,
  compareWithGuess,
  COMPARE_TEXT_UP_TO as SHADOW_TEXT_UP_TO,
  type FileStat as RepoFileStat,
  gitSubcommands,
  headMove,
  ignoredOf,
  isFullPath,
  lookAll,
  MAX_ENTRIES as SHADOW_MAX_ENTRIES,
  normalPath,
  relativeTo,
  repoFor,
  underRoot,
  repoOf,
  type Snapshot as RepoSnapshot,
  snapshot,
} from './worktree.ts'

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
//    server's review_status tool, and each project's recent reviews to ~/.claude/review-guard/history/
//    (churn.ts): files that keep coming back for review get a note in the review prompt.
//
// The person's own details live in ~/.claude/review-guard.json (read by loadConfig in outgoing.ts),
// never in this code:
//   { "personal": ["name", "email", ...], "allowNetworkInfo": ["owner/repo"], "allowValues": [],
//     "churn": { "reviews": 4, "hours": 24 } }

// The review cycle. The module keeps it in memory, where changes cannot clash (the module runs one
// thing at a time), and copies each change to the session's state, which outlives a reload: the
// engine reloads the module whenever its files change, and a reload in the middle of a review used
// to forget the review was running, so its own fixes were reviewed again. After a reload the first
// hook reads the copy back. A failed copy loses nothing now; it only risks that after a reload.
const CYCLE = { plugin: 'review-guard', key: 'cycle' } as const
const EMPTY: Cycle = { reviewing: false, held: false, changed: {}, underReview: {}, othersAtStart: [], othersChanged: {}, joined: [], promptPending: false }

const OWN_FOLDER_KEPT = 500 // agents remembered in `ownFolder`: the 500 marked last

/** The strings in a stored list; anything else (or no list) gives none. */
function texts(x: unknown): string[] {
  return Array.isArray(x) ? x.filter((y): y is string => typeof y === 'string') : []
}

/** `ownFolder` as kept: each agent once, at its last place, and only the last `OWN_FOLDER_KEPT`. */
export function ownFolderOf(ids: readonly string[]): readonly string[] {
  const last = [...new Set([...ids].reverse())].reverse()
  return last.slice(-OWN_FOLDER_KEPT)
}

let cycle: Cycle = copyOf(EMPTY)
// The agents whose relative paths are not read against the session's folder (see `SavedState` in
// types). Saved with the cycle but kept apart from it, as the list lasts across reviews. Only ever
// replaced through `ownFolderOf`, never changed in place.
let ownFolder: readonly string[] = []
// Some agent may be missing from `ownFolder` (a saved list that was damaged or at its cap): then no
// agent's relative paths are read against the session's folder, which can only mean more review.
let ownFolderDoubtful = false
let loaded: Promise<void> | undefined // reading the copy back, once per load of the module
let saving: Promise<void> = Promise.resolve() // the copies, written one after another

/**
 * The saved list of agents in a folder of their own: what is not text is dropped, then each agent once
 * and only the last `OWN_FOLDER_KEPT` (`ownFolderOf`). `damaged`: something was dropped or it was not a
 * list. `full`: it was at its cap, so older agents may be missing. `cut`: it was over the cap, and was cut.
 * `doubtful`: an earlier load already found it damaged or cut (saved with it).
 */
function readOwnFolder(value: unknown): { ids: readonly string[]; damaged: boolean; full: boolean; cut: boolean; doubtful: boolean } {
  const object = typeof value === 'object' && value !== null ? (value as { ownFolder?: unknown; ownFolderDoubtful?: unknown }) : undefined
  const saved = object?.ownFolder
  const ids = ownFolderOf(texts(saved))
  const damaged = saved !== undefined && (!Array.isArray(saved) || saved.some(x => typeof x !== 'string'))
  const unique = new Set(texts(saved)).size
  return { ids, damaged, full: unique >= OWN_FOLDER_KEPT, cut: unique > OWN_FOLDER_KEPT, doubtful: object?.ownFolderDoubtful === true }
}

/** The saved list of agents in a folder of their own (see `readOwnFolder`). */
export function ownFolderFrom(value: unknown): readonly string[] {
  return readOwnFolder(value).ids
}

/**
 * Whether a saved copy was damaged: not an object, or a field of the wrong kind, or an entry that is not
 * text. What `cycleFrom` drops is said, as a dropped file or agent can mean less review.
 */
export function savedDamaged(value: unknown): boolean {
  if (value === undefined || value === null) return false // nothing saved yet
  if (typeof value !== 'object' || Array.isArray(value)) return true
  const v = value as Record<string, unknown>
  const isMap = (x: unknown) => typeof x === 'object' && x !== null && !Array.isArray(x) && Object.values(x).every(y => typeof y === 'string')
  const isList = (x: unknown) => Array.isArray(x) && x.every(y => typeof y === 'string')
  if (['changed', 'underReview', 'othersChanged'].some(k => v[k] !== undefined && !isMap(v[k]))) return true
  if (['othersAtStart', 'joined'].some(k => v[k] !== undefined && !isList(v[k]))) return true
  return ['reviewing', 'held', 'promptPending'].some(k => v[k] !== undefined && typeof v[k] !== 'boolean')
}

function copyOf(c: Cycle): Cycle {
  return { reviewing: c.reviewing, held: c.held, changed: { ...c.changed }, underReview: { ...c.underReview }, othersAtStart: [...c.othersAtStart], othersChanged: { ...c.othersChanged }, joined: [...c.joined], promptPending: c.promptPending }
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
  }
  // Put right what a stored copy may hold wrongly (written by hand, damaged, or by another version).
  if (!c.reviewing) {
    // No review is running: nothing review-only stands, and no file it held is lost.
    c.changed = joinFiles(c.underReview, c.othersChanged, c.changed)
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
  // How paths read here first (`pathsHere` never rejects): the read joins lists, which needs `keySpelling`.
  loaded ??= pathsHere($).then(() => $.state.get(CYCLE)).then(
    ({ value }) => {
      const stored = cycleFrom(value)
      cycle = changedUnread
        ? { ...cycle, changed: joinFiles(stored.underReview, stored.othersChanged, stored.changed, cycle.changed), underReview: { ...cycle.underReview } }
        : stored
      // Marks are never taken back (only the oldest past the cap drop off), so both lists are joined: an
      // agent marked before the reload stays marked, and so does one marked meanwhile (a mark alone is no
      // change to the cycle, so a saved review stands).
      const savedList = readOwnFolder(value)
      const both = [...savedList.ids, ...ownFolder]
      const marksMeanwhile = ownFolder.some(id => !savedList.ids.includes(id))
      ownFolder = ownFolderOf(both)
      const cutNow = savedList.cut || new Set(both).size > ownFolder.length
      readBack = true
      if (savedList.damaged) logLine($, "review-guard: its saved list of agents in a folder of their own was damaged, so no agent's relative paths are read against the session's folder for now")
      if (savedList.damaged || savedList.full || savedList.doubtful || cutNow) ownFolderDoubtful = true
      if (cutNow) ownFolderCut($)
      const damaged = savedDamaged(value)
      if (readFailSaid) {
        readFailSaid = false
        // Not after a damaged copy: then something may well have been lost (said just below).
        if (!damaged) say($, 'review-guard: read back its review state after all; nothing waiting for review was lost')
      }
      if (damaged) say($, 'review-guard: its saved review state was damaged, so files it was holding for review may be lost; ask for a review by hand if in doubt')
      // What this load decided or marked before the read is saved now, so a second reload keeps it. The
      // hook that read it waits for this save (it never rejects), so the next one sees it done. Marks alone
      // fail to the log, as `inOwnFolder`'s do.
      if (changedUnread) return save($)
      return marksMeanwhile ? save($, "if the mod reloads now, agents marked before the read may have their relative paths read against the session's folder") : undefined
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

/**
 * Copies the cycle (and `ownFolder`) as they stand when the write runs, after any earlier write. A failure
 * is said on the status line; with `quietWhy` it goes to the log instead, with that risk named, for a save
 * that may follow a guard notice on the status line. Never rejects.
 */
function save($: EngineInterface, quietWhy?: string): Promise<void> {
  if (!readBack) return saving
  const own = { ownFolder: [...ownFolder], ...(ownFolderDoubtful ? { ownFolderDoubtful: true as const } : {}) }
  saving = saving.then(() => $.state.set(CYCLE, { ...copyOf(cycle), ...own })).then(
    () => undefined,
    err => {
      if (quietWhy !== undefined) logLine($, `review-guard: could not save its review state (${whyOf(err)}); ${quietWhy}`)
      else say($, `review-guard: could not save its review state (${whyOf(err)}); if the mod reloads now, a running review may be asked for again`)
    },
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
        logLine($, `review-guard: could not update its status file, so review_status may be behind (${statusFailed})`)
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
 * notice that must stay seen. `$.ui.log` returns nothing: a line the engine can't log is dropped and
 * reported by the engine itself (the test kit shows it as "$.ui.log dropped"), so the mod never sees it
 * fail. A throw, or a promise that fails should a later engine return one, is caught all the same.
 */
export function logLine($: EngineInterface, text: string): void {
  try {
    const logged: unknown = $.ui.log(text)
    if (typeof (logged as { then?: unknown } | undefined)?.then === 'function') (logged as PromiseLike<unknown>).then(undefined, () => undefined)
  } catch { /* the engine reports a line it could not log */ }
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
      logLine($, `review-guard: could not read ${name} (${whyOf(err)}), so how paths are spelled here, and the home folder (status files, review-guard.json), may be misread`)
    }
    return undefined
  }
}

/** How paths are spelled here (see `isWindows`). A variable that can't be read is logged once. */
async function pathsHere($: EngineInterface): Promise<Paths> {
  const userProfile = await envValue($, 'USERPROFILE', () => $.env.get('USERPROFILE'))
  const home = await envValue($, 'HOME', () => $.env.get('HOME'))
  const os = await envValue($, 'OS', () => $.env.get('OS'))
  const systemRoot = await envValue($, 'SystemRoot', () => $.env.get('SystemRoot'))
  const windows = isWindows({ os, systemRoot, userProfile, home })
  keySpelling = nativeSpelling(windows)
  // The temp folders a command may start a path with (`Paths.vars`): a value that can't be read is left out.
  const vars: Record<string, string> = {}
  for (const [name, read] of [
    ['TEMP', () => $.env.get('TEMP')], ['TMP', () => $.env.get('TMP')], ['TMPDIR', () => $.env.get('TMPDIR')], ['LOCALAPPDATA', () => $.env.get('LOCALAPPDATA')],
  ] as const) {
    const value = await safely(read)
    // On Windows with forward slashes; elsewhere a `\` is part of a name.
    if (value !== undefined && value.trim() !== '') vars[name] = windows ? value.trim().replace(/\\/g, '/').replace(/\/+$/, '') : value.trim()
  }
  return { windows, home, userProfile, vars }
}

/** The environment values `isWindows` decides by. */
export type EnvFacts = { os?: string; systemRoot?: string; userProfile?: string; home?: string }

/**
 * Whether these environment values are Windows'. OS is `Windows_NT` on Windows, always, so that decides
 * first. Without it, HOME: one that starts with `/` is Unix's (Linux or WSL, which may have USERPROFILE
 * or SystemRoot passed in from Windows), unless it is Git Bash's spelling of a folder on the drive that
 * USERPROFILE or SystemRoot names (`/c/Users/pat`, `/c/Users/pat/home`; not `/u/pat` or `/home/pat`).
 * Any other HOME (missing, or not starting with `/`): Windows when USERPROFILE or SystemRoot names a drive.
 */
export function isWindows(env: EnvFacts): boolean {
  if (env.os === 'Windows_NT') return true
  const driveOf = (x: string | undefined) => /^([a-zA-Z]):[\\/]/.exec((x ?? '').trim())?.[1]?.toLowerCase()
  const drives = [driveOf(env.userProfile), driveOf(env.systemRoot)].filter((d): d is string => d !== undefined)
  const home = (env.home ?? '').trim()
  if (home.startsWith('/')) {
    const homeDrive = /^\/([a-zA-Z])(?:\/|$)/.exec(home)?.[1]?.toLowerCase()
    return homeDrive !== undefined && drives.includes(homeDrive)
  }
  return drives.length > 0
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
async function sayLeftOut($: EngineInterface, scratch: string[], onlyRun: string[], said?: string, inScript: string[] = []): Promise<void> {
  const parts = [
    ...(scratch.length ? [`scratch ${scratch.map(p => p.replace(/^.*[\\/]/, '')).join(', ')}`] : []),
    ...(onlyRun.length ? [`only run ${onlyRun.join(', ')}`] : []),
    // A script can name many files: the first five, then how many more (all of them go in the status file).
    ...(inScript.length ? [`with a scratch script ${inScript.slice(0, 5).join(', ')}${inScript.length > 5 ? ` and ${inScript.length - 5} more` : ''}`] : []),
  ]
  if (parts.length === 0) return
  // After a line the guard just put there (a security notice), so that line is never hidden.
  say($, said ? `${said}. Not reviewed: ${parts.join('; ')}` : `review-guard: not reviewed (${parts.join('; ')})`)
  const at = new Date().toISOString()
  leftOut.push(...scratch.map((path): LeftOut => ({ path, why: 'scratch', at })), ...onlyRun.map((path): LeftOut => ({ path, why: 'only run', at })), ...inScript.map((path): LeftOut => ({ path, why: 'scratch script', at })))
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
 * A path spelled so that two spellings of one file compare equal, read by `spelling` (see `Spelling`): on
 * Windows `/` for `\` and the drive letter's case ignored (elsewhere a `\` is part of a file name). Other
 * case counts everywhere: a Windows folder can be case-sensitive (made so, or by WSL), and there `A.py`
 * and `a.py` are two files, so treating them as one could hide one from review. `/c/...` as
 * `C:/...` in `windows-msys` only, a relative path (a shell command's own spelling, `sed -i x app.py`)
 * resolved against `folder` when one is given, and `.` and `..` steps taken. A stored key (through
 * `keyPath` only: see `FileKey`) or a native path (the session's folder, say) is read as `nativeSpelling`,
 * so its `/c/` is never taken for drive C.
 * Only a forward-slash `/c/` is a drive: `\c\...` is a folder `c` on the current drive, as Windows reads
 * it. The caller gives no folder when it can't be sure which one a relative path is from (a command that
 * changes folder, an agent in `ownFolder`, a session folder that
 * could not be read, or a review state not yet read back): then a relative path stays relative and can
 * only fail to match a full one, which means more review, never less.
 */
export function samePath<P extends string>(path: NotFileKey<P>, folder: string | undefined, spelling: Spelling): string {
  const windows = windowsSpelling(spelling)
  const raw: string = path
  let p = spelling === 'windows-msys' ? nativePath(raw) : raw
  if (windows) p = p.replace(/\\/g, '/')
  const absolute = (windows && /^[a-zA-Z]:(\/|$)/.test(p)) || p.startsWith('/')
  if (!absolute && folder) {
    const base = samePath(folder, undefined, nativeSpelling(windows)) // the session's folder is a native path
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
  return windows ? joined.replace(/^[A-Z](?=:)/, d => d.toLowerCase()) : joined // only the drive letter's case
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
  if (ownFolder.at(-1) === id) return
  const before = ownFolder.filter(x => x !== id).length + 1
  ownFolder = ownFolderOf([...ownFolder, id])
  if (before > ownFolder.length) {
    ownFolderDoubtful = true // the oldest dropped off: they may still be at work
    ownFolderCut($)
  }
  // Saved inside the cycle's record, though the cycle does not change: no status file to write, no
  // review decided. A failure goes to the log, as a guard notice may be on the status line.
  await save($, "if the mod reloads now, this agent's relative paths may be read against the session's folder")
}

/**
 * How a changed file is stored: as it was spelled, except that `/c/...` from a `windows-msys` tool (Git
 * Bash, an edit tool on Windows) is stored as `C:/...` (`nativePath`). A key still spelled `/c/...` then
 * came from PowerShell, where it is a folder `c` on the current drive, or from a copy saved before 0.3.8
 * (0.3.7 kept the edit tools' `/c/` as written; earlier versions Git Bash's too). Either way it never
 * matches a drive C path, which means more review, never less.
 */
export function keyOf<P extends string>(path: NotFileKey<P>, spelling: Spelling): FileKey {
  const raw: string = path
  return (spelling === 'windows-msys' ? nativePath(raw) : raw) as FileKey
}

// How stored keys read on this machine: `pathsHere` sets it, and `ensureLoaded` waits for that before it
// reads the saved state, so every join of lists reads keys this machine's way. (`posix` before then
// merges the fewest spellings: more review, never less.)
let keySpelling: Spelling = 'posix'

/** Whether a path has a `..` step, which through a link may lead to another file than its text says. */
function hasUpStep(x: string): boolean {
  return x.split(/[\\/]/).includes('..')
}

/**
 * Whether a path, as `samePath` spells it, is full: on Windows one with a drive (`/proj/x.py` is the
 * current drive's root in PowerShell but under Git's install folder in Git Bash, so it is not sure which
 * file it names), elsewhere one from `/`. Only a full path is compared with another spelling.
 */
function isFull(p: string, windows: boolean): boolean {
  return windows ? /^[a-z]:\//i.test(p) : p.startsWith('/')
}

/**
 * The keys of a list of changed files, as `FileKey`s (`joinFiles` casts the same way). Every list holds
 * only keys made by `keyOf`, or read back from a saved copy (see `keyOf` for old spellings).
 */
function keysOf(files: Record<string, string>): FileKey[] {
  return Object.keys(files) as FileKey[]
}

/** A stored key as `samePath` spells it, read as this machine reads native paths (`keySpelling`). */
function keyPath(k: FileKey): string {
  return samePath(k as string, undefined, keySpelling) // the one place a key is read as a path
}

/**
 * The same-file match for `k`: its spelling as `keyPath` gives it, when `k` is a full path with no `..`
 * step (a relative path's folder is not known, and through a link `a/../b.py` may be another file than
 * `b.py`; a `.` step is always the same file). Undefined otherwise: then only `k` itself is the same file.
 * Under `posix` a `\` is part of a name, so splitting on it only refuses more.
 */
function matchOf(k: FileKey): string | undefined {
  if (hasUpStep(k)) return undefined
  const p = keyPath(k)
  return isFull(p, windowsSpelling(keySpelling)) ? p : undefined
}

/**
 * Puts `k` into `files` with this language, under the key the same file already has there (`matchOf`:
 * slashes, the drive letter's case; a Git Bash `/c/` was already made `C:/` by `keyOf`). A known language
 * is never replaced by `other code`. Written as an own property, so even a file named `__proto__` is
 * kept in any JS runtime (in Node a plain assignment would set the prototype instead). `index`: the
 * matches already in `files`, kept up to date, so a join is not quadratic; it must have been built along
 * with `files` from empty (as `joinFiles` does), or it would miss keys already there.
 */
function addFile(files: Record<string, string>, k: FileKey, lang: string, index?: Map<string, FileKey>): void {
  const match = matchOf(k)
  let at: FileKey = k
  if (!Object.hasOwn(files, k) && match !== undefined) {
    at = (index ? index.get(match) : keysOf(files).find(x => matchOf(x) === match)) ?? k
  }
  const had = Object.hasOwn(files, at) ? files[at] : undefined
  const keep = had !== undefined && had !== 'other code' && lang === 'other code'
  Object.defineProperty(files, at, { value: keep ? had : lang, enumerable: true, writable: true, configurable: true })
  if (index && match !== undefined && !index.has(match)) index.set(match, at)
}

/**
 * Lists of changed files joined into one, each file once under its first spelling (see `addFile`). Keys
 * are read as `keySpelling`, which `ensureLoaded` makes sure of before any join.
 */
function joinFiles(...lists: Record<string, string>[]): Record<string, string> {
  const out: Record<string, string> = {}
  const index = new Map<string, FileKey>()
  for (const files of lists) for (const [k, lang] of Object.entries(files)) addFile(out, k as FileKey, lang, index)
  return out
}

/**
 * Code files were just changed: they wait for a review, and an interrupted task has picked up again.
 * Files in Claude's scratch folders (`inScratch`) are throwaway: they are left out, and an edit only to
 * them does not count as work picking up again. `writer`: the tool that named the paths, which decides how
 * they are read (`rulesFor`). `keepScratch`: keep them too (a copy or move may have taken them into the
 * project). A file already queued in the same list under another full spelling keeps that entry, so it
 * is listed once there (`addFile`); a file in two lists, `changed` and `othersChanged` during a review
 * say, is listed once when they are joined (`joinFiles`).
 * `agentId`: the agent that made the change, when not the main loop. During a review, an
 * agent that is other work (`othersAtStart`) has its files wait for a review of their own instead of
 * counting as the review's fixes, and so does one that joined the review (`joined`) for any file not
 * under review. Returns the scratch files left out.
 */
async function remember($: EngineInterface, changed: [string, string][], writer: Writer, keepScratch = false, agentId?: string, sameFolder = true): Promise<string[]> {
  if (changed.length === 0) return []
  // During a review: other work's edits wait for their own review, and so do an agent's that joined the
  // review, except to the files under review (those are its fixes). Paths are compared as `samePath`
  // spells them, so another spelling of a file under review still counts as that file.
  const { windows: onWindows } = await pathsHere($)
  const rules = rulesFor(writer, onWindows)
  // Relative paths are read against the session's folder only when that is surely where they are from:
  // not when the command changes folder (`sameFolder` false), nor for an agent in `ownFolder` (started in
  // a folder of its own, by such an agent, or after an earlier `cd`), nor before the saved state is read
  // back (the saved `ownFolder` is not known yet). Read only when a joined agent's edit needs it.
  await ensureLoaded($)
  const needed = agentId !== undefined && cycle.reviewing && cycle.joined.includes(agentId)
  const sure = needed && sameFolder && readBack && !ownFolderDoubtful && !ownFolder.includes(agentId)
  const folder = sure ? await sessionFolder($) : undefined
  // Only full paths can match: a relative one (a stored key, or a path that could not be resolved) never
  // does, as the folder it was relative to may not be the one seen now.
  // On Windows a path must have a drive: `/proj/x.py` is the current drive's root in PowerShell but under
  // Git's install folder in Git Bash, so it is not sure which file it names (from any tool).
  const full = (x: string) => isFull(x, onWindows)
  const path0 = (path: string) => samePath(path, folder, rules.spelling)
  // Not across a `..` step (in the path or the key): through a link it may be another file, which would
  // then be taken for the review's fix and dropped. On Windows `..` is taken by its text, but refusing it
  // there too only means more review.
  const underReview = (c: Cycle, path: string) => {
    if (hasUpStep(path)) return false
    const p = path0(path)
    return full(p) && keysOf(c.underReview).some(k => !hasUpStep(k) && keyPath(k) === p)
  }
  // Into `map` under its stored key (`keyOf`), or the key the same file already has there (`addFile`).
  const put = (map: Record<string, string>, path: string, lang: string) => addFile(map, keyOf(path, rules.spelling), lang)
  const queueFor = (c: Cycle, path: string) =>
    c.reviewing && agentId !== undefined && (c.othersAtStart.includes(agentId) || (c.joined.includes(agentId) && !underReview(c, path)))
      ? c.othersChanged
      : c.changed
  if (keepScratch) {
    await updateCycle($, c => {
      for (const [path, lang] of changed) put(queueFor(c, path), path, lang)
      c.held = false
    })
    return []
  }
  const temp = await tempDirs($)
  const scratch = changed.filter(([path]) => inScratch(path, temp, rules)).map(([path]) => path)
  const files = changed.filter(([path]) => !scratch.includes(path))
  if (files.length === 0) return scratch
  await updateCycle($, c => {
    for (const [path, lang] of files) put(queueFor(c, path), path, lang)
    c.held = false
  })
  return scratch
}

/** What the end of a turn asks for: a review, a word that one is held, or nothing. */
type StopAsk = { kind: 'review'; prompt: string; files: string[] } | { kind: 'held'; files: number } | undefined

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

/**
 * The home folder (`homeFrom`: USERPROFILE first on Windows, HOME first elsewhere), or undefined. Never
 * throws; a variable that can't be read is logged once (`pathsHere`).
 */
async function homeDir($: EngineInterface): Promise<string | undefined> {
  return homeFrom(await pathsHere($))
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

/** `shellWrites(command, scratchFile)`, or `all` (every write, nothing blanked) if that throws; a throw is logged. */
export function blankedSafely($: EngineInterface, command: string, scratchFile: (target: string) => boolean, all: string[]): string[] {
  try {
    return shellWrites(command, scratchFile)
  } catch (err) {
    logLine($, `review-guard: a scratch script's text was kept in the review: it could not be read (${whyOf(err)})`)
    return all
  }
}

/**
 * For `shellWrites` in Bash: whether a redirect target, as the command spells it after its leading
 * variables are filled in, is a file in Claude's scratch folders (`inScratch`). Only a full path with no
 * variable, `~` or backtick left counts: where a relative name or `$TEMP` leads in the shell that ran it
 * (a failed `cd`, a profile that sets TEMP) is not known here.
 */
async function scratchTargets($: EngineInterface): Promise<(target: string) => boolean> {
  const { windows } = await pathsHere($)
  const rules = rulesFor('bash', windows)
  const temp = await tempDirs($)
  return target => !/[$`~]/.test(target) && /^(?:[A-Za-z]:)?[\\/]/.test(target) && inScratch(target, temp, rules)
}

/**
 * Before a shell command runs: the folder it starts in, when it surely does, and whether that is Claude's
 * scratch folder. That is a command whose first part is `cd` into a full folder (`cd "C:/repo" && ... >
 * a.py`, `cd "$LOCALAPPDATA/Temp/claude/.../scratchpad" && ... > body.html`, `startFolder`), where that
 * folder is already there and can be entered (so the cd can't fail and leave a later write in the folder
 * the shell was in, even after a `;`, and the command can't make it first), the cd's word is one the shell expands as
 * `startFolder` reads it (no `$` or `~` in single quotes, no `~` in double quotes), and nothing after it
 * changes folder in any way `CHANGES_FOLDER` knows (`os.chdir`, `git -C`, `--cwd`, another cd). `scratch`
 * is whether the folder is Claude's scratch folder both as written and with every link followed.
 * Undefined otherwise, for a command run in the background, or on any failure: then every name stays as
 * written. Never throws.
 */
let startDirFailSaid = false // a start-folder check that threw is logged once per load of the module

/** The folder a shell command surely starts in (`startDir`), whether it is scratch, and how its paths read. */
type Start = { base: string; scratch: boolean; windows: boolean }

async function startDir($: EngineInterface, command: string, powershell: boolean, background: boolean): Promise<Start | undefined> {
  if (background) return undefined
  // .NET calls in PowerShell (`[IO.File]::WriteAllText('a.py', ...)`) read a relative name against the
  // process's own folder, which a Set-Location does not move: such a name is not in the start folder.
  if (powershell && /\[(?:System\.)?IO\.|WriteAll(?:Text|Lines|Bytes)|Environment\]::CurrentDirectory/i.test(command)) return undefined
  try {
    const paths = await pathsHere($)
    const base = startFolder(command, paths, powershell)
    if (base === undefined) return undefined
    const cd = /^\s*(?:cd|chdir|Set-Location|sl)\s+("[^"]*"|'[^']*'|[^\s;&|]+)/i.exec(command)
    const word = cd?.[1] ?? ''
    if (!cd || (word.startsWith("'") && /[$~]/.test(word)) || (word.startsWith('"') && word.includes('~'))) return undefined
    // An unquoted variable holding a space or a wildcard is split or globbed, and the cd may fail.
    if (!word.startsWith('"') && word.includes('$') && /[\s*?[]/.test(base)) return undefined
    const rest = command.slice(cd[0].length)
    // A cd piped on (`cd X | ...`, `cd X || ...`) moves only a subshell, or runs what follows when it fails.
    if (/^\s*\|/.test(rest) || CHANGES_FOLDER.test(rest)) return undefined
    // Programs that write into a folder they are given (`patch -d`, `unzip -d`), a program named by a
    // variable (`$c$d /c/proj` is a cd), or a bare folder run as a cd (`shopt -s autocd`).
    if (/\b(?:patch|unzip)\b[^;&|\n]*\s-d/.test(rest) || /(?:^|[;&|\n({]\s*)["']?\$/.test(rest) || /\bautocd\b/.test(rest)) return undefined
    // The folder, and where it really is (every link followed), must both be Claude's scratch folder; the
    // temp folders count as they are written and as they really are (macOS's /var is /private/var).
    const temp = await tempDirs($)
    const real = async (p: string) => (await Promise.resolve().then(() => $.fs.stat(p, { resolve: true })).catch(() => undefined))
    const roots = [...temp, ...(await Promise.all(temp.map(async t => (await real(t))?.realPath))).filter((r): r is string => r !== undefined)]
    const rules = rulesFor(powershell ? 'powershell' : 'bash', paths.windows)
    const stat = await real(base)
    if (stat?.kind !== 'dir' || stat.realPath === undefined) return undefined
    // A folder the cd can't enter (no right to pass through it, which listing does not need on Linux):
    // then a write after a `;` or a new line would land in the folder the shell was in. Reaching `base/.`
    // needs that right, and reads no entries.
    if (!(await Promise.resolve().then(() => $.fs.stat(`${base}/.`)).then(() => true, () => false))) return undefined
    // Scratch as written and as it really is, or neither: a folder spelled as scratch that leads out of it
    // (or one whose real place can't be told apart) places nothing, so its writes are never dropped as scratch.
    const asWritten = inScratch(`${base}/x`, roots, rules)
    if (asWritten !== inScratch(`${stat.realPath.replace(/\\/g, '/')}/x`, roots, rules)) return undefined
    return { base, scratch: asWritten, windows: paths.windows }
  } catch (err) {
    if (!startDirFailSaid) {
      startDirFailSaid = true
      logLine($, `review-guard: could not tell which folder a command starts in (${whyOf(err)}), so its files are reviewed under the names it wrote`)
    }
    return undefined
  }
}

/**
 * The names a command wrote, its relative ones placed in the folder it starts in (`startDir`), so the
 * review and the project's history name the file there, not one in the session's folder. In the scratch
 * folder a bare file name (`body.html`, `./notes.py`) goes in `names`, so `remember` leaves it out as
 * scratch and says so; one with a folder in it may go through a link out of the scratch folder
 * (`link/a.py`), so it goes in `keep`, to be reviewed. Outside scratch a name with folders (`hooks/a.ts`)
 * is placed too, and goes in `keep` like every name placed there, so it is never left out as scratch. Never a
 * name with a `:` (`D:a.ts` is in D's own current folder, `FileSystem::D:/x`), a `.` or `..` step after a
 * leading `./` (through a link `..` may be elsewhere), a `~` or `$` (not filled in here), or off Windows a
 * `\`; those, and full names, stay as written.
 */
function placeInStart(names: string[], start: Start | undefined): { names: string[]; keep: string[] } {
  if (start === undefined) return { names, keep: [] }
  // A `\` divides folders only on Windows; elsewhere it is part of a file name, and such a name stays as written.
  const sep = start.windows ? /[\\/]/ : /\//
  const bare = (p: string) => /^[^\\/:~$]+$/.test(p) && p !== '..' && p !== '.'
  const relative = (p: string) =>
    /^[^\\/:~$][^:~$]*$/.test(p) && (start.windows || !p.includes('\\')) && !p.split(sep).some(part => part === '..' || part === '.' || part === '')
  const lead = start.windows ? /^(?:\.[\\/])+/ : /^(?:\.\/)+/
  const placed: string[] = []
  const keep: string[] = []
  for (const p of names) {
    const name = p.replace(lead, '')
    const full = `${start.base}/${start.windows ? name.replace(/\\/g, '/') : name}`
    if (start.scratch && bare(name)) placed.push(full)
    // In scratch, a name with folders may go through a link out of it (`link/a.py`): it is reviewed, under
    // its name in the scratch folder, never left out as scratch.
    // Outside scratch a placed name is kept too: through a folder of its own it may be spelled as scratch
    // (`cd /tmp && ... claude/x/a.py`), and it is still the command's own write, to be reviewed.
    else if (relative(name)) keep.push(full)
    else placed.push(p)
  }
  return { names: placed, keep }
}


// --- The shadow look (0.5.0): what git says a shell command changed, next to the text guess -------------
//
// Since 0.5.1 the repositories are looked at side by side, and each record says where its time went (`Step`).
// For a command whose writes the guess can't be sure of (`unsure`), `shadowBefore` takes `git status` of the
// repositories it may touch, and `shadowAfter` takes it again once the command is done, compares the two
// (worktree.ts), and records how that compares with the guess in ~/.claude/review-guard/shadow.jsonl. The
// review still uses the guess: this changes nothing that is reviewed. Once the record shows the look agrees
// apart from the guess's known misses, it replaces the guess inside repositories (docs/shell-writes-redesign.md).

/**
 * The repositories a command may touch, as they were just before it ran, and what else was writing then:
 * `running`, the other edits and shell commands under way; `done`, how many had finished (`asWriter`). And
 * the before look's steps (all finished), with how many were not kept (`MAX_STEPS`).
 */
type Shadow = { snaps: RepoSnapshot[]; failed: { folder: string; why: string }[]; running: number; done: number; runsOthers: boolean; steps: Step[]; dropped: number }

// Edits and shell commands under way, and finished, in this session (`asWriter`): a file another one wrote
// while a command ran shows in git as that command's, so the record says when that may have happened.
let writersRunning = 0
let writersDone = 0
// When this session last left a shell command running past its call (in the background, timed out): it may
// still be writing, so a look in the next half hour says others may be writing.
let backgroundAt = 0
const BACKGROUND_WRITES_MS = 30 * 60_000
async function asWriter<T>(f: () => Promise<T>): Promise<T> {
  writersRunning++
  try {
    return await f()
  } finally {
    writersRunning--
    writersDone++
  }
}

// Programs that write files the command's text never names: formatters and fixers, and task runners where
// they start a command (a `make` in a message is not one).
const WRITING_TOOLS = /\b(?:prettier|black|ruff|eslint|biome|gofmt|rustfmt|autopep8|isort|yapf|clang-format|dprint)\b|\b(?:npm|pnpm|yarn|bun)\s+(?:run|exec|x)\b|\b(?:npx|bunx)\b|(?:^|[;&|\n(]\s*)(?:make|just|task)\b|\bcargo\s+(?:fmt|fix|clippy)\b|\bgo\s+(?:fmt|generate|mod)\b/i

/** Whether the guess can't be sure what a command wrote: it changes folder, runs a script or a writing tool, commits, or (PowerShell) calls .NET. */
function unsure(command: string, powershell: boolean, runScripts: readonly Snapshot[]): boolean {
  return CHANGES_FOLDER.test(command) || runScripts.length > 0 || WRITING_TOOLS.test(command) || gitSubcommands(command).includes('commit') ||
    (powershell && /\[(?:System\.)?IO\.|WriteAll(?:Text|Lines|Bytes)/i.test(command))
}

// A folder's repository root, kept for a while: each look costs a run of git. A folder in none is kept for
// less, so a `git init` there is soon seen.
const REPO_CACHE_MS = 5 * 60_000
const NO_REPO_CACHE_MS = 30_000
// A lookup that failed (git missing or too slow) is kept as long as "no repository", and fails again from
// the cache: each command records it, but doesn't wait on git again for it.
const repoCache = new Map<string, { root: string | undefined; at: number; error?: unknown }>()

async function cachedRepo(host: Host, folder: string, windows: boolean): Promise<string | undefined> {
  const key = normalPath(folder, windows)
  const hit = repoCache.get(key)
  if (hit && Date.now() - hit.at < (hit.root === undefined ? NO_REPO_CACHE_MS : REPO_CACHE_MS)) {
    // Said as cached, so the record doesn't count one failure as many.
    if (hit.error !== undefined) throw new Error(`${whyOf(hit.error)} (cached from an earlier look)`)
    return hit.root
  }
  if (repoCache.size > 200) repoCache.clear()
  try {
    const root = await repoOf(host, folder)
    repoCache.set(key, { root, at: Date.now() })
    return root
  } catch (err) {
    repoCache.set(key, { root: undefined, at: Date.now(), error: err })
    throw err
  }
}

// What went wrong with the shadow look, each kind of trouble logged once per load of the module (it is
// recorded each time): a look that failed, and a record that could not be written, apart.
const shadowSaid = new Set<string>()
function sayShadowOnce($: EngineInterface, kind: string, text: string): void {
  if (shadowSaid.has(kind) || shadowSaid.size >= 100) return
  shadowSaid.add(kind)
  logLine($, text)
}

/** A failure's reason without what changes from run to run (counts, folders, quoted text), to log each kind once. */
function reasonKind(why: string): string {
  return why.replace(/"[^"]*"|'[^']*'|[A-Za-z]:[\\/]\S*|\/\S+|\d+/g, '#').slice(0, 80)
}

// The record keeps its last lines up to this many characters (at most 3 MiB as UTF-8): under the engine's
// read limit (4 MiB), so it can always be read back and added to. Each line names at most `SHADOW_PATHS` paths per list, with the count.
const SHADOW_KEEP_BYTES = 1024 * 1024
const SHADOW_PATHS = 50

/** Up to `SHADOW_PATHS` of `paths`, and how many there were. */
const listed = (paths: string[]) => ({ count: paths.length, paths: paths.slice(0, SHADOW_PATHS) })

/** Adds one line to the shadow record, keeping its last `SHADOW_KEEP_BYTES` characters. Never throws. */
async function recordShadow($: EngineInterface, entry: Record<string, unknown>): Promise<void> {
  try {
    const home = await homeDir($)
    if (home === undefined) return
    const path = `${home}/.claude/review-guard/shadow.jsonl`
    // Read, add, write: two commands ending at the same moment may lose a line, which a sample can spare.
    // A record that can't be read back (too big, damaged) is started again, and that is said.
    let old = ''
    if (await $.fs.exists(path)) {
      old = await Promise.resolve().then(() => $.fs.read(path)).then(t => (typeof t === 'string' ? t : '')).catch(err => {
        sayShadowOnce($, 'reread', `review-guard: the shadow record could not be read back (${whyOf(err)}), so it was started again`)
        return ''
      })
    }
    const lines = old.split('\n').filter(l => l.trim() !== '')
    lines.push(JSON.stringify({ at: new Date().toISOString(), ...entry }))
    let bytes = 0
    let keep = lines.length
    while (keep > 0 && bytes + (lines[keep - 1]?.length ?? 0) + 1 <= SHADOW_KEEP_BYTES) bytes += (lines[--keep]?.length ?? 0) + 1
    await $.fs.write(path, `${lines.slice(Math.min(keep, lines.length - 1)).join('\n')}\n`)
  } catch (err) {
    sayShadowOnce($, 'record', `review-guard: could not write the shadow record (${whyOf(err)}); the review is not affected`)
  }
}

/** `extra` goes into the record too: the steps (`StepsOf`), and the repositories that failed before. */
async function shadowFailed($: EngineInterface, stage: string, err: unknown, extra: Record<string, unknown> = {}): Promise<undefined> {
  sayShadowOnce($, `look ${stage} ${reasonKind(whyOf(err))}`, `review-guard: the shadow look at what a command changed failed ${stage} (${whyOf(err)}); the review is not affected`)
  await recordShadow($, { failed: `${stage}: ${whyOf(err)}`, ...extra })
  return undefined
}

// A look never holds a command up longer than this, before it or after: past it, the command goes on
// unlooked at, and the look stops at its next step (`Stop`) without recording anything more.
const SHADOW_LOOK_MS = 4_000
// How much longer a look that is already writing its record holds the command up, at most.
const SHADOW_RECORD_GRACE_MS = 1_000

/**
 * One timed step of a look, for the record: what ran (each git run, as `git status`, `git config` (the
 * filter check before a status or diff), `git rev-parse`, `git diff` or `git check-ignore`; and `look`, one
 * repository's whole look, its file reads included), in which folder, when it started (`at`, milliseconds
 * into the look) and how long it took (`ms`; none when the look ran out of time while it was still running).
 * Times are the wall clock's, whatever clock the engine gives. At most `MAX_STEPS` are kept, the rest counted.
 */
type Step = { what: string; in?: string; at: number; ms?: number }
const MAX_STEPS = 120

/**
 * A look under way: `over` once it ran out of time (`shadowInTime`), when it reads and records nothing more;
 * `recording` once it has started writing its record, which then finishes, cap or not (so no second, late
 * line). Its steps so far, timed from `startedAt`, and how many more there were than `MAX_STEPS`.
 */
type Stop = { over: boolean; recording: boolean; startedAt: number; steps: Step[]; dropped: number }

/** What a record keeps of a look's steps: copies, so a step still running when it was taken stays without `ms`. */
type StepsOf = { steps: { before?: Step[]; after?: Step[] }; stepsDropped?: number }
const frozen = (steps: readonly Step[]): Step[] => steps.map(s => ({ ...s }))
function stepsOf(stop: Stop, which: 'before' | 'after', before?: Shadow): StepsOf {
  const dropped = stop.dropped + (before?.dropped ?? 0)
  return { steps: { ...(before ? { before: before.steps } : {}), [which]: frozen(stop.steps) }, ...(dropped > 0 ? { stepsDropped: dropped } : {}) }
}

/** Runs `f` as a step of the look `stop`, timed. */
async function timed<T>(stop: Stop, what: string, where: string | undefined, f: () => Promise<T>): Promise<T> {
  const step: Step = { what, ...(where !== undefined ? { in: where } : {}), at: Date.now() - stop.startedAt }
  if (stop.steps.length < MAX_STEPS) stop.steps.push(step)
  else stop.dropped++
  try {
    return await f()
  } finally {
    step.ms = Date.now() - stop.startedAt - step.at
  }
}

/** The git subcommand and folder (`-C`) of a git argv, past its options; undefined for another program. */
function gitStep(argv: readonly string[]): { what: string; in?: string } | undefined {
  if (!/(?:^|[\\/])git(?:\.exe)?$/i.test(argv[0] ?? '')) return undefined
  let dir: string | undefined
  for (let i = 1; i < argv.length; i++) {
    const a = argv[i] ?? ''
    if (a === '-C') dir = argv[++i]
    else if (a === '-c') i++
    else if (!a.startsWith('-')) return { what: `git ${a}`, ...(dir !== undefined ? { in: dir } : {}) }
  }
  return { what: 'git', ...(dir !== undefined ? { in: dir } : {}) }
}

/** `host` with each git run timed as a step of `stop`. */
function timedHost(host: Host, stop: Stop): Host {
  return {
    ...host,
    run: (argv, init) => {
      const step = gitStep(argv)
      return step ? timed(stop, step.what, step.in, () => host.run(argv, init)) : host.run(argv, init)
    },
  }
}

/** What an after look gives back when it finished in time (it has nothing else to give). */
const SHADOW_DONE = Symbol('shadow look done')
const SHADOW_LATE = Symbol('shadow look late')

/**
 * `look(stop)`, or undefined once `SHADOW_LOOK_MS` have passed: then `stop.over` is set, and that is
 * recorded (with `late(stop)` too) and logged once. A look already writing its record is waited for instead.
 * Never throws.
 */
async function shadowInTime<T>($: EngineInterface, stage: string, look: (stop: Stop) => Promise<T>, late: (stop: Stop) => Record<string, unknown>): Promise<T | undefined> {
  const stop: Stop = { over: false, recording: false, startedAt: Date.now(), steps: [], dropped: 0 }
  const over = new AbortController()
  const timer = Promise.resolve()
    .then(() => $.clock.sleep(SHADOW_LOOK_MS, { signal: over.signal }))
    .then(() => SHADOW_LATE, err => {
      // Aborted: the look was first. Any other failure leaves the look with no time limit but its git runs' own.
      if (!over.signal.aborted) sayShadowOnce($, 'clock', `review-guard: the shadow look has no time limit: the clock failed (${whyOf(err)}); the review is not affected`)
      return new Promise<never>(() => {})
    })
  try {
    const looking = look(stop)
    const won = await Promise.race([looking, timer])
    if (won !== SHADOW_LATE) return won as T
    // Past its writing of the record, the look is as good as done: one line for this command, not two. It
    // gets a little longer to write it, then the command goes on and the write finishes on its own.
    if (stop.recording) {
      const grace = new AbortController()
      try {
        const late = Promise.resolve()
          .then(() => $.clock.sleep(SHADOW_RECORD_GRACE_MS, { signal: grace.signal }))
          .then(() => SHADOW_LATE, () => new Promise<never>(() => {}))
        const done = await Promise.race([looking, late])
        return done === SHADOW_LATE ? undefined : (done as T)
      } finally {
        grace.abort()
      }
    }
    stop.over = true
    // Recorded while the command goes on: writing the record is no reason to hold it up longer. Its steps,
    // as they were now, say where the time went (one with no `ms` was still running).
    void shadowFailed($, stage, new Error(`it took over ${SHADOW_LOOK_MS / 1000} seconds`), late(stop))
    return undefined
  } catch (err) {
    // The looks catch everything themselves; should one throw all the same, it is said, not lost.
    sayShadowOnce($, 'look threw', `review-guard: the shadow look failed ${stage} (${whyOf(err)}); the review is not affected`)
    return undefined
  } finally {
    over.abort()
  }
}

/**
 * A file as the look sees it: `fileState`, with its text when asked and small enough (not for a file that
 * holds a NUL: a binary one, compared by time and size). Nothing once the look is over (`stop`).
 */
async function lookAt($: EngineInterface, path: string, withText: boolean, stop: Stop): Promise<RepoFileStat> {
  if (stop.over) return undefined
  const state = await fileState($, path)
  if (!state || !withText || state.size > SHADOW_TEXT_UP_TO || stop.over) return state
  const text = await Promise.resolve().then(() => $.fs.read(path)).then(t => (typeof t === 'string' && !t.includes('\0') ? t : undefined)).catch(() => undefined)
  return text === undefined ? state : { ...state, text }
}

/**
 * Before a shell command runs: `git status` of the session folder's repository and of the one it cd's into,
 * when the guess can't be sure what it writes (`unsure`). A folder git can't be run in is recorded and
 * skipped; the others are still looked at. Undefined when there is nothing to look at, for a background
 * command (no "after"), and when the look fails (recorded). Never throws.
 */
async function shadowBefore($: EngineInterface, command: string, powershell: boolean, background: boolean, runScripts: readonly Snapshot[], stop: Stop): Promise<Shadow | undefined> {
  try {
    if (background || !unsure(command, powershell, runScripts)) return undefined
    const host = timedHost(hostOf($), stop)
    const paths = await pathsHere($)
    const running = writersRunning
    const done = writersDone
    const named = [await sessionFolder($), startFolder(command, paths, powershell)].filter((f): f is string => f !== undefined)
    const folders = named.filter((f, i) => named.findIndex(g => normalPath(g, paths.windows) === normalPath(f, paths.windows)) === i)
    // Side by side: on Windows most of a look is starting git, so each folder and repository waits for the
    // slowest one, not for all of them in turn. The results keep the folders' order (the session's first).
    const found = await Promise.all(folders.map(folder => cachedRepo(host, folder, paths.windows).then(
      root => ({ folder, root }),
      err => ({ folder, root: undefined, why: whyOf(err) }),
    )))
    const roots: string[] = []
    const failed: { folder: string; why: string }[] = []
    for (const f of found) {
      if ('why' in f) failed.push({ folder: f.folder, why: f.why })
      const root = f.root
      if (root !== undefined && !roots.some(r => normalPath(r, paths.windows) === normalPath(root, paths.windows))) roots.push(root)
    }
    const looked = await Promise.all(roots.map(root => timed(stop, 'look', root, () => snapshot(host, (p, t) => lookAt($, p, t, stop), root)).then(
      snap => ({ snap }),
      err => ({ root, why: whyOf(err) }),
    )))
    const snaps: RepoSnapshot[] = []
    for (const l of looked) {
      if ('snap' in l) snaps.push(l.snap)
      else failed.push({ folder: l.root, why: l.why })
    }
    if (stop.over || (snaps.length === 0 && failed.length === 0)) return undefined
    for (const f of failed) sayShadowOnce($, `look before ${reasonKind(f.why)}`, `review-guard: the shadow look could not read ${f.folder} (${f.why}); the review is not affected`)
    if (snaps.length === 0) {
      stop.recording = true
      await recordShadow($, { failed: failed.map(f => `before the command, ${f.folder}: ${f.why}`).join('; '), ...stepsOf(stop, 'before') })
      return undefined
    }
    // A script or tool it runs may run git itself (a pull), out of sight of `headMove`. Every step is over
    // here (each look above settled), so the copy is final.
    return { snaps, failed, running, done, runsOthers: runScripts.length > 0 || WRITING_TOOLS.test(command), steps: frozen(stop.steps), dropped: stop.dropped }
  } catch (err) {
    if (stop.over) return undefined
    stop.recording = true
    return shadowFailed($, 'before the command', err, stepsOf(stop, 'before'))
  }
}

/** The repositories that failed before the command, as a record's `repos` (none: nothing). */
const failedBefore = (shadow: Shadow) => (shadow.failed.length > 0 ? { repos: shadow.failed.map(f => ({ repo: f.folder, failed: f.why })) } : {})

/** What a record of an after look that did not finish keeps: what failed before it, and both looks' steps. */
const shadowLate = (shadow: Shadow) => (stop: Stop): Record<string, unknown> => ({ ...failedBefore(shadow), ...stepsOf(stop, 'after', shadow) })

/**
 * After the command: `git status` again, what changed (`changedBetween`, plus what a commit it made took
 * in, `committedWrites`), and how that compares with `guessed`, the names the guess found (before
 * `remember` leaves scratch ones out: those are outside every repository). A relative name the guess could
 * not place is not compared, only counted: the guess doesn't know its folder either. Recorded, never acted
 * on. Each repository is compared on its own, so one that fails doesn't lose the others. Never throws.
 */
async function shadowAfter($: EngineInterface, shadow: Shadow, command: string, powershell: boolean, guessed: readonly string[], stop: Stop): Promise<void> {
  try {
    const host = timedHost(hostOf($), stop)
    const { windows } = await pathsHere($)
    const full = (p: string) => isFullPath(p, windows)
    const placed = guessed.filter(full)
    const unplaced = guessed.filter(p => !full(p))
    const roots = shadow.snaps.map(s => s.repo)
    // Each repository on its own and side by side (as before the command); its lines stay together, in order.
    const compared = await Promise.all(shadow.snaps.map(async (before): Promise<Record<string, unknown>[]> => {
      const repo = before.repo
      const repos: Record<string, unknown>[] = []
      try {
        const after = await timed(stop, 'look', repo, () => snapshot(host, (p, t) => lookAt($, p, t, stop), repo, before))
        const read = headMove(command, before.state.head, after.state.head)
        // A commit beside a script or tool that may itself run git (a pull): the new commits may be others' work.
        const move = read === 'commit' && shadow.runsOthers ? 'other' : read
        if (move === 'other') return [{ repo, skipped: 'a git command in it moves HEAD or brings in other work' }]
        const seen = changedBetween(before, after)
        if (move === 'commit' && before.state.head !== undefined && after.state.head !== undefined) {
          const files = (await committedFiles(host, repo, before.state.head, after.state.head)).filter(p => !seen.includes(p))
          const looked = await lookAll((p, t) => lookAt($, p, t, stop), repo, files, p => before.stats.get(p)?.text !== undefined)
          seen.push(...committedWrites(before, files.map(p => [p, looked.get(p)])))
        }
        // Each guessed name goes to the deepest repository that holds it; a name with a `..` step that
        // climbs out of every root holds none.
        const mine = placed.filter(p => repoFor(roots, p, windows) === repo)
        const { gitOnly, guessOnly } = compareWithGuess(repo, seen, mine, windows, p => languageOf(p) !== undefined)
        // Git never lists an ignored file, so a guessed one it ignores is no disagreement.
        const rel = new Map(guessOnly.map(p => [p, relativeTo(repo, p, windows) ?? '']))
        // Asked all at once; should git refuse that (a name in a submodule fails the whole call), one by one,
        // so one such name leaves the others' answers.
        const names = [...new Set([...rel.values()].filter(r => r !== ''))].slice(0, SHADOW_MAX_ENTRIES)
        const ignored = await ignoredOf(host, repo, names).catch(async err => {
          const each = new Set<string>()
          let refused = 0
          for (const name of names.slice(0, SHADOW_PATHS)) {
            if (stop.over) break
            for (const hit of await ignoredOf(host, repo, [name]).catch(() => {
              refused++
              return new Set<string>()
            })) each.add(hit)
          }
          const skipped = Math.max(0, names.length - SHADOW_PATHS)
          if (refused + skipped > 0) {
            repos.push({ repo, partial: `git would not say whether ${refused + skipped} name(s) are ignored (${whyOf(err)})` })
            sayShadowOnce($, `ignored ${reasonKind(whyOf(err))}`, `review-guard: git would not say which names it ignores in ${repo} (${whyOf(err)}); the shadow record marks that comparison partial`)
          }
          return each
        })
        const notIgnored = guessOnly.filter(p => !ignored.has(rel.get(p) ?? ''))
        repos.push({
          repo,
          agree: gitOnly.length === 0 && notIgnored.length === 0,
          gitOnly: listed(gitOnly),
          guessOnly: listed(notIgnored),
          ignored: listed(guessOnly.filter(p => !notIgnored.includes(p))),
        })
      } catch (err) {
        repos.push({ repo, failed: whyOf(err) })
        sayShadowOnce($, `look after ${reasonKind(whyOf(err))}`, `review-guard: the shadow look could not read ${repo} after a command (${whyOf(err)}); the review is not affected`)
      }
      return repos
    }))
    const repos: Record<string, unknown>[] = [...shadow.failed.map(f => ({ repo: f.folder, failed: f.why })), ...compared.flat()]
    // Other edits or commands under way while this one ran (or still), or a shell command left running
    // lately: their files may show as this one's.
    const others = shadow.running > 0 || writersRunning > 0 || writersDone - shadow.done > 1 || Date.now() - backgroundAt < BACKGROUND_WRITES_MS
    if (stop.over) return
    stop.recording = true
    await recordShadow($, {
      shell: powershell ? 'powershell' : 'bash',
      repos,
      unplaced: unplaced.length,
      ...(others ? { othersWriting: true } : {}),
      ...stepsOf(stop, 'after', shadow),
    })
  } catch (err) {
    if (stop.over) return
    stop.recording = true
    await shadowFailed($, 'after the command', err, shadowLate(shadow)(stop))
  }
}

/**
 * Code is also changed from a shell (sed -i, a redirect, a script that writes files). Once a shell
 * command has run, the code files it wrote are remembered for the review, less the scripts it only ran
 * (`before` holds them as they were), Claude's scratch files (kept when the command copies or moves), and
 * the names in a Bash command that only writes and runs scratch scripts (`blankScratchBodies`). A command that failed may still have written, so it counts; one that was refused never ran.
 * What is left out is named on the status line, after `said` when the guard already put a line there.
 * With `shadow` (`shadowBefore`), the shadow look then compares what git saw with the names found here.
 * Never throws: it only remembers.
 */
async function rememberShellWrites<R extends { deny?: unknown; result?: unknown }>($: EngineInterface, result: R, command: string, before: readonly Snapshot[], powershell: boolean, said?: string, agentId?: string, start?: Start, shadow?: Shadow): Promise<R> {
  // Whether the after look ran (it records what failed before it): if not, those failures are recorded here.
  let lookedAfter = false
  try {
    if (result.deny === undefined) {
      // A command that changes folder (`CHANGES_FOLDER`): its relative paths are not the session's. A shell
      // may keep the new folder, so neither are those of the same agent's later commands: that agent goes
      // into `ownFolder`. A word that is not really a command (in a message, say) only means more review.
      // `inOwnFolder` never rejects, and logs a failed save rather than cover the guard's notice (`said`).
      if (agentId !== undefined && CHANGES_FOLDER.test(command)) await inOwnFolder($, agentId)
      const writer: Writer = powershell ? 'powershell' : 'bash'
      // A Bash command that only writes and runs scratch scripts writes nothing their text names
      // (`blankScratchBodies`, whose forms leave no room for a copy). The names it drops are said.
      const all = shellWrites(command)
      // `scratchTargets` can't reject today (its reads are each caught); should that change, the text is kept.
      const scratchFile = powershell || !command.includes('<<')
        ? undefined
        : await scratchTargets($).catch(err => {
          logLine($, `review-guard: a scratch script's text was kept in the review: the scratch folders could not be read (${whyOf(err)})`)
          return undefined
        })
      const written = scratchFile ? blankedSafely($, command, scratchFile, all) : all
      const inScript = all.filter(path => !written.includes(path))
      const compare = written.length > 0 && before.length > 0 && !mayStillRun(result)
      const onlyRun = compare
        ? await untouched($, before).catch(err => {
          logLine($, `review-guard: could not tell which scripts a command only ran (${whyOf(err)}), so they are reviewed as written`)
          return new Set<string>()
        })
        : new Set<string>()
      const { names: kept, keep } = placeInStart(written.filter(path => !onlyRun.has(path)), start)
      const lang = (path: string): [string, string] => [path, languageOf(path) ?? 'other code']
      // A scratch file named by a copy or move may be the source of a write into the project: keep it.
      // The names to keep first: should that throw, nothing has been left out as scratch without a word.
      await remember($, keep.map(lang), writer, true, agentId, !CHANGES_FOLDER.test(command))
      const scratch = await remember($, kept.map(lang), writer, COPIES.test(command), agentId, !CHANGES_FOLDER.test(command))
      await sayLeftOut($, scratch, written.filter(path => onlyRun.has(path)), said, inScript)
      // The shadow look, once the review has what the guess found: recorded, never acted on.
      if (mayStillRun(result)) backgroundAt = Date.now()
      else if (shadow !== undefined) {
        lookedAfter = true
        await shadowInTime($, 'after the command', stop => shadowAfter($, shadow, command, powershell, [...kept, ...keep], stop).then(() => SHADOW_DONE), shadowLate(shadow))
      }
    }
  } catch (err) {
    // A command whose writes could not be read or recorded is one fewer file in the review, not a stopped command, but say so.
    say($, `review-guard: could not record the files a shell command wrote (${whyOf(err)}); ask for a review by hand`)
  }
  // No after look (the command was refused, may still be running, or its writes could not be read): what
  // failed before it is recorded all the same.
  if (shadow !== undefined && !lookedAfter && shadow.failed.length > 0) {
    const why = result.deny !== undefined ? 'the command was refused' : mayStillRun(result) ? 'the command may still be running' : 'its writes could not be read'
    await recordShadow($, { failed: `after the command: not looked at (${why})`, ...failedBefore(shadow), steps: { before: shadow.steps }, ...(shadow.dropped > 0 ? { stepsDropped: shadow.dropped } : {}) })
  }
  return result
}

/**
 * Ends the running review. `fixes`: what to do with the files changed while it ran, its own fixes: drop
 * them (the review is over), or queue them with the files it covered (it was cut short). Files other
 * agents changed meanwhile are queued either way.
 */
function endReview(c: Cycle, fixes: 'drop' | 'requeue'): void {
  // Each file once, under the first list's spelling (`joinFiles`): the files it covered first, so their
  // spelling is kept, and other work last.
  c.changed = fixes === 'drop' ? joinFiles(c.othersChanged) : joinFiles(c.underReview, c.changed, c.othersChanged)
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
  let delivered = false // the running review's prompt is now known to have reached Claude
  const ask = await updateCycle($, (c): StopAsk => {
    // The running review's prompt was handed out at an earlier stop: this stop shows whether it arrived.
    if (c.reviewing && c.promptPending && !hookActive) {
      promptLost = true
      endReview(c, 'requeue')
    }
    if (c.reviewing && hookActive) {
      if (c.promptPending) delivered = true
      c.promptPending = false
    }
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
    return { kind: 'review', prompt, files: [...changed.keys()] }
  })
  // The project's history counts a review only once its prompt arrived (see `churnPending`).
  if (delivered) await recordChurn($)
  if (promptLost) clearChurn()
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
    clearChurn() // no review was asked for, so none is recorded
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
  if (ask?.kind === 'review') {
    // The churn check never holds the turn's end up for long: past five seconds, or once the dispatch is
    // abandoned (an interrupt, the budget), the review goes without it. A clock that fails leaves the
    // check's own time, still cut short by an abandon. The sleep runs on after a check that wins (it
    // stops only on an abandon), so it logs only when the check is in fact still going.
    let checked = false
    const checking = churnCheck($, ask.files).finally(() => {
      checked = true
    })
    const abandoned = () => new Promise<string>(resolve => {
      if (signal.aborted) resolve('')
      else signal.addEventListener('abort', () => resolve(''), { once: true })
    })
    const note = await Promise.race([
      checking,
      $.clock.sleep(5000, { signal }).then(
        () => {
          // Each time, not once per load: each one is a review that may go uncounted.
          if (!checked) logLine($, "review-guard: the churn check took over five seconds, so the review went without it; this review may not be counted in the project's history")
          return ''
        },
        abandoned,
      ),
    ])
    if (signal.aborted) return putBack()
    return { ...ask, prompt: ask.prompt + note }
  }
  return ask
}

// The review whose prompt went out last, waiting to be recorded in its project's history until the prompt
// is known to have reached Claude (`recordChurn`), so a lost prompt, whose files come back, is never
// counted twice. In memory only: a reload before then leaves that review out, which only means a churning
// file is noticed a review later.
let churnPending: { path: string; folder: string; files: string[]; at: Date; rule: ChurnRule } | undefined
// Moves on whenever `churnPending` is cleared. A churn check runs on after the turn's end stops waiting
// for it (past five seconds, or an abort), so it sets `churnPending` only if nothing cleared it since it
// began: a review put back, a lost prompt, or a newer review's check.
let churnEpoch = 0

/** Clears the pending review, so that no churn check still running sets it again. */
function clearChurn(): void {
  churnPending = undefined
  churnEpoch++
}

const churnSaid = new Set<string>() // each churn problem is logged once per load of the module

/** Logs a churn problem once per load of the module. Never on the status line: it may hold a guard notice. */
function churnLog($: EngineInterface, text: string): void {
  if (churnSaid.has(text)) return
  churnSaid.add(text)
  logLine($, text)
}

/**
 * A changed file as the history keeps it: as `samePath` spells it, relative paths read against the
 * session's folder, so one file under two spellings counts once. A path with a `..` step is kept as stored.
 * (A wrong merge here could only change a churn note, never what is reviewed.)
 */
function churnPath(k: string, folder: string): string {
  return hasUpStep(k) ? k : samePath(k, folder, keySpelling)
}

/** How long `readHistory` waits before reading text that is not JSON a second time. */
const HISTORY_REREAD_MS = 250

/**
 * The project's review history (churn.ts), or why it can't be used: a read that fails throws (to the
 * caller's catch, which leaves the file alone). Text that is not JSON, or JSON of the wrong shape (another
 * version's `v` included), counts as damaged and the history starts again, except that before a write a
 * history of another version throws instead (see below). With `forWrite` (the read
 * before a write over the file), text that is not JSON is read once more after a short wait first, since
 * another session may be part-way through writing the file and starting again then would wipe its whole
 * history; and damage is logged, every time rather than once per load, since each time loses entries. A
 * read only for the check logs nothing: it writes nothing, and any write that follows logs what it finds.
 */
async function readHistory($: EngineInterface, path: string, folder: string, forWrite = false) {
  const parse = async (): Promise<{ raw: unknown; ok: boolean }> => {
    if (!(await $.fs.exists(path))) return { raw: undefined, ok: true }
    const text = await $.fs.read(path)
    try {
      return { raw: JSON.parse(text.replace(/^﻿/, '')), ok: true }
    } catch {
      return { raw: null, ok: false }
    }
  }
  let { raw, ok } = await parse()
  if (!ok && forWrite) {
    // A clock that fails reads again at once, which still catches a write that has just finished.
    await $.clock.sleep(HISTORY_REREAD_MS).catch(() => undefined)
    ;({ raw, ok } = await parse())
  }
  // A history another version of the mod wrote (another session may run one) is never written over: that
  // would wipe it at every review. The caller's catch leaves the file alone and logs why.
  const v = typeof raw === 'object' && raw !== null && !Array.isArray(raw) ? (raw as { v?: unknown }).v : undefined
  if (forWrite && typeof v === 'number' && v !== 1) throw new Error(`it was written by another version of review-guard (v${v}), so it is left alone`)
  const read = historyFrom(raw, folder)
  if (forWrite && read.damaged) logLine($, "review-guard: this project's review history was damaged, so the churn check started it again")
  if (forWrite && read.dropped > 0) logLine($, `review-guard: ${read.dropped} damaged entr${read.dropped === 1 ? 'y was' : 'ies were'} dropped from this project's review history`)
  return read.history
}

/**
 * Whether some of `files` churn under the user's rule, judged on the project's history plus this review,
 * and if so the paragraph to add to the review prompt (otherwise ''). The review itself is recorded only
 * once its prompt has reached Claude (`churnPending`, `recordChurn`). Never throws: the review goes out
 * either way, and a problem here is logged once per load (`churnLog`). A check its caller stops waiting for
 * past five seconds, and a damaged history found before a write, are logged every time instead.
 */
async function churnCheck($: EngineInterface, files: readonly string[]): Promise<string> {
  clearChurn()
  const epoch = churnEpoch
  try {
    const loaded = await loadConfig(hostOf($)).catch((err: unknown) => {
      // A broken config stops commits (said there). Here the churn check is skipped, not run on its
      // default rule: the user may have turned it off in the file that can't be read.
      churnLog($, `review-guard: ${whyOf(err)}; the churn check is skipped until the config can be read`)
      return undefined
    })
    if (loaded === undefined) return ''
    const { config } = loaded
    if (config.churnProblem !== undefined) churnLog($, `review-guard: ${config.churnProblem}; the churn check uses its default rule`)
    const rule = config.churn
    if (rule === false) return ''
    const home = await homeDir($)
    const folder = await sessionFolder($)
    if (!home || !folder) throw new Error(!home ? 'the home folder is not known' : "the session's folder is not known")
    const path = `${historyDir(home)}/${historyFileName(folder)}`
    const now = new Date()
    const paths = files.map(k => churnPath(k, folder))
    const history = withReview(await readHistory($, path, folder), paths, now, now, rule)
    if (epoch === churnEpoch) churnPending = { path, folder, files: paths, at: now, rule }
    const found = churned(history, paths, rule, now)
    if (found.length === 0) return ''
    // In the log, not on the status line (it may hold a guard notice): the prompt has Claude tell the user.
    logLine($, `review-guard: ${found.length} file(s) keep coming back for review in this project (${found.map(f => f.path).join(', ')}); the review asks Claude to steady them first`)
    return `\n${churnNote(found, rule)}`
  } catch (err) {
    churnLog($, `review-guard: the churn check could not run (${whyOf(err)}); the review goes ahead without it`)
    return ''
  }
}

/**
 * The pending review's prompt reached Claude: adds it to its project's history, read afresh (another
 * session may have added to it meanwhile). Never throws; a failure is logged once.
 */
async function recordChurn($: EngineInterface): Promise<void> {
  const pending = churnPending
  clearChurn()
  if (!pending) return
  const record = async () => {
    try {
      const history = withReview(await readHistory($, pending.path, pending.folder, true), pending.files, pending.at, new Date(), pending.rule)
      await $.fs.write(pending.path, `${JSON.stringify(history, null, 2)}\n`)
    } catch (err) {
      churnLog($, `review-guard: could not record a review in this project's history (${whyOf(err)}); churning files may be noticed later`)
    }
  }
  // Never holds a turn's end or a prompt up for long: past two seconds it goes on without waiting (the
  // write may still land). A clock that fails leaves only the write's own time. The note is logged only
  // when the write is in fact still going, and its timer stops once the write is over.
  let done = false
  const over = new AbortController()
  const writing = record().finally(() => {
    done = true
    over.abort()
  })
  await Promise.race([
    writing,
    $.clock.sleep(2000, { signal: over.signal }).then(
      () => {
        if (!done) churnLog($, "review-guard: recording a review in this project's history took over two seconds; it was not waited for")
      },
      () => new Promise<void>(() => {}),
    ),
  ])
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
      let delivered = false // typed while the review's turn still runs: its prompt arrived
      await updateCycle($, c => {
        if (!c.reviewing) return
        // What the review's own agents wrote (scratch files, fixes) is not new work. But a review whose
        // prompt never reached Claude had no agents and no fixes: its files go back in the queue.
        requeued = c.promptPending && e.turnId === undefined
        delivered = c.promptPending && !requeued
        endReview(c, requeued ? 'requeue' : 'drop')
      })
      if (delivered) await recordChurn($)
      if (requeued) clearChurn()
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

  // An MCP tool may write files too (a code editor's): counted while it runs, for the shadow look only.
  on('tool.call', { tool: /^mcp__/ }, ($, e, next) => asWriter(() => next(e)))

  on('tool.call', { tool: ['Edit', 'Write', 'NotebookEdit'] }, async ($, e, next) => {
    // Counted while it runs (`asWriter`), for the shadow look: its file may show as a shell command's.
    const result = await asWriter(() => next(e))
    // Only remembers: a failure here must never stop an edit, but a file left out of the review is said.
    // (A failure beneath, in the edit itself, is not this mod's to report.)
    try {
      if (result.deny === undefined && result.isError !== true) {
        const path = e.tool === 'NotebookEdit' ? e.notebook_path : e.file_path
        const lang = languageOf(path) ?? (/\.ipynb$/i.test(path) ? 'Python' : undefined)
        // How the edit tools read a path (on Windows `/c/...` is drive C and `/tmp` is `\tmp` on the
        // current drive) is up to `rulesFor`.
        if (lang) await sayLeftOut($, await remember($, [[path, lang]], 'edit', false, e.agentId), [])
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
      const listed = (x: string | undefined) => x !== undefined && ownFolder.includes(x)
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
        if (cycle.promptPending) {
          await updateCycle($, c => { c.promptPending = false })
          await recordChurn($) // the project's history counts a review only once its prompt arrived
        }
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
          if (lost) clearChurn()
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
    // The folder it surely starts in, and whether that is scratch, checked before it runs (`startDir`).
    const start = await startDir($, e.command, powershell, e.run_in_background === true)
    // Runs the command, then remembers what it wrote. Just before it runs: the repositories it may touch, for
    // the shadow look (`shadowBefore`, only when the guess can't be sure), after the guard's own checks.
    const run = async (said: string | undefined) => {
      const shadow = await shadowInTime($, 'before the command', stop => shadowBefore($, e.command, powershell, e.run_in_background === true, before, stop), stop => stepsOf(stop, 'before'))
      if (e.run_in_background === true) backgroundAt = Date.now() // it runs now, past its call
      return rememberShellWrites($, await asWriter(() => next(e)), e.command, before, powershell, said, e.agentId, start, shadow)
    }
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
      return run(said)
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
    if (!toGitHub && !gh) return run(undefined)
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
    return run(said)
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
