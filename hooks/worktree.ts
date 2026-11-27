// review-guard's look at what a shell command really changed in a git repository: `git status` before and
// after the command, compared. It gives the real paths, whatever folder the command ran in and however it
// spelled them, where the text guess (`shellWrites` in scan.ts) has to work out both.
//
// For now (0.5.x) this only runs alongside the guess, as a shadow: register.ts records how the two compare
// in ~/.claude/review-guard/shadow.jsonl, and the review still uses the guess. Pure functions here, apart
// from `repoOf`, `snapshot`, `committedFiles` and `ignoredOf`, which run git through `Host`.
import { git, type Host } from './outgoing.ts'

/**
 * A file as the look saw it: its time and size, and for a small file its text (so a copy that keeps the
 * time and size still shows). Undefined when it is gone, a folder or a link, or can't be read.
 */
export type FileStat = { mtimeMs: number; size: number; text?: string } | undefined

/**
 * What `git status --porcelain=v2 --branch -z` says: the commit checked out (`undefined` before the first
 * commit), and each path that is not clean, relative to the root, with its two status letters.
 */
export type RepoState = { head: string | undefined; entries: Map<string, string> }

/**
 * A repository as it was at one moment: its root (as `git rev-parse --show-toplevel` spells it, forward
 * slashes, no trailing slash), its state, and how each path in `state.entries` looked (same keys).
 */
export type Snapshot = { repo: string; state: RepoState; stats: Map<string, FileStat> }

// Each git run here may take this long (`git status` and `git diff` are two runs: their filter check, then
// themselves). Past it the look gives up and the guess stands. Most of it, on Windows, is starting git (a
// bare `git --version` took about 350 ms on the user's PC).
export const GIT_TIMEOUT_MS = 1_500

// More paths than this not clean: too many to look at on every command, so the look gives up.
export const MAX_ENTRIES = 2_000

// A file up to this size, already changed before the command, is also compared by its text, up to
// `TEXT_BUDGET` characters in all per look; past that, by time and size only.
export const COMPARE_TEXT_UP_TO = 64 * 1024
export const TEXT_BUDGET = 4 * 1024 * 1024

// The records of `--porcelain=v2`: ordinary (`1`), renamed or copied (`2`, followed by the old path as a
// record of its own), unmerged (`u`), untracked (`?`) and ignored (`!`, only asked for with `--ignored`).
const ORDINARY = /^1 (\S\S) (?:\S+ ){6}([^]*)$/
const RENAMED = /^2 (\S\S) (?:\S+ ){7}([^]*)$/
const UNMERGED = /^u (\S\S) (?:\S+ ){8}([^]*)$/

/**
 * Reads `git status --porcelain=v2 --branch -z`. A path listed twice (`git rm --cached f` lists `D.` and
 * `? f`) keeps its first record, the tracked one. Throws on a record it doesn't know, rather than guess.
 */
export function parseStatus(out: string): RepoState {
  const records = out.split('\0')
  if (records.at(-1) === '') records.pop()
  let head: string | undefined
  let named = false
  const entries = new Map<string, string>()
  const put = (path: string, letters: string) => {
    if (!entries.has(path)) entries.set(path, letters)
  }
  for (let i = 0; i < records.length; i++) {
    const r = records[i] ?? ''
    if (r.startsWith('# ')) {
      if (r.startsWith('# branch.oid ')) {
        named = true
        const oid = r.slice('# branch.oid '.length)
        head = oid === '(initial)' ? undefined : oid
      }
      continue
    }
    const m = ORDINARY.exec(r) ?? UNMERGED.exec(r) ?? RENAMED.exec(r)
    if (m) {
      put(m[2] ?? '', m[1] ?? '')
      if (r.startsWith('2 ')) i++ // the old path
    } else if (r.startsWith('? ')) put(r.slice(2), '??')
    else if (r.startsWith('! ')) continue
    else throw new Error(`git status gave a record review-guard doesn't know (it starts "${r.slice(0, 2)}")`)
  }
  if (!named) throw new Error('git status did not say which commit is checked out')
  return { head, entries }
}

/** Whether a file looked different at two moments: its time, size, or (when both were read) text. */
export function differs(then: FileStat, now: FileStat): boolean {
  if (then === undefined || now === undefined) return true
  if (then.mtimeMs !== now.mtimeMs || then.size !== now.size) return true
  return then.text !== undefined && now.text !== undefined && then.text !== now.text
}

/**
 * The paths (relative to the repository's root) that the command wrote, by what is in the work tree:
 * - a path that was clean before and isn't now (edited, made, or edited and staged);
 * - a path that wasn't clean before either, that looks different now (`differs`: a second edit of a
 *   changed file, which git reports the same way).
 * A change in the status letters alone isn't a write: `git add` and `git reset` only move a file in or out
 * of the index. A file deleted from the work tree is left out (nothing to review), and so is one that is
 * gone, a folder or a link now (`after` has no stat for it). A file the command made clean again (undid
 * an edit) is not seen: it is clean after, so git doesn't list it.
 */
export function changedBetween(before: Snapshot, after: Snapshot): string[] {
  const out: string[] = []
  for (const [path, letters] of after.state.entries) {
    if (letters[1] === 'D' || (letters[0] === 'D' && letters[1] === '.')) continue
    const now = after.stats.get(path)
    if (now === undefined) continue
    if (!before.state.entries.has(path) || differs(before.stats.get(path), now)) out.push(path)
  }
  return out
}

/**
 * Of the files a commit made during the command changed (`committed`, with how each looks now), the ones
 * the command itself wrote: clean before (so the command changed it, then committed it), or changed before
 * and different now (a formatter in a pre-commit hook, say). One already changed before and untouched was
 * written earlier (by Edit, say) and only committed now. A file gone now is left out.
 */
export function committedWrites(before: Snapshot, committed: [string, FileStat][]): string[] {
  return committed.filter(([path, now]) => now !== undefined && (!before.state.entries.has(path) || differs(before.stats.get(path), now))).map(([p]) => p)
}

// git commands that never move `HEAD` nor bring other work into the work tree: they commit, read, or talk
// to a remote without touching the work tree (`push`, `fetch`).
const KEEPS_HEAD = new Set([
  'commit', 'add', 'stage', 'rm', 'mv', 'status', 'diff', 'log', 'show', 'blame', 'grep', 'config', 'rev-parse', 'ls-files',
  'ls-tree', 'notes', 'tag', 'branch', 'describe', 'shortlog', 'check-ignore', 'push', 'fetch', 'remote', 'ls-remote',
  'rev-list', 'cat-file', 'reflog', 'show-ref', 'for-each-ref',
])

/**
 * How the look reads git commands run during the command:
 * - `commit`: `HEAD` moved, and every git command found is one that only commits or reads (`KEEPS_HEAD`):
 *   the new commits' files may be the command's own writes (`committedWrites`);
 * - `none`: `HEAD` didn't move, and no git command found could bring other work into the work tree;
 * - `other`: any git command not in `KEEPS_HEAD` (a pull, checkout, `stash pop`, `apply`, an alias, which
 *   may move `HEAD` or bring other work in), `gh pr checkout`, `HEAD` moved with no commit, or a first commit.
 *   The look can't tell what the command itself wrote, so the repository is not compared.
 */
export function headMove(command: string, before: string | undefined, after: string | undefined): 'none' | 'commit' | 'other' {
  const subs = gitSubcommands(command)
  const quiet = subs.every(s => KEEPS_HEAD.has(s)) && !/\bgh\s+(?:pr|repo)\s+(?:checkout|clone|sync)\b/.test(command)
  if (before === after) return quiet ? 'none' : 'other'
  return quiet && subs.includes('commit') && before !== undefined ? 'commit' : 'other'
}

/**
 * The git commands a command line runs (`git -C dir commit -am x` is `commit`): after each word `git`, the
 * first word that is not one of git's own options (`-C dir`, `-c k=v`, `--git-dir dir` and `--work-tree dir`
 * take the next word). An option of the command is never read as one (`commit -am` is not `git am`). A
 * quoted word is one word. A plain walk over words, not a pattern, so a long line can't make it slow.
 */
export function gitSubcommands(command: string): string[] {
  const words = (command.match(/"[^"]*"|'[^']*'|[^\s;&|()"']+/g) ?? []).map(w => w.replace(/^(["'])([^]*)\1$/, '$2'))
  const out: string[] = []
  for (let i = 0; i < words.length; i++) {
    if (!/^(?:.*[\\/])?git(?:\.exe)?$/i.test(words[i] ?? '')) continue
    let j = i + 1
    while (j < words.length && (words[j] ?? '').startsWith('-')) j += /^(?:-[Cc]|--(?:git-dir|work-tree|namespace|config-env|super-prefix))$/.test(words[j] ?? '') ? 2 : 1
    if (j < words.length) out.push((words[j] ?? '').toLowerCase())
  }
  return out
}

/**
 * The root of the repository `folder` is in (forward slashes), or undefined when there is none git will
 * use there: not a repository, a folder that isn't there yet, one git won't trust. Git's message for each
 * is in the user's language, so any refusal counts as none. Throws when git can't be run, or runs past
 * `GIT_TIMEOUT_MS` (a cold start on Windows can).
 */
export async function repoOf(host: Host, folder: string): Promise<string | undefined> {
  const r = await git(host, folder, ['rev-parse', '--show-toplevel'], GIT_TIMEOUT_MS)
  if (r.exitCode !== 0) return undefined
  const root = r.stdout.trim().replace(/\\/g, '/').replace(/(?<=.)\/+$/, '')
  return root === '' ? undefined : root
}

/**
 * `repo` as it is now; `look` reads one file (time, size, and text when asked). Throws when git fails, is
 * too slow, or lists more than `MAX_ENTRIES` paths. `withText` (the before look) reads the text of small
 * changed files, so `differs` can see a write that kept the time and size; the after look reads text only
 * where `withText` did.
 */
export async function snapshot(host: Host, look: (path: string, text: boolean) => Promise<FileStat>, repo: string, textOf?: Snapshot): Promise<Snapshot> {
  const r = await git(host, repo, ['status', '--porcelain=v2', '--branch', '-z', '--untracked-files=all'], GIT_TIMEOUT_MS)
  if (r.exitCode !== 0) throw new Error(`git status failed (exit ${r.exitCode}): ${r.stderr.trim().slice(0, 200) || 'no message'}`)
  if (r.isStdoutTruncated) throw new Error('git status listed too much to read')
  const state = parseStatus(r.stdout)
  if (state.entries.size > MAX_ENTRIES) throw new Error(`git status listed ${state.entries.size} paths that are not clean, over ${MAX_ENTRIES}`)
  const stats = await lookAll(look, repo, [...state.entries.keys()], p => (textOf === undefined ? true : textOf.stats.get(p)?.text !== undefined))
  return { repo, state, stats }
}

/**
 * `paths` under `repo`, looked at in batches (a few hundred in about the time of a few). Text is read where
 * `withText` says, until `TEXT_BUDGET` characters have been read.
 */
export async function lookAll(look: (path: string, text: boolean) => Promise<FileStat>, repo: string, paths: string[], withText: (path: string) => boolean): Promise<Map<string, FileStat>> {
  const stats = new Map<string, FileStat>()
  let read = 0
  for (let i = 0; i < paths.length; i += 50) {
    const batch = paths.slice(i, i + 50)
    // Only as many as surely fit in what is left of the budget ask for their text.
    let left = TEXT_BUDGET - read
    const wants = batch.map(p => {
      if (!withText(p) || left < COMPARE_TEXT_UP_TO) return false
      left -= COMPARE_TEXT_UP_TO
      return true
    })
    const seen = await Promise.all(batch.map((p, k) => look(underRoot(repo, p), wants[k] ?? false)))
    batch.forEach((p, k) => {
      stats.set(p, seen[k])
      read += seen[k]?.text?.length ?? 0
    })
  }
  return stats
}

/** The paths (relative to the root) that the commits between `from` and `to` changed. Throws when git fails. */
export async function committedFiles(host: Host, repo: string, from: string, to: string): Promise<string[]> {
  const r = await git(host, repo, ['diff', '--name-only', '-z', '--no-renames', '--no-ext-diff', from, to], GIT_TIMEOUT_MS)
  if (r.exitCode !== 0) throw new Error(`git diff failed (exit ${r.exitCode}): ${r.stderr.trim().slice(0, 200) || 'no message'}`)
  if (r.isStdoutTruncated) throw new Error('git diff listed too much to read')
  const paths = r.stdout.split('\0').filter(p => p !== '')
  if (paths.length > MAX_ENTRIES) throw new Error(`the commit changed ${paths.length} paths, over ${MAX_ENTRIES}`)
  return paths
}

/** Of `paths` (relative to the root, none with a `..` step), the ones the repository ignores. Throws when git fails. */
export async function ignoredOf(host: Host, repo: string, paths: string[]): Promise<Set<string>> {
  if (paths.length === 0) return new Set()
  const r = await git(host, repo, ['check-ignore', '--stdin', '-z'], GIT_TIMEOUT_MS, `${paths.join('\0')}\0`)
  // Exit 1: none of them is ignored.
  if (r.exitCode !== 0 && r.exitCode !== 1) throw new Error(`git check-ignore failed (exit ${r.exitCode}): ${r.stderr.trim().slice(0, 200) || 'no message'}`)
  if (r.isStdoutTruncated) throw new Error('git check-ignore listed too much to read')
  return new Set(r.stdout.split('\0').filter(p => p !== ''))
}

/**
 * A path as the look compares it: forward slashes, Git Bash's `/c/` as `C:/`, `.` steps and doubled
 * slashes gone, `..` steps worked out (by their text, not through links; one above a full path's root is
 * dropped, as the system does), and on Windows any case. On Windows a network path (`//host/share/...`)
 * keeps its two leading slashes. The case is kept when `fold` is false, so a path can be cut to its part under a root
 * and given to git.
 */
export function normalPath(path: string, windows: boolean, fold = windows): string {
  let p = path.replace(/\\/g, '/')
  if (windows) p = p.replace(/^\/([a-z])(?=\/|$)/i, '$1:')
  const lead = (windows ? /^(?:\/\/(?=[^/])|[A-Za-z]:\/|\/)/ : /^\//).exec(p)?.[0] ?? ''
  const parts: string[] = []
  for (const part of p.slice(lead.length).split('/')) {
    if (part === '' || part === '.') continue
    if (part === '..' && parts.length > 0 && parts.at(-1) !== '..') parts.pop()
    else if (part === '..' && lead !== '' && parts.length === 0) continue
    else parts.push(part)
  }
  const out = lead + parts.join('/')
  return fold ? out.toLowerCase() : out
}

/** How the look and the guess compare for one repository: full paths only git saw, and only the guess named. */
export type Comparison = { gitOnly: string[]; guessOnly: string[] }

/**
 * Compares the look's paths (`seen`, relative to `repo`) with the guess's full paths (`guessed`, already
 * the ones in `repo`: `repoFor`). `isCode` is the guess's own filter, so the look counts the same kind of
 * files, and neither side counts anything under `.claude/` (Claude's own settings and plans).
 */
export function compareWithGuess(repo: string, seen: string[], guessed: string[], windows: boolean, isCode: (path: string) => boolean): Comparison {
  const mine = (rel: string) => isCode(rel) && !/(^|\/)\.claude\//.test(rel)
  const counted = seen.filter(mine).map(p => underRoot(repo, p))
  const guessHere = guessed.filter(p => mine(relativeTo(repo, p, windows) ?? ''))
  const seenKeys = new Set(counted.map(p => normalPath(p, windows)))
  const guessKeys = new Set(guessHere.map(p => normalPath(p, windows)))
  return {
    gitOnly: counted.filter(p => !guessKeys.has(normalPath(p, windows))),
    guessOnly: guessHere.filter(p => !seenKeys.has(normalPath(p, windows))),
  }
}

/** `path` relative to `root` (both full), as `normalPath` reads them, or undefined when it is not under it. */
export function relativeTo(root: string, path: string, windows: boolean): string | undefined {
  // `C:` (a repository at a drive's root, as git spells it) is `C:/`.
  const r = normalPath(/^[A-Za-z]:$/.test(root) ? `${root}/` : root, windows, false)
  const p = normalPath(path, windows, false)
  const base = r.endsWith('/') ? r : `${r}/`
  const same = windows ? p.toLowerCase().startsWith(base.toLowerCase()) : p.startsWith(base)
  return same && p.length > base.length ? p.slice(base.length) : undefined
}

/** The root in `roots` that holds `path`: the deepest, so a file in a repository nested in another goes to the inner one. */
export function repoFor(roots: readonly string[], path: string, windows: boolean): string | undefined {
  return roots.filter(r => relativeTo(r, path, windows) !== undefined).sort((a, b) => b.length - a.length)[0]
}

/** Whether `path` is full, as the look reads it: a drive (`C:/`, `/c/`) or a network path on Windows, a leading `/` elsewhere. */
export function isFullPath(path: string, windows: boolean): boolean {
  const p = normalPath(path, windows, false)
  return windows ? /^[A-Za-z]:\//.test(p) || /^\/\/[^/]+\/[^/]+/.test(p) : p.startsWith('/')
}

/** `rel` under the root `repo`, with one slash between them (a repository at `/` has no slash to add). */
export function underRoot(repo: string, rel: string): string {
  return repo.endsWith('/') ? `${repo}${rel}` : `${repo}/${rel}`
}
