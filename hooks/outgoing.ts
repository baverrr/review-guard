// review-guard's check of what leaves this machine: what a git commit or push would send, and the
// user's config of personal terms. It runs git and gitleaks through `Host`, so the hooks (through the
// engine's `$`) and the MCP server (through Node) run the same code.
import {
  addedLines,
  type Finding,
  type GitAction,
  githubRepo,
  scanDiff,
  scanFile,
  scanLine,
  type SentLine,
} from './scan.ts'
import { candidates, gitleaksFindings, type Scanner, SCANNERS, VERSION_ARGS } from './scanners.ts'

/**
 * What a program run gives back. Each output stream is kept up to 4 MiB (the engine's limit, which the
 * MCP server's host keeps too); past that it is cut to its first 4 MiB and its flag is set.
 */
export type RunResult = { exitCode: number; stdout: string; stderr: string; isStdoutTruncated: boolean; isStderrTruncated?: boolean }

/** The most of a file `Host.read` reads, and of each output stream `Host.run` keeps: the engine's limit. */
export const MAX_BYTES = 4 * 1024 * 1024

/**
 * What the check needs from where it runs: running a program, reading a file and seeing whether one
 * exists, the home folder, and the mod's own folder. Paths given to it are absolute.
 */
export type Host = {
  /**
   * Runs argv with no shell. Rejects when the program can't start and when it runs past `timeoutMs`
   * (then the message should say it timed out, so a slow scanner counts as broken, not missing). Must
   * set `isStdoutTruncated` when stdout was cut: the check treats that as too much to check.
   */
  run: (argv: string[], init?: { stdin?: string; cwd?: string; env?: Record<string, string>; timeoutMs?: number }) => Promise<RunResult>
  /** Reads a whole text file. Throws for one it can't or won't read whole (over `MAX_BYTES`). */
  read: (path: string) => Promise<string>
  /** Whether a path exists. Throws when that can't be told (no permission), never answers false then. */
  exists: (path: string) => Promise<boolean>
  /** The home folder from `homeFrom`, or undefined when it can't be known. */
  home: () => Promise<string | undefined>
  /** The mod's own folder: gitleaks runs there, where no config of its own can wave a finding through. */
  pluginRoot: string
}

/**
 * The home folder from USERPROFILE (Windows) or HOME: forward slashes, no trailing slash, and undefined
 * for a value that is empty or blank. Both hosts use this, so they agree.
 */
export function homeFrom(userProfile: string | undefined, home: string | undefined): string | undefined {
  const value = [userProfile, home].find(v => v !== undefined && v.trim() !== '')
  return value?.trim().replace(/\\/g, '/').replace(/(?<=.)\/+$/, '')
}

/** The user's config: personal terms to look for, repos where IPs and MACs may go, values let through. */
export type Config = { readonly personal: readonly string[]; readonly allowNetworkInfo: readonly string[]; readonly allowValues: readonly string[] }

const CONFIG_NAME = '.claude/review-guard.json'

/** A scanner's program (`exe`), or why one that is there would not run (`broken`); neither: not installed. */
type Located = { exe?: string; broken?: string }

// Scanners found so far, for the life of this module (a hook module load, or an MCP server process).
// Only a working one is kept: a missing or broken one is looked for again next time, so one installed
// (or unblocked) later is used without reloading the mod.
const located = new Map<Scanner, Promise<Located>>()

// A run that failed because the program was there but too slow: Node's host says "timed out"; the
// engine's own wording isn't documented, so anything else from a bare name still means "not on PATH".
const TOO_SLOW = /timed? ?out|timeout|still running/i

/**
 * Where a scanner is. A file that is there but does not run (blocked, half downloaded, too slow on its
 * first start) is `broken`, never "not installed"; only nothing at any place, and nothing on PATH, is.
 * A name on PATH that starts but exits with an error, or that times out, is broken too.
 */
function locate(host: Host, tool: Scanner): Promise<Located> {
  let found = located.get(tool)
  if (!found) {
    found = (async (): Promise<Located> => {
      const home = await host.home().catch(() => undefined)
      const windows = /^[A-Za-z]:\//.test(home ?? '')
      for (const exe of candidates(tool, home, windows)) {
        const isPath = exe.includes('/')
        if (isPath) {
          let there: boolean
          try {
            there = await host.exists(exe)
          } catch (err) {
            return { broken: `${exe} can't be checked: ${err instanceof Error ? err.message : String(err)}` }
          }
          if (!there) continue
        }
        try {
          const r = await host.run([exe, ...VERSION_ARGS[tool]], { timeoutMs: 30_000 })
          if (r.exitCode === 0) return { exe }
          return { broken: `${exe} exited ${r.exitCode}: ${r.stderr.trim().slice(0, 150) || 'no message'}` }
        } catch (err) {
          const message = err instanceof Error ? err.message : String(err)
          if (isPath || TOO_SLOW.test(message)) return { broken: `${exe} would not run: ${message}` }
          // A bare name that would not start: not on PATH, so try the next place.
        }
      }
      return {}
    })()
    located.set(tool, found)
    void found.then(l => { if (!l.exe) located.delete(tool) }, () => located.delete(tool))
  }
  return found
}

/**
 * The review scanners that run here (`found`, a scanner to its program), and why each one that is there
 * would not run or could not be looked for (`problems`), so none of those is called "not installed".
 * Never throws.
 */
export async function findScanners(host: Host): Promise<{ found: Map<Scanner, string>; problems: Map<Scanner, string> }> {
  const tools = SCANNERS.filter(t => t !== 'gitleaks')
  const results = await Promise.all(tools.map(t => locate(host, t).catch((err): Located => ({
    broken: `looking for it failed: ${err instanceof Error ? err.message : String(err)}`,
  }))))
  // Without the home folder the usual places were never searched, so "not installed" is not known.
  // (Only here, for the review: gitleaks' own lookup keeps saying "not installed" with its note.)
  const homeKnown = (await host.home().catch(() => undefined)) !== undefined
  const found = new Map<Scanner, string>()
  const problems = new Map<Scanner, string>()
  tools.forEach((t, i) => {
    const l = results[i]
    if (l?.exe) found.set(t, l.exe)
    else if (l?.broken) problems.set(t, l.broken)
    else if (!homeKnown) problems.set(t, 'the home folder is not known, so only PATH was searched')
  })
  return { found, problems }
}

/**
 * gitleaks on what is about to leave: a commit or push (messages, added lines, new files' text), a GitHub
 * write, or text given to the MCP server's check_text. Not installed: nothing, and a note. There but
 * broken, failing, timing out, or with no full report: throws, so a hook stops the command and an MCP
 * tool reports an error. Its own ways to wave a finding through are shut, so allowValues stays the only
 * one: `--ignore-gitleaks-allow` for `gitleaks:allow` comments, the mod's own folder as the working folder
 * and ignore path (no `.gitleaks.toml` or `.gitleaksignore` there), and the config variables emptied.
 */
export async function gitleaksScan(host: Host, sent: readonly SentLine[], notes: string[]): Promise<Finding[]> {
  const { exe, broken } = await locate(host, 'gitleaks')
  if (broken) throw new Error(`gitleaks is installed but would not run (${broken})`)
  if (!exe) {
    notes.push('gitleaks is not installed, so only the built-in checks ran')
    return []
  }
  if (sent.length === 0) return []
  const root = host.pluginRoot
  const r = await host.run(
    [exe, 'stdin', '--no-banner', '--exit-code', '0', '--report-format', 'json', '--report-path', '-', '--log-level', 'error',
      '--ignore-gitleaks-allow', '--gitleaks-ignore-path', root],
    { stdin: sent.map(s => s.text).join('\n'), cwd: root, env: { GITLEAKS_CONFIG: '', GITLEAKS_CONFIG_TOML: '' }, timeoutMs: 120_000 },
  )
  if (r.isStdoutTruncated) throw new Error('gitleaks failed: its report was cut short')
  if (r.exitCode !== 0) throw new Error(`gitleaks failed (exit ${r.exitCode}): ${r.stderr.trim().slice(0, 200) || 'no message'}`)
  return gitleaksFindings(r.stdout, sent.map(s => s.where))
}

async function configPath(host: Host): Promise<string | undefined> {
  const home = await host.home()
  return home ? `${home}/${CONFIG_NAME}` : undefined
}

const CONFIG_KEYS = ['personal', 'allowNetworkInfo', 'allowValues'] as const

/**
 * The user's config. With no file there, the secret checks still run and `note` says what was skipped.
 * A file that is there but can't be read, or is wrong (bad JSON, a misspelt key, a value that is not a
 * list of text, an `allowNetworkInfo` entry that is not owner/repo), throws, so a hook stops the command
 * and an MCP tool reports an error: a typo or a locked file must not quietly turn the personal checks off.
 */
export async function loadConfig(host: Host): Promise<{ config: Config; note?: string }> {
  const empty: Config = { personal: [], allowNetworkInfo: [], allowValues: [] }
  const note = 'personal details were NOT checked (no ~/.claude/review-guard.json)'
  const path = await configPath(host)
  if (!path) return { config: empty, note: 'personal details were NOT checked (the home folder is not known)' }
  let text: string
  try {
    if (!(await host.exists(path))) return { config: empty, note }
    text = await host.read(path)
  } catch (err) {
    throw new Error(`~/.claude/review-guard.json can't be read: ${err instanceof Error ? err.message : String(err)}`)
  }
  let raw: unknown
  const json = text.replace(/^﻿/, '') // Windows PowerShell writes a byte-order mark
  try {
    raw = JSON.parse(json)
  } catch (err) {
    // Never the parser's own message: it quotes the text around the mistake, which may be a personal term.
    const at = /position (\d+)/.exec(err instanceof Error ? err.message : '')?.[1]
    const line = at === undefined ? undefined : json.slice(0, Number(at)).split('\n').length
    throw new Error(`~/.claude/review-guard.json is not valid JSON${line === undefined ? '' : ` (near line ${line})`}`)
  }
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) throw new Error('review-guard.json must be a JSON object')
  const fields = raw as Record<string, unknown>
  const unknown = Object.keys(fields).filter(k => !(CONFIG_KEYS as readonly string[]).includes(k))
  if (unknown.length > 0) throw new Error(`review-guard.json has a key it does not know: ${unknown.join(', ')}`)
  const list = (key: (typeof CONFIG_KEYS)[number]): string[] => {
    const v = fields[key]
    if (v === undefined) return []
    if (!Array.isArray(v) || v.some(x => typeof x !== 'string')) throw new Error(`review-guard.json: "${key}" must be a list of text values`)
    return (v as string[]).map(x => x.trim()).filter(x => x !== '')
  }
  const allowNetworkInfo = list('allowNetworkInfo')
  // An entry the guard can't read as a GitHub repo would be ignored without a word: say so instead.
  const bad = allowNetworkInfo.filter(r => githubRepo(r) === undefined)
  if (bad.length > 0) throw new Error(`review-guard.json: ${bad.length} "allowNetworkInfo" entr${bad.length === 1 ? 'y is' : 'ies are'} not owner/repo or a GitHub URL`)
  return { config: { personal: list('personal'), allowNetworkInfo, allowValues: list('allowValues') } }
}

// What git must not do while the check reads a repository, each of which the repository's own config can
// set up: run a file system monitor command, or take the index lock to refresh the index (a commit the
// user runs at that moment would fail). Filter drivers are turned off by `noFilters`, textconv drivers by
// `--no-textconv` on diff and log. quotePath only keeps file names readable.
const SAFE_GIT = ['--no-optional-locks', '-c', 'core.fsmonitor=false', '-c', 'core.quotePath=false']

// The git commands here that read files in the working tree, and so would run a filter driver on them.
const READS_WORK_TREE = new Set(['diff', 'status'])

/**
 * `-c` options that turn off every filter driver the config names (`filter.<name>.clean`, `.smudge` or
 * `.process`): `git diff` and `git status` run a file's clean filter, a command the repository chooses,
 * to compare it. Throws when the names can't be read, or a name can't be written as a `-c` option.
 */
async function noFilters(host: Host, base: string[]): Promise<string[]> {
  const r = await host.run([...base, 'config', '--name-only', '--get-regexp', '^filter\\..+\\.(clean|smudge|process)$'], { timeoutMs: 30_000 })
  if (r.exitCode === 1 && !r.stdout.trim()) return [] // no filter driver set
  if (r.exitCode !== 0) throw new Error(`git config failed (exit ${r.exitCode}): ${r.stderr.trim().slice(0, 200) || 'no message'}`)
  const names = new Set(r.stdout.split('\n').flatMap(k => /^filter\.(.+)\.(?:clean|smudge|process)$/i.exec(k.trim())?.[1] ?? []))
  if ([...names].some(n => n.includes('='))) throw new Error('a filter driver in the git config has "=" in its name, so it could not be turned off')
  return [...names].flatMap(n => ['clean', 'smudge', 'process'].flatMap(k => ['-c', `filter.${n}.${k}=`]).concat(['-c', `filter.${n}.required=false`]))
}

/** Runs git with what it must not do turned off (see SAFE_GIT and noFilters). */
export async function git(host: Host, dir: string | undefined, args: string[], timeoutMs = 60_000) {
  const base = dir ? ['git', '-C', dir, ...SAFE_GIT] : ['git', ...SAFE_GIT]
  const filters = READS_WORK_TREE.has(args[0] ?? '') ? await noFilters(host, base) : []
  return host.run([...base, ...filters, ...args], { timeoutMs })
}

/** The repository's GitHub remote URLs, or [] when it has none (then nothing goes to GitHub). */
export async function githubRemotes(host: Host, dir: string | undefined): Promise<string[]> {
  const r = await git(host, dir, ['remote', '-v'])
  if (r.exitCode !== 0) {
    // Not a repository: git itself will refuse the commit or push. Any other failure (a folder this
    // check could not open) must not pass as "no GitHub remote", so it stops the command.
    if (/not a git repository/i.test(r.stderr)) return []
    throw new Error(`git remote failed in ${dir ?? 'the session folder'} (exit ${r.exitCode}): ${r.stderr.trim().slice(0, 200) || 'no message'}`)
  }
  return [...new Set(r.stdout.split('\n').map(l => l.split(/\s+/)[1] ?? '').filter(u => /github\.com/i.test(u)))]
}

const MAX_NEW_FILES = 300

/** Runs git and throws when it fails: a check that could not run must stop the command, not pass it. */
async function gitOk(host: Host, dir: string | undefined, args: string[], what: string, timeoutMs = 60_000) {
  const r = await git(host, dir, args, timeoutMs)
  if (r.exitCode !== 0) throw new Error(`${what} failed (exit ${r.exitCode}): ${r.stderr.trim().slice(0, 200) || 'no message'}`)
  return r
}

const TOO_MUCH = (what: string): Finding => ({ kind: `more ${what} than can be checked at once (do it in smaller steps)`, where: 'this commit or push' })

// Revisions that a push names but that don't exist yet (a branch the same command creates).
const NO_SUCH_REVISION = /unknown revision|bad revision|ambiguous argument/i

/**
 * What a commit or push would send, checked. `notes` collects what could only be partly checked, for the
 * user to see. Throws when git can't run a needed step, so a check that couldn't run never passes.
 */
export async function findingsFor(host: Host, action: GitAction, config: Config, notes: string[]): Promise<Finding[]> {
  const { dir } = action
  const out: Finding[] = []
  // What goes out, for gitleaks: one entry per line it reads, with where that line came from. Each text is
  // one line (every source is split on newlines first), so gitleaks' line i + 1 is `sent[i]`.
  const sent: SentLine[] = []
  const send = (diff: string) => sent.push(...addedLines(diff))
  // Who the commits will say made them.
  for (const v of ['GIT_AUTHOR_IDENT', 'GIT_COMMITTER_IDENT']) {
    const who = v === 'GIT_AUTHOR_IDENT' ? 'author' : 'committer'
    const r = await git(host, dir, ['var', v])
    if (r.exitCode === 0) out.push(...scanLine(r.stdout, `the commit's ${who}`, config.personal))
    else notes.push(`the commit's ${who} could not be read (git var: ${r.stderr.trim().slice(0, 120) || `exit ${r.exitCode}`}), so it was not checked`)
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
    const diffArgs = ['diff', '--no-color', '--no-ext-diff', '--no-textconv', '-U0']
    const staged = await gitOk(host, dir, [...diffArgs, '--cached'], 'git diff --cached')
    if (staged.isStdoutTruncated) out.push(TOO_MUCH('staged changes'))
    out.push(...scanDiff(staged.stdout, config.personal))
    send(staged.stdout)
    if (action.addsFiles) {
      // The same command stages more first: scan the working tree's changes and new files too.
      const tracked = await gitOk(host, dir, diffArgs, 'git diff')
      if (tracked.isStdoutTruncated) out.push(TOO_MUCH('changes'))
      out.push(...scanDiff(tracked.stdout, config.personal))
      send(tracked.stdout)
      // New files are listed from the top of the repository, not the command's folder: `git add -A`
      // stages all of them, and the names git prints are then relative to where they are read from.
      const top = (await gitOk(host, dir, ['rev-parse', '--show-toplevel'], 'git rev-parse')).stdout.trim()
      const untracked = await gitOk(host, top, ['ls-files', '--others', '--exclude-standard'], 'git ls-files')
      const files = untracked.stdout.split('\n').filter(Boolean)
      if (untracked.isStdoutTruncated || files.length > MAX_NEW_FILES) out.push(TOO_MUCH('new files'))
      let nameOnly = 0
      for (const rel of files.slice(0, MAX_NEW_FILES)) {
        try {
          const text = await host.read(`${top}/${rel}`)
          out.push(...scanFile(rel, text, config.personal))
          text.split('\n').forEach((l, i) => sent.push({ text: l, where: `${rel}:${i + 1}` }))
        } catch {
          // Over MAX_BYTES or unreadable: still check its name, and say so.
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
    const logArgs = ['log', '-p', '--no-color', '--no-ext-diff', '--no-textconv', '-U0',
      '--format=COMMIT %h%nAUTHOR %an <%ae>%nCOMMITTER %cn <%ce>%n%B']
    const upstream = await git(host, dir, ['rev-parse', '--abbrev-ref', '--symbolic-full-name', '@{u}'])
    const current = upstream.exitCode === 0 ? ['@{u}..HEAD'] : ['HEAD', '--not', '--remotes']
    const named = action.refs.length > 0 || action.allBranches || action.tags
    const heads = action.refs.length > 0 ? action.refs : action.allBranches ? [] : ['HEAD']
    const wanted = [...heads, ...(action.allBranches ? ['--branches'] : []), ...(action.tags ? ['--tags'] : []), '--not', '--remotes']
    let log = await git(host, dir, [...logArgs, ...(named ? wanted : current)], 120_000)
    // A branch the same command creates does not exist yet: check the current one instead, and say so.
    // Any other failure stops the check: falling back would leave the named branches or tags unchecked.
    if (log.exitCode !== 0 && named && NO_SUCH_REVISION.test(log.stderr)) {
      notes.push('a branch or tag the push names does not exist yet, so only the current branch was checked')
      log = await git(host, dir, [...logArgs, ...current], 120_000)
    }
    if (log.exitCode !== 0) {
      // A repository with no commit yet has nothing waiting; the commit this command makes was checked above.
      const empty = /does not have any commits yet|unknown revision|bad revision/i.test(log.stderr)
      if (!(empty && action.commits)) throw new Error(`git log failed (exit ${log.exitCode}): ${log.stderr.trim().slice(0, 200) || 'no message'}`)
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
  out.push(...(await gitleaksScan(host, sent, notes)))
  return out
}
