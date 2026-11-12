// review-guard's scanner: pure functions over text, no engine calls, so they are easy to test.
//
// What it looks for in what is about to reach GitHub: keys and tokens, private keys, secret
// assignments, MAC and IPv4 addresses, sensitive file names, and the person's own terms
// (name, email, usernames) read from a local config file, never written in this code.

export type Finding = {
  kind: string
  where: string // "path:line", "commit message", "author", ...
  network?: boolean // a MAC or IP: allowed in repos the config lists
  value?: string // what matched: compared with allowValues, never shown
}

type Detector = { kind: string; re: RegExp; network?: boolean; keep?: (m: RegExpExecArray, line: string) => boolean }

const IPV4 = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g

// Addresses that say nothing about anyone's network: loopback, "any", broadcast, and the three
// ranges set aside for documentation and examples (RFC 5737), which no real network uses.
function isHarmlessIp(ip: string, line: string, index: number): boolean {
  if (/^(127\.|0\.0\.0\.0$|255\.|192\.0\.2\.|198\.51\.100\.|203\.0\.113\.)/.test(ip)) return true
  // A version number like "v1.2.3.4" or "2.16.0.1-beta" is not an address.
  const before = line.slice(Math.max(0, index - 1), index)
  if (/[vV.\d]/.test(before)) return true
  // "version" counts only just before the number ("version": "1.2.3.4"), not anywhere on the line,
  // so a one-line JSON file with a version field and a real address still has the address caught.
  return /\bversion\b\W{0,6}$/i.test(line.slice(Math.max(0, index - 16), index))
}

const PLACEHOLDER = /(\$\{|\$\(|os\.environ|getenv|process\.env|<[^>]*>|example|changeme|your[_-]|x{6,}|\*{4,}|placeholder|dummy|redacted|\.\.\.)/i

const DETECTORS: Detector[] = [
  { kind: 'private key', re: /-----BEGIN [A-Z ]*PRIVATE KEY-----/g },
  { kind: 'AWS access key', re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { kind: 'GitHub token', re: /\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})/g },
  { kind: 'API key (sk-...)', re: /\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}/g },
  { kind: 'Slack token', re: /\bxox[abprs]-[A-Za-z0-9-]{10,}/g },
  { kind: 'Google API key', re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { kind: 'JSON web token', re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g },
  {
    kind: 'secret in an assignment',
    re: /\b(?:api[_-]?key|secret|token|passw(?:or)?d|pwd|auth[_-]?key|access[_-]?key|client[_-]?secret)[A-Za-z_]*["']?\s*[:=]\s*["']?([A-Za-z0-9_\-\/+=.]{16,})/gi,
    keep: (m, line) => {
      const value = m[1] ?? ''
      return /[A-Za-z]/.test(value) && /\d/.test(value) && !PLACEHOLDER.test(line)
    },
  },
  {
    kind: 'MAC address',
    re: /\b[0-9A-Fa-f]{2}([:-])(?:[0-9A-Fa-f]{2}\1){4}[0-9A-Fa-f]{2}\b/g,
    network: true,
    // 00:00:5e:00:53:xx is set aside for documentation (RFC 7042): no real device has it.
    // One run straight into more octets (00:00:5e:00:53:aa:bb:...) is not a documentation address.
    keep: (m, line) =>
      !/^00[:-]00[:-]5e[:-]00[:-]53[:-]/i.test(m[0]) || /^[:-][0-9A-Fa-f]{2}/.test(line.slice(m.index + m[0].length)),
  },
  { kind: 'IP address', re: IPV4, network: true, keep: (m, line) => !isHarmlessIp(m[0], line, m.index) },
]

const SENSITIVE_FILE = /(^|\/)(\.env(\.(?!example$|sample$|template$)[^/]*)?|id_(rsa|ed25519|ecdsa|dsa)|[^/]+\.(pem|key|p12|pfx|kdbx)|\.netrc|\.npmrc|credentials(\.json)?)$/i

export function sensitiveFile(path: string): boolean {
  return SENSITIVE_FILE.test(path.replace(/\\/g, '/'))
}

/** Findings in one line of text; `where` says where it came from. */
export function scanLine(line: string, where: string, personal: readonly string[]): Finding[] {
  const out: Finding[] = []
  for (const d of DETECTORS) {
    d.re.lastIndex = 0
    for (let m = d.re.exec(line); m; m = d.re.exec(line)) {
      if (!d.keep || d.keep(m, line)) {
        // Every match is kept: if the first is one the user allowed, a second on the same line must still be seen.
        out.push({ kind: d.kind, where, network: d.network, value: d.kind === 'secret in an assignment' ? m[1] : m[0] })
      }
      if (m[0].length === 0) d.re.lastIndex++
    }
  }
  const lower = line.toLowerCase()
  personal.forEach((term, i) => {
    if (term && lower.includes(term.toLowerCase())) out.push({ kind: `your personal info (term ${i + 1} in the config)`, where })
  })
  return out
}

/**
 * Walks a unified diff: `onFile` each time a file is named (its `diff --git` line and again its `+++` line,
 * so usually twice; a binary file once), `onAdded` for each added
 * line with the file and new line number it lands on. Removed and context lines are not reported.
 */
function walkDiff(diff: string, onFile: (file: string) => void, onAdded: (line: string, where: string) => void): void {
  let file = '(unknown file)'
  let lineNo = 0
  for (const raw of diff.split('\n')) {
    const line = raw.replace(/\r$/, '')
    const header = /^\+\+\+ (?:b\/)?(.*)$/.exec(line)
    if (header) {
      const name = header[1] ?? ''
      file = name === '/dev/null' || name === '' ? file : name
      onFile(file)
      continue
    }
    // A binary file has no "+++" line, so a key store (.p12, .kdbx) is named only here.
    const start = /^diff --git a\/.* b\/(.*)$/.exec(line)
    if (start) {
      file = start[1] ?? file
      onFile(file)
      continue
    }
    if (line.startsWith('--- ')) continue
    const hunk = /^@@ -\d+(?:,\d+)? \+(\d+)/.exec(line)
    if (hunk) {
      lineNo = Number(hunk[1])
      continue
    }
    if (line.startsWith('+')) {
      onAdded(line.slice(1), `${file}:${lineNo}`)
      lineNo++
    } else if (!line.startsWith('-') && !line.startsWith('\\')) {
      lineNo++
    }
  }
}

/** Findings in a unified diff: only added lines, with their file and new line number. */
export function scanDiff(diff: string, personal: readonly string[]): Finding[] {
  const out: Finding[] = []
  walkDiff(
    diff,
    file => { if (sensitiveFile(file)) out.push({ kind: 'a sensitive file (keys, .env or credentials)', where: file }) },
    (line, where) => out.push(...scanLine(line, where, personal)),
  )
  return out
}

/** One line of text an outside scanner reads, and where it came from ("app.py:3", "the commit message"). */
export type SentLine = { text: string; where: string }

/** The added lines of a diff, each with the file and line it lands on, for an outside scanner. */
export function addedLines(diff: string): SentLine[] {
  const out: SentLine[] = []
  walkDiff(diff, () => {}, (text, where) => out.push({ text, where }))
  return out
}

/** Findings in a whole file's text (an untracked file about to be added). */
export function scanFile(path: string, text: string, personal: readonly string[]): Finding[] {
  const out: Finding[] = sensitiveFile(path) ? [{ kind: 'a sensitive file (keys, .env or credentials)', where: path }] : []
  text.split('\n').forEach((line, i) => out.push(...scanLine(line, `${path}:${i + 1}`, personal)))
  return out
}

/**
 * Findings in a tool call's input or a command: every text value, line by line, so one long JSON
 * line cannot hide a quoted secret, and every `path` checked as a file name.
 */
export function scanValue(value: unknown, where: string, personal: readonly string[]): Finding[] {
  if (typeof value === 'string') {
    const lines = value.split('\n')
    return lines.flatMap((l, i) => scanLine(l, lines.length > 1 ? `${where}, line ${i + 1}` : where, personal))
  }
  if (Array.isArray(value)) return value.flatMap((v, i) => scanValue(v, `${where}[${i}]`, personal))
  if (typeof value !== 'object' || value === null) return []
  return Object.entries(value).flatMap(([key, v]) => [
    ...(key === 'path' && typeof v === 'string' && sensitiveFile(v) ? [{ kind: 'a sensitive file (keys, .env or credentials)', where: v }] : []),
    ...scanValue(v, `${where} "${key}"`, personal),
  ])
}

/** A tool call's text values as lines for an outside scanner, each named as `scanValue` names it. */
export function valueLines(value: unknown, where: string): SentLine[] {
  if (typeof value === 'string') {
    const lines = value.split('\n')
    return lines.map((text, i) => ({ text, where: lines.length > 1 ? `${where}, line ${i + 1}` : where }))
  }
  if (Array.isArray(value)) return value.flatMap((v, i) => valueLines(v, `${where}[${i}]`))
  if (typeof value !== 'object' || value === null) return []
  return Object.entries(value).flatMap(([key, v]) => valueLines(v, `${where} "${key}"`))
}

/** Keeps one finding per kind and place. Drops network findings where allowed, and any
 * whose matched value the user listed in allowValues. */
export function settle(findings: Finding[], allowNetwork: boolean, allowValues: readonly string[] = []): Finding[] {
  const seen = new Set<string>()
  const allowed = new Set(allowValues.map(v => v.toLowerCase()))
  return findings.filter(f => {
    if (allowNetwork && f.network) return false
    if (f.value !== undefined && allowed.has(f.value.toLowerCase())) return false
    const key = `${f.kind}|${f.where}`
    if (seen.has(key)) return false
    seen.add(key)
    return true
  })
}

/** What the model is told: kinds and places only, never the value found. */
export function report(findings: Finding[], action: string): string {
  const shown = findings.slice(0, 25).map(f => `- ${f.kind} at ${f.where}`)
  const more = findings.length > 25 ? [`- and ${findings.length - 25} more`] : []
  return [
    `review-guard stopped this ${action}: it would send personal or secret data to GitHub.`,
    ...shown,
    ...more,
    'Remove or replace each one (write where a secret lives, never its value; write %USERPROFILE% or ~ instead',
    'of a home folder path), then try again. Do not try to get around this check. If one is a false alarm, tell the',
    'user which and why: only they decide, by adding it to "allowValues" in ~/.claude/review-guard.json.',
  ].join('\n')
}

/** "owner/repo" from a GitHub remote URL or from a config entry, lower case; undefined when it is neither. */
export function githubRepo(urlOrName: string): string | undefined {
  const m = /(?:github\.com[:/]+)?([\w.-]+\/[\w.-]+?)(?:\.git)?\/?$/i.exec(urlOrName.trim())
  return m?.[1]?.toLowerCase()
}

/** MAC and IP addresses may go out only when every GitHub remote is a repository the user listed, by its exact name. */
export function networkAllowed(remotes: readonly string[], allowed: readonly string[]): boolean {
  const names = new Set(allowed.map(githubRepo).filter(Boolean))
  return remotes.length > 0 && remotes.every(u => names.has(githubRepo(u)))
}

// Where a prompt comes from when the user asked for something: typed, from a phone, a schedule
// they set, a Slack message of theirs. Everything else (an agent's report, a task notice, another
// session, an unlabelled engine message) is part of whatever is already running.
const USER_REQUEST = new Set(['composer', 'bridge', 'sdk', 'scheduled-trigger', 'slack-ping', 'channel'])

/**
 * Whether a prompt is a new request from the user. One that arrives during a review ends it early,
 * so what follows gets a review of its own. A review also ends by itself once no agent is still out,
 * so a report of a kind this list does not know cannot hold a review open.
 */
export function isNewRequest(originKind: string, isMeta: boolean, asUser = false): boolean {
  if (isMeta) return false
  return USER_REQUEST.has(originKind) || (originKind === 'plugin' && asUser)
}

// --- reading git commands -----------------------------------------------------------------

export type GitAction = {
  kind: 'commit' | 'push' // the label: 'push' when the command does both
  commits: boolean
  pushes: boolean
  dir?: string
  addsFiles: boolean
  message: string
  /** What a push names to send (`git push origin main` gives ['main']); empty means the current branch. */
  refs: string[]
  allBranches: boolean
  tags: boolean
}

function unquote(s: string): string {
  return s.replace(/^"(.*)"$/s, '$1').replace(/^'(.*)'$/s, '$1')
}

/** Git Bash paths (/c/Users/...) as native git on Windows reads them. */
export function nativePath(p: string): string {
  const m = /^\/([a-zA-Z])\/(.*)$/.exec(p)
  return m ? `${(m[1] ?? '').toUpperCase()}:/${m[2] ?? ''}` : p
}

/**
 * The folder a command names, as git on this machine reads it. No shell runs the check, so `~` and
 * `$HOME` are filled in here; Git Bash paths become native on Windows only (on Linux /d/work is a real folder).
 */
export function resolveDir(dir: string, home: string | undefined, windows: boolean): string {
  const d = home ? dir.replace(/^(~|\$HOME|\$\{HOME\})(?=$|[\\/])/, () => home.replace(/\\/g, '/')) : dir
  return windows ? nativePath(d) : d
}

// Words that come before the program a command runs, in Bash and PowerShell.
const BEFORE_PROGRAM = new Set(['sudo', 'exec', 'command', 'time', 'env', 'nohup', '{', '!', 'if', 'then', 'else', 'elif', 'do', 'while', 'until'])

/**
 * The command with everything ssh runs on another machine blanked out (same length, so positions
 * hold): the rest of that one command, and a heredoc fed to it. What is left runs here, so
 * `ssh host 'x' && git push` keeps its local push.
 *
 * When in doubt it blanks nothing: a quote that never closes, or a heredoc whose end line never
 * comes, leaves the whole command visible. A remote command checked by mistake is the safe error;
 * a local push hidden by mistake is not.
 */
export function localPart(command: string): string {
  const n = command.length
  const chars = command.split('')
  const blank = (from: number, to: number) => {
    for (let k = from; k < to; k++) if (chars[k] !== '\n') chars[k] = ' '
  }
  // Steps over quoted text, escapes and # comments, and stops at the first character outside them
  // that `stops` matches. `open` says whether a quote was still open at the end.
  const until = (i: number, stops: (c: string, at: number) => boolean): { at: number; open: boolean } => {
    let quote = ''
    for (; i < n; i++) {
      const c = command[i] ?? ''
      if (quote) {
        if (c === quote) quote = ''
        else if (c === '\\' && quote === '"') i++
      } else if (c === '"' || c === "'") quote = c
      else if (c === '\\') i++
      else if (stops(c, i)) break
      else if (c === '#' && /\s/.test(command[i - 1] ?? ' ')) {
        // A comment runs to the end of the line; an apostrophe in it opens no quote.
        const nl = command.indexOf('\n', i)
        i = (nl === -1 ? n : nl) - 1
      }
    }
    return { at: Math.min(i, n), open: quote !== '' }
  }
  const wordEnd = (i: number) => until(i, c => /[\s;|&()<>]/.test(c)).at
  // A command ends at ; | & or a newline; the & of 2>&1 and &> is not an end.
  const commandEnd = (i: number) =>
    until(i, (c, at) => c === ';' || c === '|' || c === '\n' || (c === '&' && command[at - 1] !== '>' && command[at + 1] !== '>'))
  // The end word of a heredoc started in command[from, to), outside quotes; `<<<` is a here-string, not one.
  const heredocWord = (from: number, to: number): string | undefined => {
    let word: string | undefined
    until(from, (c, at) => {
      if (at >= to) return true
      if (c === '<' && command[at + 1] === '<' && command[at + 2] !== '<' && command[at - 1] !== '<') {
        const m = /^<<-?[ \t]*(?:'([^'\n]+)'|"([^"\n]+)"|([^\s'"<>;|&()]+))/.exec(command.slice(at, to))
        word = m?.[1] ?? m?.[2] ?? m?.[3]
        if (word !== undefined) return true
      }
      return false
    })
    return word
  }

  // Only a real ssh command counts: the program a command runs, outside quotes. The word "ssh" in
  // another command's text (`echo "use ssh"`, a commit message, GIT_SSH_COMMAND=...) blanks nothing.
  let i = 0
  let first = true // the next word is the program a command runs
  // Inside `timeout [options] DURATION program`, the program comes after the duration. `options`: after
  // `timeout`, skipping its flags until the first non-flag word, the duration. `value`: the last flag
  // takes the next word as its value (`-k 5`, `--signal KILL`; `--signal=KILL` is one word).
  let timeout: 'off' | 'options' | 'value' = 'off'
  while (i < n) {
    const c = command[i] ?? ''
    if (c === '>' || c === '<') {
      i += command[i + 1] === '&' ? 2 : 1
    } else if (c === '&' && command[i + 1] === '>') {
      i += 2
    } else if (c === ';' || c === '|' || c === '&' || c === '(' || c === ')' || c === '\n') {
      first = true
      timeout = 'off'
      i++
    } else if (/\s/.test(c)) {
      i++
    } else {
      const end = Math.max(wordEnd(i), i + 1)
      const word = unquote(command.slice(i, end))
      if (timeout !== 'off') {
        if (timeout === 'value') timeout = 'options'
        else if (/^(?:-[ks]|--kill-after|--signal)$/.test(word)) timeout = 'value'
        else if (!word.startsWith('-')) timeout = 'off' // the duration: the program is next
        i = end
        continue
      }
      if (first && /^(?:.*[\\/])?timeout(?:\.exe)?$/i.test(word)) {
        timeout = 'options'
        i = end
        continue
      }
      if (!first || BEFORE_PROGRAM.has(word) || /^[A-Za-z_]\w*=/.test(word)) {
        i = end
        continue
      }
      first = false
      if (!/(?:^|[\\/])ssh(?:\.exe)?$/i.test(word)) {
        i = end
        continue
      }
      const stop = commandEnd(end)
      // A quote that never closes: blank nothing. And ssh's ProxyCommand and LocalCommand run their
      // command on this machine (`ssh -o ProxyCommand='sh x.sh' host`), so that ssh line stays visible.
      if (stop.open || /\b(?:ProxyCommand|LocalCommand|PermitLocalCommand)\b/i.test(command.slice(end, stop.at))) {
        i = end
        continue
      }
      const here = heredocWord(end, stop.at)
      if (here === undefined) {
        blank(i, stop.at)
        i = stop.at
        continue
      }
      // A heredoc fed to it starts on the next line and runs to its end word alone on a line.
      const body = command.indexOf('\n', stop.at)
      const escaped = here.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
      // nosemgrep: javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp -- the end word is escaped above and the pattern has no nested repeats
      const close =body === -1 ? null : new RegExp(String.raw`\n[ \t]*${escaped}[ \t]*(?=\n|$)`).exec(command.slice(body))
      if (body === -1 || !close) {
        i = end // its end line never comes: blank nothing
        continue
      }
      blank(i, stop.at)
      const after = body + close.index + close[0].length
      blank(body, after)
      i = after
    }
  }
  return chars.join('')
}

/** A commit or push this shell command is about to make on this machine, and where. */
export function gitAction(command: string): GitAction | undefined {
  // What ssh runs elsewhere is blanked, and so is the text of a script written here only to be sent to
  // ssh (`cat > x.sh <<'EOF'` ... `ssh host 'bash -s' < x.sh`): its git commands run on the other machine.
  const joined = command.replace(/\\\n/g, ' ')
  const cmd = blankDataBodies(joined, localPart(joined))
  const push = /\bgit\b[^;&|\n]*?\bpush\b([^;&|\n]*)/.exec(cmd)
  const ghPush = /\bgh\s+repo\s+create\b[^;&|\n]*--push\b/.exec(cmd)
  const commit = /\bgit\b[^;&|\n]*\bcommit\b/.exec(cmd)
  const isPush = push !== null || ghPush !== null
  const isCommit = commit !== null
  if (!isPush && !isCommit) return undefined
  const path = String.raw`("[^"]+"|'[^']+'|[^\s;&|]+)`
  // The folder in effect at the first commit or push: the last one changed to before it, not after.
  const at = Math.min(...[push, ghPush, commit].filter(m => m !== null).map(m => m.index))
  let dir: string | undefined
  for (const m of cmd.matchAll(new RegExp(String.raw`\b(?:cd|pushd|Set-Location)\s+(?:-(?:Literal)?Path\s+)?` + path, 'gi'))) {
    if (m.index < at) dir = unquote(m[1] ?? '')
  }
  const dashC = new RegExp(String.raw`\bgit\s+-C\s+` + path).exec(cmd)
  if (dashC) dir = unquote(dashC[1] ?? '')
  const source = new RegExp(String.raw`--source[=\s]+` + path).exec(cmd)
  if (source) dir = unquote(source[1] ?? '')
  const messages = [...cmd.matchAll(/(?:-m|--message)[=\s]+("(?:[^"\\]|\\.)*"|'[^']*'|\S+)/g)].map(m => unquote(m[1] ?? ''))
  const heredoc = /<<-?\s*'?(\w+)'?\n([\s\S]*?)\n\1\b/.exec(cmd)
  if (heredoc && /\bcommit\b/.test(cmd)) messages.push(heredoc[2] ?? '')
  // What the push names: `git push [options] <remote> <ref>...`. Words that are not plain ref names
  // (a redirect, a variable) are left out, and the current branch is checked instead.
  const words = (push?.[1] ?? '').trim().split(/\s+/).filter(Boolean).map(unquote)
  const deletes = words.some(w => w === '--delete' || w === '-d')
  const refs = deletes ? [] : words.filter(w => !w.startsWith('-')).slice(1)
    .map(w => w.replace(/^\+/, '').split(':')[0] ?? '')
    .filter(w => /^[\w./@-]+$/.test(w))
  return {
    kind: isPush ? 'push' : 'commit',
    commits: isCommit,
    pushes: isPush,
    dir, // as written in the command: resolveDir makes it a path git can open
    addsFiles: /\bgit\b[^;&|\n]*\badd\b/.test(cmd) || /\bcommit\b[^;&|\n]*\s-(?:a|am|[a-z]*a[a-z]*)\b/.test(cmd) || /\bcommit\b[^;&|\n]*--all\b/.test(cmd),
    message: messages.join('\n'),
    refs,
    allBranches: words.some(w => w === '--all' || w === '--mirror' || w === '--branches'),
    tags: words.some(w => w === '--tags' || w === '--follow-tags' || w === '--mirror'),
  }
}

/**
 * Whether a shell command writes text to GitHub through the gh tool (a pull request, an issue, a
 * comment, a release, a gist, an API write): its own text is then what gets checked.
 */
export function ghWrites(command: string): boolean {
  if (/\bgh\s+(?:pr|issue|release|gist|label|discussion)\s+(?:create|edit|comment|review|close|reopen|merge|upload)\b/.test(command)) return true
  return /\bgh\s+api\b/.test(command) && /(?:\s-X\s*|--method[=\s]+)(?:POST|PUT|PATCH|DELETE)\b|\s(?:-f|-F|--field|--raw-field|--input)\b/i.test(command)
}

// --- which reviews a change needs -----------------------------------------------------------

/** Every language label, declared once: the tables below and scanners.ts are checked against it. */
export const LANGUAGE_NAMES = ['Docker', 'dependencies', 'Python', 'TypeScript', 'JavaScript', 'HTML templates', 'C#', 'C/C++',
  'Shell', 'PowerShell', 'SQL', 'Go', 'Rust', 'Java/Kotlin', 'other code', 'GitHub Actions', 'config', 'CSS'] as const
export type Language = typeof LANGUAGE_NAMES[number]

const LANGUAGES: [RegExp, Language][] = [
  [/(^|\/)(Dockerfile[^/]*|[^/]*compose[^/]*\.ya?ml)$/i, 'Docker'],
  // What a project pulls in: a change here can bring in a package with known holes.
  [/(^|\/)(package(-lock)?\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|requirements[^/]*\.(txt|in|lock)|pyproject\.toml|uv\.lock|poetry\.lock|Pipfile(\.lock)?|[^/]+\.csproj|packages\.lock\.json|Directory\.Packages\.props|go\.(mod|sum)|Cargo\.(toml|lock)|Gemfile(\.lock)?)$/i, 'dependencies'],
  [/\.py$/i, 'Python'],
  [/\.(ts|tsx|mts|cts)$/i, 'TypeScript'],
  [/\.(js|jsx|mjs|cjs)$/i, 'JavaScript'],
  [/\.(html?|jinja2?|j2|vue|svelte)$/i, 'HTML templates'],
  [/\.cs$/i, 'C#'],
  [/\.(c|cc|cpp|cxx|h|hpp)$/i, 'C/C++'],
  [/\.(sh|bash|zsh)$/i, 'Shell'],
  [/\.(ps1|psm1|psd1)$/i, 'PowerShell'],
  [/\.sql$/i, 'SQL'],
  [/\.go$/i, 'Go'],
  [/\.rs$/i, 'Rust'],
  [/\.(java|kt|kts)$/i, 'Java/Kotlin'],
  [/\.(rb|php|swift|lua|dart)$/i, 'other code'],
  [/(^|\/)\.github\/workflows\/[^/]+\.ya?ml$/i, 'GitHub Actions'],
  [/\.(ya?ml|toml|ini|conf)$/i, 'config'],
  [/\.css$/i, 'CSS'],
]

/** The language of a code file, or undefined for notes, data and everything else. */
export function languageOf(path: string): Language | undefined {
  const p = path.replace(/\\/g, '/')
  if (/(^|\/)(\.git|node_modules|\.venv|dist|build|__pycache__)\//.test(p)) return undefined
  return LANGUAGES.find(([re]) => re.test(p))?.[1]
}

// Commands that write files without the Edit or Write tool: in-place editors, copies, patches,
// PowerShell's file cmdlets, and scripts that open a file for writing.
const SHELL_WRITE = new RegExp([
  String.raw`\bsed\s+(?:-\S+\s+)*-[a-zA-Z]*i`, String.raw`\bperl\s+(?:-\S+\s+)*-[a-zA-Z]*i`, String.raw`\btee\b`,
  String.raw`\b(?:cp|mv|patch)\s`, String.raw`\bgit\s+apply\b`,
  String.raw`\b(?:Set-Content|Add-Content|Out-File|Copy-Item|Move-Item)\b`,
  String.raw`\bwrite_(?:text|bytes)\b`, String.raw`\bwriteFile(?:Sync)?\b`, String.raw`\bWriteAll(?:Text|Lines|Bytes)\b`,
  String.raw`\bopen\([^)]*,\s*["'][wax]`, String.raw`\.write\(`, String.raw`\btruncate(?:Sync)?\b`,
  String.raw`\bsort\b[^;&|\n]*\s(?:-[a-zA-Z]*o|--output)`, // `-o`, `-uo`, `--output=`
  // Formatters and fixers rewrite the files they are given.
  String.raw`--write\b`, String.raw`--fix\b`, String.raw`\b(?:black|autopep8|rustfmt)\s`, String.raw`\bgofmt\s+-\w*w`, String.raw`\bdotnet\s+format\b`,
].join('|'), 'i')

// PowerShell's and cmd's own copies, moves and writes (`copy`, `cpi`, `mi`, `ren`, `sc`, `iwr`, ...), as a
// command. Short words like these are everyday words too ("Move scan.ts later"), so this is only tested
// on a command's text outside its here-document bodies, and only where a command starts.
const SHELL_WRITE_PS = /(?:^|[;&|({\n]\s*)(?:copy|cpi|move|mi|ren|rni|robocopy|xcopy|sc|ac|ni|iwr)\s|\b(?:Rename-Item|New-Item|Expand-Archive|Invoke-WebRequest)\b/i

/**
 * A here-document body and, from its opener's line, the command that reads it (`python -I -`, `cat > n.md`).
 * `quoted` is `<<'EOF'`: bash then takes the body as it is, with no `$`, backtick or backslash expansion.
 */
type Heredoc = {
  text: string; reader: string; piped: boolean; quoted: boolean
  /**
   * The opener's line, and the body's lines [from, to): indexes into `command.split('\n')` of the very
   * string given to `heredocs`, never into `outside` (which drops body lines). With no terminator, `to`
   * is the end of the command, and `complete` is false.
   */
  line: number; from: number; to: number
}

/**
 * A command's own lines with every here-document body taken out, and the bodies on their own. Openers
 * are looked for only outside quotes and `#` comments, so `echo "use <<EOF"` or `cout << endl` in a string
 * opens nothing, and a body ends only on a line that is exactly its terminator, as in bash (leading tabs
 * dropped for `<<-`). `complete` is false when the split is a guess: a body with no terminator, a quote
 * left open at the end of a line, a backtick, or process substitution. Nothing may be trusted on a guess.
 */
function heredocs(command: string): { outside: string; bodies: Heredoc[]; complete: boolean } {
  const lines = command.split('\n')
  const outside: string[] = []
  const bodies: Heredoc[] = []
  let complete = true
  for (let i = 0; i < lines.length; i++) {
    const line = (lines[i] ?? '').replace(/\r$/, '')
    outside.push(line)
    const masked = line
      .replace(/<<(-?)\s*(["'])([A-Za-z_][\w-]*)\2/g, '<<$1\x01$3') // keep a quoted terminator's name, marked
      .replace(/"[^"]*"|'[^']*'/g, '""')
      .replace(/(^|\s)#.*$/, '$1')
    // A backslash can escape a quote (`-"\" <<EOF"`), which the masking above can't follow.
    if (/["'`\\]/.test(masked.replace(/""/g, '')) || line.includes('\\') || /[<>]\(/.test(masked)) complete = false
    const opener = i // a second heredoc on this line starts after the first one's body, but opens here
    const OPENER = /(?<!<)<<(?!<)(-?)\s*(\x01?)([A-Za-z_][\w-]*)/g
    // A `<<` this parser can't read (`<<'EO F'`, `<<$'EOF'`, `<<'1E'`), or a name that runs on past what it
    // reads (`<<EOF.`): bash ends that body on another line than this parser would, so the split is a guess.
    if (/(?<!<)<<(?!<)/.test(masked.replace(OPENER, ''))) complete = false
    for (const m of masked.matchAll(OPENER)) {
      if (!/^(?:$|[\s;&|<>()])/.test(masked.slice((m.index ?? 0) + m[0].length))) complete = false
      const before = masked.slice(0, m.index).split(/[;&|(]/).pop() ?? ''
      const after = masked.slice((m.index ?? 0) + m[0].length).split(/[;&]/)[0] ?? ''
      const ends = (l: string) => (m[1] ? l.replace(/^\t+/, '') : l).replace(/\r$/, '') === m[3]
      const from = i + 1
      const body: string[] = []
      while (i + 1 < lines.length && !ends(lines[i + 1] ?? '')) body.push(lines[++i] ?? '')
      const to = i + 1
      if (i + 1 < lines.length) i++ // the terminator line
      else complete = false
      const [reads = '', ...rest] = after.split('|')
      bodies.push({ text: body.join('\n'), reader: `${before} ${reads}`.trim(), piped: rest.length > 0, quoted: m[2] !== '', line: opener, from, to })
    }
  }
  return { outside: outside.join('\n'), bodies, complete }
}

// Strip a command's path and `.exe`: `.venv/bin/python3.exe` is `python3`.
const commandName = (word: string) => word.replace(/^.*[\/\\]/, '').replace(/\.exe$/i, '').toLowerCase()
// Interpreters whose script, run outside the here-documents, is only run. perl is left out on purpose
// (`perl -pi -e ... app.py` edits the file it names), and so is deno (`deno eval` runs inline code).
const INTERPRETER = /^(?:python[\d.]*|py|node|bun|bash|sh|zsh|pwsh|powershell)$/
// Outside the here-documents, every command must be an interpreter or one of these, which write nothing
// but their redirects (caught on their own). Anything else (`git checkout`, `rsync`, `unzip`, `ruff
// format`, `chmod +x gen && ./gen`) might write code, so the exception is off.
// (`sort -o` and `uniq in out` write, so they are not here.)
const READ_ONLY = /^(?:cat|echo|printf|ls|dir|tail|head|grep|rg|wc|cd|pwd|true|get-content|get-childitem|select-object|select-string|write-output|write-host)$/
// The flags an interpreter may have and still be running a file (or stdin), never inline code or a module.
// Listing the bad ones misses spellings (`python -Ic`, `node -pe`, `node --eval`, `deno eval`), so these
// are the only ones: Python's isolation, buffering and warning flags, the `py` launcher's version, and
// PowerShell's `-File`. A flag that takes a value (`-X utf8`, `-W ignore`) takes the next word with it.
const SAFE_FLAG = /^-(?:[IuBEsSO]+|OO|\d+(?:\.\d+)?(?:-(?:32|64))?|NoProfile|NonInteractive|NoLogo|File)$/i
const FLAG_WITH_VALUE = /^-[XW]$/
/**
 * What an interpreter command runs: its script, `-` for stdin, `''` for nothing named (it reads stdin),
 * or undefined when a flag is not on the list and might mean inline code or a module.
 */
function runTarget(words: string[]): string | undefined {
  const takesFlags = /^(?:python[\d.]*|py|pwsh|powershell)$/.test(commandName(words[0] ?? '')) // node, bun, shells: none
  for (let i = 1; i < words.length; i++) {
    const w = words[i] ?? ''
    if (w === '-' || !w.startsWith('-')) return w
    if (!takesFlags) return undefined
    if (FLAG_WITH_VALUE.test(w)) i++
    else if (!SAFE_FLAG.test(w)) return undefined
  }
  return ''
}
// Names that reach any function without calling it by a listed name (`eval`, `getattr`, `exec`,
// `process`, `globalThis`, `fs['x']`, dynamic `import()`), or a `/`: Python's path join (`Path('a') / name`)
// builds a name OPENS can't see. Division, a Node regex and a `//` comment are caught too: that only costs a review.
const RISKY_CODE = /\b(?:exec|eval|compile|__import__|importlib|builtins|__builtins__|__dict__|__class__|getattr|setattr|delattr|globals|locals|vars|breakpoint|runpy|global|globalThis|process|module|Function|constructor|prototype|__proto__|Bun|Deno)\b|\bimport\s*\(|\b(?:fs|\))\s*\[|\//
// Every call that opens a file, or loads a module, must take a plain string literal, then `,` or `)`.
// Anything else (a slice, `%`, a variable, `scandir` entries, `o = open`) may name a code file.
// A path takes exactly one: `Path('src', '..', 'app.py')` joins its parts.
const OPENS = /\b(?:open|openSync|require|writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream)\b(?!\s*\(\s*""\s*[,)])|\b(?:Path|PurePath|PosixPath|WindowsPath)\b(?!\s*\(\s*""\s*\))/
// The file names those calls open, read from the unmasked body.
const OPENED = /\b(?:open|openSync|Path|PurePath|PosixPath|WindowsPath|writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream)\s*\(\s*(?:"([^"\n]*)"|'([^'\n]*)')/g
// Modules a trusted body may load: none of them reaches a process or another file but through the calls below.
const SAFE_MODULES = new Set(['json', 'datetime', 'pathlib', 'time', 'textwrap', 're', 'sys', 'fs', 'node:fs'])
// The only functions and attributes a trusted body may use. Python and Node have more ways to write a
// file than any list of them (`io.FileIO`, `fs.WriteStream`, `fs.truncateSync`), so instead every call
// and every `.name` must be one of these: the openers above (which must take a literal), and calls that
// read, format or print. A function the body defines itself is not here either, so it is not trusted.
const SAFE_NAMES = new Set([
  // control flow and Python builtins that write nothing
  'if', 'elif', 'for', 'while', 'with', 'return', 'not', 'and', 'or', 'in', 'print', 'len', 'str', 'int', 'float',
  'bool', 'list', 'dict', 'set', 'tuple', 'sorted', 'reversed', 'enumerate', 'range', 'zip', 'min', 'max', 'sum',
  'any', 'all', 'isinstance', 'repr', 'round', 'abs', 'map', 'filter',
  // opening (checked by OPENS) and reading or writing an opened file
  'open', 'Path', 'pathlib', 'write', 'write_text', 'read', 'read_text', 'readlines', 'exists', 'is_file', 'is_dir',
  'mkdir', 'require', 'writeFileSync', 'appendFileSync', 'readFileSync', 'existsSync', 'mkdirSync', 'fs',
  // strings, lists and dicts (not `replace`: `Path('a').replace('b')` moves a file)
  'strip', 'rstrip', 'lstrip', 'split', 'splitlines', 'lower', 'upper', 'title', 'startswith', 'endswith', 'encode',
  'join', 'format', 'ljust', 'rjust', 'zfill',
  'append', 'extend', 'insert', 'pop', 'get', 'items', 'keys', 'values', 'update', 'count', 'index', 'find',
  'push', 'forEach', 'trim', 'includes', 'toString', 'padStart', 'padEnd', 'length',
  // json, dates and console output
  'json', 'dump', 'dumps', 'load', 'loads', 'JSON', 'stringify', 'parse', 'console', 'log', 'datetime', 'date',
  'now', 'today', 'isoformat', 'strftime', 'toISOString', 'Date',
  // regular expressions, and UTF-8 output on Windows (`sys.stdout.reconfigure(encoding='utf-8')`)
  're', 'sub', 'match', 'search', 'findall', 'fullmatch', 'group', 'sys', 'stdout', 'reconfigure',
])
// A name the body calls (`name(`) or reaches (`.name`), or imports (`from os import truncate`).
function usedNames(plain: string): string[] {
  const names = [...plain.matchAll(/(?<![\w.])([A-Za-z_]\w*)\s*\(|\.\s*([A-Za-z_]\w*)/g)].map(m => m[1] ?? m[2] ?? '')
  for (const m of plain.matchAll(/^\s*from\s+\S+\s+import\s+(.+)$/gm)) names.push(...(m[1] ?? '').split(/[\s,()]+/).filter(n => n && n !== 'as'))
  return names
}
// Modules a body loads: `import a, b as c`, `from a.b import c`, `require('fs')`.
function loadedModules(text: string): string[] {
  const mods: string[] = []
  for (const m of text.matchAll(/^\s*import\s+([^"'\n]+)$/gm)) mods.push(...(m[1] ?? '').split(',').map(s => s.trim().split(/\s+/)[0] ?? ''))
  for (const m of text.matchAll(/^\s*from\s+(\S+)\s+import\b/gm)) mods.push(m[1] ?? '')
  // Node: `require('fs')`, and for ES imports the module, not the name it is bound to (`import fs from 'x'`).
  for (const m of text.matchAll(/\b(?:require\s*\(|from|import)\s*(?:"([^"\n]*)"|'([^'\n]*)')/g)) mods.push(m[1] ?? m[2] ?? '')
  return mods
}
// The same file spelled two ways (`./gen.txt`, `gen.txt`, `GEN.TXT` on Windows) is one file.
const sameFile = (name: string) => name.replace(/\\/g, '/').replace(/^(?:\.\/)+/, '').toLowerCase()

const REDIRECT = /\d?>>?\s*([^\s<>]+)/g

/**
 * Code files that a command only runs, never writes, so they need no review, and the command's own text
 * outside its here-documents (what the bodies say is not a mention). Kept narrow on purpose, as an
 * allowlist: every command outside is an interpreter or a read-only tool, and every here-document is
 * either `cat` data or Python/Node code read from stdin whose every file-opening call takes a plain
 * literal that is not code (Claude writing notes, then running a script). Anything else, or anything the
 * bodies write being run afterwards, and the run scripts count again.
 */
function onlyRun(command: string): { outside: string; runs: Map<string, number> } | undefined {
  const { outside, bodies, complete } = heredocs(command)
  // `--pre`: `rg --pre bash` runs a program on every file it reads, so rg is not read-only then.
  if (!complete || outside.includes('$') || /--pre\b/.test(outside) || SHELL_WRITE.test(outside) || SHELL_WRITE_PS.test(outside)) return undefined
  const written = new Set<string>() // what the bodies write: running one of these runs new code
  for (const body of bodies) {
    if (body.piped) return undefined // `cat <<EOF | bash`: the body goes on to something else
    if (!body.quoted && /[$`\\]/.test(body.text)) return undefined // bash expands an unquoted body first
    const targets = [...body.reader.matchAll(REDIRECT)].map(m => m[1] ?? '')
    const reader = body.reader.replace(REDIRECT, '').trim()
    if (targets.includes('""')) return undefined // a quoted target was masked: its name is unknown
    targets.forEach(t => written.add(sameFile(t)))
    if (/^(?:\S*[\\/])?cat(?:\.exe)?(?:\s+-\S*)*$/i.test(reader)) {
      // Data, written where the redirect says. But a body that holds a writer is a script a later command
      // may run (`bash /tmp/fix`, a git hook), so its text counts. (`blankDataBodies` has already emptied
      // the ones sent to ssh.)
      if (SHELL_WRITE.test(body.text)) return undefined
      continue
    }
    // Only Python or Node reading the body as its code: not a shell, a script reading stdin, or inline code.
    const words = reader.split(/\s+/)
    if (!/^(?:python[\d.]*|py|node|bun)$/.test(commandName(words[0] ?? '')) || !['', '-'].includes(runTarget(words) ?? 'x')) return undefined
    const plain = body.text.replace(/"[^"\n]*"|'[^'\n]*'/g, '""')
    // A name built in code (`'a' + b`, a slice, `%`, `'app.p' 'y'`) can't reach a write: OPENS wants a plain literal.
    if (RISKY_CODE.test(plain) || OPENS.test(plain)) return undefined
    if (usedNames(plain).some(n => !SAFE_NAMES.has(n)) || /\}\s*=/.test(plain)) return undefined // `{truncateSync} = require('fs')`
    if (loadedModules(body.text).some(m => !SAFE_MODULES.has(m))) return undefined
    for (const m of body.text.matchAll(OPENED)) {
      const name = m[1] ?? m[2] ?? ''
      // Plain ASCII only: an escape (`'app\x2epy'`) or another script could spell a code file's name. And
      // no trailing dot or space: Windows opens `app.py.` and `app.py ` as `app.py`.
      if (!/^[A-Za-z0-9 _.\/-]*[A-Za-z0-9_]$/.test(name) || languageOf(name)) return undefined
      written.add(sameFile(name))
    }
  }
  const masked = outside.replace(/"[^"\n]*"|'[^'\n]*'/g, '""').replace(/\d*>&\d+/g, '')
  const runs = new Map<string, number>()
  for (const cmd of masked.split(/&&|\|\||[;&\n]/)) {
    for (const [i, part] of cmd.split('|').entries()) {
      const words = part.replace(/<<-?\s*(?:""|[\w-]+)/g, '').replace(REDIRECT, '')
      if (words.includes('<')) return undefined // `bash < gen.txt` runs a file the bodies may have written
      const argv = words.trim().split(/\s+/)
      const name = commandName(argv[0] ?? '')
      if (!name) continue
      if (!INTERPRETER.test(name)) {
        if (READ_ONLY.test(name)) continue
        return undefined
      }
      const target = runTarget(argv)
      if (i > 0 || target === undefined) return undefined // reads a pipe, or a flag that may be inline code
      if (target) runs.set(target, (runs.get(target) ?? 0) + 1)
    }
  }
  // Any word naming a file the bodies wrote may run it (`python -X utf8 gen.txt`, `sh ./gen`).
  const words = outside.replace(REDIRECT, '').split(/[\s;&|()]+/).map(w => sameFile(w.replace(/["']/g, '')))
  if (words.some(w => written.has(w))) return undefined
  return { outside, runs }
}

// Outside the here-documents, the only commands under which a data body is not trusted to stay data:
// none of them runs a file (`cat` reads one). Shell keywords open and close loops whose commands are checked too.
const RUNS_NOTHING = new Set(['cat', 'mkdir', 'sleep', 'date', 'export', 'for', 'done', 'fi', 'esac', 'else'])

/**
 * `local` (the command after `localPart`) with the bodies of its data here-documents blanked, lines
 * kept so the split still holds. A data body is a quoted here-document read by `cat` alone (bash expands
 * nothing in it) that goes either onto the screen (`cat <<'EOF'`) or into a file this same command then
 * sends to ssh (`cat > "$S/x.sh" <<'EOF'` ... `ssh host 'bash -s' < "$S/x.sh"`), which runs it on
 * another machine. A body written to any other file stays: a later command may run it (`bash x`, `make`,
 * a git hook), and a write of code this command can't see is still a write of code.
 *
 * Kept narrow, as an allowlist: every command outside the bodies must be a read-only tool or one in
 * RUNS_NOTHING (`bash`, `python`, `xargs`, `eval`, `.`, `read` loops and anything unknown run something,
 * so nothing is blanked), and none may hold `$(...)`, a backtick, `--pre` (`rg --pre bash` runs a
 * program), or anything that could make `cat` another program (a PATH assignment, a function or an
 * alias). Nothing is blanked when the heredoc split is a guess, and a body that is piped on or shares
 * its opener line with another heredoc is kept.
 */
function blankDataBodies(full: string, local: string): string {
  const command = local
  const { outside, bodies, complete } = heredocs(command)
  if (!complete || /\$\(|`|--pre\b|\bPATH=|\(\s*\)|\b(?:function|alias)\b/.test(outside.replace(/'[^'\n]*'/g, "''"))) return command
  const masked = outside.replace(/"[^"\n]*"|'[^'\n]*'/g, '""').replace(/\d*>&\d+/g, '')
  for (const cmd of masked.split(/&&|\|\||[;&|\n]/)) {
    const words = cmd.replace(/<<-?\s*(?:""|[\w-]+)/g, '').replace(REDIRECT, '').trim().split(/\s+/)
    while (words.length && (BEFORE_PROGRAM.has(words[0] ?? '') || /^[A-Za-z_]\w*=/.test(words[0] ?? ''))) words.shift()
    if (commandName(words[0] ?? '') === 'timeout') { // `timeout [options] DURATION program`, as in localPart
      words.shift()
      while (words[0]?.startsWith('-')) if (/^(?:-[ks]|--kill-after|--signal)$/.test(words.shift() ?? '')) words.shift()
      words.shift() // the duration
    }
    const name = commandName(words[0] ?? '')
    if (name && !READ_ONLY.test(name) && !RUNS_NOTHING.has(name)) return command
  }
  const lines = command.split('\n')
  const perLine = new Map<number, number>()
  for (const b of bodies) perLine.set(b.line, (perLine.get(b.line) ?? 0) + 1)
  // Whether `full` feeds this file, spelled as the opener spells it, to a command `localPart` blanked (ssh).
  const sentToSsh = (target: string) => {
    // nosemgrep: javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp -- target is escaped in place and the pattern has no nested repeats
    const re =new RegExp(String.raw`(?<!<)<\s*["']?${target.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}["']?(?=$|[\s;&|)])`, 'g')
    return [...full.matchAll(re)].some(m => !local.slice(m.index ?? 0, (m.index ?? 0) + m[0].length).trim())
  }
  for (const b of bodies) {
    if (!b.quoted || b.piped || perLine.get(b.line) !== 1) continue
    if (!/^(?:\S*[\\/])?cat(?:\.exe)?(?:\s+-\S*)*$/i.test(b.reader.replace(REDIRECT, '').trim())) continue
    // Every redirect target on the opener's line, as spelled there (the masked reader hides quoted names).
    const targets = [...(lines[b.line] ?? '').matchAll(/(?<![0-9&<])\d?>>?\s*("[^"]+"|'[^']+'|[^\s;&|<>()]+)/g)].map(m => unquote(m[1] ?? ''))
    if (!targets.every(t => t === '/dev/null' || sentToSsh(t))) continue // a file left here may run later
    for (let k = b.from; k < b.to; k++) lines[k] = ''
  }
  return lines.join('\n')
}

/**
 * The code files a shell command writes, as the command names them. A redirect counts for its target
 * alone. When anything else in the command writes, every code file it names counts, which can include
 * one it only reads (`cp a.py b.py`, a loop over files, `ls a.py | xargs sed -i`): an extra review is the
 * safer mistake than a change nobody looked at. Three things are left out: what ssh runs on another
 * machine (`localPart`), the text of data here-documents nothing here runs (`blankDataBodies`), and a
 * script run after here-documents that only write notes (`onlyRun`). The caller leaves out two more: the
 * scripts a command only ran, shown by their file being the same before and after (`runOnlyScripts`), and
 * Claude's scratch files (`inScratch`).
 */
export function shellWrites(fullCommand: string): string[] {
  // What ssh runs on another machine writes no file here, and a data heredoc's text runs nowhere here.
  const command = blankDataBodies(fullCommand, localPart(fullCommand))
  // A wildcard, a variable or a sed pattern is not a file name: `src/*.ts`, `$DIR/a.py`, `hooks\/a.ts`.
  const notAName = (raw: string) => /[*?^$]|\\\//.test(raw)
  const out = new Set<string>()
  for (const m of command.matchAll(/(?<![0-9&>])>>?\s*(?!&)("[^"]+"|'[^']+'|[^\s;&|<>()]+)/g)) {
    if (notAName(m[1] ?? '')) continue
    const target = unquote(m[1] ?? '')
    if (languageOf(target)) out.add(target)
  }
  if (SHELL_WRITE.test(command) || SHELL_WRITE_PS.test(heredocs(command).outside)) {
    const trusted = onlyRun(command)
    // Shell words, quotes kept together: "$DST/hooks/a.ts" is one word, not "$DST" and "/hooks/a.ts".
    const mentions = new Map<string, number>()
    for (const raw of (trusted?.outside ?? command).match(/(?:"[^"]*"|'[^']*'|[^\s;|&<>()`,=[\]{}"'])+/g) ?? []) {
      if (notAName(raw)) continue
      const word = raw.replace(/["']/g, '')
      if (word.length > 2 && !word.startsWith('-') && languageOf(word)) mentions.set(word, (mentions.get(word) ?? 0) + 1)
    }
    for (const [word, count] of mentions) if ((trusted?.runs.get(word) ?? 0) < count) out.add(word)
  }
  return [...out]
}

/** How paths are spelled on this machine: Windows (drive letters, Git Bash `/c/`, any case) or not. */
export type Paths = { windows: boolean; home?: string; userProfile?: string }

// A path as one comparable string: forward slashes, no trailing slash, and on Windows Git Bash's `/c/` as
// `C:/` and lower case (Linux file names are case-sensitive, so they keep theirs).
function comparable(p: string, windows: boolean): string {
  const s = p.trim().replace(/\\/g, '/').replace(/\/+$/, '')
  return windows ? nativePath(s).toLowerCase() : s
}

/**
 * Whether a path is in one of Claude's own scratch folders: a `claude` or `claude-<number>` folder right inside
 * a temp folder (`tempDirs`, the machine's TEMP, TMP and TMPDIR, plus /tmp and /var/tmp when `posixTmp`:
 * the PowerShell tool reads /tmp as C:\tmp). That is where the session's scratchpad and task output live,
 * and code there is throwaway, so it is never sent for review. Anything else in a temp folder, such as a
 * repo cloned to /tmp, still is. A path with a `..`, and a temp folder that is not absolute or is a drive
 * root or `/`, never count.
 */
export function inScratch(path: string, tempDirs: readonly string[], windows: boolean, posixTmp: boolean): boolean {
  const p = comparable(path, windows)
  if (p.split('/').includes('..')) return false
  const roots = [...tempDirs, ...(posixTmp ? ['/tmp', '/var/tmp'] : [])].map(d => comparable(d, windows))
  const claude = windows ? /^claude(?:-\d+)?\/./i : /^claude(?:-\d+)?\/./
  return roots.some(r => /^(?:[a-z]:)?\/[^/]/i.test(r) && p.startsWith(`${r}/`) && claude.test(p.slice(r.length + 1)))
}

// Words that move the shell to another folder, in Bash and PowerShell.
const MOVES = /(?:^|[^\w$.-])(?:cd|chdir|pushd|popd|Set-Location|sl|Push-Location|Pop-Location)(?![\w-])/gi

/**
 * The command's parts split at `;`, `&&`, `||`, `|`, `&` and new lines outside quotes, each as its words
 * (quotes removed, the program first). Undefined when the command has a subshell, a group, a command
 * substitution, a backtick or a background job (`&`) outside quotes: then where and when its parts run
 * is not plain from the text.
 */
function commandParts(text: string): string[][] | undefined {
  const parts: string[][] = []
  let words: string[] = []
  let word = ''
  let quote = ''
  let quoted = false // the word holds a quoted part, so '' is still a word
  const endWord = () => {
    if (word || quoted) words.push(word)
    word = ''
    quoted = false
  }
  const endPart = () => {
    endWord()
    if (words.length) parts.push(words)
    words = []
  }
  for (let i = 0; i < text.length; i++) {
    const ch = text[i] ?? ''
    if (quote) {
      if (ch === quote) quote = ''
      else word += ch
    } else if (ch === '"' || ch === "'") {
      quote = ch
      quoted = true
    } else if ('(){}`'.includes(ch)) {
      return undefined
    } else if (';&|\n'.includes(ch)) {
      if (ch === '&' && /[<>]$/.test(word)) word += ch // `2>&1`, `>&2`: a redirect, not a split
      else if (ch === '&' && text[i + 1] !== '&' && text[i - 1] !== '&') return undefined // a background job
      else endPart()
    } else if (/\s/.test(ch)) {
      endWord()
    } else {
      word += ch
    }
  }
  if (quote) return undefined
  endPart()
  return parts
}

// Programs that start another program and return before it ends: what they start can write later.
const DETACHES = /(?:^|[^\w-])(?:nohup|setsid|disown|Start-Process|Start-Job|saps|start)(?![\w-])/i

/**
 * The scripts a command only runs, each with the file on disk it must be (`python -I gen.py` runs
 * `<folder>/gen.py`). A script counts only when the command, here-document bodies included, names it
 * nowhere but as what an interpreter runs (`sed -i x gen.py; python gen.py` names it twice, so it is out).
 * A relative name is placed only when the command starts by moving to a known folder (`cd /abs && ...`)
 * and nothing else in it moves the shell (another cd, pushd or popd, `source`, an escaped builtin like
 * `c\d`): where the shell stands before the command is not known here. `powershell`: the command is for
 * the PowerShell tool, where `~` and $HOME are the user's profile folder. None when the command starts
 * something in the background, or its here-documents can't be told apart.
 *
 * What it gives is only a candidate: the caller compares the file before and after the command, and only a
 * file the command left as it was is left out of the review.
 */
export function runOnlyScripts(command: string, paths: Paths, powershell = false): Map<string, string> {
  const out = new Map<string, string>()
  const docs = heredocs(command)
  if (!docs.complete) return out
  const outside = docs.outside.replace(/<<-?\s*(?:"[^"]*"|'[^']*'|[\w-]+)/g, ' ')
  const parts = commandParts(outside)
  if (!parts || DETACHES.test(outside)) return out
  // Home spellings: in Bash `~` and $HOME are HOME; in PowerShell they and $env:USERPROFILE are the
  // profile folder. A missing one leaves the name unknown, never filled in from the other.
  const homeHere = powershell ? paths.userProfile : paths.home
  const expand = (p: string): string | undefined => {
    let e = p
    if (/^(?:~|\$HOME|\$\{HOME\})(?=$|[\\/])/.test(e)) e = homeHere ? e.replace(/^(?:~|\$HOME|\$\{HOME\})/, homeHere) : ''
    else if (/^(?:\$USERPROFILE|\$\{USERPROFILE\}|\$env:USERPROFILE)(?=$|[\\/])/i.test(e)) {
      e = paths.userProfile ? e.replace(/^[^\\/]+/, paths.userProfile) : ''
    }
    if (!e || /[$`%*?~]/.test(e)) return undefined
    const f = e.replace(/\\/g, '/')
    return paths.windows ? nativePath(f) : f
  }
  const absolute = (p: string) => (paths.windows ? /^[A-Za-z]:\// : /^\//).test(p)
  // The programs, after `sudo`, `env` and VAR=value.
  const programs = parts.map(argv => {
    const words = [...argv]
    while (words.length && (BEFORE_PROGRAM.has(words[0] ?? '') || /^[A-Za-z_]\w*=/.test(words[0] ?? ''))) words.shift()
    return words
  })
  // The folder the command starts in: only `cd <folder>` as its very first part, and nothing else that
  // moves the shell. `source` and `.` run a file in this shell; in Bash `c\d` is cd.
  let base: string | undefined
  const moves = [...outside.matchAll(MOVES)].length
  const hidden = programs.some(w => /^(?:source|\.)$/.test(w[0] ?? '') || (!powershell && (w[0] ?? '').includes('\\')))
  const first = parts[0] ?? []
  if (moves === 1 && !hidden && /^(?:cd|Set-Location|sl|chdir)$/i.test(first[0] ?? '') && first.length === 2) {
    const dir = expand(first[1] ?? '')
    if (dir && absolute(dir)) base = dir.replace(/\/+$/, '')
  }
  const runs = new Map<string, number>()
  for (const words of programs) {
    if (!INTERPRETER.test(commandName(words[0] ?? ''))) continue
    const target = runTarget(words.filter(w => !/^\d*[<>]/.test(w)))
    if (target && target !== '-') runs.set(target, (runs.get(target) ?? 0) + 1)
  }
  for (const [script, n] of runs) {
    // Named anywhere else, in the command or a here-document body, as a word or inside one: it may be written.
    if (command.split(script).length - 1 !== n) continue
    const s = expand(script)
    if (s === undefined) continue
    const place = absolute(s) ? s : base === undefined ? undefined : `${base}/${s.replace(/^(?:\.\/)+/, '')}`
    if (place !== undefined) out.set(script, place)
  }
  return out
}

/**
 * Whether a command copies or moves files (`cp`, `mv`, `rsync`, `Copy-Item`, `copy`, ...), as a command,
 * not a word in text. A scratch file it names may be the source of a write into the project.
 */
export const COPIES = /(?:^|[;&|({\n]\s*|\b(?:sudo|xargs)\s+)(?:cp|mv|rsync|install|ditto|scp|Copy-Item|Move-Item|Rename-Item|copy|cpi|move|mi|ren|rni|robocopy|xcopy)(?=\s)/i

const SECURITY: Record<Language, string> = {
  Python: 'SQL built from strings, shell=True or os.system with input, eval/exec, pickle or yaml.load, path traversal, requests to URLs from input (SSRF), weak crypto. Run `bandit -q` on the changed files if bandit is installed.',
  TypeScript: 'XSS (innerHTML, dangerouslySetInnerHTML), eval or new Function, child_process with input, prototype pollution, unchecked JSON. Run `npm audit` if a lockfile changed.',
  JavaScript: 'XSS (innerHTML, dangerouslySetInnerHTML), eval or new Function, child_process with input, prototype pollution, unchecked JSON. Run `npm audit` if a lockfile changed.',
  'HTML templates': 'autoescape turned off or |safe on user data, unquoted attributes, inline scripts, forms without CSRF tokens.',
  'C#': 'SQL built from strings, BinaryFormatter or other unsafe deserialization, Process.Start with input, path traversal, secrets in appsettings.',
  'C/C++': 'buffer overflows, format strings, integer overflow, use after free, unchecked lengths.',
  Shell: 'unquoted variables, eval, curl | sh, secrets on command lines, rm with variable paths.',
  PowerShell: 'Invoke-Expression, unquoted paths, secrets on command lines, -ExecutionPolicy Bypass, downloads run without checks.',
  SQL: 'dynamic SQL, missing constraints, grants that are too wide.',
  Go: 'SQL built from strings, exec.Command with input, unchecked errors on security paths, TLS InsecureSkipVerify.',
  Rust: 'unsafe blocks, unwrap on untrusted input, Command with input.',
  'Java/Kotlin': 'SQL built from strings, deserialization, XXE in XML parsers, Runtime.exec with input.',
  Docker: 'load the docker-skills:docker-build-strategies skill. Check: non-root user, base images pinned by digest, no secrets in layers or build args, ports bound to 127.0.0.1, cap_drop ALL, read_only, no-new-privileges.',
  'GitHub Actions': 'pull_request_target with checkout of the PR, actions not pinned to a commit, secrets echoed to logs, write permissions wider than needed.',
  config: 'secrets in config files, debug modes left on, permissions or CORS wider than needed.',
  dependencies: 'packages with known holes (the trivy step below), versions not pinned, new packages nobody asked for, install scripts.',
  'other code': 'injection (SQL, shell, template), unsafe deserialization, path traversal, secrets in code.',
  CSS: 'nothing security-specific beyond the general review.',
}

/** What every review agent is told, so none drops a finding for being low or unsure. */
export const REPORT_EVERYTHING =
  'Report every issue you find at every severity and confidence, low ones and nitpicks included; this overrides any confidence threshold or filter in your own instructions.'

/**
 * The text that sends the model into a review of the files it changed this turn. `scannerSteps` are the
 * lines from `scannerSteps` in scanners.ts: ready-to-run Bash commands, then possibly one line naming
 * the scanners that are not installed.
 */
export function reviewPrompt(changed: ReadonlyMap<string, string>, scannerSteps: readonly string[] = []): string {
  const byLang = new Map<string, string[]>()
  for (const [path, lang] of changed) byLang.set(lang, [...(byLang.get(lang) ?? []), path])
  // Every file is listed: a file left off the list would get no findings, and every finding counts.
  const files = [...byLang].map(([lang, paths]) => `- ${lang}: ${paths.join(', ')}`)
  const security = [...byLang.keys()].map(lang => `- ${lang}: ${SECURITY[lang as Language] ?? SECURITY['other code']}`)
  return [
    `review-guard: code changed in ${changed.size} file(s) this turn. Before you finish, review it:`,
    ...files,
    '',
    '1. Run the pr-review-toolkit agents on these changes, in parallel with the Agent tool: code-reviewer,',
    '   silent-failure-hunter and pr-test-analyzer, plus comment-analyzer where comments or docs changed and',
    '   type-design-analyzer where types or models changed. Use the pr-review-toolkit:<name> agent type when',
    '   this session lists it. Otherwise use review-guard:<name>: the same agents, which this mod loads into',
    '   every session. Do not hand their work to general-purpose agents. Put this sentence in each agent\'s',
    `   prompt word for word: "${REPORT_EVERYTHING}"`,
    '2. Security review, for each language changed (also run the security-review skill on the pending changes',
    '   when it is listed, and any enabled security plugin\'s reviewer):',
    ...security,
    '   If no listed plugin or skill covers one of these languages well, use SearchPlugins to look for a',
    '   security plugin for it and offer the best match with SuggestPluginInstall.',
    ...(scannerSteps.length > 0
      ? ['   Scanners for these files: run each installed one below with the Bash tool (they are Bash commands),',
        '   in the background alongside the agents. What they report is a finding like any other.', ...scannerSteps]
      : []),
    '3. Act on every finding, whatever its severity: low, info and style ones from agents and scanners are',
    '   handled like high ones. "Minor", "style" or "fine here" alone is never a reason to leave one. Each',
    '   finding ends in exactly one of these:',
    '   - Fixed: say which file and line changed.',
    '   - Does not hold up: show why in one line, with the code, path or output that proves it (for example',
    '     that the input cannot come from outside, or that the warning is about test-only code).',
    '   - Holds up but is not fixed here (the fix would break something, there is no fixed version yet, it is',
    '     a large change in code this turn did not touch, or it needs the user\'s decision): say so and why,',
    '     offer a narrow suppression or a follow-up, and never count it as fixed.',
    '   If an agent or scanner fails or returns nothing, say which one and why: that is not a clean result.',
    '   If the fixes were more than small local edits, send them to code-reviewer once more.',
    '4. Rerun the tests (if the project has none, say so) and the scanners after the fixes. Every hit must be',
    '   fixed or already answered in step 3. Stop after three rounds and list what is still open.',
    '5. Tell the user every finding and its outcome, with the test and scanner commands and their final',
    '   results. Commit or push nothing as part of this review unless the user asked for that.',
    'If this turn only changed files the user told you not to review, or was itself this review, say so',
    'in one line and stop.',
  ].join('\n')
}
