// Generated from hooks/scan.ts by scripts/build-mcp.mjs. Do not edit. source-sha256: 950dd2a80f424acdea72aa29a126d9145f02c39961807b6cf5b55bfa723d8dac built-sha256: 42dcc3cc82d4b7967c07d5363e687a280e0170fc0fc911557eff5661531c260e
// review-guard's scanner: pure functions over text, no engine calls, so they are easy to test.
//
// What it looks for in what is about to reach GitHub: keys and tokens, private keys, secret
// assignments, MAC and IPv4 addresses, sensitive file names, and the person's own terms
// (name, email, usernames) read from a local config file, never written in this code.

                       
              
                                                               
                                                                     
                                                                        
 

                                                                                                                     

const IPV4 = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g

// Addresses that say nothing about anyone's network: loopback, "any", broadcast, and the three
// ranges set aside for documentation and examples (RFC 5737), which no real network uses.
function isHarmlessIp(ip        , line        , index        )          {
  if (/^(127\.|0\.0\.0\.0$|255\.|192\.0\.2\.|198\.51\.100\.|203\.0\.113\.)/.test(ip)) return true
  // A match right after a "v", a dot or a digit is part of a version number, not an address.
  const before = line.slice(Math.max(0, index - 1), index)
  if (/[vV.\d]/.test(before)) return true
  // "version" counts only just before the number ("version": "1.2.3.4"), not anywhere on the line,
  // so a one-line JSON file with a version field and a real address still has the address caught.
  return /\bversion\b\W{0,6}$/i.test(line.slice(Math.max(0, index - 16), index))
}

const PLACEHOLDER = /(\$\{|\$\(|os\.environ|getenv|process\.env|<[^>]*>|example|changeme|your[_-]|x{6,}|\*{4,}|placeholder|dummy|redacted|\.\.\.)/i

const DETECTORS             = [
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
    // One that runs straight on into more pairs is not a documentation address, so it is still reported.
    keep: (m, line) =>
      !/^00[:-]00[:-]5e[:-]00[:-]53[:-]/i.test(m[0]) || /^[:-][0-9A-Fa-f]{2}/.test(line.slice(m.index + m[0].length)),
  },
  { kind: 'IP address', re: IPV4, network: true, keep: (m, line) => !isHarmlessIp(m[0], line, m.index) },
]

const SENSITIVE_FILE = /(^|\/)(\.env(\.(?!example$|sample$|template$)[^/]*)?|id_(rsa|ed25519|ecdsa|dsa)|[^/]+\.(pem|key|p12|pfx|kdbx)|\.netrc|\.npmrc|credentials(\.json)?)$/i

export function sensitiveFile(path        )          {
  return SENSITIVE_FILE.test(path.replace(/\\/g, '/'))
}

/** Findings in one line of text; `where` says where it came from. */
export function scanLine(line        , where        , personal                   )            {
  const out            = []
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
function walkDiff(diff        , onFile                        , onAdded                                       )       {
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
export function scanDiff(diff        , personal                   )            {
  const out            = []
  walkDiff(
    diff,
    file => { if (sensitiveFile(file)) out.push({ kind: 'a sensitive file (keys, .env or credentials)', where: file }) },
    (line, where) => out.push(...scanLine(line, where, personal)),
  )
  return out
}

/** One line of text an outside scanner reads, and where it came from ("app.py:3", "the commit message"). */
                                                      

/** The added lines of a diff, each with the file and line it lands on, for an outside scanner. */
export function addedLines(diff        )             {
  const out             = []
  walkDiff(diff, () => {}, (text, where) => out.push({ text, where }))
  return out
}

/** Findings in a whole file's text (an untracked file about to be added). */
export function scanFile(path        , text        , personal                   )            {
  const out            = sensitiveFile(path) ? [{ kind: 'a sensitive file (keys, .env or credentials)', where: path }] : []
  text.split('\n').forEach((line, i) => out.push(...scanLine(line, `${path}:${i + 1}`, personal)))
  return out
}

/**
 * Findings in a tool call's input or a command: every text value, line by line, so one long JSON
 * line cannot hide a quoted secret, and every `path` checked as a file name.
 */
export function scanValue(value         , where        , personal                   )            {
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
export function valueLines(value         , where        )             {
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
export function settle(findings           , allowNetwork         , allowValues                    = [])            {
  const seen = new Set        ()
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
export function report(findings           , action        )         {
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
export function githubRepo(urlOrName        )                     {
  const m = /(?:github\.com[:/]+)?([\w.-]+\/[\w.-]+?)(?:\.git)?\/?$/i.exec(urlOrName.trim())
  return m?.[1]?.toLowerCase()
}

/** MAC and IP addresses may go out only when every GitHub remote is a repository the user listed, by its exact name. */
export function networkAllowed(remotes                   , allowed                   )          {
  const names = new Set(allowed.map(githubRepo).filter(Boolean))
  return remotes.length > 0 && remotes.every(u => names.has(githubRepo(u)))
}

// Where a prompt comes from when the user asked for something: typed, from a phone, a schedule
// they set, a Slack message of theirs. Everything else (an agent's report, a task notice, another
// session, an unlabelled engine message) is part of whatever is already running.
const USER_REQUEST = new Set(['composer', 'bridge', 'sdk', 'scheduled-trigger', 'slack-ping', 'channel'])

/**
 * Whether a prompt is a new request from the user. One that arrives during a review ends it early,
 * so what follows gets a review of its own. A review also ends by itself once none of its agents is still out,
 * so a report of a kind this list does not know cannot hold a review open.
 */
export function isNewRequest(originKind        , isMeta         , asUser = false)          {
  if (isMeta) return false
  return USER_REQUEST.has(originKind) || (originKind === 'plugin' && asUser)
}

// --- reading git commands -----------------------------------------------------------------

                         
                                                                         
                  
                 
              
                    
                 
                                                                                                           
                
                      
               
 

function unquote(s        )         {
  return s.replace(/^"(.*)"$/s, '$1').replace(/^'(.*)'$/s, '$1')
}

/**
 * Git Bash paths (/c/Users/..., or a bare /c) as native Windows reads them (C:/Users/..., C:/). The one
 * place that turns `/c/` into a drive: `comparable`, `samePath`, `keyOf`, `resolveDir`, the run-only
 * script check and the MCP server's built copy all use it.
 */
export function nativePath                  (p               )         {
  const m = /^\/([a-zA-Z])(?:\/(.*))?$/.exec(p          )
  return m ? `${(m[1] ?? '').toUpperCase()}:/${m[2] ?? ''}` : p
}

/**
 * The folder a command names, as git on this machine reads it. No shell runs the check, so `~` and
 * `$HOME` are filled in here; Git Bash paths become native on Windows only (on Linux /d/work is a real folder).
 */
export function resolveDir(dir        , home                    , windows         )         {
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
export function localPart(command        )         {
  const n = command.length
  const chars = command.split('')
  const blank = (from        , to        ) => {
    for (let k = from; k < to; k++) if (chars[k] !== '\n') chars[k] = ' '
  }
  // Steps over quoted text, escapes and # comments, and stops at the first character outside them
  // that `stops` matches. `open` says whether a quote was still open at the end.
  const until = (i        , stops                                    )                                => {
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
  const wordEnd = (i        ) => until(i, c => /[\s;|&()<>]/.test(c)).at
  // A command ends at ; | & or a newline; the & of 2>&1 and &> is not an end.
  const commandEnd = (i        ) =>
    until(i, (c, at) => c === ';' || c === '|' || c === '\n' || (c === '&' && command[at - 1] !== '>' && command[at + 1] !== '>'))
  // The end word of a heredoc started in command[from, to), outside quotes; `<<<` is a here-string, not one.
  const heredocWord = (from        , to        )                     => {
    let word                    
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
  let timeout                              = 'off'
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

/**
 * The text of every heredoc opened on a line that holds a `git ... commit`: the message of
 * `git commit -F - <<'EOF'`, `-m "$(cat <<'EOF'`, `cat <<'EOF' | git commit -F -`, and also of any other
 * heredoc on that line (`git commit -m x && cat > notes.md <<'EOF'`). Reading the line's quotes and
 * operators the way bash does is where earlier versions lost messages (`2>&1`, `--author='R&D'`), so
 * every body there counts: more text scanned, never less. A terminator is a word (letters, digits, `_`,
 * `-`, `.`), bare, after `\` or in quotes, `<<-` too. A body ends only on a line that is exactly its
 * terminator (a `\r` at the line's end dropped, leading tabs dropped for `<<-` alone), so a line like
 * `EOF and more` is still message. With no such line, the rest of the command counts. A here-string on
 * that line (`<<<'text'`) is message too. Undefined when there is no heredoc or here-string there.
 */
function commitHeredoc(cmd        )                     {
  const lines = cmd.split('\n')
  const bodies           = []
  for (let i = 0; i < lines.length; i++) {
    if (!/\bgit\b.*\bcommit\b/i.test(lines[i] ?? '')) continue // `GIT commit` too, as in gitAction
    // Each opener's body follows the one before it, as in bash.
    let j = i + 1
    for (const m of (lines[i] ?? '').matchAll(/(?<!<)<<(?!<)(-?)\s*\\?(["']?)([\w.-]+)\2/g)) {
      const body           = []
      for (; j < lines.length; j++) {
        const line = (lines[j] ?? '').replace(/\r$/, '')
        if ((m[1] ? line.replace(/^\t+/, '') : line) === m[3]) break
        body.push(line)
      }
      j++ // past the terminator line
      bodies.push(body.join('\n'))
    }
    // A here-string is message too: `git commit -F - <<<'text'`.
    for (const m of (lines[i] ?? '').matchAll(/<<<\s*("(?:[^"\\]|\\.)*"|'[^']*'|\S+)/g)) bodies.push(unquote(m[1] ?? ''))
    if (j > i + 1) i = j - 1 // the bodies are message, not lines to look at again
  }
  const text = bodies.filter(Boolean).join('\n')
  return text || undefined // only empty bodies: nothing to add
}

/** A commit or push this shell command is about to make on this machine, and where. */
export function gitAction(command        )                        {
  // What ssh runs elsewhere is blanked, and so is the text of a script written here only to be sent to
  // ssh (`cat > x.sh <<'EOF'` ... `ssh host 'bash -s' < x.sh`): its git commands run on the other machine.
  // So is a quoted `cat` heredoc's text, or Python code read from a heredoc that can start no program, when
  // nothing else in the command runs shell code (`blankWrittenScripts`).
  const joined = command.replace(/\\\n/g, ' ')
  // Bash keeps a `\`-newline as it is inside a quoted heredoc body, but `joined` joins it, so a body's end
  // could move: with one in the command, written bodies are not blanked.
  const local = blankDataBodies(joined, localPart(joined))
  const cmd = /\\\r?\n/.test(command) ? local : blankWrittenScripts(local)
  // A `;`, `&` or `|` inside quotes ends no command (`git -c user.name='A & B' commit`). In `ops` those are
  // made `\x01` (not a word character, so `\bgit` still matches after one), keeping every index, before the
  // git words are looked for. Quotes pair only within a line, and an escaped quote (`it\'s`) is skipped, so
  // an apostrophe in a note or comment can't pair with a quote lines later. A `2>&1` stays: it only ends
  // the search early on a line that has the git words before it.
  const ops = cmd.replace(/\\.|"(?:[^"\\\n]|\\.)*"|'[^'\n]*'/g, q => (q.startsWith('\\') ? q : q.replace(/[;&|]/g, '\x01')))
  // `Git` and `GIT` run git too on Windows, whose file names ignore case.
  const push = /\b[Gg][Ii][Tt]\b[^;&|\n]*?\bpush\b([^;&|\n]*)/.exec(ops)
  const ghPush = /\bgh\s+repo\s+create\b[^;&|\n]*--push\b/.exec(ops)
  const commit = /\b[Gg][Ii][Tt]\b[^;&|\n]*\bcommit\b/.exec(ops)
  // What the push names, read from the command itself at the place `ops` found (quoted words intact).
  const pushArgs = push ? cmd.slice(push.index + push[0].length - (push[1] ?? '').length, push.index + push[0].length) : ''
  const isPush = push !== null || ghPush !== null
  const isCommit = commit !== null
  if (!isPush && !isCommit) return undefined
  const path = String.raw`("[^"]+"|'[^']+'|[^\s;&|]+)`
  // The folder in effect at the first commit or push: the last one changed to before it, not after.
  const at = Math.min(...[push, ghPush, commit].filter(m => m !== null).map(m => m.index))
  let dir                    
  for (const m of cmd.matchAll(new RegExp(String.raw`\b(?:cd|pushd|Set-Location)\s+(?:-(?:Literal)?Path\s+)?` + path, 'gi'))) {
    if (m.index < at) dir = unquote(m[1] ?? '')
  }
  const dashC = new RegExp(String.raw`\bgit\s+-C\s+` + path).exec(cmd)
  if (dashC) dir = unquote(dashC[1] ?? '')
  const source = new RegExp(String.raw`--source[=\s]+` + path).exec(cmd)
  if (source) dir = unquote(source[1] ?? '')
  // `-m x`, `--message x`, `-m` at the end of combined short flags (`-am x`, `-qm x`), and a value right
  // after it, quoted or bare (`-m"x"`, `-mx`, `-amx`). Matched anywhere in the command, so
  // `python -m pytest` adds `pytest` and `find -name a` adds `e`: extra text only.
  const messages = [...cmd.matchAll(/(?:(?<![\w-])-[A-Za-z]*m|--message)(?:[=\s]+|(?=\S))("(?:[^"\\]|\\.)*"|'[^']*'|\S+)/g)].map(m => unquote(m[1] ?? ''))
  // Heredoc messages (`-F - <<'EOF'`, `-m "$(cat <<'EOF'`) are added, in place of the `$(cat <<...` an -m
  // value caught, which ends at the body's first `"`.
  const heredoc = commitHeredoc(cmd)
  if (heredoc !== undefined) messages.splice(0, messages.length, ...messages.filter(m => !/^\$\(\s*cat\s+<</.test(m)), heredoc)
  // `git commit -F file` (`-aF file` too): a heredoc in this command may have written that file, so every
  // body counts. `-F -` reads its own heredoc, handled above.
  if (/\bcommit\b[^\n]*\s(?:-[A-Za-z]*F\s*|--file[=\s]+)(?!-(?:\s|$))\S/.test(cmd)) messages.push(...heredocs(cmd).bodies.map(b => b.text))
  // What the push names: `git push [options] <remote> <ref>...`. Words that are not plain ref names
  // (a redirect, a variable) are left out, and the current branch is checked instead.
  const words = pushArgs.trim().split(/\s+/).filter(Boolean).map(unquote)
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
export function ghWrites(command        )          {
  if (/\bgh\s+(?:pr|issue|release|gist|label|discussion)\s+(?:create|edit|comment|review|close|reopen|merge|upload)\b/.test(command)) return true
  return /\bgh\s+api\b/.test(command) && /(?:\s-X\s*|--method[=\s]+)(?:POST|PUT|PATCH|DELETE)\b|\s(?:-f|-F|--field|--raw-field|--input)\b/i.test(command)
}

// --- which reviews a change needs -----------------------------------------------------------

/** Every language label, declared once: the tables below and scanners.ts are checked against it. */
export const LANGUAGE_NAMES = ['Docker', 'dependencies', 'Python', 'TypeScript', 'JavaScript', 'HTML templates', 'C#', 'C/C++',
  'Shell', 'PowerShell', 'SQL', 'Go', 'Rust', 'Java/Kotlin', 'other code', 'GitHub Actions', 'config', 'CSS']         
                                                    

const LANGUAGES                       = [
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

/**
 * The language of a code file, or undefined for notes, data and everything else. Read as Windows opens a
 * name: trailing dots and spaces go, and so does a stream (`app.py.`, `app.py `, `app.py::$DATA` are app.py).
 */
export function languageOf(path        )                       {
  const slashed = path.replace(/\\/g, '/')
  if (/(^|\/)(\.git|node_modules|\.venv|dist|build|__pycache__)\//.test(slashed)) return undefined
  const lang = (p        ) => LANGUAGES.find(([re]) => re.test(p))?.[1]
  // As written first (`notes:fix.py` is a plain name off Windows), then as Windows opens it: the last part,
  // less a drive with no slash after it (`C:app.py`).
  const cut = slashed.lastIndexOf('/') + 1 || (/^[A-Za-z]:/.test(slashed) ? 2 : 0)
  return lang(slashed) ?? lang(slashed.slice(0, cut) + slashed.slice(cut).replace(/:.*$/, '').replace(/[. ]+$/, ''))
}

// Commands that write files without the Edit or Write tool: in-place editors, copies, patches,
// PowerShell's file cmdlets, and scripts that open a file for writing.
const SHELL_WRITE = new RegExp([
  String.raw`\bsed\s+(?:-\S+\s+)*-[a-zA-Z]*i`, String.raw`\bperl\s+(?:-\S+\s+)*-[a-zA-Z]*i`, String.raw`\btee\b`,
  String.raw`\b(?:cp|mv|patch)\s`, String.raw`\bgit\s+apply\b`,
  String.raw`\b(?:Set-Content|Add-Content|Out-File|Copy-Item|Move-Item)\b`,
  String.raw`\bwrite_(?:text|bytes)\b`, String.raw`\bwriteFile(?:Sync)?\b`, String.raw`\bWriteAll(?:Text|Lines|Bytes)\b`,
  String.raw`\bopen\([^)]*,\s*["'][wax]`, String.raw`\.write\(`, String.raw`\btruncate(?:Sync)?\b`,
  // Python that copies, moves or writes by other calls, or starts a program that may: `open(p, mode='w')`,
  // `io.FileIO`, `shutil.copy`, `os.replace`, `Path(...).rename`, `subprocess.run([...])`, `os.system`.
  String.raw`\bmode\s*=\s*["'][^"']*[wax+]`, String.raw`\bFileIO\b`, String.raw`\bshutil\s*\.`,
  String.raw`\bos\s*\.\s*(?:replace|rename|renames|remove|unlink|link|symlink|system|popen|spawn\w*|exec\w*)\b`,
  String.raw`\bsubprocess\b`, String.raw`\bPath\b[^\n]*\.\s*(?:rename|replace|unlink|touch|symlink_to|hardlink_to|write_bytes)\s*\(`,
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
 * `quoted` is `<<'EOF'` or `<<"EOF"`: bash then takes the body as it is, with no `$`, backtick or backslash
 * expansion.
 */
                
                                                               
     
                                                                                                       
                                                                                                        
                                                                      
     
                                        
 

/**
 * A command's own lines with every here-document body taken out, and the bodies on their own. Openers
 * are looked for only outside quotes and `#` comments, so `echo "use <<EOF"` or `cout << endl` in a string
 * opens nothing, and a body ends only on a line that is exactly its terminator, as in bash (leading tabs
 * dropped for `<<-`). `complete` is false when the split is a guess: a body with no terminator, a quote
 * left open at the end of a line, a backtick, or process substitution. Nothing may be trusted on a guess.
 */
function heredocs(command        )                                                            {
  const lines = command.split('\n')
  const outside           = []
  const bodies            = []
  let complete = true
  for (let i = 0; i < lines.length; i++) {
    const line = (lines[i] ?? '').replace(/\r$/, '')
    outside.push(line)
    const masked = line
      .replace(/<<(-?)\s*(["'])([A-Za-z_][\w-]*)\2/g, '<<$1\x01$3') // keep a quoted terminator's name, marked
      .replace(/"[^"]*"|'[^']*'/g, '""')
      // bash starts a comment at a `#` that begins a word: at the line's start, or after a space, a tab or
      // ; & | ( ) < >. Not after \r, \v, \f or a no-break space.
      .replace(/(^|[ \t;&|()<>])#.*$/, '$1')
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
      const ends = (l        ) => (m[1] ? l.replace(/^\t+/, '') : l).replace(/\r$/, '') === m[3]
      const from = i + 1
      const body           = []
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
const commandName = (word        ) => word.replace(/^.*[\/\\]/, '').replace(/\.exe$/i, '').toLowerCase()
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
function runTarget(words          )                     {
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
// `io` too: it opens files only through `io.open`, which OPENS reads as `open`; its classes are no SAFE_NAMES.
const SAFE_MODULES = new Set(['json', 'datetime', 'pathlib', 'time', 'textwrap', 're', 'sys', 'io', 'fs', 'node:fs'])
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
  // the read-only calls of the other SAFE_MODULES
  'time', 'sleep', 'textwrap', 'dedent', 'indent', 'fill', 'wrap',
])
// A name the body calls (`name(`) or reaches (`.name`), or imports (`from os import truncate`).
function usedNames(plain        )           {
  const names = [...plain.matchAll(/(?<![\w.])([A-Za-z_]\w*)\s*\(|\.\s*([A-Za-z_]\w*)/g)].map(m => m[1] ?? m[2] ?? '')
  for (const m of plain.matchAll(/^\s*from\s+\S+\s+import\s+(.+)$/gm)) names.push(...(m[1] ?? '').split(/[\s,()]+/).filter(n => n && n !== 'as'))
  return names
}
// Modules a body loads: `import a, b as c`, `from a.b import c`, `require('fs')`.
function loadedModules(text        )           {
  const mods           = []
  for (const m of text.matchAll(/^\s*import\s+([^"'\n]+)$/gm)) mods.push(...(m[1] ?? '').split(',').map(s => s.trim().split(/\s+/)[0] ?? ''))
  for (const m of text.matchAll(/^\s*from\s+(\S+)\s+import\b/gm)) mods.push(m[1] ?? '')
  // Node: `require('fs')`, and for ES imports the module, not the name it is bound to (`import fs from 'x'`).
  for (const m of text.matchAll(/\b(?:require\s*\(|from|import)\s*(?:"([^"\n]*)"|'([^'\n]*)')/g)) mods.push(m[1] ?? m[2] ?? '')
  return mods
}

// The words that are a Python string's prefix (`r`, `rb`, `f`, `Rt`, ...; `uu` is let in, harmless).
const PY_PREFIX = /^(?:[rbuft]|[rb][rbft]|[ft][rbft])$/i
// A whole word (a name, a keyword or a number), and a string's quotes: one or three of either kind.
const PY_WORD = /\w+/y
const PY_QUOTE = /"""|'''|"|'/y
/**
 * Python code with every string literal made `""` and every `#` comment dropped, read as Python reads
 * them. Words are read whole, so only a whole word that is a string prefix (`r`, `b`, `u`, `rb`, ...)
 * opens a string with the quote after it; after any other word (`if''`, `in''`) the quote opens one on
 * its own. A `\` keeps the next character in the string (in a raw string too, as far as where it ends
 * goes), and a one-quote string ends on its own line (a `\` before the line break goes on). Undefined
 * when that reading is not sure: an f- or t-string (the code in its `{...}` runs), a string that never
 * ends, or a one-quote string that runs past its line. Every quote outside a string opens one, so none is
 * left over. A prefix word that Python would refuse (`uu`) is read as one: harmless.
 */
function pythonCode(text        )                     {
  return pythonScan(text)?.code
}

/**
 * `pythonCode`, plus each string literal's value by where its `""` stands in the code: escapes read, but
 * not in a raw string (an `r` in its prefix).
 */
function pythonScan(text        )                                                              {
  // Python reads a lone `\r` as a line break (ending a `#` comment), and an encoding line in the first two
  // (`# coding: unicode_escape`) changes what code the text is: neither is read here.
  if (/\r(?!\n)/.test(text) || /^(?:[^\n]*\n)?[ \t\f]*#[^\n]*coding[:=]/.test(text)) return undefined
  const literals = new Map                ()
  let out = ''
  for (let i = 0; i < text.length;) {
    const c = text[i] ?? ''
    if (c === '#') {
      const end = text.indexOf('\n', i)
      i = end < 0 ? text.length : end
      continue
    }
    PY_WORD.lastIndex = i
    const word = PY_WORD.exec(text)?.[0] ?? ''
    PY_QUOTE.lastIndex = i + word.length
    const quote = PY_QUOTE.exec(text)?.[0]
    // Only the f/t prefixes change the reading (they are refused): an `r`, `b` or `u` string ends as any.
    if (quote === undefined || (word && !PY_PREFIX.test(word))) {
      out += word || c
      i += word.length || 1
      continue
    }
    if (/[ft]/i.test(word)) return undefined
    let j = i + word.length + quote.length
    while (!text.startsWith(quote, j)) {
      if (j >= text.length || (quote.length === 1 && text[j] === '\n')) return undefined
      j += text[j] === '\\' ? 2 : 1
    }
    const body = text.slice(i + word.length + quote.length, j)
    // `\N{...}` names a character by its Unicode name, which is not read here: that string's value is unknown.
    if (/r/i.test(word)) literals.set(out.length, body)
    else if (!/\\N\{/.test(body)) literals.set(out.length, pythonUnescape(body, /b/i.test(word)))
    out += '""'
    i = j + quote.length
  }
  // Python reads names NFKC-folded (`ｅｘｅｃ` is `exec`), which the name lists here don't: ASCII only.
  return /[^\x00-\x7f]/.test(out) ? undefined : { code: out, literals }
}

/**
 * The files Python code from a here-document can write, when that is sure; undefined when not. Sure only
 * for code that `pythonRunsNothing` shows can start no program, with no `Path` or `pathlib` (`replace`
 * moves a file there), whose every `open(` takes a string literal, or a name bound once to one (`p = 'a.py'`
 * on a line of its own) and used nowhere but as the first thing `open(` takes. Then every file it writes is
 * one of those literals, and the other strings in it (a test case naming `app.py`) are only text.
 */
function pythonWriteTargets(text        )                       {
  const scan = pythonScan(text)
  if (!scan || !pythonRunsNothing(text)) return undefined
  const { code, literals } = scan
  if (/\b(?:Path|PurePath|PosixPath|WindowsPath|pathlib)\b/.test(code)) return undefined
  // `python -` puts the current folder first on the module path: a body that writes Python and imports
  // anything may run what it wrote (`open('json.py', 'w')`, then `import json`).
  const writesPython = [...literals.values()].some(v => /\.(?:py[cdiwz]?|pth)$|(?:^|[\\/])__init__/i.test(v))
  if (writesPython && loadedModules(code).length > 0) return undefined
  const targets           = []
  const bound = new Set        ()
  // Every `open` is one of the calls read below: `len = open` or `map(open, ...)` opens what no call names.
  if (code.match(/\bopen\b/g)?.length !== code.match(/\bopen\s*\(/g)?.length) return undefined
  for (const m of code.matchAll(/\bopen\s*\(\s*/g)) {
    const at = (m.index ?? 0) + m[0].length
    if (code.startsWith('""', at) && /^""\s*[,)]/.test(code.slice(at))) {
      const value = literals.get(at)
      if (value === undefined) return undefined
      targets.push(value)
      continue
    }
    const name = /^([A-Za-z_]\w*)\s*[,)]/.exec(code.slice(at))?.[1]
    if (name === undefined) return undefined
    bound.add(name)
  }
  for (const name of bound) {
    // Its one binding, a line of its own: `name = '...'`.
    const binding = [...code.matchAll(new RegExp(String.raw`^[ \t]*${name}[ \t]*=[ \t]*""[ \t]*$`, 'gm'))]
    if (binding.length !== 1) return undefined
    const b = binding[0]
    const value = literals.get((b?.index ?? 0) + (b?.[0].indexOf('""') ?? 0))
    if (value === undefined) return undefined
    // Every other use is the first thing an `open(` takes: nothing can bind it again.
    const uses = [...code.matchAll(new RegExp(String.raw`\b${name}\b`, 'g'))].length
    const asOpened = [...code.matchAll(new RegExp(String.raw`\bopen\s*\(\s*${name}\s*[,)]`, 'g'))].length
    if (uses !== asOpened + 1) return undefined
    targets.push(value)
  }
  // Only code files, which are then reviewed themselves, text and all: a note or data file it writes may
  // be run later with no review of what that text does (as a `cat >` body's text is kept for that).
  if (targets.some(t => !languageOf(t))) return undefined
  return targets
}

/**
 * Whether nothing in `command` but `body`'s own Python can run anything: no file it writes is then run,
 * by name or not (`python -m fix`, a glob, `pytest` or `make` finding it, `eval $(python ...)` running what
 * it prints). Every other command is read-only (`cd`, `cat`, `grep`, ...); `body` is the command's only
 * here-document; and there is no substitution, group, subshell, `exec`, background job or input redirect.
 */
function outsideRunsNothing(command        , body         )          {
  const docs = heredocs(command)
  if (!docs.complete || docs.bodies.length !== 1) return false
  // A substitution inside double quotes runs too (`echo "$(python fix.py)"`): looked for before masking.
  if (/\$\(|`|\$'/.test(docs.outside)) return false
  const masked = docs.outside.replace(/"[^"\n]*"|'[^'\n]*'/g, '""')
  if (/[`(){}<]|\$\(|(?<![&>])&(?![&>])|\bexec\b/.test(masked.replace(/<<-?\s*(?:""|[\w-]+)/g, '').replace(/\d*>&\d+/g, ''))) return false
  // rg runs a program on each file with `--pre` (and `--hostname-bin`), so it is not read-only then.
  if (/--pre\b|--hostname-bin\b/.test(docs.outside)) return false
  const lines = masked.split('\n')
  for (const [k, line] of lines.entries()) {
    for (const pipeline of line.split(/&&|\|\||;/)) {
      for (const part of pipeline.split('|')) {
        const text = part.replace(/<<-?\s*(?:""|[\w-]+)/g, ' ').replace(REDIRECT, ' ')
        if (text.trim() === '') continue
        // The Python that reads the body, on its opener line.
        if (k === body.line && /<</.test(part) && readsPythonCode(text)) continue
        // A bare read-only program, with no variable set for it (`X=/cat python gen.py`, `PATH=. cat`) and
        // no path (`./bin/cat` is any program).
        const set           = []
        const program = programWords(text, set)[0] ?? ''
        if (set.length > 0 || /[\\/]/.test(program) || !READ_ONLY.test(program.toLowerCase())) return false
      }
    }
  }
  return true
}

/**
 * Whether Python code read from a heredoc can start no program. For `blankWrittenScripts`, so a git
 * command in its text is only text (a test case, a note), and for `pythonWriteTargets`, which also checks
 * the files it opens. Like `onlyRun`'s allowlist (every call and `.name` in SAFE_NAMES, every module in
 * SAFE_MODULES, nothing in RISKY_CODE), read after `pythonCode` takes out the strings, with STARTS_PROGRAMS
 * on top. Unlike it, the files the code opens are not checked here (OPENS), and `replace` (`Path.replace`
 * moves a file) is allowed: `pythonWriteTargets` refuses `Path` itself, and `blankWrittenScripts` keeps the
 * text when a module is loaded or another script or Python runs.
 */
function pythonRunsNothing(text        )          {
  const code = pythonCode(text)
  // SAFE_MODULES is a real gate for `pythonWriteTargets` (a module it lets in, like `io`, passes), so
  // widen it only for a module that reaches no program and no file but through SAFE_NAMES. STARTS_PROGRAMS
  // is a backup: SAFE_NAMES refuses every call it lists.
  if (code === undefined || RISKY_CODE.test(code) || STARTS_PROGRAMS.test(code)) return false
  if (loadedModules(code).some(m => !SAFE_MODULES.has(m))) return false
  return usedNames(code).every(n => SAFE_NAMES.has(n) || n === 'replace')
}

// The SAFE_NAMES that reach the file system: open, write, make or move a file or folder, or a module for
// that (`print(..., file=open(...))` writes with no `.write`).
const PY_FILES = new Set(['open', 'Path', 'pathlib', 'write', 'write_text', 'mkdir', 'replace', 'writeFileSync', 'appendFileSync', 'mkdirSync', 'fs'])

/**
 * A Python string's text with its escapes read (`app\x2epy` is `app.py`, a `\` before a line break goes);
 * an unknown one is kept as it is. In a bytes string (`bytes`) `\u` and `\U` are no escapes.
 */
function pythonUnescape(s        , bytes = false)         {
  const named                         = { n: '\n', t: '\t', r: '\r', '\\': '\\', "'": "'", '"': '"', a: '\x07', b: '\b', f: '\f', v: '\v', '0': '\0', '\n': '' }
  return s.replace(/\\(x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4}|U[0-9a-fA-F]{8}|[0-7]{1,3}|[\s\S])/g, (all, e        ) => {
    if (bytes && /^[uU]/.test(e)) return all
    if (/^[xuU]/.test(e)) return String.fromCodePoint(parseInt(e.slice(1), 16))
    if (/^[0-7]/.test(e)) return String.fromCodePoint(parseInt(e, 8))
    return named[e] ?? all
  })
}

/**
 * Whether a heredoc's reader is Python taking it as its code: `python -`, `python3 -I`, a venv's python,
 * and the `py` launcher too: it follows a script file's `#!` line (left out of SCRIPT_OF for that), but
 * reads stdin as Python (checked on 2026-11-15: a `#!/usr/bin/env bash` body ran as Python).
 */
function readsPythonCode(reader        )          {
  const words = programWords(reader.replace(REDIRECT, ''))
  return /^(?:python[\d.]*|py)$/.test(commandName(words[0] ?? '')) && ['', '-'].includes(runTarget(words) ?? 'x')
}
// The same file spelled two ways (`./gen.txt`, `gen.txt`, `GEN.TXT` on Windows) is one file.
const sameFile = (name        ) => name.replace(/\\/g, '/').replace(/^(?:\.\/)+/, '').toLowerCase()

const REDIRECT = /\d?>[>|]?\s*([^\s<>]+)/g // `>|` too, so its `|` is not read as a pipe

/**
 * Code files that a command only runs, never writes, so they need no review, and the command's own text
 * outside its here-documents (what the bodies say is not a mention). Kept narrow on purpose, as an
 * allowlist: every command outside is an interpreter or a read-only tool, and every here-document is
 * either `cat` data or Python/Node code read from stdin whose every file-opening call takes a plain
 * literal that is not code (Claude writing notes, then running a script). Anything else, or anything the
 * bodies write being run afterwards, and the run scripts count again.
 */
function onlyRun(command        )                                                             {
  const { outside, bodies, complete } = heredocs(command)
  // `--pre`: `rg --pre bash` runs a program on every file it reads, so rg is not read-only then.
  if (!complete || outside.includes('$') || /--pre\b|--hostname-bin\b/.test(outside) || SHELL_WRITE.test(outside) || SHELL_WRITE_PS.test(outside)) return undefined
  const written = new Set        () // what the bodies write: running one of these runs new code
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
  const runs = new Map                ()
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
 * a git hook), and a write of code this command can't see is still a write of code. (That keeps code
 * writes visible to `shellWrites`, but for a scratch script's text, `blankScratchBodies`; `gitAction` then
 * also blanks bodies with `blankWrittenScripts`.)
 *
 * Kept narrow, as an allowlist: every command outside the bodies must be a read-only tool or one in
 * RUNS_NOTHING (`bash`, `python`, `xargs`, `eval`, `.`, `read` loops and anything unknown run something,
 * so nothing is blanked), and none may hold `$(...)`, a backtick, `--pre` (`rg --pre bash` runs a
 * program), `exec` (`exec >file` sends a screen heredoc into a file), or anything that could make `cat`
 * another program (a PATH assignment, a function or an alias). The redirects `>|`, `&>` and `>&file` are
 * refused too (their target is read from the opener line by a pattern that sees only `>` and `>>`), and so
 * is any space-like character but a space, a tab or a newline (see `ODD_SPACE`). Nothing is blanked when
 * the heredoc split is a guess, and a body that is piped on or shares its opener line with another heredoc
 * is kept.
 */
function blankDataBodies(full        , local        )         {
  const command = local
  const { outside, bodies, complete } = heredocs(command)
  // `exec >file` sends a later screen heredoc into that file. `>|`, `&>` and `>&file` write one to a file
  // (`cat <<'EOF' >|~/bin/ls`), and the `|` of `>|` would also split the command where bash doesn't.
  if (!complete || /\$\(|`|--pre\b|\bPATH=|\(\s*\)|\b(?:function|alias|exec)\b|>\||&>|>&\s*[^\d\s-]/.test(outside.replace(/'[^'\n]*'/g, "''")) || oddSpace(outside)) return command
  const masked = outside.replace(/"[^"\n]*"|'[^'\n]*'/g, '""').replace(/\d*>&\d+/g, '')
  for (const cmd of masked.split(/&&|\|\||[;&|\n]/)) {
    const name = commandName(programWords(cmd.replace(/<<-?\s*(?:""|[\w-]+)/g, '').replace(REDIRECT, ''))[0] ?? '')
    if (name && !READ_ONLY.test(name) && !RUNS_NOTHING.has(name)) return command
  }
  const lines = command.split('\n')
  const perLine = new Map                ()
  for (const b of bodies) perLine.set(b.line, (perLine.get(b.line) ?? 0) + 1)
  // Whether `full` feeds this file, spelled as the opener spells it, to a command `localPart` blanked (ssh).
  const sentToSsh = (target        ) => {
    // nosemgrep: javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp -- target is escaped in place and the pattern has no nested repeats
    const re =new RegExp(String.raw`(?<!<)<\s*["']?${target.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}["']?(?=$|[\s;&|)])`, 'g')
    return [...full.matchAll(re)].some(m => !local.slice(m.index ?? 0, (m.index ?? 0) + m[0].length).trim())
  }
  for (const b of bodies) {
    if (!b.quoted || b.piped || perLine.get(b.line) !== 1) continue
    if (!/^(?:\S*[\\/])?cat(?:\.exe)?(?:\s+-\S*)*$/i.test(b.reader.replace(REDIRECT, '').trim())) continue
    // Every redirect target on the opener's line, as spelled there (the masked reader hides quoted names).
    const targets = [...(lines[b.line] ?? '').matchAll(/(?<![0-9&<])\d?>[>|]?\s*("[^"]+"|'[^']+'|[^\s;&|<>()]+)/g)].map(m => unquote(m[1] ?? ''))
    if (!targets.every(t => t === '/dev/null' || sentToSsh(t))) continue // a file left here may run later
    for (let k = b.from; k < b.to; k++) lines[k] = ''
  }
  return lines.join('\n')
}

// Besides READ_ONLY, the commands that run no shell code: `mkdir`, `rm`, `diff` and checksums. Left out:
// `cp` and `mv` (they can put a script in a git hook or on PATH) and `chmod` (`chmod +x x.py` lets a later
// `./x.py` with no `#!` line run as a shell script).
const NOT_A_SHELL = /^(?:mkdir|rm|diff|sha256sum|md5sum)$/
// Interpreters of other languages, with the script files each runs. `git(repo, 'commit')` or a "git commit"
// string in such a script is not a commit. Only a script file of its own language counts, run with the
// flags `runTarget` allows: no inline code (`python -c`, `node -e`), module (`-m`), preload (`node -r`) or
// package script (`node --run`). Python and Node ignore a `#!` line. Left out on purpose: the `py`
// launcher (it follows a `#!/usr/bin/env bash` line) and bun (it runs `.sh` files, and `bun x` may be a
// package.json script named x).
const SCRIPT_OF = new Map                ([['python', /\.pyw?$/i], ['node', /\.[cm]?js$/i]])
// A body that may start programs itself (`subprocess.run(['git', 'push'])`, `execSync('bash x')`) or use git
// through a library (`import git`, `pygit2`, `isomorphic-git`) is kept: the guard can't follow what a
// script runs, but it can still see such a body's text. Best effort, so it is wide and ignores case. Call
// names (spawn, exec, popen, system, fork, binding and the like) match inside longer names too
// (`create_subprocess_shell`, `os.posix_spawn`, `execSync`); a body kept by mistake (`filesystem`) only
// costs a check. Module and runtime names (pty, asyncio, ctypes, child_process, Deno, ...) match at a
// word's start (`ptyprocess`, and `evaluate` by mistake), and the short ones (nt, sh, zx) as whole words
// only. Node's static `import ... from` (a helper module may run anything) and Python's `import`/`from` of
// os, git or sh count too. The regex is the full list. Every part runs in time linear in the body: `^` is
// followed by `[ \t]*`, never `\s*`, which would cross blank lines again from each one.
const STARTS_PROGRAMS = new RegExp([
  String.raw`subprocess|spawn|popen|system|exec|fork|startfile|pipepager|getBuiltinModule|binding|dlopen`,
  String.raw`\bcode\s*\.\s*interact`,
  String.raw`\b(?:pty|asyncio|multiprocessing|pydoc|ctypes|cffi|webbrowser|runpy|posix|_winapi|child_process|__import__|importlib|getattr|globals|builtins|__dict__|eval|shelljs|Deno|Bun|pexpect|plumbum|invoke|fabric|pygit2|dulwich|isomorphic-git|simple-git|nodegit)`,
  String.raw`\b(?:nt|sh|zx)\b`,
  String.raw`\b(?:import|from)\s+(?:os|git|sh)\b`,
  String.raw`^[ \t]*import\b[^\n]*\bfrom\b`,
  String.raw`\bos\s*\.|\brequire\s*\(|\bimport\s*\(|\bprocess\s*\[`,
].join('|'), 'im')
// A git push or commit command line, or `gh repo create --push`, inside the body's text (`'git push origin
// main'`, `"git -C 'my repo' commit -am y"`, `git.exe push`): when the command runs a script at all, a body
// that holds one is kept, as no list of the calls that start programs is complete. It needs a space after
// `git`, so a test helper's call (`git(repo, 'commit')`) or an argument list (`['git', 'push']`) is not one.
// Prose that says "git push" counts too, while a script runs: kept by mistake, it only costs a check.
// Read line by line, from the first `git ` on it, so a line of many `git ` words is read once, not once each.
function gitCommandText(text        )          {
  return text.split('\n').some(line => {
    const at = line.search(/\bgit(?:\.exe)?[ \t]/i)
    if (at >= 0 && /\b(?:push|commit)\b/i.test(line.slice(at))) return true
    const gh = line.search(/\bgh[ \t]+repo[ \t]+create\b/i)
    return gh >= 0 && line.includes('--push', gh)
  })
}
// Space-like characters other than a space, a tab and a newline (`\r` mid-line, `\v`, `\f`, a no-break
// space), and other control characters. JavaScript's `\s` takes most of them as spaces and bash does
// not, so the patterns here would split words where bash doesn't (`true\r# ; bash x` runs `bash x`).
// A `\r` that ends a line is fine: `heredocs()` drops it before `outside` is built. Inside quotes bash reads
// them as plain characters too, so only unquoted ones count (`ls 'a<no-break space>b'` is fine).
const ODD_SPACE = /[^\S \t\n]|[\x00-\x08\x0e-\x1f\x7f]/
const oddSpace = (outside        ) => ODD_SPACE.test(outside.replace(/"[^"\n]*"|'[^'\n]*'/g, '""'))
// The only files a body may be written to and still be blanked: scripts of the languages above and plain
// text, outside `.git`. Anything else (a file with no extension on PATH, `.bashrc`, a git hook, `.git/config`,
// `package.json`, `tox.ini`, a Makefile) may be run later by a shell or git, unseen. Git runs a hook only by
// its exact name, which has no extension, so a `.js` file in a `hooks` folder is fine.
const PLAIN_TARGET = /^(?!.*(?:^|[\\/])\.git[\\/])(?:.*[\\/])?[\w-][\w.-]*\.(?:pyw?|[cm]?[jt]s|[jt]sx|md|txt|log|csv)$/i

// Variables that change which program runs, or make a shell or interpreter run more code.
// Also the usual exported ones: setting one changes the environment of every program started after it
// (`APPDATA=` moves where Python loads `usercustomize`, `COMSPEC=` is the shell `shell=True` starts).
const RUNS_WITH = /^(?:PATH|PATHEXT|BASH_ENV|ENV|SHELLOPTS|BASHOPTS|PROMPT_COMMAND|PS4|IFS|CDPATH|LD_\w+|DYLD_\w+|NODE_\w+|PYTHON\w*|BUN_\w+|GIT_\w+|HOME|USERPROFILE|APPDATA|LOCALAPPDATA|PROGRAMDATA|COMSPEC|SHELL|TEMP|TMP|TMPDIR|PWD|OLDPWD|SYSTEMROOT|WINDIR|XDG_\w+)$/i

/**
 * The words of one command, from the program on: shell words that come before a program (`sudo`, `env`,
 * `nohup`, `if`, ...), variables set for it (`LC_ALL=C`, also after `env`), and `timeout [options]
 * DURATION` are skipped, as in `localPart`. The names of the variables set are put in `set`.
 */
function programWords(cmd        , set           = [])           {
  const words = cmd.trim().split(/\s+/).filter(Boolean)
  for (;;) {
    for (;;) {
      if (BEFORE_PROGRAM.has(words[0] ?? '')) words.shift()
      else if (/^[A-Za-z_]\w*\+?=/.test(words[0] ?? '')) set.push((words.shift() ?? '').replace(/\+?=.*$/, ''))
      else break
    }
    if (commandName(words[0] ?? '') !== 'timeout') return words
    words.shift()
    while (words[0]?.startsWith('-')) if (/^(?:-[ks]|--kill-after|--signal)$/.test(words.shift() ?? '')) words.shift()
    words.shift() // the duration
  }
}

/**
 * For `gitAction`: the command with the bodies of quoted here-documents read by `cat` alone, or by Python
 * as code that can start no program, blanked when nothing else in the command runs shell code. Such a body
 * is a file's text (or goes to the screen, or is code that runs no other), and a
 * `git commit` in it commits nothing until a shell runs it (a Python test that calls `git(repo, 'commit')`
 * is not a commit). Kept narrow, as an allowlist:
 *
 * - Every other command must be READ_ONLY or in NOT_A_SHELL, or an interpreter in SCRIPT_OF running a
 *   script file of its language, or Python reading a heredoc as its code (see below). Anything else may run the file, by name or redirect (`bash x.sh`,
 *   `. x.sh`, `sh < x.sh`) or not (`make`, `npm test`, a hook run by `git commit`), so nothing is blanked
 *   then. A program spelled as a path is any file there (`./cat`), so only python or node may be (a venv's
 *   `.venv/Scripts/python.exe`), and not when a heredoc here writes a file of that name (`/tmp/t/python`).
 * - Nothing is blanked when the split is a guess, or the command has `$(...)` or a backtick (even in double
 *   quotes), `exec` (`exec >file` sends a screen heredoc into a file), `rg --pre` in any spelling (runs a
 *   program on each file), brace expansion, `printf -v` (sets a variable by name), a variable set for a
 *   program (`X=1 python a.py`), or one in RUNS_WITH set at all (`PATH=`, `BASH_ENV=`). A line that only
 *   sets another variable (`S=/tmp/s`) is fine. Process substitution, a function and an alias are refused
 *   here too, as a backup: the name check already refuses them.
 * - A variable is read only as `$TMP`, `$TEMP`, `$TMPDIR`, `$HOME`, `$USERPROFILE`, `$LOCALAPPDATA` or `$PWD`
 *   (the machine's, as none of them may be set here): another could turn `python $S.py` into `python -c ...`.
 * - Every redirect in the command, on any line, must go to `/dev/null` or a PLAIN_TARGET file, and `&>`,
 *   `>&file`, `<>` and `>|` are refused: `cat x.txt > ~/bin/python` copies a body where a later command runs it.
 * - Nothing is blanked either when the command has a space-like or control character bash reads
 *   differently (ODD_SPACE) outside the bodies. A `\r` that ends a line is fine.
 * - A body is kept when it is unquoted (bash expands `$(...)` in it), read by anything but `cat` alone,
 *   piped on (`cat <<'EOF' | bash`), shares its opener line with another heredoc, or may start programs
 *   itself (STARTS_PROGRAMS), or holds a git commit or push command line while the command runs a script
 *   (`gitCommandText`). A body Python reads as its code follows the next rule instead.
 * - Python may also read a heredoc as its code (`python - <<'PY'`, a script editing a test file whose cases
 *   name `git commit`). Every such body must be quoted, not piped on, and shown by `pythonRunsNothing` to
 *   start no program, or nothing is blanked; and there must be one such body for each `python -` command
 *   (a reader read another way than the heredoc parser reads it would leave its body unchecked). Such a
 *   body is blanked when it is alone on its opener line and no script runs. Loading any module counts as
 *   running one (a `json.py` written here would be it), and so does a file opened by one of several
 *   Python bodies (a `sitecustomize.py` the next one loads). Running it alone does not set that: it starts
 *   nothing, so it keeps no git text in other bodies.
 * - `#` comments are read as bash reads them, and `timeout DURATION` and prefix words as `programWords` does.
 * - The caller does not use this when the command holds a `\`-newline (see `gitAction`).
 *
 * `shellWrites` does not use this: a heredoc written to `x.py` is a write of code even if nothing runs it
 * (it only blanks the text of scratch scripts, `blankScratchBodies`).
 */
function blankWrittenScripts(command        )         {
  const { outside, bodies, complete } = heredocs(command)
  // `>|` writes past noclobber, and its `|` would split the command where bash doesn't. ODD_SPACE: see there.
  if (!complete || /\$\(|`|[<>]\(|\(\s*\)|\b(?:function|alias)\b|&>|>&\s*[^\d\s-]|<>|>\|/.test(outside) || oddSpace(outside)) return command
  const lines = command.split('\n')
  const TARGET = /(?<![0-9&<])\d?>[>|]?\s*("[^"]+"|'[^']+'|[^\s;&|<>()]+)/g // `>|` is refused above; read here too as a backup
  const base = (path        ) => commandName(path.replace(/\\/g, '/'))
  // Every redirect target in the command, on any line: each must be a file nothing runs later.
  const targets = [...outside.matchAll(TARGET)].map(m => unquote(m[1] ?? ''))
  if (!targets.every(t => t === '/dev/null' || PLAIN_TARGET.test(t))) return command
  const written = new Set(targets.map(base))
  // Quotes are taken off, keeping what is inside as one word: `"bash"` and `b""ash` are bash.
  const plain = outside.replace(/"([^"\n]*)"|'([^'\n]*)'/g, (_, a, b) => String(a ?? b ?? '').replace(/[\s;&|<>()#]/g, '_'))
    .replace(/(^|[ \t;&|()<>])#.*$/gm, '$1') // a comment, as bash reads one (a # in quotes is gone already)
  // A variable other than the machine's own folders, or one of those set here, may hold anything.
  const MACHINE = /\$\{?(?:TMP|TEMP|TMPDIR|HOME|USERPROFILE|LOCALAPPDATA|PWD)\b\}?/g
  if (plain.replace(MACHINE, '').includes('$')) return command
  let runsScript = false
  let pythonReads = 0
  for (const cmd of plain.split(/&&|\|\||[;&|\n]/)) {
    const raw = cmd.replace(/<<-?\s*[\w-]+/g, '').replace(REDIRECT, '').trim().split(/\s+/).filter(Boolean)
    if (raw.some(w => w === 'exec' || w.startsWith('--pre') || /[{}]/.test(w))) return command
    // `S=/tmp/s` alone sets a variable. One that changes what runs, or one set for a program, is refused.
    const set           = []
    const words = programWords(raw.join(' '), set)
    if (set.length && (words.length || set.some(n => RUNS_WITH.test(n)))) return command
    if (!words.length) continue
    if (commandName(words[0] ?? '') === 'printf' && words.some(w => w.startsWith('-v'))) return command
    const program = words[0] ?? ''
    const name = commandName(program).replace(/^python[\d.]*$/, 'python')
    const script = SCRIPT_OF.get(name)
    // A path is any file there (`./cat`): only an interpreter's own (a venv's python) is taken as that program.
    if (/[\\/]/.test(program) && (!script || written.has(base(program)))) return command
    if (READ_ONLY.test(name) || NOT_A_SHELL.test(name)) continue
    const target = script ? runTarget(words) : undefined
    // Python reading a heredoc as its code (`python - <<'PY'`, `py -3 - <<'PY'`): that body is checked below.
    const stdin = name === 'python' || name === 'py' ? runTarget(words) : undefined
    if ((stdin === '' || stdin === '-') && /(?<!<)<<(?!<)/.test(cmd)) {
      // Another stdin (`< other.py`, `0<x`, a `<<<` here-string) is what Python reads then, not the body.
      if (cmd.replace(/(?<!<)<<-?\s*[\w-]+/g, '').includes('<')) return command
      pythonReads++
      continue
    }
    if (!script || !target || !script.test(target)) return command
    runsScript = true
  }
  // Each body Python runs must be one that can start no program, or nothing is blanked: it could run
  // another body's text. Fewer such bodies than `python -` commands accepted above means one wasn't found
  // (a backup of the `<<` check there). A piped one is refused as a backup too: what it pipes into is a
  // command checked above.
  const pythonBodies = bodies.filter(b => readsPythonCode(b.reader))
  if (pythonBodies.length < pythonReads || pythonBodies.some(b => !b.quoted || b.piped || !pythonRunsNothing(b.text))) return command
  const codes = pythonBodies.map(b => pythonCode(b.text) ?? '')
  // A module it loads may be a file written here (`cat > json.py`, or by its own `open`), so loading one
  // runs a script. So may a file one body writes, for another Python started here (a `sitecustomize.py`).
  if (codes.some(c => loadedModules(c).length > 0)) runsScript = true
  if (pythonBodies.length > 1 && codes.some(c => usedNames(c).some(n => PY_FILES.has(n)))) runsScript = true
  const perLine = new Map                ()
  for (const b of bodies) perLine.set(b.line, (perLine.get(b.line) ?? 0) + 1)
  for (const b of bodies) {
    if (!b.quoted || b.piped || perLine.get(b.line) !== 1) continue
    // A body Python runs is blanked like a data body once shown to start nothing (above): its git
    // commands are strings. Kept whenever another script runs: the body may have written that script, or
    // a module it loads (`json.py`), and its own text is all the check can see of what that runs.
    if (pythonBodies.includes(b)) {
      if (!runsScript) for (let k = b.from; k < b.to; k++) lines[k] = ''
      continue
    }
    if (STARTS_PROGRAMS.test(b.text)) continue
    if (runsScript && gitCommandText(b.text)) continue
    if (!/^cat(?:\s+-\S*)*$/i.test(b.reader.replace(REDIRECT, '').trim())) continue
    for (let k = b.from; k < b.to; k++) lines[k] = ''
  }
  return lines.join('\n')
}

// The forms a scratch-script command may take, every statement (split at `;`, `&&` and line ends) one of
// them: nothing else in it can then read a scratch file's text, run it as code, or change what a name
// means. A word is plain (`[\w./:@%+,=-]`), with `$NAME` or `${NAME}` from a leading assignment, maybe in
// double quotes as a whole. Quoted text holds no `$`, backtick, `\`, `;`, `&` or `|`, so a split never
// lands inside it.
const PLAIN_WORD = String.raw`"[^"\s$\x60\\;&|]*(?:\$(?:\{[A-Za-z_]\w*\}|[A-Za-z_]\w*)[^"\s$\x60\\;&|]*)*"|(?:[\w./:@%+,=-]|\$(?:\{[A-Za-z_]\w*\}|[A-Za-z_]\w*))+`
// `NAME=value` at the very start, before anything else runs.
const ASSIGN = new RegExp(String.raw`^([A-Za-z_]\w*)=("[^"$\x60\\;&|\n]*"|'[^'\\;&|\n]*'|[\w./:@%+,=-]*)$`)
// Names bash keeps its own value in, or that change what `cat` or a program is.
const SPECIAL = /^(?:UID|EUID|PPID|SHELLOPTS|BASHOPTS|RANDOM|SRANDOM|SECONDS|LINENO|BASHPID|EPOCHSECONDS|EPOCHREALTIME|HISTCMD|GROUPS|FUNCNAME|PIPESTATUS|DIRSTACK|PATH|BASH_ENV|ENV|IFS|PS4|BASH\w*)$/
// `cat > target <<'TAG'` or `cat <<'TAG' > target`: stdout only (`>` or `>>`), a quoted tag, nothing else.
const CAT_TO = new RegExp(String.raw`^cat(?:\.exe)?\s+(?:>>?\s*(${PLAIN_WORD})\s+<<-?\s*(?:'[\w-]+'|"[\w-]+")|<<-?\s*(?:'[\w-]+'|"[\w-]+")\s+>>?\s*(${PLAIN_WORD}))$`)
// A program running a scratch script with flags that take no code (long ones but --eval and --print, and
// `-I -u -B -s -S -x`), plain arguments, then at most `2>&1` and `| head` or `| tail` with a count.
const RUN = new RegExp(String.raw`^(?:bash|sh|zsh|dash|node|deno(?:\s+run)?|bun|tsx|python[\d.]*|py|ruby|perl|pwsh|powershell)(?:\.exe)?`
  + String.raw`(?:\s+(?:--(?!eval\b|print\b)[a-z][\w-]*(?:=[\w./:@%+,-]+)?|-[IuBsSx]))*\s+(${PLAIN_WORD})`
  + String.raw`(?:\s+(?:[\w./:=@%+,-]+|'[^'\\;&|\n]*'|"[^"$\x60\\;&|\n]*"))*(?:\s+2>&1)?(?:\s*\|\s*(?:head|tail)(?:\s+-n)?\s+-?\d+)?$`)

/**
 * `command` with the text of each scratch script it writes blanked, lines kept, when the whole command is
 * nothing but scratch scripts written and run: every statement outside the here-documents is a leading
 * `NAME=value` (`ASSIGN`, not a `SPECIAL` name), a `cat` that writes a quoted here-document to one file
 * `scratchFile` takes for Claude's scratch (`CAT_TO`), or a program that runs a scratch file (`RUN`). Any
 * other statement, here-document, redirect or spelling leaves the command as it is. A variable is filled
 * in from the leading assignments only; one not set there leaves the command as it is too. The names in
 * such a script are not this command's: when it runs, it is a scratch script, left out of review with
 * what it edits (the user's choice, 2026-11-12, in the vault note `Claude/Habits and preferences.md`).
 * The target itself is still a write.
 */
function blankScratchBodies(command        , scratchFile                             )         {
  const { bodies, complete } = heredocs(command)
  if (!complete || bodies.length === 0) return command
  const lines = command.split('\n')
  const opens = new Map(bodies.map(b => [b.line, b]))
  if (opens.size !== bodies.length) return command // two here-documents on one line
  const inBody = new Set        ()
  for (const b of bodies) for (let k = b.from; k <= b.to; k++) inBody.add(k)
  if (oddSpace(lines.filter((_l, i) => !inBody.has(i)).join('\n'))) return command
  const vars = new Map                ()
  // A word as the shell reads it, or undefined when a variable in it is not one of the leading ones.
  const fill = (word        )                     => {
    let sure = true
    const text = word.replace(/^"(.*)"$/, '$1').replace(/\$(?:\{([A-Za-z_]\w*)\}|([A-Za-z_]\w*))/g, (_all, braced         , bare         ) => {
      const v = vars.get(braced ?? bare ?? '')
      if (v === undefined) sure = false
      return v ?? ''
    })
    return sure ? text : undefined
  }
  const isScratch = (word                    ) => {
    const t = word === undefined ? undefined : fill(word)
    return t !== undefined && t !== '/dev/null' && scratchFile(t)
  }
  let leading = true
  for (let i = 0; i < lines.length; i++) {
    if (inBody.has(i)) continue
    const statements = (lines[i] ?? '').split(/;|&&/).map(t => t.trim())
    for (const [k, st] of statements.entries()) {
      if (st === '') continue
      const assign = ASSIGN.exec(st)
      if (assign) {
        const name = assign[1] ?? ''
        if (!leading || SPECIAL.test(name)) return command
        vars.set(name, unquote(assign[2] ?? ''))
        continue
      }
      leading = false
      const cat = CAT_TO.exec(st)
      if (cat) {
        // It reads the here-document opened on this line, as this line's last statement.
        const b = opens.get(i)
        if (!b || !b.quoted || b.piped || k !== statements.length - 1 || !isScratch(cat[1] ?? cat[2])) return command
        continue
      }
      const run = RUN.exec(st)
      if (run && !opens.has(i) && isScratch(run[1])) continue
      return command
    }
    if (opens.has(i) && !CAT_TO.test(statements.at(-1) ?? '')) return command
  }
  for (const b of bodies) for (let k = b.from; k < b.to; k++) lines[k] = ''
  return lines.join('\n')
}

/**
 * The code files a shell command writes, as the command names them. A redirect counts for its target
 * alone. When anything else in the command writes, every code file it names counts, which can include
 * one it only reads (`cp a.py b.py`, a loop over files, `ls a.py | xargs sed -i`): an extra review is the
 * safer mistake than a change nobody looked at. In Python code from a heredoc a string's prefix is not part
 * of a name (`r'app.py'` names `app.py` there), and every one-line string is read as a name, except in a
 * body shown to write only the code files its `open(` calls name, in a command where nothing else runs
 * anything (`pythonWriteTargets`, `outsideRunsNothing`): there only those files count. Left out:
 * what ssh runs on another machine (`localPart`), the text of data here-documents nothing here runs
 * (`blankDataBodies`), a script run after here-documents that only write notes (`onlyRun`), and, when
 * `scratchFile` is given (it gets each scratch-script target and run script, leading variables filled
 * in), the text of scratch scripts in a command that only writes and runs them (`blankScratchBodies`; the
 * target itself still counts). The caller leaves out two
 * more: the scripts a command only ran, shown by their file being the same before and after
 * (`runOnlyScripts`), and Claude's scratch files (`inScratch`).
 */
export function shellWrites(fullCommand        , scratchFile                              )           {
  // What ssh runs on another machine writes no file here, and a data heredoc's text runs nowhere here.
  const local = blankDataBodies(fullCommand, localPart(fullCommand))
  const command = scratchFile ? blankScratchBodies(local, scratchFile) : local
  // A wildcard, a variable or a sed pattern is not a file name: `src/*.ts`, `$DIR/a.py`, `hooks\/a.ts`.
  const notAName = (raw        ) => /[*?^$]|\\\//.test(raw)
  const out = new Set        ()
  // `>`, `>>` and `>|`, with an fd number (`1>`, `2>|`) or `&` (`&>`, `&>>`) before it, and `<>` (opened
  // to read and write, `exec 3<>a.py`). Not `2>&1`.
  for (const m of command.matchAll(/(?<![<>&])(?:(?:\d+|&)?(?<![<>])>[>|]?|\d*<>)\s*(?!&)("[^"]+"|'[^']+'|[^\s;&|<>()]+)/g)) {
    if (notAName(m[1] ?? '')) continue
    const target = unquote(m[1] ?? '')
    if (languageOf(target)) out.add(target)
  }
  if (SHELL_WRITE.test(command) || SHELL_WRITE_PS.test(heredocs(command).outside)) {
    const trusted = onlyRun(command)
    // Shell words, quotes kept together: "$DST/hooks/a.ts" is one word, not "$DST" and "/hooks/a.ts".
    const mentions = new Map                ()
    // Python code shown to write only the files its `open(` calls name (`pythonWriteTargets`), in a quoted
    // body read whole, whose split up to its end line is no guess (what follows can't move it): those files
    // count, and its other strings are only text, so its lines are not read for names.
    const lines = command.split('\n')
    const proven = new Set        ()
    if (!trusted) {
      for (const b of heredocs(command).bodies) {
        // Its output sent to a file (`python - <<'PY' > gen.sh`) writes what it prints: read as before.
        if (!b.quoted || b.piped || !readsPythonCode(b.reader) || /\d*>/.test(b.reader)) continue
        if (!heredocs(lines.slice(0, b.to + 1).join('\n')).complete) continue
        const targets = pythonWriteTargets(b.text)
        if (targets === undefined || !outsideRunsNothing(command, b)) continue
        for (let k = b.from; k < b.to; k++) proven.add(k)
        // A proven target is a file name, never a flag: `-x.py` counts too.
        for (const t of targets) mentions.set(t, (mentions.get(t) ?? 0) + 1)
      }
    }
    const text = trusted?.outside ?? lines.map((l, k) => (proven.has(k) ? '' : l)).join('\n')
    // The lines of bodies that are Python code (`python - <<'PY'`, `cat > fix.py <<'EOF'`): there
    // `r'C:\a.py'` is a raw string naming `C:\a.py`, not bash's word `rC:\a.py`. Each one-line string in
    // them counts as a name too, wherever it stands (`base + r'a.py'`, `{'k': 'src/a.py'}`). A target is
    // seen only when spelled plainly (`cat > "fix.py"` is masked): then the prefix stays, an extra name
    // only. When `trusted`, `text` is `outside`, which holds no body lines.
    const pythonLines = new Set        ()
    if (!trusted) {
      for (const b of heredocs(command).bodies) {
        if (proven.has(b.from)) continue
        const writes = [...b.reader.matchAll(REDIRECT)].map(m => m[1] ?? '')
        if (!readsPythonCode(b.reader) && !writes.some(t => /\.pyw?$/i.test(t))) continue
        for (let k = b.from; k < b.to; k++) pythonLines.add(k)
        // A `\` before a line break goes on in the same string (Python drops both).
        for (const m of b.text.matchAll(/(?<![\w])([rRbBuUfF]{0,2})(["'])((?:\\[\s\S]|(?!\2)[^\\\n])*)\2/g)) {
          const name = /r/i.test(m[1] ?? '') ? m[3] ?? '' : pythonUnescape(m[3] ?? '', /b/i.test(m[1] ?? ''))
          if (name.length > 2 && !name.startsWith('-') && languageOf(name)) mentions.set(name, (mentions.get(name) ?? 0) + 1)
        }
      }
    }
    let line = 0
    let seen = 0
    for (const found of text.matchAll(/(?:"[^"]*"|'[^']*'|[^\s;|&<>()`,=[\]{}"'])+/g)) {
      for (; seen < found.index; seen++) if (text[seen] === '\n') line++
      // A short word glued to a quote there is a prefix or a keyword (`in'a.py'`), never part of the name.
      const prefix = pythonLines.has(line) ? /^[A-Za-z]{1,2}(?=["'])/.exec(found[0])?.[0] ?? '' : ''
      const raw = found[0].slice(prefix.length)
      if (notAName(raw)) continue
      // Each quoted part loses only its own quotes, as bash reads it: "pat's/app.py" is pat's/app.py.
      const whole = raw.replace(/"([^"]*)"|'([^']*)'/g, (_m, dq         , sq         ) => dq ?? sq ?? '')
      // A quoted string with a line break, or a shell operator with a space on either side, or a `#` followed
      // by a space, may be a piece of shell (a test case in a script): the names inside it count one by one.
      // A piece that is not a Windows path is split at `\n` and `\r` escapes too (`C:\tools\new.py` and
      // `src\new.py` hold no escapes). The whole string counts as well (`"R & D/app.py"` is a real name),
      // except one with a line break, or a shell-like one with a `\n` or `\r` escape outside a Windows path:
      // no file name holds those. Anything else stays whole, as before (`scripts\release.py`).
      // A Windows path: one from a drive or `.\`, or a relative one with no spaces (`src\new.py`, not `true\r# ;`).
      const windowsPath = (s        ) => /^(?:[A-Za-z]:|\.{1,2})?\\/.test(s) || (!/\s/.test(s) && /^[\w.-]+\\[\w.-]/.test(s))
      // A quoted part holding a space and a pair of the other kind of quote is a piece of code (a line a
      // script writes, `"s = open('../a.ts').read()"`), not one name: the names in it count one by one. A
      // single apostrophe is a name's own (`"C:\Users\pat\Pat's Files\app.py"`), so that stays whole.
      const quotedCode = [...raw.matchAll(/"([^"]*)"|'([^']*)'/g)].some(m => {
        const inner = m[1] ?? m[2] ?? ''
        return /\s/.test(inner) && inner.split(m[1] !== undefined ? "'" : '"').length >= 3
      })
      const shellLike = quotedCode || /[\r\n]|\s[;|&<>]|[;|&<>]\s|#\s/.test(whole)
      const words = shellLike
        ? whole.split(/[\s;|&<>()#,=[\]{}`'"]+/).flatMap(piece => (windowsPath(piece) ? [piece] : piece.split(/\\[nr]/)))
        : []
      // The whole name, less any quotes left around it (`"'app.py'"` names app.py).
      const bare = whole.replace(/^['"]+|['"]+$/g, '')
      if (!quotedCode && !/[\r\n]/.test(bare) && (!shellLike || windowsPath(bare) || !/\\[nr]/.test(bare))) words.push(bare)
      for (const word of words) {
        if (word.length > 2 && !word.startsWith('-') && languageOf(word)) mentions.set(word, (mentions.get(word) ?? 0) + 1)
      }
    }
    for (const [word, count] of mentions) if ((trusted?.runs.get(word) ?? 0) < count) out.add(word)
  }
  return [...out]
}

/**
 * How paths are spelled on this machine: Windows (drive letters, `\` and `/` alike, any case) or not. How
 * one tool reads a path there, `/c/...` included, is `rulesFor`.
 */
                     
                                                       
     
                                                                                                            
                                                                                                             
                                                                                                   
     
                                         
 

// The variables `Paths.vars` may fill in.
const TRUSTED_VARS = ['TEMP', 'TMP', 'TMPDIR', 'LOCALAPPDATA']         

/**
 * How a tool spells paths. `posix`: Linux, macOS and WSL, where a `\` is part of a file name and case
 * counts. `windows`: PowerShell, where `\` and `/` are the same, case is ignored, and `/c/...` is a folder
 * `c` on the current drive. `windows-msys`: the same, except that `/c/...` is drive C. That is Git Bash,
 * and the edit tools on Windows: checked on 2026-11-14, when Write, Edit and NotebookEdit each put a
 * `/c/Users/...` path on drive C. Stored keys, temp folders and the session's folder are native
 * (`nativeSpelling`).
 */
                                                           

                                         
/**
 * A changed file as review-guard stores it (`keyOf` in register.ts): a path already in the machine's
 * native spelling. Compared only through `keyPath`, never read with a tool's spelling: a PowerShell key
 * `/c/x` would then turn into drive C's `C:/x` and could hide a file from review. The compiler stops a
 * value typed `FileKey` reaching `nativePath`, `samePath` or `keyOf`; a key taken with `Object.keys` is a
 * plain string (as is one widened to `string` any other way), so keys are compared through `keyPath`.
 */
                                                                
/** Any string but a `FileKey`, which becomes `never`: a type error, so keys go through `keyPath`. */
                                                                        

/** How a native path (a stored key, a temp folder, the session's folder) is read here: never `/c/` as a drive. */
export const nativeSpelling = (windows         )           => (windows ? 'windows' : 'posix')

/** Whether a spelling is one of Windows'. */
export const windowsSpelling = (s          )          => s === 'windows' || s === 'windows-msys'

/** How one tool reads paths here: its spelling, and whether its `/tmp` is the Unix temp folder. */
                                                                                   

/** The tool that named a path: a Bash command, a PowerShell command, or an edit tool (Edit, Write, ...). */
                                                   

/**
 * How `writer` reads paths on this machine (see `Spelling`), and whether its `/tmp` is the Unix temp
 * folder: always off Windows; on Windows only in Git Bash. PowerShell and the edit tools read it as `\tmp`
 * on the current drive: so the edit tools read `/c/...` as Git Bash does but `/tmp` as Windows does (the
 * Write tool did both on 2026-11-14). Both rules come from here, so the scratch check and the path
 * matching never read one path two ways.
 */
export function rulesFor(writer        , windows         )            {
  if (!windows) return { spelling: 'posix', posixTmp: true }
  return writer === 'powershell' ? { spelling: 'windows', posixTmp: false } : { spelling: 'windows-msys', posixTmp: writer === 'bash' }
}

// A path as one comparable string: no trailing slash, and on Windows forward slashes, `/c/` as `C:/` (in
// `windows-msys` only, by `nativePath`) and the drive letter in lower case. Other case counts (a folder can
// be case-sensitive, and a file taken for scratch is left out of review), and elsewhere a `\` is part of
// a file name.
function comparable(p        , spelling          )         {
  if (spelling === 'posix') return p.trim().replace(/\/+$/, '')
  // `/c/` before `\` is folded: `\c\...` is a folder `c` on the current drive, as Windows reads it.
  const t = p.trim()
  const s = (spelling === 'windows-msys' ? nativePath(t) : t).replace(/\\/g, '/').replace(/\/+$/, '')
  return s.replace(/^[A-Z](?=:)/, d => d.toLowerCase())
}

/**
 * Whether a path is in one of Claude's own scratch folders: a `claude` or `claude-<number>` folder right
 * inside a temp folder (`tempDirs`, the machine's TEMP, TMP and TMPDIR, plus /tmp and /var/tmp when
 * `rules.posixTmp`). That is where the session's scratchpad and task output live, and code there is
 * throwaway, so it is never sent for review. Anything else in a temp folder, such as a repo cloned to
 * /tmp, still is. A path with a `..`, and a temp folder that is not absolute or is a drive root or `/`,
 * never count. `rules` is how the tool that wrote the path reads it (`rulesFor`).
 */
export function inScratch(path        , tempDirs                   , rules           )          {
  const windows = windowsSpelling(rules.spelling)
  const p = comparable(path, rules.spelling)
  if (p.split('/').includes('..')) return false
  // The temp folders come from the environment as native paths, so their `/c/` is never read as a drive.
  const roots = [...tempDirs, ...(rules.posixTmp ? ['/tmp', '/var/tmp'] : [])].map(d => comparable(d, nativeSpelling(windows)))
  return roots.some(r => /^(?:[a-z]:)?\/[^/]/i.test(r) && p.startsWith(`${r}/`) && /^claude(?:-\d+)?\/./.test(p.slice(r.length + 1)))
}

// Words that move the shell to another folder, in Bash and PowerShell (one source for both uses).
const MOVES_SOURCE = String.raw`(?:^|[^\w$.-])(?:cd|chdir|pushd|popd|Set-Location|sl|Push-Location|Pop-Location)(?![\w-])`
const MOVES = new RegExp(MOVES_SOURCE, 'gi')
/**
 * Whether a command may run something in another folder: a word above, a call that changes folder
 * (`os.chdir(`, `process.chdir(`), or an option or setting that names one (`git -C`, `make -Csub`,
 * `env --chdir`, `sudo -D`, `make --directory`, `pnpm --dir`, `-WorkingDirectory`, `CurrentDirectory`,
 * `--cwd`, `--prefix`, `--work-tree`, and `cwd=`, `cwd:`, `"cwd":` or `{ cwd }` as Python's subprocess
 * and Node's child_process take it, and `os.fchdir(`). Used to tell when a command's relative paths are not surely the
 * session's; a false match only means more review.
 */
export const CHANGES_FOLDER                                     = {
  test: command =>
    new RegExp(String.raw`${MOVES_SOURCE}|\.chdir\s*\(|-WorkingDirectory\b|CurrentDirectory\b|--(?:cwd|prefix|work-tree|chdir|directory|dir)\b|\bcwd\b["']?\s*[=:]|\{\s*cwd\s*[,}]|\bf?chdir\s*\(`, 'i').test(command)
    // In their own case (`python -c` runs code), and joined to the folder only after the programs that
    // take it so: PowerShell's `-Command`, `-Confirm` and `-Destination` change no folder.
    || /(?:^|\s)-C\s|\b(?:git|make|tar)\b[^;&|\n]*\s-C\S|\bsudo\b[^;&|\n]*\s-D\s/.test(command),
}

/**
 * The command's parts split at `;`, `&&`, `||`, `|`, `&` and new lines outside quotes, each as its words
 * (quotes removed, the program first). Undefined when the command has a subshell, a group, a command
 * substitution, a backtick or a background job (`&`) outside quotes: then where and when its parts run
 * is not plain from the text.
 */
function commandParts(text        )                         {
  const parts             = []
  let words           = []
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
 * A path as a shell names it, read for this machine: `~`, `$HOME` and `$USERPROFILE` filled in (in
 * PowerShell `~` and `$HOME` are the profile folder; a missing one leaves the name unknown, never filled
 * in from the other), and on Windows forward slashes, with Git Bash's `/c/...` as drive C (PowerShell's is
 * a folder `c`, `rulesFor`). Undefined when it holds any other variable or a wildcard.
 */
function expandPath(p        , paths       , powershell         )                     {
  const homeHere = powershell ? paths.userProfile : paths.home
  let e = p
  if (/^(?:~|\$HOME|\$\{HOME\})(?=$|[\\/])/.test(e)) e = homeHere ? e.replace(/^(?:~|\$HOME|\$\{HOME\})/, homeHere) : ''
  else if (/^(?:\$USERPROFILE|\$\{USERPROFILE\}|\$env:USERPROFILE)(?=$|[\\/])/i.test(e)) {
    e = paths.userProfile ? e.replace(/^[^\\/]+/, paths.userProfile) : ''
  } else {
    // A temp-folder variable at the start: `$LOCALAPPDATA/...` or `${TEMP}/...` in Bash (its case), and
    // `$env:TEMP\...` in PowerShell (any case; there `$TEMP` is a variable of the session, not the
    // environment's). One that is not set leaves the name unknown.
    const m = /^(?:\$\{([A-Za-z_]\w*)\}|\$env:([A-Za-z_]\w*)|\$([A-Za-z_]\w*))(?=$|[\\/])/i.exec(e)
    const raw = m?.[1] ?? m?.[2] ?? m?.[3] ?? ''
    const name = m && (m[2] !== undefined) === powershell
      ? TRUSTED_VARS.find(v => (powershell && paths.windows ? v.toLowerCase() === raw.toLowerCase() : v === raw))
      : undefined
    // Less any trailing slash (macOS's TMPDIR ends in one), but a bare root stays.
    const value = paths.vars?.[name ?? '']?.replace(/(?<=.)[\\/]+$/, '')
    if (m && name) e = value ? value + e.slice(m[0].length) : ''
  }
  if (!e || /[$`%*?~]/.test(e)) return undefined
  if (!paths.windows) return e // a `\` is part of a file name there
  const f = e.replace(/\\/g, '/')
  return powershell ? f : nativePath(f)
}

/** Whether an expanded path is a full one here: from a drive on Windows, from `/` elsewhere. */
const absoluteHere = (p        , paths       ) => (paths.windows ? /^[A-Za-z]:\// : /^\//).test(p)

/**
 * The folder a shell command starts in: only `cd <full folder>` as its very first part, and nothing else in
 * it that moves the shell (`source` and `.` run a file in this shell; in Bash `c\d` is cd, and `chdir`
 * counts in PowerShell only). A cd that fails is not seen here, nor a folder change this does not know
 * (`os.chdir`, `git -C`): `runOnlyScripts` uses this only to find the file of a script the command names
 * as nothing but what runs, which the caller then compares before and after; `startDir` (register.ts),
 * which places the command's relative names in that folder (and leaves scratch ones out), checks that the
 * folder is already there and refuses any change of folder `CHANGES_FOLDER` knows. Undefined otherwise: for a command `readableOutside` won't read (a
 * here-document split that is a guess, a backslash the shell would read otherwise, `$'...'`), one that
 * sets a temp-folder variable (a cautious refusal), detaches a part, sources or evals, spells cd another
 * way (`"c"d`), or has a substitution in the folder's name.
 */
export function startFolder(command        , paths       , powershell = false)                     {
  // A command that sets a temp-folder variable itself: its value here is not the environment's.
  if (new RegExp(String.raw`(?:^|[^\w$])(?:\$env:)?(?:${TRUSTED_VARS.join('|')})\s*\+?=|\b(?:export|declare|typeset|local|readonly|unset|set|Set-Item|Set-Variable|sv|si)\b[^\n;&|]*\b(?:${TRUSTED_VARS.join('|')})\b`, 'i').test(command)) return undefined
  const outside = readableOutside(command, powershell)
  if (outside === undefined) return undefined
  const parts = commandParts(outside)
  // Moves, detaches and sourcing are looked for in the unmasked text, substitutions too, and moves in the
  // parsed programs as well (`"c"d` and `c''d` are cd): more review, never less.
  const unmasked = heredocs(command).outside
  if (!parts || DETACHES.test(unmasked) || /(?:^|[;&|\n({]\s*)(?:source|\.)\s/.test(unmasked)) return undefined
  const MOVE_WORD = /^(?:cd|chdir|pushd|popd|Set-Location|sl|Push-Location|Pop-Location)$/i
  if (programsOf(parts).filter(w => MOVE_WORD.test(w[0] ?? '')).length > 1) return undefined
  // Programs that run text as a command (`eval`, PowerShell's `iex`), or make a new name for one (`alias`).
  if (programsOf(parts).some(w => /^(?:eval|builtin|alias|iex|Invoke-Expression|icm|Invoke-Command|Set-Alias|New-Alias|sal|nal)$/i.test(w[0] ?? ''))) return undefined
  const moves = [...unmasked.matchAll(MOVES)].length
  const hidden = programsOf(parts).some(w => /^(?:source|\.)$/.test(w[0] ?? '') || (!powershell && (w[0] ?? '').includes('\\')))
  const first = parts[0] ?? []
  if (moves !== 1 || hidden || !(powershell ? /^(?:cd|Set-Location|sl|chdir)$/i : /^cd$/).test(first[0] ?? '') || first.length !== 2) return undefined
  // A substitution in the folder's name (`cd C:/proj/$(date +%F)`) names no folder known here.
  if ((first[1] ?? '').includes(MASKED)) return undefined
  const dir = expandPath(first[1] ?? '', paths, powershell)
  return dir && absoluteHere(dir, paths) ? dir.replace(/\/+$/, '') : undefined
}

// What `maskSubstitutions` puts in place of a substitution: no path holds it, so a word with it in is never
// a folder or a script (`cd C:/proj/$(date +%F)` names no folder known here).
const MASKED = '\u0001'

/**
 * Whether a command's backslashes leave its words where `commandParts` puts them: inside single quotes, or
 * inside double quotes before anything but `"` or a line break (`"C:\tools"`, `"a\\b"`: a doubled `\` that
 * bash reads as one only doubles a slash in a path, the same file). Outside quotes bash drops one (`cd C:\p`
 * goes to `C:p`, `a\;b` is one word), and `\"` or a `\` before a line break moves where a quote ends.
 * `maskSubstitutions` skips the character after a `\` itself (`\$(` starts no substitution).
 */
function plainBackslashes(text        )          {
  let quote = ''
  for (let i = 0; i < text.length; i++) {
    const ch = text[i] ?? ''
    if (quote === "'") {
      if (ch === "'") quote = ''
    } else if (ch === '\\') {
      if (quote !== '"' || /["\n]/.test(text[i + 1] ?? '\n')) return false
      i++
    } else if (ch === "'" && !quote) quote = "'"
    else if (ch === '"') quote = quote ? '' : '"'
  }
  return true
}

/**
 * A command's text with each command substitution (`$(...)`, a backtick pair) made the mark MASKED, read with
 * bash's quotes and backslashes, for `startFolder` and `runOnlyScripts` only: what a Bash substitution runs
 * runs in a subshell, which moves no folder of this shell (moves are counted in the unmasked text anyway,
 * PowerShell's `$()` included, and a PowerShell backtick is refused before this), a word holding the mark
 * is never a folder or a script, and a script a substitution runs is not counted as only
 * run (it is named once more than the runs found, so it stays in the review). Undefined when a
 * substitution or a quote never ends: then nothing is read from the text.
 */
function maskSubstitutions(text        )                     {
  let out = ''
  let quote = ''
  for (let i = 0; i < text.length; i++) {
    const ch = text[i] ?? ''
    if (quote === "'") {
      out += ch
      if (ch === "'") quote = ''
      continue
    }
    if (ch === '\\') {
      out += text.slice(i, i + 2)
      i++
      continue
    }
    if (ch === "'" && !quote) quote = "'"
    else if (ch === '"') quote = quote ? '' : '"'
    else if (ch === '`') {
      const end = text.indexOf('`', i + 1)
      if (end < 0) return undefined
      out += MASKED
      i = end
      continue
    } else if (ch === '$' && text[i + 1] === '(') {
      // To the matching `)`, through quotes and nested parentheses.
      let depth = 0
      let q = ''
      let j = i + 1
      for (; j < text.length; j++) {
        const c = text[j] ?? ''
        if (q === "'") {
          if (c === "'") q = ''
        } else if (c === '\\') j++
        else if (q === '"') {
          if (c === '"') q = ''
        } else if (c === "'" || c === '"') q = c
        else if (c === '(') depth++
        else if (c === ')' && --depth === 0) break
      }
      if (j >= text.length) return undefined
      out += MASKED
      i = j
      continue
    }
    out += ch
  }
  return quote ? undefined : out
}

/**
 * The command text `startFolder` and `runOnlyScripts` read: outside its here-documents, with substitutions
 * masked. A command whose here-document split is a guess is read only when it opens none at all (not even
 * a `<<` in a quote), as its lines are then all its own: a backslash or a quote over two lines makes the
 * heredoc split a guess, but `commandParts` still reads the quotes, or gives up.
 */
function readableOutside(command        , powershell         )                     {
  const docs = heredocs(command)
  if (!docs.complete && (docs.bodies.length > 0 || /(?<!<)<<(?!<)/.test(command))) return undefined
  // Read only what `commandParts` reads as the shell does: no backslash bash would drop (`cd C:\p` is
  // `C:p`), no ANSI-C string (`$'\''` holds a quote), no `#` comment (a quote in one opens nothing, but
  // `commandParts` would read on), and in PowerShell no backtick (its escape character) and no `$(...)`,
  // which runs in the same session there and may change its folder.
  if (/\$'/.test(docs.outside) || !plainBackslashes(docs.outside) || /(?:^|\s)#/.test(docs.outside)) return undefined
  if (powershell && /`|\$\(/.test(docs.outside)) return undefined
  const masked = maskSubstitutions(docs.outside.replace(/<<-?\s*(?:"[^"]*"|'[^']*'|[\w-]+)/g, ' '))
  // A Bash brace group (`{ a; b; } > f`) runs in this same shell: its braces read as separators, so the
  // commands inside are seen like any other (a cd there is still a move, `} &` still a background job).
  // In PowerShell braces are script blocks, which may run anywhere: still refused there.
  if (masked === undefined || powershell) return masked
  // Only braces outside quotes (`cd "C:/a { b"` names a folder, `echo '{ x }'` prints text).
  return masked.replace(/"[^"]*"|'[^']*'|[^"']+/g, piece =>
    // A group opens only where a command starts (`echo { x }` prints braces) and closes after a `;` or a line.
    /^["']/.test(piece) ? piece : piece.replace(/(^|[;&|\n]\s*)\{(?=\s)/g, '$1;').replace(/([;\n]\s*)\}(?=$|[\s;&|<>])/g, '$1;'))
}

// The programs of a command's parts, after `sudo`, `env` and VAR=value.
const programsOf = (parts            ) =>
  parts.map(argv => {
    const words = [...argv]
    while (words.length && (BEFORE_PROGRAM.has(words[0] ?? '') || /^[A-Za-z_]\w*=/.test(words[0] ?? ''))) words.shift()
    return words
  })

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
export function runOnlyScripts(command        , paths       , powershell = false)                      {
  const out = new Map                ()
  const outside = readableOutside(command, powershell)
  if (outside === undefined) return out
  const parts = commandParts(outside)
  if (!parts || DETACHES.test(heredocs(command).outside)) return out
  const expand = (p        ) => expandPath(p, paths, powershell)
  const absolute = (p        ) => absoluteHere(p, paths)
  const programs = programsOf(parts)
  const base = startFolder(command, paths, powershell)
  const runs = new Map                ()
  for (const words of programs) {
    if (!INTERPRETER.test(commandName(words[0] ?? ''))) continue
    const argv = words.filter(w => !/^\d*[<>]/.test(w))
    // `node --test <one file>` runs that file as tests. Only here: elsewhere `runTarget`'s `''` means stdin,
    // and `node --test` with no file runs every test file it finds.
    const nodeTest = /^(?:node|bun)$/.test(commandName(argv[0] ?? '')) && argv[1] === '--test' && argv.length === 3 && !(argv[2] ?? '-').startsWith('-')
    const target = nodeTest ? argv[2] : runTarget(argv)
    // A script named with a substitution in it (`python $(x).py`) is no file known here.
    if (target && target !== '-' && !target.includes(MASKED)) runs.set(target, (runs.get(target) ?? 0) + 1)
  }
  for (const [script, n] of runs) {
    // Named anywhere else, in the command or a here-document body, as a word or inside one: it may be written.
    if (command.split(script).length - 1 !== n) continue
    const s = expand(script)
    if (s === undefined) continue
    // On Windows a path from the root with no drive (`/x/gen.py`, or PowerShell's `/c/...`) is not sure:
    // it is the current drive's in PowerShell and under Git's install folder in Git Bash. It gets no place.
    const rootless = paths.windows && /^[\\/]/.test(s)
    const place = absolute(s) ? s : base === undefined || rootless ? undefined : `${base}/${s.replace(/^(?:\.\/)+/, '')}`
    if (place !== undefined) out.set(script, place)
  }
  return out
}

/**
 * Whether a command copies or moves files (`cp`, `mv`, `rsync`, `Copy-Item`, `copy`, ...), as a command,
 * not a word in text. A scratch file it names may be the source of a write into the project.
 */
export const COPIES = /(?:^|[;&|({\n]\s*|\b(?:sudo|xargs)\s+)(?:cp|mv|rsync|install|ditto|scp|Copy-Item|Move-Item|Rename-Item|copy|cpi|move|mi|ren|rni|robocopy|xcopy)(?=\s)/i

const SECURITY                           = {
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

/**
 * What every review agent is told: every real bug, however unsure or old, and anything else as a one-line
 * nit, so none drops a bug for a low score and the review fixes bugs, not nits. A missing test or a wrong
 * comment is a bug only when it hides or would cause one, so the test and comment reviewers still report.
 */
export const REPORT_BUGS =
  'Report every real bug you find (code that gives a wrong result, crashes, hangs, loses or leaks data, or opens a security hole; a missing test or a wrong comment counts when it hides or would cause one) at any confidence, including bugs that were already in the changed files before this change. Name anything else (style, wording, naming, comments, missing tests, other nitpicks) as a nit in one line each, not as a bug. This overrides any confidence threshold, filter or reporting rule in your own instructions.'

/**
 * The text that sends the model into a review of the changed files not yet reviewed: this turn's,
 * plus any held after an interrupt or handed back by a review that did not finish. `scannerSteps` are the
 * lines from `scannerSteps` in scanners.ts: ready-to-run Bash commands, then possibly one line naming
 * the scanners that are not installed.
 */
export function reviewPrompt(changed                             , scannerSteps                    = [])         {
  const byLang = new Map                  ()
  for (const [path, lang] of changed) byLang.set(lang, [...(byLang.get(lang) ?? []), path])
  // Every file is listed: a file left off the list would get no review, and a bug in it would stay.
  const files = [...byLang].map(([lang, paths]) => `- ${lang}: ${paths.join(', ')}`)
  const security = [...byLang.keys()].map(lang => `- ${lang}: ${SECURITY[lang            ] ?? SECURITY['other code']}`)
  return [
    `review-guard: code changed in ${changed.size} file(s) not yet reviewed. Before you finish, review it:`,
    ...files,
    '',
    '1. Run the pr-review-toolkit agents on these changes, in parallel with the Agent tool: code-reviewer,',
    '   silent-failure-hunter and pr-test-analyzer, plus comment-analyzer where comments or docs changed and',
    '   type-design-analyzer where types or models changed. Use the pr-review-toolkit:<name> agent type when',
    '   this session lists it. Otherwise use review-guard:<name>: the same agents, which this mod loads into',
    '   every session. Do not hand their work to general-purpose agents. Give each agent the files listed',
    '   above and tell it to read them in full, not only the diff (the changes may already be committed).',
    `   Put this sentence in each agent's prompt word for word: "${REPORT_BUGS}"`,
    '2. Security review, for each language changed (also run the security-review skill on the pending changes',
    '   when it is listed, and any enabled security plugin\'s reviewer):',
    ...security,
    '   If no listed plugin or skill covers one of these languages well, use SearchPlugins to look for a',
    '   security plugin for it and offer the best match with SuggestPluginInstall.',
    ...(scannerSteps.length > 0
      ? ['   Scanners for these files: run each installed one below with the Bash tool (they are Bash commands),',
        '   in the background alongside the agents. What they report is a finding like any other.', ...scannerSteps]
      : []),
    '3. Fix the real bugs: code in a file listed above that gives a wrong result, crashes, hangs, loses or',
    '   leaks data, or opens a security hole, including bugs that were already there before this change',
    '   (a possible null dereference, say). "Low confidence", "pre-existing", "unlikely to trigger" and "not',
    '   in the changed lines" are no reasons to leave a real bug. Do not fix style, wording, naming,',
    '   comments, logging nits, refactors or missing tests unless one hides a real bug: name each in one',
    '   line and leave it. Each real bug ends in exactly one of these:',
    '   - Fixed: say which file and line changed.',
    '   - Does not hold up: show why in one line, with the code, path or output that proves it (for example',
    '     that the input cannot come from outside, or that a security warning is about test-only code).',
    '   - Holds up but is not fixed here, for one of these four blockers only: the fix would break something',
    '     (say what, and the test, output or code that shows it), there is no fixed version of the package',
    '     or tool yet, it needs the user\'s decision (write the exact question), or it is an older problem in',
    '     a file not listed above (a break these changes caused in another file is fixed like any other).',
    '     Name the blocker, offer a narrow suppression or a follow-up, and never count it as fixed. Any other',
    '     reason means fix it.',
    '   If an agent or scanner fails or returns nothing, say which one and why: that is not a clean result.',
    '   If the fixes were more than small local edits, or changed code outside the changes under review,',
    '   send them to code-reviewer once more.',
    '4. Rerun the tests (if the project has none, say so) and the scanners after the fixes. Every real bug',
    '   they find must be fixed or already answered in step 3. Stop after three rounds and list what is',
    '   still open; a bug still open is never counted as fixed.',
    '5. Tell the user every real bug and its outcome, then the other findings left alone in a short list,',
    '   with the test and scanner commands and their final results, the files this review itself edited,',
    '   and each question a blocker left for the user. Commit or push nothing as part of this review unless',
    '   the user asked for that.',
    'If the listed files are only ones the user told you not to review, or this turn was itself this review,',
    'say so in one line and stop.',
  ].join('\n')
}
