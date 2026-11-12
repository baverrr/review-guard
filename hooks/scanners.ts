// review-guard's outside scanners: gitleaks, bandit, semgrep, zizmor and trivy. Pure functions over
// text and paths, like scan.ts; outgoing.ts finds the programs and runs gitleaks, and the review gives
// Claude the commands for the rest.
//
// None of them is required. One that is not installed is left out (and said so), never a reason to stop
// a command, except gitleaks failing to run once found, which stops the commit or push like any failed check.

import type { Finding, Language } from './scan.ts'

export const SCANNERS = ['gitleaks', 'bandit', 'semgrep', 'zizmor', 'trivy'] as const
export type Scanner = typeof SCANNERS[number]

/**
 * The scanners the review step runs; gitleaks runs by itself on what leaves: commits and pushes to
 * GitHub, GitHub writes, and the MCP server's checks.
 */
export type ReviewScanner = Exclude<Scanner, 'gitleaks'>

/**
 * Where a scanner may be, in the order to try: the folders it is installed into by hand (they need not
 * be on PATH, which on Windows a Claude session can't change for the rest of the system), then PATH.
 * `home` uses forward slashes.
 */
export function candidates(name: Scanner, home: string | undefined, windows: boolean): string[] {
  const exe = windows ? `${name}.exe` : name
  const dirs = !home ? [] : windows
    ? [`${home}/Tools/scanners/bin`, `${home}/Tools/scanners/venv/Scripts`]
    : [`${home}/.local/bin`, `${home}/Tools/scanners/bin`, `${home}/Tools/scanners/venv/bin`]
  return [...dirs.map(d => `${d}/${exe}`), name]
}

/** The arguments that make a scanner print its version: a cheap way to see that it runs. */
export const VERSION_ARGS: Record<Scanner, readonly string[]> = {
  gitleaks: ['version'],
  bandit: ['--version'],
  semgrep: ['--version'],
  zizmor: ['--version'],
  trivy: ['--version'],
}

/**
 * Which review scanners suit these changed files, and the files each one should get.
 * `changed` maps each changed path to its language label from `languageOf` in scan.ts
 * ('Python', 'TypeScript', 'GitHub Actions', 'dependencies', 'Docker', 'config', ...).
 * A scanner with no files is left out of the map.
 */
export function scannersFor(changed: ReadonlyMap<string, string>): Map<ReviewScanner, string[]> {
  const out = new Map<ReviewScanner, string[]>()
  for (const [path, language] of changed) {
    for (const tool of SCANNERS_BY_LANGUAGE[language as Language] ?? []) out.set(tool, [...(out.get(tool) ?? []), path])
  }
  return out
}

// Which review scanners each language label gets. A label not listed (CSS, SQL, PowerShell, plain config) gets none:
// semgrep's default rules say little about them, and trivy's config checks on any YAML or TOML are noise.
// Workflows go to zizmor alone, since semgrep's workflow rules repeat its findings (unpinned actions).
const SCANNERS_BY_LANGUAGE: Partial<Record<Language, readonly ReviewScanner[]>> = {
  Python: ['bandit', 'semgrep'],
  TypeScript: ['semgrep'],
  JavaScript: ['semgrep'],
  'HTML templates': ['semgrep'],
  'C#': ['semgrep'],
  'C/C++': ['semgrep'],
  Shell: ['semgrep'],
  Go: ['semgrep'],
  Rust: ['semgrep'],
  'Java/Kotlin': ['semgrep'],
  'other code': ['semgrep'],
  'GitHub Actions': ['zizmor'],
  Docker: ['trivy', 'semgrep'],
  dependencies: ['trivy'],
}

/** A path as one Bash word: single quotes, in which Bash expands nothing (a ' inside is closed, escaped, reopened). */
const quote = (p: string) => `'${p.replace(/'/g, "'\\''")}'`

/** The Bash command line that runs a review scanner on some files. */
export function scannerCommand(tool: ReviewScanner, exe: string, files: readonly string[]): string {
  const paths = files.map(quote).join(' ')
  switch (tool) {
    case 'bandit':
      return `${quote(exe)} -q ${paths}`
    case 'semgrep':
      // The registry's default rules; no usage metrics sent, no version check.
      return `${quote(exe)} scan --config p/default --metrics=off --disable-version-check --quiet ${paths}`
    case 'zizmor':
      // Offline: it asks GitHub nothing (online checks need a token).
      return `${quote(exe)} --offline ${paths}`
    case 'trivy':
      // `trivy fs` takes one path, so one run per file (package.json and its lock file change together).
      return files.map(f => `${quote(exe)} fs --scanners vuln,misconfig,secret --quiet ${quote(f)}`).join('; ')
  }
}

const PURPOSE: Record<ReviewScanner, string> = {
  bandit: 'risky Python',
  semgrep: 'risky code patterns, any language',
  zizmor: 'GitHub Actions security',
  trivy: 'known holes in dependencies and Docker images',
}

/**
 * The review prompt's scanner lines: one ready-to-run command per scanner that suits the changed files
 * and is installed (`found` maps a scanner to its program), then one line naming the suitable ones that
 * are not installed, so a skipped scanner is never silent.
 */
export function scannerSteps(changed: ReadonlyMap<string, string>, found: ReadonlyMap<Scanner, string>): string[] {
  const lines: string[] = []
  const missing: string[] = []
  for (const [tool, files] of scannersFor(changed)) {
    const exe = found.get(tool)
    if (exe) lines.push(`   - ${tool} (${PURPOSE[tool]}): ${scannerCommand(tool, exe, files)}`)
    else missing.push(tool)
  }
  if (missing.length > 0) lines.push(`   - Not installed here (or would not run), so skipped (say so in your summary): ${missing.join(', ')}`)
  return lines
}

/**
 * Findings from gitleaks' JSON report (`gitleaks stdin --report-format json --report-path -`).
 * `places[i]` says where line i + 1 of the text it read came from. The secret is kept as the value,
 * for allowValues only; it is never shown.
 */
export function gitleaksFindings(json: string, places: readonly string[]): Finding[] {
  const text = json.trim()
  // gitleaks writes "[]" when it finds nothing, so no report at all means it did not do its job.
  if (text === '') throw new Error('gitleaks gave no report')
  let parsed: unknown
  try {
    parsed = JSON.parse(text)
  } catch {
    // Never the parser's own message: it quotes the report around the mistake, and the report holds secrets.
    throw new Error('gitleaks gave a report that is not valid JSON')
  }
  if (!Array.isArray(parsed)) throw new Error('gitleaks gave a report that is not a list')
  return parsed.map((x: { RuleID?: unknown; StartLine?: unknown; Secret?: unknown }) => ({
    kind: `a secret gitleaks found (${typeof x.RuleID === 'string' ? x.RuleID : 'unknown rule'})`,
    where: (typeof x.StartLine === 'number' ? places[x.StartLine - 1] : undefined) ?? 'the changes',
    value: typeof x.Secret === 'string' ? x.Secret : undefined,
  }))
}
