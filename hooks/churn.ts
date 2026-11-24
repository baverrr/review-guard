// Churn: when the same files of a project keep coming back for review, new code in them is likely making
// new bugs faster than reviews remove them. Each project (the session's folder) keeps a short history of
// its reviews in ~/.claude/review-guard/history/, shared by every session in that folder. When a file has
// been in too many reviews lately (the "churn" rule in review-guard.json), the review prompt asks Claude to
// steady it (tests, a design check with the user) before adding more to it.
//
// The pure parts are here; register.ts reads and writes the file. Two sessions in one folder that record
// a review at the same moment may lose one of the two entries (there is no lock): that only means a
// churning file is noticed a review later, never a review skipped.

import { CHURN_HISTORY_KEPT, type ChurnRule } from './outgoing.ts'

/** One review: when its prompt went out, and the files it covered (as `samePath` spells them). */
export type Review = { readonly at: string; readonly files: readonly string[] }

/** A project's review history, oldest first (`historyFrom` sorts it). */
export type History = { readonly v: 1; readonly folder: string; readonly reviews: readonly Review[] }

/** A file that keeps coming back: how many reviews in the window it was in. */
export type Churned = { readonly path: string; readonly reviews: number }

/** Reviews kept per project at most, so a busy project's file stays small. */
export const HISTORY_KEPT = CHURN_HISTORY_KEPT

/** The history folder under a home folder (forward slashes, no trailing slash). */
export const historyDir = (home: string) => `${home.replace(/\\/g, '/').replace(/\/+$/, '')}/.claude/review-guard/history`

/**
 * A project folder as the history keys it: forward slashes, no trailing slash, and the drive letter in
 * capitals, so the spellings one Windows session gives of its folder share one file. Other case is kept
 * (as for files under review): two spellings that differ in it give two file names, which a disk that
 * ignores case (NTFS, as usual) still reads as one file.
 */
export function projectKey(folder: string): string {
  return folder.replace(/\\/g, '/').replace(/(?<=.)\/+$/, '').replace(/^([a-z]):/, (_, d: string) => `${d.toUpperCase()}:`)
}

/** FNV-1a, 32 bits, as eight hex digits: only to keep long file names apart, not for security. */
function fnv(text: string, seed: number): string {
  let h = seed >>> 0
  for (let i = 0; i < text.length; i++) {
    h ^= text.charCodeAt(i)
    h = Math.imul(h, 0x01000193) >>> 0
  }
  return h.toString(16).padStart(8, '0')
}

/** Longest file name kept as is: well under the 255-character limit, and Windows' 260 for the full path. */
const NAME_KEPT = 120

/**
 * A project folder as a file name: anything but ASCII letters, digits, `_` and `-` as `%` and four hex
 * digits, so two folders never share a file (`%` is encoded too). A name that would be too long keeps its
 * end (the folder's own name) and adds two 32-bit FNV-1a hashes of the whole, with different seeds.
 */
export function historyFileName(folder: string): string {
  const key = projectKey(folder)
  const name = key.replace(/[^\w-]/g, c => `%${c.charCodeAt(0).toString(16).padStart(4, '0')}`)
  if (name.length <= NAME_KEPT) return `${name}.json`
  return `${name.slice(-(NAME_KEPT - 18))}~${fnv(key, 0x811c9dc5)}${fnv(key, 0x050c5d1f)}.json`
}

const isTime = (x: unknown): x is string => typeof x === 'string' && !Number.isNaN(Date.parse(x))

/**
 * A history file's parsed JSON for `folder`, oldest first. No file (`undefined`) gives an empty history.
 * A file of the wrong shape gives an empty one and `damaged`, and bad entries are dropped (`dropped`, the
 * rest kept): a lost entry only means a churning file is noticed later, never a review skipped.
 */
export function historyFrom(x: unknown, folder: string): { history: History; damaged: boolean; dropped: number } {
  const empty: History = { v: 1, folder: projectKey(folder), reviews: [] }
  if (x === undefined) return { history: empty, damaged: false, dropped: 0 }
  if (typeof x !== 'object' || x === null || Array.isArray(x)) return { history: empty, damaged: true, dropped: 0 }
  const h = x as Record<string, unknown>
  if (h.v !== 1 || !Array.isArray(h.reviews)) return { history: empty, damaged: true, dropped: 0 }
  const reviews: Review[] = []
  let dropped = 0
  for (const r of h.reviews) {
    const { at, files } = (typeof r === 'object' && r !== null ? r : {}) as Record<string, unknown>
    if (!isTime(at) || !Array.isArray(files) || files.some(f => typeof f !== 'string')) {
      dropped++
      continue
    }
    reviews.push({ at, files: [...new Set(files as string[])] })
  }
  reviews.sort((a, b) => Date.parse(a.at) - Date.parse(b.at))
  return { history: { ...empty, reviews }, damaged: false, dropped }
}

/**
 * `history` with a review of `files` at `at` added, keeping only reviews in the rule's window before
 * `now` (none dated after `now`: a clock moved back must not leave entries that count for good) and at
 * most `HISTORY_KEPT`, the newest.
 */
export function withReview(history: History, files: readonly string[], at: Date, now: Date, rule: ChurnRule): History {
  const since = now.getTime() - rule.hours * 3_600_000
  const reviews = [...history.reviews, { at: at.toISOString(), files: [...new Set(files)] }]
    .filter(r => {
      const t = Date.parse(r.at)
      return t >= since && t <= now.getTime()
    })
    .sort((a, b) => Date.parse(a.at) - Date.parse(b.at))
    .slice(-HISTORY_KEPT)
  return { ...history, reviews }
}

/**
 * The files of the review now starting (`files`) that churn under `rule`, judged on the reviews of
 * `history` in the window before `now` (the count includes this review when `history` holds it, as
 * `withReview` makes it), most-reviewed first.
 */
export function churned(history: History, files: readonly string[], rule: ChurnRule, now: Date): Churned[] {
  // The window is checked again here, so a history built some other way (by hand, say) is judged the same.
  const since = now.getTime() - rule.hours * 3_600_000
  // One pass over the history, so a review of thousands of files stays quick (this runs at a turn's end).
  const counts = new Map<string, number>()
  for (const r of history.reviews) {
    const t = Date.parse(r.at)
    if (t < since || t > now.getTime()) continue
    for (const f of new Set(r.files)) counts.set(f, (counts.get(f) ?? 0) + 1)
  }
  return [...new Set(files)]
    .map(path => ({ path, reviews: counts.get(path) ?? 0 }))
    .filter(f => f.reviews >= rule.reviews)
    .sort((a, b) => b.reviews - a.reviews)
}

/** The paragraph added to the review prompt when files churn. */
export function churnNote(found: readonly Churned[], rule: ChurnRule): string {
  const list = found.map(f => `${f.path} (${f.reviews} reviews)`).join(', ')
  return [
    '',
    `review-guard: some of these files keep coming back. In this project they have been in ${rule.reviews} or more`,
    `reviews in the last ${rule.hours} hours: ${list}. New code keeps going into them and each review finds more`,
    'to fix, a sign they need steadying, not more features. Do the review above first, then:',
    '- Add no new features to these files in this turn.',
    '- Write or extend tests that pin down what each of them should do, around the bugs this review found.',
    '- Tell the user these files keep coming back, and ask whether their design needs another look before more',
    '  work goes into them (write the exact question).',
  ].join('\n')
}
