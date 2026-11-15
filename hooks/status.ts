// The review status file: each session's review state, written by the hooks (register.ts) and read by
// the MCP server's review_status tool (mcp/server.mjs), which runs in another process and can't see the
// engine's state. Shared here so both sides agree on where it is and what it holds.

/** Why a file was left out of the review, as the hooks write it. */
export type LeftOutWhy = 'scratch' | 'only run' | 'scratch script'

/**
 * One file left out of the review. A reader takes any short reason (`why`), so a status file from a
 * newer mod, with a reason this one doesn't know, is still read.
 */
export type LeftOut = { path: string; why: LeftOutWhy | (string & {}); at: string }

/** Where the session's reviews stand. */
export type Phase = 'idle' | 'reviewing' | 'held' | 'ended'

/** What a session's status file holds. */
export type StatusFile = {
  v: 1
  session: string
  /** The session's folder, when it could be read. */
  folder?: string
  /** When the file was written (ISO time). */
  updated: string
  phase: Phase
  /** Code files waiting for review. */
  queued: string[]
  /** What the running review covers (empty unless `phase` is "reviewing"). */
  underReview: string[]
  /** Files left out of the review, newest last, since `leftOutSince`. */
  leftOut: LeftOut[]
  /** When the list of left-out files started: it lives in memory, so a reload of the mod starts it again. */
  leftOutSince: string
  /** Set when the last write failed, so the file may be behind: what went wrong. */
  writeFailed?: string
}

/** The status folder under a home folder (forward slashes, no trailing slash). */
export const statusDir = (home: string) => `${home.replace(/\\/g, '/').replace(/\/+$/, '')}/.claude/review-guard/status`

/**
 * A session id as a file name: anything but letters, digits, `_` and `-` becomes `%` and its four-digit
 * hex code, so two different ids never share a file (`%` is encoded too).
 */
export const statusFileName = (session: string) =>
  `${session.replace(/[^\w-]/g, c => `%${c.charCodeAt(0).toString(16).padStart(4, '0')}`)}.json`

const PHASES: readonly Phase[] = ['idle', 'reviewing', 'held', 'ended']
const isText = (x: unknown): x is string => typeof x === 'string'
const isTextList = (x: unknown): x is string[] => Array.isArray(x) && x.every(isText)
const isTime = (x: unknown): x is string => isText(x) && !Number.isNaN(Date.parse(x))

/**
 * A status file's parsed JSON as a `StatusFile`, or undefined when its shape is wrong in any way (so the
 * reader can say it can't be read rather than show part of it, or drop it unseen).
 */
export function statusFrom(x: unknown): StatusFile | undefined {
  if (typeof x !== 'object' || x === null || Array.isArray(x)) return undefined
  const s = x as Record<string, unknown>
  if (s.v !== 1 || !isText(s.session) || !isTime(s.updated)) return undefined
  if (!PHASES.includes(s.phase as Phase) || !isTextList(s.queued) || !isTextList(s.underReview) || !isTime(s.leftOutSince)) return undefined
  if (s.folder !== undefined && !isText(s.folder)) return undefined
  if (s.writeFailed !== undefined && !isText(s.writeFailed)) return undefined
  if (!Array.isArray(s.leftOut)) return undefined
  const leftOut: LeftOut[] = []
  for (const l of s.leftOut) {
    if (typeof l !== 'object' || l === null) return undefined
    const { path, why, at } = l as Record<string, unknown>
    if (!isText(path) || !isText(why) || why === '' || why.length > 40 || !isTime(at)) return undefined
    leftOut.push({ path, why, at })
  }
  return {
    v: 1,
    session: s.session,
    ...(s.folder !== undefined ? { folder: s.folder } : {}),
    updated: s.updated,
    phase: s.phase as Phase,
    queued: s.queued,
    underReview: s.underReview,
    leftOut,
    leftOutSince: s.leftOutSince,
    ...(s.writeFailed !== undefined ? { writeFailed: s.writeFailed } : {}),
  }
}
