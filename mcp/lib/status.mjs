// Generated from hooks/status.ts by scripts/build-mcp.mjs. Do not edit. source-sha256: 4e8a9a52d4dc68ef15404c666d96ff36ac318f6e723a80b4b6f4efa2e6320d7c built-sha256: 816308e5480cbd801ad2246895e36ae100e46046ba66e8be513f1cbe80b1f8f4
// The review status file: each session's review state, written by the hooks (register.ts) and read by
// the MCP server's review_status tool (mcp/server.mjs), which runs in another process and can't see the
// engine's state. Shared here so both sides agree on where it is and what it holds.

/** Why a file was left out of the review. */
                                               

/** One file left out of the review. */
                                                                   

/** Where the session's reviews stand. */
                                                           

/** What a session's status file holds. */
                          
      
                 
                                                     
                 
                                              
                 
              
                                       
                  
                                                                              
                       
                                                                         
                    
                                                                                                             
                      
                                                                                    
                      
 

/** The status folder under a home folder (forward slashes, no trailing slash). */
export const statusDir = (home        ) => `${home.replace(/\\/g, '/').replace(/\/+$/, '')}/.claude/review-guard/status`

/**
 * A session id as a file name: anything but letters, digits, `_` and `-` becomes `%` and its four-digit
 * hex code, so two different ids never share a file (`%` is encoded too).
 */
export const statusFileName = (session        ) =>
  `${session.replace(/[^\w-]/g, c => `%${c.charCodeAt(0).toString(16).padStart(4, '0')}`)}.json`

const PHASES                   = ['idle', 'reviewing', 'held', 'ended']
const isText = (x         )              => typeof x === 'string'
const isTextList = (x         )                => Array.isArray(x) && x.every(isText)
const isTime = (x         )              => isText(x) && !Number.isNaN(Date.parse(x))

/**
 * A status file's parsed JSON as a `StatusFile`, or undefined when its shape is wrong in any way (so the
 * reader can say it can't be read rather than show part of it, or drop it unseen).
 */
export function statusFrom(x         )                         {
  if (typeof x !== 'object' || x === null || Array.isArray(x)) return undefined
  const s = x                           
  if (s.v !== 1 || !isText(s.session) || !isTime(s.updated)) return undefined
  if (!PHASES.includes(s.phase         ) || !isTextList(s.queued) || !isTextList(s.underReview) || !isTime(s.leftOutSince)) return undefined
  if (s.folder !== undefined && !isText(s.folder)) return undefined
  if (s.writeFailed !== undefined && !isText(s.writeFailed)) return undefined
  if (!Array.isArray(s.leftOut)) return undefined
  const leftOut            = []
  for (const l of s.leftOut) {
    if (typeof l !== 'object' || l === null) return undefined
    const { path, why, at } = l                           
    if (!isText(path) || (why !== 'scratch' && why !== 'only run') || !isTime(at)) return undefined
    leftOut.push({ path, why, at })
  }
  return {
    v: 1,
    session: s.session,
    ...(s.folder !== undefined ? { folder: s.folder } : {}),
    updated: s.updated,
    phase: s.phase         ,
    queued: s.queued,
    underReview: s.underReview,
    leftOut,
    leftOutSince: s.leftOutSince,
    ...(s.writeFailed !== undefined ? { writeFailed: s.writeFailed } : {}),
  }
}
