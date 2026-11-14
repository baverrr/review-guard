/** The review cycle, kept in the session's state so a reload of the mod does not forget it. */
export type Cycle = {
  /** A review this mod asked for is running: its own fixes are not sent for another. */
  reviewing: boolean
  /** The user interrupted a turn: no review is asked for until work on code picks up again. */
  held: boolean
  /** Code files changed and not yet sent for review: path to language. */
  changed: Record<string, string>
  /** What the running review covers, put back in `changed` if the review is cut short. */
  underReview: Record<string, string>
  /**
   * The agents that are other work in the running review: those present when it began (idle teammates
   * included), plus any that other work starts or messages, less those that joined. They do not hold the
   * review open. An agent the main conversation or the review's agents start does.
   */
  othersAtStart: string[]
  /**
   * Code files changed during the review by other work, and by joined agents outside the files under
   * review: not the review's fixes, so they are queued for a review of their own when it ends.
   */
  othersChanged: Record<string, string>
  /**
   * Agents that work for the review although it did not start them: earlier agents that the main
   * conversation or the review's agents started again or messaged, earlier agents seen finished (so a
   * later run is the review's), and new helpers that one of these starts. Their edits to files under
   * review are the review's fixes; their edits to any other file are their own work, so they go to
   * `othersChanged` for a review of their own. Never also in `othersAtStart`.
   */
  joined: string[]
  /**
   * The running review's prompt was handed out but is not yet known to have reached Claude: the next
   * stop, the turn's end, or a new request shows it (a Stop hook continuation if it arrived). Saved, so a
   * reload keeps it. A copy from before 0.3.6 has none, and is read as arrived.
   */
  promptPending: boolean
}
// Outside a review (`reviewing` false), `underReview`, `othersAtStart`, `othersChanged` and `joined` are
// empty and `promptPending` is false; `cycleFrom` restores that for any stored copy.

declare module 'claude-code' {
  interface PluginState {
    'review-guard': { cycle: Cycle }
  }
}
