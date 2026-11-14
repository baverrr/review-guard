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
   * The ids of the agents already at work when the running review began: other work, which does not
   * hold the review open. Every agent started after it (reviewers, a fork fixing findings) does.
   */
  othersAtStart: string[]
  /**
   * Code files those other agents changed while the review ran: not the review's fixes, so they are
   * queued for a review of their own when it ends.
   */
  othersChanged: Record<string, string>
}

declare module 'claude-code' {
  interface PluginState {
    'review-guard': { cycle: Cycle }
  }
}
