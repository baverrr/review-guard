# How a review runs

When a turn ends with code changed, review-guard asks Claude for a review of the changed files. This
page says when that review counts as over, and what happens to the edits made while it runs.

## The review's own work and other work

- **The review's own agents.** A review stays open while one of its own agents is still working, so
  fixes that come back with its reports are not reviewed again. An agent that the main conversation or
  one of the review's agents starts after the review began is one of its own, whatever its type: a
  reviewer, an agent doing the security review, a fork fixing findings. A workflow's agents and
  background shell commands never hold a review open.
- **What counts as a fix.** While a review runs, every edit by the main conversation or the review's own
  agents counts as one of its fixes and is not reviewed again, whatever the file.
- **Other work.** Agents already there when the review began (idle teammates included) are other work.
  They don't hold the review open, and files they change meanwhile are queued when it ends, for a
  review of their own. An agent that other work starts or messages becomes (or stays) other work.
- **Earlier agents that join.** An earlier agent that the main conversation or one of the review's
  agents starts again or messages, or one that finishes and later runs again, is part of the review
  from then on. Its edits to files under review are fixes; its edits to any other file still get their
  own review, and so do those of a helper it starts.
- **Paths.** To tell whether a joined agent's edit is to a file under review, a path is matched
  however it is spelled: `\` or `/`, Git Bash's `/c/...`, and on Windows any case. A relative path is
  read against the session's folder, but only when that is surely its folder: not after a command
  changed folder (`cd sub && ...`), and not for an agent with a folder of its own. A path that is still
  relative then never counts as a file under review, which can only mean more review.

## Timing

- An agent start that goes through, or is still under way, while an end-of-turn check runs keeps the
  review open until a later check. An agent that appears right as a review starts is other work (if the
  agent list can't be read again just then, it counts as the review's, and the status line says so).
- An agent that is still starting after two minutes no longer holds a review open, so one stuck start
  can't keep a review open for good.
- If the agents can't be listed as a review begins, every agent counts as part of it, and the status
  line says so.

## When a review ends

- At the first end of a turn where none of its agents is working and no agent start is under way.
- When you send a new request: edits after it get a review of their own.
- When you stop the turn, or it fails: its files go back in the queue (after a stop, until Claude edits
  code again).
- When the agent list can't be read at an end-of-turn check: the status line says so.

## A review prompt that never arrives

The review prompt reaches Claude as a continuation of the turn. If the turn ends another way instead
(it ends with an answer, the next stop is not that continuation, or a new request comes with no turn
running), the prompt never arrived: its files go back in the queue and the review is asked for again.
A new request typed while the review's turn still runs shows the prompt did arrive.

## Where the state lives

The review state is saved in the session, so a reload of the mod in the middle of a review keeps it
(the counts of agent starts are kept in memory only, and start again after a reload). A session with
something to report also writes it to `~/.claude/review-guard/status/` for the `review_status` tool. Old
files there are not removed; the tool shows the last 24 hours.
