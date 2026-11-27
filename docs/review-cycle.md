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
  however it is spelled. On Windows `\` and `/` are the same and the drive letter's case is ignored (other
  case counts: a folder can be case-sensitive, and there `A.py` and `a.py` are two files), and in Git Bash and the
  edit tools `/c/...` is drive C (a file changed that way is listed as `C:/...`); in PowerShell `/c/...`
  is a folder `c` on the current drive, so it is never taken for drive C, and so is `\c\...` from any tool.
  On Windows a path with no drive
  (`/proj/x.py`) names a different file in each tool, so it never counts as a file under review. A file
  changed under two full spellings is listed once, under the first, in each list and again when lists
  are joined (when a review ends or is cut short, or a saved state with no review running is read
  back). Not across a `..` step, which through a link may name another file: such a path is never taken
  for a file under review either. A known language is never replaced by `other code`. The check for
  Claude's scratch folders ignores only the drive letter's case too.
- **Scratch scripts.** A Bash command that does nothing but write scripts into a scratch folder and run
  them names no file of its own in their text, so those names are left out, said on the status line as
  "with a scratch script" and kept in the status file. Every statement of such a command must be one of
  three forms: `NAME=value` at its very start, `cat > <file> <<'TAG'` (a quoted tag, stdout only), or a
  program such as `bash`, `node` or `python` running a scratch file with plain arguments and flags that
  take no code, then at most `2>&1` and `| head -N` or `| tail -N`. Only a full path counts as scratch,
  after the leading variables are filled in: not a relative path, `$TEMP` or any other variable. Anything
  else in the command (a copy, a pipe into another program, another here-document, a glob, a function)
  leaves its text in the review.
- **A cd into the scratch folder.** A command that starts with `cd` into Claude's scratch folder, by a full
  path or by a temp-folder variable at its start (`$TEMP`, `$TMP`, `$TMPDIR`, `$LOCALAPPDATA`, or
  `$env:TEMP` in PowerShell, filled in with the values the hooks read; `~`, `$HOME` and `$USERPROFILE`
  are filled in as everywhere), writes its bare file names there (`body.html`, not `sub/a.py`, `D:a.ts` or
  `..`), so they are left out as scratch and named on the status line. Trusting those variables was the
  user's choice: a shell profile (or Git Bash's own, for `TMPDIR`) could set them otherwise. Only when:
  the folder is already there before the command runs and can be entered, and is Claude's scratch folder both as written and
  with every link followed (so the cd can't fail, and a write after a `;` lands there too); the cd's word
  is one the shell expands as written (no `$` or `~` in single quotes, no `~` in double quotes, no
  unquoted variable holding a space); the cd is not piped on (`cd X | ...`, `cd X || ...`); nothing after
  it changes folder (another cd in any spelling, `os.chdir`, `git -C`, `--prefix`, `patch -d`, a program
  named by a variable); the command sets none of those variables itself, and is not run in the
  background. Scratch names are still kept when the command copies or moves (`cp`, `mv`). The start
  folder is read as under "Scripts only run". (The rule for scratch scripts above is unchanged: there a
  variable is not filled in.)
- **A cd into another folder.** Under the same conditions as above (the folder already there and enterable,
  the cd's word expanded as written, the cd not piped on, nothing after it changes folder, a `cwd=` given
  to a program included, not run in the background), a command that starts with `cd` into any other full
  folder has its relative file names read in that folder (`cd C:/repo && sed -i ... hooks/a.ts` is
  `C:/repo/hooks/a.ts`), so the review and the project's history name the real file. These are always
  reviewed, never left out as scratch. A name with a `.` or `..` step after a leading `./`, a drive
  (`D:a.ts`), a `~`, a `$`, or off Windows a `\` stays as written. In PowerShell, .NET calls
  (`[IO.File]::WriteAllText`) keep the process's own folder, and a name with a `\` is read only in
  quotes, which Set-Location does not move, so a
  command with one places nothing. A folder spelled as scratch that leads out of it (a link) places
  nothing either. A full path with `Local/Temp` in it is read as a command that sets `TEMP`, so it is not
  trusted as a start folder; by its variable (`$LOCALAPPDATA/Temp/...`) it is.
- **Scripts only run.** A script a command names only as what an interpreter runs (`python gen.py`,
  `node --test a.mjs` with exactly one file) and that is the same before and after the command is not
  reviewed. A command substitution (`$(...)` or backticks) runs in a subshell and does not stop this; a
  script also named inside one, a `cd` inside one, or one in a script's or folder's name still does. A
  relative name is placed only when the command starts with `cd <full folder>` (with no substitution in
  it) and nothing else moves the shell (another cd in any spelling, `"c"d` too, `source`, `.`, `eval`,
  `iex`, an alias). A command is read this way only where its words split as the shell splits them: no
  backslash outside quotes, no `\"` inside double quotes, no `$'...'`, no `#` comment, and in PowerShell no
  backtick and no `$(...)` (which runs in the same session there).
- **Python fed in by a here-document.** When that code can start no program, uses no `Path`, `PurePath`,
  `PosixPath`, `WindowsPath` or `pathlib`, uses `open` only as a call, and every `open(` takes a string,
  or a name set once to a string on a line of its own and used for nothing else, only the files those
  calls open count (read or written). Its other strings (a test case naming `app.py`) are text. This
  holds only when every file it opens is a code file, which is then reviewed with its text, and nothing
  else in the command can run anything: every other command is a read-only program named bare, with no
  variable set for it (`cd`, `cat`, `grep`, ...; not `rg --pre`), there is no other here-document, substitution, group, `exec`, background job or input redirect, and its
  own output goes to no file. So a script that edits files and then runs the tests in the same command is
  read as before, every name in it counting. So is a body that writes a Python file and imports anything
  (`python -` looks in the current folder first). The body must be quoted (`<<'PY'`) and not piped on. A
  string with an escape not read here (`\N{...}`) proves nothing. Such a script is then treated like an
  edit made with the Write tool: a later command that runs a file it wrote is judged on its own.
- **Relative paths.** A relative path is read against the session's folder only when that is surely its
  folder: not when the command changes folder (`cd sub && ...`, `git -C sub ...`, `env --chdir sub ...`),
  and never again for an agent that has run such a command (a shell may keep the folder), was started in
  a folder of its own, or was started or resumed by an agent on this list. The list is saved, so a reload
  keeps it (the last 500 agents). If the saved list was damaged or full, or before it is read back after
  a reload, no agent's relative path is read against the session's folder, and an agent that another
  agent starts before the read goes on the list. A path that is still relative never counts as a file
  under review, which can only mean more review.
- **Windows or not.** The hooks take the machine for Windows when `OS` is `Windows_NT`. Without it they
  go by `HOME`: one that starts with `/` means Linux or WSL (which may have `USERPROFILE` or `SystemRoot`
  passed in from Windows), unless it is Git Bash's spelling of a folder on the drive `USERPROFILE` or
  `SystemRoot` names (`/c/Users/pat`). Any other `HOME`, or none, means Windows when `USERPROFILE` or
  `SystemRoot` names a drive. The MCP server asks Node instead, which gives the same answer on a normal
  Windows, Linux or WSL setup. The home folder (for the config and status files) is `USERPROFILE` on
  Windows and `HOME` elsewhere; when that one is missing or blank, the other is used. On WSL with
  `USERPROFILE` passed in, `~/.claude/review-guard.json` is read from the Linux home, not the Windows one.

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

The review state is saved in the session, so a reload of the mod keeps it, in the middle of a review or
not. That includes the list of agents whose relative paths are not read against the session's folder
(see Paths). The counts of agent starts and the list of files left out are kept in memory only, and
start again after a reload. A session with
something to report also writes it to `~/.claude/review-guard/status/` for the `review_status` tool. Old
files there are not removed; the tool shows the last 24 hours.

## Files that keep coming back

Each project folder keeps a list of its recent reviews in `~/.claude/review-guard/history/`, one file per
folder, shared by every session there. A review is added only once its prompt has reached Claude: a
prompt that never arrived is not counted, and the review asked for again in its place is counted once.
Only reviews inside the window of the `churn` rule are kept (at most 200). A file is counted under one
spelling: slashes and the drive letter's case are evened out and a relative path is read against the
session's folder, but other case still counts, and a path with a `..` step is kept as it was written.
When a file under review has been in the rule's number of reviews within its hours, the review prompt gets
a paragraph: no new features in those files this turn, tests that pin them down, and a question for the
user about their design, with Claude's own recommendation: redesign yes, no or not yet, a short reason from
the bugs it has seen (the history keeps no findings), and the smallest redesign when yes. The user decides.
The check never holds a review back for long: if it fails, or takes over five seconds (two for recording a
review), the review goes on without it, and the log says why (a check over five seconds is logged every
time, since that review may go uncounted). A config file that can't be read skips the check, so a
`"churn": false` in it is never undone. Before a review is written in, a history file that is not valid
JSON is read once more after a quarter second, since another session may be part-way through writing it.
If it is still not valid, or of the wrong shape, it is logged (every time, as are dropped entries) and
started again. A history another version of the mod wrote is left alone, and that review is not recorded
(the log says so). Two sessions writing at the same moment may lose one entry, which only means a churning
file is noticed a review later.

## Checking shell writes against git (trial)

A shell command's writes are found by reading its text, which has to guess where each name lands. For a
command whose writes that guess can't be sure of, review-guard also asks git. That covers a command that
changes folder, runs a script, runs a writing tool (a formatter, `npm run`, `make`), commits, or in
PowerShell calls .NET. It takes `git status` just before the command runs and again after, in two
repositories: the session folder's, and the one a leading `cd` goes into.

**What counts as written:**
- a file that is newly changed or untracked;
- a file that was changed already and now looks different (its time, its size, or for a small file its
  text).

**What doesn't count:**
- staging alone (`git add`, `git reset`);
- a deleted file;
- a file changed before the command that a commit in it only took in.

**What isn't compared:**
- a repository where the command ran a git command other than ones that only commit, read, or talk to a
  remote (`add`, `commit`, `push`, `fetch`, `status`, `diff`, `log` and the like): a pull, a checkout,
  `stash pop`, `apply` or an alias may move `HEAD` or bring in other work; `gh pr checkout` too;
- a relative name the guess couldn't place (it is only counted);
- anything that isn't a code file (the same filter as the guess), and anything under `.claude/`.

Each compared command adds a line to `~/.claude/review-guard/shadow.jsonl`. The file keeps its last
megabyte, so it can always be read back. Each line has, per repository, up to 50 of the files only git
saw, of the files only the guess named, and of the guessed ones git ignores (git never lists those), each
with its count. It also says when other edits or commands were running at the same time, since their files
show as this command's.

Every line also has `steps`, with `before` and `after` lists that say where each look's time went. Each
step is one git run (`git status`, the filter check `git config` before a status or diff, `git rev-parse`,
`git diff`, `git check-ignore`) or one repository's whole look (`look`, its file reads included), with
when it started and how long it took. A look that ran out of time keeps its steps as they were at that
moment: one with no time was still running. Past 120 steps the rest are only counted (`stepsDropped`).

When a command touches two repositories, they are looked at side by side, not one after the other. On
Windows most of a look is starting git, so the wait is about that of the slower repository, not both.

**When a look fails:** each git run is limited to 1.5 seconds, the look before the command and the one
after it to 4 seconds each (one that is already writing its record gets up to 1 second more), and the
paths to 2,000. Small files are read for their text up to 4 MB per batch of files looked at. A look that
fails is recorded too, and each reason is logged once, also when only one repository fails. One
repository that fails doesn't lose the other's comparison. When something failed before a command and
nothing is looked at after it (it was refused, or may still be running), that failure is still recorded.
A folder git couldn't open is not tried again for 30 seconds; the record says the failure is cached.

Nothing here changes what is reviewed. Once the record shows git's list is right, it will replace the
guess inside repositories (`docs/shell-writes-redesign.md`). Plain commands, and ones run in the
background, are never looked at.
