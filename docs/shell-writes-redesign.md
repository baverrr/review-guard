# Plan: find a shell command's writes by looking, not guessing

Status: approved. Step 3, the shadow release, is built (0.5.0); the switch (step 4) waits on its record.
What was built differs from the plan below in places, and `docs/review-cycle.md` ("Checking shell writes
against git") describes it as it is:
- It watches the session folder's repository and the one a leading `cd` goes into, but not repositories
  named by `git -C` or by full paths.
- It gives up past 2,000 changed paths, not 50,000.
- Nothing is cached per repository except the repository's root, so a status costs two runs of git
  (the filter check, then the status).
- It records every compared command, agreeing or not, in `~/.claude/review-guard/shadow.jsonl`, not
  only the ones that disagree, in the log.
- It also looks when a formatter, a task runner or a PowerShell .NET call runs.
- A git command that brings in other work without moving `HEAD` (`stash pop`, `apply`) skips the
  comparison too.
- A commit counts only the files the command itself changed.
- Small files already changed before the command are compared by their text as well.

## Why

Today `rememberShellWrites` reads the command's text (`shellWrites` in `hooks/scan.ts`) and guesses which
files it wrote, then `startDir` and `placeInStart` guess which folder those names are in. Every fix to that
guess has brought the next bug, in the same two files:

- names after a `cd` filed under the session's folder (fixed in 0.4.6);
- a `;` after a cd that can fail, a folder that can't be entered, a link out of scratch;
- PowerShell .NET calls that ignore Set-Location;
- `cwd=` and `{ cwd }` given to a program;
- still open: a full temp path not trusted, an unquoted `\` in PowerShell, `cwd:` in plain text, and
  the shell keeping a cd's folder for its next command.

The churn note flagged `register.ts`, `scan.ts` and the tests 8 times for this reason. These bugs come
from guessing where a name lands, not from one bad rule, so more rules won't end them.

## The idea

For the folders that are git repos, ask git what changed: once before the command runs and once after.
Git gives the real paths, whatever folder the command ran in or however it spelled them. Keep the text
guess for files outside any repo (mainly scratch), for background commands (there is no "after"), and
for plain commands, where it is cheap and right.

## How it works

1. **Before** (in the Bash/PowerShell `tool.call` hook, where `snapshotRunScripts` runs now):
   - Pick the repos to watch: the session folder's repo, plus the repos of any full folder the command
     names (a `cd` target, `git -C`, `Set-Location`, full paths in its write targets). Each is found once
     with `git rev-parse --show-toplevel` and kept per session.
   - For each repo, run `git status --porcelain=v2 --branch -z --untracked-files=all` (which gives
     `HEAD` too), using `git()` in `outgoing.ts` (filters off, `--no-optional-locks`, fsmonitor off).
   - For every path already dirty, stat it (mtime and size). Writing to an already-changed file doesn't
     change what git reports, so those stats are how a second edit is caught.
2. **After** `next(e)` returns:
   - Run the same status again.
   - **Written** means there's evidence in the work tree: a path that is newly dirty or untracked, or a
     dirty path whose mtime or size changed. A change in the status letters alone isn't a write:
     `git add` and `git reset` only move a file in or out of the index, and counting them would requeue
     the review's own fixes once they're staged. Deleted files are dropped, since there's nothing to
     review.
   - **`HEAD` moved:**
     - If the command committed (`sed -i … && git commit -am …` leaves the tree clean both times), add
       `git diff --name-only old new`.
     - If it moved `HEAD` some other way (`pull`, `checkout`, `rebase`, `reset`, `merge`), it brought
       other people's work, not a write. Use the text guess for that command instead.
   - **Code files only,** by the same `languageOf` filter the text guess uses (no logs, test output,
     `node_modules`, `.git`). Anything under `.claude/` is left out too. Without this filter, a review
     whose commands make files would never end.
   - Make each path absolute from its repo root.
3. **Combine:**
   - Inside a watched repo, the snapshot's list replaces the text guess, with one exception: a guessed
     name that `git check-ignore --stdin` says is gitignored is kept, since git never lists those. Other
     guessed names that git doesn't list were not written, and are dropped.
   - Outside every watched repo (scratch, a folder with no repo), the text guess stays as it is now,
     scratch rules included.
   - **During a review:** a file under review that only the snapshot found (the command's text never
     names it) goes in `othersChanged`, not counted as the review's fix. Then another writer's edit,
     made while a reviewer's command ran, is never dropped by `endReview('drop')`.
4. **When the snapshot can't run**, fall back to today's behaviour for that repo and log it once with
   `logLine`. That covers git missing, a folder that isn't a repo, the time limit being hit, and a repo
   with over 50,000 entries. A failed snapshot only means the guess is used. It never means fewer files
   reviewed.

## What it fixes and what it removes

- **Placement bugs:** all of those above, and the open "shell keeps the cd's folder" case, since git
  doesn't care where the shell was.
- **Writes no text guess can see:** a script or build tool that writes files, `npm run fix`,
  `python gen.py`, a formatter.
- **Code that goes:** `startDir`, `placeInStart` and the `Start` type are left with scratch work only.
  Their outside-scratch branches, the .NET exception and the `cwd=` placement rules go. `CHANGES_FOLDER`
  stays, both for `inOwnFolder` and to decide when to snapshot.

## Costs and risks

- **Time.** This is the big one. Measured on this PC from Git Bash on 2026-11-26:
  - one `git status` takes 210 to 1060 ms (230 to 1060 in this repo, 210 to 365 in a small one);
  - a bare `git --version` alone takes about 350 ms, so most of that is starting a process here;
  - `git()` also runs a `config` call first (`noFilters`).

  That's roughly 1 to 3 seconds added to every shell command. So the snapshot runs only on commands whose
  writes the guess can't be sure of:
  - a change of folder (`CHANGES_FOLDER`, a cd or Set-Location);
  - a script or tool that runs (what `snapshotRunScripts` already finds);
  - a `git commit`.

  Plain `ls`, `grep`, `cat` and a simple `sed -i file` keep the guess and cost nothing new. The
  `noFilters` answer is cached per repo, so it's two spawns per snapshot command.
- **Other writers:** some writes made during the command are counted as this command's work. They can
  come from parallel tool calls, other agents, another session, or the user's editor, and a permission
  prompt can keep the command open a long time. With the `othersChanged` rule above, that means more
  review, never less. The review prompt can say a file "changed while the command ran".
- **Slow or hung git** (a network drive, a locked index): covered by the time limit and the fallback.
  `--no-optional-locks` keeps status from taking the index lock, so it can't block the user's own git.
- **The guard's own git calls** (push checks) are unchanged. The snapshot only reads.

## Steps

1. **Measured already** (see Costs). Each git call is limited to 1.5 seconds.
2. **New module** `hooks/worktree.ts`, with `repoOf(host, folder)`, `snapshot(host, repo)` and
   `changedBetween(before, after)`. It's written against `Host` so the MCP side can reuse it, and goes
   into `scripts/build-mcp.mjs`.
3. **Shadow release (0.5.0):** wire it into the Bash/PowerShell hook, but keep using the guess. For a few
   days of normal work, log each command where the snapshot and the guess disagree to the review-guard
   log (which files, never their text).
4. **Switch (0.5.1):** once the log shows only the guess's known misses, combine as in "How it works"
   step 3.
5. **Tests,** with `process.run` mocked:
   - a cd into another repo;
   - a script that writes a file the text never names;
   - a second edit to an already-dirty file;
   - a gitignored file the guess found (kept);
   - git missing or too slow (fallback, logged once);
   - another writer during the command (kept in `othersChanged`);
   - a background command (guess only);
   - an edit and a commit in one command;
   - `git add` alone (not a write);
   - a `git pull` (guess only);
   - generated logs and `.claude/` files (not counted).

   Today's placement tests should pass unchanged, or be marked as no longer needed.
6. **Trim** the outside-scratch parts of `startDir` and `placeInStart`, once the tests cover what they
   did.
7. **Docs and release:** update `docs/review-cycle.md` and the README's "What it does" with each release.
   Then the usual review and push, and update the other installed copies.

## Choices for the user

1. **Inside a repo, replace the guess or add to it?** Recommended: replace it, once the shadow release
   shows the two agree. Adding to it keeps every wrong placement the guess makes. With the check-ignore
   rule, replacing loses nothing the guess found.
2. **Which repos to watch:** the session's repo plus those the command names (recommended), or the
   session's only. The second is simpler but misses `cd C:/other-repo && ...`.
3. **When to pay the time:** only on uncertain commands (recommended, about 1 to 3 s each), or on every
   shell command, which is safer but slows every `ls`.
