# review-guard

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A mod for Claude Code. After Claude changes code it sends Claude back to review the change, and before any
commit or push to GitHub it checks what would go out for keys, IP and MAC addresses and your personal details.

> [!TIP]
> It needs no setup to start: install it and the reviews and the GitHub check begin in your next session.
> Add your own name and email to a small config file (see [How to use it](#how-to-use-it)) so it can watch for those too.

> [!IMPORTANT]
> It catches common mistakes, not every leak. It knows the usual key and token formats, not every secret
> anyone could write, and a git command sent over SSH to another machine is not checked.

**[What it does](#what-it-does)** · **[What you need](#what-you-need)** · **[Install](#install)** · **[How to use it](#how-to-use-it)** · **[Help](#help)**

## What it does

- **Reviews every code change.** When a turn ends with code changed, Claude is sent back once to run review
  agents on it (code review, hidden errors, test gaps) and to fix what they confirm.
- **Adds a security check per language.** Python, TypeScript, Docker, shell, C# and others each get their own
  short list of things to look for.
- **Brings its own reviewers.** It ships five review agents, so the review works even where the
  pr-review-toolkit plugin is not installed.
- **Stops leaks to GitHub.** A `git commit`, `git push`, `gh pr create` or GitHub tool call that would send a
  key, a token, a private key, an IP or MAC address, or one of your personal terms is stopped, and Claude is
  told what and where, never the value itself.
- **Knows when to wait.** If you stop Claude part way, it waits until work picks up again before asking for
  a review.

## What you need

- [Claude Code](https://claude.com/claude-code) on Windows, macOS or Linux
- `git` (and `gh` if you use it)
- For a private copy of this repository: access to it on GitHub, and git signed in to GitHub on your computer

## Install

1. In a terminal Claude Code session, type:

   ```
   /plugin install review-guard --marketplace baverrr/review-guard
   ```

2. Answer `y` to add the marketplace, then press Enter to install it for your user.

3. Start a new session. The mod is active from then on.

<details>
<summary><b>From a shell, or in the desktop app</b></summary>

- Shell: `claude plugin install review-guard --marketplace baverrr/review-guard`
- Desktop app: click **+** next to the prompt box, then **Plugins**, **Add marketplace** with
  `baverrr/review-guard`, then **Add plugin**.
</details>

## How to use it

1. **Work as usual.** When Claude changes code, the review starts by itself at the end of the turn.
2. **Commit and push as usual.** If something should not go to GitHub, the command is stopped and Claude says
   what it found and where.
3. **Add your own terms.** Create `~/.claude/review-guard.json` with your name, email and usernames:

   ```json
   {
     "personal": ["Your Name", "you@example.com", "yourusername"],
     "allowNetworkInfo": ["owner/notes-repo"],
     "allowValues": []
   }
   ```

<details>
<summary><b>The config file</b></summary>

| Key | What it does |
|---|---|
| `personal` | Text that must never reach GitHub (matched without regard to case) |
| `allowNetworkInfo` | Repositories, as `owner/repo`, where IP and MAC addresses are fine |
| `allowValues` | Exact values that are false alarms |

Claude cannot edit this file; the mod stops it from trying. A typo in it stops commits until it is fixed.
</details>

## Help

**"review-guard could not check this command."** Git could not open the folder the command names, or the
config file has a mistake. The message gives the reason. Run git with `git -C <full path>` or fix the file.

**"It asks for a review I don't need."** Changes to notes and other non-code files are never reviewed. To turn
the mod off for a while, set `"review-guard@review-guard": false` under `enabledPlugins` in your settings.

**"A real address was stopped in my home-lab notes repo."** Add that repository to `allowNetworkInfo`.

<details>
<summary><b>For developers</b></summary>

- The hooks are in `hooks/register.ts`; the scanning and command reading are pure functions in `hooks/scan.ts`.
- The review agents are in `agents/`, with the same prompts in `hooks/agents.ts` for sessions that were
  already open when the mod loaded. Refresh both together (see `licenses/NOTICE.md`).
- Run the tests: `claude plugin test .`
- Check the plugin: `claude plugin validate .`
</details>

## License

MIT. See [LICENSE](LICENSE).

The five agents in `agents/` are copies of the pr-review-toolkit plugin's agents by Anthropic, under the
Apache License 2.0 (`licenses/`). Not affiliated with Anthropic.
