# Where these agents come from

The agent prompts in the `agents` folder are copies from the pr-review-toolkit plugin by Anthropic
(claude-plugins-official), under the Apache License 2.0 in `LICENSE-pr-review-toolkit`.
Changed here: only the `description` line of each file, shortened.

They are copies, so they do not update with the plugin. To refresh them, copy the plugin
agent files again, shorten the descriptions, and regenerate `hooks/agents.ts` from them.
