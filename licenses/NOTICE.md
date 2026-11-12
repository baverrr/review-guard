# Where these agents come from

The agent prompts in the `agents` folder are copies from the pr-review-toolkit plugin by Anthropic
(claude-plugins-official), under the Apache License 2.0 in `LICENSE-pr-review-toolkit`.
Changed here:

- the `description` line of each file, shortened;
- `code-reviewer.md` and `pr-test-analyzer.md` (2026-11-12): they report every issue and gap they find,
  low-confidence and minor ones included, instead of filtering to the top ones (the confidence-80 cutoff
  and the "not pedantic" line are replaced, and the outputs gain a place for lower findings).

They are copies, so they do not update with the plugin. To refresh them, copy the plugin
agent files again, shorten the descriptions, make the two changes above again, and regenerate
`hooks/agents.ts` from them.
