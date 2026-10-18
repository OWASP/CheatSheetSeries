## Lineup

| Step | Model | Job |
|---|---|---|
| 1. Build | Astra (`gpt-6-astra`, through Codex) | Coordinates one approved issue or scoped fix on a clean branch from `master`. Writes concise guidance, runs the checks below, and prepares the PR for review. |
| 2. Second build | Opus 5.5 (`claude-opus-5-5`, through the Claude Code CLI) | Works on Astra's change. Reads primary sources, corrects mistakes, fills gaps in the agreed scope, and removes unnecessary prose and code. |
| 3. Review | Sol 6.1 (`gpt-6.1-sol`, through Codex) | Independently reviews the commit from step 2 for correctness, regressions, missing controls, and practical developer guidance. |
| 3. Review | Daybreak Blue (Codex CLI access program; current model required) | When account access permits, independently reviews the same commit for threat-model errors and control bypasses. Record the selected model and access program; report this review as unavailable if no current model is eligible. |
| 3. Review | Mythos 5.1 (`claude-mythos-5-1`, through the Claude Code CLI) | Independently checks difficult security claims against primary sources and looks for unsafe examples or advice outside the threat model. |
| 3. Review | Sonnet 5.5 (`claude-sonnet-5-5`, through the Claude Code CLI) | Independently reviews concision, duplication, placement, and plain US English. Proposes specific cuts while preserving necessary controls and caveats. |
| 4. Decide and ship | Astra (`gpt-6-astra`, through Codex) | Resolves every finding with evidence, checks the final commit, and gives the operator a concrete decision to make or does the merge if authorized to do so. |

Standalone proposal for review workflow. Use the full lineup for substantial security-content changes; use focused review for small corrections.

Current model families checked on October 18, 2026 against the installed CLIs and official documentation: [Astra](https://developers.openai.com/api/docs/models/gpt-6-astra), [Sol](https://developers.openai.com/api/docs/models/gpt-6.1-sol), and [Claude model selection](https://platform.claude.com/docs/en/about-claude/models/choosing-a-model). Before starting, confirm the latest version of each selected family is available and record its exact model ID. Report unavailable reviewers explicitly.

[Daybreak Blue is an access program](https://developers.openai.com/api/docs/guides/daybreak), not a separate model. Select an eligible current model with `--model` and request `--cyber-access-program daybreak_blue`. Explicit Astra and Sol 6.1 requests require the documented organization and project access; model availability alone does not establish Daybreak eligibility.

During the October 18 reviews, Claude Code reported `claude-opus-5-5` and `claude-mythos-5-1`. Codex CLI accepted `gpt-daybreak-blue-latest`, but rejected Daybreak requests for both `gpt-6-astra` and `gpt-6.1-sol` on this account. Its output did not expose the alias's resolved model. The [Daybreak alias is deprecated](https://developers.openai.com/api/docs/models/gpt-daybreak-blue-latest), so those historical runs do not establish a current-model Daybreak review. Keep deprecated aliases out of this lineup; report the Daybreak slot unavailable until a current model succeeds. Sol and Sonnet remain proposed reviewers, not reviewers that ran on those PRs.

## Review contract

- Give every reviewer the same commit SHA, issue or PR intent, complete diff, full changed sheets, and relevant repository guidance. Keep their sessions independent until each returns its findings.
- Reviewers propose changes without editing the shared branch. Astra applies accepted fixes and sends affected changes back for review; earlier reviews do not cover later edits automatically.
- Require a **MERGE**, **REQUEST_CHANGES**, or **CLOSE** recommendation, with exact file locations, evidence, and concrete fixes. Separate new regressions from inherited problems.
- Fetch and read sources. A working URL proves availability; the reviewer must also confirm that the page supports the claim. Check internal links and anchors after moves or deletions.
- Cut introductions, repeated advice, obsolete material, and tutorial-sized examples. Link to existing cheat sheets and upstream implementation documentation. Preserve platform-specific security decisions and control limitations.
- Report the word count and code-block line count before and after substantial rewrites. Judge usefulness as well as size; keep every sentence that changes a developer's security decision.
- Resolve disagreements against evidence. Agreement between models is not proof of correctness.

Use the existing [cheat sheet review workflow](.claude/commands/review-cheatsheet-pr.md) for its five review dimensions and report format. Follow the [contribution process](CONTRIBUTING.md) and [writing guide](GUIDELINE.md).

## Local checks

Run these after the last content change:

```bash
npm run lint-markdown
npm run lint-terminology
npm run link-check -- --base origin/master
```

For checker or workflow changes, also run the relevant tests from [package.json](package.json). Inspect final-commit CI, including scope, citations, index consistency, and the website build. Passing checks does not establish security correctness or source support.

## Decide and ship

- Keep one topic per branch and PR. New or substantial cheat sheet changes need an approved issue. Prefer a short conceptual revision to a growing implementation tutorial.
- Record each reviewer's actual model, reviewed SHA, findings, and their resolution. Disclose every tool that materially assisted the PR, its version when known, and the prompts used in the PR template's AI Tool Usage section.
- Before an authorized merge or close, run the workflow-approval audit after the last push or PR description edit:

```bash
npm run check-pr-approvals -- <PR> --repo OWASP/CheatSheetSeries --head <SHA>
```

- Resolve approval holds across the PR's history using the [maintainer procedure](CONTRIBUTING.md#before-merging-or-closing-a-pull-request). Review held code before approval, verify terminal run status, and check required reviews and final-commit CI separately.
- Give the operator the verdict, remaining blockers, proposed cuts, and validation results. Post reviews, merge, or close only within his authorization.

<!-- markdownlint-disable-file MD041 -->
