## Lineup

| Step | Model | Job |
|---|---|---|
| 1. Build | Astra (`gpt-6-astra`, through Codex) | Coordinates one approved issue or scoped fix on a clean branch from `master`. Writes concise guidance, runs the checks below, and prepares the PR for review. |
| 2. Second build | Opus 5.5 (`claude-opus-5-5`, through the Claude Code CLI) | Works on Astra's change. Reads primary sources, corrects mistakes, fills gaps in the agreed scope, and removes unnecessary prose and code. |
| 3. Review | Sol 6.1 (`gpt-6.1-sol`, through Codex) | Independently reviews the commit from step 2 for correctness, regressions, missing controls, and practical developer guidance. |
| 3. Review | Daybreak Blue (`gpt-daybreak-blue-latest`, through the Codex CLI) | When account access permits, independently reviews the same commit for threat-model errors and control bypasses. Record the requested alias and resolved model when exposed; report this review as unavailable if the request fails. |
| 3. Review | Sonnet 5.5 (`claude-sonnet-5-5`, through the Claude Code CLI) | Independently reviews concision, duplication, placement, and plain US English. Proposes specific cuts while preserving necessary controls and caveats. |
| 4. Decide and ship | Astra (`gpt-6-astra`, through Codex) | Resolves every finding with evidence, checks the final commit, and gives the operator a concrete decision to make or does the merge if authorized to do so. |

Use the full lineup for substantial security-content changes; use focused review for small corrections.

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
