# Model workflow

This file is an execution contract, not an automated runner. Reading it does not launch models or enforce stage order. The coordinating agent must invoke the selected models, preserve their results, and report which stages actually ran. Do not claim a stage ran because its model was named in a prompt or because the coordinator performed similar work.

## Choose the run mode

State the mode and intended stages before starting:

- **Full:** Use for new or substantial security-content changes, or whenever the operator requests the full lineup. Run build, second build, all three independent reviews, and the final decision in order. Only the three reviews may run in parallel.
- **Review-only:** For an existing PR when no authoring is requested, skip both build stages and review its current commit with all three reviewers, followed by Astra's decision. Record the build stages as skipped; this is not a full run.
- **Focused:** For a small, bounded correction or tooling-documentation change, select reviewers for the affected dimensions and name every omitted stage with a reason. Do not use the size of a diff alone to justify skipping threat-model review. Attempt Daybreak Blue when the change affects a security recommendation, control guarantee, or bypass.

An explicitly requested full run overrides the focused exception. A failed invocation is **unavailable**, not skipped or passed. Continue useful work when a model is unavailable, but report the missing stage and do not call the lineup complete. Never silently substitute another model or a standard-access review for Daybreak.

## Lineup

| Step | Model | Job |
|---|---|---|
| 1. Build | Astra (`gpt-6-astra`, through Codex) | Coordinates one approved issue or scoped fix on a clean branch from `master`. Writes concise guidance and commits the candidate for the second build. |
| 2. Second build | Opus 5.5 (`claude-opus-5-5`, through the Claude Code CLI) | Reads Astra's actual change and primary sources. Corrects mistakes, fills gaps in scope, and cuts unnecessary prose and code. Commit any edits before review; a documented no-change result is valid. |
| 3. Review | Sol 6.1 (`gpt-6.1-sol`, through Codex) | Independently reviews the commit from step 2 for correctness, regressions, missing controls, and practical developer guidance. |
| 3. Review | Daybreak Blue (`gpt-daybreak-blue-latest`, through the Codex CLI) | Independently reviews the same commit for threat-model errors and control bypasses when account access permits. Record failures as unavailable. |
| 3. Review | Opus 5.5 (`claude-opus-5-5`, through the Claude Code CLI) | Independently reviews the same commit for concision, duplication, placement, and plain US English. Proposes specific cuts while preserving controls and caveats. |
| 4. Decide and ship | Astra (`gpt-6-astra`, through Codex) | Reads all reviewer results, resolves findings against evidence, obtains re-review for fixes, and checks the final commit. Gives the operator a decision or merges only when authorized. |

## Invoke models explicitly

The model and cybersecurity access program are separate selections. Use `standard` for Astra and Sol, and `daybreak_blue` for the Daybreak reviewer. Do not rely on inherited defaults: during testing, an ordinary Sol invocation failed because Daybreak was selected for a model without that access. See the [OpenAI Daybreak access-program documentation](https://developers.openai.com/api/docs/guides/daybreak).

Check the installed interfaces with `codex exec --help`, `claude --help`, and `codex debug models`. The catalog reports supported access programs; a catalog entry alone does not prove that a request completed. Record CLI versions with `codex --version` and `claude --version`.

The following command templates select each model and capture results. Run them from the task's isolated checkout. Create a private evidence directory with `run_dir=$(mktemp -d)` and prepare the named prompt files there. Each prompt must include the task and permitted actions, prohibit posting or merging without authorization, and prohibit unrequested delegation or model substitution. Prepare each next-stage prompt only after the preceding stage's result and commit are available.

Build and second build:

```bash
codex exec --model gpt-6-astra --cyber-access-program standard \
  --sandbox workspace-write --json - < "$run_dir/build.prompt.txt" \
  > "$run_dir/astra-build.jsonl" 2> "$run_dir/astra-build.stderr"

claude -p --model claude-opus-5-5 --permission-mode acceptEdits \
  --allowedTools 'Read,Edit,Write,Glob,Grep,WebFetch,WebSearch' \
  --output-format json < "$run_dir/second-build.prompt.txt" \
  > "$run_dir/opus-build.json" 2> "$run_dir/opus-build.stderr"
```

Freeze and record the reviewed commit. Give each independent session the same SHA, intent, complete diff, full changed sheets, and repository guidance. Role-specific instructions may differ; the content snapshot must not. Reviewers must not see one another's findings before returning their own results.

```bash
codex exec --model gpt-6.1-sol --cyber-access-program standard \
  --sandbox read-only --json - < "$run_dir/sol.prompt.txt" \
  > "$run_dir/sol.jsonl" 2> "$run_dir/sol.stderr"

codex exec --model gpt-daybreak-blue-latest --cyber-access-program daybreak_blue \
  --sandbox read-only --json - < "$run_dir/daybreak.prompt.txt" \
  > "$run_dir/daybreak.jsonl" 2> "$run_dir/daybreak.stderr"

claude -p --model claude-opus-5-5 --permission-mode dontAsk \
  --tools 'Read,Grep,Glob,WebFetch,WebSearch' --strict-mcp-config \
  --allowedTools 'Read,Grep,Glob,WebFetch,WebSearch' \
  --output-format json < "$run_dir/opus.prompt.txt" \
  > "$run_dir/opus.json" 2> "$run_dir/opus.stderr"
```

Astra's decision prompt must contain all reviewer results and the commit they cover. A decision-only turn can remain read-only; any subsequent edits require a new commit and re-review.

```bash
codex exec --model gpt-6-astra --cyber-access-program standard \
  --sandbox read-only --json - < "$run_dir/decision.prompt.txt" \
  > "$run_dir/astra-decision.jsonl" 2> "$run_dir/astra-decision.stderr"
```

Record each command's exit status immediately. Exit zero alone is insufficient: confirm that a usable response completed, the requested review was performed, and no tool denial or error prevented required source checks. Do not automatically retry with a different model or access program. Native Codex delegation is also acceptable for the Codex stages other than Daybreak when it exposes the requested model and equivalent execution evidence. A coordinator whose actual model is unknown cannot count itself as an Astra stage.

### Verify Daybreak, not a model's self-description

For every Daybreak attempt, retain the requested alias, explicit access program, exit status, completion or error event, and session identifier. Codex's saved `turn_context` records the selected `model` and `cyber_access_program`; use runtime evidence rather than asking the model what it is. Claude's JSON `modelUsage` provides corresponding model-usage evidence for Claude stages.

As of October 25, 2026, the [official Daybreak Blue model page](https://developers.openai.com/api/docs/models/gpt-daybreak-blue-latest) marks this alias deprecated and maps it to `gpt-5.6-sol`. Keep the configured alias until the lineup is deliberately updated. Record the resolved backend model only when the response or runtime exposes it; otherwise write **not exposed**. Documentation describing an alias mapping is not proof of the backend serving an individual request.

When testing routing, use a harmless prompt with the exact model and program above. A positive completion verifies that route. As a negative control, the same alias with `--cyber-access-program standard` should be rejected; in the October 25 test it returned HTTP 400 requiring `daybreak_blue`. Do not weaken safeguards or change account permissions to make a test pass.

## Execution record and review contract

Keep one record per run, with a row for every lineup stage, including skipped and unavailable stages:

| Stage | Status | Requested model/program | Runtime evidence | Input/output SHA | Findings and resolution |
|---|---|---|---|---|---|
| Each stage | completed / skipped / unavailable | Exact model and program, if applicable | CLI version, session ID, exit status, result/log location; resolved model or not exposed | Exact commit(s), or not run | Verdict, fixes, re-review coverage, or reason not run |

Retain exact prompts and outputs outside tracked content. Share only evidence needed for review; do not publish credentials or unrelated session data. A full run is complete only when every required stage has a usable result and every fix has review coverage. Daybreak unavailability is permitted when access is unavailable, but must remain visible in the result. A `MERGE` recommendation does not itself authorize merging or replace required GitHub reviews.

- Reviewers propose changes without editing the shared branch. Require a **MERGE**, **REQUEST_CHANGES**, or **CLOSE** recommendation with exact file locations, evidence, and concrete fixes. Separate new regressions from inherited problems.
- After edits, record the new SHA and send the affected diff and current full content back for review. A focused delta review may extend earlier coverage when the remaining content is unchanged. Identify both SHAs and the delta explicitly; do not say every model reviewed the final commit if it did not. Broader changes require a fresh independent review round.
- Fetch and read sources. A working URL proves availability, not support for the claim. Check internal links and anchors after moves or deletions.
- Cut introductions, repeated advice, obsolete material, and tutorial-sized examples. Link to existing sheets and upstream implementation documentation. Preserve platform-specific security decisions and control limitations.
- Report word counts and code-block line counts before and after substantial rewrites. Keep every sentence that changes a developer's security decision.
- Resolve disagreements against evidence. Agreement between models is not proof of correctness.

Use the [cheat sheet review workflow](.claude/commands/review-cheatsheet-pr.md) for its five dimensions and report format. Follow [CONTRIBUTING.md](CONTRIBUTING.md) and [GUIDELINE.md](GUIDELINE.md).

## Validate the workflow and the change

A workflow smoke test must exercise all six invocations in an isolated fixture: Astra builds, Opus inspects that output, three independent reviewers receive the same resulting commit, and Astra reads their results. Verify the commits and handoffs rather than accepting stage names in generated text. A no-tools fixture test with supplied sources validates invocation and handoff mechanics; it does not prove independent source retrieval, real-file editing, repository CI, approval handling, or merge behavior. State what was and was not exercised.

Run these after the last content change:

```bash
npm run lint-markdown
npm run lint-terminology
npm run link-check -- --base origin/master
```

For checker or workflow code changes, also run the relevant tests from [package.json](package.json). Inspect final-commit CI, including scope, citations, index consistency, and the website build when applicable. Local checks passing does not mean remote CI passed. Report queued runs, approval holds, unavailable checks, and failures accurately. Passing checks does not establish security correctness or source support.

## Decide and ship

- Keep one topic per branch and PR. New or substantial cheat sheet changes need an approved issue. Prefer a short conceptual revision to a growing implementation tutorial.
- Include the run mode, execution record, remaining blockers, proposed cuts, and validation results in the review report. Disclose all materially assisting AI tools, versions when known, and prompts in the PR template's AI Tool Usage section. Distinguish maintainer AI-assisted follow-ups from the original author's declaration.
- Before an authorized merge or close, run the workflow-approval audit after the last push or PR description edit:

```bash
npm run check-pr-approvals -- <PR> --repo OWASP/CheatSheetSeries --head <SHA>
```

- Resolve approval holds across the PR's history using the [maintainer procedure](CONTRIBUTING.md#before-merging-or-closing-a-pull-request). Review held code before approval, verify terminal run status, and check required reviews and final-commit CI separately.
- Post reviews, merge, or close only within the operator's current authorization. If the operator changes the request to editing and asking the author to review, leave the PR open.
