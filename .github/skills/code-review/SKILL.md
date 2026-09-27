---
name: code-review
description: Rigorous review of OWASP Cheat Sheet Series pull requests across security correctness, practicality, link and source verification, duplication, and language. Use for any pull request that touches cheatsheets/ or cheatsheets_draft/, or that adds or changes external links or citations.
---

# Reviewing an OWASP Cheat Sheet Series pull request

You are reviewing a contribution to the OWASP Cheat Sheet Series. The project
carries a large backlog of low-quality submissions, including AI-generated
content that cites pages which do not exist or do not support the claim being
made. Reviews must be rigorous, but every finding must rest on evidence you
actually gathered, never on a guess. A wrong "looks fine" is worse than a false
alarm.

Apply the rules in `AGENTS.md`, `CONTRIBUTING.md` and `GUIDELINE.md`. Where this
skill and those files disagree, those files win.

## Triage first

Not every contribution earns a full review, and spending one where it is not
needed is how a backlog stays a backlog.

**Link spam closes without a review.** When the substance of a change is added
links aimed at pages unrelated to application security, close it as spam and
stop. Nothing catches this for you: `pr-scope-check` counts only cheat sheet
files and the link checker never opens `README.md`, so a large block of live but
irrelevant links into a non-content file passes every gate green.

**Process gaps are answered with the process.** A new cheat sheet, a substantial
rewrite, or a newly added tool or resource link needs an approved tracking issue
before the pull request, and where that is missing the answer is to point at the
requirement rather than to review the content in depth. Check the issue's state,
not just that a number was quoted; the next section says how. A typo or dead
link fix needs no issue, so never raise this against one.

**Match the depth to the change.** A single dead-link swap or a typo fix does
not need five dimensions and a full-file read. There the questions that matter
live in dimensions 3 and 5: is the replacement canonical, does it support the
sentence it sits in, and does the surrounding prose still read correctly after
the swap. Reserve the full pass for new sections, reworks, and any change to
what a control does or when it applies.

## Before reviewing

Once a change has earned a full review, read the **full current content** of
every changed file under `cheatsheets/` or `cheatsheets_draft/`, not only the
diff hunk. A reviewer needs the whole section a change lands in to judge whether
the change is correct, redundant, or contradicts a neighboring paragraph. For
new files, read the whole file.

## What CI already checks, and where it is blind

Read the check results first and build on them. Do not re-derive a result a
check has already produced, and do not report a finding a green check has
already settled.

| Check | Covers | Blind to |
|---|---|---|
| `markdownlint` | the whole repository except `node_modules`, `cheatsheets_excluded` and `.claude/` | `MD013`, `MD040`, `MD059` and `MD060` are disabled, so long lines and untagged code fences are not defects here |
| `textlint` (`lint-terminology`) | `cheatsheets/` only | `cheatsheets_draft/` gets no terminology or US English check at all |
| `markdown-link-check` | `cheatsheets/` only, and the whole directory rather than the diff | every other path, including `cheatsheets_draft/` and `README.md`; plus ignored domains, among them `csrc.nist.gov`, `developer.android.com`, `vincent.bernat.im` and `www.exploit-db.com` |
| `pr-scope-check` | 3 changed cheat sheet files, and 1500 net added lines counted across the **entire** diff | whether a wide diff is one coherent change |
| `citation-check` | a newly added `## H2` in `cheatsheets/` contains an inline `[text](https://...)` link | whether that link resolves, and whether it supports the claim |
| `index-drift-check` | `Index.md` matches the output of `scripts/Update_CheatSheets_Index.py` | nothing that matters here |

Three consequences, each of which has produced a wrong review in this
repository:

- **A check that did not run settles nothing.** A merge conflict blocks every
  check on a pull request. When results are missing, say so and fall back to
  judgment rather than reading absence as cleanliness.
- **Green is not correct.** `citation-check` says an H2 contains a link, not
  that the link supports the sentence beside it. The link check says a URL
  answered, not that the page is the right one.
- **The link check is repo-wide and partial.** Red does not mean this pull
  request broke anything, and green does not mean its links were checked. A link
  in `cheatsheets_draft/`, in `README.md`, or to an ignored domain such as
  `csrc.nist.gov` has been verified by nobody until you verify it.

Spend the review on the judgment no check can make: whether a source supports
its claim, whether the advice is correct, whether an example would actually run,
and whether the content belongs in this sheet at this length.

## Pre-checks CI does not perform

Skip scope arithmetic. `pr-scope-check` reports it; read its result, and when it
is red decide whether the breadth is a coordinated change or an unfocused one.
If you advise an author on a scope failure, note that linking a tracking issue
waives only the 1500-line limit. The 3-file limit has no exemption.

These are checked by nothing and are yours:

**AI Tool Usage disclosure.** Three separate requirements, all of them enforced:

1. The pull request template has to be used at all. `CONTRIBUTING.md` treats a
   pull request that ignores it as a signal in itself that the contribution was
   produced without reading the contributing guidance.
2. Exactly one disclosure box has to be ticked.
3. Where "I have used AI tools" is ticked, `AGENTS.md` rule 7 requires the tool
   name, the version if known, and the prompt. A ticked box carrying none of
   these is not a disclosure.

Failing any of the three is a **must-fix, and at least REQUEST_CHANGES**,
including on a one-line typo fix. Because it is a one-line edit to the pull
request body, ask for it rather than closing. Reserve **CLOSE** for a missing
disclosure combined with content that shows signs of unverified generation,
such as a citation to a page that does not exist, or a source that does not
support the sentence it is attached to.

**Contribution path and issue state.** Classify the change first, because the
issue requirement depends on which path `CONTRIBUTING.md` puts it on:

- *Minor fix*, meaning a typo, a dead link or a small correction: **no issue is
  required**. Do not ask for one. This is the project's largest and healthiest
  stream of contributions and the carve-out exists to keep it cheap.
- *Update to an existing sheet*, or a *new cheat sheet*: an issue is required,
  and it has to have been **approved**, not merely opened.

Where an issue is required, or where the author references one, a number in the
body is not compliance. Read the issue: it should carry `ACK_OBTAINED` rather
than `ACK_WAITING`, and the author should be among its assignees. A pull request
opened against an `ACK_WAITING` issue, or against one assigned to someone else,
is answered by pointing at the process rather than by a content review.

Report rather than resolve two states: an issue with `ACK_OBTAINED` and
`HELP_WANTED` but no assignees, since `CONTRIBUTING.md` strips assignees after a
month of inactivity and the work may be genuinely unclaimed; and an issue
carrying no labels at all. Say what you found and leave the call to the
maintainer. If you cannot read the issue, say that too, and do not record an
unread issue as compliant.

**Single-topic focus.** Is this one coherent change, or unrelated edits bundled
together? A stray `Index.md` hunk is the common case: that file is generated by
`scripts/Update_CheatSheets_Index.py`, so the fix is always to drop the hunk and
rebase, never to hand-correct it. An `Index.md` change that the generator
produces, such as the entry for a genuinely new sheet, is required rather than
stray, and `index-drift-check` tells you which one you are looking at.

## The five review dimensions

For any substantive change, work through all five explicitly and separately,
then consolidate. Do not skip a dimension because another one already produced
a blocker.

### 1. Security correctness

Is the advice correct, current, and inside the threat model of the cheat sheet
it lands in? Flag guidance that is deprecated, that solves a different problem
than the one stated, that is safe only under unstated assumptions, or that would
degrade security if followed literally. Note where a control is described
without its necessary preconditions.

### 2. Practicality

Can a working developer act on this? Flag advice that is abstract to the point
of being unusable, that requires infrastructure most readers will not have, or
that gives no way to verify the control is in place. This dimension may be N/A
for small corrections.

**An example presented as runnable must actually run.** Illustrative snippets
are allowed to be short and incomplete. But the moment a contribution shows a
pipeline, a workflow or a command sequence as something a reader can adopt,
trace it end to end before accepting it:

- Every tool it invokes is installed, or is present on the runner it names.
- Every step's inputs exist, including outputs that earlier steps were supposed
  to produce.
- Identity strings, flags and paths are the real ones rather than the plausible
  ones. A verification command given the wrong value verifies nothing, and does
  so silently.

"Checked against the documentation" is not the same as "run". For supply chain,
signing and attestation examples that difference is the whole contribution, and
a headline example that cannot execute is grounds to close rather than a draft
to iterate on.

### 3. Links and sources

The link check has already reported whether URLs under `cheatsheets/` answered.
Do not re-fetch a link to establish that it resolves. Judge what the checker
cannot:

- **Does the page support the specific claim it is attached to?** This is the
  main question, and the one most often answered wrongly.
- **Is the source canonical and authoritative for this topic?** A live link is
  not automatically the right link. Where a dead reference is being replaced,
  the replacement should be the canonical home of the material, not merely
  something reachable that mentions it. Vendor marketing pages, SEO content
  farms and blog posts restating a standard are weak where a primary source
  exists.
- **Would deleting beat repointing?** When the underlying thing is itself dead
  or withdrawn, removing the advice is better than re-aiming its citation at a
  page that merely documents what it used to be.
- **Does the surrounding prose still hold?** A swapped link often strands a
  sentence that no longer introduces what comes after it.
- **Is a named tool common and popular open source?** The series links tools
  sparingly. A project that is young or little known does not belong in a cheat
  sheet yet, however permissive its licence and however strong its feature
  list. Adoption and track record are the test, and a contributor proposing
  their own project is the usual way this arrives.

Fetch links yourself only where CI did not: anything under `cheatsheets_draft/`
or outside `cheatsheets/`, and any ignored domain, `csrc.nist.gov` above all,
since NIST is among the sources `AGENTS.md` most recommends.

**Only claim to have checked a link you actually fetched.** If you cannot
retrieve a page, say so and mark the citation as needing maintainer
verification. Do not infer from the URL that a page exists or that it contains
the claimed content, that inference is the exact failure mode this review
exists to catch. Fabricated or mis-attributed citations are a blocker.

Internal cross-links to other cheat sheets do not count toward `citation-check`.
A failing `citation-check` is **not** by itself a blocker: it is a floor that
maintainers can override for otherwise-sound content. Conversely, do not pass
well-cited content that is wrong.

### 4. Duplication and placement

Does this repeat content that already exists in this sheet or another one?
Search the repository before concluding it is new. If the material is sound but
belongs in a different cheat sheet, say which one.

Coordinated cross-linking between related sheets (the XSS, injection and
authorization families) is intentional and is not duplication. What is
prohibited is reproducing another sheet's guidance instead of linking to it.

### 5. Language and structure

US English, grammar, clarity. Headings, code fences, and list conventions
consistent with the rest of the series. Prefer concrete imperative guidance over
hedged prose. Keep this dimension proportionate: language issues are rarely
blockers on their own.

A cheat sheet is a cheat sheet, not a guide. When a rewrite leaves a section
substantially longer than it found it, ask what the added length buys.
Accumulation while every individual sentence stays defensible is the usual way
these sheets degrade, and a net reduction that keeps the advice intact is a good
outcome rather than a loss.

## Consolidating

Deduplicate before reporting. If two dimensions flag the same sentence, report
it once with both angles. Rank by severity.

Keep the output small enough to be read and acted on. A review returning thirty
findings gets skimmed, and its real blockers are lost among its nits.

- **Must-fix is uncapped.** If a contribution carries eight genuine blockers,
  report eight. Never drop a blocker to hit a number.
- **Should-fix is capped at five, nits at three, one finding per bullet.** Past
  the cap, keep the ones that most improve the contribution and drop the rest.
  Packing several defects into a single bullet to stay under the cap defeats it.
- **On a CLOSE verdict, lead with the reasons for closing** and keep them apart
  from everything else. Do not simply discard the content findings: where the
  same material lives on elsewhere, most often in the pull request this one
  duplicates, they are still worth having. Put them under a heading that names
  where they belong, so the reason for closing is not buried under defects in
  text that is merging by another route. Nits go.
- Stay inside the change. Do not raise findings against content the pull request
  did not touch, and do not re-raise one the author has already answered with
  reasoning. There is one exception, and the pull request template writes it
  down: a grammar or typo contribution is asked to "double-check the file for
  other mistakes in order to fix all the issues in the current cheat sheet", so
  remaining errors elsewhere in that same file are in scope on those pull
  requests and nowhere else.
- Say nothing about the pull request's own statistics. Line counts, diff sizes
  and stale figures in the description are not review findings.
- This review is one input, not a gate. An author rejecting a finding with an
  explanation is a normal outcome, not an unresolved issue.

Treat as **not mergeable**: any security blocker, any claim that is wrong or
outside the sheet's threat model even when cited, any broken, unsupported or
fabricated link, substantial duplication, a missing AI disclosure, or a scope
violation.

## Output

Lead with a single verdict and a two to four sentence rationale:

- **MERGE** — sound, sourced, in scope, useful; at most trivial nits.
- **REQUEST_CHANGES** — fixable issues; list exactly what the author must change.
- **CLOSE** — fundamentally unsound, out of scope or process, AI slop, or
  duplicative beyond easy repair. Explain why, and be respectful.

Then group findings as **Must-fix**, **Should-fix**, and **Nits**, each with
`file:line` and a concrete fix rather than a restatement of the problem. Inline
comments should carry the specific fix; the summary comment carries the verdict
and the reasoning.

On a **CLOSE**, use **Reasons for closing** in place of Must-fix, and add
**Carry over to `<where>`** for findings about content that continues its life
in another pull request. Leave Should-fix and Nits out.

## Tone

Contributors are volunteers. Be direct about defects and generous about intent.
Never imply a contribution is AI-generated unless the evidence is concrete
(for example a citation to a page that does not exist); say what is wrong with
the content instead.
