# AGENTS.md — Rules for AI Tools in the OWASP Cheat Sheet Series

This file governs **every AI tool** used in this repository — Claude Code, Codex, Cursor, Copilot, and anything else. If you are an AI assistant generating issues, pull requests, comments, or content, these rules are mandatory. `CLAUDE.md` imports this file; treat it as the single source of truth.

The full human documentation lives in [CONTRIBUTING.md](CONTRIBUTING.md) (process + policy) and [GUIDELINE.md](GUIDELINE.md) (how to write good content). Read them. This file distills the rules that matter most and that AI tools most often break.

> The audience for every cheat sheet is **developers, not security experts**. Content must be accurate, practical, concise, and opinionated. We would rather have _good_ advice a developer can follow than _best_ advice they cannot.

---

## Non-negotiable rules

These are the rules whose violation gets a contribution closed. Most rejected contributions break one of these.

### 1. Sources must be real, read, and supportive

Anti-fabrication (always):

- You must have **actually fetched and read** each source and confirmed it supports the specific claim. Do **not** rely on training-data memory or summaries.
- **Never invent or guess a URL.** Fabricated citations, links that 404 or redirect to a homepage, and links to a page that does not actually support the claim are the single most common reason PRs are reverted. If you cannot find a real supporting source, do not make the claim.
- Link the **specific page or section** that supports the claim, not an index or landing page.
- Do not link to cheat sheet pages or anchors that do not exist — verify the target is present in the repo first.

How much to cite (calibrated to what actually gets merged):

- **Every new `## H2` section must contain at least one inline citation** `[text](https://...)` — this is the CI floor (`citation-check`). Beyond that, any **novel, surprising, parameter-specific, or contestable** claim needs its own source. Well-established common practice does not need a citation on every sentence.
- Sources may be **inline** _or_ collected in a `## References` section — both are accepted (about half the series has no References section).
- Internal cross-links to other cheat sheets are encouraged (see rule 4) but do **not** satisfy the CI citation gate, which only counts `https://` links.
- Cite **authoritative** sources: RFCs, NIST, OWASP, official vendor/project documentation, MDN, reputable tool docs and canonical source repositories (e.g. GitHub), or peer-reviewed research. Prefer the most authoritative source available and avoid SEO/marketing content farms — but a solid project doc, MDN page, or canonical repo is a valid citation (these are in fact the most-cited sources across the series).
- The citation gate is a **floor, not a ceiling**: maintainers merge on overall soundness and may accept content that trips the gate, or reject well-cited content that is wrong.

### 2. Claims must be correct and within the security threat model

Citations are necessary, not sufficient — the most detailed rejections in this project are fully-cited content that was simply wrong or off-topic.

- Pair every threat with a concrete countermeasure, and state explicitly what a control **does and does not** protect against.
- Do not drag in attacks outside the topic's threat model (e.g. endpoint compromise under MFA) without a caveat.
- Add only guidance that is genuinely a **security** control or risk. General code-quality, performance, or architecture advice belongs elsewhere.

### 3. Stay in scope — one topic, one PR, one branch

- A PR modifies a **single cheat sheet** (or a small, clearly-coordinated set). CI enforces a hard limit of **3 cheat sheets** and **1500 net added lines** without a linked tracking issue. (The scope check counts only `cheatsheets/` and `cheatsheets_draft/` Markdown — dependency/CI/typo-sweep PRs are not bound by it.)
- Work from a **clean branch off `master`, one topic per branch**. Never open two PRs from the same branch — it leaks unrelated changes between them (this has caused reverts here).
- A new or substantially updated cheat sheet requires an **approved issue first** (see CONTRIBUTING.md). Do not open a large unsolicited PR.
- Do not bundle unrelated changes, drive-by reformatting, or mass edits across files.

### 4. Don't duplicate — link instead

- Before adding a section, check whether it already exists in this or another cheat sheet (`cheatsheets/` and `Index.md`). If the topic is covered elsewhere, **link to it** instead of restating it.
- Coordinated multi-sheet families (e.g. the XSS, injection, and authorization sheets) are **intentional** and cross-link in a hub-and-spoke pattern — that is correct, not duplication. What's prohibited is reproducing another sheet's guidance instead of linking it.
- Confirm the content belongs in the cheat sheet you are editing. If it is really a different topic, it belongs in a different (or new) cheat sheet.

### 5. Architecture over code — for general topics

- For general topics, prefer architectural patterns, design principles, and security decisions over language-specific code. Code rots, and out-of-context snippets are often insecure.
- **Carve-out:** language-specific, injection/payload, parameterization, and hardening sheets are *expected* to be code-dense — that is correct for them (~40% of the corpus is code-heavy by design). This rule targets gratuitous boilerplate in architectural topics, not legitimately code-heavy sheets.
- When code is illustrative, keep it short (not production-ready) and language-tag fences where practical.

### 6. No slop

- Be concise and opinionated. Cut generic filler, verbose preambles, restated obvious background, and "in today's world…" intros. Recommend a specific approach; don't enumerate every option.
- If a section reads like generic AI output, rewrite or remove it. Maintainers close contributions that read as AI-slop.

### 7. Declare AI usage

- Any PR whose content was generated or materially assisted by AI **must** disclose it in the PR description (the template's AI Tool Usage section): tool name (Claude, Copilot, Cursor, Codex, …), version if known, and the prompt used. This applies to **all** AI tools, not just one. Failure to disclose can get the contribution deleted.

---

## Format & style (partly enforced by CI)

- US English. Spell-check. Keep language simple for non-native readers. Define non-obvious acronyms on first use (not "HTTP"/"URL").
- Markdown only — avoid raw HTML (only `details`/`summary` allowed). Lists use `-`. Bold uses `**`. Quotes use `>`.
- **Structure (typical shape, not a hard contract):** H1 = cheat sheet name → `## Introduction` (open this way — ~82% of sheets do) → main H2 sections → an optional `## References`. Typically 3–6 H2 sections, but more is fine for broad topics. Sourcing can be a `## References` section or inline — both accepted. Blank line after every heading (markdownlint-enforced). The TOC is auto-generated — do not add one.
- Filenames: letters/numbers/hyphens/underscores only, ending `_Cheat_Sheet.md`. New sheets start from [`templates/New_CheatSheet.md`](templates/New_CheatSheet.md).
- Assets go in `assets/`, images in PNG, referenced as `![alt](../assets/NAME.png)`.
- Links are inline with a descriptive label: `[Description](https://example.org)`. Always HTTPS where possible.

## Run the local checks before proposing changes

CI runs these on every PR; run them locally first so you don't ship obvious failures:

```bash
npm run lint-markdown      # markdownlint
npm run lint-terminology   # textlint (US English / terminology)
npm run link-check         # detects dead links
```

CI also enforces: **PR scope** (`pr-scope-check`), **citation density** (`citation-check`: every new H2 must contain at least one inline `[text](https://...)` citation), and the link check above. These catch mechanical problems — they do **not** judge whether a source actually supports its claim, whether advice is correct and in-scope, or whether content is duplicated. That judgment is on you and the maintainers.

---

## For maintainers reviewing PRs

This repo ships an aggressive, multi-dimensional review workflow for Claude Code. From the repo root:

```
/review-cheatsheet-pr <PR number | PR URL | (omit for local diff)>
```

It fans out specialized reviewers (security, developer practicality, link/source quality, duplication & placement, language) and returns a single verdict — **MERGE / REQUEST_CHANGES / CLOSE** — with evidence. See [`.claude/commands/review-cheatsheet-pr.md`](.claude/commands/review-cheatsheet-pr.md). Use it to triage the backlog and fact-check sources at scale.
