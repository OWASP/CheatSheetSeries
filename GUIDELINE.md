# Cheat Sheet Writing Guide

This guide helps you write effective cheat sheet content. For the contribution process (how to submit issues, set up your environment, and open pull requests), see [CONTRIBUTING.md](CONTRIBUTING.md).

## What Makes a Good Cheat Sheet

The best cheat sheets in this project share a few qualities:

- **Written for developers**, not security experts. Assume your reader builds software daily but does not have deep security knowledge.
- **Practical over theoretical.** Actionable advice that can be implemented today beats academic discussion.
- **Concise.** Cheat sheets are reference material. Get to the point.
- **Opinionated.** Recommend specific approaches rather than listing every possible option. Developers want to know what to do, not evaluate trade-offs themselves.

## Getting Started

Copy the template and rename it for your topic:

```bash
cp templates/New_CheatSheet.md cheatsheets/Your_Topic_Cheat_Sheet.md
```

File naming rules:

- Use only letters, numbers, hyphens, and underscores
- End with `_Cheat_Sheet.md`
- Example: `API_Rate_Limiting_Cheat_Sheet.md`

## Structure

Every cheat sheet follows this structure:

```markdown
# Your Topic Cheat Sheet

## Introduction

A brief overview: what is this topic, why does it matter for security,
and who should read this cheat sheet.

## Main Sections

Organize your advice into clear sections. Most cheat sheets have
3-6 top-level sections covering different aspects of the topic.

## References

Links to external resources, standards, or related cheat sheets.
```

### Introduction

The introduction should be 2-4 sentences that tell the reader what the cheat sheet covers and why it matters. Here is a real example from the Authentication Cheat Sheet:

> **Authentication** is the process of verifying that an individual, entity, or website is whom it claims to be. This cheat sheet provides guidance on implementing authentication in web applications.

Short, clear, and sets expectations for what follows.

### Main Sections

Organize your content into 3-6 top-level sections. Each section should address a distinct aspect of the topic. Use subsections (H3) to break down complex areas.

Look at existing cheat sheets for inspiration:

- [Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html) - organized by concern (passwords, MFA, logging)
- [Docker Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html) - organized as numbered rules
- [Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html) - organized by technique

### References

Link to authoritative external resources: RFCs, NIST publications, OWASP standards, and related cheat sheets. Don't repeat content from other cheat sheets - link to them instead.

## Writing Tips

### Lead with Architecture, Not Code

Cheat sheets should prioritize architectural patterns, design principles, and security decisions over language-specific code samples. Architectural guidance applies across languages and frameworks, making it more durable and broadly useful. Code samples require ongoing maintenance and, when taken out of context, are often not fully secure.

**Prefer this** (architectural guidance):

> Use a dedicated password hashing algorithm (Argon2id, bcrypt, or scrypt) with appropriate cost factors. Never use general-purpose hash functions like SHA-256 for password storage. Delegate hashing to a well-maintained library rather than implementing it yourself. Store the algorithm identifier and cost parameters alongside the hash so you can upgrade without invalidating existing passwords.

**Over this** (language-specific code):

```java
String hash = BCrypt.hashpw(password, BCrypt.gensalt(12));
```

A code snippet like the one above may look correct but omits error handling, input validation, and context that matter in production. Architectural guidance helps developers make the right decisions regardless of their language or framework.

### When to Use Code Examples

Code examples are appropriate when they illustrate a concept that is difficult to explain in prose alone, such as a specific API call pattern or configuration syntax. When you do include code:

- Keep it short and clearly illustrative, not production-ready.
- Use pseudocode or a single common language rather than providing examples in multiple languages.
- Make clear that the example is for illustration and that developers should consult their framework's documentation for complete usage.

### Use Tables for Comparisons

Tables work well for showing secure vs. insecure approaches side by side:

| Approach | Secure | Insecure |
|----------|--------|----------|
| Password storage | bcrypt/Argon2 hash | MD5/SHA-1 hash |
| Session tokens | Cryptographically random | Sequential IDs |
| Error messages | Generic message | Stack trace to user |

Use [tablesgenerator.com](https://www.tablesgenerator.com/markdown_tables) to build Markdown tables easily.

### Keep Recommendations Feasible

It is much better to give _good_ practices that developers can actually follow than _best_ practices that are completely impractical. If a recommendation requires specialized tools, significant infrastructure changes, or deep expertise, say so explicitly and offer a simpler alternative where possible.

### Support Claims with References

When making security recommendations, link to authoritative sources. Inline links work best:

```markdown
Use Argon2id for password hashing as recommended by
[OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
and [NIST SP 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html).
```

### Stay Focused

Cover one topic well. If you find yourself writing extensively about a related topic, it probably deserves its own cheat sheet. Link to existing cheat sheets rather than duplicating their content.

## Common Mistakes to Avoid

- **Writing for security experts.** If your cheat sheet requires security expertise to understand, it needs to be simplified.
- **Being too abstract.** "Validate all input" is not helpful. Describe the specific validation strategy and what it protects against.
- **Covering too much.** A focused cheat sheet on one topic is better than a sprawling guide that tries to cover everything.
- **Listing without recommending.** Don't just present options - tell the reader which approach to use and why.
- **Skipping the "why".** A brief explanation of _why_ a practice matters helps developers prioritize and remember it.

## Quick Reference

| What | Where |
|------|-------|
| Template for new cheat sheets | [templates/New_CheatSheet.md](templates/New_CheatSheet.md) |
| Existing cheat sheets | [cheatsheets/](cheatsheets/) directory |
| Draft cheat sheets | [cheatsheets_draft/](cheatsheets_draft/) directory |
| Image assets | [assets/](assets/) directory |
| Contribution process and style guide | [CONTRIBUTING.md](CONTRIBUTING.md) |
| Published site | [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/) |
