# Security Policy

The OWASP Cheat Sheet Series is primarily documentation, but some in-scope examples include:

- Allows an attacker to run code in a reader’s browser via [our site](https://cheatsheetseries.owasp.org/) (XSS, open redirect, etc)
- Leaks GitHub Actions secrets
- Tampers with our build pipeline

The following are out of scope unless they are directly exploitable on the live site:

- Snippets that are intentionally vulnerable for demonstration
- Third-party dependencies (automatically handled by Dependabot)

## Reporting a Vulnerability

**Do not open public issues for new vulnerabilities**.

Instead, use the **Report a vulnerability** button on the [repository's Security tab](https://github.com/OWASP/CheatSheetSeries/security). That opens a private advisory that only the maintainers can see, and we can work on the fix with you there.

If you prefer email, write to:

- <jim.manico@owasp.org>
- <jakub.mackowski@owasp.org>
- <corona.gabriel@gmail.com>

Either way, include clear steps to reproduce and details about the potential impact.
