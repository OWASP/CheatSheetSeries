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

Instead, submit a private report including clear steps to reproduce and details about potential impact to:

- <jim.manico@owasp.org>
- <jakub.mackowski@owasp.org>
- <shlomo.heigh@owasp.org>
