# Secure Coding with AI Cheat Sheet

## Introduction

Developers are rapidly adopting AI coding assistants (GitHub Copilot, Cursor, Claude Code, Gemini Code Assist, Windsurf) to accelerate development. These tools generate code, suggest dependencies, and automate implementation. However, AI-generated code introduces security risks that are distinct from human-written code and require specific mitigations within existing DevSecOps pipelines.

This cheat sheet provides actionable guidance for developers and security teams on safely integrating AI coding tools into their development workflow. It focuses on risks unique to AI-generated code and does not duplicate general secure coding guidance already covered in existing OWASP cheat sheets. Where overlap exists, this document links to the relevant cheat sheet.

For general input validation, see the [Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html). For SQL injection prevention, see the [SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html). For general secure coding principles, see the [Secure Coding Practices Quick Reference Guide](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/).

## Section 1: Hallucinated Dependencies

AI coding assistants frequently suggest package names that do not exist on public registries. Attackers monitor these hallucinated names and register malicious packages with matching names, a technique known as AI-assisted typosquatting.

### The Risk

A developer asks an AI assistant for help with a task. The assistant suggests `npm install fast-xml-validator`. The package does not exist on npm. An attacker registers `fast-xml-validator` as a malicious package containing a credential stealer. The developer installs it without checking.

### Do

- Verify every AI-suggested package exists on the public registry before installing. Check the package page, download count, maintainer history, and creation date.
- Be suspicious of packages with very low download counts, recent creation dates (less than 30 days), or a single maintainer with no other packages.
- Use package safety checking tools that verify package existence, age, maintainer count, and known vulnerability status before installation.
- Implement a pre-install hook or CI check that blocks installation of packages below a minimum age threshold (e.g. 30 days).
- Maintain an internal allowlist of approved packages for your organisation.

### Don't

- Blindly run `npm install`, `pip install`, or `go get` with package names suggested by an AI without verification.
- Assume that because an AI suggested a package, it exists or is safe.
- Ignore typosquatting risk. AI assistants frequently suggest names that are close to real packages but slightly different.

## Section 2: Outdated Dependencies with Known CVEs

AI models are trained on historical code. They frequently suggest dependency versions that were current during training but now have known vulnerabilities. The AI may not know about CVEs published after its training cutoff or after the coding tool's last security-index update.

### The Risk

An AI assistant suggests `npm install axios@0.21.1`. This version has known vulnerabilities. The current version is significantly newer with security patches applied.

### Do

- Run dependency auditing tools (npm audit, pip audit, govulncheck, cargo audit) on every AI-generated dependency list before merging.
- Configure CI/CD pipelines to fail on known vulnerabilities in dependencies, regardless of whether the code was human-written or AI-generated.
- Pin dependencies to specific versions and update them through your normal dependency management process, not through AI suggestions.
- Cross-reference AI-suggested versions against vulnerability databases (NVD, GitHub Advisory Database, OSV).

### Don't

- Accept AI-suggested dependency versions without checking for known CVEs.
- Assume that AI assistants are aware of recent vulnerability disclosures.
- Disable dependency auditing for AI-generated code.

## Section 3: Static Analysis of AI-Generated Code

AI-generated code may contain the same vulnerability classes as human-written code -- SQL injection, command injection, path traversal, XSS, insecure deserialization -- and teams should assume it requires equal or greater scrutiny.

### The Risk

An AI generates a database query function using string concatenation instead of parameterised queries. The code works correctly but is vulnerable to SQL injection. The developer accepts it because it passes tests.

### Do

- Run SAST tools on all AI-generated code with the same rules and severity thresholds as human-written code.
- Pay particular attention to common AI code generation weaknesses:
    - String concatenation in SQL queries instead of parameterised queries
    - Shell command construction from user input without escaping
    - File path construction from user input without traversal prevention
    - Hardcoded credentials, API keys, or secrets in generated code
    - Missing input validation on function parameters
    - Use of deprecated or insecure cryptographic functions
- Treat AI-generated code as untrusted input to your codebase. It should pass the same review and analysis gates as any external contribution.

### Don't

- Assume AI-generated code is secure because it came from a reputable AI provider.
- Skip code review for AI-generated code.
- Merge AI-generated code that fails SAST checks, even if it "works."
- Disable SAST rules for AI-generated files.

## Section 4: Dynamic Analysis of AI-Generated Code

Static analysis catches many issues but cannot detect runtime vulnerabilities such as race conditions, authentication bypass under specific request sequences, or business logic flaws. Dynamic testing is essential for AI-generated code that handles user input or performs sensitive operations.

### Do

- Include AI-generated endpoints and functions in your existing DAST scanning scope.
- Write security-focused test cases for AI-generated code, particularly for:
    - Authentication and authorisation boundaries
    - Input handling edge cases (empty, null, oversized, malformed)
    - Error handling behaviour (does it fail closed or fail open?)
    - Rate limiting and resource consumption
- Run fuzz testing on AI-generated parsers, validators, and input handlers.

### Don't

- Exclude AI-generated code from dynamic testing because "the AI tested it."
- Trust AI-generated test cases as sufficient for security validation. AI tends to generate happy-path tests, not adversarial tests.
- Deploy AI-generated API endpoints without DAST scanning.

## Section 5: Secrets in AI-Generated Code

AI assistants frequently generate code containing placeholder secrets, example API keys, or hardcoded credentials. These placeholders are sometimes realistic enough to be mistaken for actual credentials or may accidentally match real credentials from training data.

### Do

- Run secret scanning tools on all AI-generated code before committing.
- Configure pre-commit hooks that block commits containing patterns matching API keys, tokens, private keys, or connection strings.
- Replace AI-generated placeholder credentials with environment variable references immediately, before the code is committed.
- Audit existing codebase for secrets that may have been introduced by AI-generated code in past commits.

### Don't

- Commit AI-generated code without secret scanning.
- Assume placeholder credentials in AI output are fake. They may match real credentials from training data.
- Hardcode credentials in configuration files because the AI suggested that pattern.

For comprehensive guidance on secrets management, see the [Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html).

For guidance on preventing your existing secrets from being sent to AI providers through the IDE context window, see Section 8: Prompt Context Leakage and Sensitive Code Exposure.

## Section 6: License and Intellectual Property Risks

AI-generated code may resemble or reproduce portions of copyrighted or restrictively licensed code, creating potential licence or IP review obligations. Including such code in your project without awareness of its provenance can create legal exposure.

### Do

- Run licence scanning tools on AI-generated code to detect potential licence conflicts.
- Maintain awareness of your project's licence obligations and whether AI-generated contributions are compatible.
- Document which portions of your codebase were AI-generated for IP audit purposes.
- Review AI-generated code for unusually specific or complex implementations that may be reproduced from training data rather than genuinely generated.

### Don't

- Assume AI-generated code is free of licence obligations.
- Include AI-generated code in proprietary projects without licence review.
- Ignore licence scanning results for AI-generated files.

## Section 7: AI-Generated Infrastructure Code

AI assistants generate infrastructure-as-code (Terraform, CloudFormation, Dockerfiles, Kubernetes manifests) with the same security risks as application code. Misconfigurations in infrastructure code can expose entire environments.

### Do

- Run IaC security scanning tools on AI-generated infrastructure code (Terraform, CloudFormation, Docker, Kubernetes manifests).
- Check AI-generated Dockerfiles for:
    - Running as root
    - Installing unnecessary packages
    - Exposing unnecessary ports
    - Using `latest` tags instead of pinned versions
    - Copying secrets into the image
- Check AI-generated Kubernetes manifests for:
    - Privileged containers
    - Missing resource limits
    - Missing network policies
    - Default service account usage
- Check AI-generated Terraform/CloudFormation for:
    - Public S3 buckets or storage
    - Security groups with 0.0.0.0/0 ingress
    - Missing encryption at rest
    - Overly permissive IAM policies

### Don't

- Deploy AI-generated infrastructure code without IaC scanning.
- Trust AI-generated security group rules or IAM policies without review.
- Use AI-generated Dockerfiles in production without hardening.

## Section 8: Prompt Context Leakage and Sensitive Code Exposure

When using AI coding assistants in IDEs, the tool sends code context (open files, project structure, terminal output) to the AI provider's API. This context may contain sensitive information including credentials, personal data, proprietary business logic, and internal architecture details.

### Do

- Review what context your AI coding assistant sends to the provider. Most tools document this.
- Configure AI tools to exclude sensitive directories (e.g. `.env` files, credential stores, private key directories) from context.
- Add `.env`, `.env.*`, `*.pem`, `*.key`, `credentials.json`, `serviceAccountKey.json`, and similar sensitive files to your AI tool's context exclusion list (`.cursorignore`, `.copilotignore`, or equivalent).
- Audit what your AI coding tool sends by enabling request logging or using a network proxy to inspect outbound API calls.
- Use self-hosted or air-gapped AI coding tools for projects handling classified, regulated, or highly sensitive code.
- Implement data loss prevention (DLP) rules that detect and block sensitive data in AI tool API traffic.
- Store all secrets in environment variables, vault services, or encrypted secret stores -- never in files within the project tree where AI tools can read them.

### Don't

- Use cloud-hosted AI coding assistants on classified or top-secret codebases without approval.
- Assume that AI coding assistants only send the current file. Many send broader project context.
- Ignore your organisation's data classification policies when choosing AI coding tools.
- Open `.env` files or private keys in your IDE while an AI coding assistant is active. The file contents may be sent as context.
- Paste API keys, tokens, or credentials into your terminal while AI tools with terminal context access are running.
- Assume that `.gitignore` prevents AI tools from reading files. `.gitignore` only affects git -- AI tools read from the filesystem directly.

## Section 9: Enterprise Deployment and Data Governance

Organisations deploying AI coding tools at scale face data governance, privacy, and intellectual property risks that individual developers may not consider.

### Data Protection and GDPR

When AI coding assistants process code that contains or references personal data, GDPR and other data protection regulations apply.

#### Do

- Conduct a Data Protection Impact Assessment (DPIA) before deploying AI coding tools across your organisation. Assess what data flows to the AI provider, how it is processed, and what retention policies apply.
- Verify the AI provider's data processing agreement (DPA) covers your obligations under GDPR, UK GDPR, or applicable data protection law.
- Confirm whether the AI provider uses your code or prompts to train or fine-tune their models. If they do, assess whether this constitutes a new purpose requiring consent or a legitimate interest assessment.
- Ensure your AI tool configuration complies with data minimisation principles -- only send the minimum context necessary for code generation.
- Maintain records of processing activities that include AI coding tool usage, including what data categories are processed and the legal basis.
- Provide clear information to developers about what data the AI tool processes and their rights under applicable privacy law.

#### Don't

- Deploy AI coding tools that process personal data without a DPIA.
- Assume that code never contains personal data. Database schemas, test fixtures, configuration files, and comments frequently contain PII, email addresses, or customer identifiers.
- Use AI coding tools from providers without a clear data processing agreement.
- Ignore data residency requirements. Some AI providers process data outside your jurisdiction -- verify this is compatible with your transfer mechanisms.

### Intellectual Property and Code Ownership

AI-generated code raises unresolved questions about ownership, copyright, and the risk of reproducing proprietary code from training data.

#### Do

- Establish a clear organisational policy on IP ownership of AI-generated code before developers start using AI tools.
- Assess whether AI-generated code in your codebase affects your ability to patent, licence, or sell your software.
- Monitor for code that appears to be reproduced from specific open source projects rather than genuinely generated. Indicators include project-specific variable names, exact comment text, or unusual implementation patterns that match known repositories.
- Maintain an inventory of which code in your codebase was AI-generated, including the tool and model version used. This supports future IP audits and licence disputes.
- Review your employment contracts and contributor agreements to clarify whether AI-assisted contributions are covered.

#### Don't

- Assume that AI-generated code is free of third-party IP claims.
- Use AI coding tools to generate code for patent applications without legal review of the IP implications.
- Ignore the possibility that AI-generated code reproduces copyrighted material from training data. The legal landscape is evolving and organisations should maintain awareness of relevant case law.

### Training Data Opt-Out and Telemetry

Many AI coding tools collect telemetry data and may use customer code to improve their models unless explicitly opted out.

#### Do

- Review the AI provider's terms of service for clauses about using customer code for model training or improvement.
- Opt out of training data collection where the option exists. Most enterprise plans offer this -- verify it is enabled.
- Audit what telemetry your AI coding tools send beyond the code context. Some tools report usage patterns, error rates, and editor state.
- Use enterprise or business tiers of AI coding tools that offer contractual guarantees against training on customer data. Free and individual tiers frequently do not offer these guarantees.
- Consider self-hosted or air-gapped AI coding tools for regulated industries (financial services, healthcare, defence, government) where code leaving the network boundary is unacceptable.

#### Don't

- Use free-tier AI coding tools on proprietary or regulated codebases without verifying the training data policy.
- Assume that opting out of training in the UI settings is sufficient. Verify the contractual terms match the UI settings.
- Ignore telemetry collection. Even if code is not used for training, metadata about your development patterns may be collected and processed.

### Enterprise Architecture Considerations

#### Do

- Deploy AI coding tools through a centralised gateway or proxy that enforces organisation-wide policies (context exclusions, data classification rules, approved models).
- Implement logging of all AI tool API calls for audit and incident response purposes.
- Establish an approved list of AI coding tools and models. Prevent developers from using unapproved tools that may have weaker data protection guarantees.
- Include AI coding tool risk in your third-party vendor risk assessment process.
- Plan for AI tool provider incidents -- what happens to your development workflow if the AI provider experiences an outage, breach, or discontinuation of service?

#### Don't

- Allow developers to individually sign up for AI coding tools with personal accounts on enterprise codebases.
- Deploy AI coding tools without centralised policy enforcement.
- Exclude AI tool providers from your vendor risk management programme.
- Assume AI coding tools are low-risk because they "only generate code." They process your codebase, your architecture, and your business logic.

## Section 10: AI-Generated Tests

AI coding assistants generate test suites alongside application code. These tests often assert the generated behaviour rather than the correct or secure behaviour. A passing test suite does not indicate security when the tests themselves were generated by the same AI that produced the vulnerable code.

### The Risk

An AI generates an authentication function with a logic flaw (e.g. fail-open on token expiry). It simultaneously generates tests that assert this broken behaviour. The tests pass, the developer gains false confidence, and the vulnerability ships.

### Do

- Require human review of all AI-generated test cases, with particular focus on security assertions.
- Add negative and adversarial test cases that the AI did not generate: invalid inputs, expired tokens, malformed payloads, boundary conditions, concurrent access.
- Verify that generated tests assert the correct security behaviour, not just the generated behaviour. A test that asserts a broken function works is worse than no test.
- Measure security confidence by adversarial testing results and SAST/DAST findings, not by "all tests pass."
- Write security-specific tests manually for authentication, authorisation, input validation, and cryptographic operations.

### Don't

- Trust AI-generated test suites as evidence of security.
- Measure confidence by test pass rate alone. 100% passing means nothing if the tests assert broken behaviour.
- Allow AI to generate both the security-critical code and its tests without independent human verification of correctness.
- Skip adversarial/negative test cases because the AI-generated happy-path tests pass.

## Section 11: AI-Generated Authentication and Authorisation Logic

AI frequently generates plausible but broken authentication and authorisation code. The generated code often works for the happy path but fails under adversarial conditions. This deserves dedicated scrutiny because auth failures are the highest-impact vulnerability class.

### The Risk

An AI generates middleware that checks user roles, but only validates the role claim from the JWT without checking object ownership. The result: users can access any resource by supplying a valid token with the correct role, regardless of whether they own the resource (IDOR).

### Do

- Require mandatory security review for all AI-generated authentication, authorisation, and access control code.
- Check AI-generated auth code specifically for:
    - IDOR / missing object-level authorisation (user can access another user's resources)
    - Role confusion (admin check uses wrong field, or trusts client-supplied role)
    - Client-side-only authorisation (checks in frontend but not enforced server-side)
    - Missing tenant checks in multi-tenant systems (user from Tenant A accesses Tenant B data)
    - Fail-open middleware (auth middleware that passes requests through on error instead of blocking)
    - Missing token validation (signature not verified, expiry not checked, issuer not validated)
- Test AI-generated auth with adversarial scenarios: expired tokens, tokens for different users, tokens with modified claims, missing tokens, tokens from different issuers.

### Don't

- Trust AI-generated authorisation middleware without explicit security review.
- Accept role-based access control code from AI without testing object-level authorisation.
- Deploy AI-generated auth that only validates on the client side.
- Assume AI understands your tenant model. AI frequently generates single-tenant auth patterns for multi-tenant applications.

## Section 12: AI-Generated Cryptographic Code

AI coding assistants generate cryptographic code that appears correct but often uses deprecated algorithms, insecure modes, predictable randomness, or custom schemes that are trivially breakable. Cryptography requires domain expertise that AI does not reliably possess.

### Do

- Use approved cryptographic libraries and patterns only. AI should generate calls to well-known libraries (e.g. libsodium, OpenSSL, Web Crypto API, Go crypto/), not custom implementations.
- Require mandatory security review for all AI-generated code involving encryption, signing, hashing, password storage, token generation, key derivation, or random number generation.
- Verify AI-generated crypto code uses:
    - Current algorithms (AES-256-GCM, ChaCha20-Poly1305 for encryption; SHA-256/SHA-3 for hashing; ECDSA P-256 or Ed25519 for signing; Argon2id for password hashing)
    - Cryptographically secure random number generation (crypto.randomBytes, secrets module, /dev/urandom)
    - Proper IV/nonce handling (never reused, sufficient length)
    - Authenticated encryption (GCM, Poly1305) rather than unauthenticated modes (ECB, CBC without HMAC)

### Don't

- Ask AI to invent encryption schemes, custom token formats, or novel cryptographic protocols.
- Accept AI-generated password hashing using MD5, SHA-1, or unsalted SHA-256.
- Trust AI-generated key derivation or key exchange code without cryptographic review.
- Use AI-generated random token generation that uses Math.random(), time-based seeds, or other predictable sources.
- Allow AI to generate its own JWT signing/verification logic instead of using established JWT libraries.

## Section 13: Prompt-to-Code Supply Chain Risk

AI coding assistants modify not just application code but also build scripts, CI/CD configurations, package scripts, and deployment infrastructure. Malicious or incorrect changes to these files have outsized impact because they execute automatically in trusted contexts.

### The Risk

A developer asks an AI to "add a build step." The AI modifies `package.json` to add a `postinstall` script, or changes a GitHub Actions workflow to include a new step that downloads and executes an external script. These changes execute automatically on every install or CI run.

### Do

- Review AI changes to the following files with heightened scrutiny -- treat them as security-critical:
    - `package.json` (scripts section: postinstall, preinstall, prepare, prebuild)
    - `.github/workflows/*.yml` (GitHub Actions)
    - `.gitlab-ci.yml`
    - `Dockerfile`, `docker-compose.yml`
    - `Makefile`, `Rakefile`, `Taskfile`
    - `setup.py`, `pyproject.toml` (build scripts)
    - `go generate` directives
    - Any file that executes automatically during build, install, test, or deploy
- Flag any AI-generated change that adds network access, downloads external resources, or executes shell commands in build/deploy context.
- Implement CI checks that diff build configuration files and require explicit approval for changes to CI/CD pipelines.

### Don't

- Allow AI to modify CI/CD pipelines, Dockerfiles, or package scripts without explicit human review.
- Accept AI-generated GitHub Actions that reference third-party actions without pinning to a specific SHA.
- Trust AI-generated build scripts that download or execute external URLs.
- Merge AI changes to deployment configurations without verifying what changed in the build/deploy path.

## Section 14: Runtime Guardrails for AI-Generated Code

Secure coding guidance must extend beyond development to deployment. AI-generated code that passes all review gates may still behave unexpectedly in production. Defence-in-depth requires runtime controls.

### Do

- Deploy AI-generated services with least-privilege runtime credentials. If the code only reads from a database, the runtime credential should only have read access.
- Sandbox AI-generated tools, scripts, and automation using containers, VMs, or process-level isolation.
- Apply egress restrictions to AI-generated services. If the code does not need outbound network access, block it at the network level.
- Set resource limits (memory, CPU, file descriptors, process count) on AI-generated services to prevent unbounded resource consumption.
- Monitor AI-generated code in production for unexpected behaviour: unusual network connections, excessive resource usage, unexpected file access patterns.
- Implement kill switches for AI-generated automation that can halt execution immediately if anomalous behaviour is detected.

### Don't

- Run AI-generated code with admin or root credentials in production.
- Deploy AI-generated services without network egress controls.
- Allow AI-generated code unlimited resource consumption in production.
- Deploy AI-generated automation without monitoring and alerting.
- Assume that code which passed review cannot behave unexpectedly at runtime.

## Section 15: Human Accountability

AI-generated code must have a human owner. Every AI-assisted change should be reviewed, approved, and attributable to a developer who is responsible for its security and maintainability. AI tools do not accept responsibility for the code they generate. The developer who accepts and commits the code does.

### Do

- Assign a human owner to every AI-generated code change. That owner is responsible for its correctness, security, and maintenance.
- Require explicit developer approval before merging any AI-generated code. The approval indicates the developer has reviewed and understood the change.
- Maintain audit trails showing which developer approved which AI-generated changes, including the AI tool and model version used.
- Include AI-generated code in your normal code review process. The reviewer is accountable for what they approve.
- Treat AI as a tool, not a colleague. A developer who says "the AI wrote it" is still responsible for it.

### Don't

- Deploy AI-generated code that no human has reviewed and approved.
- Allow AI-generated code to bypass code review because "the AI is usually right."
- Treat AI approval (e.g. AI-generated code review comments) as a substitute for human review.
- Attribute security failures to the AI tool. The developer who approved the code is accountable.

## Section 16: Do's and Don'ts Summary

### Do

- Verify every AI-suggested package exists and is safe before installing.
- Run npm audit / pip audit / govulncheck on AI-generated dependency lists.
- Run SAST on AI-generated code with the same rules as human-written code.
- Run DAST on AI-generated endpoints and input handlers.
- Run secret scanning on all AI-generated code before committing.
- Run IaC scanning on AI-generated infrastructure code.
- Run licence scanning on AI-generated code.
- Treat AI-generated code as untrusted input to your codebase.
- Document which portions of your codebase were AI-generated.
- Require mandatory security review for AI-generated auth, crypto, and build scripts.
- Add adversarial/negative tests alongside AI-generated tests.
- Deploy AI-generated services with least-privilege credentials, sandboxing, and egress controls.
- Review AI changes to CI/CD, Dockerfiles, and package scripts with heightened scrutiny.
- Assign a human owner to every AI-generated change.

### Don't

- Blindly install AI-suggested packages without verification.
- Accept AI-suggested dependency versions without CVE checks.
- Skip code review for AI-generated code.
- Trust AI-generated test cases as sufficient for security validation.
- Commit AI-generated code without secret scanning.
- Deploy AI-generated infrastructure without IaC scanning.
- Use cloud AI coding tools on sensitive projects without data classification review.
- Ask AI to invent cryptographic schemes or custom auth protocols.
- Trust AI-generated authorisation without testing object-level access control.
- Allow AI to modify CI/CD pipelines or build scripts without explicit approval.
- Run AI-generated code with admin credentials or unlimited resources in production.

## OWASP Top 10 Mapping

This cheat sheet maps to the OWASP Top 10 2021 as follows:

| OWASP Top 10 | Relevant Section |
|---|---|
| A01: Broken Access Control | Section 11: AI-Generated Authentication and Authorisation Logic |
| A02: Cryptographic Failures | Section 12: AI-Generated Cryptographic Code |
| A03: Injection | Section 3: Static Analysis (SQL, command, path traversal in generated code) |
| A04: Insecure Design | Section 10: AI-Generated Tests, Section 11: AI-Generated Authentication and Authorisation Logic, Section 15: Human Accountability |
| A05: Security Misconfiguration | Section 7: AI-Generated Infrastructure Code |
| A06: Vulnerable and Outdated Components | Section 1: Hallucinated Dependencies, Section 2: Outdated Dependencies |
| A07: Identification and Authentication Failures | Section 11: AI-Generated Authentication and Authorisation Logic |
| A08: Software and Data Integrity Failures | Section 13: Prompt-to-Code Supply Chain Risk |
| A09: Security Logging and Monitoring Failures | Section 9: Enterprise Deployment and Data Governance, Section 14: Runtime Guardrails |
| A10: Server-Side Request Forgery | Section 3: Static Analysis, Section 13: Prompt-to-Code Supply Chain Risk, Section 14: Runtime Guardrails |

## References

- [OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [OWASP Secure Coding Practices Quick Reference Guide](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/)
- [OWASP Top 10 for LLM Applications](https://genai.owasp.org/)
- [OWASP AISVS](https://github.com/OWASP/AISVS)
- CVE-2026-39313 -- mcp-framework before 0.2.22: unbounded memory allocation in HTTP request body handling allowed unauthenticated denial of service. Example of a vulnerability in AI framework code that highlights the need for dependency auditing and runtime limits.
