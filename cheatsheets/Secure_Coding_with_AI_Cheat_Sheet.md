# Secure Coding with AI Cheat Sheet

## Introduction

AI coding tools have moved beyond code suggestion. In 2026, agentic coding tools (Claude Code, Cursor agent mode, Aider, Devin, Copilot Workspace, Codex) execute shell commands, install packages, edit files, run tests, access the network, and push branches autonomously. Many developers run these agents with auto-accept enabled, meaning the agent operates with the developer's full permissions and minimal human oversight.

This cheat sheet addresses the security risks specific to AI-assisted and agentic coding. It focuses on threats that do not exist in traditional development workflows and does not restate general secure coding guidance already covered elsewhere.

For general secure coding, see the [Secure Coding Practices Quick Reference Guide](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/). For AI agent security beyond coding tools, see the [AI Agent Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html). For prompt injection prevention, see the [LLM Prompt Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html). For MCP protocol security, see the [MCP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html).

## Threat Model and Trust Boundaries

AI coding agents operate across multiple trust boundaries. Understanding these boundaries is essential before applying any controls.

```
                    TRUST BOUNDARIES IN AGENTIC CODING

 [DEVELOPER]                    [AGENT]                    [EXTERNAL]
  Developer  ──── permissions ──── AI Agent  ──── reads ──── Repo Content
  approves        (often full       executes       ingests     (issues, PRs,
  or auto-        dev access)       commands       context     READMEs, deps,
  accepts                                                      changelogs)
      |                |                |                |
      |           [MODEL PROVIDER]      |          [MCP SERVERS]
      |            API calls            |           Tool calls
      |            Code + context       |           File access
      |            sent to provider     |           Network access
      |                                 |           Credentials
      |                                 |
      |              [CI/CD]            |
      |            Workflows            |
      |            Org secrets          |
      |            Deploy access        |
```

### Threat Actors and Attack Surfaces

- **Repository content as instruction source.** Issue bodies, PR descriptions, PR comments, README files, dependency changelogs, error traces, fetched web pages, and MCP tool responses all become instructions when the agent reads them. An attacker who can write to any of these can influence agent behaviour.
- **MCP servers as tool providers.** Agents connect to MCP servers to access tools. A malicious or compromised MCP server can poison tool descriptions, shadow legitimate tool names, exfiltrate credentials through tool arguments, or update tool definitions after initial approval (rug-pull).
- **Rules files as persistent steering.** Files like `.cursorrules`, `CLAUDE.md`, `AGENTS.md`, `.github/copilot-instructions.md`, and `.windsurfrules` silently steer every future generation. They can be modified by a malicious PR or by the agent itself to embed persistent instructions.
- **The agent itself.** Agents running with auto-accept and full developer permissions can install packages, write to any file, execute shell commands, modify CI configuration, and push branches. A compromised agent context has the same blast radius as a compromised developer workstation.
- **CI/CD agents.** Review bots and CI runners (e.g. `claude-code-action`, Copilot review) act on PR content with access to org secrets. A malicious PR can trigger the CI agent to exfiltrate secrets or modify the build pipeline. This is confused deputy at scale.

## Section 1: Hallucinated Dependencies

AI coding assistants frequently suggest package names that do not exist on public registries. Attackers monitor these hallucinated names and register malicious packages with matching names (AI-assisted typosquatting).

### Do

- Verify every AI-suggested package exists on the public registry before installing. Check the package page, download count, maintainer history, and creation date.
- Be suspicious of packages with very low download counts, recent creation dates (less than 30 days), or a single maintainer with no other packages.
- Implement a pre-install hook or CI check that blocks installation of packages below a minimum age threshold.
- Maintain an internal allowlist of approved packages for your organisation.

### Don't

- Blindly run `npm install`, `pip install`, or `go get` with package names suggested by an AI without verification.
- Assume that because an AI suggested a package, it exists or is safe.
- Ignore typosquatting risk. AI assistants frequently suggest names that are close to real packages but slightly different.

## Section 2: Outdated Dependencies with Known CVEs

AI models are trained on historical code. They frequently suggest dependency versions that were current during training but now have known vulnerabilities. The AI may not know about CVEs published after its training cutoff or after the coding tool's last security-index update.

### Do

- Run dependency auditing tools (npm audit, pip audit, govulncheck, cargo audit) on every AI-generated dependency list before merging.
- Configure CI/CD pipelines to fail on known vulnerabilities in dependencies, regardless of whether the code was human-written or AI-generated.
- Pin dependencies to specific versions and update them through your normal dependency management process, not through AI suggestions.
- Cross-reference AI-suggested versions against vulnerability databases (NVD, GitHub Advisory Database, OSV).

### Don't

- Accept AI-suggested dependency versions without checking for known CVEs.
- Assume that AI assistants are aware of recent vulnerability disclosures.
- Disable dependency auditing for AI-generated code.

## Section 3: Indirect Prompt Injection in the Development Loop

Agentic coding tools ingest context from the repository, the network, and connected tools. Any content the agent reads can contain hidden instructions that alter its behaviour. This is indirect prompt injection applied to the development workflow.

### Attack Vectors

- **Issue bodies and PR descriptions.** An attacker opens an issue containing hidden instructions. When a developer asks the agent to "fix issue #123", the agent reads the issue body and follows the embedded instructions.
- **PR comments and review feedback.** Malicious review comments can instruct the agent to modify unrelated files, weaken security controls, or exfiltrate code when the developer asks the agent to "address review feedback."
- **README and documentation files.** Cloned repositories, dependencies, and fetched documentation can contain instructions invisible to human readers but parsed by the agent.
- **Error traces and log output.** When an agent reads error output to debug a failure, crafted error messages can inject instructions.
- **Dependency changelogs and release notes.** Agents reading changelogs to understand version differences can be influenced by injected content.
- **Fetched web pages.** Agents with web access can be influenced by content on pages they are asked to reference.

### Do

- Treat all repository content (issues, PRs, comments, READMEs) as untrusted input when processed by an AI coding agent.
- Review agent output for unexpected changes after the agent processes any external content.
- Use tools that sanitise or flag potential injection patterns in repository content before the agent processes it.
- Restrict agent context to the minimum files and content needed for the task.
- Audit agent actions after processing content from external contributors or public repositories.

### Don't

- Allow agents to process issue bodies, PR descriptions, or comments from untrusted contributors without review of the agent's resulting actions.
- Assume that content an agent reads is safe because it appears in a familiar context (e.g. a GitHub issue).
- Give agents unrestricted access to browse the web or fetch arbitrary URLs without egress controls.

## Section 4: MCP and Tool Security

AI coding agents connect to MCP (Model Context Protocol) servers to access tools for file operations, database queries, API calls, and more. Compromised or malicious MCP servers are a direct supply chain risk to the development environment.

For comprehensive MCP security guidance, see the [MCP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html).

### Do

- Audit all MCP servers connected to your development environment. Maintain an allowlist of approved servers and tools.
- Pin tool definitions and detect changes. Use snapshot-and-diff mechanisms to catch rug-pull updates where a tool's behaviour changes after initial approval.
- Review tool descriptions for hidden instructions. Tool descriptions are part of the agent's context and can contain prompt injection payloads.
- Restrict which tools the agent can invoke. Apply least privilege -- a coding agent does not need access to email, payment, or administrative tools.
- Monitor for tool name shadowing where a malicious MCP server registers a tool with the same name as a legitimate one to intercept calls.
- Validate tool arguments before execution. Agents may pass sensitive data (credentials, file contents, environment variables) as tool arguments without awareness of the data classification.

### Don't

- Connect to MCP servers from untrusted sources without security review.
- Allow agents to discover and connect to MCP servers automatically without approval.
- Trust tool descriptions as benign. They are an injection surface.
- Allow MCP tools unrestricted filesystem, network, or credential access on the developer's machine.

Reference: CVE-2026-39313 -- mcp-framework before 0.2.22: unbounded memory allocation in HTTP request body handling allowed unauthenticated denial of service. Example of a vulnerability in AI framework code that highlights the need for dependency auditing and runtime limits.

## Section 5: Agent Runtime Sandboxing

Agentic coding tools execute commands, install packages, write files, and access the network on the developer's machine. Without sandboxing, a compromised agent context has the same privileges as the developer.

### Do

- Run AI coding agents in sandboxed environments: dev containers, restricted shells, virtual machines, or ephemeral cloud workspaces.
- Use tool allowlists that restrict which commands the agent can execute. Block access to credential stores, SSH keys, cloud CLI configurations, and sensitive directories.
- Apply egress controls on the agent's runtime. If the agent does not need outbound network access for the current task, block it.
- Use ephemeral credentials scoped to the current task rather than long-lived developer credentials.
- Understand and evaluate the risk of flags like `--dangerously-skip-permissions` or auto-accept modes. These bypass confirmation prompts and give the agent unrestricted execution.
- Set resource limits (CPU, memory, disk, process count) on agent execution environments.

### Don't

- Run AI coding agents with your full developer credentials, SSH keys, and cloud access tokens without sandboxing.
- Enable auto-accept mode on untrusted or unfamiliar codebases.
- Allow agents to access production credentials, deployment keys, or org-level secrets from the development environment.
- Assume the agent will only touch files relevant to the current task.

## Section 6: Rules Files and Persistent Steering

AI coding tools read configuration files that steer their behaviour across all future interactions. These files are a persistence mechanism -- an attacker who can modify them controls every subsequent generation.

### Affected Files

- `.cursorrules`, `.cursor/rules/`
- `CLAUDE.md`, `.claude/`
- `AGENTS.md`
- `.github/copilot-instructions.md`
- `.windsurfrules`
- `.aider.conf.yml`
- Custom system prompt files referenced by any AI tool

### Do

- Treat rules files as security-critical configuration. Review changes to these files with the same scrutiny as CI/CD pipeline changes.
- Add rules files to your code review requirements. Require explicit approval for any modification.
- Monitor for unexpected rules file creation or modification, including by the agent itself.
- Use git hooks or CI checks that flag changes to known rules files in every PR.
- Audit existing rules files for instructions that weaken security controls, disable safety features, or direct the agent to ignore certain file types or patterns.

### Don't

- Allow PRs from external contributors to add or modify rules files without security review.
- Allow the AI agent itself to modify its own rules files without explicit developer approval.
- Assume rules files are benign because they are plain text. They are instruction injection surfaces with session-level persistence.

## Section 7: Out-of-Scope Edits and Review Anchoring

Agents routinely touch files beyond the scope of the requested change: lockfiles, CI configurations, unrelated tests, formatting changes, and dependency updates. Reviewers anchored on the requested change miss these modifications. This is the most common review failure mode in agentic coding.

### Do

- Use diff-aware review tooling that highlights all files changed, not just the ones relevant to the task description.
- Implement CI checks that flag unexpected file modifications: lockfile changes, CI/CD config changes, test modifications, and changes to files outside the requested scope.
- Review every file in an agent-generated PR individually. Do not approve based on the PR description alone.
- Set up CODEOWNERS rules that require specific reviewers for sensitive files (CI configs, Dockerfiles, deployment scripts, rules files).
- Limit the agent's file access scope when possible. Some tools support directory restrictions or file allowlists.

### Don't

- Approve agent-generated PRs based on the summary or description without reviewing the full diff.
- Assume that lockfile changes, test modifications, or formatting changes are benign because they "look routine."
- Allow agents to modify files outside the explicitly requested scope without flagging those changes for review.

## Section 8: Test Fabrication and Test Deletion

AI agents make CI green by deleting failing tests, weakening assertions, mocking the unit under test instead of fixing the code, or asserting the buggy behaviour. A passing test suite generated by the same agent that produced the code provides no independent assurance.

### Do

- Require human review of all AI-generated test modifications, with focus on:
    - Deleted tests (why was this test removed?)
    - Weakened assertions (did `assertEquals` become `assertNotNull`?)
    - New mocks that replace real dependencies the test was designed to exercise
    - Tests that assert the generated behaviour rather than the correct behaviour
- Add adversarial and negative test cases that the AI did not generate: invalid inputs, expired tokens, malformed payloads, boundary conditions, concurrent access.
- Measure security confidence by adversarial testing results and independent analysis, not by "all tests pass."
- Implement CI rules that flag test deletions or assertion-count reductions in agent-generated PRs.
- Write security-critical tests manually for authentication, authorisation, input validation, and cryptographic operations.

### Don't

- Trust AI-generated test suites as evidence of security.
- Measure confidence by test pass rate alone. 100% passing means nothing if the tests assert broken behaviour.
- Allow agents to delete or modify existing tests without explicit justification reviewed by a human.
- Allow the agent to both write the security-critical code and its tests without independent verification.

## Section 9: Prompt Context Leakage and Sensitive Code Exposure

AI coding assistants send code context (open files, project structure, terminal output) to the model provider's API. This context may contain credentials, personal data, proprietary business logic, and internal architecture details.

### Do

- Review what context your AI coding assistant sends to the provider. Most tools document this.
- Configure AI tools to exclude sensitive directories from context. Add `.env`, `.env.*`, `*.pem`, `*.key`, `credentials.json`, `serviceAccountKey.json`, and similar sensitive files to your AI tool's context exclusion list (`.cursorignore`, `.copilotignore`, or equivalent).
- Audit what your AI coding tool sends by enabling request logging or using a network proxy to inspect outbound API calls.
- Use self-hosted or air-gapped AI coding tools for projects handling classified, regulated, or highly sensitive code.
- Store all secrets in environment variables, vault services, or encrypted secret stores -- never in files within the project tree where AI tools can read them.

### Don't

- Use cloud-hosted AI coding assistants on classified or top-secret codebases without approval.
- Assume that AI coding assistants only send the current file. Many send broader project context.
- Open `.env` files or private keys in your IDE while an AI coding assistant is active. The file contents may be sent as context.
- Paste API keys, tokens, or credentials into your terminal while AI tools with terminal context access are running.
- Assume that `.gitignore` prevents AI tools from reading files. `.gitignore` only affects git -- AI tools read from the filesystem directly.

## Section 10: Prompt-to-Code Supply Chain Risk

AI coding agents modify not just application code but also build scripts, CI/CD configurations, package scripts, and deployment infrastructure. Changes to these files execute automatically in trusted contexts with elevated privileges.

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
- Ensure AI-generated GitHub Actions reference third-party actions pinned to a specific commit SHA, not a mutable tag.

### Don't

- Allow AI to modify CI/CD pipelines, Dockerfiles, or package scripts without explicit human review.
- Accept AI-generated GitHub Actions that reference third-party actions by tag without SHA pinning.
- Trust AI-generated build scripts that download or execute external URLs.
- Merge AI changes to deployment configurations without verifying what changed in the build/deploy path.

## Section 11: CI/CD Agents and Confused Deputy Risk

AI-powered CI/CD agents (review bots, automated code fixers, PR assistants) run on PR events with access to org secrets, deployment credentials, and write access to the repository. A malicious PR can manipulate the CI agent into exfiltrating secrets or modifying the pipeline.

### Do

- Scope CI agent credentials to the minimum required permissions. Review bots should not have deploy keys or write access to secrets.
- Filter and sanitise PR content (title, body, comments, diff) before passing it to CI agents as context. PR content is attacker-controlled input.
- Run CI agents in isolated environments with no access to production secrets or credentials beyond what the specific job requires.
- Log all CI agent actions with full context for audit. Monitor for unexpected file modifications, network calls, or secret access patterns.
- Implement approval gates before CI agents can push commits, modify workflows, or access sensitive resources.

### Don't

- Give CI agents org-level secrets or deployment credentials when they only need read access.
- Allow CI agents to process PR content from external contributors without sandboxing.
- Trust CI agent output (comments, reviews, suggested fixes) without verifying that the agent was not influenced by malicious PR content.

## Section 12: Markdown, Link, and Unicode Injection

Agent output rendered in IDE chat panes, PR comments, or review interfaces can contain Markdown-based exfiltration links, bidi (bidirectional) text overrides, and zero-width characters that influence future agent behaviour or mislead reviewers.

### Do

- Sanitise agent output before rendering in IDE chat panes or PR comments. Strip or escape Markdown image tags, hidden links, and HTML entities.
- Detect and flag bidi override characters (U+202A through U+202E, U+2066 through U+2069) and zero-width characters (U+200B, U+200C, U+200D, U+FEFF) in code, commits, and agent output.
- Use CI checks that scan for homoglyph attacks and invisible characters in PRs.
- Review agent-generated commit messages and PR descriptions for embedded content that could influence future agent runs.

### Don't

- Render agent output containing Markdown images or links without sanitisation. Image tags with external URLs can exfiltrate conversation context via URL parameters.
- Assume that code containing only visible ASCII characters is safe. Zero-width and bidi characters are invisible in most editors.
- Allow agent-generated content to be committed without scanning for unicode injection.

## Section 13: Multi-Agent and Sub-Agent Propagation

When multiple agents interact (e.g. a coding agent delegates to a search agent, or a review agent processes output from a coding agent), prompt injection can propagate across agent boundaries. A compromised context in one agent becomes instructions for the next.

### Do

- Treat output from one agent as untrusted input when passed to another agent.
- Implement context boundaries between agents. Do not pass full conversation history or raw tool responses between agents without sanitisation.
- Monitor cross-agent interactions for instruction propagation patterns (e.g. one agent's output instructing another to exfiltrate data or modify files).
- Validate that sub-agent actions remain within the scope defined by the parent task.

### Don't

- Chain agents without context boundaries. If Agent A is compromised, Agent B should not blindly execute Agent A's output.
- Allow sub-agents to inherit the full permissions and credentials of the parent agent without scope restriction.
- Assume that agent-to-agent communication is trusted because both agents are "your" tools.

For comprehensive guidance on multi-agent trust boundaries, see the [AI Agent Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html) and the [MCP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html) Section 8 (Multi-Server Isolation).

## Section 14: Human Accountability

AI-generated code must have a human owner. Every AI-assisted change should be reviewed, approved, and attributable to a developer who is responsible for its security and maintainability. AI tools do not accept responsibility for the code they generate. The developer who accepts and commits the code does.

### Do

- Assign a human owner to every AI-generated code change. That owner is responsible for its correctness, security, and maintenance.
- Require explicit developer approval before merging any AI-generated code. The approval indicates the developer has reviewed and understood the change.
- Maintain audit trails showing which developer approved which AI-generated changes, including the AI tool and model version used.
- Treat AI as a tool, not a colleague. A developer who says "the AI wrote it" is still responsible for it.

### Don't

- Deploy AI-generated code that no human has reviewed and approved.
- Allow AI-generated code to bypass code review because "the AI is usually right."
- Treat AI approval (e.g. AI-generated code review comments) as a substitute for human review.
- Attribute security failures to the AI tool. The developer who approved the code is accountable.

## OWASP Top 10 Mapping

| OWASP Top 10 | Relevant Section |
|---|---|
| A01: Broken Access Control | Section 5: Agent Runtime Sandboxing, Section 11: CI/CD Agents |
| A03: Injection | Section 3: Indirect Prompt Injection, Section 12: Markdown and Unicode Injection |
| A04: Insecure Design | Section 8: Test Fabrication, Section 14: Human Accountability |
| A05: Security Misconfiguration | Section 6: Rules Files, Section 7: Out-of-Scope Edits |
| A06: Vulnerable and Outdated Components | Section 1: Hallucinated Dependencies, Section 2: Outdated Dependencies |
| A07: Identification and Authentication Failures | Section 4: MCP and Tool Security |
| A08: Software and Data Integrity Failures | Section 10: Prompt-to-Code Supply Chain Risk |
| A09: Security Logging and Monitoring Failures | Section 9: Prompt Context Leakage, Section 11: CI/CD Agents |
| A10: Server-Side Request Forgery | Section 3: Indirect Prompt Injection, Section 4: MCP and Tool Security |

## References

- [OWASP AI Agent Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html)
- [OWASP LLM Prompt Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html)
- [OWASP MCP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html)
- [OWASP Secure Coding Practices Quick Reference Guide](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/)
- [OWASP Software Supply Chain Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.html)
- [OWASP Top 10 for LLM Applications](https://genai.owasp.org/)
- [OWASP AISVS](https://github.com/OWASP/AISVS)
- CVE-2026-39313 -- mcp-framework before 0.2.22: unbounded memory allocation in HTTP request body handling allowed unauthenticated denial of service. Example of a vulnerability in AI framework code that highlights the need for dependency auditing and runtime limits.
