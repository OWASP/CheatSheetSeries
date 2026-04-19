# GitHub Actions Security Cheat Sheet

## Introduction

This cheat sheet provides guidance on securing GitHub Actions workflows, primarily for public GitHub repositories. The main goal is to prevent attacker-controlled code execution, which may lead to the following outcomes.

- **Secrets exfiltration.** CI/CD pipelines often use long-lived credentials to access external services (e.g., cloud provider credentials or package registry tokens). Such secrets can be exfiltrated (printing to logs, sending to external endpoints or embedding them in artifacts) via remote code execution.
- **Compromise of `GITHUB_TOKEN` with `write` permissions.** GitHub automatically provides each workflow run with a short-lived `GITHUB_TOKEN` that is scoped to the repository and has specific permissions. If this token is granted with `write` permissions and an attacker is able to exfiltrate or misuse the token, they could potentially modify repository contents, create or alter releases or interact with other GitHub resources.
- **GitHub Actions cache poisoning.** Workflows may reuse cached data across different workflow runs. If an attacker can inject malicious content into the cache and subsequent workflows (such as release pipelines) restore and use this cache, the poisoned data can be executed in a privileged context and potentially compromise the integrity of published release artifacts, obtain code execution in the privileged workflow and steal the production secrets.
- **Denial-of-wallet attacks.** CI/CD pipelines often integrate with paid external services, such as LLMs, for code review. If an attacker can repeatedly trigger pipelines or manipulate inputs to maximize resource consumption, this can lead to uncontrolled spending and financial impact.

## Treat your CI/CD pipeline as a critical production code

Because a CI/CD pipeline usually has access to sensitive credentials and functions/endpoints, it must be treated as a critical asset, potentially even more critical than the source code it processes.
Therefore, secure software development best practices must be applied, including (but not limited to): threat modeling, secure code reviews, security validation and penetration testing.

For deeper guidance and recommended practices, see:

- [NIST "Strategies for the Integration of Software Supply Chain Security in DevSecOps CI/CD Pipeline"](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-204D.pdf);
- [OWASP CI/CD Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/CI_CD_Security_Cheat_Sheet.html);
- [OWASP Secure Pipeline Verification Standard](https://owasp.org/www-project-spvs).

## Assume failure and have an incident response plan in place

Assume breaches will happen and design for rapid response. Define clear incident response procedures with roles, communication and escalation paths.
Continuously improve by actively learning from other incidents through publicly available post-mortems (e.g., [Trivy post-mortem](https://github.com/aquasecurity/trivy/discussions/10462), [Cline post-mortem](https://cline.bot/blog/post-mortem-unauthorized-cline-cli-npm)).

## Enable static analysis for GitHub Actions workflows

> [!IMPORTANT]
> CodeQL is freely available for open-source repositories on GitHub.
> Verify that CodeQL is enabled for your repositories and configured to scan GitHub Actions workflow files.
> CodeQL can be enabled via GitHub UI or by including a workflow file under `.github/workflows` folder:
>
> - If enabling via workflow, ensure that `language: actions` is included in the workflow.
> - If enabling via `Settings` → `Advanced Security` → `Code scanning` → `CodeQL analysis`, ensure that `GitHub Actions` appears under the Languages section.

- If available, enable [CodeQL](https://docs.github.com/en/code-security/reference/code-scanning/codeql/codeql-queries/actions-built-in-queries) `actions` scanning in your repositories to detect vulnerabilities in GitHub Actions workflows. In addition, use [Zizmor](https://docs.zizmor.sh/) for defense in depth. Periodically upgrade these tools, as new releases may contain updated detection rules.
- Configure these tools to run on every relevant pull request and mark them as required status checks before merging. At a minimum, block merges when high or critical severity issues are detected.
- Run comprehensive workflow scans on a scheduled basis (e.g., daily) and ensure that findings are tracked and remediated over time.
- If you need to enable scanning across several repositories, try to utilize a centralized reusable workflow or shared actions to standardize security practices (see this [Grafana example](https://github.com/grafana/shared-workflows/blob/main/.github/workflows/reusable-zizmor.yml)).

## Harden repository settings

> [!IMPORTANT]
> Please note that the `Require approval for first-time contributors` setting presents a security risk because an attacker can submit an initially legitimate-looking pull request
> (e.g., a typo fix) to gain trust and later submit subsequent PRs that introduce malicious changes which are executed in CI without requiring further approval.

- Enable the setting `Require approval for all external contributors` in the repository settings. This ensures that workflows triggered by pull requests from forks (i.e., users who are not members of the repository or organization) do not run automatically and therefore prevents untrusted code execution.
- Restrict default `GITHUB_TOKEN` permissions to `Read repository contents and packages permissions` in the repository settings. Explicitly grant additional permissions in the workflow file if required.
- Enforce strong branch protection rules. Configure branch protection to require pull request reviews, status checks, signed commits and `CODEOWNERS` approval before merging into protected branches. Tools such as the [OpenSSF Scorecard](https://github.com/ossf/scorecard-action) can help audit these settings.

## Restrict egress traffic from GitHub-hosted runners

Use solutions (e.g., [Harden-Runner](https://github.com/step-security/harden-runner)) to monitor and restrict egress traffic from GitHub-hosted runners to prevent secret exfiltration.

## Use self-hosted runners with extra caution

Self-hosted runners usually have access to internal networks and may cache credentials, secrets or store internal data.
Because they execute arbitrary code by design, they can be used by an attacker to establish persistent remote access and exfiltrate secrets.
In general, never use self-hosted runners with public repositories, as anyone who can fork the repository and open a pull request can potentially execute code on your runner.

If you use self-hosted runners for a public repository:

- Use standard secure software development best practices when enabling self-hosted runners (threat modeling, secure code reviews, security validation, penetration testing, patching and hardening).
- Use the `Require approval for all external contributors` option, review proposed changes and manually approve each workflow execution for all external contributors.
- Use ephemeral runners (e.g., container-based runners) and destroy the runner environment after each job execution to prevent persistence.
- Do not store sensitive data on runner machines, as any user who can invoke workflows has access to the runner environment.
- Restrict runner network access and avoid giving self-hosted runners access to sensitive infrastructure.

## Maintain curated shared workflows and actions

If you need to support several repositories, establish a centralized repository of curated, security-reviewed workflows/actions and reuse it across other repositories.

For a practical example, see [grafana/shared-workflows](https://github.com/grafana/shared-workflows).

## Prevent artifact poisoning

Artifact poisoning occurs when malicious or untrusted content is introduced into build artifacts, often via shared caches or previously stored dependencies
([GitHub Actions Cache Poisoning](https://adnanthekhan.com/2024/05/06/the-monsters-in-your-build-cache-github-actions-cache-poisoning)).
This can compromise the integrity of released software or lead to production secret exfiltration.
To reduce this risk, disable all forms of caching in release or publishing workflows to avoid reusing potentially compromised artifacts or exfiltrating production secrets.

## Be careful with AI assistant running in CI/CD pipeline

Sometimes, an AI assistant is used directly in workflows, e.g., to review pull requests or triage submitted issues.
This creates a risk of prompt injection attacks, where malicious input manipulates the AI assistant's behavior. If the workflow running the AI assistant has access to secrets or a `GITHUB_TOKEN` with `write` permissions and can be triggered by untrusted users (e.g., any GitHub account), this may lead to secret exfiltration or unauthorized actions.
A real-world example is the ["clinejection" attack](https://adnanthekhan.com/posts/clinejection/).

To mitigate potential attacks, limit AI assistant capabilities — only enable the minimum tools and actions required for task execution.

## Write Secure GitHub Workflows

This section contains some recommendations. In general, a static code analyzer (CodeQL, Zizmor) should report such issues.

### Avoid dangerous triggers

#### Avoid using the `pull_request_target` trigger

Workflows triggered by `pull_request_target` run in the context of the base (target) repository and have access to the `GITHUB_TOKEN` with `write` permissions and GitHub secrets available to the workflow.
If untrusted code from a PR is checked out and used, this may lead to code execution.
There are some common patterns, like labeling workflows where untrusted code is not checked out, but in general, try to avoid the `pull_request_target` trigger.

> [!IMPORTANT]
> Never check out (via `actions/checkout` or GitHub CLI) and run untrusted code in this context.

#### Avoid using the `workflow_run` trigger

The `workflow_run` trigger automates tasks based on the execution of other workflows and can grant access to the `GITHUB_TOKEN` with `write` permissions and GitHub secrets.
An attacker can modify triggering workflows via pull requests and cause privileged workflows to run.
Even if the initial workflow is unprivileged, the triggered one may execute with higher permissions, enabling privilege escalation.
Additionally, attackers can exploit artifact poisoning by injecting malicious files that downstream workflows use without verification, leading to potential code execution.
If you need to implement workflow chains, use `workflow_call` with reusable workflows instead.

#### Use `issue_comment` trigger with extra care

This trigger can automate workflows (e.g., end-to-end tests) in response to comments on issues or pull requests and can grant access to the `GITHUB_TOKEN` with `write` permissions and GitHub secrets.
Implementation may introduce a Time-of-Check to Time-of-Use (TOCTOU) issue, where an attacker can modify a pull request between comment approval and workflow execution to run malicious code.
Additionally, this trigger can bypass pull request approval mechanisms, allowing attackers to execute workflows without proper review.

To secure the implementation with the `issue_comment` trigger:

1. Check if the triggering actor meets authorization criteria, e.g., allow workflow execution only if it was triggered by a trusted member of the specific GitHub org.
2. Use the commit SHA in a comment that triggers the workflow: instead of using a `/ok-to-test` comment, design the workflow to accept `/ok-to-test(<trusted_sha_commit>)` and check out code only from `<trusted_sha_commit>` submitted by an authorized actor. This will help mitigate the checkout and execution of untrusted code.

Alternatively, consider replacing the `issue_comment` trigger with label-based triggers.
When using the `pull_request` trigger with the labeled event, `github.event.pull_request.head.sha` contains the latest commit SHA for the pull request.
Labels can only be applied by authorized users (i.e., GitHub accounts with write permissions), so the workflow does not need to implement additional authorization checks.
Additionally, since the event is triggered by a user with write permissions, the workflow can consume `GITHUB_TOKEN` with `write` permissions and required GitHub secrets.
The workflow should check out the code using the trusted commit SHA available via `github.event.pull_request.head.sha`, which reflects the state of the pull request at the time the label was applied.

> [!IMPORTANT]
> In general, never check out code using mutable references (e.g., pull request numbers or branch names) - always use immutable references such as a full commit SHA.

### Use third-party GitHub Actions and reusable workflows securely

#### Use third-party actions with caution

In general, try to minimize third-party actions usage, e.g., use the GitHub API in your workflows when possible to implement required logic.

While using third-party actions, verify the origin, check that the author is trusted and active, ensure that there are multiple active contributors.
Check that the code is stable and safe to use, and that the action does not require unnecessary permissions.

#### Always pin all action and reusable workflow versions with a commit hash and check for impostor commits

Check that the used commit belongs to the specified organization/repository. This will prevent dependency confusion attacks, as currently GitHub resolves the commit SHA,
finds a matching object and executes it regardless of which fork it originated from. This check can be automated with the Zizmor `impostor-commit` [rule](https://docs.zizmor.sh/audits/#impostor-commit).

#### Use automated dependency update tools

- Use tools such as Dependabot or Renovate to keep third-party GitHub Actions up to date.
- Configure a delay between a dependency release and its adoption (e.g., a few days). This helps avoid immediately pulling in newly published malicious or compromised versions, allowing time for the community to detect and report issues. To configure this, Dependabot has a `cooldown` [flag](https://docs.github.com/en/code-security/reference/supply-chain-security/dependabot-options-reference#cooldown), Renovate has a `minimumReleaseAge` [flag](https://docs.renovatebot.com/key-concepts/minimum-release-age/).

### Minimize `GITHUB_TOKEN` permissions

Always set `permissions: {}` at the workflow level to disable all permissions by default. Then, grant only the specific permissions needed at the job level.

### Require approval for deployments or publications to critical environments

Use [GitHub environments](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments) with required approval rules. Define a list of authorized accounts who must manually approve deployments to production or other critical environments before workflow execution.

### Sanitize user input

An attacker may submit a malicious payload via context (e.g., via PR title) that could cause remote execution.
To prevent injection, always use [intermediate environment variables](https://docs.github.com/en/actions/reference/security/secure-use#good-practices-for-mitigating-script-injection-attacks) to pass any context into `run:` and similar code execution blocks.
Although some input contexts may appear relatively safe, it is better to always follow this approach for consistency and security.

### Protect secrets used in workflows

#### Try to eliminate all static credentials from your workflows

Try to eliminate all static credentials (e.g., personal access tokens, static cloud keys) used in workflows. Migrate to OIDC-based short-lived authentication tokens ("Trusted publishing").
Currently, many major registries and cloud providers [support](https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments) this feature.

#### Secure handling of static credentials (if elimination is unavoidable)

If complete elimination cannot be achieved:

- Never hardcode secrets in workflow files.
- Pass secrets at the step level, not the job level.
- Prefer [environment-level secrets](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments) that are only accessible when a job targets a specific environment.
- Rotate secrets regularly.

#### Eliminate `secrets: inherit` while reusing workflows

When using the `inherit` keyword while invoking a reusable workflow, all the calling workflow’s secrets (organization, repository and environment secrets) are passed to the called workflow, even if the called workflow does not need them.
When you call a reusable workflow, explicitly pass each secret required by the called workflow.

#### Mask sensitive data

Mask all sensitive information that is not a GitHub secret by using `::add-mask::{value}`.
Masking a value prevents a string or variable from being printed in the log

#### Use secret scanning tools

Implement secret scanning in both pre-commit and pull request stages to prevent accidental exposure of sensitive data in the repository:

- Run secret scanning locally (e.g., via pre-commit hooks) to catch issues before code is committed.
- Enforce scanning in pull requests to detect and block any leaked secrets before merging.
- Automatically fail checks when potential secrets are detected to ensure remediation before proceeding.

#### `actions/checkout` should be used with `persist-credentials: false`

Unless needed for git operations, `actions/checkout` should be used with `persist-credentials: false`.
This prevents Git credentials from being persisted to the workflow's environment, reducing the risk of credential exposure if the workflow is compromised.

## References

- [Secure use reference](https://docs.github.com/en/actions/reference/security/secure-use)
- [Keeping your GitHub Actions and workflows secure Part 1: Preventing pwn requests](https://securitylab.github.com/resources/github-actions-preventing-pwn-requests)
- [Keeping your GitHub Actions and workflows secure Part 2: Untrusted input](https://securitylab.github.com/resources/github-actions-untrusted-input)
- [Keeping your GitHub Actions and workflows secure Part 3: How to trust your building blocks](https://securitylab.github.com/resources/github-actions-building-blocks)
- [Keeping your GitHub Actions and workflows secure Part 4: New vulnerability patterns and mitigation strategies](https://securitylab.github.com/resources/github-actions-new-patterns-and-mitigations)
- [Securing GitHub Actions Workflows](https://wellarchitected.github.com/library/application-security/recommendations/actions-security/)
