# Workload Identity Federation Cheat Sheet

## Introduction

Use workload identity federation instead of stored, long-lived cloud credentials for continuous integration and continuous deployment (CI/CD), when both platforms support it. This cheat sheet covers OpenID Connect (OIDC) federation for deployment jobs. It removes the need to keep a reusable cloud key in the pipeline, as described in [GitHub's OIDC overview](https://docs.github.com/en/actions/concepts/security/openid-connect). Manage secrets that cannot be replaced through the [Secrets Management Cheat Sheet](Secrets_Management_Cheat_Sheet.md).

Federation does not make a compromised job trustworthy. Code running in an authorized job can use its identity and credentials. Keep untrusted pull request code out of jobs that can obtain production access; apply the [CI/CD Security Cheat Sheet](CI_CD_Security_Cheat_Sheet.md) and, where applicable, the [GitHub Actions Security Cheat Sheet](GitHub_Actions_Security_Cheat_Sheet.md). See GitHub's explanation of [compromised runner risks](https://docs.github.com/en/actions/concepts/security/compromised-runners).

## Understand the Trust Boundary

The CI/CD platform issues a signed OIDC token describing the job. The job presents it to the cloud provider, which validates it against a configured trust policy before issuing temporary credentials. These may be access tokens or temporary access keys, depending on the provider. Use the provider's supported federation integration; do not implement a token validator in the pipeline. See the [Google Cloud deployment pipeline integration](https://docs.cloud.google.com/iam/docs/workload-identity-federation-with-deployment-pipelines).

A valid signature establishes who issued the token, not whether the job should have production access. Configure both controls:

- **Trust policy:** which external workloads may obtain credentials.
- **Permissions policy:** which resources and operations those credentials authorize. A tightly scoped trust policy does not compensate for an administrative deployment role. [AWS distinguishes the role's trust and permissions policies](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-idp_oidc.html).

## Restrict Which Jobs Are Trusted

- Configure the exact trusted issuer (`iss`), expected audience (`aud`), and allowed subject (`sub`) or equivalent workload attributes. The provider must validate the signature and token validity period as well as these restrictions. Use the actual claims issued for your job and the provider's documented matching rules; for example, [Microsoft Entra requires matching issuer, subject, and audience values](https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation-considerations).
- Restrict access to the intended organization, repository or project, and deployment context. Trusting a shared CI/CD issuer alone can admit other tenants. Prefer immutable, non-reusable organization and repository identifiers where supported, rather than names that another owner could acquire. [Google Cloud documents these tenant restrictions and identifier risks](https://docs.cloud.google.com/iam/docs/workload-identity-federation-with-deployment-pipelines).
- Allow only the required branches, environments, or workflows. Avoid wildcards that admit every repository or every job context. Verify which claims the cloud provider can actually enforce; a claim's presence in a token does not mean it is available as a policy condition. Follow the provider's integration documentation, such as [GitHub's AWS OIDC configuration guidance](https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments/oidc-in-aws).
- When trusting a deployment environment, protect who can use it and which branches or tags may deploy to it. For GitHub Actions, the default environment-based subject does not also contain the branch. Match the subject format configured for your repository and enforce the branch restriction through environment protection or another supported condition. See the [GitHub OIDC subject reference](https://docs.github.com/en/actions/reference/security/oidc).

## Limit Credential Exposure and Permissions

- Grant only the cloud operations and resources the deployment needs. Use separate identities and trust rules for production and non-production. Keep federation configuration and permission administration outside ordinary deployment roles to prevent a compromised job from widening its own access. See [Google Cloud's federation security practices](https://docs.cloud.google.com/iam/docs/best-practices-for-using-workload-identity-federation).
- Enable OIDC token requests only for jobs that need cloud access. In GitHub Actions, set `id-token: write` at the job level; it permits token requests and does not itself grant cloud permissions. See [GitHub's OIDC permission requirements](https://docs.github.com/en/actions/reference/security/oidc#workflow-permissions-for-the-requesting-the-oidc-token).
- Request the shortest credential lifetime the provider supports that meets the job's needs. Do not assume credentials expire when the job ends or when its OIDC token expires: issued cloud credentials have their own lifetime. For example, [AWS temporary credentials remain valid until expiry unless their access is disabled](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_control-access_disable-perms.html).
- Treat both the OIDC token and issued credentials as secrets: do not print them, place them in artifacts or caches, or pass them to unrelated jobs. After verifying migration, revoke the replaced static keys and remove pipeline copies so they cannot bypass the federation restrictions. Apply the [Secrets Management lifecycle guidance](Secrets_Management_Cheat_Sheet.md#27-secret-lifecycle).

## Verify and Monitor Access

Before production use, test the permitted deployment and verify that unauthorized repositories, branches, and job contexts cannot obtain production credentials. Confirm that the authorized job cannot access resources outside its assigned permissions. Repeat these checks after changes to trust policies, claim formats, or workflow configuration. Use the platform's documented claims, such as the [GitHub OIDC reference](https://docs.github.com/en/actions/reference/security/oidc), to select relevant cases.

Enable cloud audit events for token exchange and role or service account use. Check which identity fields are recorded and correlate them with CI/CD run records; complete workflow attribution is not automatic. For example, [Google Cloud requires enabling relevant data access logs and choosing an unambiguous subject mapping](https://docs.cloud.google.com/iam/docs/best-practices-for-using-workload-identity-federation#enable-data-access-logs). Alert on unexpected identities and changes to federation trust or permissions.

Prepare to stop new credential issuance and restrict already-issued credentials if a job is compromised. Removing a trust relationship alone is not a guarantee that existing sessions stop working. Follow the provider's incident procedure, such as [revoking AWS role session permissions](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_revoke-sessions.html), and account for policy propagation delays.

## References

- [GitHub: OpenID Connect reference](https://docs.github.com/en/actions/reference/security/oidc)
- [Google Cloud: Workload Identity Federation with deployment pipelines](https://docs.cloud.google.com/iam/docs/workload-identity-federation-with-deployment-pipelines)
- [AWS: Create a role for OpenID Connect federation](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-idp_oidc.html)
