# Secrets Management Cheat Sheet

## 1 Introduction

Secrets are being used everywhere nowadays, especially with the popularity of the DevOps movement. Application Programming Interface (API) keys, database credentials, Identity and Access Management (IAM) permissions, Secure Shell (SSH) keys, certificates, etc. Many organizations have them hardcoded within the source code in plaintext, littered throughout configuration files and configuration management tools.

There is a growing need for organizations to centralize the storage, provisioning, auditing, rotation and management of secrets to control access to secrets and prevent them from leaking and compromising the organization. Often, services share the same secrets, which makes identifying the source of compromise or leak challenging.

This cheat sheet offers best practices and guidelines to help properly implement secrets management.

## 2 General Secrets Management

Secrets management relies on foundational principles spanning lifecycle governance, least-privilege access, automated rotation, and runtime memory protection to prevent credential compromise and limit breach impact.

### 2.1 High Availability

Secrets management systems sit on the critical path for both application availability and operational recovery. Latency or outages in secrets infrastructure degrade dependent services, delay application startup, and impede incident responders retrieving emergency credentials. Deploy secrets management solutions with clustering, multi-region replication, and automated failover capable of reliably serving production traffic and disaster-recovery operations.

### 2.2 Centralize and Standardize

Centralizing secrets storage reduces secret sprawl and enables uniform enforcement of lifecycle, access, and auditing policies. Where multi-cloud or hybrid architectures necessitate multiple specialized stores (such as cloud-native vaults alongside container secrets stores), standardize naming conventions, authentication mechanisms, and access patterns across platforms. Maintain clear documentation of secret ownership and purpose. The primary administrative and root credentials of the secrets management platform itself must be secured in an independent, secondary storage mechanism to prevent single points of administrative compromise.

### 2.3 Access Control

Enforce the principle of least privilege across all secrets infrastructure. Limit human and machine access using fine-grained, path-based access control policies scoped strictly to the specific secrets and operations required for each workload or operational role. Separate administrative roles managing the secrets platform from consumer roles reading credentials. Restrict and audit direct human access to production secrets, preferring automated delivery wherever possible.

### 2.4 Automate Secrets Management

Automating secret provisioning and rotation eliminates error-prone manual interventions and limits human exposure to plaintext credentials:

- **Automated Delivery Pipelines:** Integrate secrets provisioning into deployment pipelines and runtime orchestrators so secrets are delivered directly to workloads without manual extraction.
- **Dynamic Secrets:** Where supported by backing services (such as databases or cloud platforms), generate ephemeral credentials dynamically on demand for each workload session. Dynamic secrets significantly reduce the blast radius of credential theft. Configure short [lease durations](https://developer.hashicorp.com/vault/docs/concepts/lease) and explicitly revoke credentials when no longer needed; restarting a client process does not revoke credentials issued by the backing service.
- **Risk-Based Automated Rotation:** Implement automated rotation for static credentials and cryptographic keys to reduce the window of opportunity for exposed secrets. Rotation frequency should align with credential privilege, exposure surface, provider lease policies, and operational risk rather than an arbitrary calendar schedule. Automated rotation must be triggered immediately upon suspected compromise.

#### 2.4.1 Architectural Patterns for Automated Rotation

Automated rotation must update credentials without interrupting active workloads:

- **Dual-Credential Phased Rotation:** For services supporting multiple active credentials (such as API keys, cryptographic verification keys, or database accounts), introduce the new credential while maintaining the previous credential for verification or read operations. Once all clients transition to the new credential, decommission and revoke the old credential.
- **Orchestrated Multi-Step Rotation:** For target services supporting only one active credential per identity, automated rotation must execute an orchestrated, multi-step sequence rather than an immediate in-place overwrite. The rotation orchestrator (such as a cloud function or controller; see [Choosing a Secret Management Service](#41-choosing-a-secret-management-service)) creates a new pending credential, updates the target service to accept it, tests authentication against the service with the pending credential, and then promotes the pending credential to active before invalidating the prior version.

Sidecars and local agents (such as Vault Agent or Kubernetes secrets sidecars) serve as client delivery mechanisms that continuously fetch updated or refreshed secrets from the vault into local in-memory mounts without requiring application code changes or restarts (see [Short-Lived Sidecar Containers](#52-short-lived-sidecar-containers)).

### 2.5 Handling Secrets in Memory

Protecting secrets in memory minimizes the exposure window during which plaintext credentials reside in process memory. In-memory defenses protect against credential extraction from crash reports, core dumps, unencrypted swap or paging files, and unauthorized local process inspection. They cannot defend against an attacker with root or kernel access on the host; where untrusted host environments or hypervisors are part of the threat model, deploy hardware-isolated enclaves (see [Confidential Computing and Enclaves](#413-confidential-computing-and-enclaves)).

Implementation approaches depend on the runtime environment:

- **Unmanaged Runtimes (C/C++):** Use explicit secure zeroing functions (`memset_s()`, `explicit_bzero()`, `SecureZeroMemory()`) to overwrite memory buffers immediately after use, preventing compilers from optimizing away the zeroing operation as dead code.
- **Managed Runtimes (Java, .NET, Go):** Avoid immutable string types (`String`) for sensitive credentials, as they remain in the managed heap until garbage collection occurs and cannot be overwritten in place. Instead, store secrets in mutable primitive arrays (`char[]` or `byte[]`) and explicitly overwrite them (`Arrays.fill()`) immediately after consumption. However, developers must recognize that managed runtimes may create internal copies or relocate objects during garbage collection compaction, JIT compilation, or I/O operations without developer visibility, so reliable zeroization in managed environments cannot always be guaranteed.
- **Operating System Safeguards:** Disable core dumps (`RLIMIT_CORE` limits or setting the process non-dumpable flag) and lock sensitive memory pages where supported to prevent credentials from being flushed to unencrypted swap or crash artifacts.

For mobile and client-side memory testing methodologies, see [Testing Memory for Sensitive Data](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0011) from the OWASP MAS project.

### 2.6 Auditing

Comprehensive, tamper-resistant auditing of the secrets management system is essential for detecting unauthorized access, policy violations, and credential compromise. Audit logs must capture:

- Secret access requests, approvals, and rejections, recording the requesting identity, target resource, and role.
- Secret creation, updates, manual or automated rotations, and revocations.
- Authorization and authentication errors, abnormal access patterns, or attempts to access expired credentials.
- Administrative actions, policy modifications, and underlying infrastructure events.

Audit logs must use synchronized timestamps generated by secure time-synchronization protocols (such as authenticated NTP) to ensure reliable forensic reconstruction. Protect audit logs against unauthorized modification or deletion, and forward them promptly to a centralized, monitored log repository.

### 2.7 Secret Lifecycle

Secrets must be managed systematically across their operational lifecycle:

- **Creation:** Generate secrets using cryptographically secure pseudo-random number generators (CSPRNG) with sufficient entropy and appropriate key lengths for their cryptographic purpose. Scope newly created credentials to the minimum privileges required. For secret creation recommendations, see [the Open CRE project on secrets lookup](https://www.opencre.org/cre/223-780).
- **Distribution:** Provision secrets directly to authorized workloads over encrypted transport channels (TLS) or through platform injection mechanisms (such as in-memory volume mounts or environment configurations). Never transmit credentials across unencrypted or out-of-band channels like email or SMS.
- **Rotation:** Regularly rotate machine credentials and API keys through automated workflows to limit the validity window of compromised secrets. For human user passwords, follow [NIST recommendations](https://pages.nist.gov/800-63-FAQ/#q-b05) avoiding arbitrary periodic expiration without suspicion of compromise, as forced password changes prompt users to select predictable permutations.
- **Revocation:** Explicitly and immediately revoke secrets when they are no longer required, when associated workloads are decommissioned, or upon any suspicion of compromise. Certificate management must include corresponding certificate revocation workflows.
- **Expiration:** Enforce explicit validity bounds and time-to-live (TTL) leases on all issued credentials. Applications and consuming services should verify that a secret is currently active before accepting it, triggering renewal or automated rotation when approaching expiration.

### 2.8 Transport Layer Security (TLS) Everywhere

Never transmit secrets in plaintext. Enforce modern Transport Layer Security (TLS 1.2 or TLS 1.3) with forward secrecy (such as ECDHE cipher suites) and strict server certificate validation for all secrets management APIs and client connections. Prefer TLS 1.3 where supported, and explicitly prohibit deprecated protocols (SSL 3.0, TLS 1.0, TLS 1.1) and weak ciphers.

Where zero-trust architectures warrant cryptographic client identity verification at the transport layer, deploy Mutual TLS (mTLS). Otherwise, clients authenticate over server-authenticated TLS using OIDC tokens, platform IAM roles, or scoped API tokens. Secrets management solutions can also automate internal TLS certificate issuance, renewal, and revocation.

### 2.9 Downtime, Break-glass, Backup and Restore

Secrets management systems require robust business continuity and disaster-recovery procedures:

- **Automated Backups:** Execute periodic, automated backups of secrets stores and cryptographic configurations, calibrated to secret volume and update velocity.
- **Restoration Drills:** Regularly test backup restoration procedures in an isolated environment to verify backup integrity and validate recovery time objectives.
- **Secure Backup Storage:** Encrypt backups at rest, restrict storage access permissions, and monitor the backup location for unauthorized access attempts.
- **Break-Glass Emergency Access:** Maintain documented, audited emergency procedures to restore service if primary authentication or secrets services fail. Store emergency break-glass credentials in an independent, secondary secrets management system or secure offline custody to eliminate circular dependencies during disaster recovery, and routinely test break-glass access workflows.

### 2.10 Policies

Consistently enforce organization-wide policies defining approved encryption algorithms, key lengths, password complexity rules, and mandatory secrets lifecycle controls. Centralized secrets management solutions provide the technical enforcement mechanism to apply these policies uniformly across development, operational, and cloud environments.

### 2.11 Metadata: prepare to move the secret

A secrets management solution should track essential metadata for each managed secret:

- **Ownership and Contact:** Technical owner, responsible team, and designated emergency contact.
- **Purpose and Scope:** Consuming applications, target systems, environments, and business purpose.
- **Cryptographic Details:** Secret type (e.g., symmetric key, asymmetric key pair, database credential, API token) and algorithm parameters.
- **Lifecycle Timestamps:** Creation, last consumption, modification, archive, and scheduled rotation dates.

Structured metadata facilitates security audits, ownership transitions, automated rotation, and provider migrations to mitigate vendor lock-in.

### 2.12 Passwordless Authentication and Token Security

OpenID Connect (OIDC) lets an application delegate user authentication to an identity provider (IdP), instead of storing and verifying the user's password itself. It does not require passwordless authentication: [OpenID Connect Core Section 3.1.2.3](https://openid.net/specs/openid-connect-core-1_0.html#Authenticates) leaves the IdP's authentication method, including passwords, outside the protocol's scope.

OIDC alone does not eliminate phishing, credential stuffing, or weak passwords at the IdP. Choose an IdP that enforces appropriate authentication controls; for phishing resistance, require [phishing-resistant authentication](https://pages.nist.gov/800-63-4/sp800-63b/authenticators/#verifimpers), such as WebAuthn. See the [Multifactor Authentication Cheat Sheet](Multifactor_Authentication_Cheat_Sheet.md).

Federation still requires protecting issued tokens and any client credentials. Follow the [OAuth2 Cheat Sheet](OAuth2_Cheat_Sheet.md) for token transmission, storage, validation, expiration, and refresh-token protection. OIDC does not replace other application secrets, such as database credentials or API keys.

## 3 Continuous Integration (CI) and Continuous Deployment (CD)

Continuous Integration (CI) and Continuous Deployment (CD) tools frequently store secrets to configure applications or interact with secrets management systems during deployment. For general CI/CD pipeline hardening, runner isolation, and build-log masking, see the [CI/CD Security Cheat Sheet](CI_CD_Security_Cheat_Sheet.md). This section covers architectural patterns and controls for managing secrets accessed or delivered by pipelines.

### 3.1 Hardening your CI/CD pipeline

For guidance on securing CI/CD infrastructure, pipeline execution environments, and source control configurations, see the [CI/CD Security Cheat Sheet](CI_CD_Security_Cheat_Sheet.md) (specifically [Secure SCM Configuration](CI_CD_Security_Cheat_Sheet.md#secure-scm-configuration) and [Pipeline and Execution Environment](CI_CD_Security_Cheat_Sheet.md#pipeline-and-execution-environment)).

### 3.2 Where should a secret be?

When deploying applications, select a secret delivery model based on your environment's isolation and lifecycle requirements:

#### 3.2.1 As part of your CI/CD tooling

When secrets are part of your CI/CD tooling (such as GitHub secrets, GitLab repository secrets, Azure DevOps variable groups, or Jenkins credentials), they are exposed to pipeline jobs and project maintainers. When using tool-stored secrets:

- **Limit blast radius**: Avoid storing high-value, long-term, or widely scoped credentials in CI/CD variables; never share credentials across administrative users.
- **Review access permissions**: Maintain an overview of which users and roles can view or modify stored secrets, and review these permissions periodically.
- **Prevent fork leakage**: Validate that a repository fork or copied job definition does not expose or copy stored secrets.
- **Rotate regularly**: Establish a defined rotation schedule for secrets maintained within CI/CD tooling.
- **Document stored secrets**: Maintain documentation of which secrets are stored as part of your CI/CD tooling, including their purpose and ownership, to simplify audits and future migrations.

#### 3.2.2 Storing it in a secrets management system

Pipelines can retrieve credentials dynamically from a dedicated secrets manager (see [Cloud Providers](#4-cloud-providers)). When integrating pipelines with external secrets managers:

- **Avoid static bootstrap credentials**: Authenticate pipeline runners using short-lived OpenID Connect (OIDC) tokens and workload identity federation (see the [Workload Identity Federation Cheat Sheet](Workload_Identity_Federation_Cheat_Sheet.md)), eliminating static cloud access keys from the CI/CD platform.
- **Separate federation from secret access**: Token exchange establishes the workload's identity but does not automatically grant access to secrets. Separate the permission to exchange an OIDC token or impersonate an identity from distinct, least-privilege permissions required to access specific secrets for the active build or deployment stage.
- **Enforce job-scoped temporality**: Issue ephemeral, dynamic credentials with short time-to-live (TTL) leases. Stopping a runner or completing a build does not itself revoke issued credentials; credentials expire according to configured lease TTLs or must be explicitly revoked when no longer needed.
- **Preserve caller attribution**: Ensure requests from the CI/CD pipeline to the secrets manager can be attributed to the specific user, job trigger, or commit that initiated the pipeline run.

#### 3.2.3 Not touched by CI/CD at all

The recommended approach avoids passing application runtime secrets through the CI/CD pipeline entirely. The pipeline deploys the application with a platform identity (such as a Kubernetes service account or cloud IAM role), and the deployed service retrieves its own secrets directly from the secrets manager at runtime. This decouples build infrastructure from production application secrets.

### 3.3 Authentication and Authorization of CI/CD tooling

CI/CD service accounts must operate with least privilege, scoped strictly to the required secrets or deployment targets. Where supported, authenticate pipelines using workload identity federation (OIDC), exchanging the pipeline's signed ID token for short-lived credentials from the target secrets store or cloud provider. Ensure pipeline authentication preserves caller identity, such as by passing the triggering user, workflow identity, or job creator in token claims or certificates, so that secret access in external stores can be audited back to a specific initiator. Verify these attribution mappings periodically.

### 3.4 Logging and Accounting

Define security alerting rules to detect unauthorized access to or attempted exfiltration of secrets, such as anomalous secret retrieval, unexpected outbound network requests, or attempts to dump secrets to logs. Define CI/CD audit-log retention periods according to incident investigation requirements and applicable legal or regulatory compliance mandates. For general pipeline logging configuration, see [Visibility and Monitoring](CI_CD_Security_Cheat_Sheet.md#visibility-and-monitoring) in the CI/CD Security Cheat Sheet.

### 3.5 Rotation vs Dynamic Creation

Pipelines can trigger automated rotation or request dynamic, ephemeral credentials for deployment operations. When using dynamic secrets, bind credential lifecycles to the provider's [lease expiry or explicit revocation](https://developer.hashicorp.com/vault/docs/concepts/lease), as described in [3.2.2](#322-storing-it-in-a-secrets-management-system). Dynamic credentials significantly reduce the exposure window of deployment credentials and simplify misuse detection.

### 3.6 Pipeline Created Secrets

When pipelines generate secrets during deployment, they can register them directly with a secrets manager or commit asymmetrically encrypted secrets to Git (the GitOps pattern). For example, with [Sealed Secrets](https://github.com/bitnami-labs/sealed-secrets#sealed-secrets-for-kubernetes), the `kubeseal` CLI encrypts a Kubernetes Secret into a `SealedSecret` custom resource using the cluster's public key. The encrypted resource is committed to Git, and an in-cluster Sealed Secrets controller uses its private key to decrypt the resource and create the standard Kubernetes Secret. In a GitOps workflow, encrypt secrets using environment-specific keys so only the designated environment's controller can decrypt them. Any pipeline-generated secrets must use cryptographically secure random generation and appropriate key lengths.

## 4 Cloud Providers

For cloud providers, there are at least four essential topics to touch upon:

- Designated secret storage/management solutions. Which service(s) do you use?
- Envelope & client-side encryption
- Identity and access management: decreasing the blast radius
- API quotas or service limits

### 4.1 Choosing a Secret Management Service

When selecting a secret management solution in cloud environments, prioritize designated secret management services over general-purpose configuration stores. Key capabilities to evaluate and require:

- **Granular access control**: Support for fine-grained, least-privilege IAM policies scoped to individual secrets or secret versions rather than account-wide access.
- **Automated rotation support**: Native lifecycle hooks or integration with automated functions to rotate credentials periodically and on demand, enabling phased or dual-credential rotation patterns to minimize service disruption. Prefer native provider rotation when suitable. When custom rotation functions are required, ensure the function's privileged execution role can only be assumed by that rotation function.
- **Strong encryption at rest and in transit**: Enforced TLS for all API communication and robust encryption at rest, including support for customer-managed keys (CMK) when policy requires organizational control over root keys.
- **Centralized audit logging**: Comprehensive logging of secret creation, read, modification, and access attempts integrated with organizational audit trails and alerting.
- **Version tracking and recovery capabilities**: Support for secret versioning to safely deploy and rotate credentials, alongside rollback and recovery options to prevent accidental data loss.

#### 4.1.1 Native Cloud Provider Services

Major cloud providers offer native managed secrets services designed to integrate directly with their platform identity and access management (IAM) and centralized audit logging infrastructure. When operating primarily within a single cloud provider, using these native services helps reduce operational complexity compared to running self-managed vault instances. However, native services vary in their feature sets, encryption models, and automation support. Teams should evaluate each provider offering against their security and operational requirements, distinguishing dedicated secrets managers from general configuration stores that may lack built-in rotation or default encryption:

- **Amazon Web Services (AWS)**: [AWS Secrets Manager](https://docs.aws.amazon.com/secretsmanager/latest/userguide/intro.html) provides dedicated secrets storage, fine-grained IAM scoping, and automated rotation (see [AWS Secrets Manager best practices](https://docs.aws.amazon.com/secretsmanager/latest/userguide/best-practices.html)), contrasted with [AWS Systems Manager Parameter Store](https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-parameter-store.html) for general configuration.
- **Google Cloud Platform (GCP)**: [Google Cloud Secret Manager](https://cloud.google.com/secret-manager/docs) provides centralized secrets management with IAM-based access control and versioning (see [Google Cloud Secret Manager best practices](https://cloud.google.com/secret-manager/docs/best-practices)).
- **Microsoft Azure**: [Azure Key Vault](https://learn.microsoft.com/en-us/azure/key-vault/general/overview) provides centralized secrets, keys, and certificate storage with Azure RBAC integration (see [Azure Key Vault best practices](https://learn.microsoft.com/en-us/azure/key-vault/general/best-practices)).

#### 4.1.2 Hardware Security Modules (HSMs)

A [Hardware Security Module (HSM)](https://docs.aws.amazon.com/cloudhsm/latest/userguide/introduction.html) is a hardened, tamper-resistant physical device designed to securely generate, store, and manage cryptographic keys and perform cryptographic operations. HSMs protect cryptographic keys rather than managing application credential lifecycles, access leasing, or automated secret rotation; they complement, rather than replace, secrets management services. Cryptographic-module validation (such as FIPS 140 validation) and dedicated single-tenant custody are distinct requirements. For example, AWS KMS uses FIPS 140-validated HSMs in its [standard key stores](https://docs.aws.amazon.com/kms/latest/developerguide/key-store-overview.html). AWS KMS [custom key stores](https://docs.aws.amazon.com/kms/latest/developerguide/key-store-overview.html) support requirements for dedicated HSM control, but introduce additional operational complexity. A dedicated HSM is only warranted when explicit regulatory, contractual, or security policies mandate single-tenant hardware custody or direct cryptographic domain control, as dedicated HSM appliances introduce substantial management, clustering, and disaster-recovery overhead compared to standard key stores.

#### 4.1.3 Confidential Computing and Enclaves

Confidential computing and enclave technologies provide hardware-isolated execution environments to protect secrets in memory during processing. Isolation boundaries and threat models vary by platform architecture: while certain hardware-enforced memory-encryption models isolate workloads from host administrators and adjacent tenants, other enclave models rely on the platform hypervisor for partitioning and isolation. Never release secrets or decryption keys to an isolated environment until cryptographic attestation has been verified. The relying party or key management system must, in accordance with approved appraisal policies, cryptographically verify evidence of the approved workload's identity and configuration and ensure that the evidence is fresh. Nonce-based freshness verification can help prevent replay attacks. For architectural patterns separating attesters, verifiers, and relying parties, see [RFC 9334, Section 2.3: Confidential Data Protection](https://datatracker.ietf.org/doc/html/rfc9334#section-2.3).

#### 4.1.4 Other clouds, Multi-cloud, and Cloud agnostic

Managing secrets across multiple cloud providers introduces distinct operational and security challenges: disparate APIs, varying access control models, inconsistent rotation mechanisms, and fragmented audit logging across providers.

To address these challenges and avoid vendor lock-in, consider using a cloud-agnostic secrets management solution that can operate across all your cloud environments (and on-premises). A centralized, cloud-agnostic solution allows you to:

- Standardize security policies and access controls across different platforms using least-privilege principles.
- Automate key and secret rotation consistently across environments rather than maintaining separate per-provider workflows.
- Centralize audit logging and monitoring to detect secret extraction or abnormal access patterns across all clouds.

There are open-source and commercial solutions available. Some examples are:

- [CyberArk Conjur](https://www.conjur.org/)
- [HashiCorp Vault](https://www.vaultproject.io/)
- [Pulumi ESC](https://www.pulumi.com/esc/)

### 4.2 Envelope & client-side encryption

This section will describe how a secret is encrypted and how you can manage the keys for that encryption in the cloud.

#### 4.2.1 Client-side encryption versus server-side encryption

Server-side encryption of secrets ensures that the cloud provider takes care of the encryption of the secret in storage. The secret is then safeguarded against compromise while at rest. Encryption at rest often does not require additional work other than selecting the key to encrypt it with (See section 4.2.2). However, when you submit the secret to another service, it will no longer be encrypted. It is decrypted before sharing with the intended service or human user.

Client-side encryption of secrets ensures that the secret remains encrypted until you actively decrypt it. This means it is only decrypted when it arrives at the consumer. You need to have a proper crypto system to cater for this. Think about mechanisms such as PGP using a safe configuration and other more scalable and relatively easy to use systems. Client-side encryption can provide an end-to-end encryption of the secret: from producer to consumer.

#### 4.2.2 Bring Your Own Key versus Cloud Provider Key

When you encrypt a secret at rest, the question is: which key do you want to use? The less trust you have in the cloud provider, the more you will want to manage yourself.

Often, you can either encrypt a secret with a key managed at the secrets management service or use a key management solution from the cloud provider to encrypt the secret. The key offered through the key management solution of the cloud provider can be either managed by the cloud provider or by yourself. Industry standards call the latter "bring your own key" (BYOK). You can either directly import or generate this key at the key management solution or using cloud HSM supported by the cloud provider.
You can then either use your key or the customer main key from the provider to encrypt the data key of the secrets management solution. The data key, in turn, encrypts the secret. By managing the CMK, you have control over the data key at the secrets management solution.

While importing your own key material can generally be done with all providers ([AWS](https://docs.aws.amazon.com/kms/latest/developerguide/importing-keys.html), [Azure](https://docs.microsoft.com/en-us/azure/key-vault/keys/byok-specification), [GCP](https://cloud.google.com/kms/docs/key-import)), unless you know what you are doing and your threat model and policy require this, this is not a recommended solution due to its complexity and difficulty of use.

### 4.3 Identity and Access Management (IAM)

IAM applies to both on-premises and cloud setups: to effectively manage secrets, you need to set up suitable access policies and roles. Setting this up goes beyond policies regarding secrets; it should include hardening the full IAM setup, as it could otherwise allow for privilege escalation attacks. Ensure you never allow open "pass role" privileges or unrestricted IAM creation privileges, as these can use or create credentials that have access to the secrets. Next, make sure you tightly control what can impersonate a service account: are your machines' roles accessible by an attacker exploiting your server? Can service roles from the data-pipeline tooling access the secrets easily? Ensure you include IAM for every cloud component in your threat model (e.g., ask yourself: how can you do elevation of privileges with this component?). See [this blog entry](https://xebia.com/ten-pitfalls-you-should-look-out-for-in-aws-iam/) for multiple do's and don'ts with examples.

Leverage the temporality of the IAM principals effectively: e.g., ensure that only specific roles and service accounts that require it can access the secrets. Monitor these accounts so that you can tell who or what used them to access the secrets.

Next, make sure that you scope access to your secrets: one should not be simply allowed to access all secrets. In GCP and AWS, you can create fine-grained access policies to ensure that a principal cannot access all secrets at once. For Azure Key Vault, use the recommended [Azure RBAC permission model](https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-guide) with least-privilege roles. Azure RBAC supports role assignments at the scope of individual keys, secrets, and certificates for limited sharing scenarios, but Microsoft recommends [separate vaults per application and environment](https://learn.microsoft.com/en-us/azure/key-vault/general/secure-key-vault) as the primary security boundary.

### 4.4 API limits

Cloud services can generally provide a limited amount of API calls over a given period. You could potentially (D)DoS yourself when you run into these limits. Most of these limits apply per account, project, or subscription, so spread workloads to limit your blast radius accordingly. Additionally, some services may support data key caching, preventing load on the key management service API (see, for example, [AWS data key caching](https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/data-key-caching.html)). Some services can leverage built-in data key caching. [S3 is one such example](https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-key.html).

## 5 Containers & Orchestrators

You can enrich containers with secrets in multiple ways: build time (not recommended) and during orchestration/deployment.

### 5.1 Injection of Secrets (file, in-memory)

There are three ways to get secrets to an app inside a Docker container.

- Mounted volumes (file): With this method, we keep our secrets within a particular config/secret file and mount that file to our instance as a mounted volume. Ensure that these mounts are mounted in by the orchestrator and never built-in, as this will leak the secret with the container definition. Instead, make sure that the orchestrator mounts in the volume when required.
- Fetch from the secret store (in-memory): A sidecar app/container fetches the secrets it needs directly from a secret manager service without dealing with docker config. This solution allows you to use dynamically constructed secrets without worrying about the secrets being viewable from the file system or from checking the Docker container's environment variables.
- Environment variables: We can provide secrets directly as part of the Docker container configuration. Note: secrets themselves should never be hardcoded using docker ENV or docker ARG commands, as these can easily leak with the container definitions. See the Docker challenges at [WrongSecrets](https://github.com/OWASP/wrongsecrets) as well. Instead, let an orchestrator overwrite the environment variable with the actual secret and ensure that this is not hardcoded. Additionally, environment variables are generally accessible to all processes and may be included in logs or system dumps. Using environment variables is therefore not recommended unless the other methods are not possible.

### 5.2 Short-Lived Sidecar Containers

To inject secrets, you could create short-lived sidecar containers that fetch secrets from some remote endpoint and then store them on a shared volume mounted to the original container. The original container can now use the secrets from the mounted volume. The benefit of using this approach is that we don't need to integrate any third-party tool or code to get secrets. Once the sidecar has fetched the secrets, it terminates. Examples of this include [Vault Agent Sidecar Injector](https://developer.hashicorp.com/vault/docs/platform/k8s/injector) and [Conjur Secrets Provider](https://github.com/cyberark/secrets-provider-for-k8s). By mounting secrets to a volume shared with the pod, containers within the pod can consume secrets without being aware of the secrets manager.

### 5.3 Internal vs External Access

You should only expose secrets to communication mechanisms between the container and the deployment representation (e.g., a Kubernetes Pod). Never expose secrets through external access mechanisms shared among deployments or orchestrators (e.g., a shared volume).

When the orchestrator stores secrets (e.g., Kubernetes Secrets), make sure that the storage backend of the orchestrator is encrypted and you manage the keys well. See the [Kubernetes Security Cheat Sheet](Kubernetes_Security_Cheat_Sheet.md) for more information.

## 6 Implementation Guidance

In this section, we will discuss implementation. Note that it is always best to refer to the official documentation of the secrets management system of choice for the actual implementation as it will be more up to date than any secondary document such as this cheat sheet.

### 6.1 Key Material Management Policies

Key material management is discussed in the [Key Management Cheat Sheet](Key_Management_Cheat_Sheet.md)

### 6.2 Dynamic vs Static Use Cases

We see the following use cases for dynamic secrets, among others:

- short-lived secrets (e.g., credentials or API keys) for a secondary service that expresses the intent for connecting the primary service (e.g., consumer) to the service.
- short-lived integrity and encryption controls for guarding and securing in-memory and runtime communication processes. Think of encryption keys that only need to live for a single session or a single deployment lifetime.
- short-lived credentials for building a stack during the deployment of a service for interacting with the deployers and supporting infrastructure.

Note that these dynamic secrets often need to be created with the service we need to connect to. To create these types of dynamic secrets, we usually require long-term static secrets to create the dynamic secrets themselves. Other static use cases:

- key material that needs to live longer than a single deployment due to the nature of its usage in the interaction with other instances of the same service (e.g., storage encryption keys, TLS PKI keys)
- key material or credentials to connect to services that do not support creating temporal roles or credentials.

### 6.3 Ensure limitations are in place

Secrets should never be retrievable by everyone and everything. Always make sure that you put guardrails in place:

- Do you have the opportunity to create access policies? Ensure that there are policies in place to limit the number of entities that can read or write the secret. At the same time, write the policies so that you can easily extend them, and they are not too complicated to understand.
- Is there no way to reduce access to certain secrets within a secrets management solution? Consider separating the production and development secrets by having separate secret management solutions. Then, reduce access to the production secrets management solution.

### 6.4 Security Event Monitoring is Key

Continually monitor who/what, from which IP, and what methodology accesses the secret. There are various patterns to look out for, such as, but not limited to:

- Monitor who accesses the secret at the secret management system: is this normal behavior? If the CI/CD credentials are used to access the secret management solution from a different IP than where the CI/CD system is running, provide a security alert and assume the secret is compromised.
- Monitor the service requiring the secret (if possible), e.g., whether the user of the secret is coming from an expected IP, with an expected user agent. If not, alert and assume the secret is compromised.

### 6.5 Usability and Ease of Onboarding

For a secrets management solution to be effective, it must be easy for developers to adopt and use. If the process is too complex, developers may resort to insecure practices. A focus on usability and a smooth onboarding experience is critical.

- **Clear and Comprehensive Documentation:**
    - Provide clear, concise, and easy-to-find documentation. This should include tutorials for common use cases, detailed API references, and practical examples.
    - Maintain a "getting started" guide that walks new users through the process of obtaining their first secret.
- **Developer-Friendly Tooling and SDKs:**
    - Offer well-maintained SDKs for various programming languages to simplify integration.
    - Provide a command-line interface (CLI) that allows developers to manage secrets from their local development environment.
    - Develop plugins for common IDEs, CI/CD systems, and infrastructure-as-code (IaC) tools like Terraform and Pulumi.
- **Streamlined Workflows:**
    - Implement self-service workflows that enable developers to request and receive secrets with minimal manual intervention.
    - Use GitOps principles to manage secrets as code, allowing developers to define secret needs in a declarative manner alongside their application code.
    - Automate the approval process for low-risk secrets while maintaining appropriate controls for more sensitive ones.
- **Actionable Feedback and Support:**
    - Provide clear error messages that help developers troubleshoot issues independently.
    - Establish dedicated support channels (e.g., a Slack channel, a ticketing system) where developers can get help from the security or platform team.
- **Easy Integration:**
    - Ensure the secrets management solution can be easily integrated with existing applications. Sidecar containers, such as the [Vault Agent Sidecar Injector](https://developer.hashicorp.com/vault/docs/platform/k8s/injector) or the [Conjur Secrets Provider](https://github.com/cyberark/secrets-provider-for-k8s), can help decouple applications from the secrets management system.

## 7 Encryption

Secrets Management goes hand in hand with encryption. After all, secrets must be stored encrypted somewhere to protect their confidentiality and integrity.

### 7.1 Encryption Types to Use

You can use various encryption types to secure a secret as long as they provide sufficient security, including adequate resistance against quantum computing-based attacks. Given that this is a moving field, it is best to follow current recommendations such as [NIST SP 800-57 Part 1](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf), which lists comparable security strengths for algorithms and key lengths, and the time frames during which each strength is acceptable, as well as the NSA's [Commercial National Security Algorithm Suite 2.0](https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF) which enumerates quantum resistant algorithms.

Please note that in all cases, we need to preferably select an algorithm that provides encryption and confidentiality at the same time, such as AES-256 using GCM [(Galois Counter Mode)](https://en.wikipedia.org/wiki/Galois/Counter_Mode), or a mixture of ChaCha20 and Poly1305 according to the best practices in the field.

### 7.2 Convergent Encryption

[Convergent Encryption](https://en.wikipedia.org/wiki/Convergent_encryption) ensures that a given plaintext and its key results in the same ciphertext. This can help detect possible reuse of secrets, resulting in the same ciphertext.
The challenge with enabling convergent encryption is that it allows attackers to use the system to generate a set of cryptographic strings that might end up in the same secret, allowing the attacker to derive the plaintext secret. Given the algorithm and key, you can mitigate this risk if the convergent crypto system you use has sufficient resource challenges during encryption. Another factor that can help reduce the risk is ensuring that a secret is of adequate length, further hampering the possible guess-iteration time required.

### 7.3 Where to store the Encryption Keys?

You should not store keys next to the secrets they encrypt, except if those keys are encrypted themselves (see envelope encryption). Start by consulting the [Key Management Cheat Sheet](Key_Management_Cheat_Sheet.md) on where and how to store the encryption and possible HMAC keys.

### 7.4 Encryption as a Service (EaaS)

EaaS is a model in which users subscribe to a cloud-based encryption service without having to install encryption on their own systems. Using EaaS, you can get the following benefits:

- Encryption at rest
- Encryption in transit (TLS)
- Key handling and cryptographic implementations are taken care of by Encryption Service, not by developers
- The provider could add more services to interact with the sensitive data

## 8 Detection

There are many approaches to secrets detection and some very useful open-source projects to help with this. The [Yelp Detect Secrets](https://github.com/Yelp/detect-secrets) project is mature and has signature matching for around 20 secrets. For more information on other tools to help you in the detection space, check out the [Secrets Detection](https://github.com/topics/secrets-detection) topic on GitHub.

### 8.1 General detection approaches

Shift-left and DevSecOps principles apply to secrets detection as well. These general approaches below aim to consider secrets earlier and evolve the practice over time.

- Create standard test secrets and use them universally across the organization. This allows for reducing false positives by only needing to track a single test secret for each secret type.
- Consider enabling secrets detection at the developer level to avoid checking secrets into code before commit/PR either in the IDE, as part of test-driven development, or via pre-commit hook.
- Make secrets detection part of the threat model. Consider secrets as part of the attack surface during threat modeling exercises.
- Evaluate detection utilities and related signatures often to ensure they meet expectations.
- Consider having more than one detection utility and correlating/de-duping results to identify potential areas of detection weakness.
- Explore a balance between entropy and ease of detection. Secrets with consistent formats are easier to detect with lower false-positive rates, but you also don't want to miss a human-created password simply because it doesn't match your detection rules.

### 8.2 Types of secrets to be detected

Many types of secrets exist, and you should consider signatures for each to ensure accurate detection for all. Among the more common types are:

- High availability secrets (Tokens that are difficult to rotate)
- Application configuration files
- Connection strings
- API keys
- Credentials
- Passwords
- 2FA keys
- Private keys (e.g., SSH keys)
- Session tokens
- Platform-specific secret types (e.g., Amazon Web Services, Google Cloud)

For more fun learning about secrets and practice rooting them out, check out the [Wrong Secrets](https://owasp.org/www-project-wrongsecrets/) project.

### 8.3 Detection lifecycle

Secrets are like any other authorization token. They should:

- Exist only for as long as necessary (rotate often)
- Have a method for automatic rotation
- Only be visible to those who need them (least privilege)
- Be revocable (including the logging of attempt to use a revoked secret)
- Never be logged (must implement either an encryption or masking approach in place to avoid logging plaintext secrets)

Create detection rules for each of the stages of the secret lifecycle.

### 8.4 Documentation for how to detect secrets

Create documentation and update it regularly to inform the developer community on procedures and systems available at your organization and what types of secrets management you expect, how to test for secrets, and what to do in the event of detected secrets.

Documentation should:

- Exist and be updated often, especially in response to an incident
- Include the following information:
    - Who has access to the secret
    - How it gets rotated
    - Any upstream or downstream dependencies that could potentially be broken during secret rotation
    - Who is the point of contact during an incident
    - Security impact of exposure

- Identify when secrets may be handled differently depending on the threat risk, data classification, etc.

## 9 Incident Response

Quick response in the event of a secret exposure is perhaps one of the most critical considerations for secrets management.

### 9.1 Documentation

Incident response in the event of secret exposure should ensure that everyone in the chain of custody is aware and understands how to respond. This includes application creators (every member of a development team), information security, and technology leadership.

Documentation must include:

- How to test for secrets and secrets handling, especially during business continuity reviews.
- Whom to alert when a secret is detected.
- Steps to take for containment
- Information to log during the event

### 9.2 Remediation

The primary goal of incident response is rapid response and containment.

Containment should follow these procedures:

1. Revocation: Keys that were exposed should undergo immediate revocation. The secret must be able to be de-authorized quickly, and systems must be in place to identify the revocation status.
2. Rotation: A new secret must be able to be quickly created and implemented, preferably via an automated process to ensure repeatability, low rate of implementation error, and least-privilege (not directly human-readable).
3. Deletion: Secrets revoked/rotated must be removed from the exposed system immediately, including secrets discovered in code or logs. Secrets in code could have commit history for the exposure squashed to before the introduction of the secret, however, this may introduce other problems as it rewrites git history and will break any other links to a given commit. If you decide to do this be aware of the consequences and plan accordingly. Secrets in logs must have a process for removing the secret while maintaining log integrity.
4. Logging: Incident response teams must have access to information about the lifecycle of a secret to aid in containment and remediation, including:
    - Who had access?
    - When did they use it?
    - When was it previously rotated?

### 9.3 Logging

Additional considerations for logging of secrets usage should include:

- Logging for incident response should be to a single location accessible by incident response (IR) teams
- Ensure fidelity of logging information during purple team exercises such as:
    - What should have been logged?
    - What was actually logged?
    - Do we have adequate alerts in place to ensure this?

Consider using a standardized logging format and vocabulary such as the [Logging Vocabulary Cheat Sheet](Logging_Vocabulary_Cheat_Sheet.md) to ensure that all necessary information is logged.

## 10 Related Cheat Sheets & further reading

- [CI/CD Security Cheat Sheet](CI_CD_Security_Cheat_Sheet.md)
- [Key Management Cheat Sheet](Key_Management_Cheat_Sheet.md)
- [Logging Cheat Sheet](Logging_Cheat_Sheet.md)
- [Password Storage Cheat Sheet](Password_Storage_Cheat_Sheet.md)
- [Cryptographic Storage Cheat Sheet](Cryptographic_Storage_Cheat_Sheet.md)
- [OWASP WrongSecrets project](https://github.com/OWASP/wrongsecrets/)

## References

- [NIST SP 800-57 Part 1 Rev. 5: Recommendation for Key Management](https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final)
- [AWS Secrets Manager: Best practices](https://docs.aws.amazon.com/secretsmanager/latest/userguide/best-practices.html)
- [Azure Key Vault: Secure your secrets](https://learn.microsoft.com/en-us/azure/key-vault/secrets/secure-secrets)
- [Google Cloud Secret Manager](https://cloud.google.com/secret-manager)
- [CyberArk Conjur](https://www.conjur.org/)
- [HashiCorp Vault](https://www.vaultproject.io/)
