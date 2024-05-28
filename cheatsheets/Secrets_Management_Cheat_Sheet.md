# Secrets Management Cheat Sheet

## 1 Introduction

Secrets are being used everywhere nowadays, especially with the popularity of the DevOps movement. Application Programming Interface (API) keys, database credentials, Identity and Access Management (IAM) permissions, Secure Shell (SSH) keys, certificates, etc. Many organizations have them hardcoded within the source code in plaintext, littered throughout configuration files and configuration management tools.

There is a growing need for organizations to centralize the storage, provisioning, auditing, rotation and management of secrets to control access to secrets and prevent them from leaking and compromising the organization. Often, services share the same secrets, which makes identifying the source of compromise or leak challenging.

This cheat sheet offers best practices and guidelines to help properly implement secrets management.

## 2 General Secrets Management

The following sections address the main concepts relating to secrets management.

### 2.1 High Availability

It is vital to select a technology that is robust enough to service traffic reliably:

- Users (e.g. SSH keys, root account passwords). In an incident response scenario, users expect to be provisioned with credentials rapidly, so they can recover services that have gone offline. Having to wait for credentials could impact the responsiveness of the operations team.
- Applications (e.g. database credentials and API keys). If the service is not performant, it could degrade the availability of dependent applications or increase application startup times.

Such a service could receive a considerable volume of requests within a large organization.

### 2.2 Centralize and Standardize

Secrets used by your DevOps teams for your applications might be consumed differently than secrets stored by your marketeers or your SRE team. You often find poorly maintained secrets where the needs of secret consumers or producers mismatch. Therefore, you must standardize and centralize the secrets management solution with care. Standardizing and centralizing can mean that you use multiple secret management solutions. For instance: your cloud-native development teams choose to use the solution provided by the cloud provider, while your private cloud uses a third-party solution, and everybody has an account for a selected password manager.
By making sure that the teams standardize the interaction with these different solutions, they remain maintainable and usable in the event of an incident.
Even when a company centralizes its secrets management to just one solution, you will often have to secure the primary secret of that secrets management solution in a secondary secrets management solution. For instance, you can use a cloud provider's facilities to store secrets, but that cloud provider's root/management credentials need to be stored somewhere else.

Standardization should include Secrets life cycle management, Authentication, Authorization, and Accounting of the secrets management solution, and life cycle management. Note that it should be immediately apparent to an organization what a secret is used for and where to find it. The more Secrets management solutions you use, the more documentation you need.

### 2.3 Access Control

When users can read the secret in a secret management system and/or update it, it means that the secret can now leak through that user and the system he used to touch the secret.
Therefore, engineers should not have access to all secrets in the secrets management system, and the Least Privilege principle should be applied. The secret management system needs to provide the ability to configure fine granular access controls on each object and component to accomplish the Least Privilege principle.

### 2.4 Automate Secrets Management

Manual maintenance does not only increase the risk of leakage; it introduces the risk of human errors while maintaining the secret. Furthermore, it can become wasteful.
Therefore, it is better to limit or remove the human interaction with the actual secrets. You can restrict human interaction in multiple ways:

- **Secrets pipeline:** Having a secrets pipeline which does large parts of the secret management (E.g. creation, rotation, etc.)
- **Using dynamic secrets:** When an application starts it could request it's database credentials, which when dynamically generated will be provided with new credentials for that session. Dynamic secrets should be used where possible to reduce the surface area of credential re-use. Should the application's database credentials be stolen, upon reboot they would be expired.
- **Automated rotation of static secrets:** Key rotation is a challenging process when implemented manually, and can lead to mistakes. It is therefore better to automate the rotation of keys or at least ensure that the process is sufficiently supported by IT.

Rotating certain keys, such as encryption keys, might trigger full or partial data re-encryption. Different strategies for rotating keys exist:

- Gradual rotation
- Introducing new keys for Write operations
- Leaving old keys for Read operations
- Rapid rotation
- Scheduled rotation
- and more...

### 2.5 Handling Secrets in Memory

An additional level of security can be achieved by minimizing the time window
where a secret is in memory and limiting the access to its memory space.

Depending on your application's particular circumstances, this can be difficult
to implement in a manner that ensures memory security. Because of this potential
implementation complexity, you are first encouraged to develop a threat model in order to clearly
surface your implicit assumptions about both your application's deployment environment as well
as understanding the capabilities of your adversaries.

Often attempting to protect secrets in memory will be considered overkill
because as you evaluate a threat model, the potential threat
actors that you consider either do not have the capabilities to carry out such attacks
or the cost of defense far exceeds the likely impact of a compromise arising from
exposing secrets in memory. Also, it should be kept in mind while developing an
appropriate threat model, that if an attacker already has access to the memory of
the process handling the secret, by that time a security breach may have already
occurred. Furthermore, it should be recognized that with the advent of attacks like
[Rowhammer](https://arxiv.org/pdf/2211.07613.pdf), or
[Meltdown and Spectre](https://meltdownattack.com/), it is important
to understand that the operating system alone is not sufficient to protect your process
memory from these types of attacks. This becomes especially important when your
application is deployed to the cloud. The only foolproof approach to protecting memory
against these and similar attacks to fully physically isolate your process memory from all other
untrusted processes.

Despite the implementation difficulties, in highly sensitive
environments, protecting secrets in memory can
be a valuable additional layer of security. For example, in scenarios where an
advanced attacker can cause a system to crash and gain access to a memory dump,
they may be able to extract secrets from it. Therefore, carefully safeguarding
secrets in memory is recommended for untrusted environments or situations where
tight security is of utmost importance.

Furthermore, in lower level languages like C/C++, it is relatively easy to protect
secrets in memory. Thus, it may be worthwhile to implement this practice even if
the risk of an attacker gaining access to the memory is low. On the other hand, for
programming languages that rely on garbage collection, securing secrets in memory
generally is much more difficult.

- **Structures and Classes:** In .NET and Java, do not use immutable structures
    such as Strings to store secrets, since it is impossible to force them to
    be garbage collected. Instead use primitive types such as byte arrays or
    char arrays, where the memory can be directly overwritten. You can also
    use Java's
    [GuardedString](https://docs.oracle.com/html/E28160_01/org/identityconnectors/common/security/GuardedString.html)
    or .NET's
    [SecureString](https://learn.microsoft.com/en-us/dotnet/api/system.security.securestring#string-versus-securestring)
    which are designed to solve precisely this problem.

- **Zeroing Memory:** After a secret has been used, the memory it occupied
  should be zeroed out to prevent it from lingering in memory where it could
  potentially be accessed.
    - If using Java's GuardedString, call the `dispose()` method.
    - If using .NET's SecureString, call the `Dispose()` method.

- **Memory Encryption:** In some cases, it may be possible to use hardware or
  operating system features to encrypt the entire memory space of the process
  handling the secret. This can provide an additional layer of security. For
  example, GuardedString in Java encrypts the values in memory, and SecureString
  in .NET does so on Windows.

Remember, the goal is to minimize the time window where the secret is in
plaintext in memory as much as possible.

For more detailed information, see
[Testing Memory for Sensitive Data](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0011)
from the OWASP MAS project.

### 2.6 Auditing

Auditing is an essential part of secrets management due to the nature of the application. You must implement auditing securely to be resilient against attempts to tamper with or delete the audit logs. At a minimum, you should audit the following:

- Who requested a secret and for what system and role.
- Whether the secret request was approved or rejected.
- When the secret was used and by whom/what.
- When the secret has expired.
- Whether there were any attempts to re-use expired secrets.
- If there have been any authentication or authorization errors.
- When the secret was updated and by whom/what.
- Any administrative actions and possible user activity on the underlying supporting infrastructure stack.

It is essential that all auditing has correct timestamps. Therefore, the secret management solution should have proper time sync protocols set up at its supporting infrastructure. You should monitor the stack on which the solution runs for possible clock-skew and manual time adjustments.

### 2.7 Secret Lifecycle

Secrets follow a lifecycle. The stages of the lifecycle are as follows:

- Creation
- Rotation
- Revocation
- Expiration

#### 2.7.1 Creation

New secrets must be securely generated and cryptographically robust enough for their purpose. Secrets must have the minimum privileges assigned to them to enable their required use/role.

You should transmit credentials securely, such that ideally, you don't send the password along with the username when requesting user accounts. Instead, you should send the password via a secure channel (e.g. mutually authenticated connection) or a side-channel such as push notification, SMS, email. Refer to the [Multi-Factor Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet) to learn about the pros and cons of each channel.

Applications may not benefit from having multiple communication channels, so you must provision credentials securely.

See [the Open CRE project on secrets lookup](https://www.opencre.org/cre/223-780) for more technical recommendations on secret creation.

#### 2.7.2 Rotation

You should regularly rotate secrets so that any stolen credentials will only work for a short time. Regular rotation will also reduce the tendency for users to fall back to bad habits such as re-using credentials.

Depending on a secret's function and what it protects, the lifetime could be from minutes (think end-to-end encrypted chats with perfect forward secrecy) to years (consider hardware secrets).

User credentials are excluded from regular rotating. These should only be rotated if there is suspicion or evidence that they have been compromised, according to [NIST recommendations](https://pages.nist.gov/800-63-FAQ/#q-b05).

#### 2.7.3 Revocation

When secrets are no longer required or potentially compromised, you must securely revoke them to restrict access. With (TLS) certificates, this also involves certificate revocation.

#### 2.7.4 Expiration

You should create secrets to expire after a defined time where possible. This expiration can either be active expiration by the secret consuming system, or an expiration date set at the secrets management system forcing supporting processes to be triggered, resulting in a secret rotation.
You should apply policies through the secrets management solution to ensure credentials are only made available for a limited time appropriate for the type of credentials. Applications should verify that the secret is still active before trusting it.

### 2.8 Transport Layer Security (TLS) Everywhere

Never transmit secrets via plaintext. In this day and age, there is no excuse given the ubiquitous adoption of TLS.

Furthermore, you can effectively use secrets management solutions to provision TLS certificates.

### 2.9 Downtime, Break-glass, Backup and Restore

Consider the possibility that a secrets management service becomes unavailable for various reasons, such as scheduled downtime for maintenance. It could be impossible to retrieve the credentials required to restore the service if you did not previously acquire them. Thus, choose maintenance windows carefully based on earlier metrics and audit logs.

Next, the backup and restore procedures of the system should be regularly tested and audited for their security. A few requirements regarding backup & restore. Ensure that:

- An automated backup procedure is in place and executed periodically; base the frequency of the backups and snapshots on the number of secrets and their lifecycle.
- Frequently test restore procedures to guarantee that the backups are intact.
- Encrypt backups and put them on secure storage with reduced access rights. Monitor the backup location for (unauthorized) access and administrative actions.

Lastly, you should implement emergency ("break-glass") processes to restore the service if the system becomes unavailable for reasons other than regular maintenance. Therefore, emergency break-glass credentials should be regularly backed up securely in a secondary secrets management system and tested routinely to verify they work.

### 2.10 Policies

Consistently enforce policies defining the minimum complexity requirements of passwords and approved encryption algorithms at an organization-wide level. Using a centralized secrets management solution can help companies implement these policies.

Next, having an organization-wide secrets management policy can help enforce applying the best practices defined in this cheat sheet.

### 2.11 Metadata: prepare to move the secret

A secret management solution should provide the capability to store at least the following metadata about a secret:

- When it was created/consumed/archived/rotated/deleted
- Who created/consumed/archived/rotated/deleted it (e.g. both the actual producer, and the engineer using the production method)
- What created/consumed/archived/rotated/deleted it
- Who to contact when having trouble with the secret or having questions about it
- For what the secret is used (E.g. designated intended consumers and purpose of the secret)
- What type of secret it is (E.g. AES Key, HMAC key, RSA private key)
- When you need to rotate it, if done manually

Note: if you don't store metadata about the secret nor prepare to move, you will increase the probability of vendor lock-in.

## 3 Continuous Integration (CI) and Continuous Deployment (CD)

Building, testing and deploying changes generally requires access to many systems. Continuous Integration (CI) and Continuous Deployment (CD) tools typically store secrets to provide configuration to the application or during deployment. Alternatively, they interact heavily with the secrets management system. Various best practices can help smooth out secret management in CI/CD; we will deal with some of them in this section.

### 3.1 Hardening your CI/CD pipeline

CI/CD tooling consumes (high-privilege) credentials regularly. Ensure that the pipeline cannot be easily hacked or misused by employees. Here are a few guidelines which can help you:

- Treat your CI/CD tooling as a production environment: harden it, patch it and harden the underlying infrastructure and services.
- Have Security Event Monitoring in place.
- Implement least-privilege access: developers do not need to be able to administer projects. Instead, they only need to be able to execute required functions, such as setting up pipelines, running them, and working with code. Administrative tasks can quickly be done using configuration-as-code in a separate repository used by the CI/CD system to update its configuration. There is no need for privileged roles that might have access to secrets.
- Make sure that pipeline output does not leak secrets, and you can't listen in on production pipelines with debugging tools.
- Make sure you cannot exec into any runners and workers for a CI/CD system.
- Have proper authentication, authorization and accounting in place.
- Ensure only an approved process can create pipelines, including MR/PR steps to ensure that a created pipeline is security-reviewed.

### 3.2 Where should a secret be?

There are various places where you can store a secret to execute CI/CD actions:

- As part of your CI/CD tooling: you can store a secret in [GitLab](https://docs.gitlab.com/charts/installation/secrets.html)/[GitHub](https://docs.github.com/en/actions/security-guides/encrypted-secrets)/[jenkins](https://www.jenkins.io/doc/developer/security/secrets/). This is not the same as committing it to code.
- As part of your secrets-management system: you can store a secret in a secrets management system, such as facilities provided by a cloud provider ([AWS Secret Manager](https://aws.amazon.com/secrets-manager/), [Azure Key Vault](https://azure.microsoft.com/nl-nl/services/key-vault/), [Google Secret Manager](https://cloud.google.com/secret-manager)), or other third-party facilities ([Hashicorp Vault](https://www.vaultproject.io/), [Conjur](https://www.conjur.org/), [Keeper](https://www.keepersecurity.com/), [Confidant](https://lyft.github.io/confidant/)). In this case, the CI/CD pipeline tooling requires credentials to connect to these secret management systems to have secrets in place. See [Cloud Providers](#4-cloud-providers) for more details on using a cloud provider's secret management system.

Another alternative here is using the CI/CD pipeline to leverage the Encryption as a Service from the secrets management systems to do the encryption of a secret. The CI/CD tooling can then commit the encrypted secret to git, which can be fetched by the consuming service on deployment and decrypted again. See section 3.6 for more details.

Note: not all secrets must be at the CI/CD pipeline to get to the actual deployment. Instead, make sure that the deployed services take care of part of their secrets management at their own lifecycle (E.g. deployment, runtime and destruction).

#### 3.2.1 As part of your CI/CD tooling

When secrets are part of your CI/CD tooling, it means that these secrets are exposed to your CI/CD jobs. CI/CD tooling can comprise, e.g. GitHub secrets, GitLab repository secrets, ENV Vars/Var Groups in Microsoft Azure DevOps, Kubernetes Secrets, etc.
These secrets are often configurable/viewable by people who have the authorization to do so (e.g. a maintainer in GitHub, a project owner in GitLab, an admin in Jenkins, etc.), which together lines up for the following best practices:

- No "big secret": ensure that secrets in your CI/CD tooling that are not long-term, don't have a wide blast radius, and don't have a high value. Also, limit shared secrets (e.g. never have one password for all administrative users).
- As is / To be: have a clear overview of which users can view or alter the secrets. Often, maintainers of a GitLab/GitHub project can see or otherwise extract its secrets.
- Reduce the number of people that can perform administrative tasks on the project to limit exposure.
- Log & Alert: Assemble all the logs from the CI/CD tooling and have rules in place to detect secret extraction, or misuse, whether through accessing them through a web interface or dumping them while double base64 encoding or encrypting them with OpenSSL.
- Rotation: Regularly rotate secrets.
- Forking should not leak: Validate that a fork of the repository or copy of the job definition does not copy the secret.
- Document: Make sure you document which secrets you store as part of your CI/CD tooling and why so that you can migrate these easily when required.

#### 3.2.2 Storing it in a secrets management system

Naturally, you can store secrets in a designated secrets management solution. For example, you can use a solution offered by your (cloud) infrastructure provider, such as [AWS Secrets Manager](https://aws.amazon.com/secrets-manager/), [Google Secrets Manager](https://cloud.google.com/secret-manager), or [Azure KeyVault](https://azure.microsoft.com/nl-nl/services/key-vault/). You can find more information about these in [section 4](#4-cloud-providers) of this cheat sheet. Another option is a dedicated secrets management system, such as [Hashicorp Vault](https://www.vaultproject.io/), [Keeper](https://www.keepersecurity.com/), [Confidant](https://lyft.github.io/confidant/), [Conjur](https://www.conjur.org/).
Here are a few do's and don'ts for the CI/CD interaction with these systems. Make sure that the following is taken care of:

- Rotation/Temporality: credentials used by the CI/CD tooling to authenticate against the secret management system are rotated frequently and expire after a job completes.
- Scope of authorization: scope credentials used by the CI/CD tooling (e.g. roles, users, etc.), only authorize those secrets and services of the secret management system required for the CI/CD tooling to execute its job.
- Attribution of the caller: credentials used by the CI/CD tooling still hold attribution of the one calling the secrets management solution. Ensure you can attribute any calls made by the CI/CD tooling to a person or service that requested the actions of the CI/CD tooling. If this is not possible through the default configuration of the secrets manager, make sure that you have a correlation setup in terms of request parameters.
- All of the above: Still follow those do's and don'ts listed in section 3.2.1: log & alert, take care of forking, etc.
- Backup: back up secrets to product-critical operations in separate storage (e.g. cold storage), especially encryption keys.

#### 3.2.3 Not touched by CI/CD at all

Secrets do not necessarily need to be brought to a consumer of the secret by a CI/CD pipeline. It is even better when the consumer of the secret retrieves the secret. In that case, the CI/CD pipeline still needs to instruct the orchestrating system (e.g. [Kubernetes](https://kubernetes.io/)) that it needs to schedule a specific service with a given service account with which the consumer can then retrieve the required secret. The CI/CD tooling then still has credentials for the orchestrating platform but no longer has access to the secrets themselves. The do's and don'ts regarding these credentials types are similar to those described in section 3.2.2.

### 3.3 Authentication and Authorization of CI/CD tooling

CI/CD tooling should have designated service accounts, which can only operate in the scope of the required secrets or orchestration of the consumers of a secret. Additionally, a CI/CD pipeline run should be easily attributable to the one who has defined the job or triggered it to detect who has tried to exfiltrate secrets or manipulate them. When you use certificate-based auth, the caller of the pipeline identity should be part of the certificate. If you use a token to authenticate towards the mentioned systems, make sure you set the principal requesting these actions (e.g. the user or the job creator).

Verify on a periodical basis whether this is (still) the case for your system so that you can do logging, attribution, and security alerting on suspicious actions effectively.

### 3.4 Logging and Accounting

Attackers can use CI/CD tooling to extract secrets. They could, for example, use administrative interfaces or job creation which exfiltrates the secret using encryption or double base64 encoding. Therefore, you should log every action in a CI/CD tool. You should define security alerting rules at every non-standard manipulation of the pipeline tool and its administrative interface to monitor secret usage.
Logs should be queryable for at least 90 days and stored for a more extended period in cold storage. It might take security teams time to understand how attackers can exfiltrate or manipulate a secret using CI/CD tooling.

### 3.5 Rotation vs Dynamic Creation

You can leverage CI/CD tooling to rotate secrets or instruct other components to do the rotation of the secret. For instance, the CI/CD tool can request a secrets management system or another application to rotate the secret. Alternatively, the CI/CD tool or another component could set up a dynamic secret: a secret required for a consumer to use for as long as it lives. The secret is invalidated when the consumer no longer lives. This procedure reduces possible leakage of a secret and allows for easy detection of misuse. If an attacker uses secret from anywhere other than the consumer's IP, you can easily detect it.

### 3.6 Pipeline Created Secrets

You can use pipeline tooling to generate secrets and either offer them directly to the service deployed by the tooling or provide the secret to a secrets management solution. Alternatively, the secret can be stored encrypted in git so that the secret and its metadata is as close to the developer's daily place of work as possible. A git-stored secret does require that developers cannot decrypt the secrets themselves and that every consumer of a secret has its encrypted variant of the secret. For instance: the secret should then be different per DTAP environment and be encrypted with another key. For each environment, only the designated consumer in that environment should be able to decrypt the specific secret. A secret does not leak cross-environment and can still be easily stored next to the code.
Consumers of a secret could now decrypt the secret using a sidecar, as described in section 5.2. Instead of retrieving the secrets, the consumer would leverage the sidecar to decrypt the secret.

When a pipeline creates a secret by itself, ensure that the scripts or binaries involved adhere to best practices for secret generation. Best practices include secure-randomness, proper length of secret creation, etc. and that the secret is created based on well-defined metadata stored somewhere in git or somewhere else.

## 4 Cloud Providers

For cloud providers, there are at least four essential topics to touch upon:

- Designated secret storage/management solutions. Which service(s) do you use?
- Envelope & client-side encryption
- Identity and access management: decreasing the blast radius
- API quotas or service limits

### 4.1 Services to Use

It is best to use a designated secret management solution in any environment. Most cloud providers have at least one service that offers secret management. Of course, it's also possible to run a different secret management solution (e.g. HashiCorp Vault or Conjur) on compute resources within the cloud. We'll consider cloud provider service offerings in this section.

Sometimes it's possible to automatically rotate your secret, either via a service provided by your cloud provider or a (custom-built) function. Generally, you should prefer the cloud provider's solution since the barrier of entry and risk of misconfiguration are lower. If you use a custom solution, ensure the function's role to do its rotation can only be assumed by said function.

#### 4.1.1 AWS

For AWS, the recommended solution is [AWS secret manager](https://docs.aws.amazon.com/secretsmanager/latest/userguide/intro.html).

Permissions are granted at the secret level. Check out the [Secrets Manager best practices](https://docs.aws.amazon.com/secretsmanager/latest/userguide/best-practices.html).

It is also possible to use the [Systems Manager Parameter store](https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-parameter-store.html), which is cheaper, but that has a few downsides:

- you'll need to make sure you've specified encryption yourself (secrets manager does that by default)
- it offers fewer auto-rotation capabilities (you will likely need to build a custom function)
- it doesn't support cross-account access
- it doesn't support cross-region replication
- there are fewer [security hub controls](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-standards-fsbp-controls.html) available

##### 4.1.1.1 AWS Nitro Enclaves

With [AWS Nitro Enclaves](https://aws.amazon.com/ec2/nitro/nitro-enclaves/), you can create trusted execution environments. Thus, no human-based access is possible once the application is running. Additionally, enclaves do not have any permanent storage attached to them. Therefore, secrets and other sensitive data stored on the nitro enclaves have an additional layer of security.

##### 4.1.1.2 AWS CloudHSM

For secrets being used in highly confidential applications, it may be needed to have more control over the encryption and storage of these keys. AWS offers [CloudHSM](https://aws.amazon.com/cloudhsm/), which lets you bring your own key (BYOK) for AWS services. Thus, you will have more control over keys' creation, lifecycle, and durability. CloudHSM allows automatic scaling and backup of your data. The cloud service provider, Amazon, will not have any access to the key material stored in Azure Dedicated HSM.

#### 4.1.2 GCP

For GCP, the recommended service is [Secret Manager](https://cloud.google.com/secret-manager/docs).

Permissions are granted at the secret level.

Check out the [Secret Manager best practices](https://cloud.google.com/secret-manager/docs/best-practices).

##### 4.1.2.1 Google Cloud Confidential Computing

[GCP Confidential Computing](https://cloud.google.com/confidential-computing) allows encryption of data during runtime. Thus, application code and data are kept secret, encrypted, and cannot be accessed by humans or tools.

#### 4.1.3 Azure

For Azure, the recommended service is [Key Vault](https://docs.microsoft.com/en-us/azure/key-vault/).

Contrary to other clouds, permissions are granted at the _**Key Vault**_ level. This means secrets for separate workloads and separate sensitivity levels should be in separated Key Vaults accordingly.

Check out the [Key Vault best practices](https://docs.microsoft.com/en-us/azure/key-vault/general/best-practices).

##### 4.1.3.1 Azure Confidential Computing

With [Azure Confidential Computing](https://azure.microsoft.com/en-us/solutions/confidential-compute/#overview), you can create trusted execution environments. Thus, every application will be executed in an encrypted enclave that protects the data and code consumed by the application is protected end-to-end. Furthermore, any application running inside enclaves is not accessible by any tool or human.

##### 4.1.3.2 Azure Dedicated HSM

For secrets being used in Azure environments and requiring special security considerations, Azure offers [Azure Dedicated HSM](https://azure.microsoft.com/en-us/services/azure-dedicated-hsm/). This allows you more control over the secrets stored on it, including enhanced administrative and cryptographic control. The cloud service provider, Microsoft, will not have any access to the key material stored in Azure Dedicated HSM.

#### 4.1.4 Other clouds, Multi-cloud, and Cloud agnostic

If you're using multiple cloud providers, you should consider using a cloud agnostic secret management solution. This will allow you to use the same secret management solution across all your cloud providers (and possibly also on-premises). Another advantage is that this avoids vendor lock-in with a specific cloud provider, as the solution can be used on any cloud provider.

There are open source and commercial solutions available. Some examples are:

- [CyberArk Conjur](https://www.conjur.org/)
- [HashiCorp Vault](https://www.vaultproject.io/)

### 4.2 Envelope & client-side encryption

This section will describe how a secret is encrypted and how you can manage the keys for that encryption in the cloud.

#### 4.2.1 Client-side encryption versus server-side encryption

Server-side encryption of secrets ensures that the cloud provider takes care of the encryption of the secret in storage. The secret is then safeguarded against compromise while at rest. Encryption at rest often does not require additional work other than selecting the key to encrypt it with (See section 4.2.2). However: when you submit the secret to another service, it will no longer be encrypted. It is decrypted before sharing with the intended service or human user.

Client-side encryption of secrets ensures that the secret remains encrypted until you actively decrypt it. This means it is only decrypted when it arrives at the consumer. You need to have a proper crypto system to cater for this. Think about mechanisms such as PGP using a safe configuration and other more scalable and relatively easy to use systems. Client-side encryption can provide an end-to-end encryption of the secret: from producer till consumer.

#### 4.2.2 Bring Your Own Key versus Cloud Provider Key

When you encrypt a secret at rest, the question is: which key do you want to use? The less trust you have in the cloud provider, the more you will want to manage yourself.

Often, you can either encrypt a secret with a key managed at the secrets management service or use a key management solution from the cloud provider to encrypt the secret. The key offered through the key management solution of the cloud provider can be either managed by the cloud provider or by yourself. Industry standards call the latter "bring your own key" (BYOK). You can either directly import or generate this key at the key management solution or using cloud HSM supported by the cloud provider.
You can then either use your key or the customer main key from the provider to encrypt the data key of the secrets management solution. The data key, in turn, encrypts the secret. By managing the CMK, you have control over the data key at the secrets management solution.

While importing your own key material can generally be done with all providers ([AWS](https://docs.aws.amazon.com/kms/latest/developerguide/importing-keys.html), [Azure](https://docs.microsoft.com/en-us/azure/key-vault/keys/byok-specification), [GCP](https://cloud.google.com/kms/docs/key-import)), unless you know what you are doing and your threat model and policy require this, this is not a recommended solution due to its complexity and difficulty of use.

### 4.3 Identity and Access Management (IAM)

IAM applies to both on-premise and cloud setups: to effectively manage secrets, you need to set up suitable access policies and roles. Setting this up goes beyond policies regarding secrets; it should include hardening the full IAM setup, as it could otherwise allow for privilege escalation attacks. Ensure you never allow open "pass role" privileges or unrestricted IAM creation privileges, as these can use or create credentials that have access to the secrets. Next, make sure you tightly control what can impersonate a service account: are your machines' roles accessible by an attacker exploiting your server? Can service roles from the data-pipeline tooling access the secrets easily? Ensure you include IAM for every cloud component in your threat model (e.g. ask yourself: how can you do elevation of privileges with this component?). See [this blog entry](https://xebia.com/ten-pitfalls-you-should-look-out-for-in-aws-iam/) for multiple do's and don'ts with examples.

Leverage the temporality of the IAM principals effectively: e.g. ensure that only specific roles and service accounts that require it can access the secrets. Monitor these accounts so that you can tell who or what used them to access the secrets.

Next, make sure that you scope access to your secrets: one should not be simply allowed to access all secrets. In GCP and AWS, you can create fine-grained access policies to ensure that a principal cannot access all secrets at once. In Azure, having access to the key vault means having access to all secrets in that key vault. It is, thus, essential to have separate key vaults when working on Azure to segregate access.

### 4.4 API limits

Cloud services can generally provide a limited amount of API calls over a given period. You could potentially (D)DoS yourself when you run into these limits. Most of these limits apply per account, project, or subscription, so spread workloads to limit your blast radius accordingly. Additionally, some services may support data key caching, preventing load on the key management service API (see for example [AWS data key caching](https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/data-key-caching.html)). Some services can leverage built-in data key caching. [S3 is one such example](https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-key.html).

## 5 Containers & Orchestrators

You can enrich containers with secrets in multiple ways: build time (not recommended) and during orchestration/deployment.

### 5.1 Injection of Secrets (file, in-memory)

There are three ways to get secrets to an app inside a docker container.

- Mounted volumes (file): With this method, we keep our secrets within a particular config/secret file and mount that file to our instance as a mounted volume. Ensure that these mounts are mounted in by the orchestrator and never built-in, as this will leak the secret with the container definition. Instead, make sure that the orchestrator mounts in the volume when required.
- Fetch from the secret store (in-memory): A sidecar app/container fetches the secrets it needs directly from a secret manager service without dealing with docker config. This solution allows you to use dynamically constructed secrets without worrying about the secrets being viewable from the file system or from checking the docker container's environment variables.
- Environment variables: We can provide secrets directly as part of the docker container configuration. Note: secrets themselves should never be hardcoded using docker ENV or docker ARG commands, as these can easily leak with the container definitions. See the Docker challenges at [WrongSecrets](https://github.com/OWASP/wrongsecrets) as well. Instead, let an orchestrator overwrite the environment variable with the actual secret and ensure that this is not hardcoded. Additionally, environment variables are generally accessible to all processes and may be included in logs or system dumps. Using environment variables is therefore not recommended unless the other methods are not possible.

### 5.2 Short Lived Side-car Containers

To inject secrets, you could create short-lived sidecar containers that fetch secrets from some remote endpoint and then store them on a shared volume mounted to the original container. The original container can now use the secrets from mounted volume. The benefit of using this approach is that we don't need to integrate any third-party tool or code to get secrets. Once the sidecar has fetched the secrets, it terminates. Examples of this inclue [Vault Agent Sidecar Injector](https://developer.hashicorp.com/vault/docs/platform/k8s/injector) and [Conjur Secrets Provider](https://github.com/cyberark/secrets-provider-for-k8s). By mounting secrets to a volume shared with the pod, containers within the pod can consume secrets without being aware of the secrets manager.

### 5.3 Internal vs External Access

You should only expose secrets to communication mechanisms between the container and the deployment representation (e.g. a Kubernetes Pod). Never expose secrets through external access mechanisms shared among deployments or orchestrators (e.g. a shared volume).

When the orchestrator stores secrets (e.g. Kubernetes Secrets), make sure that the storage backend of the orchestrator is encrypted and you manage the keys well. See the [Kubernetes Security Cheat Sheet](Kubernetes_Security_Cheat_Sheet.md) for more information.

## 6 Implementation Guidance

In this section, we will discuss implementation. Note that it is always best to refer to the official documentation of the secrets management system of choice for the actual implementation as it will be more up to date than any secondary document such as this cheat sheet.

### 6.1 Key Material Management Policies

Key material management is discussed in the [Key Management Cheat Sheet](Key_Management_Cheat_Sheet.md)

### 6.2 Dynamic vs Static Use Cases

We see the following use cases for dynamic secrets, amongst others:

- short-lived secrets (e.g. credentials or API keys) for a secondary service that expresses the intent for connecting the primary service (e.g. consumer) to the service.
- short-lived integrity and encryption controls for guarding and securing in-memory and runtime communication processes. Think of encryption keys that only need to live for a single session or a single deployment lifetime.
- short-lived credentials for building a stack during the deployment of a service for interacting with the deployers and supporting infrastructure.

Note that these dynamic secrets often need to be created with the service we need to connect to. To create these types of dynamic secrets, we usually require long term static secrets to create the dynamic secrets themselves. Other static use cases:

- key material that needs to live longer than a single deployment due to the nature of their usage in the interaction with other instances of the same service (e.g. storage encryption keys, TLS PKI keys)
- key material or credentials to connect to services that do not support creating temporal roles or credentials.

### 6.3 Ensure limitations are in place

Secrets should never be retrievable by everyone and everything. Always make sure that you put guardrails in place:

- Do you have the opportunity to create access policies? Ensure that there are policies in place to limit the number of entities that can read or write the secret. At the same time, write the policies so that you can easily extend them, and they are not too complicated to understand.
- Is there no way to reduce access to certain secrets within a secrets management solution? Consider separating the production and development secrets by having separate secret management solutions. Then, reduce access to the production secrets management solution.

### 6.4 Security Event Monitoring is Key

Continually monitor who/what, from which IP, and what methodology accesses the secret. There are various patterns where you need to look out for, such as, but not limited to:

- Monitor who accesses the secret at the secret management system: is this normal behavior? If the CI/CD credentials are used to access the secret management solution from a different IP than where the CI/CD system is running, provide a security alert and assume the secret compromised.
- Monitor the service requiring the secret (if possible), e.g., whether the user of the secret is coming from an expected IP, with an expected user agent. If not, alert and assume the secret is compromised.

### 6.5 Usability

Ensure that your secrets management solution is easy to use, as you do not want people to work around it or use it ineffectively due to complexity. This usability requires:

- Easy onboarding of new secrets and removal of invalidated secrets.
- Easy integration with the existing software: it should be easy to integrate applications as consumers of the secret management system. For instance, an SDK or simple sidecar container should be available to communicate with the secret management system so that existing software is decoupled and does not need extensive modification. You can find examples of this in the AWS, Google, and Azure SDKs. These SDKs allow an application to interact with the respective secrets management solutions. You can find similar examples in the HashiCorp Vault software integrations and the [Vault Agent Sidecar Injector](https://developer.hashicorp.com/vault/docs/platform/k8s/injector), as well as Conjur integrations and [Conjur Secrets Provider](https://github.com/cyberark/secrets-provider-for-k8s).
- A clear understanding of the organization of secrets management and its processes is essential.

## 7 Encryption

Secrets Management goes hand in hand with encryption. After all, secrets must be stored encrypted somewhere to protect their confidentiality and integrity.

### 7.1 Encryption Types to Use

You can use various encryption types to secure a secret as long as they provide sufficient security, including adequate resistance against quantum computing-based attacks. Given that this is a moving field, it is best to take a look at sources like [keylength.com](https://www.keylength.com/en/4/), which enumerate up to date recommendations on the usage of encryption types and key lengths for existing standards, as well as the NSA's [Commercial National Security Algorithm Suite 2.0](https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF) which enumerates quantum resistant algorithms.

Please note that in all cases, we need to preferably select an algorithm that provides encryption and confidentiality at the same time, such as AES-256 using GCM [(Gallois Counter Mode)](https://en.wikipedia.org/wiki/Galois/Counter_Mode), or a mixture of ChaCha20 and Poly1305 according to the best practices in the field.

### 7.2 Convergent Encryption

[Convergent Encryption](https://en.wikipedia.org/wiki/Convergent_encryption) ensures that a given plaintext and its key results in the same ciphertext. This can help detect possible re-use of secrets, resulting in the same ciphertext.
The challenge with enabling convergent encryption is that it allows attackers to use the system to generate a set of cryptographic strings that might end up in the same secret, allowing the attacker to derive the plain text secret. Given the algorithm and key, you can mitigate this risk if the convergent crypto system you use has sufficient resource challenges during encryption. Another factor that can help reduce the risk is ensuring that a secret is of adequate length, further hampering the possible guess-iteration time required.

### 7.3 Where to store the Encryption Keys?

You should not store keys next to the secrets they encrypt, except if those keys are encrypted themselves (see envelope encryption). Start by consulting the [Key Management Cheat Sheet](Key_Management_Cheat_Sheet.md) on where and how to store the encryption and possible HMAC keys.

### 7.4 Encryption as a Service (EaaS)

EaaS is a model in which users subscribe to a cloud-based encryption service without having to install encryption on their own systems. Using EaaS, you can get the following benefits:

- Encryption at rest
- Encryption in transit (TLS)
- Key handling and cryptographic implementations are taken care of by Encryption Service, not by developers
- The provider could add more services to interact with the sensitive data

## 8 Detection

There are many approaches to secrets detection and some very useful open source projects to help with this. The [Yelp Detect Secrets](https://github.com/Yelp/detect-secrets) project is mature and has signature matching for around 20 secrets. For more information on other tools to help you in the detection space, check out the [Secrets Detection](https://github.com/topics/secrets-detection) topic on GitHub.

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

For more fun learning about secrets and practice rooting them out check out the [Wrong Secrets](https://owasp.org/www-project-wrongsecrets/) project.

### 8.3 Detection lifecycle

Secrets are like any other authorization token. They should:

- Exist only for as long as necessary (rotate often)
- Have a method for automatic rotation
- Only be visible to those who need them (least privilege)
- Be revokable (including the logging of attempt to use a revoked secret)
- Never be logged (must implement either an encryption or masking approach in place to avoid logging plaintext secrets)

Create detection rules for each of the stages of the secret lifecycle.

### 8.4 Documentation for how to detect secrets

Create documentation and update it regularly to inform the developer community on procedures and systems available at your organization and what types of secrets management you expect, how to test for secrets, and what to do in event of detected secrets.

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

- [Key Management Cheat Sheet](Key_Management_Cheat_Sheet.md)
- [Logging Cheat Sheet](Logging_Cheat_Sheet.md)
- [Password Storage Cheat Sheet](Password_Storage_Cheat_Sheet.md)
- [Cryptographic Storage Cheat Sheet](Cryptographic_Storage_Cheat_Sheet.md)
- [OWASP WrongSecrets project](https://github.com/OWASP/wrongsecrets/)
- [Blog: 10 Pointers on Secrets Management](https://xebia.com/blog/secure-deployment-10-pointers-on-secrets-management/)
- [Blog: From build to run: pointers on secure deployment](https://xebia.com/from-build-to-run-pointers-on-secure-deployment/)
- [Github listing on secrets detection tools](https://github.com/topics/secrets-detection)
- [NIST SP 800-57 Recommendation for Key Management](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)
- [OpenCRE References to secrets](https://opencre.org/cre/223-780)
