# Secrets Management Cheat Sheet

1. [Introduction](#1-Introduction)
2. [General Secrets Management](#2-General-Secrets-Management)
3. [Continuous Integration (CI) and Continuous Deployment (CD)](#3-Continuous-Integration-(CI)-and-Continuous-Deployment-(CD))
4. [Cloud Providers](#4-Cloud-Providers)
5. [Containers and Orchestration](#5-Containers-&-Orchestrators)
6. [Implementation](#6-Implementation)
7. [Encryption](#7-Encryption)
9. [Workflow in case of compromise](#9-Workflow-in-case-of-compromise)
11. [Secret detection](#10-Secret-detection)

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
Even when a company centralizes its secrets management to just one solution, you will often have to secure the master secret of that secrets management solution in a secondary secrets management solution. For instance, you can use a cloud provider's facilities to store secrets, but that cloud provider's root/management credentials need to be stored somewhere else.

Standardization should include Secrets life cycle management, Authentication, Authorization, and Accounting of the secrets management solution, and life cycle management. Note that it should be immediately apparent to an organization what a secret is used for and where to find it. The more Secrets management solutions you use, the more documentation you need.

### 2.3 Fine-Grained Access-Control List (ACL)

If required, the ability to configure access control on even the tiniest component of a system, such as an object in a data store, allows for granular access control. A Secrets management solution should cater for this level of configuration.

### 2.4 Remove Human Interaction and Use Least Privilege

When users can read the secret in a secret management system or update it, the secret can now leak through that user and the system he used to touch the secret.
Therefore, engineers shouldn't have access to all secrets in the secrets management system.
Manual maintenance does not only increase the risk of leakage; it introduces the risk of human errors while maintaining the secret. Furthermore, it can become wasteful.
Therefore, it is better to limit or remove the human interaction with the actual secrets. You can restrict human interaction in multiple ways:

- having a secrets pipeline that does large parts of the secret management (E.g. creation, rotation, etc.)
- Using dynamic secrets: these are generated for each request. When an application starts, it could request its database credentials, which will be provided with new credentials for that session when dynamically generated. You should use dynamic secrets to reduce the surface area of credential re-use. Should the application's database credentials be stolen, they would expire upon reboot.
- Using automation to rotate static secrets by other services and applications.

### 2.5 Auditing

Auditing is an essential part of secrets management due to the nature of the application. You must implement auditing securely to be resilient against attempts to tamper with or delete the audit logs. At a minimum, you should audit the following:

- Who requested a secret and for what system and role.
- Whether the secret request was approved or rejected.
- When the secret was used and by whom/source.
- When the secret has expired.
- Whether there were any attempts to re-use expired secrets.
- If there have been any authentication or authorization errors.
- When the secret was updated and by whom/what.
- Any administrative actions and possible user activity on the underlying supporting infrastructure stack.

It is essential that all auditing has correct timestamps. Therefore, the secret management solution should have proper time sync protocols set up at its supporting infrastructure. You should monitor the stack on which the solution runs for possible clock-skew and manual time adjustments.

### 2.6 Secret Lifecycle

Secrets follow a lifecycle. The stages of the lifecycle are as follows:

- Creation
- Rotation
- Revocation
- Expiration

#### 2.6.1 Creation

New secrets must be securely generated and cryptographically robust enough for their purpose. Secrets must have the minimum privileges assigned to them to enable their requested use/role.

You should transmit credentials securely, such that ideally, you don't send the password along with the username when requesting user accounts. Instead, you should send the password via a secure channel (e.g. mutually authenticated connection) or a side-channel such as push notification, SMS, email. Refer to the [Multi-Factor Authentication Cheat Sheet](cheat sheets/Multifactor_Authentication_Cheat_Sheet) to learn about the pros and cons of each channel.

Applications may not benefit from having multiple communication channels, so you must provision credentials securely.

See [the Open CRE project on secrets lookup](https://www.opencre.org/search/secret) for more technical recommendations on secret creation.

#### 2.6.2 Rotation

You should regularly rotate secrets so that any stolen credentials will only work for a short time. Regular rotation will also reduce the tendency for users to fall back to bad habits such as re-using credentials.

Depending on a secret's function and what it protects, the lifetime could be from minutes (think end-to-end encrypted chats with perfect forward secrecy) to years (consider hardware secrets).

#### 2.6.3 Revocation

When secrets are no longer required or potentially compromised, you must securely revoke them to restrict access. With (TLS) certificates, this also involves certificate revocation.

#### 2.6.4 Expiration

You should create secrets to expire after a defined time where possible. This expiration can either be active expiration by the secret consuming system, or an expiration date set at the secrets management system forcing supporting processes to be triggered, resulting in a secret rotation.
You should apply policies through the secrets management solution to ensure credentials are only made available for a limited time appropriate for the type of credentials. Applications should verify that the secret is still active before trusting it.

### 2.7 Transport Layer Security (TLS) Everywhere

Never transmit secrets via plaintext. In this day and age, there is no excuse given the ubiquitous adoption of TLS.

Furthermore, you can effectively use secrets management solutions to provision TLS certificates.

### 2.8 Automate Key Rotation

When implemented manually, key rotation is challenging and can lead to mistakes. It is, therefore, better to automate the rotation of keys or at least ensure that the process is sufficiently supported by IT.

Like data encryption keys, Rotating some keys might trigger fully or partially data re-encryption. Different strategies of rotating keys exist:

- Gradual rotation
- Introducing new keys for Write operations
- Leaving old keys for Read operations
- Rapid rotation
- Scheduled rotation
- and more...

### 2.9 Downtime, Break-glass, Backup and Restore

Consider the possibility that a secrets management service becomes unavailable for various reasons, such as scheduled downtime for maintenance. It could be impossible to retrieve the credentials required to restore the service if you did not previously acquire them. Thus, choose maintenance windows carefully based on earlier metrics and audit logs.

Next, the backup and restore procedures of the system should be regularly tested and audited for their security. A few requirements regarding backup & restore. Ensure that:

- Ensure an automated backup procedure is in place and executed periodically; base the frequency of the backups and snapshots on the number of secrets and their lifecycle;
- Frequently test restore procedures to guarantee that the backups are intact.
- Encrypt backups and put them on secure storage with reduced access rights. Monitor the backup location for (unauthorized) access and administrative actions.

Last, you should implement emergency ("break-glass") processes to restore the service if the system becomes unavailable for other reasons than regular maintenance. Therefore, emergency break-glass credentials should be regularly backed up securely in a secondary secrets management system and tested routinely to verify they work.

### 2.10 Policies

Consistently enforce policies defining the minimum complexity requirements of passwords and approved encryption algorithms at an organization-wide level. Using a centralized secrets management solution would help companies implement these policies.

Next, having an organization-wide secrets management policy can help enforce applying the best practices defined in this cheat sheet.

### 2.11 Metadata: prepare to move the secret

A secret management solution should provide the capability to store at least the following metadata about a secret:

- When it was created/consumed/archived/rotated/deleted
- Who created it (e.g., both the producer and the engineer using the production method)
- What created it
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
- As part of our secrets-management system: here you can store a secret in a secrets management system, such as facilities provided by a cloud provider ([AWS Secret Manager](https://aws.amazon.com/secrets-manager/), [Azure Key Vault](https://azure.microsoft.com/nl-nl/services/key-vault/)), or other third-party facilities ([Hashicorp Vault](https://www.vaultproject.io/), [Keeper](https://www.keepersecurity.com/), [Confidant](https://lyft.github.io/confidant/)). In this case, the CI/CD pipeline tooling requires credentials to connect to these secret management systems to have secrets in place.

Another alternative here is using the CI/CD pipeline to leverage the Encryption as a Service from the secrets management systems to do the encryption of a secret. The CI/CD tooling can then commit the encrypted secret to git, which can be fetched by the consuming service on deployment and decrypted again. See section 3.6 for more details.

Note: not all secrets must be at the CI/CD pipeline to get to the actual deployment. Instead, make sure that the deployed services take care of part of their secrets management at their own lifecycle (E.g. deployment, runtime and destruction).

#### 3.2.1 As part of your CI/CD tooling

When secrets are part of your CI/CD tooling, it means that these secrets are exposed to your CI/CD jobs. CI/CD tooling can comprise, e.g. GitHub secrets, GitLab repository secrets, ENV Vars/Var Groups in Microsoft Azure DevOps, Secrets, et cetera.
These secrets are often configurable/viewable by people who have the authorization to do so (e.g. a maintainer in GitHub, a project owner in GitLab, an admin in Jenkins, etc.). Which together lines up for the following best practices:

- No "big secret": ensure that secrets in your CI/CD tooling that are not long-term, don't have a prominent blast radius, and don't have a high value. Also, limit shared secrets (e.g. never have one password for all administrative users).
- IST/SOLL: have a clear overview of which users can view or alter the secrets. Often, maintainers of a GitLab/GitHub project can see or otherwise extract its secrets.
- Reduce the number of people that can perform administrative tasks on the project to limit exposure.
- Log & Alert: Assemble all the logs from the CI/CD tooling and have rules in place to detect secret extraction, or misuse, whether through accessing them through a web interface or dumping them while double base64 encoding or encrypting them with OpenSSL.
- Rotation: Regularly rotate secrets.
- Forking should not leak: Validate that a fork of the repository or copy of the job definition does not copy the secret.
- Document: Make sure you document which secrets you store as part of your CI/CD tooling and why so that you can migrate these easily when required.

#### 3.2.2 Storing it in a secrets management system

Naturally, you can store secrets in a designated secrets management solution. For example, you can use a solution offered by your (cloud) infrastructure provider, such as [AWS Secrets Manager](https://aws.amazon.com/secrets-manager/) [Google Secrets Manager](https://cloud.google.com/secret-manager) [Azure KeyVault](https://azure.microsoft.com/nl-nl/services/key-vault/). You can find more information about these in section 4 of this cheat sheet. Another option is a dedicated secrets management system, such as [Hashicorp Vault](https://www.vaultproject.io/), [Keeper](https://www.keepersecurity.com/), [Confidant](https://lyft.github.io/confidant/), [Cyberark Vault](https://www.cyberark.com/). Here are a few do's and don'ts from the CI/CD interaction with these systems. Make sure that the following is taken care of:

- Rotation/Temporality: credentials used by the CI/CD tooling to authenticate against the secret management system are rotated frequently and expire after a job completes.
- Scope of authorization: scope credentials used by the CI/CD tooling (e.g. roles, users, etc.), e.g. only authorize those secrets and services of the secret management system required for the CI/CD tooling to execute its job.
- Attribution of the caller: credentials used by the CI/CD tooling still hold attribution of the one calling the secrets management solution. Ensure you can attribute any calls made by the CI/CD tooling to a person or service that requested the actions of the CI/CD tooling. If this is not possible through the default configuration of the secrets manager, make sure that you have a correlation setup in terms of request parameters.
- All of the above: Still follow those do's and don'ts listed in section 3.2.1: log & alert, take care of forking, etc.
- Backup: back up secrets to product-critical operations in separate storage (f.e. cold storage), especially encryption keys.

#### 3.2.3 Not touched by CI/CD at all

Secrets do not necessarily need to be brought to a consumer of the secret by a CI/CD pipeline. It is even better when the consumer of the secret retrieves the secret. In that case, the CI/CD pipeline still needs to instruct the orchestrating system (e.g. [Kubernetes](https://kubernetes.io/)) that it needs to schedule a specific service with a given service account with which the consumer can then retrieve the required secret. The CI/CD tooling then still has credentials for the orchestrating platform but no longer has access to the secrets themselves. The do's and don'ts regarding these credentials types are similar to those described in section 3.2.2.

### 3.3 Authentication and Authorization of CI/CD tooling

CI/CD tooling should have designated service accounts, which can only operate in the scope of the required secrets or orchestration of the consumers of a secret. Additionally, a CI/CD pipeline run should be easily attributable to the one who has defined the job or triggered it to detect who has tried to exfiltrate secrets or manipulate them. When you use certificate-based auth, the caller of the pipeline identity should be part of the certificate. If you use a token to authenticate towards the mentioned systems, make sure that you set the principal requesting these actions (E.g. the user or the job creator).

Verify on a periodical basis whether this is (still) the case for your system so that you can do logging, attribution, and security alerting on suspicious actions effectively.

### 3.4 Logging and Accounting

CI/CD tooling can be used in various ways to extract secrets by an attacker: from using administrative interfaces, to job creation which exfiltrates the secret using double base64 encoding or encryption. Therefore, you should log every action which happens at a CI/CD tool. Security alerting rules should be defined at every non-standard manipulation of the pipeline tool and its administrative interface, to be able to monitor secret usage.
Logs should be at least queryable for 90 days and stored for a longer period on cold storage, as it might take security teams time to understand how a secret can be exfiltrated and/or manipulated with the CI/CD tooling.

### 3.5 Rotation vs Dynamic Creation

CI/CD tooling can be used to rotate secrets or instruct other components to do the rotation of the secret. For instance, the CI/CD tool can request a secrets management system, or another application to do the actual rotation of the secret by replacing the actual value with a new one. Alternatively, the CI/CD tool or another component could set up a dynamic secret: a secret required for a consumer to use for as long as it lives, after which the secret is invalidated when the consumer no longer lives. This reduces possible leakage of a secret, and allows for easy detection of misuse: if a secret is used anywhere else than from the IP of the consumer: then the secret is misused.

### 3.6 Pipeline Created Secrets

The pipeline tooling can be used to generate secrets and either offer them directly to the service which is deployed by the tooling, or provision the secret to a secrets management solution. Alternatively, the secret can be stored encrypted in git, so that the secret and its metadata is as close to the developer daily place of work as possible. This does require that developers cannot decrypt the secrets themselves and that every consumer of a secret has its encrypted variant of the secret. For instance: the secret should then be different per DTAP environment, and be encrypted with a different key. For each environment, only the designated consumer in that environment should be able to decrypt the specific secret. That way, a secret does not leak cross-environment and can still be easily stored next to the code.
Consumers of a secret could now decrypt the secret using a side-car, as described in section 5.2, where instead of retrieving the secrets, the consumer would leverage the side-car to do decryption of the secret.

When a pipeline  creates a secret itself, make sure that the scripts and/or binaries involved in the creation adhere to best practices for secret generation (e.g. secure-randomness, proper length of secret creation, etc.) and that the secret is created based on well-defined metadata which is stored somewhere in Git or somewhere else.

## 4 Cloud Providers

For cloud providers, there are at least four important topics to touch upon:

- Designated secret storage/management solutions. Which service(s) do you use?
- Envelope & client-side encryption
- Identity and access management: decreasing the blast radius
- API quotas or service limits

### 4.1 Services to Use

In any environment, it is best to use a designated secret management solution. Most cloud providers have at least one service that offers secret management. Of course, it's also possible to run a different secret management solution (e.g. HashiCorp Vault) on compute resources within the cloud, but we'll consider cloud provider service offerings in this section.

Sometimes it's possible to automatically rotate your secret, either via a service provided by your cloud provider or a (custom-built) function. Generally, the cloud provider's solution is preferred since the barrier of entry and risk of misconfiguration are lower. If you use a custom solution, ensure the role the function uses to do its rotation can only be assumed by said function.

#### 4.1.1 AWS

For AWS, the recommended solution is [AWS secret manager](https://docs.aws.amazon.com/secretsmanager/latest/userguide/intro.html).

Permissions are granted at the secret level. Check out the [Secrets Manager best practices](https://docs.aws.amazon.com/secretsmanager/latest/userguide/best-practices.html) for more information.

It is also possible to use the [Systems Manager Parameter store](https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-parameter-store.html), which is cheaper, but that has a few downsides:

- you'll need to make sure you've specified encryption yourself (secrets manager does that by default)
- it offers fewer auto-rotation capabilities (you will likely need to build a custom function)
- it doesn't support cross-account access
- it doesn't support cross-region replication
- there are fewer [security hub controls](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-standards-fsbp-controls.html) available

#### 4.1.2 GCP

For GCP, the recommended service is [Secret Manager](https://cloud.google.com/secret-manager/docs).

Permissions are granted at the secret level.

Check out the [Secret Manager best practices](https://cloud.google.com/secret-manager/docs/best-practices) for more information.

#### 4.1.3 Azure

For Azure, the recommended service is [Key Vault](https://docs.microsoft.com/en-us/azure/key-vault/).

Contrary to other clouds, permissions are granted at the _**Key Vault**_ level. This means secrets for separate workloads and separate sensitivity levels should be in separated Key Vaults accordingly.

Check out the [Key Vault best practices](https://docs.microsoft.com/en-us/azure/key-vault/general/best-practices) for more information.

### 4.2 Envelope & client-side encryption

Two considerations we want to deal with here are how the secret is encrypted and how the keys for that encryption can be managed in the cloud.

#### 4.2.1 Client-side encryption versus server-side encryption

Server-side encryption of secrets ensures that the cloud provider takes care of the encryption of the secret at storage. This means that the secret is safeguarded against compromise while being at rest. This often does not require any additional work, other than selecting the key to encrypt it with (See section 4.2.2). However: when the secret is submitted to another service to consume the secret, it will no longer be encrypted, as it is decrypted before submission to the intended service or human user with whom it should be shared.

Client-side encryption of secrets ensures that the secret remains encrypted until you actively decrypt it. This means it is encrypted at rest and while it arrives at the intended consumer until it is decrypted. This does mean that you need to have a proper cryptosystem to cater for this. Think about mechanisms such as PGP using a safe configuration and other more scalable and relatively easy to use systems. Client-side encryption can provide an end2end encryption of the secret: from producer till consumer.

#### 4.2.2 Bring Your Own Key versus Cloud Provider Key

When you encrypt a secret at rest, the question is: with which key do you want to do this? The less trust you have in the cloud provider, the more you will have to manage yourself.

Often, you can either encrypt a secret with a key managed at the secrets management service or use a key management solution from the cloud provider to encrypt the secret. The key offered through the key management solution of the cloud provider can be either managed by the cloud provider or by yourself. In the latter case, it is called "bring your own key"  (BYOK). This key can either be directly imported and/or generated at the key management solution or be created at the cloud HSM supported by the cloud provider.
Either your key or the customer master key from the provider is then used to encrypt the data key of the secrets management solution. The data key is then in turn used to encrypt the secret. This means that, by managing the CMK, you have control over the data key at the secrets management solution.

While importing your own key material can generally be done with all providers ([AWS](https://docs.aws.amazon.com/kms/latest/developerguide/importing-keys.html), [Azure](https://docs.microsoft.com/en-us/azure/key-vault/keys/byok-specification), [GCP](https://cloud.google.com/kms/docs/key-import)). Unless you know what you are doing and your threat model and/or policy require this, this is not a recommended solution.

### 4.3 Identity and Access Management (IAM)

IAM applies to both on-premise and cloud setups: to effectively manage secrets, you need to set up the right access policies and roles. This goes beyond setting up policies regarding who can access a secret and who can't, it should include hardening the full IAM setup, as it could otherwise allow for privilege escalation attacks. Make sure you never allow for open "pass role" privileges or open IAM creation privileges, as these can be used to use and/or create credentials that again have access to the secrets. Next, make sure you tightly control what can impersonate a service account: are your machines' roles accessible by an attacker exploiting your server? Can service roles from the data-pipeline tooling access the secrets easily? Make sure you include IAM for every cloud component in your threat model (e.g. ask yourself: how can you do elevation of privileges with this component?). See [this blog entry](https://xebia.com/ten-pitfalls-you-should-look-out-for-in-aws-iam/) for multiple do's and don'ts with examples.

Make sure that you leverage the temporality of the IAM principals effectively way: e.g. ensure that only certain roles and service accounts that require it can access the secrets. Monitor these accounts, so that you can tell who or what used them to access the secrets.

Next, make sure that you scope access to your secrets: one should not be simply allowed to access all secrets. In GCP and AWS, you can create fine-grained access policies to ensure that a principal cannot access all secrets at once. In Azure having access to the keyvault, means having access to all secrets in that Key Vault. This is why it is key to have separate key vaults when working on Azure to segregate access.

### 4.4 API limits

Cloud services can generally provide a limited amount of API calls over a given period. This means you could potentially (D)DoS yourself when you run into these limits. Most of these limits apply per account, project, or subscription, so limit your blast radius accordingly by spreading workloads. Additionally, some services may support data key caching, preventing load on the key management service API (see for example [AWS data key caching](https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/data-key-caching.html)). Some services can leverage built-in data key caching. [S3 is one such example](https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-key.html).

## 5 Containers & Orchestrators

There are various ways how containers can be enriched with secrets: at container build time (not recommended) and during orchestration/deployment.

### 5.1 Injection of Secrets (file, in-memory)

Ther are 3 ways to get secrets to an app inside a docker container

- Environment variables: We can provide secrets directly as part of the docker container configuration. Note that secrets themselves should never be hardcoded using docker ENV or docker ARG commands, as these can easily leak with the container definitions. See the Docker challenges at [WrongSecrets](https://github.com/commjoen/wrongsecrets) as well. Instead, let an orchestrator overwrite the environment variable with the actual secret and make sure that this is not hardcoded by itself.
- Mounted volumes (file): With this method, we keep our secrets within a particular config/secret file and mount that file to our instance as a mounted volume. Make sure that these mounts are mounted in by the orchestrator and never build in at container build time, as this will leak the secret with the container definition, instead: make sure that the orchestrator mounts in the volume when required.
- Fetch from the secret store (in-memory): A sidecar app/container fetches the secrets it need directly from a secret manager service without having to deal with docker config. This solution allows you to use dynamically constructed secrets without worrying about the secrets being viewable from the file system or from checking the docker container's env variables.

### 5.2 Short Lived Side-car Containers

To inject secrets into a container one could create short-lived side-car containers that fetch secrets from some remote endpoint and then store them on a shared volume which is also mounted to the original container. The original container can now use the secrets from mounted volume benefit of using this approach is that we don't need to integrate any third-party tool or code to get secrets. Once the secrets are fetched the sidecar container terminates that's why they are called short lived. An example of one such service is Vault Agent Sidecar Injector. The Vault Agent Injector alters pod specifications to include Vault Agent containers that render Vault secrets to a shared memory volume using Vault Agent Templates. By rendering secrets to a shared volume, containers within the pod can consume Vault secrets without being Vault aware.

### 5.3 Internal vs External Access

Secrets should only be exposed to internal communication mechanisms between the container and the deployment representation (E.g. a Kubernetes Pod), it should never be exposed through external access mechanisms which are shared among deployments and/or orchestrators (e.g. a shared volume).

When secrets are stored by the orchestrator (e.g. Kubernetes Secrets), make sure that the storage backend of the orchestrator is encrypted and keys are managed well.

## 6 Implementation Guidance

In this section, we discuss the implementation. Note that for the actual implementation it is better to always refer to the documentation of the secrets management system of choice as this will be better up to date than any secondary document such as this cheat sheet.

### 6.1 Key Material Management Policies

Key material management is discussed in the [Key management Secret cheat sheet](cheat sheets/Key_Management_Cheat_Sheet)

### 6.2 Dynamic vs Static Use Cases

We see the following use cases for dynamic secrets, amongst others:

- short living secrets (E.g. credentials and/or API keys) for a secondary service that expresses the intent for connecting the primary service (e.g. consumer) to the service.
- short-lived integrity and encryption controls for guarding and securing in-memory and runtime communication processes. Think of encryption keys that only need to live for a single session or a single deployment lifetime.
- short-lived credentials that are required to build a stack during the deployment of a service for interacting with the deployers and supporting infrastructure.

Note that these dynamic secrets often need to be created at the service/technology stack to which we need to connect. To create these types of dynamic secrets, we often need long term static secrets so that we can create the dynamic secrets themselves. Other static use cases:

- key materials that need to live longer than a single deployment due to the nature of their usage in the interaction with other instances of the same service (e.g. storage encryption keys, TLS PKI keys)
- key materials and/or credentials to connect to services that do not support creating temporal roles and/or credentials.

### 6.3 Ensure limitations are in place

Secrets should never be retrievable by everyone and everything. Always make sure that you put guardrails in place:

- Do you have the opportunity to create access policies? Make sure that there are policies in place to limit the number of entities that can read or write the secret. At the same time: make sure that the policies are written in such a way that they can easily be extended and are not too complicated to use.
- Is there no way to reduce access to certain secrets within a secrets management solution? Consider separating the production and development secrets from each other by having separate secret management solutions. Then, reduce access to the production secrets management solution.

### 6.4 Security Event Monitoring is Key

Always monitor who/what, from which IP, and with what methodology is accessing the secret. There are various patterns where you need to look out for, such as, but not limited to:

- Monitor who accesses the secret at the secret management system: is this normal behavior? So if the CI/CD credentials are used to access the secret management solution from a different IP than where the CI/CD system is running: provide a security alert and assume the secret compromised.
- Monitor the service requiring the secret (if possible), e.g., whether the user of the secret is actually coming from an expected IP, with an expected user agent. If not: alert and assume the secret is compromised.

### 6.5 Ease of Use

Ensure that the secrets management solution is easy to use, as you do not want people to work around it or use it not effectively due to complexity. This requires:

- Easy onboarding of new secrets and removal of invalidated secrets.
- Easy integration with the existing software: it should be easy to integrate applications as consumers of the secret management system. For instance: there should be an SDK available and/or a simple sidecar container to communicate with the secret management system so that existing software does not need heavy modification. Examples of this can be found in the AWS, Google and Azure SDKs which allows an application to interact with the secrets management solution of the cloud directly. Similar examples can be found with the Hashicorp Vault software integrations, as well as the Vault Agent Sidecar Injector.
- A clear understanding of the organization on why secrets management is important, and which processes need to be followed when it comes to handling secrets.

## 7 Encryption

Secrets Management goes hand in hand with encryption. After all: the secrets should be stored encrypted somewhere to protect their confidentiality and Integrity.

### 7.1 Encryption Types to Use

There are various encryption types to use when it comes to securing a secret, as long as they provide sufficient security, including sufficient resistance against quantum computing based attacks. Given that this is a moving field, it is best to take a look at sources like [keylength.com](https://www.keylength.com/en/4/), which enumerate up to date recommendations on the usage of encryption types and key lengths for existing standards, as well as the [OWASP Cryptographic Storage cheat sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html).
Note that post-quantum cryptography approaches are still in development at this time of writing. For this, it is best to keep an eye on [Nist Post Quantum Cryptography Standardization Page](https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization), which explains which future algorithms might be recommended in a post-quantum computing stage.

Please note that in all cases we need to preferably select an algorithm that provides encryption and confidentiality at the same time, such as AES-256 using GCM [(Gallois Counter Mode)](https://en.wikipedia.org/wiki/Galois/Counter_Mode). Or a mixture of ChaCha20 and Poly1305 according to the best practices in the field.

### 7.2 Convergent Encryption

[Convergent Encryption](https://en.wikipedia.org/wiki/Convergent_encryption) ensures that a given plaintext and its key results in the same ciphertext. This can help to detect possible re-use of secrets as this will result in the same ciphertext.
The challenge with enabling convergent encryption is that it allows for attackers who can use the system to generate a set of cryptographic strings that might end up in the same secret, which allows the attacker to derive the plain text secret. You can mitigate this risk if the convergent cryptosystem you use has sufficient resource challenges during encryption given the algorithm and key. Another factor that can help reduce the risk is ensuring that a secret needs to be of sufficient length, further hampering the possible guess-iteration time required.

### 7.3 Where to store the Encryption Keys?

You should not store keys next to the secrets they encrypt, except if those keys are encrypted themselves (see envelope encryption). Start by consulting the [OWASP Key
Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html) on where or how to store the encryption and possible HMAC keys.

### 7.4 Encryption as a Service (EaaS)

EaaS is a model in which users subscribe to a cloud-based encryption service without having to install encryption on their own systems. Using EaaS, you can get the following benefits:

- Encryption at rest
- Encryption in Transit (TLS)
- Key handling and cryptographic implementations are taken care of by Encryption Service, not by developers
- The provider could add more services to interact with the sensitive data

## 9 Workflow in Case of Compromise

(by @thatsjet)

### 9.1 Process

## 11 Secret detection

(by @thatsjet)

- Many native integrations possible (Cloud platforms, CI/CD tooling, application libraries, container orchestrators)
- Secret lifecycle (rotation, deletion, lifespan)
- Key material management (keys to the kingdom)
- Open source? (Depending on security posture)
- Encryption (at rest, in transit)
- Access control (fine-grained)
- Performance
- Audit logs
- Scalable (enterprise)
- Manageable operations (upgrading, recovery)
- Agnostic
- Support for many secrets backends: database, certificates, ssh keys, cloud providers, key/value, etc
- Dynamic secrets
- Encryption as a service
- Fine-grained policies (MFA requirements)
- Extensibility
- Documentation

## 12 Related Cheat Sheets & further reading

- [Key Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html)
- [Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [OWASP WrongSecrets project](https://github.com/commjoen/wrongsecrets/)
- [Blog: 10 Pointers on Secrets Management](https://xebia.com/blog/secure-deployment-10-pointers-on-secrets-management/)
- [Blog: From build to run: pointers on secure deployment](https://xebia.com/from-build-to-run-pointers-on-secure-deployment/)
- [Listing of possible secret management tooling](https://gist.github.com/maxvt/bb49a6c7243163b8120625fc8ae3f3cd)
- [Github listing on secrets detection tools](https://github.com/topics/secrets-detection)
- [OpenCRE References to secrets](https://www.opencre.org/search/secret)
- [NIST SP 800-57 Recommendation for Key Management](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)
