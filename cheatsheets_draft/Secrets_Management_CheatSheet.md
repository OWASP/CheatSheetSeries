# Secrets Management Cheatsheet

1. [Introduction](#1-Introduction)
1. [General](#2-General-Secrets-Management)
1. [Continuous Integration (CI) and Continuous Deployment (CD)](#3-Continuous-Integration-(CI)-and-Continuous-Deployment-(CD))
1. [Cloud Providers](#4-Cloud-Providers)
1. [Containers and Orchestration](#5-Containers-&-Orchestrators)
1. [Implementation](#6-Implementation)
1. [Encryption](#7-Encryption)
1. [Applications](#8-Applications)
1. [Workflow in case of compromise](#9-Workflow-in-case-of-compromise)
1. [Secrets Management Tooling](#10-Secrets-Management-Tooling-Guidelines)

## 1. Introduction

Secrets are being used everywhere nowadays, especially with the popularity DevOps movement. Application Programming Interface (API) keys, database credentials, Identity and Access Management (IAM) permissions, Secure Shell (SSH) keys, certificates, etc. Many organizations have them hard coded in plaintext within the source code, littered throughout configuration files and configuration management tools.

There is a growing need for organisations to centralise the storage, provisioning, auditing, rotation and management of secrets in order to control access to and prevent secrets from leaking and compromising the organization. Most of the time, services share the same secrets that make identifying the source of compromise or leak very challenging.

This cheat sheet offers best practices and guidelines to help implement secrets management properly.

## 2. General Secrets Management

The following sections address the main concepts relating to secrets management.

### 2.1 High Availability

It is important to select a technology that is robust enough to reliably service traffic from:

- Users (e.g. SSH keys, root account passwords). In an incident response scenario users expect to be provisioned with credentials rapidly, so they can recover services that have gone offline. Having to wait for credentials could impact the responsiveness of the operations team.
- Applications (e.g. database credentials and API keys). If the service is not preferment it could degrade the availability of dependent applications or increase application startup times.

Within a large organisation such a service could receive a huge volume of requests.

### 2.2 Centralize and Standardize

Secrets used by your DevOps teams for your applications might be consumed differently, then secrets stored by your marketeers or your SRE team. When consumers and/or producers of a secret are not catered to their needs, you often find the secret badly maintained within the organization. Therefore, it is key that you standardize and centralize the secrets management solution. This can still mean that you centralize to multiple secret management solutions. For instance: your cloud native development teams choose to use the solution provided by the cloud provider, while your private cloud uses a third party solution, and everybody has an account for a selected password manager.
By making sure that the teams standardize the interaction with these different solutions, they remain maintainable and usable in the event of an incident.
Even when a company centralizes its secrets management to just one solution, you will still often have to secure the master secret of that secrets management solution in a secondary secrets management solution. For instance: a cloud provider its facilities can be used to store secrets, but then the root/master credentials of that cloud provider need to be stored somewhere else.

Standardization should at least include: secrets life cycle management, Authentication, Authorization, and Accounting of the secrets management solution, and life cycle management of the secrets management solution itself. Note that it should be immediately clear to an organization where a secret is used for and where to find it. The more places are used for secrets management, the more evident it is to have some documentation across the various secret management solutions to identify which solution is responsible for which (group of) of secrets.

### 2.3 Fine Grained Access-Control List (ACL)

The ability to configure access control on even the tiniest component of a system, such as an object in a data store, if required allows for granular access control. A secrets management solution should cater for this level of configuration.

### 2.4 Remove Human Interaction and Use Least Privilege

When users can actually read the secret in a secret management system and/or update it, it means that the secret can now leak through that user, as well as through the system he used to touch the secret.
Therefore, it is best that engineers do not have access to all secrets in the secrets management system.
Manually maintenance does not only increase the risk of leakage, it introduces the risk of human errors while maintaining the secret. Furthermore, it can become wasteful.
Therefore it is better to limit or remove the human interaction with the actual secrets. This can be done in multiple ways:

- having a secrets pipeline which does large parts of the secret management (E.g. creation, rotation, etc.)
- Using dynamic secrets: these are generated for each request. When an application starts it could request it's database credentials, which when dynamically generated will be provided with new credentials for that session. Dynamic secrets should be used where possible to reduce the surface area of credential re-use. Should the application's database credentials be stolen, upon reboot they would be expired.
- Using automation to rotate static secrets by other services and applications.

### 2.5 Auditing

Auditing is an important role of secrets management due to the nature of the application. Auditing must be implemented in a secure way so as to be resilient against attempts to tamper with or delete the audit logs. At minimum the following should be audited:

- Who requested a secret and for what system and role.
- Whether the secret request was approved or rejected.
- When the secret was used and by whom/source.
- When the secret has expired.
- If any attempts to re-use expired expired secrets have been made.
- If there have been any authentication or authorization errors.
- When the secret was updated and by whom/what.
- Any administrative actions and possible user activity on the underlying supporting infrastructure stack.

It is important that all auditing is correctly timestamped, therefore, the secret management solution should have proper time sync protocols setup at its supporting infrastructure. The stack on which the solution runs, should be monitored for possible clock-skew and/or manual time adjustments.

### 2.6 Secret Lifecycle

Secrets follow a lifecycle. The stages in the lifecycle are as follows:

- Creation
- Rotation
- Revocation

#### 2.6.1 Creation

New secrets must be securely generated and cryptographically robust enough for their purpose. Secrets must have the minimum privileges assigned to them to enable their requested use/role.

Credentials should be transmitted in a secure way, such that ideally the password would not be transmitted along with the username when requesting user accounts. Instead, the password should be transmitted via a side-channel such as SMS.

Applications may not benefit from having multiple channels for communication and so credentials must be provisioned in a secure way.

#### 2.6.2 Rotation

Secrets should be regularly rotated so that any stolen credentials will only work for a short period of time. This will also reduce the tendency for users to fall bac to bad-habits such as re-using credentials.

#### 2.6.3 Revocation

When secrets are no longer required they must be securely revoked in order to restrict access. With certificates such as SSL certificates this also involves certificate revocation.

#### 2.6.4 Lifespan

Secrets should, where ever possible, always be created to expire after a defined time. This can either be an active expiration by the secret consuming system, or an expiration date set at the secrets management system, forcing supporting processes to be triggered resulting in a rotation of the secret.

Policies should be applied by the secrets management solution to ensure credentials are only made available for a limited time that is appropriate for the type of credential.

### 2.7 Transport Layer Security (TLS) Everywhere

It goes without saying that no secrets should ever be transmitted via plaintext. There is no excuse in this day and age given the ubiquitous adoption of SSL/TLS to not use encryption to protect the secrets in transit.

Furthermore secrets management solutions can be used to effectively provision SSL certificates.

### 2.8 Automate Key Rotation

Key rotation is a challenging process when implemented manually, and can lead to mistakes. It is therefor highly recommended to automate the rotation of keys or at least ensure that the process is sufficiently supported by IT.

### 2.9 Downtime, Break-glass, Backup and Restore

Consideration must be made for the possibility that a secrets management service could become unavailable. This could be due to various reasons, such as scheduled down-time for maintenance. In that case it could be impossible to retrieve the credentials required to restore the service if they were not previously acquired. This means that possible downtime windows need to be chosen carefully based on earlier metrics and/or audit-logs. You can best give short downtime to the system at a time when its secrets are often not updated and/or retrieved.

Next, the backup and restore procedures of the system should be regularly tested, and audited for their security. A few requirements regarding backup & restore. Ensure that:

- An automated backup procedure is in place and executed periodically; the frequency of the backup/snapshot should be based on the amount of secrets, and their lifecycle;
- Restore procedures are tested frequently, in order to guarantee that the backups are intact.
- Backups are encrypted on a secure storage with reduced access rights. The backup location should be monitored for (unauthorized) access and administrative actions.

LAst, should the system become unavailable due to other reasons than normal maintenance, emergency break-glass processes should be implemented to restore the service. Emergency break-glass credentials therefore should be regularly backed up in a secure fashion in a secondary secrets management system, and tested routinely to verify they work.

### 2.10 Policies

Policies defining the minimum complexity requirements of passwords, as well as approved encryption algorithms are typically set at an organisation-wide level and should be enforced consistently. The use of a centralised secrets management solution would help companies to enforce these policies.  

Next to that, having an organization wide secrets management policy can help to enforce application of the best practices defined in this cheatsheet.

### 2.11 Metadata: prepare to move the secret

A secret management solution should provide the capability to store at least the following metadata about a secret:

- When it was created/consumed/archived/rotated/deleted
- By whom it was created (E.g. both the actual producer, and the engineer using the production method)
- By what it was created
- Who to contact when having trouble with the secret or having questions about it
- For what the secret is used (E.g. designated intended consumers and purpose of the secret)
- What type of secret it is (E.g. AES Key, HMAC key, RSA private key)
- When it needs to be rotated, if done manually

## 3. Continuous Integration (CI) and Continuous Deployment (CD)

The process of building, testing and deploying changes generally requires access to many systems. Continuous Integration (CI) and Continuous Deployment (CD) tools typically store secrets themselves for providing configuration to the application or for during deployment. Alternatively, they interact heavily with the secrets management system.

### 3.1. Hardening your CI/CD pipeline

Given that the CI/CD tooling heavily consume secrets, it is key that the pipeline cannot be easily hacked 

### 3.2. Where should a secret be?

### 3.3. Rotation vs Dynamic Creation

### 3.4. Deployment

### 3.5. Pipeline Created Secrets

## 4. Cloud Providers
<TODO; LET'S HAVE SOME CONTENT IN HIGHLIGHT/COMMENTS WHATWE WANT TO WRITE DOWN: ECAUSE CLOUD NATIVE SECRETS MANAGEMENT CAN HELP IF YOU HAVE A CLOUD NATIVE STRATEGY. LOCKIN IS AS DEEP AS YOU WANT IT TO BE WITH ANY SECRETS MANAGEMENT PROVIDER>

### 4.1. Vendor Lock-in

### 4.2. Geo Restrictions

### 4.3. Latency

### 4.4. Data Access (keys of the kingdom)

## 5. Containers & Orchestrators

### 5.1. Injection of Secrets (file, in-memory)

### 5.2. Short Lived Side-car Containers

### 5.3. Internal vs External Access

## 6. Implementation Guidance

### 6.1. Key Material Management Policies

### 6.2. Dynamic vs Static Use Cases

### 6.3. Processes and Governance

## 7. Encryption

### 7.1. Encryption as a Service (EaaS)

## 8. Applications

### 8.1. Least Amount of Impact (LAoI)

### 8.2. Ease of Use

### 8.3. Ease of On-boarding

## 9. Workflow in Case of Compromise

### 9.1. Process

## 10. Secrets Management Tooling Guidelines

## 11. Secret detection

- Many native integrations possible (Cloud platforms, CI/CD tooling, application libraries, container orchestrators)
- Secret lifecycle (rotation, deletion, lifespan)
- Key material management (keys to kingdom)
- Open source? (Depending on security posture)
- Encryption (at rest, in transit)
- Access control (fine grained)
- Performance
- Audit logs
- Scalable (enterprise)
- Manageable operations (upgrading, recovery)
- Agnostic
- Support for many secrets backends: database, certificates, ssh keys, cloud providers, key/value, etc
- Dynamic secrets
- Encryption as a service
- Fine grained policies (mfa requirements)
- Extensibility
- Documentation

## 12. Related Cheatsheets & further reading

- [Key Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html)
- [Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [OWASP WrongSecrets project](https://github.com/commjoen/wrongsecrets/)
- [Blog: 10 Pointers on Secrets Management](https://xebia.com/blog/secure-deployment-10-pointers-on-secrets-management/)
