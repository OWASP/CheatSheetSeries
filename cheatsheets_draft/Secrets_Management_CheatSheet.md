# Secrets Management Cheatsheet

1. [Introduction](#1-Introduction)
2. [General](#2-General-Secrets-Management)
3. [Continuous Integration (CI) and Continuous Deployment (CD)](#3-Continuous-Integration-(CI)-and-Continuous-Deployment-(CD))
4. [Cloud Providers](#4-Cloud-Providers)
5. [Containers and Orchestration](#5-Containers-&-Orchestrators)
6. [Implementation](#6-Implementation)
7. [Encryption](#7-Encryption)
8. [Applications](#8-Applications)
9. [Workflow in case of compromise](#9-Workflow-in-case-of-compromise)
10. [Secrets Management Tooling](#10-Secrets-Management-Tooling-Guidelines)

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
Therefore, it is better to limit or remove the human interaction with the actual secrets. This can be done in multiple ways:

- having a secrets pipeline which does large parts of the secret management (E.g. creation, rotation, etc.)
- Using dynamic secrets: these are generated for each request. When an application starts it could request it's database credentials, which when dynamically generated will be provided with new credentials for that session. Dynamic secrets should be used where possible to reduce the surface area of credential re-use. Should the application's database credentials be stolen, upon reboot they would be expired.
- Using automation to rotate static secrets by other services and applications.

### 2.5 Auditing

Auditing is an important role of secrets management due to the nature of the application. Auditing must be implemented in a secure way to be resilient against attempts to tamper with or delete the audit logs. At minimum the following should be audited:

- Who requested a secret and for what system and role.
- Whether the secret request was approved or rejected.
- When the secret was used and by whom/source.
- When the secret has expired.
- If any attempts to re-use expired secrets have been made.
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

Furthermore, secrets management solutions can be used to effectively provision SSL certificates.

### 2.8 Automate Key Rotation

Key rotation is a challenging process when implemented manually, and can lead to mistakes. It is therefore better to automate the rotation of keys or at least ensure that the process is sufficiently supported by IT.

### 2.9 Downtime, Break-glass, Backup and Restore

Consideration must be made for the possibility that a secrets management service could become unavailable. This could be due to various reasons, such as scheduled down-time for maintenance. In that case it could be impossible to retrieve the credentials required to restore the service if they were not previously acquired. This means that possible downtime windows need to be chosen carefully based on earlier metrics and/or audit-logs. You can best give short downtime to the system at a time when its secrets are often not updated and/or retrieved.

Next, the backup and restore procedures of the system should be regularly tested, and audited for their security. A few requirements regarding backup & restore. Ensure that:

- An automated backup procedure is in place and executed periodically; the frequency of the backup/snapshot should be based on the amount of secrets, and their lifecycle;
- Restore procedures are tested frequently, in order to guarantee that the backups are intact.
- Backups are encrypted on a secure storage with reduced access rights. The backup location should be monitored for (unauthorized) access and administrative actions.

Last, should the system become unavailable due to other reasons than normal maintenance, emergency break-glass processes should be implemented to restore the service. Emergency break-glass credentials therefore should be regularly backed up in a secure fashion in a secondary secrets management system, and tested routinely to verify they work.

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

The process of building, testing and deploying changes generally requires access to many systems. Continuous Integration (CI) and Continuous Deployment (CD) tools typically store secrets themselves for providing configuration to the application or for during deployment. Alternatively, they interact heavily with the secrets management system. There are various best-practices which can help smoothing out secret management in CI/CD, some of them will be dealt with in this section.

### 3.1. Hardening your CI/CD pipeline

Given that the CI/CD tooling heavily consume secrets, it is key that the pipeline cannot be easily hacked or misused by employees. Here are a few guidelines which can help you:

- Thread your CI/CD tooling as a production environment: harden it, patch it and ensure that the underlying infrastructure and services are hardened.
- Have Security Event Monitoring in place.
- Implement least-privilege access: developers do not need to be able to administrate projects, instead they only need to be able to execute required functions, such as setting up pipelines, running them, and working with code. Administrative tasks can easily be done by means of configuration-as-code in a separate repository which is used by the CI/CD system to update its configuration. This way there is no need for privileged roles which might have access to secrets.
- Make sure that pipelines their output does not leak secrets, nor that production pipelines can be debugged.
- Make sure that any runners and/or workers for a CI/CD system cannot be exec'ed into.
- Have proper authentication, authorization and accounting in place.
- Make sure that pipelines can only be created by means of an approved process, including MR/PR steps to make sure that a created pipeline is security-reviewed.

### 3.2 Where should a secret be?

There are various places at which you can store a secret in order to execute certain CI/CD actions:

- As part of your CI/CD tooling: a secret can be stored as a secret in [Gitlab](https://docs.gitlab.com/charts/installation/secrets.html)/[Github](https://docs.github.com/en/actions/security-guides/encrypted-secrets)/[jenkins](https://www.jenkins.io/doc/developer/security/secrets/). This is not the same as committing it to code.
- As part of our secrets-management system: here you can store a secret in a secrets management system, such as facilities provided by a cloud provider ([AWS Secret Manager](https://aws.amazon.com/secrets-manager/), [Azure Key Vault](https://azure.microsoft.com/nl-nl/services/key-vault/)), or other third party facilities ([Hashicorp Vault](https://www.vaultproject.io/), [Keeper](https://www.keepersecurity.com/), [Confidant](https://lyft.github.io/confidant/)). In this case, the CI/CD pipeline tooling requires credentials to connect to these secret management systems in order to have secrets in place.

Note: not all secrets are required to be at the CI/CD pipeline to get to the actual deployment. Instead, make sure that the services which are deployed, will take care of part of their secrets management at first boot.

#### 3.2.1 As part of your CI/CD tooling

//TODO: CONTINUE HERE!

Jeroen does:EXPLAIN DO'S AND DONT'S

#### 3.2.2 Storing it in a secrets management system

Jeroen does: EXPLAIN DO'S AND DONT'S

#### 3.2.3 Not touched by CI/CD at all

Jeroen does: EXPLAIN DO'S AND DONT'S

### 3.3: Authentication and Authorization

Jeroen does:HOW DOES A PIPELINE AUTHENTICATE? HOW DO YOU KNOW AUTHORIZAITON IS OK?

### 3.4: Logging and accounting

Jeroen does:HOW CAN YOU TELL WHO ACCESSED THE SECRET WITH THE PIPELINE?

### 3.5. Rotation vs Dynamic Creation

Jeroen does: DO YOU ROTATE PER ACTION, OR CREATE NEW SECRETS UPON DEPLOYMENT?

### 3.6. Pipeline Created Secrets

Jeroen does: HOW TO USE A SECRETS PIPELINE

## 4. Cloud Providers

<TODO; LET'S HAVE SOME CONTENT IN HIGHLIGHT/COMMENTS WHATWE WANT TO WRITE DOWN: ECAUSE CLOUD NATIVE SECRETS MANAGEMENT CAN HELP IF YOU HAVE A CLOUD NATIVE STRATEGY. LOCKIN IS AS DEEP AS YOU WANT IT TO BE WITH ANY SECRETS MANAGEMENT PROVIDER>

### 4.1. Vendor Lock-in

[comment]: TODO: REPLACE/REWRITE/REMOVE as agreed with @bendehaan
"[Vendor lock-in](https://www.cloudflare.com/learning/cloud/what-is-vendor-lock-in/) refers to a situation where the cost of switching to a different vendor is so high that the customer is essentially stuck with the original vendor. Because of financial pressures, an insufficient workforce, or the need to avoid interruptions to business operations, the customer is "locked in" to what may be an inferior product or service." If a secret management solution is written in such a way that it is hard to discern which secrets are used for what, and secrets cannot be easily extracted, you end up with a vendor lockin. This can make it harder to find a better fit-for-purpose in the future.

### 4.2. Geo Restrictions

### 4.3. Latency

### 4.4. Data Access (keys of the kingdom)

## 5. Containers & Orchestrators

### 5.1. Injection of Secrets (file, in-memory)

Ther are 3 ways to get secrets to an app inside a docker container

- Environment variables: We can provide secrets directly as the part of the docker container configuration. In this method the secrets could be either hard coded in docker configuration file or could be passed as argument at docker runtime.
- Mounted volumes (file): In this method we keep our secrets within a particular config/secret file and mount that file to our instance as a mounted volume.
- Fetch from secret store (in-memory): A sidecar app/container fetches the secrets it need directly from a secret manager service without having to deal with docker config. This solution allows you to use dynamically constructed secrets without worrying about the secrets being viewable from the file system or from checking the docker container's env variables.

### 5.2. Short Lived Side-car Containers

To inject secret within a container one could create short lived side-car containers that fethces secret from some remote end point and then store them on a shared volume which is also mounted to the original container. The original container can now use the secrets from mounted volume benefit of using this approach is that we don't need to integrate any third party tool or code to get secrets. Once the secret are fethced the side car container dies and that's why they are called short lived. Example of one such service is Vault Agent Sidecar Injector. The Vault Agent Injector alters pod specifications to include Vault Agent containers that render Vault secrets to a shared memory volume using Vault Agent Templates. By rendering secrets to a shared volume, containers within the pod can consume Vault secrets without being Vault aware.

### 5.3. Internal vs External Access

## 6. Implementation Guidance

### 6.1. Key Material Management Policies

### 6.2. Dynamic vs Static Use Cases

### 6.3. Processes and Governance

## 7. Encryption

### 7.1. Encryption as a Service (EaaS)

EaaS is a model in which users subscribe to a cloud-based encryption service without having to install encryption in their own systems. By using Encryption as a service we get following benefits:

- Data can be encrypted at rest
- Data is secured in Transit (TLS)
- Key handling and cryptographic implementations is taken care by Encryption Service, not by developers
- More services could be added to interact with the sensitive data

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
- [Blog: From build to run: pointers on secure deployment](https://xebia.com/from-build-to-run-pointers-on-secure-deployment/)
