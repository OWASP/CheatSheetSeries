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
* Users (e.g. SSH keys, root account passwords). In an incident response scenario users expect to be provisioned with credentials rapidly so they can recover services that have gone offline. Having to wait for credentials could impact the responsiveness of the operations team.
* Applications (e.g. database credentials and API keys). If the service is not preferment it could degrade the availability of dependent applications or increase application startup times.

Within a large organisation such a service could receive a huge volume of requests.

### 2.2 Centralized Approach

It makes sense to maintain a single system for the purpose of secrets management. Having too many systems could result in confusion over which one to use, and this could slow down a response to an incident.

### 2.3 Fine Grained Access-Control List (ACL)

The ability to configure access control on even the tiniest component of a system, such as an object in a data store, if required allows for granular access control. A secrets management solution should cater for this level of configuration.

### 2.4 Remove Human Interaction

Dynamic secrets are those that are generated for each request. When an application starts it could request it's database credentials, which when dynamically generated will be provided with new credentials for that session. Dynamic secrets should be used where possible to reduce the surface area of credential re-use. Should the application's database credentials be stolen, upon reboot they would be expired.

Manually maintaining configuration files and password changes can be wasteful. The use of dynamic secrets removes the need for human interaction.

### 2.5 Auditing

Auditing is an important role of secrets management due to the nature of the application. Auditing must be implemented in a secure way so as to be resilient against attempts to tamper with or delete the audit logs. At minimum the following should be audited:
* Who requested a secret and for what system and role.
* Whether the secret request was approved or rejected.
* When the secret was used and by whom/source.
* When the secret has expired.
* If any attempts to re-use expired expired secrets have been made.
* If there have been any authentication errors.

It is important that all auditing is correctly timestamped, another reason for a centralised approach, to maintain temporal consistency.

### 2.6 Secret Lifecycle

Secrets follow a lifecycle. The stages in the lifecycle are as follows:
* Creation
* Rotation
* Deletion

#### 2.6.1 Creation

New secrets must be securely generated and cryptographically robust enough for their purpose. Secrets must have the minimum privileges assigned to them to enable their requested use/role.

Credentials should be transmitted in a secure manor, such that ideally the password would not be transmitted along with the username when requesting user accounts. Instead the password should be transmitted via a side-channel such as SMS.

Applications may not benefit from having multiple channels for communication and so credentials must be provisioned in a secure way.

#### 2.6.1 Rotation

Secrets should be regularly rotated so that any stolen credentials will only work for a short period of time. This will also reduce the tendency for users to fall bac to bad-habits such as re-using credentials.

#### 2.6.1 Deletion

When secrets are no longer required they must be securely revoked in order to restrict access. With certificates such as SSL certificates this also involves certificate revocation.

#### 2.6.1 Lifespan

With exception of emergency break-glass credentials, secrets should always be created to expire after a fixed time.

Policies should be applied by the secrets management solution to ensure credentials are only made available for a limited time that is appropriate for the type of credential.

### 2.7 Transport Layer Security (TLS) Everywhere

It goes without saying that no secrets should ever be transmitted via plaintext. There is no excuse in this day and age given the ubiquitous adoption of SSL/TLS to not use encryption to protect the secrets in transit.

Furthermore secrets management solutions can be used to effectively provision SSL certificates.

### 2.8 Automate Key Rotation

Key rotation is a challenging process when implemented manually, and can lead to mistakes. It is therefor highly recommended to automate the rotation of keys.

### 2.9 Restore and Backup

Consideration must be made for the possibility that the central secrets management service could become unavailable, perhaps due to scheduled down-time for maintenance - in which case it could be impossible to retrieve the credentials required to restore the service if they were not previously acquired. Furthermore should the system become unavailable due to other reasons, emergency break-glass processes should be implemented to restore the service.

Emergency break-glass credentials therefore should be regularly backed up in a secure fashion, and tested routinely to verify they work.

### 2.10 Policies

Policies defining the minimum complexity requirements of passwords, as well as approved encryption algorithms are typically set at an organisation-wide level and should be enforced consistently. The use of a centralised secrets management solution would help companies to enforce these policies.

## 3. Continuous Integration (CI) and Continuous Deployment (CD)

The process of integrating features and deploying changes commonly requires secrets to several systems, such as version control.

### 3.1. Build Tools

### 3.2. Rotation vs Dynamic Creation

### 3.3. Identity Authentication

### 3.4. Deployment

## 4. Cloud Providers

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

## Authors and Primary Editors

* Dominik de Smit - dominik.de.smit@araido.com
* Anthony Fielding - anthony.fielding@orbital3.com