# Secure Application Development Cheat Sheet

## Introduction

This cheat sheet provides a concise entry point to the OWASP Cheat Sheet Series for developers designing and building applications. Rather than replicating in-depth implementation guidance or serving as an exhaustive manual, this guide helps development teams identify the security concerns that apply to their software architecture and directs them to authoritative OWASP Cheat Sheets for actionable practices.

Modern application development requires embedding security across the entire software development lifecycle. The [OWASP Top 10:2025](https://owasp.org/Top10/2025/) provides an essential awareness document highlighting the most critical application security risks, while frameworks such as the [NIST Secure Software Development Framework (SSDF)](https://csrc.nist.gov/pubs/sp/800/218/final) outline secure development practices. Each of the following sections addresses a core architectural domain, outlines when and why that domain matters, provides a light mapping to relevant [OWASP Top 10:2025](https://owasp.org/Top10/2025/) categories, and points to the relevant specialized cheat sheets.

## 1. Identity, Authentication, and Access Control

Identity, authentication, and access control establish who is interacting with an application—whether a human user or an automated service—and enforce what actions that subject is permitted to perform. These controls matter whenever an application manages sensitive assets, user accounts, multi-tenant boundaries, or service-to-service transactions. Inadequate controls allow attackers to impersonate legitimate entities, hijack active sessions, or execute unauthorized operations.

**OWASP Top 10 Mapping:**

- [A01:2025 – Broken Access Control](https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/)
- [A07:2025 – Authentication Failures](https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/)

**Relevant OWASP Cheat Sheets:**

- **User Authentication and Credentials:**
    - [Authentication Cheat Sheet](Authentication_Cheat_Sheet.md): General authentication controls, password policies, and credential verification.
    - [Password Storage Cheat Sheet](Password_Storage_Cheat_Sheet.md): Work-factor password hashing algorithms (Argon2id, bcrypt, scrypt) and storage hygiene.
    - [Multifactor Authentication Cheat Sheet](Multifactor_Authentication_Cheat_Sheet.md): Multi-factor authentication (MFA) design and factor verification.
    - [Passkey Security Cheat Sheet](Passkey_Security_Cheat_Sheet.md): Phishing-resistant passwordless authentication with WebAuthn and FIDO2.
    - [Forgot Password Cheat Sheet](Forgot_Password_Cheat_Sheet.md): Secure account recovery and credential reset flows.
- **Session Management:**
    - [Session Management Cheat Sheet](Session_Management_Cheat_Sheet.md): Session lifecycle, cookie security attributes, timeouts, and termination.
    - [JSON Web Token Cheat Sheet](JSON_Web_Token_Cheat_Sheet.md): Cryptographic verification and claims handling for token-based sessions.
- **Authorization and Access Control:**
    - [Authorization Cheat Sheet](Authorization_Cheat_Sheet.md): Principles of least privilege, default-deny authorization, and access enforcement.
    - [Transaction Authorization Cheat Sheet](Transaction_Authorization_Cheat_Sheet.md): Contextual step-up authorization and re-authentication for high-impact operations.
- **Service Identities and Trust Boundaries:**
    - [Workload Identity Federation Cheat Sheet](Workload_Identity_Federation_Cheat_Sheet.md): Machine identity federation without long-lived static credentials.
    - [Identity Propagation Patterns Cheat Sheet](Identity_Propagation_Patterns_Cheat_Sheet.md): Propagating verified user context and calling service identity across microservices.

## 2. Input Handling and Injection Prevention

Input handling and injection defense govern how an application receives, inspects, processes, and displays data from untrusted sources. These controls matter whenever an application processes data from users, client requests, external APIs, webhooks, or file uploads. When applications process untrusted data without validation, parameterization, or context-aware encoding, attackers can manipulate query interpreters, execute unauthorized commands, or run malicious scripts in user browsers.

**OWASP Top 10 Mapping:**

- [A05:2025 – Injection](https://owasp.org/Top10/2025/A05_2025-Injection/)

**Relevant OWASP Cheat Sheets:**

- **Input Validation:**
    - [Input Validation Cheat Sheet](Input_Validation_Cheat_Sheet.md): Allow-list validation strategies, syntactic checks, and semantic verification.
- **Query Parameterization and Database Injections:**
    - [Query Parameterization Cheat Sheet](Query_Parameterization_Cheat_Sheet.md): Prepared statements and parameterization to separate SQL code from untrusted data.
    - [SQL Injection Prevention Cheat Sheet](SQL_Injection_Prevention_Cheat_Sheet.md): Defense-in-depth against SQL injection across relational database interfaces.
- **Output Encoding and Cross-Site Scripting (XSS):**
    - [Cross Site Scripting Prevention Cheat Sheet](Cross_Site_Scripting_Prevention_Cheat_Sheet.md): Context-aware output encoding to prevent reflected and stored XSS.
    - [DOM based XSS Prevention Cheat Sheet](DOM_based_XSS_Prevention_Cheat_Sheet.md): Safe client-side JavaScript execution, sink defense, and DOM manipulation.
- **Files, Payloads, and System Commands:**
    - [File Upload Cheat Sheet](File_Upload_Cheat_Sheet.md): File type validation, storage isolation, and safe handling of uploaded files.
    - [XML External Entity Prevention Cheat Sheet](XML_External_Entity_Prevention_Cheat_Sheet.md): Disabling external entity resolution and DTD processing in XML parsers.
    - [OS Command Injection Defense Cheat Sheet](OS_Command_Injection_Defense_Cheat_Sheet.md): Safe argument handling and avoiding direct shell execution.
    - [Deserialization Cheat Sheet](Deserialization_Cheat_Sheet.md): Safe object serialization and preventing arbitrary code execution during deserialization.
    - [Webhook Security Cheat Sheet](Webhook_Security_Cheat_Sheet.md): Verifying authenticity and payload integrity for incoming webhooks.

## 3. Cryptography and Sensitive Data Protection

Cryptography and sensitive data protection ensure the confidentiality and integrity of information both while moving across networks and while stored on disk. These controls matter whenever an application handles personal information, credentials, financial records, or operational secrets. Flaws in algorithm selection, encryption implementation, or credential storage can expose sensitive assets even if the rest of the application remains secure.

**OWASP Top 10 Mapping:**

- [A04:2025 – Cryptographic Failures](https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/)

**Relevant OWASP Cheat Sheets:**

- **Transport Layer Security:**
    - [Transport Layer Security Cheat Sheet](Transport_Layer_Security_Cheat_Sheet.md): Modern TLS protocol configuration, certificate validation, and secure channel setup.
    - [HTTP Strict Transport Security Cheat Sheet](HTTP_Strict_Transport_Security_Cheat_Sheet.md): Enforcing encrypted HTTPS connections and preventing downgrade attacks.
    - [Pinning Cheat Sheet](Pinning_Cheat_Sheet.md): Certificate and public key pinning for native applications and controlled endpoints.
- **Data at Rest and Privacy:**
    - [Cryptographic Storage Cheat Sheet](Cryptographic_Storage_Cheat_Sheet.md): Selecting vetted algorithms, encryption modes, and initialization vectors for data at rest.
    - [User Privacy Protection Cheat Sheet](User_Privacy_Protection_Cheat_Sheet.md): Data minimization and privacy controls for personal data throughout its lifecycle.
- **Secrets and Key Management:**
    - [Secrets Management Cheat Sheet](Secrets_Management_Cheat_Sheet.md): Safeguarding application credentials, API keys, vault integration, and rotation practices.
    - [Key Management Cheat Sheet](Key_Management_Cheat_Sheet.md): Cryptographic key lifecycle management, including generation, storage, rotation, and destruction.

## 4. Application Architecture and Communication Boundaries

Application architecture and communication boundaries define how services interact with one another, how trust is partitioned, and how unexpected conditions are handled. These controls matter whenever applications expose APIs, communicate across network boundaries, integrate with third-party systems, or run behind reverse proxies. Without secure architecture defaults and explicit boundary defenses, applications are susceptible to request forgery, unintended exposure of internal topologies, and information disclosure through diagnostic messages.

**OWASP Top 10 Mapping:**

- [A01:2025 – Broken Access Control](https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/)
- [A02:2025 – Security Misconfiguration](https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/)
- [A06:2025 – Insecure Design](https://owasp.org/Top10/2025/A06_2025-Insecure_Design/)
- [A10:2025 – Mishandling of Exceptional Conditions](https://owasp.org/Top10/2025/A10_2025-Mishandling_of_Exceptional_Conditions/)

**Relevant OWASP Cheat Sheets:**

- **Outbound Request Protection:**
    - [Server Side Request Forgery Prevention Cheat Sheet](Server_Side_Request_Forgery_Prevention_Cheat_Sheet.md): Destination host validation and network egress controls to prevent SSRF.
- **API and Service Architecture:**
    - [REST Security Cheat Sheet](REST_Security_Cheat_Sheet.md): Endpoint authorization, HTTP method restrictions, and input constraints for REST APIs.
    - [GraphQL Cheat Sheet](GraphQL_Cheat_Sheet.md): Defending GraphQL APIs against query depth attacks, introspection exposure, and batch abuse.
    - [Microservices Security Cheat Sheet](Microservices_Security_Cheat_Sheet.md): Security perimeter enforcement and service-to-service trust models.
    - [Zero Trust Architecture Cheat Sheet](Zero_Trust_Architecture_Cheat_Sheet.md): Microsegmentation, least privilege, and continuous explicit verification.
- **Secure Defaults, Browser Defense, and Error Handling:**
    - [HTTP Headers Cheat Sheet](HTTP_Headers_Cheat_Sheet.md): Hardening browser clients through defensive HTTP response headers.
    - [Content Security Policy Cheat Sheet](Content_Security_Policy_Cheat_Sheet.md): Restricting script sources, resource loading, and frame ancestry.
    - [Cross-Site Request Forgery Prevention Cheat Sheet](Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md): Mitigating cross-site request forgery using SameSite cookies and anti-CSRF tokens.
    - [Error Handling Cheat Sheet](Error_Handling_Cheat_Sheet.md): Fail-safe error processing and preventing sensitive information disclosure in stack traces.

## 5. Dependencies, Deployment, and Security Operations

Dependencies, deployment, and security operations protect software throughout its build pipeline, execution environment, and production lifecycle. These controls matter whenever an application incorporates third-party libraries, runs within automated CI/CD pipelines, deploys onto containerized or cloud platforms, or requires operational visibility into potential attacks. Flaws in supply chain governance, infrastructure configurations, or security logging can compromise otherwise secure application code.

**OWASP Top 10 Mapping:**

- [A03:2025 – Software Supply Chain Failures](https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/)
- [A08:2025 – Software or Data Integrity Failures](https://owasp.org/Top10/2025/A08_2025-Software_or_Data_Integrity_Failures/)
- [A09:2025 – Security Logging and Alerting Failures](https://owasp.org/Top10/2025/A09_2025-Security_Logging_and_Alerting_Failures/)

**Relevant OWASP Cheat Sheets:**

- **Dependency and Supply Chain Security:**
    - [Software Supply Chain Security Cheat Sheet](Software_Supply_Chain_Security_Cheat_Sheet.md): Verifying artifact provenance, dependency integrity, and build environment security.
    - [Vulnerable Dependency Management Cheat Sheet](Vulnerable_Dependency_Management_Cheat_Sheet.md): Identifying, tracking, and patching known vulnerabilities in third-party libraries.
    - [CI CD Security Cheat Sheet](CI_CD_Security_Cheat_Sheet.md): Hardening continuous integration and continuous deployment pipelines against tampering.
- **Infrastructure and Deployment Hardening:**
    - [Docker Security Cheat Sheet](Docker_Security_Cheat_Sheet.md): Container image hardening, rootless execution, and container isolation.
    - [Kubernetes Security Cheat Sheet](Kubernetes_Security_Cheat_Sheet.md): Cluster hardening, pod security standards, and network policies.
    - [Infrastructure as Code Security Cheat Sheet](Infrastructure_as_Code_Security_Cheat_Sheet.md): Static analysis and security scanning of infrastructure-as-code definitions.
- **Logging, Monitoring, and Response:**
    - [Logging Cheat Sheet](Logging_Cheat_Sheet.md): Recording security events, sanitizing log data, and protecting log file integrity.
    - [Vulnerability Disclosure Cheat Sheet](Vulnerability_Disclosure_Cheat_Sheet.md): Establishing coordinated vulnerability disclosure programs and security.txt contacts.

## References

- [OWASP Top 10:2025](https://owasp.org/Top10/2025/)
- [OWASP Application Security Verification Standard (ASVS)](https://owasp.org/www-project-application-security-verification-standard/)
- [NIST SP 800-218: Secure Software Development Framework (SSDF) Version 1.1](https://csrc.nist.gov/pubs/sp/800/218/final)
