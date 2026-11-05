
# Service Hardening Cheat Sheet

## Introduction and Scope

Services are software components that perform tasks for applications, users, or other systems. They may process network requests, execute scheduled jobs, access databases, or perform background operations. A service can become an entry point for an attacker if it exposes unnecessary functionality, runs with excessive privileges, or has access to resources beyond those required for its operation.

Service hardening reduces this exposure by restricting a service's privileges, accessible resources, network connectivity, and available functionality. The objective is to reduce opportunities for exploitation and limit the impact of a compromised service.

This Cheat Sheet provides general service-hardening recommendations for developers, system administrators, and DevOps engineers. The principles apply across operating systems where equivalent security controls are available. Their implementation depends on the operating system, service manager, application requirements, and deployment environment.

The Cheat Sheet covers:

- General principles for configuring and operating services securely.
- Practical hardening of Linux services managed by systemd.
- Brief references to complementary hardening mechanisms.

The systemd section focuses on host-managed Linux services. Its configuration directives are not directly applicable to other service managers or operating systems.

Container and orchestration security are outside the primary scope. For those environments, refer to the OWASP Docker Security Cheat Sheet and OWASP Kubernetes Security Cheat Sheet.

Hardening controls should be selected according to the service's required functionality and threat model. A restriction that is appropriate for one service may prevent another service from operating correctly. Test configuration changes before deploying them to production.

## General Service Hardening Principles

The following recommendations apply to services regardless of the service manager used. Use the equivalent controls provided by the target platform, and verify that the configured restrictions are enforced.

### Keep Service Software and Dependencies Updated

Known vulnerabilities in service software, operating systems, and dependencies can expose services to compromise.

- Use supported versions of the operating system, service software, and dependencies.
- Maintain an inventory of service components and their versions.
- Maintain visibility into third-party components and dependencies. Use a Software Bill of Materials (SBOM), where available and appropriate, to support dependency inventory and vulnerability management.
- Monitor relevant security advisories and prioritize updates according to vulnerability risk and service exposure.
- Obtain updates from trusted sources and verify their authenticity using supported mechanisms.
- Test updates before production deployment where practical, using a process proportionate to the risk and urgency. For emergency updates, use an expedited deployment and rollback procedure, and verify successful installation.
- Remove or replace unsupported components when security fixes are no longer available. Where immediate replacement is not feasible, apply compensating controls to reduce exposure.

### Apply the Principle of Least Privilege

A service should have only the permissions necessary to perform its intended functions. Excessive privileges can increase the impact of a vulnerability or compromised service.

- Run services under dedicated, non-administrative identities where possible, and avoid granting unnecessary capabilities or privileged group memberships.
- Avoid sharing service identities between unrelated applications when separate identities are practical.
- Restrict read, write, and execute permissions on files, directories, and other resources.
- Grant privileged operations only when required, and minimize the duration and scope of elevated access where the application architecture permits.
- Review service permissions when functionality, dependencies, or deployment requirements change.
- Periodically verify the service's effective privileges and resource access rather than relying solely on its intended configuration.

For example, a service that only reads configuration files should not require permission to modify them. A service that writes application data should not automatically receive write access to application executables or unrelated system directories.

### Reduce the Attack Surface

Every unnecessary interface, component, or enabled feature can introduce additional opportunities for attack.

- Disable service features, plugins, modules, and administrative interfaces that are not required.
- Remove unused software components and dependencies where doing so is operationally safe.
- Disable unnecessary services and background processes.
- Avoid exposing debugging, diagnostic, or development endpoints in production.

For example, a service used only by applications on the same host should not listen on all network interfaces unless remote access is explicitly required. Binding to a loopback interface does not prevent access by other local processes.

### Maintain Secure Service Configurations

Default configurations may enable functionality or access that is unnecessary for a particular deployment. Define and maintain a configuration baseline appropriate to the service.

- Review security-relevant defaults before deployment, including disabling unused default accounts and changing or disabling insecure default credentials.
- Disable unnecessary features and replace insecure settings with supported, secure alternatives.
- Restrict modification of service configuration files to authorized identities.
- Keep configuration changes under version control or another auditable change-management process, where practical.
- Review configuration changes during application updates and deployment changes.
- Avoid relying solely on configuration-file contents as proof of enforcement; verify the effective behavior of relevant security controls.

For example, when changing a service's permitted filesystem access, verify both that required application operations still succeed and that prohibited operations are denied.

### Restrict Network Communication

A service should accept and initiate only the network connections required for its operation.

- Bind listening sockets to the necessary network interfaces.
- Restrict inbound traffic to required ports, protocols, and authorized sources.
- Restrict outbound connectivity where supported and operationally feasible.
- Restrict administrative interfaces to authorized access paths, require strong authentication and authorization, and prevent exposure to untrusted networks unless explicitly required and adequately protected.
- Review communication paths between services and remove unnecessary network access.
- Test network restrictions from relevant source networks rather than assuming that configured rules provide the intended isolation.
- Use appropriate authentication and authorization for service-to-service communication, including communication over internal or otherwise trusted networks.

For example, a database service used exclusively by an application on an internal network should not be directly accessible from the public internet.

Network restrictions reduce exposure but do not replace authentication, authorization, or transport protection where those controls are required.

### Protect Service Credentials and Sensitive Data

Services frequently use API keys, database credentials, certificates, and other sensitive information. Exposure of these secrets can allow unauthorized access to the service or dependent systems.

- Do not hardcode secrets in application source code or commit them to version control.
- Use an appropriate secrets-management mechanism to provide credentials to services.
- Limit access to secrets to the service identities and processes that require them.
- Avoid exposing secrets through command-line arguments, environment variables, logs, error messages, or other interfaces where they may be disclosed.
- Revoke and replace credentials when compromise is suspected, ensuring that exposed credentials are no longer valid. Follow the organization's credential lifecycle requirements for routine rotation.
- Give each service only the permissions required by its credentials.

For implementation details, see the OWASP Secrets Management Cheat Sheet.

### Enable Security-Relevant Logging and Monitoring

Logs and monitoring provide information needed to identify service failures, investigate suspicious activity, and support incident response.

- Record security-relevant events appropriate to the service, such as successful and failed authentication attempts, access-control failures, and significant configuration changes.
- Include sufficient context to support investigation without logging credentials or other unnecessary sensitive information.
- Protect logs against unauthorized access, modification, and deletion. Where appropriate, use centralized log collection, access controls, or storage mechanisms that provide tamper resistance.
- Handle untrusted log data safely to prevent log injection, and monitor logging failures and storage exhaustion that could affect log availability.
- Monitor service failures, unexpected restarts, and unusual resource consumption.
- Define log retention and alerting requirements according to operational needs and applicable policies.
- Test that important events are recorded and can be retrieved during investigation.

Logging alone does not prevent compromise. It supports detection and investigation when relevant events are collected, reviewed, and acted upon.

### Limit Resource Consumption

A service that consumes excessive memory, CPU time, processes, or other resources can affect its own availability and that of other workloads.

- Identify the service's expected resource requirements under normal and peak load.
- Configure resource limits using controls supported by the operating system or service manager.
- Limit resource consumption without preventing legitimate workloads from completing.
- Test limits under representative workloads, including expected peak conditions.
- Monitor resource-limit events and resulting service failures, and adjust limits or recovery behavior when justified by operational evidence.

Resource limits can reduce the impact of some resource-exhaustion conditions, but they do not guarantee availability or replace application-level protections against denial-of-service attacks.

### Validate Hardening Changes

Hardening should be introduced in a controlled manner. A configuration that appears restrictive may not provide the expected protection, and an overly restrictive configuration may interrupt legitimate operations.

- Identify the resources and operations required by the service before applying restrictions.
- Apply controls incrementally so that compatibility problems can be isolated.
- Verify that required service functionality continues to work.
- Where safe and practical, test that operations intended to be prohibited are actually denied.
- Record the platform version, configuration, test procedure, and results for reproducibility.
- Reassess hardening settings after significant application, operating-system, or service-manager changes.


## References

### Introduction and Scope

- [OWASP Docker Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)
- [OWASP Kubernetes Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Kubernetes_Security_Cheat_Sheet.html)

### Keep Service Software and Dependencies Updated

- [NIST SP 800-40 Rev. 4 — Enterprise Patch Management](https://csrc.nist.gov/pubs/sp/800/40/r4/final) — Supports planning, prioritizing, testing, and deploying software updates.
- [NIST SP 800-53 Rev. 5 — SI-2 (Flaw Remediation) (control-specific view, CSF Tools)](https://csf.tools/reference/nist-sp-800-53/r5/si/si-2/) — Supports identifying, correcting, and testing security-related flaws.
- [NIST SP 800-53 Rev. 5 — CM-8 (System Component Inventory) (control-specific view, CSF Tools)](https://csf.tools/reference/nist-sp-800-53/r5/cm/cm-8/) — Supports maintaining an inventory of system components.
- [NIST SP 800-53 Rev. 5 — CM-14 (Signed Components) (control-specific view, CSF Tools)](https://csf.tools/reference/nist-sp-800-53/r5/cm/cm-14/) — Supports verifying approved digital signatures before installing designated software and firmware components, including updates.
- [NIST SP 800-53 Rev. 5 — SI-7 (Software, Firmware, and Information Integrity) (control-specific view, CSF Tools)](https://csf.tools/reference/nist-sp-800-53/r5/si/si-7/) — Supports detecting unauthorized changes through integrity verification.
- [NIST SP 800-53 Rev. 5 — SA-22 (Unsupported System Components) (control-specific view, CSF Tools)](https://csf.tools/reference/nist-sp-800-53/r5/sa/sa-22/) — Supports replacing unsupported components or arranging documented alternative support.
- [OWASP Software Supply Chain Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.html) — Provides guidance on software dependencies and supply-chain risks.
- [NTIA — Minimum Elements for an SBOM (2021)](https://www.ntia.gov/report/2021/minimum-elements-software-bill-materials-sbom) — Supports documenting software components and dependencies using an SBOM.

### Apply the Principle of Least Privilege

- [NIST SP 800-53 Rev. 5 — AC-6 (Least Privilege) (control-specific view, CSF Tools)](https://csf.tools/reference/nist-sp-800-53/r5/ac/ac-6/) — Supports limiting service privileges to those necessary for required operations.
- [NIST SP 800-53 Rev. 5 — AC-2 (Account Management) (control-specific view, CSF Tools)](https://csf.tools/reference/nist-sp-800-53/r5/ac/ac-2/) — Supports managing service accounts, their intended use, and their authorizations.
- [NIST SP 800-53 Rev. 5 — AC-3 (Access Enforcement) (control-specific view, CSF Tools)](https://csf.tools/reference/nist-sp-800-53/r5/ac/ac-3/) — Supports enforcing approved read, write, execute, and other access permissions on system resources.
- [NIST SP 800-53 Rev. 5 — AC-6(7) (Review of User Privileges) (control-specific view, CSF Tools)](https://csf.tools/reference/nist-sp-800-53/r5/ac/ac-6/ac-6-7/) — Supports periodically reviewing assigned privileges and removing privileges that are no longer required.

### Reduce the Attack Surface

- [NIST SP 800-53 Rev. 5 — CM-7 (Least Functionality) (control-specific view, CSF Tools)](https://csf.tools/reference/nist-sp-800-53/r5/cm/cm-7/) — Supports disabling unnecessary functionality, services, and software.
- [NIST SP 800-53 Rev. 5 — SC-7 (Boundary Protection) (control-specific view, CSF Tools)](https://csf.tools/reference/nist-sp-800-53/r5/sc/sc-7/) — Supports controlling network communications and limiting unnecessary network exposure.

### Maintain Secure Service Configurations

- [NIST SP 800-53 Rev. 5 — CM-6 (Configuration Settings) (control-specific view, CSF Tools)](https://csf.tools/reference/nist-sp-800-53/r5/cm/cm-6/) — Supports establishing, implementing, and monitoring security-relevant configuration settings.
- [NIST SP 800-53 Rev. 5 — CM-2 (Baseline Configuration) (control-specific view, CSF Tools)](https://csf.tools/reference/nist-sp-800-53/r5/cm/cm-2/) — Supports establishing and maintaining documented configuration baselines.
- [NIST SP 800-53 Rev. 5 — CM-3 (Configuration Change Control) (control-specific view, CSF Tools)](https://csf.tools/reference/nist-sp-800-53/r5/cm/cm-3/) — Supports reviewing, documenting, and controlling configuration changes.
- [NIST SP 800-53 Rev. 5 — CM-5 (Access Restrictions for Change) (control-specific view, CSF Tools)](https://csf.tools/reference/nist-sp-800-53/r5/cm/cm-5/) — Supports restricting who can modify system components and configurations.

### Restrict Network Communication

- [NIST SP 800-53 Rev. 5 — SC-7 (Boundary Protection) (control-specific view, CSF Tools)](https://csf.tools/reference/nist-sp-800-53/r5/sc/sc-7/) — Supports controlling communications at system boundaries and managed interfaces.
- [NIST SP 800-53 Rev. 5 — SC-7(5) (Deny by Default — Allow by Exception) (control-specific view, CSF Tools)](https://csf.tools/reference/nist-sp-800-53/r5/sc/sc-7/sc-7-5/) — Supports default-deny restrictions for inbound and outbound network communications, with approved exceptions.
- [NIST SP 800-207 — Zero Trust Architecture](https://csrc.nist.gov/pubs/sp/800/207/final) — Supports explicit authentication and authorization without relying solely on network location.

### Protect Service Credentials and Sensitive Data

- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [NIST SP 800-53 Rev. 5 — IA-5 (Authenticator Management) (control-specific view, CSF Tools)](https://csf.tools/reference/nist-sp-800-53/r5/ia/ia-5/) — Supports protecting and managing service authenticators and credentials.

### Enable Security-Relevant Logging and Monitoring

- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [NIST AU-2 — Event Logging (CSF Tools)](https://csf.tools/reference/nist-sp-800-53/r5/au/au-2/) — Supports identifying which security-relevant events should be logged.
- [NIST AU-9 — Protection of Audit Information (CSF Tools)](https://csf.tools/reference/nist-sp-800-53/r5/au/au-9/) — Supports protecting audit information against unauthorized access, modification, and deletion.
- [NIST AU-12 — Audit Record Generation (CSF Tools)](https://csf.tools/reference/nist-sp-800-53/r5/au/au-12/) — Supports generating audit records for defined event types.
- [NIST SI-4 — System Monitoring (CSF Tools)](https://csf.tools/reference/nist-sp-800-53/r5/si/si-4/) — Supports monitoring for attacks and indicators of potential compromise.
- [NIST AU-11 — Audit Record Retention (CSF Tools)](https://csf.tools/reference/nist-sp-800-53/r5/au/au-11/) — Supports defining and enforcing audit-record retention periods.
- [NIST AU-5 — Response to Audit Logging Process Failures (CSF Tools)](https://csf.tools/reference/nist-sp-800-53/r5/au/au-5/) — Supports responding to audit-logging failures, including notifying designated personnel.
- [NIST SI-4(5) — System-Generated Alerts (CSF Tools)](https://csf.tools/reference/nist-sp-800-53/r5/si/si-4/si-4-5/) — Supports generating alerts when defined indicators of compromise or potential compromise occur.

### Limit Resource Consumption

- [NIST SP 800-53 Rev. 5 — SC-5 (Denial-of-Service Protection) (control-specific view, CSF Tools)](https://csf.tools/reference/nist-sp-800-53/r5/sc/sc-5/) — Supports protecting service availability against denial-of-service attacks.
- [NIST SP 800-53 Rev. 5 — SC-6 (Resource Availability) (control-specific view, CSF Tools)](https://csf.tools/reference/nist-sp-800-53/r5/sc/sc-6/) — Supports protecting resource availability through allocation mechanisms such as quotas and priorities.
- [systemd.resource-control(5) — Linux/systemd implementation](https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html) — Documents systemd mechanisms for controlling resource consumption.

### Validate Hardening Changes

- [NIST CA-2 — Control Assessments (CSF Tools)](https://csf.tools/reference/nist-sp-800-53/r5/ca/ca-2/) — Supports assessing whether security controls are implemented correctly and operate as intended.
- [NIST CM-3 — Configuration Change Control (CSF Tools)](https://csf.tools/reference/nist-sp-800-53/r5/cm/cm-3/) — Supports documenting, reviewing, and controlling hardening configuration changes.

The NIST control-specific links above use CSF Tools, a third-party navigation aid. The authoritative publication is the official NIST SP 800-53 catalog linked below.

- [NIST SP 800-53 Rev. 5 — Security and Privacy Controls for Information Systems and Organizations](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
- [NIST SP 800-40 Rev. 4 — Guide to Enterprise Patch Management Planning](https://csrc.nist.gov/pubs/sp/800/40/r4/final)
- [OWASP Software Supply Chain Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.html)
