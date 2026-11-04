
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
- Test updates before production deployment and confirm that required updates were installed successfully.
- Remove or replace unsupported components when security fixes are no longer available.

### Apply the Principle of Least Privilege

A service should have only the permissions necessary to perform its intended functions. Excessive privileges can increase the impact of a vulnerability or compromised service.

- Run services under dedicated, non-administrative identities when elevated privileges are not required.
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
- Restrict service listeners to the network interfaces required by the deployment.

For example, a service used only by applications on the same host should not listen on all network interfaces unless remote access is explicitly required.

### Maintain Secure Service Configurations

Default configurations may enable functionality or access that is unnecessary for a particular deployment. Define and maintain a configuration baseline appropriate to the service.

- Review security-relevant defaults before deploying a service.
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
- Protect administrative interfaces from unnecessary external access.
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
- Avoid exposing secrets through command-line arguments, logs, error messages, or other unnecessarily accessible interfaces.
- Revoke or rotate credentials when compromise is suspected and according to the organization's credential lifecycle requirements.
- Give each service only the permissions required by its credentials.

For implementation details, see the OWASP Secrets Management Cheat Sheet.

### Enable Security-Relevant Logging and Monitoring

Logs and monitoring provide information needed to identify service failures, investigate suspicious activity, and support incident response.

- Record security-relevant events appropriate to the service, such as authentication failures, access-control failures, and significant configuration changes.
- Include sufficient context to support investigation without logging credentials or other unnecessary sensitive information.
- Protect logs against unauthorized access, modification, and deletion. Where appropriate, use centralized log collection, access controls, or storage mechanisms that provide tamper resistance.
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
- Monitor resource-limit events and adjust settings when justified by operational evidence.

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

- [NIST SP 800-40 Rev. 4 — Enterprise Patch Management](https://csrc.nist.gov/pubs/sp/800/40/r4/final)
- [NIST SP 800-53 Rev. 5 — SI-2 (Flaw Remediation) (control-specific view, CSF Tools)](https://csf.tools/reference/nist-sp-800-53/r5/si/si-2/)
- [OWASP Software Supply Chain Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.html)
- [NTIA — Minimum Elements for an SBOM (2021)](https://www.ntia.gov/report/2021/minimum-elements-software-bill-materials-sbom)

### Apply the Principle of Least Privilege

- [NIST SP 800-53 Rev. 5 — AC-6 (Least Privilege) (control-specific view, CSF Tools)](https://csf.tools/reference/nist-sp-800-53/r5/ac/ac-6/)

### Reduce the Attack Surface

- [NIST SP 800-53 Rev. 5 — CM-7 (Least Functionality) (control-specific view, CSF Tools)](https://csf.tools/reference/nist-sp-800-53/r5/cm/cm-7/)

### Maintain Secure Service Configurations

- [NIST SP 800-53 Rev. 5 — CM-6 (Configuration Settings) (control-specific view, CSF Tools)](https://csf.tools/reference/nist-sp-800-53/r5/cm/cm-6/)

### Restrict Network Communication

- [NIST SP 800-53 Rev. 5 — SC-7 (Boundary Protection) (control-specific view, CSF Tools)](https://csf.tools/reference/nist-sp-800-53/r5/sc/sc-7/)
- [NIST SP 800-207 — Zero Trust Architecture](https://csrc.nist.gov/pubs/sp/800/207/final)

### Protect Service Credentials and Sensitive Data

- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [NIST SP 800-53 Rev. 5 — IA-5 (Authenticator Management) (control-specific view, CSF Tools)](https://csf.tools/reference/nist-sp-800-53/r5/ia/ia-5/)

### Enable Security-Relevant Logging and Monitoring

- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [NIST AU-2 — Event Logging (CSF Tools)](https://csf.tools/reference/nist-sp-800-53/r5/au/au-2/)
- [NIST AU-9 — Protection of Audit Information (CSF Tools)](https://csf.tools/reference/nist-sp-800-53/r5/au/au-9/)
- [NIST AU-12 — Audit Record Generation (CSF Tools)](https://csf.tools/reference/nist-sp-800-53/r5/au/au-12/)
- [NIST SI-4 — System Monitoring (CSF Tools)](https://csf.tools/reference/nist-sp-800-53/r5/si/si-4/)

### Limit Resource Consumption

- [NIST SP 800-53 Rev. 5 — SC-5 (Denial-of-Service Protection) (control-specific view, CSF Tools)](https://csf.tools/reference/nist-sp-800-53/r5/sc/sc-5/)
- [systemd.resource-control(5) — Linux/systemd implementation](https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html)

### Validate Hardening Changes

- [NIST CA-2 — Control Assessments (CSF Tools)](https://csf.tools/reference/nist-sp-800-53/r5/ca/ca-2/)
- [NIST CM-3 — Configuration Change Control (CSF Tools)](https://csf.tools/reference/nist-sp-800-53/r5/cm/cm-3/)

The NIST control-specific links above use CSF Tools, a third-party navigation aid. The authoritative publication is the official NIST SP 800-53 catalog linked below.

- [NIST SP 800-53 Rev. 5 — Security and Privacy Controls for Information Systems and Organizations](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
- [NIST SP 800-40 Rev. 4 — Guide to Enterprise Patch Management Planning](https://csrc.nist.gov/pubs/sp/800/40/r4/final)
- [OWASP Software Supply Chain Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.html)
