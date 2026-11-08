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

Container and orchestration security are outside the primary scope. For those environments, refer to the [OWASP Docker Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html) and [OWASP Kubernetes Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Kubernetes_Security_Cheat_Sheet.html).

Hardening controls should be selected according to the service's required functionality and threat model. A restriction that is appropriate for one service may prevent another service from operating correctly. Test configuration changes before deploying them to production.

## General Service Hardening Principles

The following recommendations apply to services regardless of the service manager used. Use the equivalent controls provided by the target platform, and verify that the configured restrictions are enforced.

### Keep Service Software and Dependencies Updated

Known vulnerabilities in service software, operating systems, and dependencies can expose services to compromise.

- Use supported versions of the operating system, service software, and dependencies. Maintain an inventory of service components and their versions, using an SBOM where appropriate.
- Monitor relevant security advisories, prioritize updates according to risk and exposure, and obtain updates from trusted sources using supported authenticity checks.
- Test updates before production deployment where practical. For urgent fixes, use an expedited deployment and rollback procedure and verify successful installation.
- Remove or replace unsupported components when security fixes are unavailable; apply compensating controls if immediate replacement is not feasible.

See [NIST SP 800-40 Rev. 4](https://csrc.nist.gov/pubs/sp/800/40/r4/final) for patch-management guidance and the [OWASP Software Supply Chain Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.html) for dependency and supply-chain practices.

### Apply the Principle of Least Privilege

A service should have only the permissions necessary to perform its intended functions. Excessive privileges can increase the impact of a vulnerability or compromised service.

- Run services under dedicated, non-administrative identities where possible, and avoid granting unnecessary capabilities or privileged group memberships.
- Avoid sharing service identities between unrelated applications when separate identities are practical.
- Restrict read, write, and execute permissions on files, directories, and other resources.
- Grant privileged operations only when required, and minimize the duration and scope of elevated access where the application architecture permits.
- Review service permissions when functionality, dependencies, or deployment requirements change.
- Periodically verify the service's effective privileges and resource access rather than relying solely on its intended configuration.

For example, a service that only reads configuration files should not require permission to modify them. A service that writes application data should not automatically receive write access to application executables or unrelated system directories.

See [NIST SP 800-53 Rev. 5, AC-6 (Least Privilege)](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final) for the underlying least-privilege control.

### Reduce the Attack Surface

Every unnecessary interface, component, or enabled feature can introduce additional opportunities for attack.

- Disable service features, plugins, modules, and administrative interfaces that are not required.
- Remove unused software components and dependencies where doing so is operationally safe.
- Disable unnecessary services and background processes.
- Avoid exposing debugging, diagnostic, or development endpoints in production.

For example, a service used only by applications on the same host should not listen on all network interfaces unless remote access is explicitly required. Binding to a loopback interface does not prevent access by other local processes.

See [NIST SP 800-53 Rev. 5, CM-7 (Least Functionality)](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final) for supporting guidance.

### Maintain Secure Service Configurations

Default configurations may enable functionality or access that is unnecessary for a particular deployment. Define and maintain a configuration baseline appropriate to the service.

- Review security-relevant defaults before deployment, including disabling unused default accounts and changing or disabling insecure default credentials.
- Disable unnecessary features and replace insecure settings with supported, secure alternatives.
- Restrict modification of service configuration files to authorized identities.
- Keep configuration changes under version control or another auditable change-management process, where practical.
- Review configuration changes during application updates and deployment changes.
- Avoid relying solely on configuration-file contents as proof of enforcement; verify the effective behavior of relevant security controls.

For example, when changing a service's permitted filesystem access, verify both that required application operations still succeed and that prohibited operations are denied.

See [NIST SP 800-53 Rev. 5, CM-6 (Configuration Settings)](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final) for supporting guidance.

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

See [NIST SP 800-53 Rev. 5, SC-7 (Boundary Protection)](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final) and [NIST SP 800-207 (Zero Trust Architecture)](https://csrc.nist.gov/pubs/sp/800/207/final) for supporting guidance.

### Protect Service Credentials and Sensitive Data

Services frequently use API keys, database credentials, certificates, and other sensitive information. Exposure of these secrets can allow unauthorized access to the service or dependent systems.

- Do not hardcode secrets in source code or commit them to version control. Provide credentials through an appropriate secrets-management mechanism.
- Limit access to secrets and the permissions they grant to the service identities and processes that require them.
- Avoid exposing secrets through command-line arguments, environment variables, logs, error messages, or other interfaces where they may be disclosed.
- Revoke and replace credentials when compromise is suspected, ensuring that exposed credentials are no longer valid. Follow organizational requirements for routine rotation.

For implementation and credential lifecycle guidance, see the [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html).

### Enable Security-Relevant Logging and Monitoring

Logs and monitoring provide information needed to identify service failures, investigate suspicious activity, and support incident response.

- Record security-relevant service events, such as authentication attempts, access-control failures, and significant configuration changes, with sufficient context for investigation.
- Avoid logging credentials or unnecessary sensitive information. Protect logs against unauthorized access, modification, and deletion, and handle untrusted log data safely.
- Monitor service failures, unexpected restarts, unusual resource consumption, and logging failures. Define retention and alerting requirements and verify that important events can be retrieved.

Logging alone does not prevent compromise. It supports detection and investigation when relevant events are collected, reviewed, and acted upon. See the [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) for detailed logging, protection, retention, and monitoring guidance.

### Limit Resource Consumption

A service that consumes excessive memory, CPU time, processes, or other resources can affect its own availability and that of other workloads.

- Identify the service's expected resource requirements under normal and peak load.
- Configure resource limits using controls supported by the operating system or service manager.
- Limit resource consumption without preventing legitimate workloads from completing.
- Test limits under representative workloads, including expected peak conditions.
- Monitor resource-limit events and resulting service failures, and adjust limits or recovery behavior when justified by operational evidence.

Resource limits can reduce the impact of some resource-exhaustion conditions, but they do not guarantee availability or replace application-level protections against denial-of-service attacks.

See [NIST SP 800-53 Rev. 5, SC-6 (Resource Availability)](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final) for the general principle and [systemd.resource-control(5)](https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html) for a Linux/systemd implementation.

### Validate Hardening Changes

Hardening should be introduced in a controlled manner. A configuration that appears restrictive may not provide the expected protection, and an overly restrictive configuration may interrupt legitimate operations.

- Identify the resources and operations required by the service before applying restrictions.
- Apply controls incrementally so that compatibility problems can be isolated.
- Verify that required service functionality continues to work.
- Where safe and practical, test that operations intended to be prohibited are actually denied.
- Record the platform version, configuration, test procedure, and results for reproducibility.
- Reassess hardening settings after significant application, operating-system, or service-manager changes.

See [NIST SP 800-53 Rev. 5, CA-2 (Control Assessments)](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final) for assessing whether controls operate as intended.

## Hardening Services with systemd

On Linux systems using systemd, service unit settings can restrict a service's privileges and access to system resources. Apply restrictions according to the service's requirements, and test them before deployment. These settings provide defense in depth; they do not replace secure application configuration, patching, or other operating-system security controls.

### Apply Least Privilege and Filesystem Restrictions

The following directives are useful starting points for services that support them:

| Directive | Purpose |
| --- | --- |
| `User=` | Run the service under a dedicated, non-root account rather than as root. |
| `NoNewPrivileges=yes` | Set the kernel's `no_new_privs` restriction for the service and its descendants, preventing privilege gains through mechanisms such as set-user-ID binaries and file capabilities during program execution. |
| `CapabilityBoundingSet=` | Restrict the Linux capabilities available to the service. An empty value removes all capabilities from the bounding set. |
| `ProtectSystem=strict` | Make most of the filesystem hierarchy read-only within the service's mount namespace, subject to documented exceptions and additional writable paths. |
| `StateDirectory=` | Create and manage a service state directory under `/var/lib`, with write access even when `ProtectSystem=strict` is enabled. |
| `PrivateTmp=yes` | Give the service private `/tmp` and `/var/tmp` directories, separate from the host's corresponding directories. |
| `ProtectHome=yes` | Make `/home`, `/root`, and `/run/user` inaccessible within the service's filesystem namespace. |

For example, a service that does not require root privileges, Linux capabilities, or access to home directories might use the following settings in its unit configuration:

```ini
[Service]
User=example-service
NoNewPrivileges=yes
CapabilityBoundingSet=
ProtectSystem=strict
StateDirectory=example-service
PrivateTmp=yes
ProtectHome=yes
```

This is an **illustrative configuration, not a universal baseline**. The service account must exist, and the restrictions must be compatible with the application's actual requirements. An empty capability bounding set can break operations requiring Linux capabilities. Filesystem restrictions can also prevent access to required configuration, data, sockets, or other resources.

Prefer explicitly managed writable directories, such as `StateDirectory=`, over granting broad write access. If the service needs additional writable paths, evaluate narrowly scoped exceptions rather than disabling filesystem protection altogether.

See the [systemd.exec manual](https://www.freedesktop.org/software/systemd/man/systemd.exec.html) for directive semantics, exceptions, and interactions.

### Apply and Validate Changes

Use a service-specific drop-in rather than editing a package-managed unit file directly:

```bash
sudo systemctl edit example.service
```

Add only the directives appropriate for that service. Saving changes through `systemctl edit` normally reloads the systemd manager configuration automatically. If unit files or drop-ins are modified manually, reload the configuration before restarting the service:

```bash
sudo systemctl daemon-reload
```

Restart the service and inspect its status and logs:

```bash
sudo systemctl restart example.service
systemctl status example.service
journalctl -u example.service --no-pager
```

Verify that the service still performs its required operations, including reading necessary files, writing persistent state, and handling expected requests. Where possible, test the relevant restriction directly: compare access or behavior before and after enabling a directive, while keeping other conditions unchanged.

The following command provides an additional review of a unit's sandboxing and security-related settings:

```bash
systemd-analyze security example.service
```

Its exposure score is a **heuristic assessment of unit settings**, not proof that the service is secure or vulnerable. It does not replace functional testing, application review, or verification of the effective restrictions.

Consult the [systemd-analyze manual](https://www.freedesktop.org/software/systemd/man/systemd-analyze.html) and the [systemctl manual](https://www.freedesktop.org/software/systemd/man/systemctl.html) for further details.

Review hardening settings when service requirements change, and validate compatibility with the systemd version and Linux kernel used in the deployment.

## Other Options

Service hardening can also use controls outside systemd. The appropriate mechanisms depend on the operating system, deployment environment, and service requirements. These controls can complement one another, but each must be configured and validated for the service being protected.

### AppArmor and SELinux

AppArmor and SELinux are Linux mandatory access control (MAC) mechanisms that can restrict what a service is permitted to access or perform, beyond traditional file permissions.

For AppArmor, apply an appropriate enforced profile to the service. Processes without an applicable profile may run unconfined. For SELinux, use an enforcing policy and ensure that the service runs in an appropriately confined domain with correct resource labels. An enabled security module does not necessarily mean that a particular service is confined.

See the [Linux kernel AppArmor documentation](https://docs.kernel.org/admin-guide/LSM/apparmor.html) and [Red Hat's SELinux documentation](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/).

### Firewalls and Network Namespaces

Use host or network firewalls to restrict traffic to the ports, protocols, sources, and destinations required by the service. Consider both inbound and outbound traffic according to the service's communication requirements.

Linux network namespaces can provide separate network interfaces, routing tables, and network stacks for services. However, a network namespace alone does not establish an appropriate traffic-filtering policy. Configure and verify network connectivity and firewall rules explicitly.

See the [nftables documentation](https://wiki.nftables.org/wiki-nftables/index.php/Main_Page) and [network_namespaces(7)](https://man7.org/linux/man-pages/man7/network_namespaces.7.html).

### Application Sandboxing

Application sandboxing tools, such as Firejail, can restrict a service's execution environment using Linux namespaces, seccomp filters, and capability controls.

Evaluate the sandbox's privileges, configuration, security implications, and compatibility before deployment. A sandboxing tool does not automatically provide complete isolation, and some implementations introduce their own privileged components.

See the [Firejail manual](https://man7.org/linux/man-pages/man1/firejail.1.html).

### Landlock

Landlock is a Linux security module that allows processes, including unprivileged processes, to apply additional restrictions to themselves and their descendants.

Developers can use Landlock to limit supported operations on resources such as files. Available restrictions depend on the running kernel and supported Landlock ABI version. Applications should check supported features rather than assume that every restriction is available.

See the [Linux kernel Landlock documentation](https://docs.kernel.org/userspace-api/landlock.html).

### eBPF-Based Security Controls

Security tools built on extended Berkeley Packet Filter (eBPF) can support runtime monitoring and, with appropriate kernel facilities such as BPF LSM, enforcement of security policies.

The protection provided depends on the specific tool, its policies, privileges, and kernel support. eBPF itself is not a security policy, and monitoring alone does not prevent prohibited operations.

See the [Linux kernel BPF LSM documentation](https://docs.kernel.org/bpf/prog_lsm.html).

### Containers

Containers can provide additional isolation for services through Linux namespaces, control groups, and other security mechanisms. However, containerization alone does not guarantee that a service is secure. Apply least privilege, restrict unnecessary capabilities, and avoid privileged containers unless explicitly required.

For Docker-specific hardening guidance, see the [OWASP Docker Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html).

## References

Primary references and relevant OWASP Cheat Sheets are linked alongside the recommendations they support. For the general security-control framework, see [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final).
