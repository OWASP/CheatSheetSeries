# Service Hardening Cheat Sheet

## Introduction

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

The following principles apply regardless of the service manager used. Use the equivalent controls provided by the target platform and verify that the configured restrictions are enforced.

| Principle | Recommendation | Further Guidance |
| --- | --- | --- |
| Keep Software and Dependencies Updated | Use supported software versions, maintain a component inventory, and prioritize security updates according to risk and exposure. | [Vulnerable Dependency Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html) |
| Apply Least Privilege | Use dedicated, non-administrative service identities and grant only the permissions required for operation. | [Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html) |
| Reduce the Attack Surface | Disable unnecessary services, features, modules, and administrative or debugging interfaces. | [Attack Surface Analysis Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.html) |
| Maintain Secure Configurations | Review security defaults, restrict configuration changes, and maintain an auditable configuration baseline. | [NIST SP 800-53 Rev. 5, CM-6](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf) |
| Restrict Network Communication | Limit inbound and outbound traffic to operational requirements. Prefer Unix domain sockets for local communication where supported, or bind local-only services to loopback interfaces. | [Network Segmentation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Network_Segmentation_Cheat_Sheet.html) |
| Protect Credentials and Sensitive Data | Avoid hardcoded secrets, use appropriate secrets-management mechanisms, and restrict access to sensitive data. | [Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html) |
| Enable Security-Relevant Logging and Monitoring | Record security-relevant events, protect logs, and monitor service failures and suspicious activity. | [Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) |
| Limit Resource Consumption | Configure resource limits according to service requirements and test them under representative workloads. | [Denial of Service Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html) |

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
| `ProtectProc=invisible` | Hide processes belonging to other users from the service's `/proc` view, subject to documented limitations. |
| `ProtectControlGroups=yes` | Make the control-group filesystem read-only within the service's mount namespace. |
| `PrivateDevices=yes` | Provide a restricted `/dev` environment that limits access to physical devices. |
| `ProtectKernelTunables=yes` | Restrict modification of kernel tunables through filesystem interfaces such as `/proc/sys` and `/sys`. |

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
ProtectProc=invisible
ProtectControlGroups=yes
PrivateDevices=yes
ProtectKernelTunables=yes
```

This is an **illustrative configuration, not a universal baseline**. The service account must exist, and the restrictions must be compatible with the application's actual requirements. An empty capability bounding set can break operations requiring Linux capabilities. Filesystem restrictions can also prevent access to required configuration, data, sockets, or other resources.

Prefer explicitly managed writable directories, such as `StateDirectory=`, over granting broad write access. If the service needs additional writable paths, evaluate narrowly scoped exceptions using `ReadWritePaths=` rather than disabling filesystem protection altogether.

`ProtectSystem=strict` restricts filesystem writes but does not prevent reading accessible files. The `/dev`, `/proc`, and `/sys` subtrees are excluded from its read-only protection. Additional controls may be needed to restrict access to these resources. Writable-directory exceptions and other filesystem namespace limitations must also be considered.

See the [systemd.exec manual](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html) for directive semantics, exceptions, and interactions.

### Restrict Network Communication

systemd provides controls that can restrict socket creation and IP communication. Combined with socket activation, these controls can allow a service to handle TCP connections passed by systemd while restricting its ability to create additional network sockets.

| Directive | Purpose |
| --- | --- |
| `RestrictAddressFamilies=` | Restrict the socket address families available through the `socket(2)` system call on supported architectures. Allow only those required by the service, such as `AF_UNIX`, `AF_INET`, and `AF_INET6`. |
| `IPAddressDeny=` / `IPAddressAllow=` | Filter inbound and outbound IPv4 and IPv6 traffic using denied and permitted IP address ranges. |

To implement an IP address allowlist, use `IPAddressDeny=any` together with `IPAddressAllow=` entries for the required IP address ranges. Using `IPAddressAllow=` alone does not restrict unmatched traffic unless an applicable deny policy is configured.

`RestrictAddressFamilies=` only filters the `socket(2)` system call. It does not restrict sockets passed to a service through socket activation, sockets created through `socketpair(2)`, or socket creation through `io_uring`. Filtering also has architecture-specific limitations. Use `SystemCallArchitectures=native` where compatible to reduce the risk of bypasses through alternative system-call ABIs.

IP address filtering requires supported kernel functionality and may have no effect where the necessary eBPF support is unavailable. For socket-activated services, consider the network restrictions on the socket and service units separately, according to their respective communication requirements.

See [systemd.exec(5)](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html) and [systemd.resource-control(5)](https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html) for network restriction options and their limitations.

### Restrict System Calls

systemd can restrict the system calls available to a service using seccomp filtering.

| Directive | Purpose |
| --- | --- |
| `SystemCallFilter=@system-service` | Apply a system-call allowlist using the `@system-service` group. System calls outside the permitted set are blocked, subject to systemd's filtering behavior and exceptions. |
| `SystemCallArchitectures=native` | Restrict system calls to the native architecture, reducing opportunities to bypass system-call restrictions through alternative ABIs. |

This filter is suitable for consideration by many system services, but it can prevent applications from using required system calls. Test compatibility before enabling it. By default, prohibited system calls cause the affected process to receive `SIGSYS`.

Use `SystemCallArchitectures=native` where compatible, as it may prevent applications that require alternative system-call ABIs from functioning correctly.

See [systemd.exec(5)](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html) for system-call filtering behavior and supported system-call groups.

### Limit Service Resource Consumption

systemd can use Linux control groups to limit resources consumed by a service.

| Directive | Purpose |
| --- | --- |
| `MemoryHigh=` | Set a memory usage threshold above which the service is subject to increased memory reclaim and throttling. |
| `MemoryMax=` | Set an absolute memory usage limit for the service. Exceeding the limit can trigger out-of-memory termination within the unit. |
| `TasksMax=` | Limit the number of tasks, including processes and threads, that the service can create. |

Select limits based on the service's expected workload and test them under representative conditions. `MemoryMax=` is a final safeguard rather than a substitute for appropriate memory management; `MemoryHigh=` is recommended as the primary memory-control mechanism.

See [systemd.resource-control(5)](https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html) for resource limits and control-group requirements.

### Protect Service Credentials

Do not pass secrets through `Environment=` or `EnvironmentFile=`. systemd warns that environment variables may be exposed through D-Bus IPC and inherited by processes that should not receive them.

Use `LoadCredential=` to provide credentials through a restricted, read-only credential directory instead. The service must be configured to read the supplied credential files.

See [systemd.exec(5): Credentials](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#Credentials) for credential-loading options and their security properties.

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

Consult the [systemd-analyze manual](https://www.freedesktop.org/software/systemd/man/latest/systemd-analyze.html) and the [systemctl manual](https://www.freedesktop.org/software/systemd/man/latest/systemctl.html) for further details.

Review hardening settings when service requirements change, and validate compatibility with the systemd version and Linux kernel used in the deployment.

## Other Options

Service hardening can also use controls outside systemd. The appropriate mechanisms depend on the operating system, deployment environment, and service requirements. These controls can complement one another, but each must be configured and validated for the service being protected.

### AppArmor and SELinux

AppArmor and SELinux are Linux mandatory access control (MAC) mechanisms that can restrict what a service is permitted to access or perform, beyond traditional file permissions.

For AppArmor, apply an appropriate enforced profile to the service. Processes without an applicable profile may run unconfined. For SELinux, use an enforcing policy and ensure that the service runs in an appropriately confined domain with correct resource labels. An enabled security module does not necessarily mean that a particular service is confined.

See the [Linux kernel AppArmor documentation](https://docs.kernel.org/admin-guide/LSM/apparmor.html) and [Red Hat's SELinux documentation](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/).

### Firewalls and Network Namespaces

Use host or network firewalls to restrict traffic to the ports, protocols, sources, and destinations required by the service. Consider both inbound and outbound traffic according to the service's communication requirements.

On Linux, nftables can apply service-specific outbound traffic restrictions using the `output` chain and socket user identity matching (`meta skuid`). This can help restrict network connections initiated by services running under dedicated user accounts. When multiple services share an account, user-based rules cannot distinguish between them.

Linux network namespaces can provide separate network interfaces, routing tables, and network stacks for services. However, a network namespace alone does not establish an appropriate traffic-filtering policy. Configure and verify network connectivity and firewall rules explicitly.

See the [nftables packet metainformation matching documentation](https://wiki.nftables.org/wiki-nftables/index.php/Matching_packet_metainformation) and [network_namespaces(7)](https://man7.org/linux/man-pages/man7/network_namespaces.7.html).

### Application Sandboxing

Application sandboxing tools, such as Firejail, can restrict a service's execution environment using Linux namespaces, seccomp filters, and capability controls.

Evaluate the sandbox's privileges, configuration, security implications, and compatibility before deployment. A sandboxing tool does not automatically provide complete isolation. Firejail uses a set-user-ID (SUID) root executable, which introduces an additional privileged component whose security must also be considered.

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

- [systemd.exec(5) — Execution Environment Configuration](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html)
- [systemd.resource-control(5) — Resource Control Unit Settings](https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html)
- [NIST SP 800-53 Rev. 5 — Security and Privacy Controls](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf)
