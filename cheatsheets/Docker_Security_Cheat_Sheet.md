# Docker Security Cheat Sheet

## Introduction

Docker is the most popular containerization technology. When used correctly, it can enhance security compared to running applications directly on the host system. However, certain misconfigurations can reduce security levels or introduce new vulnerabilities.

The aim of this cheat sheet is to provide a straightforward list of common security errors and best practices to assist in securing your Docker containers.

## Rules

### RULE \#0 - Keep Host and Docker up to date

To protect against known container escape vulnerabilities like [Leaky Vessels](https://snyk.io/blog/cve-2024-21626-runc-process-cwd-container-breakout/), which typically result in the attacker gaining root access to the host, it's vital to keep both the host and Docker up to date. This includes regularly updating the host kernel as well as the Docker Engine.

This is due to the fact that containers share the host's kernel. If the host's kernel is vulnerable, the containers are also vulnerable. For example, the kernel privilege escalation exploit [Dirty COW](https://github.com/scumjr/dirtycow-vdso) executed inside a well-insulated container would still result in root access on a vulnerable host.

### RULE \#1 - Do not expose the Docker daemon socket (even to the containers)

Docker socket */var/run/docker.sock* is the UNIX socket that Docker is listening to. This is the primary entry point for the Docker API. The owner of this socket is root. Giving someone access to it is equivalent to giving unrestricted root access to your host.

**Do not enable *tcp* Docker daemon socket.** If you are running docker daemon with `-H tcp://0.0.0.0:XXX` or similar you are exposing un-encrypted and unauthenticated direct access to the Docker daemon, if the host is internet connected this means the docker daemon on your computer can be used by anyone from the public internet.
If you really, **really** have to do this, you should secure it. Check how to do this [following Docker official documentation](https://docs.docker.com/engine/reference/commandline/dockerd/#daemon-socket-option).

**Do not expose */var/run/docker.sock* to other containers**. If you are running your docker image with `-v /var/run/docker.sock://var/run/docker.sock` or similar, you should change it. Remember that mounting the socket read-only is not a solution but only makes it harder to exploit. Equivalent in the docker compose file is something like this:

```yaml
    volumes:
    - "/var/run/docker.sock:/var/run/docker.sock"
```

### RULE \#2 - Set a user

Configuring the container to use an unprivileged user is the best way to prevent privilege escalation attacks. This can be accomplished in three different ways as follows:

1. During runtime using `-u` option of `docker run` command e.g.:

```bash
docker run -u 4000 alpine
```

2. During build time. Simply add user in Dockerfile and use it. For example:

```dockerfile
FROM alpine
RUN groupadd -r myuser && useradd -r -g myuser myuser
#    <HERE DO WHAT YOU HAVE TO DO AS A ROOT USER LIKE INSTALLING PACKAGES ETC.>
USER myuser
```

3. Enable user namespace support (`--userns-remap=default`) in [Docker daemon](https://docs.docker.com/engine/security/userns-remap/#enable-userns-remap-on-the-daemon)

More information about this topic can be found at [Docker official documentation](https://docs.docker.com/engine/security/userns-remap/). For additional security, you can also run in rootless mode, which is discussed in [Rule \#11](#rule-11---run-docker-in-rootless-mode).

In Kubernetes, this can be configured in [Security Context](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/) using the `runAsUser` field with the user ID e.g:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: example
spec:
  containers:
  - name: example
    image: gcr.io/google-samples/node-hello:1.0
    securityContext:
      runAsUser: 4000 # <-- This is the pod user ID
```

As a Kubernetes cluster administrator, you can configure a hardened default using the [`Restricted` level](https://kubernetes.io/docs/concepts/security/pod-security-standards/#restricted) with built-in [Pod Security admission controller](https://kubernetes.io/docs/concepts/security/pod-security-admission/), if greater customization is desired consider using [Admission Webhooks](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#what-are-admission-webhooks) or a [third party alternative](https://kubernetes.io/docs/concepts/security/pod-security-standards/#alternatives).

### RULE \#3 - Limit capabilities (Grant only specific capabilities, needed by a container)

[Linux kernel capabilities](http://man7.org/linux/man-pages/man7/capabilities.7.html) are a set of privileges that can be used by privileged. Docker, by default, runs with only a  subset of capabilities.
You can change it and drop some capabilities (using `--cap-drop`) to harden your docker containers, or add some capabilities (using `--cap-add`) if needed.
Remember not to run containers with the `--privileged` flag - this will add ALL Linux kernel capabilities to the container.

The most secure setup is to drop all capabilities `--cap-drop all` and then add only required ones. For example:

```bash
docker run --cap-drop all --cap-add CHOWN alpine
```

**And remember: Do not run containers with the *--privileged* flag!!!**

In Kubernetes this can be configured in [Security Context](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/) using `capabilities` field e.g:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: example
spec:
  containers:
  - name: example
    image: gcr.io/google-samples/node-hello:1.0
    securityContext:
        capabilities:
            drop:
                - ALL
            add: ["CHOWN"]
```

As a Kubernetes cluster administrator, you can configure a hardened default using the [`Restricted` level](https://kubernetes.io/docs/concepts/security/pod-security-standards/#restricted) with built-in [Pod Security admission controller](https://kubernetes.io/docs/concepts/security/pod-security-admission/), if greater customization is desired consider using [Admission Webhooks](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#what-are-admission-webhooks) or a [third party alternative](https://kubernetes.io/docs/concepts/security/pod-security-standards/#alternatives).

### RULE \#4 - Prevent in-container privilege escalation

Always run your docker images with `--security-opt=no-new-privileges` in order to prevent privilege escalation. This will prevent the container from gaining new privileges via `setuid` or `setgid` binaries.

In Kubernetes, this can be configured in [Security Context](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/) using `allowPrivilegeEscalation` field e.g.:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: example
spec:
  containers:
  - name: example
    image: gcr.io/google-samples/node-hello:1.0
    securityContext:
      allowPrivilegeEscalation: false
```

As a Kubernetes cluster administrator, you can configure a hardened default using the [`Restricted` level](https://kubernetes.io/docs/concepts/security/pod-security-standards/#restricted) with built-in [Pod Security admission controller](https://kubernetes.io/docs/concepts/security/pod-security-admission/), if greater customization is desired consider using [Admission Webhooks](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#what-are-admission-webhooks) or a [third party alternative](https://kubernetes.io/docs/concepts/security/pod-security-standards/#alternatives).

### RULE \#5 - Be mindful of Inter-Container Connectivity

Inter-Container Connectivity (icc) is enabled by default, allowing all containers to communicate with each other through the [`docker0` bridged network](https://docs.docker.com/network/drivers/bridge/). Instead of using the `--icc=false` flag with the Docker daemon, which completely disables inter-container communication, consider defining specific network configurations. This can be achieved by creating custom Docker networks and specifying which containers should be attached to them. This method provides more granular control over container communication.

For detailed guidance on configuring Docker networks for container communication, refer to the [Docker Documentation](https://docs.docker.com/network/#communication-between-containers).

In Kubernetes environments, [Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/) can be used to define rules that regulate pod interactions within the cluster. These policies provide a robust framework to control how pods communicate with each other and with other network endpoints. Additionally, [Network Policy Editor](https://networkpolicy.io/) simplifies the creation and management of network policies, making it more accessible to define complex networking rules through a user-friendly interface.

### RULE \#6 - Use Linux Security Module (seccomp, AppArmor, or SELinux)

**First of all, do not disable default security profile!**

Consider using security profile like [seccomp](https://docs.docker.com/engine/security/seccomp/) or [AppArmor](https://docs.docker.com/engine/security/apparmor/).

Instructions how to do this inside Kubernetes can be found at [Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tutorials/security/seccomp/).

### RULE \#7 - Limit resources (memory, CPU, file descriptors, processes, restarts)

The best way to avoid DoS attacks is by limiting resources. You can limit [memory](https://docs.docker.com/config/containers/resource_constraints/#memory), [CPU](https://docs.docker.com/config/containers/resource_constraints/#cpu), maximum number of restarts (`--restart=on-failure:<number_of_restarts>`), maximum number of file descriptors (`--ulimit nofile=<number>`) and maximum number of processes (`--ulimit nproc=<number>`).

[Check documentation for more details about ulimits](https://docs.docker.com/engine/reference/commandline/run/#set-ulimits-in-container---ulimit)

You can also do this for Kubernetes: [Assign Memory Resources to Containers and Pods](https://kubernetes.io/docs/tasks/configure-pod-container/assign-memory-resource/), [Assign CPU Resources to Containers and Pods](https://kubernetes.io/docs/tasks/configure-pod-container/assign-cpu-resource/) and [Assign Extended Resources to a Container](https://kubernetes.io/docs/tasks/configure-pod-container/extended-resource/)

### RULE \#8 - Set filesystem and volumes to read-only

**Run containers with a read-only filesystem** using `--read-only` flag. For example:

```bash
docker run --read-only alpine sh -c 'echo "whatever" > /tmp'
```

If an application inside a container has to save something temporarily, combine `--read-only` flag with `--tmpfs` like this:

```bash
docker run --read-only --tmpfs /tmp alpine sh -c 'echo "whatever" > /tmp/file'
```

The Docker Compose `compose.yml` equivalent would be:

```yaml
version: "3"
services:
  alpine:
    image: alpine
    read_only: true
```

Equivalent in Kubernetes in [Security Context](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/):

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: example
spec:
  containers:
  - name: example
    image: gcr.io/google-samples/node-hello:1.0
    securityContext:
      readOnlyRootFilesystem: true
```

In addition, if the volume is mounted only for reading **mount them as a read-only**
It can be done by appending `:ro` to the `-v` like this:

```bash
docker run -v volume-name:/path/in/container:ro alpine
```

Or by using `--mount` option:

```bash
docker run --mount source=volume-name,destination=/path/in/container,readonly alpine
```

### RULE \#9 - Integrate container scanning tools into your CI/CD pipeline

[CI/CD pipelines](CI_CD_Security_Cheat_Sheet.md) are a crucial part of the software development lifecycle and should include various security checks such as lint checks, static code analysis, and container scanning.

Many issues can be prevented by following some best practices when writing the Dockerfile. However, adding a security linter as a step in the build pipeline can go a long way in avoiding further headaches. Some issues that are commonly checked are:

- Ensure a `USER` directive is specified
- Ensure the base image version is pinned
- Ensure the OS packages versions are pinned
- Avoid the use of `ADD` in favor of `COPY`
- Avoid curl bashing in `RUN` directives

References:

- [Docker Baselines on DevSec](https://dev-sec.io/baselines/docker/)
- [Use the Docker command line](https://docs.docker.com/engine/reference/commandline/cli/)
- [Overview of Docker Compose v2 CLI](https://docs.docker.com/compose/reference/overview/)
- [Configuring Logging Drivers](https://docs.docker.com/config/containers/logging/configure/)
- [View logs for a container or service](https://docs.docker.com/config/containers/logging/)
- [Dockerfile Security Best Practices](https://cloudberry.engineering/article/dockerfile-security-best-practices/)

 Container scanning tools are especially important as part of a successful security strategy. They can detect known vulnerabilities, secrets and misconfigurations in container images and provide a report of the findings with recommendations on how to fix them. Some examples of popular container scanning tools are:

- Free
    - [Clair](https://github.com/coreos/clair)
    - [ThreatMapper](https://github.com/deepfence/ThreatMapper)
    - [Trivy](https://github.com/aquasecurity/trivy)
- Commercial
    - [Snyk](https://snyk.io/) **(open source and free option available)**
    - [Anchore](https://github.com/anchore/grype/) **(open source and free option available)**
    - [Docker Scout](https://www.docker.com/products/docker-scout/) **(open source and free option available)**
    - [JFrog XRay](https://jfrog.com/xray/)
    - [Qualys](https://www.qualys.com/apps/container-security/)

To detect secrets in images:

- [ggshield](https://github.com/GitGuardian/ggshield) **(open source and free option available)**
- [SecretScanner](https://github.com/deepfence/SecretScanner) **(open source)**

To detect misconfigurations in Kubernetes:

- [kubeaudit](https://github.com/Shopify/kubeaudit)
- [kubesec.io](https://kubesec.io/)
- [kube-bench](https://github.com/aquasecurity/kube-bench)

To detect misconfigurations in Docker:

- [inspec.io](https://www.inspec.io/docs/reference/resources/docker/)
- [dev-sec.io](https://dev-sec.io/baselines/docker/)
- [Docker Bench for Security](https://github.com/docker/docker-bench-security)

### RULE \#10 - Keep the Docker daemon logging level at `info`

By default, the Docker daemon is configured to have a base logging level of `info`. This can be verified by checking the daemon configuration file `/etc/docker/daemon.json` for the`log-level` key. If the key is not present, the default logging level is `info`. Additionally, if the docker daemon is started with the `--log-level` option, the value of the `log-level` key in the configuration file will be overridden. To check if the Docker daemon is running with a different log level, you can use the following command:

```bash
ps aux | grep '[d]ockerd.*--log-level' | awk '{for(i=1;i<=NF;i++) if ($i ~ /--log-level/) print $i}'
```

Setting an appropriate log level, configures the Docker daemon to log events that you would want to review later. A base log level of 'info' and above would capture all logs except the debug logs. Until and unless required, you should not run docker daemon at the 'debug' log level.

### Rule \#11 - Run Docker in rootless mode

Rootless mode ensures that the Docker daemon and containers are running as an unprivileged user, which means that even if an attacker breaks out of the container, they will not have root privileges on the host, which in turn substantially limits the attack surface. This is different to [userns-remap](#rule-2---set-a-user) mode, where the daemon still operates with root privileges.

Evaluate the [specific requirements](Attack_Surface_Analysis_Cheat_Sheet.md) and [security posture](Threat_Modeling_Cheat_Sheet.md) of your environment to determine if rootless mode is the best choice for you. For environments where security is a paramount concern and the [limitations of rootless mode](https://docs.docker.com/engine/security/rootless/#known-limitations) do not interfere with operational requirements, it is a strongly recommended configuration. Alternatively consider using [Podman](#podman-as-an-alternative-to-docker) as an alternative to Docker.

> Rootless mode allows running the Docker daemon and containers as a non-root user to mitigate potential vulnerabilities in the daemon and the container runtime.
> Rootless mode does not require root privileges even during the installation of the Docker daemon, as long as the [prerequisites](https://docs.docker.com/engine/security/rootless/#prerequisites) are met.

Read more about rootless mode and its limitations, installation and usage instructions on [Docker documentation](https://docs.docker.com/engine/security/rootless/) page.

### RULE \#12 - Utilize Docker Secrets for Sensitive Data Management

Docker Secrets provide a secure way to store and manage sensitive data such as passwords, tokens, and SSH keys. Using Docker Secrets helps in avoiding the exposure of sensitive data in container images or in runtime commands.

```bash
docker secret create my_secret /path/to/super-secret-data.txt
docker service create --name web --secret my_secret nginx:latest
```

Or for Docker Compose:

```yaml
  version: "3.8"
  secrets:
    my_secret:
      file: ./super-secret-data.txt
  services:
    web:
      image: nginx:latest
      secrets:
        - my_secret
```

While Docker Secrets generally provide a secure way to manage sensitive data in Docker environments, this approach is not recommended for Kubernetes, where secrets are stored in plaintext by default. In Kubernetes, consider using additional security measures such as etcd encryption, or third-party tools. Refer to the [Secrets Management Cheat Sheet](Secrets_Management_Cheat_Sheet.md) for more information.

### RULE \#13 - Enhance Supply Chain Security

Building on the principles in [Rule \#9](#rule-9---integrate-container-scanning-tools-into-your-cicd-pipeline), enhancing supply chain security involves implementing additional measures to secure the entire lifecycle of container images from creation to deployment. Some of the key practices include:

- [Image Provenance](https://slsa.dev/spec/v1.0/provenance): Document the origin and history of container images to ensure traceability and integrity.
- [SBOM Generation](https://cyclonedx.org/guides/CycloneDX%20One%20Pager.pdf): Create a Software Bill of Materials (SBOM) for each image, detailing all components, libraries, and dependencies for transparency and vulnerability management.
- [Image Signing](https://github.com/notaryproject/notary): Digitally sign images to verify their integrity and authenticity, establishing trust in their security.
- [Trusted Registry](https://snyk.io/learn/container-security/container-registry-security/): Store the documented, signed images with their SBOMs in a secure registry that enforces strict [access controls](Access_Control_Cheat_Sheet.md) and supports metadata management.
- [Secure Deployment](https://www.openpolicyagent.org/docs/latest/#overview): Implement secure deployment polices, such as image validation, runtime security, and continuous monitoring, to ensure the security of the deployed images.

## Podman as an alternative to Docker

[Podman](https://podman.io/) is an OCI-compliant, open-source container management tool developed by [Red Hat](https://www.redhat.com/en) that provides a Docker-compatible command-line interface and a desktop application for managing containers. It is designed to be a more secure and lightweight alternative to Docker, especially for environments where secure defaults are preferred. Some of the security benefits of Podman include:

1. Daemonless Architecture: Unlike Docker, which requires a central daemon (dockerd) to create, run, and manage containers, Podman directly employs the fork-exec model. When a user requests to start a container, Podman forks from the current process, then the child process execs into the container's runtime.
2. Rootless Containers: The fork-exec model facilitates Podman's ability to run containers without requiring root privileges. When a non-root user initiates a container start, Podman forks and execs under the user's permissions.
3. SELinux Integration: Podman is built to work with SELinux, which provides an additional layer of security by enforcing mandatory access controls on containers and their interactions with the host system.

## References and Further Reading

[OWASP Docker Top 10](https://github.com/OWASP/Docker-Security)
[Docker Security Best Practices](https://docs.docker.com/develop/security-best-practices/)
[Docker Engine Security](https://docs.docker.com/engine/security/)
[Kubernetes Security Cheat Sheet](Kubernetes_Security_Cheat_Sheet.md)
[SLSA - Supply Chain Levels for Software Artifacts](https://slsa.dev/)
[Sigstore](https://sigstore.dev/)
[Docker Build Attestation](https://docs.docker.com/build/attestations/)
[Docker Content Trust](https://docs.docker.com/engine/security/trust/)
