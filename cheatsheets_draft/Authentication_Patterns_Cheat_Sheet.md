# Authentication Patterns

Authentication can be handled at different layers of a system’s architecture. Broadly speaking, there are three main approaches:

- **Service-Level:** responsibility for verifying identity is delegated to each service, or to a proxy tightly coupled to it.
- **Edge-Level:** authentication is centralized in a shared component at the system boundary.
- **Kernel-Level:** authentication is performed in the operating system kernel, using cryptographic identities enforced at the transport layer.

Each approach comes with trade-offs in terms of scalability, consistency, and operational complexity.

Authentication applies to different types of actors. These can be **external** actors, such as end users or client applications outside the system, or **internal** actors, such as services, or other workloads, and even nodes, the workloads are running on, all operating within the system boundary. The same architectural patterns can often be applied to both kinds of actors, though the technical mechanisms and trust assumptions differ.

Before diving into these patterns, it is also important to clarify what is being verified. Most systems handle authentication in two phases:

- **Primary Authentication:** This is the process of directly verifying credentials tied to authentication factors, such as passwords, biometric inputs, or signed challenges like WebAuthn assertions. For internal actors, this might involve validating machine-issued certificates, SPIFFE IDs, or workload authentication data issued by the platform. This step establishes identity by proving control over a credential and linking it to a known identity, such as a user account or a system identity.
- **Authentication Proof Verification:** After successful primary authentication, the system typically issues an authentication proof — a reusable artifact that confirms the authenticated identity in subsequent interactions. At the application layer, this might take the form of a session cookie, token, or assertion. At lower layers, it can take the form of cryptographic session state, such as a TLS session key, IPsec Security Association, or similar. Verifying the proof ensures that the identity remains trusted without repeating primary authentication.

Where this distinction is not relevant, the term **authentication data** is used to refer collectively to both primary credentials and authentication proofs. The following subsections use this term when referring to either or both phases.

The patterns described below differ in **what** is verified (credentials in primary authentication vs. authentication proofs), **where** verification happens, and **which** implications this has for system design and trust boundaries.

## Service-Level Embedded Authentication

In this pattern, each service is responsible for handling primary authentication internally. This includes managing identities and credentials, performing credential verification, and implementing authentication workflows. Common credential types used in this setup include username/password, API keys, and similar simple methods. All authentication logic and subject related data storage are embedded directly within the service, often through custom code or built-in libraries.

![Service-Level Embedded Authentication](../assets/Service_Level_Embedded_Authentication.svg)

### Pros

- **Simplicity:** Each service is fully self-contained and does not rely on external systems or additional infrastructure for authentication.
- **Customization freedom:** Authentication behavior can be adapted to service-specific requirements without external constraints.
- **Support for external and internal actors:** Since the implementation of a service can fully control all authentication related functionality, orchestration of different authentication contexts - like authentication of internal services and external users - is possible, but comes with a huge complexity (see also the authentication orchestration con below).

### Cons

- **Inconsistency:** Authentication behavior, credential storage, and authentication flows differ across services, leading to fragmentation and a poor user experience, incl. not being able to support SSO.
- **Security risk:** Authentication code is duplicated across services, increasing the risk of vulnerabilities and complicating audits.
- **Maintenance burden:** Changing authentication methods (e.g., introducing MFA) requires updates across all affected services.
- **Limited scalability:** Each service is responsible for identity management, complicating secure identity management across a large system. This makes the pattern unsuitable for scalable service-to-service authentication.
- **Limited observability and governance:** Suspicious activity often goes undetected without centralized monitoring. Credential reuse, account compromise, or brute-force attacks on one service remain invisible to others, hindering coordinated detection and response.
- **Authentication orchestration:** Handling of multi-principal subjects — that is supporting multiple authentication configurations, including protocol chaining and subject-specific variations, required to support different contexts, like first- and third-party, or external client and service-to-service authentication — adds significant complexity.
- **Coupling of external authentication data with internal trust assumptions:** Using the same authentication data for both external clients and internal services increases the risk of leakage and unauthorized access. If an internal service is inadvertently exposed because of a misconfiguration or an attacker gaining internal access, the leaked authentication data may enable unauthorized access to sensitive resources.

## Service-Level Code-Mediated Authentication

This pattern addresses key limitations of the [Service-Level Embedded Authentication](#service-level-embedded-authentication), such as fragmented identity management, duplicated credential stores, and lack of support for SSO. In this pattern, the service no longer verifies credentials directly. Instead, an external Identity Provider (IdP) authenticates the subject and issues authentication proofs. The service verifies these internally and extracts identity attributes for request processing.

![Service-Level Code-Mediated Authentication](../assets/Service_Level_Code_Mediated_Authentication.svg)

### Pros

- **SSO support:** Identity and credential lifecycle is consolidated in the IdP, enabling Single Sign-On and reducing duplication.
- **Lower security risks:** Centralized authentication reduces the attack surface related to credential handling.
- **Improved user experience:** Consistent authentication flows and session handling across services.
- **Interoperability:** Widely adopted protocols like [OIDC](https://openid.net/specs/openid-connect-core-1_0.html) and [SAML](https://www.oasis-open.org/standard/saml/) provide flexibility and broad integration possibilities with various IdPs.
- **Customization freedom:** Services can still tailor authentication behavior to specific needs, for example, in environments where standards like OIDC are not applicable.
- **Support for external and internal actors:** Since the implementation of a service can fully control all authentication related functionality, orchestration of different authentication contexts - like authentication of internal services and external users - is possible, but comes with a huge complexity (see also the authentication orchestration con below).

### Cons

- **Protocol handling overhead:** Each service must implement and maintain logic for authentication proof verification and protocol-specific behavior.
- **Misconfiguration risks:** Incorrect verification logic, such as missing expiration checks or improper cryptography use, can introduce sever security vulnerabilities.
- **Authentication orchestration:** Handling of multi-principal subjects — that is supporting multiple authentication configurations, including protocol chaining and subject-specific variations, required to support different contexts, like first- and third-party, or external client and service-to-service authentication, adds significant complexity.
- **Coupling of external authentication data with internal trust assumptions:** Using the same authentication data for both external clients and internal services increases the risk of leakage and unauthorized access. If an internal service is inadvertently exposed because of a misconfiguration or an attacker gaining internal access, the leaked authentication data may enable unauthorized access to sensitive resources.

## Service-Level Proxy-Mediated Authentication

This pattern builds on the [previous pattern](#service-level-code-mediated-authentication) but further reduces complexity within services by offloading authentication-related logic to a dedicated proxy deployed as a sidecar alongside the service. The proxy operates in front of the application, forwards requests locally to it, performs verification of authentication proofs with the Identity Provider (IdP), and injects identity context, typically via headers, into requests before forwarding them to the service.

![Service-Level Proxy-Mediated Authentication](../assets/Service_Level_Proxy_Mediated_Authentication.svg)

### Pros

- **SSO support:** Identity and credential lifecycle is consolidated in the IdP, enabling Single Sign-On and reducing duplication.
- **Lower security risks:** Centralized authentication reduces the attack surface related to credential handling.
- **Improved user experience:** Consistent authentication flows and session handling across services.
- **Interoperability:** Widely adopted protocols like [OIDC](https://openid.net/specs/openid-connect-core-1_0.html) and [SAML](https://www.oasis-open.org/standard/saml/) provide flexibility and broad integration possibilities with various IdPs.
- **Separation of concerns:** Removes authentication-related logic from application code by offloading it to the proxy, simplifying service development and reducing maintenance effort.
- **Consistent behavior:** Identity verification and protocol handling in the proxy ensure uniform behavior across services.
- **Improved security posture:** Reduces the risk of implementation flaws by consolidating authentication-related logic into a dedicated, hardened component.
- **Authentication orchestration:** Some proxies support multiple authentication configurations, including protocol chaining and subject-specific variations. This enables support for different contexts, such as first- and third-party access, or a mix of external clients and internal services.
- **Strong foundation for service-to-service trust:** Enables [Zero Trust](https://csrc.nist.gov/pubs/sp/800/207/final) networking with workload identity, typically realized via systems like [SPIFFE/SPIRE](https://spiffe.io/), which define workload identities embedded in [X.509 certificates](https://www.rfc-editor.org/rfc/rfc5280) used for [mTLS](https://www.rfc-editor.org/rfc/rfc8446) authentication between services.

### Cons

- **Operational complexity:** Requires deployment and maintenance of additional components per microservice, leading to higher resource usage and costs.
- **Header spoofing risk:** Misconfiguration or insufficient validation in the proxy can allow malicious clients or internal actors to spoof or manipulate identity headers. Ensuring correct proxy setup and strict header validation is essential to maintain the integrity of identity information.
- **Configuration consistency:** All proxies across the service landscape must be configured uniformly to ensure consistent authentication behavior and user experience. Inconsistencies in configuration can lead to confusing user flows or even security vulnerabilities.
- **Coupling of external authentication data with internal trust assumptions:** Using the same authentication data for both external clients and internal services increases the risk of leakage and unauthorized access. If an internal service is inadvertently exposed because of a misconfiguration or an attacker gaining internal access, the leaked authentication data may enable unauthorized access to sensitive resources.

## Edge-Level Authentication

In this pattern, authentication is handled at the system boundary by a shared component such as an API gateway or ingress proxy. This component authenticates incoming requests from external clients before they reach internal services. It integrates with one or multiple Identity Providers (IdPs) using protocols such as [OIDC](https://openid.net/specs/openid-connect-core-1_0.html), [OAuth2](https://www.rfc-editor.org/rfc/rfc6749), [SAML](https://www.oasis-open.org/standard/saml/), [mTLS](https://www.rfc-editor.org/rfc/rfc8446), or other mechanisms, and propagates verified identity information, typically via headers, to downstream services for further processing.

![Edge-Level Authentication](../assets/Edge_Level_Authentication.svg)

This approach consolidates authentication logic into a single enforcement point, simplifies service implementation by removing per-service authentication handling, and is particularly common in [Zero Trust](https://csrc.nist.gov/pubs/sp/800/207/final) architectures.

### Pros

- **Improved consistency:** Authentication is performed uniformly and consistently across services at a single entry point, reducing fragmentation, configuration drift, and improving auditability.
- **Simplified service logic:** Internal services are relieved from implementing authentication logic, focusing only on authorization and business functionality.
- **Faster service onboarding:** New services can rely on existing infrastructure for authentication, requiring minimal additional setup.
- **Protocol-agnostic identity propagation:** Verified identity information can be propagated to internal services using trusted, implementation-independent formats (e.g., via a newly issued [JWT](https://www.rfc-editor.org/rfc/rfc7519), injected headers carrying identity information in protected form using standards like [HTTP Message Signatures](https://www.rfc-editor.org/rfc/rfc9421.html)), or signed proprietary structures. This avoids passing raw external authentication data, as is necessary with all previous patterns.

### Cons

- **Limited granularity:** Fine-grained or per-endpoint authentication policies (e.g., step-up authentication) are generally harder to implement and may require additional coordination with downstream services. This heavily depends on the capabilities of the edge proxy
- **Identity propagation challenges:** Ensuring secure and reliable propagation of identity context (e.g., via headers) requires strict validation and trust models between the edge and internal services. Proper governance can help overcome this limitation.
- **Single Point of Failure:** While the ingress proxy or gateway is already a central component in most architectures, performing authentication at the edge makes it a critical part of the security infrastructure. Misconfiguration or compromise can impact not just access, but the integrity of authentication decisions system-wide.
- **Not suitable for service-to-service authentication:** Edge-level authentication only applies to incoming external requests. Internal service-to-service calls require additional authentication mechanisms. Although technically possible, routing internal communication through the edge may introduce severe performance bottlenecks.

## Kernel-Level Authentication

This pattern involves performing authentication at the operating system kernel level using cryptographic identities attached to either a service, or a machine/node, the service is running on. The actual implementation is based on protocols, such as [IPSec](https://www.rfc-editor.org/rfc/rfc6071), or [WireGuard](https://www.wireguard.com/). The identity of a peer is cryptographically verified on each exchanged packet and is limited to [layer 3](https://en.wikipedia.org/wiki/Network_layer). This form of enforcement is transparent to applications, making it a strong foundation for secure communication between workloads.

![Kernel-Level Authentication](../assets/Kernel_Level_Authentication.svg)

### Pros

- **Transparent to applications:** Services do not need to implement authentication logic; identity is enforced by the OS Kernel.
- **Protocol-agnostic:** Applies to all traffic types, not just HTTP.
- **Low latency:** Enables fast connection setup with strong isolation guarantees.
- **Provides strong workload identity:** Provides identity verification tied directly to the transport channel, reducing risk of spoofing or replay, which makes it a strong foundation for service-to-service trust and enables [Zero Trust](https://csrc.nist.gov/pubs/sp/800/207/final) networking models.

### Cons

- **Not suitable for layer 7 — application-level — authentication:** Identities are tied to workloads or nodes only and not to individual users or external clients. Because of this, this pattern cannot convey user-specific identity attributes.
- **Limited observability:** Monitoring is confined to connection-level data (e.g., source/target workloads), lacking insight into user-driven actions within the application.
- **Infrastructure complexity:** Requires robust automation for identity management, and OS- or kernel-level authentication policy enforcement mechanisms (e.g. via [eBPF](https://ebpf.io/)).

## Operational and Security Considerations

While the above authentication patterns differ primarily in terms of *where* and *how* authentication is performed, they also have significant implications for operations and authorization. Choosing the right pattern often comes down to balancing development flexibility, operational effort, and risk tolerance.

### Operational Considerations

| Pattern                          | Configuration & Implementation Burden | Operational Overhead     | Observability Scope        |
| -------------------------------- |---------------------------------------| -----------------------  |----------------------------|
| **Service-Level Embedded**       | High                                  | High                     | Application-specific       |
| **Service-Level Code-Mediated**  | Medium                                | Medium                   | IDP + Application-specific |
| **Service-Level Proxy-Mediated** | Medium                                | High (infra cost)        | Proxy + Application        |
| **Edge-Level**                   | Low                                   | Low                      | Centralized (Proxy)        |
| **Kernel-Level**                 | Low-Medium                            | High (infra complexity)  | Network-level only         |

Patterns with decentralized authentication (like [Service-Level Embedded Authentication](#service-level-embedded-authentication)) typically incur more operational overhead due to inconsistencies, duplicated configuration, and monitoring complexity. Centralized patterns reduce duplication but introduce infrastructure dependencies and require resilient design.

### Security Considerations

Security risks increase significantly when authentication logic and credentials are handled directly within application code. Centralized enforcement approaches — whether at the IDP, edge, or within the OS kernel — help limit exposure, enforce stronger boundaries, and reduce the risk of misconfiguration (especially at the edge). However, care must be taken to prevent trust leakage, which directly impacts the ability to enforce the principle of least privilege. Achieving this depends not only on where authentication occurs, but also on how identity information is propagated and verified downstream. Without trustworthy, tamper-resistant propagation, even strong initial authentication can be undermined — weakening trust boundaries and ultimately impairing the system’s ability to make reliable authorization decisions. To address this, the next section examines common identity propagation strategies and their impact on system security, observability, and trust enforcement.

**Note:** Operational and security concerns such as token theft, replay protection, session lifecycle, and reauthentication are critical when implementing authentication mechanisms. These topics are extensively covered in e.g. [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html), and [Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html).
