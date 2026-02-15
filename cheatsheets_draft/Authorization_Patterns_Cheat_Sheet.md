# Authorization Patterns

While some basic access control can be applied to anonymous or unauthenticated subjects, the most meaningful authorization requires a reliable understanding of the subject’s identities and associated attributes, both covered in [Authentication Patterns](Authentication_Patterns_Cheat_Sheet.md) and [Identity Propagation Patterns](Identity_Propagation_Patterns_Cheat_Sheet.md) Cheat Sheets.

The corresponding architectural approaches can be described by authorization patterns. These patterns define where Policy Decision Points (PDPs), Policy Enforcement Points (PEPs), and Policy Information Points (PIPs) are placed within a system and how they interact. They also govern how subject and object identities, along with related attributes, flow between these components — and where policies are stored and accessed.

Choosing the right patterns is critical, as it directly impacts the system’s security posture, performance, scalability, and maintainability. The following subsections explore the most common ones used in distributed architectures and outline their trade-offs.

## Decentralized Service-Level Authorization

In this pattern, most of the functional components from the reference architecture are implemented directly within each microservice. Even the Policy Information Points (PIPs) may be embedded into the service logic (e.g., via database or configuration entries) if the microservice is responsible for all relevant attributes itself. However, this is rarely the case, and most microservices must integrate with other services to retrieve required attributes, treating those other services as external PIPs.

![Decentralized Service-Level Authorization](../assets/Decentralized_Service_Level_Authorization.svg)

The access control rules are typically implemented using native language constructs (e.g., `if`/`else` statements), either inline with business logic functions or via abstraction mechanisms such as interceptors.

When a microservice receives a request containing authorization data (e.g., end-user context or resource identifiers), it evaluates whether access should be granted. This may involve querying other services (PIPs) for additional attributes before reaching a decision and enforcing it (implicitly). Alternatively, some services may use asynchronous communication patterns (e.g., periodic syncs or event-driven updates) to pre-fetch required data in advance, improving performance and resilience.

When adopting this approach, the following trade-offs should be considered:

### Pros

- **Familiar development model**: Developers can use the same language and tools they already know.
- **Framework support**: Many libraries and frameworks exist for many languages to reduce boilerplate and simplify integration.
- **Rapid prototyping**: Policy logic is implemented directly in code, enabling quick experimentation and iteration.
- **Team autonomy**: Fits well with independent team ownership; each team can choose its approach.
- **High performance**: Policy evaluation is done in-memory within the microservice.
- **Full context awareness**: The service has access to runtime data, business logic, and domain models, enabling fine-grained, context-rich and nuanced decisions.
- **Failure isolation**: If all required attributes are available locally or cached, failures in external systems do not impact decision-making.

### Cons

- **Scattered logic**: Authorization requirements tend to spread across multiple services, leading to code duplication, increased complexity, and maintenance overhead. Over time, this results in a slow and error-prone policy lifecycle, significantly reducing time to market. This is a classic "Hardcoded Rules" antipattern.
- **Role explosion**: Business stakeholders typically describe authorization requirements using roles — for example, "a user with role X can do Y". Without introducing an abstraction layer between business roles and the actual implementation, systems often accumulate many similar but inconsistent roles. Roles also tend to evolve or change names over time. This leads quickly to role explosion, again slowing the policy lifecycle and increasing the risk of errors. This is known as the “Code Against the Role” antipattern.
- **Deprived Governance**: Autonomous teams may interpret and implement policies differently, making consistent governance for the whole environment nearly impossible. This may result in enforcement gaps and unpredictable behavior.
- **No central auditability**: When authorization logic is distributed across services, it becomes nearly impossible to answer "before-the-fact" questions such as "Who has access to what, and when?" — a key requirement in compliance and security contexts.
- **Inconsistent monitoring**: Logging and audit trails vary widely across services and are often incomplete or incompatible. This hampers the ability to detect abuse, investigate incidents, or analyze system-wide access patterns.
- **Coverage gaps**: Many frameworks do not expose ways to integrate access control into certain auto-exposed endpoints. Teams may also forget to secure these paths entirely. Documentation of the frameworks is also often inconsistent or misleading. All of that leads to unintended public exposure of sensitive endpoints.

**NOTE:** These cons often result in "accept by default" behavior, ultimately leading to broken access control vulnerabilities.

## Centralized Service-Level Authorization

This pattern aims to address the first three drawbacks of the previous pattern — to reduce complexity, improve time to market, and establish governance over policy definitions — by decoupling policy logic from service code and supporting its own lifecycle management. In this model, authorization rules are defined independently of the microservice code. This separation allows policies to be reviewed, versioned, and audited without being tied to the specific implementation languages of the microservices. These policies can reside in a dedicated policy repository, which explains the "centralized" in the pattern name, or they can be colocated with the service code in the same repository. The essential aspect is that policies are decoupled from the service code, rather than intertwined with it. The actual enforcement of the access decisions still takes place locally to each microservice.

The PDP can be implemented as a library (e.g., [Casbin](https://casbin.org/)) embedded in the service’s codebase, as a local sidecar process (e.g., [Open Policy Agent](https://www.openpolicyagent.org/)), or even be external, centrally managed PDP — shared across a domain (in domain driven design sense), scoped to a business unit, or truly central depending on organizational needs. Authorization rules are now defined using the PDP’s domain-specific language (e.g., Rego in the case of OPA), rather than being hardcoded into the service logic.

![Centralized Service-Level Authorization](../assets/Centralized_Service_Level_Authorization.svg)

The microservice continues to act as the PEP, calling into the PDP to make access decisions during request handling. To make an authorization decision, the PDP requires attributes, which — depending on the PDP deployment options mentioned above — may either be available within the service or retrieved from external sources (PIPs). Some PDPs support data-fetching logic within the policy itself, allowing them to directly retrieve the necessary attributes at runtime. This is represented by 1 and 2 in the diagram above. Both connections are just an abstraction and denote logic communication paths.

Although this pattern significantly improves the maintainability and consistency of access control logic, it also introduces new challenges and does not resolve all the limitations inherent in the previous pattern. It’s important to note that aspects such as performance, failure resilience, and auditability — including support for "before-the-fact" audit — largely depend on the type of PDP and its integration approach (e.g., embedded, sidecar, or external). These trade-offs are discussed separately in [PDP Deployment & Integration Options](#pdp-deployment--integration-options).

### Pros

- **Policy governance:** Policies can be centrally defined, versioned, reviewed, and audited, independent of the service’s implementation language.
- **Policy layering:** The model allows for both global (e.g. security team–defined) and local (e.g. service team–defined) policies to coexist. This enables clearer separation of concerns and better alignment with organizational structure and responsibilities.
- **Improved monitoring:** All decisions can be consistently logged and monitored, assuming proper instrumentation.
- **Team autonomy:** Teams remain responsible for their services and their policies, with local enforcement and minimal external dependencies. This aligns well with independent team ownership and domain-driven design principles.
- **Enhanced testability:** Authorization logic can be tested independently of the microservice business logic.

### Cons

- **Policy distribution complexity:** Policies are now decoupled from the code, so mechanisms are needed to deploy the correct version of each policy to the appropriate service instances.
- **Context sharing:** PDPs do not inherently have access to the microservice context. Developers must design mechanisms to assemble and pass the right attributes into the PDP for evaluation.
- **Coverage gaps:** Some frameworks expose endpoints by default, often without offering hooks for policy enforcement. Teams may also just forget to add the required logic to some endpoints. Combined with poor or misleading documentation, this can result in unintentionally exposed functionality and missed access control. Common examples include health and metrics endpoints (e.g., Spring Boot Actuator), auto-generated documentation routes (e.g., FastAPI or OpenAPI UIs), or static routes in frameworks like e.g. Express.js.
- **Incomplete enforcement observability:** While policy decisions are consistently logged, there’s often no visibility into whether those decisions were correctly enforced across all code paths. Missing instrumentation or scattered enforcement logic makes it difficult to validate effective protection, investigate incidents, analyze system-wide access patterns or detect abuse.

**NOTE:** Due to these remaining gaps, "accept by default" behaviors remain a real risk, leading to broken access control vulnerabilities.

## Edge-Level Authorization (Classic)

This pattern aims to address several shortcomings of service-level access control patterns, particularly inconsistent enforcement, policy sprawl, and limited observability. Instead of tying PEP related logic in each service, access control is moved to the system’s perimeter — typically implemented via API gateways, ingress controllers, or reverse proxies.

![Edge-Level Authorization (Classic)](../assets/Edge_Level_Authorization_Classic.svg)

Since authorization must follow authentication, this pattern tightly couples authentication and authorization at the network boundary. Gateways or proxies serve as the PEP, and either evaluate policies locally, using embedded logic, or delegate decisions to an external PDP.

All external traffic flows through the edge component, making this the first pattern that guarantees every inbound request is observed and subject to access control logic. As with the previous pattern, aspects such as performance, failure resilience, and auditability are not covered here but are discussed in [PDP Deployment & Integration Options](#pdp-deployment--integration-options) instead.

### Pros

- **Consistent enforcement:** All inbound requests pass through a centralized enforcement point, ensuring uniform application of policies and reducing the likelihood of unprotected endpoints ("no accept by default").
- **Policy governance:** Policies can be centrally defined, versioned, reviewed, and audited, independent of the service’s implementation language.
- **Policy layering:** The model allows for both global (e.g. security team–defined) and local (e.g. service team–defined) policies to coexist. This enables clearer separation of concerns and better alignment with organizational structure and responsibilities.
- **Best observability:** All external access attempts are visible and can be logged centrally, supporting effective monitoring, alerting, and forensics.

### Cons

- **Socio-technical challenges:** In many organizations, API gateways are operated by infrastructure or platform teams, meaning development teams cannot directly manage authorization policies or authentication configurations. This separation of responsibilities requires close coordination between developers and operations/security, which often reduces delivery velocity due to communication and process overhead, especially in complex ecosystems with many roles, evolving access control rules, and the need for flexible authentication flows.
- **Policy distribution complexity:** Policies are decoupled from the code, so mechanisms are needed to deploy the correct version of each policy for the appropriate service instances.
- **Authentication limitations:** Edge components only support a single authentication configuration per listener or route group. Supporting multiple identity providers, per-endpoint authentication flows, or more advanced patterns—such as dynamic consent, step-up authentication, or conditional logic based on subject actions — is difficult or impossible without custom logic or deep integration.
- **Context sharing:** Edge components only have access to request-level attributes (e.g., headers, paths, IPs). This makes it difficult to evaluate fine-grained, object-level, or business-context-sensitive access decisions.
- **Enforcement blind spots and defense-in-depth violations:** Since the edge only governs ingress traffic, any internal traffic (e.g., service-to-service calls) or network misconfigurations may bypass enforcement entirely - violating the defense-in-depth principle and creating a single point of failure.

## Edge-Level Authorization (Modern)

This pattern evolves the classic edge-level authorization approach to overcome its key limitations. While enforcement still occurs at the perimeter via proxies or gateways, this approach allows per-service customization through service-specific rules — declarative definitions of how identity and context are gathered, how authorization is performed, and how decisions are propagated — forming explicit *authorization contracts*. These contracts manifest as structured, signed data (e.g., JWT claims or enriched signed headers) that the edge proxies or gateways relay to downstream services. This explicit propagation of authorization context ensures that internal service-to-service calls rely on a trusted, verifiable authorization boundary, addressing common concerns around enforcement blind spots and defense-in-depth violations typically associated with edge-only models. By making authorization an explicit API-level contract, teams can confidently decentralize enforcement without creating single points of failure or gaps in access control.

![Edge-Level Authorization (Modern)](../assets/Edge_Level_Authorization_Modern.svg)

Instead of embedding rigid policy logic or centralizing control in infrastructure teams, this pattern emphasizes composability, autonomy, and observability, enabling each team to define how their endpoints are protected, while still benefiting from centralized governance and enforcement guarantees. As with the previous pattern, aspects such as performance, failure resilience, and auditability are not covered here but are discussed in [PDP Deployment & Integration Options](#pdp-deployment--integration-options) instead.

### Pros

- **Consistent enforcement:** Uniform application of policies at a centralized point prevents unprotected or overlooked endpoints.
- **Policy governance:** Policies remain versioned, reviewed, and auditable, often authored centrally but can be referenced declaratively in service-specific contracts.
- **Best observability:** All external access attempts are visible and can be logged centrally, supporting effective monitoring, alerting, and forensics.
- **Rapid prototyping:** Through authorization contracts, teams can experiment with different authorization models (e.g., embedded JWT claims, header-based roles, etc.) without relying on the infrastructure components.
- **Context sharing:** The proxy can fetch contextual data from arbitrary PIPs, enabling context-sensitive decisions based on domain-specific attributes, object metadata, or subject state.
- **Service autonomy:** Authorization contracts empower microservice teams to define their own access control needs declaratively, supporting domain-driven service ownership without duplicating enforcement logic.
- **Authorization context propagation:** The system can rewrite identity and authorization responses from the PDP into formats that match each service’s expectations (e.g., structured JWTs, plain or signed headers), decoupling service-specific logic from authorization protocols.
- **Secure by default:** The use of declarative contracts and centralized enforcement reduces misconfiguration risks and prevents implicit access grants.

### Cons

- **Policy distribution complexity:** Ensuring the correct version of a policy is evaluated in the context of the specific service version requires additional coordination. This mainly depends on PDP capabilities and tooling.
- **Contract governance:** While authorization contracts empower teams with autonomy, it requires clear guidelines and automated validation tools to prevent misconfiguration or misuse.

There is also a variant of this pattern — **"Side-Car-Proxy-Based Authorization"** — where the PEP is deployed alongside the microservice as a dedicated proxy, intercepting and controlling all inbound traffic to that service. This approach shares many of the same advantages and drawbacks as the edge-level model. However, operational complexity increases, as each service gains an additional moving part. Furthermore, observability becomes fragmented, since monitoring is limited to individual services unless all services in a given context adopt the same pattern.

## PDP Deployment & Integration Options

The choice of PDP deployment — embedded, as a sidecar, or external — significantly impacts performance, auditability, and supported authorization models. The table below summarizes the key trade-offs:

| Aspect                | Embedded PDP          | Side-Car PDP              | External PDP                                       |
|-----------------------|-----------------------|---------------------------|----------------------------------------------------|
| Location              | as a library          | as local side-car process | separate PDP service                               |
| Latency               | no impact             | very low latency          | higher latency due to network hops                 |
| Before the Fact Audit | limited               | limited                   | possible system wide                               |
| Access Control Models | PBAC, e.g. Casbin     | PBAC, e.g. OPA            | PBAC, ReBAC, and NGAC (e.g. OPA, OpenFGA, SpiceDB) |
| Dependencies          | none (self-contained) | none (self-contained)     | Relies on PDP service availability                 |

### On Data Source Integration

The need to fetch or inject data required for policy evaluation introduces operational challenges across all authorization patterns — including [Decentralized Service-Level Authorization](#decentralized-service-level-authorization). This responsibility may lie with the PEP (e.g., a service or edge proxy) or the PDP itself. Accessing PIPs at runtime can complicate network configurations, conflict with segmentation or firewall policies, and broaden the system’s attack surface. These concerns require careful architectural consideration, which is also something the next section aims to support you with — and since you're reading this as part of the blog post series, the next blog post.
