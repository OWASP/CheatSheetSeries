# Enterprise API Security Architectural Patterns Cheat Sheet

## Introduction

This cheat sheet provides focused guidance on enterprise API security patterns that address specific security challenges beyond basic controls. Each pattern addresses real-world scenarios where standard security measures are insufficient.

This cheat sheet focuses on **architectural patterns** rather than individual control implementations. The patterns described apply to **REST, GraphQL, gRPC, and event-driven APIs**, unless otherwise noted.

For detailed implementation guidance of individual controls, refer to the foundational cheat sheets.

## Foundational Cheat Sheets

Before implementing the patterns in this cheat sheet, you should be familiar with the following foundational concepts:

- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/) – Core API vulnerabilities
- [Authentication Cheat Sheet](Authentication_Cheat_Sheet.md) – User identity verification
- [Authorization Cheat Sheet](Authorization_Cheat_Sheet.md) – Access control patterns
- [REST Security Cheat Sheet](REST_Security_Cheat_Sheet.md) – Protocol-specific security
- [Input Validation Cheat Sheet](Input_Validation_Cheat_Sheet.md) – Data sanitization
- [Error Handling Cheat Sheet](Error_Handling_Cheat_Sheet.md) – Secure error responses
- [Logging Cheat Sheet](Logging_Cheat_Sheet.md) – Security event logging

## Identity and Access Management Patterns

These patterns focus on how users and services are identified and how access to resources is controlled across complex enterprise environments.

### Multi-Tenant Data Isolation

This pattern prevents data leakage between tenants in a shared SaaS environment. The choice of isolation level is a critical decision based on security requirements, compliance needs, and operational complexity. There is no single "best" approach; each has significant trade-offs.

> **Defense-in-Depth Reminder**  
> API-level tenant validation must **never be the only isolation mechanism**. It must be combined with data-layer isolation controls to reduce blast radius if application-layer checks fail.

#### API-Level Tenant Validation

This is a required control for any multi-tenant architecture, regardless of the data storage model. It ensures that every API request is validated for tenant access before any data is accessed.

**Implementation:**

- The tenant context is typically extracted from a JWT token or session data.
- A validation check must be performed at the beginning of every request that accesses tenant-specific data.
- This check should verify that the authenticated user belongs to the tenant they are attempting to access.

**Critical Failure Modes:**

- **Inconsistent Validation:** Tenant validation logic is missing from some endpoints or implemented inconsistently across services.
- **Stale Permissions:** Cached tenant permissions become outdated, leading to incorrect access decisions.
- **Bypassed Validation:** Background jobs or service-to-service calls bypass the API gateway or validation middleware.
- **GraphQL-Specific Risks:**
    - Resolvers that forget to apply tenant filters consistently.
    - Nested queries that access related objects without re-validating tenant ownership.

#### Data Separation Approaches

1. **Separate Database per Tenant**  
   Highest security, highest cost. Each tenant has a dedicated database instance.

2. **Separate Schema per Tenant**  
   Medium–high security, medium cost. Each tenant has a dedicated schema in a shared database.

3. **Row-Level Security (Shared Database, Shared Schema)**  
   Medium security, lowest cost. A `tenant_id` column and database-enforced policies restrict access.

### Cross-Organization Federation

This pattern enables secure API access across organizational boundaries (B2B scenarios) by establishing trust between different identity providers.

> **Authentication vs Authorization**  
> Federation establishes **identity (authentication)**, not **permissions (authorization)**. Authorization decisions must always be enforced locally according to your own policies.

**When to use:**

- Users from partner organizations require API access.
- Seamless single sign-on (SSO) is needed across organizations.

**How it works:**

- Standards such as **SAML** or **OpenID Connect (OIDC)** establish trust between your system (Service Provider) and a partner IdP.
- Users authenticate with their own organization.
- The partner IdP sends a signed assertion or ID token, which your system validates before issuing access.

**Pros:**

- Improved user experience
- Reduced identity management overhead
- Authentication handled by the identity-owning organization

**Cons:**

- Federation setup and metadata management complexity
- Dependency on partner IdP availability
- Certificate and endpoint rotation risks

### Service-to-Service Authentication

In microservices architectures, secure communication between services is critical.

#### Mutual TLS (mTLS)

Establishes encrypted communication where both client and server authenticate using X.509 certificates.

**When to use:**

- Zero Trust environments
- Service mesh deployments (e.g., Istio, Linkerd)

**Pros:**

- Strong, cryptographic service identity
- Transparent to application code

**Cons:**

- PKI and certificate lifecycle complexity
- Does not propagate end user identity

#### JWT Bearer Tokens for Service Identity

Services authenticate using OAuth 2.0 client credentials and JWTs.

**When to use:**

- Service meshes are unavailable
- Service identity or metadata must be conveyed in token claims

**Security Recommendations:**

- **Avoid long-lived service tokens.**
- Use **short TTLs** with automated rotation.
- Enforce strict **audience (`aud`) restrictions**.

**Cons:**

- Token leakage risk
- Application-level implementation required

### Advanced Authorization

For advanced authorization models such as **Attribute-Based Access Control (ABAC)** and **Relationship-Based Access Control (ReBAC)**, refer to the [Authorization Cheat Sheet](Authorization_Cheat_Sheet.md). These models enable fine-grained, dynamic access control decisions but require careful architectural planning.

For patterns related to session management, see the [Session Management Cheat Sheet](Session_Management_Cheat_Sheet.md).

## API Gateway Security Patterns

These patterns are typically implemented at a central ingress point like an API Gateway to provide consistent security enforcement for all upstream services.

### Centralized Policy Enforcement

The API Gateway enforces authentication, authorization, and traffic controls for upstream services.

> **Important Limitation**  
> Gateway controls are **coarse-grained** and must not replace service-level authorization. Backend services must always enforce their own fine-grained authorization checks.

**Pros:**

- Consistent security enforcement
- Centralized policy management and logging

**Cons:**

- Single point of failure
- Gateway bypass risk

### API Abuse Protection

Protects APIs from excessive or abusive usage.

**Implementation:**

- Apply both **per-tenant** and **per-user/client** rate limits.
- Use burst and sustained thresholds to handle traffic spikes gracefully.
- Enforce quotas and return `429 Too Many Requests` when exceeded.

**Pros:**

- Prevents service degradation
- Enables API monetization models

**Cons:**

- Requires distributed, low-latency state management

## Application-Level Security Patterns

These patterns are implemented within the application or service logic itself to provide more granular security controls.

### Token Security: Proof of Possession (PoP)

Mitigates bearer token theft by binding tokens to cryptographic proof from the client.

**Mechanisms:**

- **mTLS-bound tokens**: Binds the token to the client's TLS certificate.
- **DPoP (RFC 9449)**: The client signs a proof JWT with a private key.

> **Applicability Note**  
> DPoP is generally **not suitable for confidential server-side clients** that can use a stronger binding method like mTLS.
>
> **Important Warning**  
> Proof-of-possession protects tokens from theft but **does not replace authorization checks**. A valid PoP token from an unauthorized user must still be rejected.

**Pros:**

- Prevents token replay outside the original client context
- Reduces impact of token theft

**Cons:**

- Increased cryptographic complexity
- Performance overhead

### Secure Webhook Patterns

Webhooks expose public endpoints and require strong validation to prevent abuse.

#### Payload Signature Verification

Ensures webhook authenticity and integrity.

**Implementation:**

- The provider signs the payload using HMAC (with a shared secret) or asymmetric keys.
- The signature is included in request headers (e.g., `X-Hub-Signature-256`).
- The receiver recalculates the signature and verifies it.

**Supplemental Controls:**

- **IP allowlisting** may be used as an additional layer but must not be the primary control, as IPs can be spoofed or shared.

#### Replay Attack Prevention

Prevents an attacker from replaying valid webhook requests.

**Implementation:**

- Verify timestamps for freshness.
- Track nonces or event IDs in a cache to reject duplicates.

**Additional Recommendation:**

- For operations that are not naturally idempotent (e.g., payments), the receiver should implement an **idempotency key** mechanism to prevent duplicate processing.

## References

### Standards & Best Practices

- **IETF:**
    - [RFC 6749 - OAuth 2.0 Authorization Framework](https://datatracker.ietf.org/doc/html/rfc6749)
    - [RFC 8725 - JSON Web Token Best Current Practices](https://datatracker.ietf.org/doc/html/rfc8725)
    - [RFC 9449 - OAuth 2.0 Demonstrating Proof of Possession (DPoP)](https://datatracker.ietf.org/doc/html/rfc9449)
    - [RFC 8705 - OAuth 2.0 Mutual-TLS Client Authentication](https://datatracker.ietf.org/doc/html/rfc8705)
- **NIST:**
    - [SP 800-207 - Zero Trust Architecture](https://csrc.nist.gov/publications/detail/sp/800-207/final)
    - [SP 800-204 - Security Strategies for Microservices-based Application Systems](https://csrc.nist.gov/publications/detail/sp/800-204/final)

### Industry & Implementation Guides

- **Cloud Provider Guidance:**
    - [AWS Well-Architected Framework - Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html)
    - [Azure Architecture Center - API Design](https://docs.microsoft.com/en-us/azure/architecture/best-practices/api-design)
    - [Google Cloud Architecture Framework - Security](https://cloud.google.com/architecture/framework/security)
- **Multi-Tenancy:**
    - [Azure Multi-Tenant Applications](https://docs.microsoft.com/en-us/azure/architecture/multitenant-identity/)
    - [Postgres Row Level Security](https://www.postgresql.org/docs/current/ddl-rowsecurity.html)
- **Service Mesh:**
    - [Istio Service Mesh - Security Policies](https://istio.io/latest/docs/concepts/security/)
    - [BeyondCorp: A New Approach to Enterprise Security](https://research.google/pubs/pub43231/)
- **Authorization Systems & Models:**
    - [Google Zanzibar: Global Authorization System](https://research.google/pubs/pub48190/)
    - [OpenFGA Authorization Model](https://openfga.dev/docs/concepts)
- **Webhook Security & Event Processing:**
    - [GitHub Webhook Security Best Practices](https://docs.github.com/en/webhooks/using-webhooks/securing-your-webhooks)
