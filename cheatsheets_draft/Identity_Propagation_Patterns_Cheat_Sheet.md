# Identity Propagation Patterns

Trustworthy identity propagation is essential for maintaining strong trust boundaries across a system. Architectures following [Zero Trust](https://csrc.nist.gov/pubs/sp/800/207/final) principles exemplify this need, as they emphasize strict access control and continuous verification. This Cheat Sheet introduces commonly used identity propagation patterns — that is, the ways in which identity context flows between services. These patterns influence where and how access control decisions are made, the reliability and trustworthiness of those decisions, and ultimately how effectively least privilege can be enforced. They also differ in how tightly internal services are coupled to the external authentication mechanisms and identity representations used at the boundary.

Some identity propagation patterns aim to decouple internal service logic from specific external authentication protocols and data formats. This approach, often called *protocol-agnostic* or *token-agnostic* identity propagation, means internal services consume a normalized, unified identity representation that abstracts away the details of the original authentication protocol and authentication data (including both primary credentials and authentication proofs). This abstraction enables internal services to remain stable, simplified, and focused on authorization logic, even as external authentication methods evolve or change.

At one end of the spectrum, some patterns directly forward externally issued authentication data (such as OAuth2 tokens, session cookies, or certificates) downstream, requiring internal services to understand and process the original authentication protocols. This approach can increase complexity and trust assumptions within internal services. At the other end, a trusted system component at the edge transforms incoming authentication data into cryptographically signed, normalized identity structures. These structures abstract away the original protocol and data format, allowing internal services to remain agnostic to how authentication was performed. By providing tamper-resistant, verifiable representations of identity, they establish strong trust boundaries across service interactions and enable auditable access decisions, making them especially effective for enforcing least privilege in distributed environments.

Between these extremes exist intermediate patterns where internal services rely on simplified identity representations issued or transformed by upstream services but without cryptographic protections, requiring implicit trust between services.

Each pattern involves trade-offs between implementation complexity, security, trust, privacy and operational overhead. Choosing the appropriate identity propagation approach depends on the system’s security posture, scalability requirements, and the desired level of trust between internal components.

Understanding these trade-offs in concrete terms requires examining how identity propagation is commonly implemented in practice. The following sections describe representative patterns along this spectrum, highlighting their characteristics, benefits, and limitations.

## External Identity Propagation

In this pattern, the edge component forwards the externally received authentication data (e.g., an access token, ID token, session cookie, or certificate) directly to internal services without transformation. The internal services are responsible for the verification of the received authentication data, for extracting the identity context (such as user ID, or other attributes), and making access control decisions based on it. When an internal service needs to communicate with another service, it just forwards the authentication data further downstream. The aforesaid verification may require contacting a Verifier, which depending on the authentication protocol and data used, could be an authorization server that issued the token or, for example, an OCSP responder to check the revocation status of a certificate.

![External Identity Propagation](../assets/External_Identity_Propagation.svg)

As already said above, the actual verification of the authentication data, represented by the dotted lines in steps 3 and 5 of the diagram above, depends on the type of authentication data used. For example, in the case of an opaque token, each service must call the appropriate identity provider, respectively, authorization server endpoint to retrieve the associated data. If the token is self-descriptive, such as a [JWT](https://www.rfc-editor.org/rfc/rfc7519), the service needs the corresponding key material to verify its signature, and so on.

### Pros

- **Minimal edge logic required:** The edge mainly forwards the authentication data, reducing its complexity. It may also just verify the validity of the authentication data.
 **No additional infrastructure needed:** Internal services use the same authentication data as the edge, avoiding the need for internal signing or identity transformation.

### Cons

- **Tight coupling to external protocols:** Each microservice must understand and correctly handle potentially multiple types of external authentication data and formats (e.g., [OAuth2](https://www.rfc-editor.org/rfc/rfc6749), [OIDC](https://openid.net/specs/openid-connect-core-1_0.html), cookies). As a result, services must support protocol-specific logic (e.g., [JWT](https://www.rfc-editor.org/rfc/rfc7519) parsing, OAuth2 token validation, cookie decoding) and are exposed to external semantics, expiration rules, and revocation mechanisms, increasing implementation complexity and brittleness. Changes to external identity providers or protocols typically break internal service behavior.
- **Increased security risk:** If external authentication data is leaked, any internal service exposed, intentionally or not, can potentially be accessed directly using the leaked token.
- **Unsuitable for [Zero Trust](https://csrc.nist.gov/pubs/sp/800/207/final) or multi-tenant environments:** Trust assumptions and lack of verifiability conflict with the security guarantees required in these environments.
- **Privacy concern:** Because externally visible authentication data is reused internally, identifiers intended for internal use (e.g., subject IDs in JWTs) may become externally observable. This can violate privacy requirements by enabling cross-context linkability and may conflict with regulations such as the GDPR or the CCPA.

## Simple Service-Level Identity Forwarding

This pattern builds on the previous one but introduces a lightweight form of internal identity abstraction. While the edge component still forwards the externally received authentication data (e.g., an access token, ID token, session cookie, or certificate) to internal services, each microservice no longer forwards this data unchanged. Instead, a microservice extracts the relevant identity information (e.g., user ID, roles, scopes) from the incoming request and creates a simplified representation of the identity, such as a plain JSON object, a self-signed JWT, or even a single value embedded in a query or path parameter, when making calls to downstream services. As with the previous pattern, the verification of the initially received authentication data may require contacting a Verifier, which depending on the authentication protocol and data used, could be an authorization server that issued the token or, for example, an OCSP responder to check the revocation status of a certificate.

![Simple Service-Level Identity Forwarding](../assets/Simple_Service_Level_Identity_Forwarding.svg)

This internal identity representation is not strongly cryptographically protected and often relies on implicit trust between services. As a result, downstream services must trust the integrity and correctness of the identity information forwarded by their upstream callers.

As with the previous pattern and as also said above, the actual verification of the received authentication data, represented by the dotted line in steps 3 of the diagram above, depends on the type of authentication data used. For example, in the case of an opaque token, the service must call the appropriate identity provider, respectively, authorization server endpoint to retrieve the associated data. If the token is self-descriptive, such as a JWT, the service needs the corresponding key material to verify its signature, and so on.

### Pros

- **Simple and lightweight:** Requires minimal implementation effort and no complex cryptography or signing infrastructure.
- **Protocol abstraction:** Internal services operate on simplified identity representations, avoiding the need to parse or validate external authentication protocols.
- **Flexible identity forwarding:** Enables propagation of identity context without dependency on a central trusted issuer for every internal call.

### Cons

- **High trust requirement:** Downstream services must trust upstream callers to provide unaltered and accurate identity information and related data.
- **Vulnerable to spoofing:** Lack of cryptographic protection makes identity data susceptible to tampering.
- **Unsuitable for [Zero Trust](https://csrc.nist.gov/pubs/sp/800/207/final) or multi-tenant environments:** Trust assumptions and lack of verifiability conflict with the security guarantees required in these environments.
- **Protocol complexity leakage:** If any internal service becomes externally exposed, support for full external authentication mechanisms is required to avoid API abuse.
- **Privacy concern:** Because externally visible authentication data is reused internally, identifiers intended for internal use (e.g., subject IDs in JWTs) may become externally observable. This can violate privacy requirements by enabling cross-context linkability and may conflict with regulations such as the GDPR or the CCPA.

As obvious from the cons listed above, this pattern introduces risks commonly associated with [Insecure Direct Object References (IDOR)](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html#introduction) resulting in data exposure.

## Token Exchange-Based Identity Propagation

This pattern builds upon the previous pattern by introducing a trusted intermediary, an authorization server, through use of the [OAuth2 Token Exchange](https://www.rfc-editor.org/rfc/rfc8693), or the new [OAuth2 Transaction Tokens (draft)](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-transaction-tokens) protocol. A microservice that receives a request containing externally issued identity (e.g., an access token) exchanges it for a new, signed access token issued by the authorization server. This exchanged token is specifically scoped for a downstream internal service and is then propagated as part of the internal call. As with the previous patterns, the verification happens optionally with the help of a Verifier. The issuance of a new token is, however, the responsibility of the Secure Token Service (STS). The latter assumes the role of the Verifier for the verification of tokens it has issued. Both might be implemented by the same authorization server, but don't need to.

![Token Exchange-Based Identity Issuance](../assets/Token_Exchange_Based_Identity_Issuance.svg)

Downstream services trust the token issued by the STS rather than the one used by the external client ("Some Client" in the diagram above). The pattern improves the trust model and strengthens identity guarantees, but is tightly coupled to the [OAuth2](https://www.rfc-editor.org/rfc/rfc6749) protocol family and its associated token types.

The actual verification of all involved tokens, represented by the dotted lines in steps 3 and 6 of the diagram above, depends on the type of the token used. For example, in the case of an opaque token, each service must call the appropriate identity provider endpoint to retrieve the associated data. If the token is self-descriptive, such as a JWT, the service needs the corresponding key material to verify its signature.

### Pros

- **Improved trust model:** Downstream services do not need to trust upstream service implementations, only the STS.
- **Cryptographically verifiable identity:** Issued tokens are signed by an STS, offering strong integrity guarantees.
- **Scoping and audience control:** Exchanged tokens can be restricted in scope and audience, reducing the risk of token misuse.

### Cons

- **OAuth2-specific:** Relies on [OAuth2 Token Exchange](https://www.rfc-editor.org/rfc/rfc8693), respectively, on [OAuth2 Transaction Tokens (draft)](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-transaction-tokens), limiting its applicability to systems using that protocol family for externally visible authentication data.
- **Service-side complexity:** Application code must integrate with the STS to handle token exchange logic, and manage caching or retries.
- **Latency overhead:** The token exchange process introduces additional network round-trips per request flow unless aggressively optimized.
- **Operational dependency on the STS:** Introduces runtime dependency on the STS implementation availability and scalability.

## Protocol-Agnostic Identity Propagation

The external request is authenticated at the system edge by a trusted component, which then generates a cryptographically signed (and/or encrypted) data structure representing the external entity’s identities and attributes (e.g., user ID, roles, permissions) - typically a self-contained, verifiable structure, such as a JWT or a proprietary signed format. By doing that, the edge component assumes the role of a Secure Token Service (STS) This signed identity structure, hereafter referred to as a token, is propagated downstream to internal microservices. Internal services trust the signature from the edge issuer and use the token to make access control decisions.

![Protocol-Agnostic Identity Propagation](../assets/Protocol_Agnostic_Identity_Propagation.svg)

As with the previous pattern, the verification of the original authentication data may require contacting a Verifier. The implementation of the Verifier depends on the protocol and data format used — e.g. it could be an authorization server that issued a token, or it could be an OCSP responder, used to check the revocation status of a certificate. Unlike in previous patterns, only the edge component is responsible for that verification. The specific verification process depends on the aforesaid type and format of the authentication data, denoted by the dotted line in step 2.

Further downstream, the microservices validate the signed token issued by the trusted edge-component. Each microservice must have access to the corresponding verification key to validate the authenticity of this token. The corresponding verification steps are denoted by the dotted lines in steps 5 and 7. This is where the trusted component at the edge assumes the role of a Verifier.

It’s worth noting that the edge-component roles shown in the diagram above — Edge Proxy, STS, and Verifier — may all be implemented within a single technical component, or split across multiple cooperating services. For example, a proxy might delegate the authentication data and token issuance related logic to another service via a mechanism typically named as *forward auth* or *external auth*. That service could implement the STS and the Verifier logic by itself, or, in turn, delegate token issuance to an existing authorization server using mechanisms such as the [OAuth2 Token Exchange](https://www.rfc-editor.org/rfc/rfc8693), as described in the previous pattern.

### Pros

- **Cryptographic trust:** Signed tokens provide strong guarantees about the integrity and authenticity of the propagated identity.
- **Decoupling from external authentication data and context:** Internal services neither handle external protocols nor need to differentiate whether requests originate from first- or third-party actors, simplifying their logic and trust assumptions.
- **Rich identity context:** Allows inclusion of fine-grained identity and authorization metadata.
- **Secure across trust boundaries:** Suitable for multi-tenant and [Zero Trust](https://csrc.nist.gov/pubs/sp/800/207/final) environments.
- **Separation of external and internal identities:** Enables mapping externally known identifiers to distinct internal representations, preventing direct exposure of internal identifiers and thereby enhancing privacy by reducing correlation and tracking risks across domains.

### Cons

- **Key management complexity:** Requires secure handling and rotation of signing keys to maintain trust.
- **Token size overhead:** Signed tokens issued by the edge component may be large, increasing network overhead.
- **Revocation challenges:** Once issued, tokens may be valid for many services until expiration, complicating immediate revocation. This can, however, be mitigated by issuing short-lived tokens and tailoring subject structures to individual downstream services.
- **Increased complexity at the edge:** The edge component must handle external authentication data verification as well as internal token generation and signing, making it a critical security component.

In [this blog post](https://netflixtechblog.com/edge-authentication-and-token-agnostic-identity-propagation-514e47e0b602), Netflix refers to this pattern as "Token Agnostic Identity Propagation".

## Privacy By-Design

Privacy concerns — particularly around cross-context linkability and the risk of exposing internal identifiers — affect all identity propagation patterns, though their severity depends on how externally received authentication data is handled.

Implementation of patterns like [External Identity Propagation](#external-identity-propagation) and [Simple Service-Level Identity Forwarding](#simple-service-level-identity-forwarding) typically directly reuse externally visible authentication data within the system. This increases the risk that internal identifiers (e.g., `sub` claims in JWTs) become externally observable, enabling correlation of user activity across contexts. Such reuse undermines core privacy goals like pseudonymisation and data minimisation and conflicts with principles of integrity and confidentiality — all central to privacy-by-design thinking.

In contrast, patterns like [Token Exchange-Based Identity Propagation](#token-exchange-based-identity-propagation) and [Protocol-Agnostic Identity Propagation](#protocol-agnostic-identity-propagation) help enforce privacy boundaries by transforming or isolating authentication data before it’s used internally. That doesn’t mean these patterns — or their specific implementations — are immune to privacy risks. They simply make it easier to adopt techniques such as opaque tokens, session-referencing cookies, or identifier mapping, which reduce unnecessary exposure of user-specific identifiers. Even so, mapped identifiers can still reveal the existence of a persistent relationship with the system, which may be problematic in certain contexts. Still, these patterns embody privacy-by-design principles more effectively — and as a positive side effect, tend to align well with legal requirements such as the GDPR (Art. 5(1)(b, c, f), Art. 25, Art. 32, Recitals 26 and 30), CCPA, and similar frameworks.
