# AML and Sanctions Compliance for AI Agent Payments Cheat Sheet

## Introduction

AI agents are initiating regulated financial transactions in production. Mastercard Agent Pay, Visa Intelligent Commerce, and Google A2A payments are live. Using an AI agent does not remove applicable Anti-Money Laundering (AML) or sanctions obligations. Determine the requirements for the institution, transaction, customer relationship, and jurisdiction before implementing the controls below.

This cheat sheet provides practical controls for fintechs, banks, and payment processors when autonomous AI agents -- rather than human users in browser sessions -- initiate or facilitate regulated payments. It covers agent identity verification, entity screening, audit trail requirements, and fail-closed enforcement.

Use the [MCP authentication and authorization guidance](MCP_Security_Cheat_Sheet.md#6-authentication-authorization-transport-security) when exposing screening tools through MCP. Message-level signing is an [optional additional control](MCP_Security_Cheat_Sheet.md#7-optional-message-level-integrity), not a core MCP requirement. The signed-audit and receipt design in Sections 4 and 8-10 is one option for systems that need verification beyond a transport connection.

## Regulatory Context

The applicable obligations depend on the institution's regulated role, the transaction, and the jurisdictions involved. Have compliance owners identify the requirements the payment service must enforce:

- **Bank Secrecy Act (BSA)**: US [BSA regulations](https://www.fincen.gov/resources/statutes-and-regulations/bank-secrecy-act) establish recordkeeping, reporting, and other requirements for covered financial institutions and businesses. Determine which requirements apply to the service's activities.
- **Office of Foreign Assets Control (OFAC) Sanctions**: Comply with applicable sanctions prohibitions and blocking requirements. Screening supports those controls, but [OFAC does not impose a general requirement to scan names or use screening software](https://ofac.treasury.gov/faqs/43). Complete the necessary analysis before concluding a transaction.
- **Financial Crimes Enforcement Network (FinCEN)**: Apply Customer Identification Program (CIP) and Customer Due Diligence (CDD) requirements to the relevant customers and beneficial owners under the institution's applicable rules and exceptions. The [CDD rule covers specified types of financial institutions](https://www.fincen.gov/resources/statutes-and-regulations/cdd-final-rule); authenticating software does not identify the legal customer. [CIP guidance distinguishes an account owner from a person merely acting as that owner's agent](https://www.fincen.gov/resources/statutes-regulations/guidance/interagency-interpretive-guidance-customer-identification).
- **UK Financial Sanctions**: The Office of Financial Sanctions Implementation (OFSI) provides guidance on applying the sanctions requirements relevant to the parties and activities. [OFSI assesses whether due diligence is appropriate to the sanctions risk and transaction](https://www.gov.uk/government/publications/financial-sanctions-enforcement-and-monetary-penalties-guidance/financial-sanctions-enforcement-and-monetary-penalties-guidance#due-diligence); it does not prescribe one level or type of due diligence for every case.
- **EU Sanctions**: Identify the applicable sanctions regimes and legal acts. The [European Commission's sanctions resources](https://finance.ec.europa.eu/eu-and-world/sanctions-restrictive-measures/overview-sanctions-and-related-resources_en) distinguish the consolidated list of designated parties from the legal acts governing sanctions; a list check alone does not establish compliance with every restriction.
- **Funds-Transfer Recordkeeping**: Follow the requirements applicable to the institution's role and payment type. The [FFIEC examination manual](https://bsaaml.ffiec.gov/manual/AssessingComplianceWithBSARegulatoryRequirements/09) describes thresholds, exceptions, and required originator and beneficiary information; it does not establish a universal requirement for a cryptographic software-agent identity.

### Key Principle

Separate legal customer and counterparty identification from software authentication and authorization. Record which customer an agent acts for and what it may do as an application security control. Have compliance owners define the required screening, monitoring, reporting, and retention rules; do not treat an agent credential or a successful list match check as proof that all legal obligations are satisfied.

## Section 1: Agent Identity Before Screening

Before an agent is permitted to access sanctions screening services or initiate a payment, its identity must be cryptographically verified. Self-declared identity headers (e.g. `X-Agent-ID`, `X-Agent-Role`) without cryptographic proof MUST be rejected. For protected MCP endpoints, follow the [MCP authorization profile](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization) and validate authorization on every request.

### Do

- Require agents to present a cryptographic identity credential (e.g. signed passport, ECDSA key pair, or verifiable credential) before accessing screening endpoints.
- Bind the agent's identity to the screening request so the audit trail proves which specific agent performed the check.
- Verify the agent's trust level before granting access. Not all agents should have the same level of access to sanctions data. Use graduated trust levels (e.g. L0 to L4) with increasing access rights.
- Record the agent's public key fingerprint or passport ID in every screening request log entry.

### Don't

- Accept self-declared identity claims without cryptographic verification.
- Allow agents to access screening endpoints without authentication.
- Trust caller-supplied identity headers merely because TLS terminates at a proxy. If forwarding a validated client-certificate identity, [accept it only over a trusted proxy path and remove caller-supplied certificate headers](https://www.rfc-editor.org/rfc/rfc9440.html#section-4).
- Allow agents to escalate their own trust level or modify their own permissions.

## Section 2: Entity Screening

Entity screening against global sanctions lists (OFAC SDN, UK Sanctions List, EU Consolidated, UN Consolidated) remains fundamentally unchanged when agents are the callers. The screening engine matches names, addresses, vessels, and identifiers against the lists. What changes is the context around the screening request. The authoritative source for the United States is the [OFAC Sanctions List Search](https://sanctionssearch.ofac.treas.gov/).

### Do

- Screen all counterparties (individuals, businesses, vessels, addresses) against applicable sanctions lists before processing a payment.
- Include the agent's identity and trust level in the screening context so that downstream systems can distinguish agent-initiated screens from human-initiated screens.
- Return structured, machine-readable screening results to the agent. Agents cannot interpret PDF reports or HTML pages. Results should be JSON with clear match/no-match/partial-match indicators and match scores.
- Enforce minimum match thresholds. An agent should not be able to override or lower the match threshold below the institution's configured minimum.
- Log every screening request and result with the agent's cryptographic identity, a timestamp, and a unique request nonce.

### Don't

- Allow agents to bypass screening by calling payment endpoints directly without a prior screening step.
- Accept unsigned or invalidly signed results when the chosen message-signing profile requires signatures. TLS protects the connection, but does not prevent a compromised component from changing data after termination.
- Allow agents to cache screening results beyond a configurable time window. Sanctions lists are updated frequently and stale results create compliance gaps.
- Expose raw sanctions list data to agents. Agents should call a screening API, not download the full list.

## Section 3: Agent Operator Screening

Identify the customer and organization responsible for operating the agent. Determine which parties require sanctions screening and due diligence under the institution's approved compliance program. Do not assume that every developer, deployer, or operator is the legal customer merely because it provides the software; [FinCEN's CIP guidance](https://www.fincen.gov/resources/statutes-regulations/guidance/interagency-interpretive-guidance-customer-identification) makes customer identification depend on the account relationship. Bind the authenticated agent to the verified account and its delegated permissions as an application security control.

### Do

- Verify the organization responsible for the agent during onboarding and screen the parties identified by the institution's compliance program against applicable sanctions lists.
- Define rescreening triggers and frequency in the compliance program, including relevant list and ownership changes; restrict agent access when the required assessment does not permit the relationship to continue.
- Record the operator's screening status as part of the agent's trust profile.
- Require agents to declare their operator identity as part of their cryptographic passport or identity credential.

### Don't

- Assume that because an agent was verified once, its operator remains non-sanctioned indefinitely.
- Allow agents to operate without a declared operator. Anonymous agents MUST NOT access sanctions screening services.
- Accept operator identity claims without independent verification against business registries or KYB (Know Your Business) databases.

## Section 4: Signed Audit Trail

Keep tamper-evident audit records that associate the authenticated agent with the screening request and result. The following bullets describe an optional signed, hash-chained audit design. The [MCPS Internet-Draft](https://datatracker.ietf.org/doc/draft-sharif-mcps-secure-mcp/) separately proposes a message-signing and replay-protection layer; it is an individual work in progress, not an adopted MCP standard. Select a reviewed, interoperable profile when this protection is needed, and apply the [log-protection controls](Logging_Cheat_Sheet.md#protection) regardless of the chosen design.

### Do

- Sign every screening request with the agent's private key, including a unique nonce and timestamp.
- Sign every screening response with the server's private key, including its own nonce and timestamp.
- Chain audit entries using cryptographic hashes (each entry includes the SHA-256 hash of the previous entry) to create a tamper-evident log.
- Include in each audit entry: agent identity (public key fingerprint or passport ID), tool invoked, hash of the screening arguments (not the raw arguments, for privacy), screening result (match/no-match/partial), timestamp, and the hash of the previous audit entry.
- Retain audit records for the period required by applicable regulations (typically 5 years for BSA/AML).
- Make audit records exportable in a machine-readable format for regulatory examination.

### Don't

- Rely on application-level logging (e.g. `console.log`, syslog) as the sole audit trail. These logs are not tamper-evident and can be modified without detection.
- Store audit records on the agent's device or in agent-controlled storage. Audit records must be stored on infrastructure controlled by the financial institution.
- Omit the agent's identity from audit records. A screening record that does not identify which agent performed the check is useless for regulatory purposes.
- Allow gaps in the hash chain. A broken chain indicates tampering or data loss and must trigger an alert.

## Section 5: Fail-Closed Enforcement

Treat an incomplete or unavailable screening result as unresolved, never as clearance. Withhold transaction execution while the required assessment is unresolved; use bounded retries, manual review, or rejection according to the institution's approved policy. [OFAC advises financial institutions not to conclude transactions before the necessary analysis is complete](https://ofac.treasury.gov/faqs/43). A service failure is not itself a confirmed sanctions match; compliance owners must define the appropriate response for each case.

### Do

- Hold or reject the payment when required screening cannot be completed; do not release it unless the required assessment permits proceeding.
- Return a clear, structured error to the agent indicating that screening failed and the transaction cannot proceed.
- Log all screening failures with the same level of detail as successful screens, including the reason for failure.
- Alert compliance teams when screening failure rates exceed a threshold, as this may indicate a denial-of-service attack designed to force fail-open behavior.
- Implement circuit breakers that halt agent-initiated payments entirely if the screening service is unavailable for an extended period.

### Don't

- Allow transactions to proceed when screening results are unavailable, ambiguous, or timed out.
- Implement fallback logic that bypasses screening under any condition.
- Allow agents to retry screening indefinitely without rate limiting (this could be used to probe for timing-based information leakage).
- Return generic errors that do not distinguish between "screening service unavailable" and "screening completed with a match."

## Section 6: Trust-Tiered Rate Limiting

Not all agents should be treated equally. Unverified or low-trust agents should be rate-limited more aggressively than verified, high-trust agents. Rate limiting should be based on the agent's cryptographic identity, not IP address (which can be shared or spoofed). This pattern operationalises [OWASP API Security Top 10 API4:2023 (Unrestricted Resource Consumption)](https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/) in the agent-payment context.

### Do

- Implement per-agent rate limits based on cryptographic identity (public key fingerprint or passport ID).
- Set lower rate limits for newly registered or low-trust agents (e.g. L0/L1) and higher limits for verified, high-trust agents (e.g. L3/L4).
- Include rate limit status in screening responses (remaining quota, reset time) so agents can adjust their behavior.
- Downgrade an agent's rate limit allocation if anomalous behavior is detected (e.g. sudden spike in screening requests, unusual entity patterns).

### Don't

- Apply rate limits based solely on IP address. Multiple agents may share an IP, and a single agent may use multiple IPs.
- Set rate limits so high that they provide no meaningful protection against abuse.
- Allow agents to circumvent rate limits by creating multiple identities. Tie agent identities to verified operator accounts to prevent sybil attacks.

## Section 7: Self-Hosted vs Hosted Screening Architecture

Institutions must decide whether to run their own screening engine or use a hosted screening API. Both architectures are valid, but each has different security considerations when agents are the callers. The microservice-boundary trust posture in this section follows [NIST SP 800-209 (Security Guidelines for Storage Infrastructure)](https://csrc.nist.gov/pubs/sp/800/209/final) applied to the screening service plane.

### Self-Hosted Screening

- The institution maintains the sanctions lists, the matching engine, and the screening API on its own infrastructure.
- Agent requests stay within the institution's network boundary.
- The institution has full control over list update frequency, matching algorithms, and data retention.
- Requires operational investment in list ingestion, normalization, and matching quality.

### Hosted Screening (Third-Party API)

- The institution calls a third-party screening API (e.g. a sanctions screening provider).
- Agent identity credentials and screening data leave the institution's network boundary.
- The institution must ensure the third-party provider meets applicable regulatory requirements.
- Data minimization principles apply -- send only the minimum data needed for screening, not the agent's full context.

### Do

- Encrypt all screening requests in transit (TLS 1.2 minimum) regardless of architecture.
- If the threat model requires verification across untrusted intermediaries, use a reviewed message-signing profile supported by both endpoints; define trusted keys, signed fields, replay handling, and verification failures.
- Verify the screening provider's response signatures when the agreed profile requires them.

### Don't

- Send agent private keys or full identity credentials to a third-party screening provider. Send only the minimum identity attributes needed.
- Assume TLS protects data after the connection terminates. Protect each subsequent connection and decide which intermediaries are trusted to read or modify requests.

## Section 8: Receipt Canonicalization (RFC 8785 / JCS)

When systems independently serialize the same JSON object for hashing or signature verification, they need an agreed byte representation. JSON permits variable key order, whitespace, and number formatting, so two systems can produce different bytes for the same logical object.

[JSON Canonicalization Scheme (JCS), RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) provides one deterministic JSON representation for that use case. It is not required for every signed-token format: a [JSON Web Signature (JWS)](https://www.rfc-editor.org/rfc/rfc7515.html#section-5.2) verifier checks the encoded signing input rather than reserializing the payload. Cross-system verification also needs an agreed signature profile and a trusted verification key. Canonicalization alone supplies neither.

### Do

- If the receipt profile calls for independently serializing JSON, canonicalize the agreed payload before signing and before verification.
- Use the hashing and signing procedure required by the chosen signature profile and API; do not add a separate prehash unless that profile requires it.
- Record the canonicalization and signature profile used so a verifier can reproduce the signing input.

### Don't

- For a profile that requires reconstructing signed JSON, don't rely on framework-default or pretty-printed serialization; key order and whitespace can differ across systems.
- Don't assume two services emit identical JSON for the same object; they usually will not.

## Section 9: Cross-Agent Payment Accountability

Agent payments can traverse multiple agents. When downstream services rely on a signed screening receipt, they must verify it using a key bound to a trusted screening issuer. [Digital signatures provide data-origin and integrity assurance](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf#page=18); they do not prove that the issuer performed screening correctly. The receipt records the issuer's assertions about the entities, lists, and decision, so the verifier still needs a policy for which screening issuers it trusts.

Bind each receipt to the specific transaction (include the transaction or intent hash in the signed payload) and propagate it end-to-end. Each hop verifies the inbound receipt and, if it takes its own action, appends its own signed receipt, producing a verifiable chain of accountability across agents. See [Optional Message-Level Integrity](MCP_Security_Cheat_Sheet.md#7-optional-message-level-integrity) for the additional threat model and profile requirements.

### Do

- Attach the signed compliance receipt to the transaction and propagate it across every agent hop.
- Bind each receipt to the transaction by signing over the transaction or intent hash.
- At each hop, verify the signature, trusted issuer, transaction binding, and acceptable screening freshness before relying on the receipt; append a new signed receipt for any action taken.

### Don't

- Don't keep the receipt only in the issuing system's logs, because downstream agents then cannot prove screening occurred.
- Don't let a downstream agent rely on an upstream agent's unverifiable claim that screening happened.

## Section 10: Binding Sanctions-List Freshness to the Receipt

A receipt stating "screened, no match" is meaningless without which version of the list, and as of when. Sanctions lists change frequently; a clean screen against a stale list is a compliance gap. Bind the **list version and timestamp** into the signed receipt so screening freshness is itself non-tamperable and auditable. Public sanctions sources such as the [OFAC Sanctions List Search](https://sanctionssearch.ofac.treas.gov/) and the [EU Consolidated Sanctions List](https://data.europa.eu/data/datasets/consolidated-list-of-persons-groups-and-entities-subject-to-eu-financial-sanctions) change frequently, so the version screened against must be recorded.

### Do

- Include the sanctions-list source(s), version or publication date, and screening timestamp **inside the signed receipt**.
- Bind each screening result and list version to the specific transaction or payment intent in the signed data, so a later verifier can distinguish it from another transaction.
- Enforce the verifier's maximum acceptable list age and screening age; do not let an issuer-supplied age limit override that policy.
- Retain evidence of the list version used and the screening service's update history. A signed timestamp or version protects the recorded assertion from alteration; it does not independently establish that the list was current or actually used.

### Don't

- Don't assert a screening result without recording the list version and date it was screened against.
- Don't treat "screened" as a boolean; a clean result against an out-of-date list is not compliant.

## Section 11: Regulatory Mapping

The controls in this cheat sheet map to common AML and sanctions obligations. This mapping is illustrative and is not legal advice; obligations vary by jurisdiction. For underlying obligations see, for example, the [Bank Secrecy Act](https://www.fincen.gov/index.php/resources/statutes-and-regulations/bank-secrecy-act) and [FinCEN Customer Due Diligence Requirements](https://www.fincen.gov/resources/statutes-regulations/federal-register-notices/customer-due-diligence-requirements).

| Control (this cheat sheet) | Maps to |
| --- | --- |
| Agent identity before screening (Section 1) | Technical attribution and authorization; does not replace applicable customer or beneficial-owner identification |
| Entity and operator screening (Sections 2-3) | Screening parties identified by the applicable sanctions compliance program; not a universal legal duty to screen every software operator |
| Signed audit trail and receipt (Sections 4, 8-10) | Recordkeeping; FATF Recommendation 11; multi-year retention (BSA, EU AMLD) |
| Sanctions-list freshness in receipt (Section 10) | Evidence of which list data supported the assessment; list screening alone does not establish compliance |
| Fail-closed enforcement (Section 5) | Preventing execution while required checks are unresolved; distinguish this technical gate from legal blocking obligations for confirmed sanctions matches |
| Trust-tiered limits (Section 6) | Risk-based approach (FATF Recommendation 1); monitoring thresholds |

### Do

- Treat this table as a starting point and confirm specific obligations with qualified counsel for each operating jurisdiction.

### Don't

- Don't rely on a single jurisdiction's lists or rules for a cross-border agent payment system.

## Section 12: Do's and Don'ts Summary

The consolidated controls below align with the AI-system-specific verification requirements in the [OWASP Artificial Intelligence Security Verification Standard (AISVS)](https://github.com/OWASP/AISVS), in particular Chapter 10 (MCP Security Requirements).

### Do

- Verify agent identity cryptographically before every screening request.
- When using a message-signing profile, sign and verify screening requests and responses and enforce its replay controls.
- Screen counterparties and relevant operator entities as defined by the institution's applicable compliance program.
- Protect screening audit records against unauthorized changes and deletion; use hash chaining when the chosen audit design requires it.
- Withhold transaction execution on a screening error, timeout, or ambiguous result until the required assessment permits proceeding.
- Rate limit based on cryptographic agent identity, not IP address.
- Apply graduated trust levels with different access rights and rate limits.
- Re-screen relevant parties according to the compliance program's list-change and other review triggers.
- Make audit records exportable for regulatory examination.

### Don't

- Accept self-declared agent identity without cryptographic proof.
- Allow transactions to proceed when screening fails or is unavailable.
- Store audit records in agent-controlled infrastructure.
- Cache screening results beyond a configurable time window.
- Allow agents to lower match thresholds or override screening results.
- Treat transport protection as protection from a compromised component after TLS termination.
- Allow anonymous agents to access screening services.
- Assume that a one-time identity check is sufficient for ongoing access.

## References

- [FinCEN: Customer Due Diligence Requirements for Financial Institutions](https://www.gpo.gov/fdsys/pkg/FR-2016-05-11/pdf/2016-10567.pdf)
- [NIST SP 800-53 Rev. 5: Security and Privacy Controls](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
- [OFAC: A Framework for Compliance Commitments](https://ofac.treasury.gov/system/files/126/framework_ofac_cc.pdf)
