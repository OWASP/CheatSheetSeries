# AML and Sanctions Compliance for AI Agent Payments Cheat Sheet

## Introduction

AI agents are initiating regulated financial transactions in production. Mastercard Agent Pay, Visa Intelligent Commerce, and Google A2A payments are live. Every agent-initiated payment carries the same Bank Secrecy Act (BSA), Anti-Money Laundering (AML), and sanctions screening obligations as human-initiated payments.

This cheat sheet provides practical controls for fintechs, banks, and payment processors when autonomous AI agents -- rather than human users in browser sessions -- initiate or facilitate regulated payments. It covers agent identity verification, entity screening, audit trail requirements, and fail-closed enforcement.

The controls described here are complementary to the [OWASP MCP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html) and build on the cryptographic identity and signing controls defined in Section 7 of that document.

## Regulatory Context

Agent-initiated payments are subject to the same regulatory framework as human-initiated payments. Key regulations include:

- **Bank Secrecy Act (BSA)**: Requires financial institutions to maintain effective AML programmes, including customer identification, transaction monitoring, and suspicious activity reporting. The [Bank Secrecy Act](https://www.fincen.gov/index.php/resources/statutes-and-regulations/bank-secrecy-act) does not distinguish between human-initiated and agent-initiated transactions.
- **OFAC Sanctions**: The Office of Foreign Assets Control requires all US persons and entities to screen transactions against the Specially Designated Nationals (SDN) list and other sanctions lists. Screening obligations apply regardless of whether the transaction was initiated by a human or an agent.
- **FinCEN Requirements**: [FinCEN](https://www.fincen.gov/) rules require Customer Identification Programs (CIP), Customer Due Diligence (CDD), and Suspicious Activity Reports (SARs). When an agent acts on behalf of a customer, the institution must be able to identify both the customer and the agent.
- **UK Financial Sanctions (OFSI)**: HM Treasury's Office of Financial Sanctions Implementation maintains the [UK Consolidated Sanctions List](https://www.gov.uk/government/publications/financial-sanctions-consolidated-list-of-targets). Screening is mandatory for all financial transactions regardless of initiation method.
- **EU Sanctions**: The [EU Consolidated Sanctions List](https://data.europa.eu/data/datasets/consolidated-list-of-persons-groups-and-entities-subject-to-eu-financial-sanctions) applies to all transactions processed through EU-regulated entities. Agent-initiated transactions are not exempt.
- **OCC BSA/AML Exam Procedures**: [OCC examiners](https://www.occ.treas.gov/topics/supervision-and-examination/bsa/index-bsa.html) assess whether institutions have controls to identify the originator of each transaction. When agents initiate transactions, the institution must demonstrate that agent identity was verified and the transaction was screened.

### Key Principle

Regulators do not care whether a transaction was initiated by a human clicking a button or an agent calling an API. The compliance obligations are identical. The burden is on the institution to prove that screening occurred, that the agent was authorised, and that the results are tamper-evident.

## Section 1: Agent Identity Before Screening

Before an agent is permitted to access sanctions screening services or initiate a payment, its identity must be cryptographically verified. Self-declared identity headers (e.g. `X-Agent-ID`, `X-Agent-Role`) without cryptographic proof MUST be rejected. The message-level identity primitives in [Section 7 of the OWASP MCP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html#7-message-level-integrity-and-replay-defence) apply directly to the agent-payment context.

### Do

- Require agents to present a cryptographic identity credential (e.g. signed passport, ECDSA key pair, or verifiable credential) before accessing screening endpoints.
- Bind the agent's identity to the screening request so the audit trail proves which specific agent performed the check.
- Verify the agent's trust level before granting access. Not all agents should have the same level of access to sanctions data. Use graduated trust levels (e.g. L0 to L4) with increasing access rights.
- Record the agent's public key fingerprint or passport ID in every screening request log entry.

### Don't

- Accept self-declared identity claims without cryptographic verification.
- Allow agents to access screening endpoints without authentication.
- Trust transport-layer identity (TLS client certificates at a load balancer) as the sole proof of agent identity. Message-level identity binding is required.
- Allow agents to escalate their own trust level or modify their own permissions.

## Section 2: Entity Screening

Entity screening against global sanctions lists (OFAC SDN, UK HMT, EU Consolidated, UN Consolidated) remains fundamentally unchanged when agents are the callers. The screening engine matches names, addresses, vessels, and identifiers against the lists. What changes is the context around the screening request. The authoritative source for the United States is the [OFAC Sanctions List Search](https://sanctionssearch.ofac.treas.gov/).

### Do

- Screen all counterparties (individuals, businesses, vessels, addresses) against applicable sanctions lists before processing a payment.
- Include the agent's identity and trust level in the screening context so that downstream systems can distinguish agent-initiated screens from human-initiated screens.
- Return structured, machine-readable screening results to the agent. Agents cannot interpret PDF reports or HTML pages. Results should be JSON with clear match/no-match/partial-match indicators and match scores.
- Enforce minimum match thresholds. An agent should not be able to override or lower the match threshold below the institution's configured minimum.
- Log every screening request and result with the agent's cryptographic identity, a timestamp, and a unique request nonce.

### Don't

- Allow agents to bypass screening by calling payment endpoints directly without a prior screening step.
- Return screening results without signing them. Unsigned results can be tampered with in transit, allowing a compromised intermediary to change a "match" to "no match."
- Allow agents to cache screening results beyond a configurable time window. Sanctions lists are updated frequently and stale results create compliance gaps.
- Expose raw sanctions list data to agents. Agents should call a screening API, not download the full list.

## Section 3: Agent Operator Screening

The agent itself is software. But the agent has an operator -- the developer, company, or deployer that built and runs it. The agent's operator must also be screened against sanctions lists. The framework for verifying the underlying entity follows the [FinCEN Customer Due Diligence Requirements](https://www.fincen.gov/resources/statutes-regulations/federal-register-notices/customer-due-diligence-requirements) applied to the operator as the regulated counterparty behind the agent.

### Do

- Screen the agent's declared operator (organisation name, jurisdiction, registration number) against sanctions lists during agent onboarding.
- Re-screen agent operators periodically (at minimum when sanctions lists are updated) and revoke agent access if the operator becomes sanctioned.
- Record the operator's screening status as part of the agent's trust profile.
- Require agents to declare their operator identity as part of their cryptographic passport or identity credential.

### Don't

- Assume that because an agent was verified once, its operator remains non-sanctioned indefinitely.
- Allow agents to operate without a declared operator. Anonymous agents MUST NOT access sanctions screening services.
- Accept operator identity claims without independent verification against business registries or KYB (Know Your Business) databases.

## Section 4: Signed Audit Trail

Every screening interaction must produce a tamper-evident audit record that a compliance officer or regulator can verify. When agents perform screening, the audit trail must cryptographically bind the agent's identity to the screening request and result. The hash-chained, ECDSA-signed audit-entry pattern used in this section is specified in detail in the [IETF Internet-Draft draft-sharif-mcps-secure-mcp](https://datatracker.ietf.org/doc/draft-sharif-mcps-secure-mcp/).

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

When screening fails -- due to a timeout, service outage, malformed response, or any other error -- the system MUST deny the transaction. Silent pass-through on screening failure is a compliance violation. The fail-closed posture is consistent with the AC-4 information-flow-enforcement and AU-12 audit-record-generation control families defined in [NIST SP 800-53 Revision 5](https://csrc.nist.gov/pubs/sp/800/53/r5/final).

### Do

- Deny the payment or transaction if screening cannot be completed successfully.
- Return a clear, structured error to the agent indicating that screening failed and the transaction cannot proceed.
- Log all screening failures with the same level of detail as successful screens, including the reason for failure.
- Alert compliance teams when screening failure rates exceed a threshold, as this may indicate a denial-of-service attack designed to force fail-open behaviour.
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
- Include rate limit status in screening responses (remaining quota, reset time) so agents can adjust their behaviour.
- Downgrade an agent's rate limit allocation if anomalous behaviour is detected (e.g. sudden spike in screening requests, unusual entity patterns).

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
- Requires operational investment in list ingestion, normalisation, and matching quality.

### Hosted Screening (Third-Party API)

- The institution calls a third-party screening API (e.g. a sanctions screening provider).
- Agent identity credentials and screening data leave the institution's network boundary.
- The institution must ensure the third-party provider meets applicable regulatory requirements.
- Data minimisation principles apply -- send only the minimum data needed for screening, not the agent's full context.

### Do

- Encrypt all screening requests in transit (TLS 1.2 minimum) regardless of architecture.
- Sign screening requests at the message level (not just transport level) to ensure integrity through intermediaries, CDNs, or proxies.
- Verify the screening provider's response signatures if using a hosted service.

### Don't

- Send agent private keys or full identity credentials to a third-party screening provider. Send only the minimum identity attributes needed.
- Assume that TLS alone provides sufficient integrity. After TLS termination at a load balancer or CDN, the plaintext request is visible to downstream components.

## Section 8: Receipt Canonicalization (RFC 8785 / JCS)

A compliance receipt is only verifiable across systems if every party serializes it to the **exact same bytes** before signing and verifying. JSON permits variable key order, whitespace, and number formatting, so two systems can produce different byte streams for the *same* logical receipt, and a signature over one will fail against the other.

Use the **JSON Canonicalization Scheme (JCS), [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785)**, to produce a deterministic byte representation before hashing and signing. The signer canonicalizes, hashes (for example with SHA-256), then signs; every verifier canonicalizes the received receipt identically and checks the signature. This makes receipts verifiable by **any** counterparty, regulator, or downstream agent, not just the issuing system.

### Do

- Canonicalize every receipt with RFC 8785 (JCS) before signing, and again before verifying.
- Sign over the hash of the canonical bytes, not raw or pretty-printed JSON.
- Record the canonicalization, hash, and signature algorithm in the receipt (for example `canon: jcs`, `alg: ecdsa-p256-sha256`) so any verifier can reproduce it.

### Don't

- Don't sign framework-default or pretty-printed JSON, because key order or whitespace differences break cross-system verification.
- Don't assume two services emit identical JSON for the same object; they usually will not.

## Section 9: Cross-Agent Payment Accountability

Agent payments often traverse multiple agents (orchestrator to sub-agent to service). If the compliance receipt stays only with the issuing system, accountability is lost at the first hop. The signed receipt MUST **travel with the transaction** so every downstream party can independently verify who was screened, against which lists, and what was decided, without trusting an upstream agent's word.

Bind each receipt to the specific transaction (include the transaction or intent hash in the signed payload) and propagate it end-to-end. Each hop verifies the inbound receipt and, if it takes its own action, appends its own signed receipt, producing a verifiable chain of accountability across agents. Message-level integrity and replay defence for such receipts is covered in [Section 7 of the OWASP MCP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html#7-message-level-integrity-and-replay-defence).

### Do

- Attach the signed compliance receipt to the transaction and propagate it across every agent hop.
- Bind each receipt to the transaction by signing over the transaction or intent hash.
- At each hop, verify the inbound receipt before acting, and append a new signed receipt for any action taken.

### Don't

- Don't keep the receipt only in the issuing system's logs, because downstream agents then cannot prove screening occurred.
- Don't let a downstream agent rely on an upstream agent's unverifiable claim that screening happened.

## Section 10: Binding Sanctions-List Freshness to the Receipt

A receipt stating "screened, no match" is meaningless without which version of the list, and as of when. Sanctions lists change frequently; a clean screen against a stale list is a compliance gap. Bind the **list version and timestamp** into the signed receipt so screening freshness is itself non-tamperable and auditable. Public sanctions sources such as the [OFAC Sanctions List Search](https://sanctionssearch.ofac.treas.gov/) and the [EU Consolidated Sanctions List](https://data.europa.eu/data/datasets/consolidated-list-of-persons-groups-and-entities-subject-to-eu-financial-sanctions) change frequently, so the version screened against must be recorded.

### Do

- Include the sanctions-list source(s), version or publication date, and screening timestamp **inside the signed receipt**.
- Define a maximum acceptable list age, record it in the receipt, and fail-closed if it is exceeded.
- Make list freshness auditable after the fact from the receipt alone.

### Don't

- Don't assert a screening result without recording the list version and date it was screened against.
- Don't treat "screened" as a boolean; a clean result against an out-of-date list is not compliant.

## Section 11: Regulatory Mapping

The controls in this cheat sheet map to common AML and sanctions obligations. This mapping is illustrative and is not legal advice; obligations vary by jurisdiction. For underlying obligations see, for example, the [Bank Secrecy Act](https://www.fincen.gov/index.php/resources/statutes-and-regulations/bank-secrecy-act) and [FinCEN Customer Due Diligence Requirements](https://www.fincen.gov/resources/statutes-regulations/federal-register-notices/customer-due-diligence-requirements).

| Control (this cheat sheet) | Maps to |
| --- | --- |
| Agent identity before screening (Section 1) | KYC/KYB attribution; FATF Recommendation 10 (Customer Due Diligence) |
| Entity and operator screening (Sections 2-3) | OFAC, EU, UK, and UN sanctions screening; FATF Recommendation 6 |
| Signed audit trail and receipt (Sections 4, 8-10) | Recordkeeping; FATF Recommendation 11; multi-year retention (BSA, EU AMLD) |
| Sanctions-list freshness in receipt (Section 10) | Obligation to screen against current lists; sanctions-evasion controls |
| Fail-closed enforcement (Section 5) | Blocking obligations for sanctioned parties |
| Trust-tiered limits (Section 6) | Risk-based approach (FATF Recommendation 1); monitoring thresholds |

### Do

- Treat this table as a starting point and confirm specific obligations with qualified counsel for each operating jurisdiction.

### Don't

- Don't rely on a single jurisdiction's lists or rules for a cross-border agent payment system.

## Section 12: Do's and Don'ts Summary

The consolidated controls below align with the AI-system-specific verification requirements in the [OWASP Artificial Intelligence Security Verification Standard (AISVS)](https://github.com/OWASP/AISVS), in particular Chapter 10 (MCP Security Requirements).

### Do

- Verify agent identity cryptographically before every screening request.
- Sign every screening request and response with unique nonces and timestamps.
- Screen both the counterparty entity and the agent's operator against sanctions lists.
- Maintain a hash-chained, tamper-evident audit trail of every screening interaction.
- Fail closed on any screening error, timeout, or ambiguous result.
- Rate limit based on cryptographic agent identity, not IP address.
- Apply graduated trust levels with different access rights and rate limits.
- Re-screen agent operators periodically as sanctions lists are updated.
- Make audit records exportable for regulatory examination.

### Don't

- Accept self-declared agent identity without cryptographic proof.
- Allow transactions to proceed when screening fails or is unavailable.
- Store audit records in agent-controlled infrastructure.
- Cache screening results beyond a configurable time window.
- Allow agents to lower match thresholds or override screening results.
- Rely on transport-layer security (TLS) alone for message integrity.
- Allow anonymous agents to access screening services.
- Assume that a one-time identity check is sufficient for ongoing access.

## References

- [OWASP MCP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html) -- Section 7: Message-Level Integrity
- [OWASP Artificial Intelligence Security Verification Standard (AISVS)](https://github.com/OWASP/AISVS) -- Chapter 10: MCP Security Requirements
- [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/) -- MCP01 (Token Mismanagement), MCP07 (Insufficient Auth), MCP08 (Lack of Audit)
- [OWASP API Security Top 10 (2023)](https://owasp.org/API-Security/editions/2023/en/0x00-header/) -- API4 Unrestricted Resource Consumption
- [IETF draft-sharif-mcps-secure-mcp](https://datatracker.ietf.org/doc/draft-sharif-mcps-secure-mcp/) -- Cryptographic Security Layer for MCP
- [NIST SP 800-53 Revision 5](https://csrc.nist.gov/pubs/sp/800/53/r5/final) -- Security and Privacy Controls for Information Systems and Organizations
- [NIST SP 800-209](https://csrc.nist.gov/pubs/sp/800/209/final) -- Security Guidelines for Storage Infrastructure
- [OFAC Sanctions List Search](https://sanctionssearch.ofac.treas.gov/)
- [UK HM Treasury Consolidated Sanctions List](https://www.gov.uk/government/publications/financial-sanctions-consolidated-list-of-targets)
- [EU Consolidated Financial Sanctions List](https://data.europa.eu/data/datasets/consolidated-list-of-persons-groups-and-entities-subject-to-eu-financial-sanctions)
- [FinCEN](https://www.fincen.gov/) -- BSA / AML regulations and SAR filings
- [FinCEN Customer Due Diligence (CDD) Requirements](https://www.fincen.gov/resources/statutes-regulations/federal-register-notices/customer-due-diligence-requirements)
- [OCC BSA/AML Examination Procedures](https://www.occ.treas.gov/topics/supervision-and-examination/bsa/index-bsa.html)
