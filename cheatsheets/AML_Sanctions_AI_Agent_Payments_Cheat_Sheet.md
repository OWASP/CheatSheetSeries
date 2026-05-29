# AML and Sanctions Compliance for AI Agent Payments

## Introduction

AI agents increasingly initiate financial transactions autonomously. When an
agent approves a loan, executes a trade, or processes a payment, the same
Anti-Money Laundering (AML) and sanctions screening obligations apply as for
human-initiated transactions. The challenge: proving compliance when the
decision-maker is software, not a person.

This cheat sheet covers the controls needed to make AI agent payment decisions
auditable, compliant, and independently verifiable.

## Pre-Transaction Compliance Checks

Every agent-initiated payment must pass compliance screening before execution,
not after.

**DO:**

- Run sanctions screening (OFAC, EU, UN lists) against all counterparties
  before the agent executes the payment
- Generate a signed receipt proving the screening ran, capturing: the lists
  checked, the timestamp, the verdict (ALLOW/DENY/REFER), and the agent
  identity
- Store the receipt independently from the agent's own logs (the agent
  should not be the sole custodian of its compliance evidence)

**DON'T:**

- Allow agents to execute payments and screen afterward
- Trust the agent's self-reported compliance status without independent
  verification
- Assume that because the agent was configured correctly at deployment,
  it remains compliant at execution time


## Tamper-Evident Audit Trails

Regular application logs are insufficient for AML compliance because the
operator can modify them after the fact. Agent payment audit trails must be
tamper-evident.

**Requirements:**

- Every payment decision generates a cryptographically signed receipt
  (Ed25519 or equivalent) over a canonical representation of the decision
  context
- Receipts are hash-chained so that deletion or reordering is detectable
- An external auditor can verify the chain without access to the agent's
  runtime or the operator's infrastructure

**Receipt contents (minimum viable):**

- Agent identity (who made the decision)
- Action type (payment.screen, payment.execute, payment.settle)
- Counterparty identifiers (hashed if PII restrictions apply)
- Sanctions list versions checked
- Verdict (ALLOW, DENY, REFER for manual review)
- Timestamp (millisecond precision, UTC)
- Signature (detached, over the canonical form of the above fields)

**Canonicalization:** Use RFC 8785 (JSON Canonicalization Scheme / JCS) to
ensure byte-deterministic serialization. Without canonical form, two correct
implementations can produce different bytes for the same logical receipt,
breaking cross-system verification.

## Cross-Agent Payment Accountability

When multiple agents participate in a payment chain (e.g., an initiating
agent, a routing agent, and a settlement agent), each agent must produce
its own receipt for its own decision.

**Key principle:** The receipt travels with the transaction. A downstream
agent or auditor can verify every upstream decision without trusting any
single operator.

**Pattern:**

1. Agent A screens the counterparty, produces Receipt_A (verdict: ALLOW)
2. Agent A passes Receipt_A's action_ref to Agent B along with the payment
3. Agent B screens independently, produces Receipt_B referencing Receipt_A
4. The settlement layer holds both receipts as evidence
5. An auditor verifies both signatures and the referential chain

**Anti-pattern:** A single "compliance gateway" that screens once and issues
a blanket approval token. This creates a single point of trust and a single
point of failure. Per-agent receipts distribute the evidence.

## Sanctions List Freshness

Agents operating continuously must verify they are screening against
current sanctions lists, not stale cached copies.

**Controls:**

- Record the list version or publication date in every screening receipt
- Set a maximum staleness threshold (e.g., 24 hours) beyond which the
  agent must refuse to execute until lists are refreshed
- Include the staleness check outcome in the signed receipt so an auditor
  can verify the agent was using current data at decision time

## Suspicious Activity Reporting

When an agent detects patterns consistent with money laundering (structuring,
rapid counterparty cycling, jurisdiction hopping), it must:

1. Generate a signed receipt with action_type: "sar.flag" capturing the
   pattern detected and the evidence
2. Route the flag to a human compliance officer (agents should not
   autonomously file SARs)
3. Continue operating within its constraints but escalate the flagged
   transaction for human review

**Critical:** The agent must not tip off the counterparty that a flag was
raised. The receipt for a flagged transaction should be stored in a
restricted evidence channel, not in the agent's general audit trail.

## Regulatory Mapping

| Regulation | Requirement | Agent Control |
|---|---|---|
| BSA/AML (US) | Customer identification, transaction monitoring | Pre-transaction screening receipt with counterparty hash |
| EU AMLD6 | Enhanced due diligence for high-risk | Per-transaction signed receipt with risk score |
| EU AI Act Art. 12 | Automatic recording of events | Tamper-evident hash-chained audit trail |
| FATF Rec. 16 | Originator/beneficiary info for wire transfers | Receipt carries originator_ref and beneficiary_ref |
| OFAC | Sanctions screening | Receipt proves screening ran with list version |

## References

- [OWASP AARS (Agentic AI Risk Scoring)](https://github.com/OWASP/www-project-artificial-intelligence-vulnerability-scoring-system)
- [RFC 8785 - JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785)
- [FATF Recommendations](https://www.fatf-gafi.org/recommendations.html)
- [EU AI Act Article 12](https://eur-lex.europa.eu/eli/reg/2024/1689/oj)
