# Verifying Third-Party Agent Execution Evidence Cheat Sheet

## Introduction

A team that adopts an agent, an MCP server, or a skill it did not build ends up holding a record of what that component did, and someone has to say what that record establishes. [MCP Security](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html#10-monitoring-logging-auditing) and [AI Agent Security](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html#6-monitoring-observability) both tell you to log every tool invocation, and each of those instructions is satisfied by a record the observed component wrote about itself. This cheat sheet covers the other side of that exchange, where the record was produced by the same party it describes. It gives a reviewer six questions to ask of such a record, and a way to score the answers.

## Three Review Outcomes

Score each question below with one of three outcomes, and score the record no higher than its weakest answer. [MCP08:2025 Lack of Audit and Telemetry](https://owasp.org/www-project-mcp-top-10/2025/MCP08-2025%E2%80%93Lack-of-Audit-and-Telemetry) recommends "cryptographic hashing (HMAC, SHA-256) to log files for integrity" and "audit trail self-verification, where logs cross-reference session data for consistency". Both are sound for an operator who holds the logs and the key. A reviewer holds neither.

| Outcome | What it means | What it will carry |
|---|---|---|
| Independently re-checkable | A party who cannot produce the record can confirm it, from material the producer does not control when the check runs. | A disagreement with the supplier. |
| Supplier assertion | A claim by an interested party. It may well be true, and nothing in the record establishes it. | Operational awareness, and anything the supplier has no incentive to misstate. |
| No information about this execution | The record cannot distinguish a clean run from no run at all. | Nothing. |

Three activities get called verification, and this sheet keeps them apart: reading a record or re-running the producer's own tool over it is re-checking, watching an event as it happens is witnessing, and re-checking offline as a party who trusts neither the component nor its operator is what these questions test. The [Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html#verification) uses the word in its own sense, of testing that logging works as specified, and both senses are in ordinary use across this series.

## Six Questions to Ask About an Execution Record

These are questions about a record as an artifact, so they apply to a plain signed JSON log, a structured attestation such as an [in-toto Statement](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md), a [COSE receipt](https://datatracker.ietf.org/doc/html/rfc9942), or a supplier's proprietary export. Each closes with the outcome that common answers map to.

### 1. Could the component the record describes have written or altered it?

A component that writes its own execution log can omit the call that mattered, rewrite an argument, or emit a record for a run that did not happen, and the document still parses with every field complete. What settles the question is not where the recorder sits in a diagram, but how many parties would have to cooperate to produce this record for a run that did not happen.

- List the parties between the event and the bytes you hold: the component, its host, the recorder's operator, the keyholder.
- Count parties, not processes. A recorder the supplier operates is one party however many hosts it spans.
- Look for an input the component did not choose. A recorder fed only by the component records the component's report.
- Check whether the signing service will sign arbitrary content on the component's request.
- If it will, that signature is worth what a readable key is worth.
- Look for a copy landing where the component cannot change it. [ASVS 16.4.2](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x25-V16-Security-Logging-and-Error-Handling.md) asks that logs "cannot be modified".

**Outcome.** Most agent telemetry shipping today is a supplier assertion, and it is worth saying so plainly: SDK-emitted spans, a framework's own traces, an MCP server's logs, and a hosted provider's export are all fed by the component and handled downstream by a single party. Independently re-checkable needs an input the component did not choose and a party with no stake in the answer. A supplier who will not describe the path scores no information. Where the answer is supplier assertion and you still have to proceed:

- Corroborate against a record your own side produces, such as a gateway or egress log covering the same calls.
- Contract for a copy delivered to a party the supplier cannot edit.
- Size the decision so this record is not its only basis.

### 2. Was the record witnessed while the work ran, or assembled afterwards?

A record assembled after execution, from state the component still controls, inherits every weakness of that state, and the artifact looks identical either way. Capture during the run narrows the window in which an account can be composed to fit a known outcome.

- Treat a timestamp applied over a finished record as a bound on how late it was written.
- A timestamp field inside the record is an assertion by the producer.
- [RFC 3161](https://datatracker.ietf.org/doc/html/rfc3161) countersigning is stronger, but the authority "may be operated as a Trusted Third Party (TTP) service, though other operational models may be appropriate".
- Apply question 1 to whoever operates that authority.
- Look for a bound in the other direction, since contemporaneity is a claim about how early the record was fixed.
- [RFC 9334 Section 10](https://datatracker.ietf.org/doc/html/rfc9334#section-10) gives three approaches. Send a nonce to be signed into the record, and on a match "the appraising entity knows that the Claims were signed after the nonce was generated".
- A challenge issued mid-run also reaches components that never produce a discrete finished document.
- Read whether the record covers one execution or several, and whether per-step material survives.

**Outcome.** A countersignature from an authority the supplier does not operate, or a nonce you supplied, makes the timing independently re-checkable. A producer-asserted timestamp, or a countersignature from the supplier's own authority, is a supplier assertion. No timing evidence at all, or entries aggregated across runs with nothing per-step surviving, gives no information about this execution.

### 3. What is the record about, and is that thing named precisely enough to re-check?

A correctly signed record whose subject is named loosely, as "the agent" or "the latest build", can be presented next to a different artifact than the one it describes. Nothing is forged and no signature fails; the reviewer draws a conclusion about the thing in front of them from evidence about something else.

- Look for the subject identified by content, using a cryptographic digest of the artifact, image, configuration, or transcript described.
- The [in-toto Statement layer](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md) is one worked example: every subject element "MUST have `digest` set" and subjects "are matched purely by digest".
- Recompute the digest over the artifact you received through your own channel, not over a copy shipped in the same bundle as the record.
- Check that the subject separates this execution from another run of the same artifact.
- A digest identical across runs lets any record stand for any run.
- Read which run-determining inputs the record enumerates, and treat anything unenumerated as uncovered.
- A digest over an agent binary says nothing about the tool definitions, prompts, model version, or policy the run used.

**Outcome.** A digest you can recompute from your own copy is independently re-checkable, and what it establishes is which artifact the claim is about. A name without a digest, or a digest that does not vary per run, is a supplier assertion about identity. A record that identifies neither the artifact nor the execution gives no information about this execution.

### 4. If something was left out, would you be able to tell?

Reviewers read absence as evidence: no denied call means nothing was denied. That reading holds only when the recorder was positioned to see the event and could not decline to write it. A component able to suppress one entry produces a clean record and a clean summary.

- Check whether the record states its window. A window you inferred from the entries present is not a stated one.
- Treat a transparency log as detection of removal after entry. It says nothing about an entry that was never made.
- [RFC 9162](https://datatracker.ietf.org/doc/html/rfc9162) describes an append-only log built on Merkle Trees, which can prove that any particular instance "of the log is a superset of any particular previous instance".
- [Sigstore's Rekor](https://docs.sigstore.dev/logging/overview/) is one deployed instance of such a log.
- Find out what forces an event into that log when it occurs, and whether that mechanism is under the observed component's control.
- Discount a sequence number the producer maintains, since it counts what the producer chose to count.
- Gap detection needs a sequence advanced from outside the producer's control, such as an independent log's tree size.
- Generate an event you expect to appear, such as a denied call or a blocked write.
- Check that it reaches the record you are handed.
- Where you cannot run the component, ask for a sandbox tenant, and failing that cross-check against records from your own side of the boundary.

**Outcome.** Coverage is independently re-checkable when something outside the producer saw the sequence: an independent log, your own boundary records, or an event you injected and found. A window backed only by the producer's own numbering is a supplier assertion. An undated selection, or a window you had to infer, gives no information about this execution.

### 5. What happened if recording or delivery failed?

If a component keeps executing when its recorder is unreachable, an empty record and a clean run are indistinguishable, and the cheapest attack is to break the recording path instead of forging anything. The [Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html#attacks-on-logs) lists this under Accountability: an attacker prevents writes in order to cover their tracks.

- Get the behavior on the unavailable path in writing. Continue-and-drop, buffer-and-retry, and halt are three different behaviors under load.
- Read the overflow behavior, not the happy path. A bounded buffer that overwrites oldest-first under pressure is continue-and-drop at the moment it matters.
- Look for delivery failures recorded where the component has no reach. [ASVS 16.4.3](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x25-V16-Security-Logging-and-Error-Handling.md) asks that logs are "securely transmitted to a logically separate system", which is where a gap marker has to land.
- [ASVS 16.5.3](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x25-V16-Security-Logging-and-Error-Handling.md) separately asks that an application "fails gracefully and securely, including when an exception occurs, preventing fail-open conditions". That is the component's own behavior.
- Interrupt the recording path in your own environment and watch whether execution continues.
- Where the component is hosted, ask for gap markers from a real outage.
- An operator who has never recorded a gap is telling you the marker is not emitted.

**Outcome.** A gap marker landing in a system the component does not control, or an interruption you performed yourself, is independently re-checkable. Documented fail-closed behavior you have not seen exercised is a supplier assertion. Treat "no findings" from a recorder that may have been fail-open as no information about that execution. Completeness is what this question tests; the accuracy of what was written is question 1.

### 6. Can the record be verified by someone who cannot also produce one?

If the key material needed to check a record is the key material needed to create one, every party who can check can also forge, and the record cannot settle a disagreement between them. [RFC 2104](https://datatracker.ietf.org/doc/html/rfc2104) describes message authentication codes as "used between two parties that share a secret key in order to validate information transmitted between these parties". A shared-secret receipt is a reasonable control between a client and a server that already trust each other, and it carries nothing to the third party a reviewer is.

- Check what a reviewer must hold to run the check.
- A public key permits checking without conferring the ability to produce; a shared secret does not.
- Count whose keys these are. Two keys held by one party are one party.
- Check what the check depends on while it runs. Asking the producer's service whether a record is valid returns the claim under review.
- Fetching public trust material, such as a root or an inclusion proof from an independent log, is a different dependency and carries no such defect.
- Look for the format and signature suite stated in the record, so the check runs against a general-purpose implementation.
- Pin your own roots of trust, and treat a change to them as a decision. A key delivered alongside the record it authenticates adds nothing.
- [SLSA's verification guidance](https://slsa.dev/spec/v1.2/verifying-artifacts) shows the shape: configure "the verifier's roots of trust" as a map from recognized producer identities to what will be believed from each.

**Outcome.** A signature checkable against a root you pinned, with a stated suite and no call to the producer, is independently re-checkable, and what it establishes is who asserted the record and that the bytes are unchanged. A shared-secret receipt, or a check that queries the producer's service, is a supplier assertion. An unsigned export gives no information beyond what the producer chose to send.

## What These Questions Do Not Cover

Three things sit outside the six questions, and a reviewer is better off knowing they are outside than assuming they were covered.

- The live channel between agent and server. Message signing, nonces, tool-definition pinning, and mutual signing are in [Section 7 of the MCP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html#7-message-level-integrity-and-replay-protection).
- Records your own systems produce. Protecting logs at rest and in transit is in the [Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html).
- Runs spanning several parties. The interesting failure is at the seams: one agent's record shows a delegation and the counterparty has no record of receiving it, while both answer all six questions well.

## References

- [MCP Security Cheat Sheet](MCP_Security_Cheat_Sheet.md)
- [AI Agent Security Cheat Sheet](AI_Agent_Security_Cheat_Sheet.md)
- [Logging Cheat Sheet](Logging_Cheat_Sheet.md)
- [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/)
- [OWASP ASVS 5.0, V16 Security Logging and Error Handling](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x25-V16-Security-Logging-and-Error-Handling.md)
- [RFC 2104: HMAC: Keyed-Hashing for Message Authentication](https://datatracker.ietf.org/doc/html/rfc2104)
- [RFC 3161: Internet X.509 Public Key Infrastructure Time-Stamp Protocol (TSP)](https://datatracker.ietf.org/doc/html/rfc3161)
- [RFC 9162: Certificate Transparency Version 2.0](https://datatracker.ietf.org/doc/html/rfc9162)
- [RFC 9334: Remote ATtestation procedureS (RATS) Architecture](https://datatracker.ietf.org/doc/html/rfc9334)
- [RFC 9942: CBOR Object Signing and Encryption (COSE) Receipts](https://datatracker.ietf.org/doc/html/rfc9942)
- [in-toto Attestation Framework: Statement layer](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md)
- [SLSA v1.2: Verifying artifacts](https://slsa.dev/spec/v1.2/verifying-artifacts)
