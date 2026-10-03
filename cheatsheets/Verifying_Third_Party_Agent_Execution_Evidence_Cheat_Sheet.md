# Verifying Third-Party Agent Execution Evidence Cheat Sheet

## Introduction

This cheat sheet helps developers assess execution records supplied by an agent, a Model Context Protocol (MCP) server, or a service they do not control. A supplier can sign a record that omits actions or describes a run that never happened. Verify the specific claim you need, and identify who could fabricate the evidence supporting it.

[Supply-chain Levels for Software Artifacts (SLSA) verification guidance](https://slsa.dev/spec/v1.2/verifying-artifacts) separates checking signatures and artifact identity from deciding which producers to trust. Apply the same distinction to execution records. Use these outcomes for each question below:

| Outcome | What the evidence supports |
|---|---|
| Independently re-checkable | Another reviewer can verify the stated property using authenticated evidence and trust material the supplier does not exclusively control. This does not establish other properties of the execution. |
| Supplier assertion | The supplier claims the property, but independent evidence is missing. The record can still help with debugging and routine operations. |
| No information | The evidence does not let you assess this property of the execution. Do not infer that the run was clean. |

A signature may establish who made an assertion without establishing that the assertion is true. Do not use supplier assertions alone to resolve an incident attribution or dispute involving that supplier.

For producing and protecting your own logs, see the [Logging Cheat Sheet](Logging_Cheat_Sheet.md). For optional message integrity and replay protection between agent and server, see [MCP Security Section 7](MCP_Security_Cheat_Sheet.md#7-optional-message-level-integrity). These checks assess individual records; they do not establish end-to-end completeness across a chain of delegated actions.

## Six Questions to Ask About an Execution Record

### 1. Who could have written or altered it?

List the component, host, recorder, operator, and signing-key holder. Count independent parties, not processes: several services under one supplier's control remain one party. A recorder fed only by the component preserves that component's account of events. A signing service that accepts arbitrary content from the component does not independently confirm the content.

- Identify an observer that obtains event data independently of the component's own reports.
- Keep its records where the component and supplier cannot rewrite them.
- Corroborate the supplier's record against calls recorded at a gateway or other boundary you control.

A boundary recorder covers only what crosses that boundary. It cannot establish local file writes or in-process actions, and it cannot inspect encrypted request bodies without access to their plaintext. Where independent observation is unavailable, classify the account of execution as a supplier assertion and limit the decisions you base on it.

### 2. What does the timing evidence actually establish?

A timestamp written by the supplier is a supplier assertion. To check freshness, send a fresh, unpredictable challenge value (a nonce) and require it to be signed together with the execution claims. Verify the signature and compare the returned nonce with the one you sent.

[RFC 9334 Section 10](https://datatracker.ietf.org/doc/html/rfc9334#section-10) explains the limit: a matching nonce bounds signing to after the challenge was generated; it does not show when the individual claims were captured. A trusted timestamp bound to the signed record can establish that it existed by a particular time, but does not establish that its contents describe real events.

Record which timing property you checked. Do not label capture as contemporaneous merely because a signature is fresh or a record appears in a transparency log. That claim needs evidence from an observer positioned to witness the execution.

### 3. Does it identify the intended artifact and execution?

A valid signature on a record about another artifact or run does not answer your question.

- Recompute a collision-resistant digest of the expected artifact and compare it with the signed subject. Obtain the expected artifact or digest independently of the report being assessed.
- Separately match the signed execution identifier or challenge to the run you intended to review.
- Check which relevant inputs are covered, such as tool definitions, configuration, prompts, model version, and policy. A binary digest alone does not identify these inputs.

An artifact digest can legitimately stay the same across many runs. The problem is using that digest as the only binding to an execution. A matched digest establishes artifact identity; a matched run identifier establishes which execution the supplier is claiming to describe. Neither establishes that the reported actions occurred.

### 4. Would an omitted event be detectable?

Define the execution or time window and the events an independent observer was positioned to see. Reconcile the record against an expected-event list or per-execution sequence that the supplier cannot silently redefine. A supplier-maintained sequence counts only what the supplier chose to include.

A transparency log can make changes after entry detectable; it cannot reveal an event that was never submitted. [RFC 9162](https://datatracker.ietf.org/doc/html/rfc9162) describes inclusion and consistency checks and warns that a log can present inconsistent views to different clients. Verify those proofs and check how the deployment detects inconsistent views, such as by comparing signed log states across independent observers. The log operator remains a trust dependency.

A log's total entry count is not an execution's event count. Unrelated entries can increase it while events from the run are missing. Likewise, injecting one expected event and finding it in the returned record is a useful spot-check, not a completeness test. Any coverage claim must remain limited to the events the independent observer could see and reconcile.

### 5. What happens when recording or delivery fails?

Determine whether the component continues and drops events, buffers and retries, or stops execution. Check buffer overflow behavior as well as normal operation.

- In an environment you control, interrupt the recording path and observe whether execution continues and gaps become visible.
- Where you cannot test, request evidence from an outage or an exercised failure scenario. Treat documentation alone as a supplier assertion.
- Preserve independently observed delivery failures outside the component's control. A gap marker written solely by the component is still its assertion, even when stored elsewhere.

A test establishes the behavior observed under its conditions; it does not prove that another execution had no gaps. An empty report from a recorder that may have dropped events provides no basis for declaring that run clean. Stopping execution on every logging failure is not automatically appropriate: it turns a recording outage into an availability failure. Choose the behavior according to the action's risk and make any loss of evidence visible.

### 6. Can the reviewer verify it without being able to forge it?

Use a maintained verifier with trusted signer identities, keys or certificate roots, and permitted algorithms configured independently of the record. A key packaged with the record is not a trust anchor merely because it verifies that record; it must connect to trust you already established. The [SLSA verification steps](https://slsa.dev/spec/v1.2/verifying-artifacts) illustrate checking the signature, subject digest, and expected producer before relying on provenance.

Validate applicable certificate paths and revocation information, as described in [RFC 9334 Section 12.4](https://datatracker.ietf.org/doc/html/rfc9334#section-12.4). Do not accept a signature solely because the cryptographic calculation succeeds.

Public-key verification does not require the signing secret. By contrast, everyone holding the shared secret needed to verify a message authentication code can also create one. Such a record cannot independently attribute authorship between those key holders. Asking the supplier's service whether its own record is valid also leaves the supplier as the source of the assertion.

### Worked Examples

These examples describe evidence after the stated checks, rather than assigning guarantees to a file format.

| Evidence and checks performed | What you may conclude | What remains unestablished |
|---|---|---|
| Vendor-exported traces, with no independent corroboration | The vendor supplied these claims. | Whether the actions occurred and whether the record is complete. |
| A signed record verified against your trusted signer, with artifact digest and run identifier matched to your expectations | That signer asserted these bytes about the expected artifact and run. | Whether the assertions are true or complete. |
| The same record, with verified log inclusion and consistency evidence plus an independently trusted timestamp over the signed record | The signed record existed by the supported time and is included in the checked log state. | When events were captured, whether they occurred, or whether any were omitted before submission. |
| The record reconciled against events captured by an independent boundary observer | Whether the record includes the events that observer saw in the stated window. | Internal actions, other boundaries, or events outside the observer's coverage. |

## Do's and Don'ts

Keep the verification policy and expected values outside the evidence under review, following the separation in [SLSA verification guidance](https://slsa.dev/spec/v1.2/verifying-artifacts).

### Do

- State the exact property being checked: signer, artifact, execution binding, timing, or coverage.
- Record the trust assumptions and limits alongside each result.
- Reconcile supplier reports with observations you control when possible.
- Exercise recording failures in an environment you control and preserve the results.

### Don't

- Treat a valid signature or log inclusion proof as proof that an action occurred.
- Confuse a stable artifact digest with a unique execution identifier.
- Treat a fresh signature as proof of live capture, or a successful spot-check as proof of completeness.
- Treat missing entries as evidence that nothing happened when recording could have failed.

## References

- [SLSA: Verifying Artifacts](https://slsa.dev/spec/v1.2/verifying-artifacts)
- [RFC 9334: Remote ATtestation procedureS (RATS) Architecture](https://datatracker.ietf.org/doc/html/rfc9334#section-10)
- [RFC 9162: Certificate Transparency Version 2.0](https://datatracker.ietf.org/doc/html/rfc9162)
