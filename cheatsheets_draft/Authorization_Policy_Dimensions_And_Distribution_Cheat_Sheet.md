# Authorization Policy Dimensions & Distribution

Before choosing an authorization pattern, you need to understand the context it must operate in. This Cheat Sheet introduces the key dimensions that characterize how policies are owned, how quickly they must take effect, and how they reach the Policy Decision Points (PDPs) that evaluate them. These dimensions directly influence which [Authorization Patterns](Authorization_Patterns_Cheat_Sheet.md) are suitable for your system — and which are not.

> See also: *Authorization Data Dimensions, Distribution & Performance*

## Policy Characteristics

Policy characteristics define how authorization policies are authored, maintained, and updated over time, influencing their management and distribution. Two key dimensions, **policy ownership** and **policy change latency**, guide these processes and are critical for operationalizing authorization systems.

> **Don't confuse change latency with change frequency.**
> Frequency describes how often policies are updated — this affects governance and authoring workflows. Latency describes how quickly an update must reach the PDPs once published. Both are independent dimensions and both influence architecture choices.

### Policy Ownership

Policy ownership identifies who is responsible for authoring and maintaining a given policy. It defines governance boundaries — determining who may create, modify, review, and deploy policies — and often indicates how composable or layered policies need to be.

Three levels of ownership are common in distributed systems:

- **Microservice Team:** Policies authored and maintained by the team responsible for a specific microservice. These are typically focused on local enforcement logic and closely tied to internal service semantics.
  *Example:* A recommendation service defines request filters that exclude certain products based on internal scoring thresholds or active experiments.

- **Domain Level:** Policies shared across services within a business domain, often requiring coordination between teams. These policies may be abstracted and reused across multiple services.
  *Example:* A subscription domain enforces business rules about grace periods, usage limits, or billing thresholds that are referenced by billing, customer portal, and notification services.

- **Central (Organization Level):** Policies governed by a central security, compliance, or platform team. These typically apply across domains or services and provide the foundation upon which more granular policies are built.
  *Example:* An organizational policy defines acceptable data residency constraints or standard access conditions for administrative APIs.

### Policy Change Latency

Policy change latency describes how quickly a change must be reflected in the system once introduced. It should not be confused with the **frequency** of policy changes (how often they occur), or with **input data freshness** (how quickly attribute updates must be reflected in policy decisions). While policy change frequency influences governance and authoring processes, the latency defines how fast policies must be deployed and propagated across services to take effect.

Three latency levels are common:

- **Immediate:** Policies must take effect as soon as they are changed (seconds to minutes).
  *Example:* A financial system introduces a temporary block on a specific payment method due to detected processing errors. The rule itself (block this method) must be enforced immediately across all services to prevent further transactions.

- **Fast:** Policies should be effective within hours to days of being changed.
  *Example:* A sales team requests an update to discount eligibility rules for enterprise customers. Once approved and authored, the new policy should be effective by the next business day.

- **Delayed:** Policies can take effect on a longer timescale — weeks or more.
  *Example:* A data retention policy update mandated by new legislation is scheduled for enforcement with the next release.

## Policy Distribution Strategies

Policy change latency requirements directly determine how policies must be delivered to PDPs. Two primary strategies exist, each with distinct trade-offs.

### Out-of-Band Delivered Policies

Policies are proactively pushed from the Policy Administration Point (PAP) to the PDP and stored locally for evaluation. This strategy suits policies that tend to have immediate to fast change latencies, requiring agile, incremental updates without disrupting service availability.

#### Pros

- Enables dynamic policy updates without PDP redeployment, supporting high availability.

#### Cons

- Requires robust synchronization mechanisms to deploy the correct versions of required policies to each PDP instance.
- Demands governance controls to enforce ownership boundaries — e.g., microservice teams must only be able to update their own policies, while domain or central teams retain control over shared or organizational policies.

> **Best fit:** Immediate and fast change latency requirements.

### Embedded Policies

Policies are embedded directly within the PDP (e.g., as code, or as static configuration) and cannot be updated without restarting or redeploying the PDP. Stability and operational simplicity are prioritized over agility.

#### Pros

- Simplifies policy management, as policies are bundled with the PDP, and no external synchronization is needed.

#### Cons

- Increases deployment overhead, as changes involve rebuilding and/or redeploying the PDP.
- Limits scalability for needs with frequent policy adjustments.
- Introduces governance challenges, since the team deploying the PDP effectively decides which policies get bundled and activated, even if those policies are owned by different teams or organizational units.

> **Best fit:** Delayed change latency requirements.

## Operational Considerations

| Dimension                            | Out-of-Band Delivered                                                    | Embedded                                                      |
|--------------------------------------|--------------------------------------------------------------------------|---------------------------------------------------------------|
| **Suitable latency**                 | Immediate, Fast                                                          | Delayed                                                       |
| **Deployment overhead**              | Low (no redeployment needed)                                             | High (rebuild/redeploy per change)                            |
| **Sync mechanism required**          | Yes                                                                      | No                                                            |
| **Governance complexity**            | Medium — ownership boundaries must be enforced at the distribution layer | Medium — deploying team implicitly controls policy activation |
| **Scalability for frequent changes** | High                                                                     | Low                                                           |

## Ownership × Latency × Distribution — Quick Reference

| Ownership         | Typical Change Latency | Recommended Distribution Strategy |
|-------------------|------------------------|-----------------------------------|
| Microservice Team | Immediate to Fast      | Out-of-Band Delivered             |
| Domain Level      | Fast                   | Out-of-Band Delivered             |
| Central (Org)     | Delayed                | Embedded                          |

## Security Considerations

Policy ownership and distribution are not purely operational concerns — they directly affect the security posture of the authorization system.

**Governance gaps in out-of-band delivery** can allow teams to deploy policies beyond their ownership scope, effectively overriding organizational or domain-level rules. Distribution pipelines must enforce strict ownership boundaries and include policy review steps.

**Governance gaps in embedded policies** are more subtle: because policies are bundled with the PDP at build time, the team performing the deployment determines what gets activated — regardless of who authored the policy. This risk increases in multi-team environments where central or domain-level policies coexist with service-specific ones.

In both strategies, changes to policies should be subject to the same review and audit processes as changes to application code. Unreviewed policy changes — even well-intentioned ones — are a common source of broken access control vulnerabilities.
