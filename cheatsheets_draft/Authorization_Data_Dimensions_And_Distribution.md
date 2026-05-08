# Authorization Input Data Dimensions & Distribution

Before choosing an authorization pattern, you need to understand not only how policies are owned and distributed, but also what input data those policies depend on — things like subject attributes, resource attributes, relationship data, environmental context, risk signals, or tenant metadata. How this data is sourced, distributed, and refreshed directly influences which [Authorization Patterns](Authorization_Patterns_Cheat_Sheet.md) are suitable for your system — and which are not.

This Cheat Sheet introduces the key dimensions that characterize data relevant for authorization decisions:

- **input data locality:** the scope within which data is relevant and shared
- **input data cardinality:** determines how much data must be managed
- **input data freshness:** how often that data must be refreshed or fetched in real time

Together, these dimensions shape the feasibility, performance, and operational complexity of authorization system design. They also determine which data distribution strategies are practical for making the required input data available to Policy Decision Points (PDPs). The sources of that data are the Policy Information Points (PIPs).

> **Don't confuse input data freshness with policy change latency.**  
> Policy change latency describes how quickly changed policies must take effect. Input data freshness describes how quickly changed attribute values must affect authorization decisions. Both are independent dimensions and both influence architecture choices.
> See also: *Authorization Policy Dimensions & Distribution*.

## Input Data Locality

Input data locality defines the boundaries of data relevance and reuse — from data used only inside a single service to data shared across the entire organization.

Three levels of locality are common in distributed systems:

- **Service-Local Data:** Data relevant only within a single service and not reused elsewhere.
  *Example:* A service-specific configuration flag affecting authorization decisions only inside that service, or ephemeral session attributes used exclusively by the service's internal logic.

- **Domain-Level Data:** Data shared across multiple services within the same bounded context or business domain. This data often requires coordination between teams.  
  *Example:* Ownership metadata of documents in a document management domain, customer account status used by both billing and support services, or time-based availability windows used by booking and scheduling services.

- **Organization-Level Data:** Data relevant across domains or across the entire system. This data usually forms a common baseline for many authorization decisions.  
  *Example:* Regulatory data classification, tenant-level subscription tier, or organization-wide administrative roles.

## Input Data Cardinality

Input data cardinality refers to the number of distinct attributes across all subjects or resources. It determines how easily data can be cached or distributed to PDPs.

Three cardinality levels are common:

- **High:** Many distinct data items, often tied to individual requests, users, resources, or relationships.  
  *Example:* Real-time risk scores, or geo-IP information.

- **Medium:** A moderate number of distinct data items, typically shared across sets of subjects or resources.  
  *Example:* Project IDs.

- **Low:** Few distinct data items, usually stable and broadly reusable.  
  *Example:* Environment labels such as `"production"` or `"staging"`, deployment regions, or business unit identifiers such as `"HR"`, `"Finance"`, or `"R&D"`.

## Input Data Freshness

Input data freshness describes the maximum acceptable delay between an attribute value changing and that change being reflected in authorization decisions.

Three freshness levels are common:

- **High:** Changes must be reflected immediately or within seconds to maintain correct authorization decisions.  
  *Example:* Real-time risk scores, breach detection flags, or emergency account locks.

- **Medium:** Changes should be reflected within minutes to hours, balancing freshness and performance.  
  *Example:* Feature toggles, or subscription tiers.

- **Low:** Changes can be reflected with delays of hours to days without significant impact.  
  *Example:* Slowly changing organizational classifications, or planned configuration changes.

## Policy Input Data Distribution Strategies

While the **[input data freshness](#input-data-freshness)** dimension defines how quickly data changes must be reflected in access control decisions, **[input data cardinality](#input-data-cardinality)** can, depending on the PDP type, limit how much information can be stored or cached in practice, and with that also the ability to fully achieve that reflection. This challenge is especially relevant in PBAC systems.

This tension highlights a broader challenge for all approaches relying on embedded or external PDPs: how to make the right data available at evaluation time without overwhelming the system. To address this challenge, different strategies for distributing input data from PIPs to PDPs have emerged. Each comes with distinct trade-offs, and their suitability depends on the PDP type (e.g., PBAC, ReBAC, NGAC) as well as on system requirements for performance, scalability, and freshness.

Each strategy addresses different operational concerns, and no single approach works universally. Mature systems often combine them, guided by data characteristics, performance targets, and architectural constraints.

### On-Demand Data Pull

The PDP fetches required data from PIPs at the time of policy evaluation, typically via APIs or database queries. PDPs supporting this option often allow configurable caching of the pulled data.

![On-Demand Data Pull](../assets/On_demand_data_pull.svg)

#### Pros

- Ensures [data freshness](#input-data-freshness) by retrieving the latest attributes values from PIPs at evaluation time.
- Enables handling of [high-cardinality](#input-data-cardinality) data without preloading large datasets into the PDP.
- No need for data synchronization mechanisms, since the PDP always queries the PIPs directly.
- Since the PDP does not need to maintain a local copy of data, the memory or storage demand of the PDP is low.
- Governance responsibility is at the policy author – the policy defines where the data is retrieved from.

#### Cons

- Increases latency due to network calls to PIPs during evaluation, which negatively impacts performance, especially for high-throughput systems.
- Introduces dependencies on external systems, reducing resilience if PIPs are slow or unavailable, potentially leading to cascading failures, degraded service or fallback decisions.
- Limits the usable PDP types, as ReBAC and NGAC implementations typically don't support this strategy.
- Degrades system performance when attributes are accessed repeatedly, especially for high-throughput systems.

While caching (if supported by the PDP) can mitigate some of these drawbacks, it undermines the freshness guarantee, potentially leading to incorrect authorization decisions. Moreover, caching also negates the low-storage advantage listed above – especially for high cardinality data.

> **Typically suited for:** High- to low-freshness or high-cardinality input data where querying the PIP at decision time is acceptable.

### Out-of-Band Data Push

Data is proactively sent to the PDP in advance and stored in memory or a local data store for faster access during evaluation.

![Out-of-Band Data Push](../assets/Out_of_band_data_push.svg)

#### Pros

- Improves performance by storing data locally (e.g., in memory or a local database), enabling faster policy evaluation.
- Enhances resilience, as the PDP can operate independently of PIP availability, allowing PDP instances to remain lightweight and focused on evaluation, which improves their scalability.
- ReBAC/NGAC PDP types typically require access to complete relationship graphs or contextual data sets, which are infeasible to retrieve on-demand or pass inline. This strategy enables those models.
- Reduces the load on the PDP by shifting data synchronization to other system components, allowing PDP instances to remain lightweight and focused on evaluation, which improves their scalability.

#### Cons

- Requires robust data synchronization mechanisms to push updates to the PDP instances in real-time or near-real-time, especially for data with [high-freshness](#input-data-freshness) requirements.
- Increases memory or storage demands on the PDP, which is usually problematic for [high-cardinality data](#input-data-cardinality).
- Introduces governance complexity, as mechanisms, who can write to the event/topic the PDP listens to, or who can invoke the PDP's API for updates, and which specific data each party is allowed to send, must be established.

> **Typically suited for:** High- to low-freshness input data.

### Request-Time Data Injection

Required data is passed directly in the request from the PEP to the PDP – an approach often referred to as *inline data passing*. Early-stage standardization efforts ([OpenID AuthZEN Initiative](https://openid.net/authzen-authorization-api-1-0-implementers-draft-approved/)) aim to make this interaction more consistent and interoperable.

![Request-Time Data Injection](../assets/Request_time_data_injection.svg)

#### Pros

- Ensures [data freshness](#input-data-freshness) by providing the latest attributes values from PIPs.
- Enables handling of [high-cardinality](#input-data-cardinality) data without preloading large datasets into the PDP.
- Reduces load on the PDP by shifting data synchronization to other system components (the PEP), allowing PDP instances to remain lightweight and focused on evaluation, which improves their scalability.
- Since the PDP does not need to maintain a local copy of data, the memory or storage demand of the PDP is low.
- Typically, the only option for ReBAC and NGAC systems to provide attributes which are not stored in their databases.

#### Cons

- Increases request size, as additional data is included in the decision request, potentially impacting network performance.
- Places the burden on the PEP (e.g., microservice or edge component) to collect and validate data from PIPs, increasing complexity in the calling component.
- Risks inconsistent data if the PEP fails to provide all required attributes or if data collection is misconfigured, potentially leading to incorrect decisions.
- Can degrade system performance when attributes are accessed repeatedly by the PEPs.
- Introduces governance complexity, as PEP configuration becomes a concern – it determines which attributes are fetched and sent to the PDP (configuration changes directly impact authorization decisions).

While caching (if supported by the PEP) can mitigate some of these cons, it introduces the risk of stale data, potentially leading to incorrect authorization decisions.

> **Typically suited for:** High- to low-freshness or high-cardinality input data when the PEP can reliably collect, validate, and pass the required attributes with the request, and querying the PIPs at decision time is acceptable.

### Embedded Data

Data is baked directly into the PDP's configuration or code, rather than being pulled, pushed, or injected dynamically.

![Embedded Data](../assets/Embedded_data.svg)

#### Pros

- Zero runtime dependencies on external PIPs.
- No synchronization concerns; the data is always available and consistent.
- Keeps deployments simple.

#### Cons

- Useful only for static or rarely changing information.
- Requires rebuilding and/or redeploying the PDP when data changes.
- Introduces governance challenges as the team deploying the PDP effectively decides which data get bundled and used, even if those data elements are owned by different teams or organizational units.

> **Typically suited for:** Low-cardinality, low-freshness, stable input data.

## Operational Considerations

| Dimension                              | On-Demand Data Pull                                      | Out-of-Band Data Push                                                  | Request-Time Data Injection                                                | Embedded Data                                 |
|----------------------------------------|----------------------------------------------------------|------------------------------------------------------------------------|----------------------------------------------------------------------------|-----------------------------------------------|
| **Freshness support**                  | High to Low — depends on source availability and caching | High to Low — depends on synchronization guarantees                    | High to Low — depends on PEP-side data collection and caching              | Low                                           |
| **Cardinality support**                | High — data is fetched as needed                         | Low to Medium; High only if storage and sync model can handle it       | High — data is passed per request                                          | Low                                           |
| **Decision latency**                   | Higher and more variable due to runtime PIP calls        | Low, as data is avalable locally                                       | Medium — PDP stays lightweight, but request preparation may add latency    | Low                                           |
| **Runtime dependency on PIPs**         | Yes                                                      | No, after synchronization                                              | Indirectly, via the PEP                                                    | No                                            |
| **PDP storage demand**                 | Low, unless caching is used extensively                  | Medium to High                                                         | Low                                                                        | Low                                           |
| **PEP complexity**                     | Low                                                      | Low                                                                    | High                                                                       | Low                                           |
| **Synchronization mechanism required** | No                                                       | Yes                                                                    | No PDP-side synchronization, but PEP-side data collection is required      | No                                            |
| **Governance complexity**              | Medium — policies define which sources are queried       | High — writers, topics, APIs, and data ownership must be controlled    | High — PEP configuration determines which data is sent                     | Medium — deploying team controls bundled data |
| **Typical PDP fit**                    | PBAC-oriented PDPs that support external data lookup     | ReBAC/NGAC systems, graph-based models, or PDPs with local data stores | PBAC, ReBAC, and NGAC when request-specific external attributes are needed | Simple PDPs with static configuration data    |

## Input Data × Distribution — Quick Reference

| Data Characteristics                      | Common Distribution Strategy                                                                                                 |
|-------------------------------------------|------------------------------------------------------------------------------------------------------------------------------|
| High freshness + high cardinality         | On-Demand Data Pull or Request-Time Data Injection                                                                           |
| High freshness + low/medium cardinality   | Out-of-Band Data Push, On-Demand Data Pull, or Request-Time Data Injection                                                   |
| Medium freshness + high cardinality       | On-Demand Data Pull or Request-Time Data Injection; Out-of-Band Data Push only if storage and synchronization are manageable |
| Medium freshness + low/medium cardinality | Out-of-Band Data Push or Request-Time Data Injection                                                                         |
| Low freshness + low cardinality           | Embedded Data or Out-of-Band Data Push                                                                                       |
| Low freshness + medium/high cardinality   | Out-of-Band Data Push, On-Demand Data Pull, or Request-Time Data Injection depending on latency and storage constraints      |

These combinations are common starting points. The final choice also depends on PDP type, latency budget, resilience requirements, storage constraints, governance boundaries, and whether the data can be trusted when supplied by the PEP or synchronized out of band. Some of such architectural constraints are listed in the table below.

| Constraint or Context                              | Common Distribution Strategy                                         |
|----------------------------------------------------|----------------------------------------------------------------------|
| Relationship graph or complete authorization model | Out-of-Band Data Push                                                |
| Request-specific context already known by the PEP  | Request-Time Data Injection                                          |
| PIP must remain authoritative at decision time     | On-Demand Data Pull                                                  |
| PDP must keep runtime dependencies low             | Out-of-Band Data Push, Request-Time Data Injection, or Embedded Data |
| Data is static, stable, and globally applicable    | Embedded Data                                                        |

## Security Considerations

Input data distribution is not purely an operational concern — it directly affects authorization correctness.

**Stale input data** can lead to outdated decisions, especially when data is cached, pushed asynchronously, or embedded into PDP deployments.

**Missing or inconsistent request-time attributes** can cause incorrect decisions when PEPs are responsible for collecting and injecting data.

**Unauthorized data updates** can undermine pushed-data models if systems do not control who may publish which updates to PDPs. Data distribution mechanisms must enforce ownership boundaries just like policy distribution pipelines do.

**Untrusted input data** can undermine policy evaluation if PDPs or PEPs do not validate the provenance, integrity, and meaning of authorization-relevant attributes.

As with policy changes, changes to authorization-relevant data flows should be reviewed, tested, and audited. Broken access control often results not only from wrong policies, but also from wrong, stale, missing, or misapplied input data.
