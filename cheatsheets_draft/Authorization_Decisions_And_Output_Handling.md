# Authorization Decisions & Output Handling

The canonical form of an authorization request is: *"Can subject X perform action Y on object Z?"*. In the simplest case, the result of such a request is an atomic permit or deny.

In practice, authorization decisions are rarely limited to a single, isolated check. Systems often need to determine what a subject may do across a set of resources — for example, to render a filtered list, or to decide which action buttons to show for a given object. This raises a question that goes beyond the mechanics of a single PDP call: *how is the authorized set of resources or actions determined, and who is responsible for that?*

Historically, PDPs returned only atomic decisions. If a system needed to know which of many objects a subject could access, the PEP had to retrieve all candidates from the data source and check each one against the PDP individually, or bundled into batch calls to reduce round-trips. This worked, but placed significant load on the data source and the PEP, and scaled poorly for large datasets.

> **Data sources vs. PIPs:** The data sources are the application's own stores — databases, APIs, or services that hold the resources being filtered or queried. They are distinct from Policy Information Points (PIPs), which supply attributes used as input to policy evaluation and are discussed in *Authorization Input Data Dimensions & Distribution*.

Modern PDP implementations — in particular ReBAC and NGAC systems, and PBAC systems with sufficiently expressive policy languages — can return structured results directly: a computed set of permitted resources, or a filter expression the data source can apply itself. This shifts the responsibility for determining the authorized set from the PEP to the PDP or the data layer, and makes the iteration or batching approach a fallback rather than the default.

The following sections first introduce the relevant mechanics of PDP calls, then describe the output handling patterns that have emerged from this evolution, and conclude with the performance factors most relevant when evaluating these choices.

## Authorization Request Mechanics

A **Single Decision Request** is one authorization query sent to the PDP, returning one **output data** object. At minimum, a request is a triplet — `(subject, action, object)` — and often a quadruplet: `(subject, action, object, context)`, where context carries additional information such as environment attributes, risk signals, or request metadata relevant to the decision.

> See also *Authorization Input Data Dimensions & Distribution*.

This structure is intentional: the PEP supplies *who is asking, what they want to do, and what they want to do it on* — not criteria for how the decision should be made. The policy logic in the PDP is solely responsible for evaluating those criteria. Patterns that leak authorization criteria into the request — such as passing role names or permission flags directly — are antipatterns, as they couple the PEP to policy internals and undermine the separation of concerns that makes authorization maintainable.

The output data returned by the PDP may be a simple permit/deny, a structured result, or a list — depending on what the policy logic produces and what the PDP supports.

A **Batch Request** bundles multiple independent Single Decision Requests into one PDP call, receiving one output data object per query in return. It is a call optimization, reducing round-trips and serialization overhead across several checks. Batch calls are typically used in two situations:

- **Multiple actions for one object:** The PEP needs to know which actions a subject may perform on a specific resource — for example, to determine whether to render read, edit, and delete buttons. Rather than sending three separate requests, it bundles them into one call.
- **One action across a known, bounded candidate set:** The PEP already holds a small set of objects and needs the same action checked for each — for example, filtering a short list of search results. Rather than iterating with individual calls, it sends all checks at once.

Even with batching, the PEP still needs to retrieve the candidate set first, and batching does not help when output data cardinality is high or not known in advance.

## Output Data Cardinality

Output data cardinality describes the structure and size of the decision object returned by the PDP. It is defined by the policy logic, which reflects the needs of the consuming application.

Three output cardinality levels are common:

- **Low:** Simple decisions with minimal metadata.
  *Example:* `{ "decision": "permit" }`

- **Medium:** Decisions include multiple structured attributes or small result sets.
  *Example:* `{ "allowed_projects": ["A", "B"] }`

- **High:** Decisions include large or complex result sets.
  *Example:* `{ "resources": ["doc1", "doc2", ..., "doc5000"] }`

High-output cardinality often requires pagination, streaming, query rewriting, or pushing authorization logic closer to the data source.

## Policy Output Data Handling Patterns

The following patterns describe how systems handle authorization when the decision concerns a set of resources rather than a single object. They differ in where the authorized set is determined — in the PEP, in the PDP, or at the data source — and in what the PDP returns as a result.

### PDP as Filter (Brute-Force Lookup)

The PEP retrieves all potentially relevant data from a data source and checks each item against the PDP — either through individual Single Decision Requests or, where supported, through Batch Requests. Permitted items are included in the final result.

![PDP as Filter](../assets/PDP_as_filter.svg)

#### Pros

- Simple to implement.
- Works with any PDP type.
- Easy to debug and monitor.

#### Cons

- High latency and poor scalability for large candidate sets due to repeated PDP calls.
- Increases resource consumption by retrieving more data than needed.
- Tightly couples the PEP with service business logic.
- Makes externalizing the PEP difficult or impossible.
- Policy changes may require service redeployments or refactorings.

> **Typically suited for:** Small candidate sets where Authorized Data Set and Authorization Filter are not supported by the PDP.

### Authorized Data Set

The PEP makes a single request to the PDP, and the PDP returns the complete set of resources the subject may access, e.g., a list of permitted object IDs. The PDP constructs this result based on policy logic and available attributes.

![Authorized Data Set](../assets/Authorized_data_set.svg)

#### Pros

- No candidate set needs to be retrieved in advance.
- Reduces round-trips by returning all results at once.
- Simplifies PEP logic — the PDP handles the complexity of determining the authorized set.
- Well-suited for ReBAC or NGAC PDPs that can leverage internal graph data to compute permitted resources.

#### Cons

- Externalizing the PEP to e.g., an external proxy is only feasible for low to medium cardinality output data sets.
- Might complicate error handling and monitoring of data access.
- Require pagination or streaming for bigger output data sets.
- Results in complex policies for PDPs implementing PBAC approaches.
- Not supported by every PBAC PDP implementation.

> **Typically suited for:** Low to medium output cardinality, especially when the PDP can efficiently compute permitted resources from internal relationship or graph data.

### Authorization Filter

The PEP calls the PDP, and the PDP returns a filter expression — such as a query predicate or attribute-based condition. The PEP applies this filter during data retrieval, so only permitted data is fetched in the first place.

![Authorization Filter](../assets/Authorization_filter.svg)

#### Pros

- No candidate set needs to be retrieved in advance.
- Highly efficient for large datasets — filtering happens at the data source.
- Scales well with high output cardinality.
- Reduces PDP load.
- Enables flexible PEP placement — as part of the service or as an external proxy.

#### Cons

- Not supported by every PDP (ReBAC und NGAC PDPs do not support that at all).
- Requires the PEP or data access layer to apply the returned filter correctly.
- Can complicate error handling, monitoring, and diagnosis of access decisions.

> **Typically suited for:** High output cardinality and queryable resources where authorization constraints can be translated into data-source filters.

## Interaction & Output Handling — Quick Reference

| Scenario                                                  | Common Approach                                       |
|-----------------------------------------------------------|-------------------------------------------------------|
| Single access check                                       | Single Decision Request                               |
| Multiple actions for one object (e.g. render UI controls) | Batch Request                                         |
| One action across a small, known candidate set            | PDP as Filter                                         |
| Authorized set must be derived — low/medium cardinality   | Authorization Filter or Authorized Data Set           |
| Authorized set must be derived — high cardinality         | Authorization Filter or paginated Authorized Data Set |

## Performance Considerations

Performance plays a critical role in the design of authorization systems – especially in latency-sensitive environments. Authorization decisions consume part of the latency budget available before a response can be produced — and from the user's perspective, Time to First Byte (TTFB) is one of the most relevant indicators of responsiveness.

The following factors are most relevant when evaluating integration and output handling choices. For input-side performance factors — such as data retrieval latency, PDP storage demand, or synchronization overhead — see *Authorization Input Data Dimensions & Distribution*.

**Policy evaluation latency** is the time the PDP takes to compute a decision. It depends on the number and complexity of policies, the amount of input data evaluated, and on whether the PDP must enumerate or filter large result sets internally.

**Policy output handling** adds work proportional to output cardinality. The selected output handling pattern affects the time required to process and apply the result.

**PDP integration overhead** covers network latency, TLS handshake, DNS resolution, and serialization costs for each PDP call. Protocol choices (e.g., HTTP/1.1 vs. HTTP/2 vs. gRPC) can further influence this. In-process PDPs minimize this overhead but may increase local resource contention. For patterns that make many PDP calls per request — such as PDP as Filter without batching — this overhead multiplies. Batch requests directly reduce this multiplication effect.

**Runtime resource contention** is especially relevant when a PDP is co-located with edge components, gateways, or application services ("Busy Neighbor" effect). PDPs are typically CPU- and memory-intensive. Shared compute resources without isolation can degrade throughput for both the PDP and the host component. This is especially relevant when integrating a PDP into an edge component (either embedded or as a sidecar), which is often optimized for high IOPS throughput. In such cases, embedding a PDP introduces trade-offs between CPU-bound policy evaluation and I/O-heavy request processing.

**Caching and memoization** can reduce decision latency significantly — many PDPs support caching of evaluation results for deterministic inputs. These optimizations can reduce latency but can lead to outdated decisions and require robust cache invalidation logic.

**Fallback strategies and timeouts** determine system behavior when PDPs are slow or unavailable. The choice between fail-closed, fail-open, and graceful degradation affects both perceived performance and security posture.

## Performance Quick Reference

| Design Choice                                | Performance Impact                                                                                                  |
|----------------------------------------------|---------------------------------------------------------------------------------------------------------------------|
| Batch Request                                | Reduces round-trips; increases payload size                                                                         |
| PDP as Filter                                | Poor scalability for large candidate sets; repeated PDP calls multiply integration overhead                         |
| PDP as Filter with batching                  | Reduces round-trips; still retrieves more data than needed                                                          |
| Authorized Data Set (low/medium cardinality) | Efficient; single round-trip                                                                                        |
| Authorized Data Set (high cardinality)       | Requires pagination or streaming; risks large response payloads                                                     |
| Authorization Filter                         | Usually best for large queryable datasets; shifts cost to data source                                               |
| Remote PDP                                   | Adds network and serialization overhead per call                                                                    |
| In-process/Sidecar PDP                       | Reduces integration overhead; increases local CPU/memory pressure                                                   |
| Decision caching                             | Reduces latency; may produce stale decisions if invalidation is not aligned with freshness and latency requirements |
| Fallback: fail-open                          | Improves availability; weakens security posture                                                                     |
| Fallback: fail-closed                        | Preserves security posture; may degrade availability                                                                |
