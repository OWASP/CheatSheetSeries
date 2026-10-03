# Backend as a Service (BaaS) Security Cheat Sheet

## Introduction

Backend as a Service (BaaS) platforms can let browser and mobile clients call managed database, storage, realtime, authentication, and function APIs without an intermediary application server. In this client-direct architecture, the client is untrusted and authorization moves into provider policies such as row, document, record, or resource rules. The model is documented by both [Firebase](https://firebase.google.com/docs/firestore/client/libraries) and [Supabase](https://supabase.com/docs/guides/database/secure-data).

The essential rules are:

- Assume that every identifier, endpoint, and publishable key shipped to a client is public, as illustrated by [Supabase's public-component key guidance](https://supabase.com/docs/guides/getting-started/api-keys).
- [Deny access by default](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html) unless an explicit policy grants the action on the resource.
- Keep policy-bypassing credentials on trusted servers only, as required for [Supabase secret keys](https://supabase.com/docs/guides/getting-started/api-keys).
- [Authorize every request](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html), including requests handled with a privileged credential.
- Test and deploy policies as production code across every exposed service, following the [Firebase Security Rules implementation path](https://firebase.google.com/docs/rules).

## Model the Trust Boundaries

Do not classify a credential by its name. Classify it by who can possess it and what it can do. For example, [Supabase publishable keys are intended for public components while secret keys bypass row-level security](https://supabase.com/docs/guides/getting-started/api-keys). Other platforms use different names and enforcement models, but the same capability-based review applies.

| Component | Trust decision | Evidence |
| --- | --- | --- |
| Project URL, application ID, or publishable key | Treat as discoverable. It may select the backend or identify the application, but it must not grant data access by itself. | [Supabase API keys](https://supabase.com/docs/guides/getting-started/api-keys) |
| User session or identity token | Use as authenticated identity input. Do not trust client-supplied owner IDs, tenant IDs, roles, or other mutable fields in place of verified identity. | [OWASP Authorization](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html) |
| Database, storage, or resource policy | Treat as the authorization boundary for direct client operations. Evaluate identity, resource, action, and relevant tenant or ownership state. | [Firebase Security Rules](https://firebase.google.com/docs/rules) |
| Server, service-role, administrative, or superuser credential | Treat as privileged because it may bypass ordinary resource policies. | [Appwrite server integrations](https://appwrite.io/docs/advanced/security/permissions) and [PocketBase superusers](https://pocketbase.io/docs/api-rules-and-filters/) |

Draw the actual user-context and privileged request paths, including SDKs, API endpoints, realtime connections, functions, automation, and administration tools, following the [OWASP threat modeling process](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html). Keep this small inventory with the architecture:

| Request path | Credential | Enforcement point | Bypass | Negative test | Audit evidence |
| --- | --- | --- | --- | --- | --- |
| `<client> → <surface>` | `<public or user>` | `<policy or server>` | `<none or privileged route>` | `<denied actor and action>` | `<decision or configuration event>` ([OWASP logging](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)) |

Use provider analyzers and audit logs as additional evidence, not as proof that the inventory is complete. For example, Supabase documents both its [Security Advisor checks](https://supabase.com/docs/guides/database/database-advisors) and [platform audit log coverage and limitations](https://supabase.com/docs/guides/security/platform-audit-logs).

## Apply Deny-by-Default to Every Surface

Maintain an inventory of every client-reachable resource and its policy engine. A database policy does not prove that storage, realtime, functions, authentication administration, or management APIs are protected. Firebase Security Rules cover Cloud Firestore, Realtime Database, and Cloud Storage; each supported data product in use needs its own rules, as explained in the [Security Rules documentation](https://firebase.google.com/docs/rules). Supabase separately documents controls for [Storage](https://supabase.com/docs/guides/storage/security/access-control), [Realtime](https://supabase.com/docs/guides/realtime/authorization), and [Edge Functions](https://supabase.com/docs/guides/functions/auth).

Do not rely on provider defaults. Review bootstrap or test modes and exposed schemas before release: [Firebase Test mode can allow anyone access](https://firebase.google.com/docs/rules/basics), while [Supabase warns that exposed tables without row-level security may be reachable by roles with grants](https://supabase.com/docs/guides/database/postgres/row-level-security).

For every resource, record:

- Whether it is public, user-scoped, tenant-scoped, server-only, or not applicable; unspecified access must remain denied under [OWASP's deny-by-default guidance](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html).
- The policy engine and rules for each applicable action, such as the [separate action rules documented by PocketBase](https://pocketbase.io/docs/api-rules-and-filters/).
- Which fields establish ownership or tenant membership, and which fields clients cannot set or change, consistent with [OWASP multi-tenant context guidance](https://cheatsheetseries.owasp.org/cheatsheets/Multi_Tenant_Security_Cheat_Sheet.html).
- Every policy bypass, policy owner, and automated test, as called for by [OWASP authorization testing guidance](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html).

[Grant only the operations the application needs](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html). Check both the existing resource and proposed new state so a client cannot make unauthorized ownership, tenant, or role changes, as described by [OWASP's tenant-aware write guidance](https://cheatsheetseries.owasp.org/cheatsheets/Multi_Tenant_Security_Cheat_Sheet.html). Treat query behavior as platform-specific: some rule engines reject a query whose possible result is broader than the policy instead of filtering its results, as explained in [Firebase's secure query guidance](https://firebase.google.com/docs/firestore/security/rules-query).

Authorize realtime join, publish, receive, and presence capabilities explicitly, including the topic or tenant context. Do not infer this coverage from database read rules; [Supabase documents separate policies for sending and receiving Broadcast and Presence messages](https://supabase.com/docs/guides/realtime/authorization).

Validate write shape as well as authorization. Where supported, use rules to constrain allowed fields and compare existing with proposed state, as shown in [Firebase's data-validation guidance](https://firebase.google.com/docs/rules/data-validation), and enforce independent data invariants according to the [OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html).

For a function that accepts untrusted input or a user-influenced outbound destination, apply the relevant [Serverless FaaS](https://cheatsheetseries.owasp.org/cheatsheets/Serverless_FaaS_Security_Cheat_Sheet.html), [Input Validation](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html), [Secrets Management](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html), and case-specific [server-side request forgery (SSRF) prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html) guidance.

## Authorize Before Using Privileged Access

Privileged clients deliberately remove a client-policy boundary. [Firebase server libraries bypass Cloud Firestore Security Rules](https://firebase.google.com/docs/firestore/security/rules-query), while [Supabase secret keys bypass row-level security](https://supabase.com/docs/guides/getting-started/api-keys). Possession of such a credential proves only that the server component is privileged; [authorization must still be validated on every request](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html).

For every privileged request:

- Authenticate the caller using the controls in the [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html).
- Authorize the action against trusted resource, membership, ownership, and tenant data before performing the bypassed operation, following [OWASP's per-request authorization guidance](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html).
- Derive tenant and ownership attributes from trusted state rather than accepting client values as authorization proof, as required by the [OWASP Multi-Tenant Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Multi_Tenant_Security_Cheat_Sheet.html).
- Apply [least privilege](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html) to the credential and record the actor, resource, decision, and outcome according to [OWASP logging guidance](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html).

Prefer a user-context client when the ordinary policy can express the operation. Keep user-context and privileged client instances separate so an administrative client cannot be selected accidentally. Follow the OWASP [Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html), [Multi-Tenant Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Multi_Tenant_Security_Cheat_Sheet.html), and [Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html) for the adjacent controls.

## Test, Deploy, and Monitor Policies as Code

Version policies with the schemas and resources they protect. Review and deploy them together, and preserve [deny-by-default](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html) by failing deployment when a new resource has no policy classification. Firebase recommends testing rules before production and supports deploying them through its CLI, as summarized in the [Security Rules implementation path](https://firebase.google.com/docs/rules).

Build an authorization matrix for each action and resource class, as recommended by the [OWASP Multi-Tenant Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Multi_Tenant_Security_Cheat_Sheet.html). Test both allowed and forbidden operations, including intended sharing and authorized service callers. At minimum, cover these negative cases:

| Principal | Required negative tests | Evidence |
| --- | --- | --- |
| Anonymous client | User-only reads, writes, subscriptions, and function calls fail. | [OWASP Authorization](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html) |
| User without permission for the target resource | Access to another user's or tenant's protected resources is denied. | [OWASP Multi-Tenant Security](https://cheatsheetseries.owasp.org/cheatsheets/Multi_Tenant_Security_Cheat_Sheet.html) |
| User whose access was revoked | Access stops within the defined revocation deadline. | [OWASP Authorization](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html) |
| Client making an unauthorized ownership or tenant assignment | Create and update are denied. | [OWASP Multi-Tenant Security](https://cheatsheetseries.owasp.org/cheatsheets/Multi_Tenant_Security_Cheat_Sheet.html) |
| Privileged server route | Missing required caller authorization is rejected before the policy bypass is used. | [OWASP Authorization](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html) |

Define how quickly revoked access must stop on each surface. Test existing tokens and open subscriptions as well as new requests: [Supabase caches Realtime permissions until reauthorization or token expiry](https://supabase.com/docs/guides/realtime/authorization#updating-rls-policies). Configure token lifetimes or provider-supported revocation controls to meet that deadline; do not rely on voluntary client refresh.

Use one repeatable test shape: seed two users and tenants, then run allowed and forbidden operations for anonymous, user, cross-tenant, and privileged paths. Assert the expected result and state changes for allowed operations; for denied operations, confirm that protected application state is unchanged. Use real query and mutation shapes with production-equivalent policies in an isolated local or emulator environment, such as the [Firebase Local Emulator Suite](https://firebase.google.com/docs/emulator-suite/connect_firestore).

Compare deployed resources and policy versions with reviewed source, consistent with [OWASP secure deployment guidance](https://owaspsamm.org/model/implementation/secure-deployment/), so console changes and partial deployments cannot drift silently.

Use separate projects, data, policies, and credentials for development, preview or test, and production. Do not put production credentials or user data in lower environments. This isolation is also recommended in [Firebase's environment guidance](https://firebase.google.com/docs/projects/dev-workflows/overview-environments).

Add per-user and per-tenant limits, quotas, spend alerts, and anomaly detection appropriate to each surface. These controls reduce bulk extraction, automated abuse, function amplification, and billing impact; they do not replace authorization. Application or device attestation is also defense in depth: [Firebase App Check explicitly complements user authentication and does not eliminate every abuse vector](https://firebase.google.com/docs/app-check). See the OWASP [Denial of Service Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html) for generic abuse controls.

For supporting services, see the [Database Security](../cheatsheets/Database_Security_Cheat_Sheet.md), [REST Security](../cheatsheets/REST_Security_Cheat_Sheet.md), and [Vulnerable Dependency Management](../cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.md) cheat sheets.

## References

- [Firebase Security Rules](https://firebase.google.com/docs/rules)
- [Supabase: Row-Level Security](https://supabase.com/docs/guides/database/postgres/row-level-security)
- [Appwrite: Permissions](https://appwrite.io/docs/advanced/security/permissions)
