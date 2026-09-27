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

Draw the actual user-context and privileged request paths, including SDKs, API endpoints, realtime connections, functions, automation, and administration tools. Mark where authentication, authorization, and policy bypass occur, following the [OWASP threat modeling process](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html).

## Apply Deny-by-Default to Every Surface

Maintain an inventory of every client-reachable resource and its policy engine. A database policy does not prove that storage, realtime, functions, authentication administration, or management APIs are protected. Firebase, for example, requires rules for each product in use and notes that rule behavior differs by product in its [Security Rules documentation](https://firebase.google.com/docs/rules). Supabase separately documents controls for [Storage](https://supabase.com/docs/guides/storage/security/access-control), [Realtime](https://supabase.com/docs/guides/realtime/authorization), and [Edge Functions](https://supabase.com/docs/guides/functions/auth).

For every resource, record:

- Whether it is public, user-scoped, tenant-scoped, server-only, or not applicable; unspecified access must remain denied under [OWASP's deny-by-default guidance](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html).
- The policy engine and rules for each applicable action, such as the [separate action rules documented by PocketBase](https://pocketbase.io/docs/api-rules-and-filters/).
- Which fields establish ownership or tenant membership, and which fields clients cannot set or change, consistent with [OWASP multi-tenant context guidance](https://cheatsheetseries.owasp.org/cheatsheets/Multi_Tenant_Security_Cheat_Sheet.html).
- Every policy bypass, policy owner, and automated test, as called for by [OWASP authorization testing guidance](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html).

[Grant only the operations the application needs](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html). Check both the existing resource and proposed new state so a client cannot assign ownership, move a record to another tenant, or change a role, as described by [OWASP's tenant-aware write guidance](https://cheatsheetseries.owasp.org/cheatsheets/Multi_Tenant_Security_Cheat_Sheet.html). Treat query behavior as platform-specific: some rule engines reject a query whose possible result is broader than the policy instead of filtering its results, as explained in [Firebase's secure query guidance](https://firebase.google.com/docs/firestore/security/rules-query).

## Authorize Before Using Privileged Access

Privileged clients deliberately remove a client-policy boundary. [Firebase server libraries bypass Cloud Firestore Security Rules](https://firebase.google.com/docs/firestore/security/rules-query), while [Supabase secret keys bypass row-level security](https://supabase.com/docs/guides/getting-started/api-keys). Possession of such a credential proves only that the server component is privileged; [authorization must still be validated on every request](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html).

For every privileged request:

- Authenticate the caller using the controls in the [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html).
- Authorize the action against trusted resource, membership, ownership, and tenant data before performing the bypassed operation, following [OWASP's per-request authorization guidance](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html).
- Derive tenant and ownership attributes from trusted state rather than accepting client values as authorization proof, as required by the [OWASP Multi-Tenant Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Multi_Tenant_Security_Cheat_Sheet.html).
- Apply [least privilege](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html) to the credential and record the actor, resource, decision, and outcome according to [OWASP logging guidance](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html).

Prefer a user-context client when the ordinary policy can express the operation. Keep user-context and privileged client instances separate so an administrative client cannot be selected accidentally. Follow the OWASP [Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html), [Multi-Tenant Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Multi_Tenant_Security_Cheat_Sheet.html), and [Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html) for the adjacent controls instead of duplicating them here.

## Test, Deploy, and Monitor Policies as Code

Version policies with the schemas and resources they protect. Review and deploy them together, and preserve [deny-by-default](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html) by failing deployment when a new resource has no policy classification. Firebase recommends testing rules before production and supports deploying them through its CLI, as summarized in the [Security Rules implementation path](https://firebase.google.com/docs/rules).

Build an authorization matrix for each action and resource class, as recommended by the [OWASP Multi-Tenant Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Multi_Tenant_Security_Cheat_Sheet.html). At minimum, test these principals against both allowed and forbidden resources:

| Principal | Required negative tests | Evidence |
| --- | --- | --- |
| Anonymous client | User-only reads, writes, subscriptions, and function calls fail. | [OWASP Authorization](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html) |
| User A | User B's and another tenant's resources fail for every action. | [OWASP Multi-Tenant Security](https://cheatsheetseries.owasp.org/cheatsheets/Multi_Tenant_Security_Cheat_Sheet.html) |
| User with changed or deleted membership | Previously allowed access fails. | [OWASP Authorization](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html) |
| Client changing ownership or tenant fields | Create and update fail. | [OWASP Multi-Tenant Security](https://cheatsheetseries.owasp.org/cheatsheets/Multi_Tenant_Security_Cheat_Sheet.html) |
| Privileged server route | Missing user authorization fails before the policy bypass is used. | [OWASP Authorization](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html) |

Run tests against the provider emulator or an isolated environment using real query and mutation shapes, following [Firebase's rule testing guidance](https://firebase.google.com/docs/rules). Compare deployed resources and policy versions with reviewed source, consistent with [OWASP secure deployment guidance](https://owaspsamm.org/model/implementation/secure-deployment/), so console changes and partial deployments cannot drift silently.

Use separate projects, data, policies, and credentials for development, preview or test, and production. Do not put production credentials or user data in lower environments. This isolation is also recommended in [Firebase's environment guidance](https://firebase.google.com/docs/projects/dev-workflows/overview-environments).

Add per-user and per-tenant limits, quotas, spend alerts, and anomaly detection appropriate to each surface. These controls reduce bulk extraction, automated abuse, function amplification, and billing impact; they do not replace authorization. Application or device attestation is also defense in depth: [Firebase App Check explicitly complements user authentication and does not eliminate every abuse vector](https://firebase.google.com/docs/app-check). See the OWASP [Denial of Service Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html) and [Abuse Case Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Abuse_Case_Cheat_Sheet.html) for generic abuse controls.

## References

- [Database Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html)
- [REST Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html)
- [Serverless FaaS Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Serverless_FaaS_Security_Cheat_Sheet.html)
