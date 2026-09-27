# Backend as a Service (BaaS) Security Cheat Sheet

## Introduction

Backend as a Service (BaaS) platforms can let browser and mobile clients call managed database, storage, realtime, authentication, and function APIs without an intermediary application server. In this client-direct architecture, the client is untrusted and authorization moves into provider policies such as row, document, record, or resource rules. The model is documented by both [Firebase](https://firebase.google.com/docs/firestore/client/libraries) and [Supabase](https://supabase.com/docs/guides/database/secure-data).

The essential rules are:

- Assume that every identifier, endpoint, and publishable key shipped to a client is public.
- Deny access unless an explicit policy grants the required action on the required resource.
- Keep credentials that bypass client policies on trusted servers only.
- Authorize the end user before using a privileged credential on their behalf.
- Test and deploy policies as production code across every exposed service.

## Model the Trust Boundaries

Do not classify a credential by its name. Classify it by who can possess it and what it can do. For example, [Supabase publishable keys are intended for public components while secret keys bypass row-level security](https://supabase.com/docs/guides/getting-started/api-keys). Other platforms use different names and enforcement models, but the same capability-based review applies.

| Component | Trust decision |
| --- | --- |
| Project URL, application ID, or publishable key | Treat as discoverable. It may select the backend or identify the application, but it must not grant data access by itself. |
| User session or identity token | Use as authenticated identity input. Do not trust client-supplied owner IDs, tenant IDs, roles, or other mutable fields in place of verified identity. |
| Database, storage, or resource policy | Treat as the authorization boundary for direct client operations. Evaluate identity, resource, action, and relevant tenant or ownership state. |
| Server, service-role, administrative, or superuser credential | Treat as privileged. It may bypass ordinary resource policies, as documented for [Appwrite server integrations](https://appwrite.io/docs/advanced/security/permissions) and [PocketBase superusers](https://pocketbase.io/docs/api-rules-and-filters/). |

Draw the actual user-context and privileged request paths, including SDKs, API endpoints, realtime connections, functions, automation, and administration tools. Mark where authentication, authorization, and policy bypass occur.

## Apply Deny-by-Default to Every Surface

Maintain an inventory of every client-reachable resource and its policy engine. A database policy does not prove that storage, realtime, functions, authentication administration, or management APIs are protected. Firebase, for example, requires rules for each product in use and notes that rule behavior differs by product in its [Security Rules documentation](https://firebase.google.com/docs/rules). Supabase separately documents controls for [Storage](https://supabase.com/docs/guides/storage/security/access-control), [Realtime](https://supabase.com/docs/guides/realtime/authorization), and [Edge Functions](https://supabase.com/docs/guides/functions/auth).

For every resource, record:

- Whether it is public, user-scoped, tenant-scoped, server-only, or not applicable.
- The policy engine and rules for each applicable action, including list, read, create, update, delete, subscribe, invoke, and administration.
- Which fields establish ownership or tenant membership, and which fields clients cannot set or change.
- Every policy bypass, policy owner, and automated test.

Grant only the operations the application needs. Check both the existing resource and the proposed new state for mutations so that a client cannot assign ownership, move a record to another tenant, or change a role. Treat query behavior as platform-specific: some rule engines reject a query whose possible result is broader than the policy instead of filtering its results, as explained in [Firebase's secure query guidance](https://firebase.google.com/docs/firestore/security/rules-query).

## Authorize Before Using Privileged Access

Privileged clients deliberately remove a client-policy boundary. Firebase server libraries, for example, bypass Cloud Firestore Security Rules, while [Supabase secret keys bypass row-level security](https://supabase.com/docs/guides/getting-started/api-keys). Possession of such a credential proves only that the server component is privileged; it does not prove that the requesting user may perform the operation.

For every privileged request:

- Authenticate the caller and reject missing, expired, disabled, or otherwise invalid identities.
- Authorize the action against trusted resource, membership, ownership, and tenant data before creating the privileged client or performing the bypassed operation.
- Derive security-sensitive attributes from trusted server or provider state, not request fields.
- Scope the credential and component to the minimum services and operations available, and log the actor, resource, decision, and outcome.

Prefer a user-context client when the ordinary policy can express the operation. Keep user-context and privileged client instances separate so an administrative client cannot be selected accidentally. Follow the OWASP [Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html), [Multi-Tenant Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Multi_Tenant_Security_Cheat_Sheet.html), and [Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html) for the adjacent controls instead of duplicating them here.

## Test, Deploy, and Monitor Policies as Code

Version policies with the schemas and resources they protect. Review and deploy them together, and make deployment fail when a new table, collection, bucket, channel, function, or administrative route has no explicit policy classification. Firebase recommends testing rules before production and supports deploying them through its CLI, as summarized in the [Security Rules implementation path](https://firebase.google.com/docs/rules).

Build an authorization matrix for each action and resource class. At minimum, test these principals against both allowed and forbidden resources:

| Principal | Required negative tests |
| --- | --- |
| Anonymous client | User-only reads, writes, subscriptions, and function calls fail. |
| User A | User B's and another tenant's resources fail for every action. |
| User with changed or deleted membership | Previously allowed access fails promptly. |
| Client changing ownership or tenant fields | Create and update fail. |
| Privileged server route | Missing user authorization fails before the policy bypass is used. |

Run tests against the provider emulator or an isolated environment using real query and mutation shapes. Compare deployed resources and policy versions with the reviewed source so console changes and partial deployments cannot drift silently.

Use separate projects, data, policies, and credentials for development, preview or test, and production. Do not put production credentials or user data in lower environments. This isolation is also recommended in [Firebase's environment guidance](https://firebase.google.com/docs/projects/dev-workflows/overview-environments).

Add per-user and per-tenant limits, quotas, spend alerts, and anomaly detection appropriate to each surface. These controls reduce bulk extraction, automated abuse, function amplification, and billing impact; they do not replace authorization. Application or device attestation is also defense in depth: [Firebase App Check explicitly complements user authentication and does not eliminate every abuse vector](https://firebase.google.com/docs/app-check). See the OWASP [Denial of Service Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html) and [Abuse Case Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Abuse_Case_Cheat_Sheet.html) for generic abuse controls.

## References

- [Database Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html)
- [REST Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html)
- [Serverless FaaS Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Serverless_FaaS_Security_Cheat_Sheet.html)
