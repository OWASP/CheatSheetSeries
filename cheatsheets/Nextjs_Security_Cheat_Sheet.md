# Next.js Security Cheat Sheet

## Introduction

Next.js applications have several server entry points and can render or cache data on both sides of the server/client boundary. The framework's [authentication guidance](https://nextjs.org/docs/app/guides/authentication) recommends placing authorization close to the data source instead of relying on routing or user interface checks.

Use these rules throughout an application:

- Authorize every server entry point independently.
- Return only the data the browser needs.
- Include the intended audience in every cache decision.
- Treat routing and image configuration as security-sensitive code.
- Test controls by calling entry points directly, without using the user interface.

This sheet covers both the App Router and Pages Router. General JavaScript, authentication, Cross-Site Scripting (XSS), Cross-Site Request Forgery (CSRF), and Server-Side Request Forgery (SSRF) guidance is linked rather than repeated.

## Authorize Every Server Entry Point

Next.js applications have multiple server entry points. A check in one does not protect the others. Centralize secure checks in a server-only Data Access Layer (DAL), then call that DAL from every operation that reads or changes protected data. The [Next.js Data Security guide](https://nextjs.org/docs/app/guides/data-security#data-access-layer) recommends that a DAL perform authorization and return minimal Data Transfer Objects (DTOs).

| Entry point | Secure use |
|-------------|------------|
| Proxy (`proxy.ts`; `middleware.ts` before Next.js 16) | Use for optimistic redirects and request filtering. Do not make it the only authorization layer. |
| Server Action | Treat every used action as directly callable by POST. Validate input, authenticate the caller, and authorize the specific resource inside the action or its DAL function. |
| Route Handler (`route.ts`) or Pages API Route (`pages/api`) | Treat it as a public-facing API endpoint. Authenticate and authorize in the handler. |
| Server Component, page, or data loader | Authorize before reading protected data. Return a narrow DTO rather than a database record. |
| Layout or Client Component | Use checks only to choose what the user sees. They do not prevent direct calls to nested routes, actions, or APIs. |

### Do not rely on Proxy or middleware alone

Proxy can redirect unauthenticated users early, but its `matcher` may omit a route and routing changes can silently move an operation outside its coverage. Next.js explicitly states that [Proxy should not be the only line of defense](https://nextjs.org/docs/app/guides/authentication#optimistic-checks-with-proxy-optional). Authorize again at the handler or data source.

This is also a defense against framework defects. [CVE-2025-29927](https://github.com/vercel/next.js/security/advisories/GHSA-f82v-jwr5-mffw) allowed affected self-hosted Next.js versions to bypass authorization implemented only in middleware. Patch the framework, but keep authorization behind the routing layer so one bypass cannot expose data.

### Secure Server Actions as endpoints

A Server Action used by the application is reachable by a direct POST request. Rendering its form only on a protected page does not authenticate the request. Next.js documents that [page-level authentication does not extend to Server Actions](https://nextjs.org/docs/app/guides/data-security#authentication-and-authorization).

For every action:

- Re-read and verify the session on the server.
- Check permission on the exact object being read or changed; do not trust a user or tenant identifier submitted by the client.
- Validate all arguments as untrusted input.
- Return a minimal result because Server Action return values are serialized to the client.
- Apply rate limits or stronger re-authentication to expensive or high-impact operations.

Next.js compares the request `Origin` with the host for Server Actions. Keep [`serverActions.allowedOrigins`](https://nextjs.org/docs/app/api-reference/config/next-config-js/serverActions#allowedorigins) narrow when a trusted proxy requires additional origins. This built-in check does not replace authentication, authorization, or the general controls in the [CSRF Prevention Cheat Sheet](Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md).

### Protect Route Handlers and Pages API Routes separately

Protecting a page does not protect a Route Handler or API Route that serves related data. Next.js says to treat [Route Handlers as public-facing API endpoints](https://nextjs.org/docs/app/guides/authentication#route-handlers). Apply the [Authorization Cheat Sheet](Authorization_Cheat_Sheet.md) inside each handler, including object-level and tenant-level checks.

Do not infer that a handler is private because only a Server Component calls it. If the client does not need an HTTP API, call the DAL directly from the Server Component and remove the extra public entry point.

## Control Data Crossing into the Browser

Code running only on the server can still send its return values to the browser. The App Router [serializes values passed to Client Components](https://nextjs.org/docs/app/guides/data-security#passing-data-from-server-to-client), and the Pages Router exposes page props in the initial HTML. The [Pages Router documentation](https://nextjs.org/docs/pages/building-your-application/data-fetching/get-server-side-props#behavior) warns that `getServerSideProps` values are visible to the client.

- Select only the columns needed for the response and construct a narrow DTO at the DAL.
- Never pass whole ORM records, session objects, access tokens, or internal configuration to Client Components.
- Keep Server Action return values minimal; a server-side function does not make its returned value secret.
- Treat `getStaticProps`, `getServerSideProps`, and [`getInitialProps`](https://nextjs.org/docs/pages/api-reference/functions/get-initial-props) values as public to that page's browser.
- Prefix an environment variable with `NEXT_PUBLIC_` only when its value is intentionally public. The value is included in client JavaScript according to the [Next.js environment variable guide](https://nextjs.org/docs/app/guides/environment-variables#bundling-environment-variables-for-the-browser).

Importing `server-only` in a sensitive module is a useful build-time guard because it prevents that module from being imported into a Client Component. It does not stop server code from explicitly returning sensitive data. React taint APIs can add another guard, but Next.js describes [tainting as defense in depth](https://nextjs.org/docs/app/guides/data-security#tainting), not a replacement for shaping data.

For browser rendering sinks and React-specific client concerns, use the [XSS Prevention Cheat Sheet](Cross_Site_Scripting_Prevention_Cheat_Sheet.md) and [DOM-based XSS Prevention Cheat Sheet](DOM_based_XSS_Prevention_Cheat_Sheet.md).

## Scope Every Cache to Its Audience

Before caching a response or function result, classify it as public, tenant-scoped, user-scoped, or request-specific. A cache entry must not be reusable by a broader audience than the data permits. With `use cache`, Next.js includes serializable arguments and captured closure values in the [generated cache key](https://nextjs.org/docs/app/api-reference/directives/use-cache#cache-keys); data that varies by user or tenant therefore needs a verified user or tenant identifier as an input.

- Authenticate on every request before reading protected cached data.
- Include the verified user ID, tenant ID, role or permission version, and other authorization predicates that change the result in the cache inputs. Do not use a raw cookie or bearer token as a cache key.
- Do not put user-specific data in a `use cache` function that has no user-specific input.
- Use shared `fetch` caching, Incremental Static Regeneration (ISR), `getStaticProps`, and shared CDN cache headers only for data that the full cache audience may read. Next.js states that [`getStaticProps` data must be publicly cacheable](https://nextjs.org/docs/pages/building-your-application/data-fetching/get-static-props#when-should-i-use-getstaticprops).
- Do not add shared `Cache-Control` directives to personalized `getServerSideProps` responses.
- Invalidate all affected audience keys after authorization or tenancy changes, not only after content changes.

`use cache: private` can read request-time values, but its results are cached in the browser's memory and are still delivered to that browser. The [directive documentation](https://nextjs.org/docs/app/api-reference/directives/use-cache-private) does not make over-broad data safe to return.

Test caches with at least two users or tenants: fill the cache as identity A, then request the same route and object identifiers as identity B. Repeat after changing a role or tenant membership. This catches missing audience keys that a positive-path cache test cannot.

## Treat Next.js Configuration as Security Code

Review `next.config.*`, Proxy matchers, and route configuration with the same care as application handlers. Next.js [rewrites act as a URL proxy](https://nextjs.org/docs/app/api-reference/config/next-config-js/rewrites), and matcher values can flow into destinations.

- Keep external rewrite hosts fixed and allowlisted. Do not interpolate untrusted header, host, cookie, or query captures into an upstream hostname.
- Require the destination service to authenticate and authorize requests. A rewrite masks the destination URL; it does not create an authorization boundary.
- Do not interpolate untrusted captures into an external redirect destination. Use the [Unvalidated Redirects and Forwards Cheat Sheet](Unvalidated_Redirects_and_Forwards_Cheat_Sheet.md) for validation rules.
- Define `images.remotePatterns` with an exact protocol, hostname, port, pathname, and query policy. Next.js warns that [omitted fields imply broad wildcards](https://nextjs.org/docs/app/api-reference/components/image#remotepatterns).
- Keep `images.dangerouslyAllowLocalIP` disabled unless a reviewed private-network use case requires it. Next.js warns that enabling it can let users [access content on the internal network](https://nextjs.org/docs/app/api-reference/components/image#dangerouslyallowlocalip). Apply the [SSRF Prevention Cheat Sheet](Server_Side_Request_Forgery_Prevention_Cheat_Sheet.md) to any server-side fetch destination.
- Keep `serverActions.allowedOrigins` restricted to trusted application and proxy origins.

Configuration assembled from environment variables is still code. Validate it against an allowlist at startup and fail closed when a required host or origin is missing.

## Verify the Boundaries

Framework controls need direct negative-path tests. The [Next.js production checklist](https://nextjs.org/docs/app/guides/production-checklist#security) recommends checking authorization inside each Server Action rather than relying on Proxy, layouts, or pages.

- Inventory every Server Action, Route Handler, Pages API Route, server-side data loader, Proxy matcher, cached function, rewrite, redirect, and remote image pattern.
- Call actions and handlers directly without first loading their page. Verify unauthenticated, unauthorized, wrong-owner, and wrong-tenant requests fail.
- Add a route outside each intended Proxy matcher and prove the DAL or handler still denies access.
- Inspect rendered HTML, React Server Component payloads, Pages Router data responses, and Server Action responses for fields that should remain server-only.
- Run cross-user and cross-tenant cache tests, including after permission changes and revalidation.
- Keep Next.js on a supported patched release. [CVE-2024-46982](https://github.com/vercel/next.js/security/advisories/GHSA-gp8f-8m3g-qvj9) is an example where an affected Pages Router response could be cached when the application intended otherwise.

Security tests should fail when a new entry point or cache is added without an explicit classification. A fixed hand-maintained list can miss the new file for the same reason the control was omitted, so derive the inventory from the route and source tree where practical.

## References

- [Next.js Authentication Guide](https://nextjs.org/docs/app/guides/authentication)
- [Next.js Data Security Guide](https://nextjs.org/docs/app/guides/data-security)
- [Next.js Server Actions Guide](https://nextjs.org/docs/app/guides/server-actions)
- [Next.js Proxy Reference](https://nextjs.org/docs/app/api-reference/file-conventions/proxy)
- [Node.js Security Cheat Sheet](Nodejs_Security_Cheat_Sheet.md)
- [Secrets Management Cheat Sheet](Secrets_Management_Cheat_Sheet.md)
