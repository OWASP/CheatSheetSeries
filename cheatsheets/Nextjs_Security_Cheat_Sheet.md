# Next.js Security Cheat Sheet

## Introduction

Next.js applications have several server entry points and can render or cache data on both sides of the server/client boundary. The framework's [authentication guidance](https://nextjs.org/docs/app/guides/authentication) recommends placing authorization close to the data source instead of relying on routing or user interface checks.

Apply these principles to the relevant framework surfaces:

- Classify every server entry point and enforce controls appropriate to its audience and effects.
- Return only data that the browser is authorized to receive and the application needs.
- Include the intended audience in every cache decision.
- Treat routing and image configuration as security-sensitive code.
- Test controls by calling entry points directly, without using the user interface.

This sheet covers both the App Router and Pages Router. General JavaScript, authentication, Cross-Site Scripting (XSS), Cross-Site Request Forgery (CSRF), and Server-Side Request Forgery (SSRF) guidance is linked rather than repeated.

## Classify and Protect Server Entry Points

Next.js applications have multiple server entry points. A check in one does not protect another independently callable path. For protected operations, enforce authorization at a boundary that every applicable path traverses. The [Next.js Data Security guide](https://nextjs.org/docs/app/guides/data-security#data-access-layer) recommends a server-only Data Access Layer (DAL) that performs authorization and returns minimal Data Transfer Objects (DTOs). An equivalent service-layer policy enforcement point or database control can also provide the boundary when all protected paths necessarily traverse it.

| Entry point | Secure use |
|-------------|------------|
| Proxy (`proxy.ts` in Next.js 16+; deprecated `middleware.ts` remains available during migration) | Use for optimistic redirects and request filtering. Do not make it the only authorization layer. |
| Server Action | Treat each reachable action as a client-callable POST entry point. Validate input, then apply authentication and resource authorization when the operation is protected. |
| Route Handler (`route.ts`) or Pages API Route (`pages/api`) | Treat it as an HTTP endpoint with an explicit audience. Apply the controls appropriate to a public endpoint, authenticated API, service endpoint, or webhook. |
| Server Component, page, or data loader | Authorize before reading protected data. Return a narrow DTO rather than a database record. |
| Layout or Client Component | A layout can enforce render-time access, but it does not protect independently callable descendants. Client Component checks only control what the user interface shows. |

### Do not rely on Proxy or middleware alone

Proxy can redirect unauthenticated users early, but its `matcher` may omit a route and routing changes can silently move an operation outside its coverage. Next.js explicitly states that [Proxy should not be the only line of defense](https://nextjs.org/docs/app/guides/authentication#optimistic-checks-with-proxy-optional). Authorize protected operations again at the handler or data source.

This is also a defense against framework defects. [CVE-2025-29927](https://github.com/vercel/next.js/security/advisories/GHSA-f82v-jwr5-mffw) allowed affected self-hosted Next.js versions to bypass authorization implemented only in middleware. Patch the framework, but keep authorization behind the routing layer so one bypass cannot expose data.

### Secure Server Actions as endpoints

A Server Action referenced by the application can receive a client-originated POST independently of the page that renders its form. Rendering the form only on a protected page does not authenticate the action request. Next.js documents that [page-level authentication does not extend to Server Actions](https://nextjs.org/docs/app/guides/data-security#authentication-and-authorization).

Classify each action as public or protected, then apply the relevant controls:

- Validate all arguments as untrusted input.
- For a protected action, derive the current authentication context on the server rather than accepting identity claims in its arguments.
- Check permission on the exact protected object being read or changed; treat a user or tenant identifier submitted by the client as a selector, not authorization proof.
- Return only authorized result fields because Server Action return values are serialized to the client.
- Apply rate limits or stronger re-authentication to expensive or high-impact operations.

Next.js compares the request `Origin` with the host for Server Actions. Keep [`serverActions.allowedOrigins`](https://nextjs.org/docs/app/api-reference/config/next-config-js/serverActions#allowedorigins) narrow when a trusted proxy requires additional origins. On a self-hosted deployment, ensure that only trusted infrastructure can establish the canonical `Host` or `X-Forwarded-Host` value seen by the application. A [historical Server Action SSRF advisory](https://github.com/vercel/next.js/security/advisories/GHSA-fr5h-rqp8-mj6g), fixed in Next.js 14.1.1, demonstrates why patching and trustworthy host handling both matter. This built-in Origin check does not replace authentication, authorization, or the general controls in the [CSRF Prevention Cheat Sheet](Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md).

### Protect Route Handlers and Pages API Routes separately

Protecting a page does not protect a Route Handler or API Route that serves related data. Next.js says to treat [Route Handlers as public-facing API endpoints](https://nextjs.org/docs/app/guides/authentication#route-handlers). Classify each handler's audience: an intentionally public endpoint may require input validation and abuse controls, a webhook may authenticate a signature, and a protected API requires the applicable authentication plus object-level or tenant-level authorization from the [Authorization Cheat Sheet](Authorization_Cheat_Sheet.md).

Do not infer that a handler is private because only a Server Component calls it. If no browser, service, webhook, or external client needs the HTTP API, call the DAL directly from the Server Component and remove the extra entry point.

### Protect Draft Mode as a privileged state change

If the application uses Draft Mode, treat the handler that enables it as a protected entry point. Calling `enable()` on the value returned by `await draftMode()` sets the `__prerender_bypass` cookie; it does not authenticate the caller or validate a secret by itself. The [Draft Mode guide](https://nextjs.org/docs/app/guides/draft-mode) recommends validating a shared secret and confirming that the requested content exists before enabling the mode.

- Authenticate the CMS or other caller and use a high-entropy secret when a shared-secret integration is appropriate.
- Validate any requested content identifier against the trusted content source before enabling Draft Mode.
- Redirect to a server-established path returned by that source, not directly to an untrusted query parameter.
- Test that an unauthenticated caller cannot obtain the `__prerender_bypass` cookie or use a Draft Mode entry point to expose unpublished content.

## Control Data Crossing into the Browser

Code running only on the server can still send its return values to the browser. The App Router [serializes values passed to Client Components](https://nextjs.org/docs/app/guides/data-security#passing-data-from-server-to-client), and the Pages Router exposes page props in the initial HTML. The [Pages Router documentation](https://nextjs.org/docs/pages/building-your-application/data-fetching/get-server-side-props#behavior) warns that `getServerSideProps` values are visible to the client.

- Construct an explicit DTO containing only fields the browser is authorized to receive. Selecting only required columns at the data source provides additional defense in depth.
- Do not pass ORM records, session objects, or configuration merely because they are available. Do not send secrets to Client Components. Any token intentionally sent to the browser must be narrowly scoped and treated as exposed; configuration must be explicitly classified as public.
- Keep Server Action return values authorized and minimal; a server-side function does not make its returned value secret.
- Treat values returned in the `props` from `getStaticProps`, `getServerSideProps`, and [`getInitialProps`](https://nextjs.org/docs/pages/api-reference/functions/get-initial-props) as visible to that page's browser.
- Prefix an environment variable with `NEXT_PUBLIC_` only when its value is intentionally public. The value is included in client JavaScript according to the [Next.js environment variable guide](https://nextjs.org/docs/app/guides/environment-variables#bundling-environment-variables-for-the-browser).

Importing `server-only` in a sensitive module is a useful build-time guard because it prevents that module from being imported into a Client Component. It does not stop server code from explicitly returning sensitive data. React taint APIs can add another guard, but Next.js describes [tainting as defense in depth](https://nextjs.org/docs/app/guides/data-security#tainting), not a replacement for shaping data.

For browser rendering sinks and React-specific client concerns, use the [XSS Prevention Cheat Sheet](Cross_Site_Scripting_Prevention_Cheat_Sheet.md) and [DOM-based XSS Prevention Cheat Sheet](DOM_based_XSS_Prevention_Cheat_Sheet.md).

## Scope Caches to Their Audiences

Before caching a response or function result, classify its audience, such as public, tenant-scoped, user-scoped, permission-set, locale, cohort, or request-specific. A cache entry must not be reusable by a broader audience than the data permits. With `use cache`, Next.js includes serializable arguments and captured closure values in the [generated cache key](https://nextjs.org/docs/app/api-reference/directives/use-cache#cache-keys). Include a verified user, tenant, or other audience dimension when it changes the cached value or a cached authorization decision. When content is identical across authorized callers and authorization is enforced separately before return, do not duplicate the cache merely by identity.

- Establish and verify the required authorization context before returning protected cached data. Depending on the design, this may be a user identity, service identity, or validated capability.
- Include only verified dimensions that change the cached value or cached authorization decision, such as user ID, tenant ID, permission version, or locale. Do not use a raw cookie or bearer token as a cache key.
- Do not put user-specific data in a `use cache` function that has no user-specific input.
- Use caches that can serve a response before per-request application authorization, such as Incremental Static Regeneration (ISR), `getStaticProps`, or shared CDN caching, only for data the full cache audience may read. Next.js states that [`getStaticProps` data must be publicly cacheable](https://nextjs.org/docs/pages/building-your-application/data-fetching/get-static-props#when-should-i-use-getstaticprops).
- A server-side data or `fetch` cache may hold protected content shared by authorized callers when every return path authorizes access and the key separates every content variant.
- Do not add shared `Cache-Control` directives to personalized `getServerSideProps` responses.
- After authorization or tenancy changes, prevent reuse under stale permissions by invalidating affected keys or tags, advancing a permission version in the key, or using another bounded expiration strategy.

Treat cache invalidation as a mutation capability. [`revalidatePath`](https://nextjs.org/docs/app/api-reference/functions/revalidatePath) and [`revalidateTag`](https://nextjs.org/docs/app/api-reference/functions/revalidateTag) can be called from server entry points, while [`updateTag`](https://nextjs.org/docs/app/api-reference/functions/updateTag) is limited to Server Actions. Authenticate and authorize callers, derive the invalidation target from an authorized object or validate it against constrained application-owned path and tag patterns, and apply abuse controls to externally reachable invalidation handlers. A deliberately global purge should require the correspondingly privileged operation.

`use cache: private` can read request-time values, but its results are cached in the browser's memory and are still delivered to that browser. The [directive documentation](https://nextjs.org/docs/app/api-reference/directives/use-cache-private) does not make over-broad data safe to return.

For user-, tenant-, or permission-scoped caches, test representative identities with different entitlements: fill the cache as identity A, then request the same route and object identifiers as identity B. Repeat after changing a role or tenant membership. This catches missing audience keys that a positive-path cache test cannot.

## Treat Next.js Configuration as Security Code

Review `next.config.*`, Proxy matchers, and route configuration with the same care as application handlers. Next.js [rewrites act as a URL proxy](https://nextjs.org/docs/app/api-reference/config/next-config-js/rewrites), and matcher values can flow into destinations.

- Resolve external rewrite hosts from a fixed allowlist or a server-controlled registry. Do not let an untrusted header, host, cookie, or query capture select an upstream scheme, authority, or port.
- For a protected destination, ensure direct requests cannot bypass equivalent authentication and authorization. Enforcement may live at the destination or at a trusted gateway whose network policy blocks direct access. A rewrite masks the destination URL; it does not create an authorization boundary.
- Do not let untrusted captures select the scheme or authority of an external redirect. Validate any interpolated path or query component using the [Unvalidated Redirects and Forwards Cheat Sheet](Unvalidated_Redirects_and_Forwards_Cheat_Sheet.md).
- Define every `images.remotePatterns` restriction the application can enforce. Next.js warns that [omitted fields imply broad wildcards](https://nextjs.org/docs/app/api-reference/components/image#remotepatterns); allow port, pathname, or query variation only when the use case requires it and the trust model accounts for the broader match.
- Keep `images.dangerouslyAllowLocalIP` disabled unless a reviewed private-network use case requires it. Next.js warns that enabling it can let users [access content on the internal network](https://nextjs.org/docs/app/api-reference/components/image#dangerouslyallowlocalip). Apply the [SSRF Prevention Cheat Sheet](Server_Side_Request_Forgery_Prevention_Cheat_Sheet.md) to any server-side fetch destination.
- Keep `serverActions.allowedOrigins` restricted to trusted application and proxy origins.
- Leave [`productionBrowserSourceMaps`](https://nextjs.org/docs/app/api-reference/config/next-config-js/productionBrowserSourceMaps) disabled unless the operational need justifies publicly serving the original browser source maps. Enabling it causes Next.js to emit and automatically serve those files.
- Deploy an optimized production build with an appropriate production server or adapter. Do not expose [`next dev`](https://nextjs.org/docs/app/api-reference/cli/next#next-dev-options), which enables development-mode hot reloading and error reporting, as the production service.

Security-sensitive configuration assembled from environment variables is still code. Validate hosts and origins against an allowlist at startup and fail closed when a required value is missing or invalid. Validate other configuration using an appropriate schema, type, or range constraint.

### Choose a CSP compatible with the rendering model

Use a Content Security Policy (CSP) appropriate to the application's script, style, and third-party resource requirements; see the [Content Security Policy Cheat Sheet](Content_Security_Policy_Cheat_Sheet.md) for general policy design. Next.js can [generate a fresh nonce in Proxy and apply it during rendering](https://nextjs.org/docs/app/guides/content-security-policy#nonces). A nonce must be unpredictable and unique for each response; do not cache HTML in a way that reuses it for another response.

Nonce-based CSP has an architectural cost: Next.js requires dynamic rendering, disables static optimization and ISR for those pages, and does not support Partial Prerendering (PPR) with request-specific nonces. Applications that retain static rendering can use a CSP without nonces when their resource policy permits it. Do not weaken a production policy with development-only directives such as `'unsafe-eval'` merely to make the development server work.

## Verify the Boundaries

Framework controls need direct negative-path tests. The [Next.js production checklist](https://nextjs.org/docs/app/guides/production-checklist#security) recommends checking authorization inside protected Server Actions rather than relying on Proxy, layouts, or pages.

- Inventory application-defined Server Actions, Route Handlers, Pages API Routes, Draft Mode entry points, server-side data loaders, Proxy matchers, cached functions, cache-invalidation call sites, rewrites, redirects, CSP configuration, source map settings, and remote image patterns. Classify each applicable audience and effect.
- Call actions and handlers directly without first loading their page. For protected operations, verify the applicable unauthenticated, unauthorized, wrong-owner, and wrong-tenant requests fail. For public operations, verify the intended public behavior and abuse controls.
- For protected route families that use Proxy for early filtering, exercise an unmatched or bypassed-Proxy path and prove the handler or data boundary still denies unauthorized access.
- Inspect the applicable rendered HTML, React Server Component payloads, Pages Router data responses, and Server Action responses for fields that should remain server-only.
- Run cross-user and cross-tenant tests for audience-scoped caches, including after permission changes and revalidation.
- Call Draft Mode and cache-invalidation handlers directly and prove that unauthorized callers cannot enable preview state or invalidate content.
- Keep Next.js on a supported patched release. [CVE-2024-46982](https://github.com/vercel/next.js/security/advisories/GHSA-gp8f-8m3g-qvj9) is an example where an affected Pages Router response could be cached when the application intended otherwise.

Security tests should fail when a new application entry point or cache is added without an explicit classification. A fixed hand-maintained list can miss the new file for the same reason the control was omitted, so derive the inventory from the route and source tree where practical.

## References

- [Next.js Authentication Guide](https://nextjs.org/docs/app/guides/authentication)
- [Next.js Data Security Guide](https://nextjs.org/docs/app/guides/data-security)
- [Next.js Server Actions Guide](https://nextjs.org/docs/app/guides/server-actions)
- [Next.js Proxy Reference](https://nextjs.org/docs/app/api-reference/file-conventions/proxy)
- [Node.js Security Cheat Sheet](Nodejs_Security_Cheat_Sheet.md)
- [Secrets Management Cheat Sheet](Secrets_Management_Cheat_Sheet.md)
