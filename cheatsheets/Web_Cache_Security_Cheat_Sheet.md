# Web Cache Security Cheat Sheet

## Introduction

HTTP caches improve performance by reusing stored responses in browsers, reverse proxies, content delivery networks (CDNs), and application data stores. A cache becomes a security boundary when it serves a response to a request other than the one that originally produced it. The [HTTP caching specification](https://www.rfc-editor.org/rfc/rfc9111.html) defines the behavior of private and shared caches, while the [MDN HTTP caching guide](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Caching) provides practical examples of common directives.

This cheat sheet focuses on preventing sensitive data exposure, web cache poisoning, web cache deception, and cross-tenant data leakage. It applies to developers and operators configuring origin applications, reverse proxies, CDNs, and application-level caches.

## Key Risks

The [security considerations in RFC 9111](https://www.rfc-editor.org/rfc/rfc9111.html#name-security-considerations) describe caches as attractive attack targets because one stored response can affect many users. [OWASP's cache poisoning overview](https://owasp.org/www-community/attacks/Cache_Poisoning) also explains how a harmful cached response can be distributed to other visitors.

- **Sensitive response exposure**: A shared cache stores a personalized or authenticated response and returns it to another user.
- **Web cache poisoning**: An attacker-controlled request input changes a response but is excluded from the cache key. The harmful response is then served to other users.
- **Web cache deception**: A dynamic or personalized URL is made to look like a static asset, causing an intermediary to cache sensitive content.
- **Cache key confusion**: The cache and origin disagree about URL normalization, query parameters, headers, or request routing, causing unrelated requests to share an entry.
- **Cross-tenant leakage**: An application cache omits the tenant or authorization context from its key.
- **Stale security state**: Cached content remains accessible after permissions, account state, or the underlying resource changes.

## Best Practices

Treat cacheability and cache-key design as part of the application's authorization model. [RFC 9111](https://www.rfc-editor.org/rfc/rfc9111.html) specifies how response directives, request inputs, and validation control whether a stored response can be reused.

### 1. Classify Responses Before Caching

Define an explicit policy for every route. Default to preventing shared caching for authenticated, personalized, tenant-specific, or otherwise sensitive responses.

- Use `Cache-Control: no-store` when a response must not be stored by any compliant cache.
- Use `Cache-Control: private` when a response may be stored by a user's private cache but not by a shared cache.
- Remember that `no-cache` permits storage but requires successful validation before reuse. It does not mean "do not store."
- Do not assume that cookies make a response private. A `Set-Cookie` header alone does not prevent caching.
- Do not mark a response influenced by `Authorization` or session cookies as `public`, or give it an `s-maxage`, unless sharing the response has been deliberately designed and reviewed.
- Purge previously stored entries when changing a route to `no-store`; the directive does not delete old entries.

For a response containing sensitive data:

```http
Cache-Control: no-store
```

For non-sensitive content that may be stored only in a private cache and must be revalidated:

```http
Cache-Control: private, no-cache
```

### 2. Design a Complete Cache Key

Every request input that can change a cacheable response must either be represented in the cache key or be rejected for that route.

- Include the request method, scheme, host, normalized path, and all relevant query parameters.
- Use [`Vary`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Vary) for representation-selecting headers such as `Accept-Encoding` or `Accept-Language`.
- Do not use `Vary: Cookie` as a general authorization boundary. Prefer disabling shared caching for personalized responses.
- Derive tenant and user identifiers from trusted, authenticated server-side context, not directly from an untrusted header or query parameter.
- Apply the same URL normalization and parameter handling at the CDN, reverse proxy, and origin.
- Reject ambiguous requests, including conflicting host information, duplicate parameters with inconsistent meanings, and malformed path encodings.

For an application-level cache, use a structured, versioned key:

```text
<environment>:<resource-version>:<tenant-id>:<resource-type>:<resource-id>
```

Do not put session tokens, API keys, or other secrets in cache keys because keys often appear in logs and administrative interfaces.

### 3. Prevent Web Cache Poisoning

[Cloudflare's cache poisoning guidance](https://developers.cloudflare.com/cache/cache-security/avoid-web-poisoning/) describes the central design rule: untrusted request inputs that are not part of the cache key must not influence a cacheable response.

- Cache only routes that are explicitly intended to be shared.
- Do not let unkeyed headers or a body on a `GET` request alter a cacheable response.
- Trust `Forwarded` and `X-Forwarded-*` headers only when they were added or replaced by a trusted proxy.
- Canonicalize the host and scheme before using them to generate links, redirects, or security-sensitive headers.
- Do not reflect unvalidated request metadata into cached HTML, JSON, redirects, or response headers.
- Separate static assets and dynamic application routes by hostname or an unambiguous path namespace where practical.
- If poisoning occurs, purge every affected cache layer and fix the key or origin behavior before re-enabling caching.

### 4. Prevent Web Cache Deception

Web cache deception occurs when an attacker causes a shared cache to store personalized content under a URL that appears cacheable. [Cache Deception Armor](https://developers.cloudflare.com/cache/cache-security/cache-deception-armor/) documents one mitigation: verifying that the requested file extension agrees with the response `Content-Type`.

- Base cache eligibility on an allowlisted route and response policy, not only on a file extension.
- Make dynamic routes reject unexpected path segments and static-looking suffixes instead of silently routing them to the same handler.
- Ensure that a request such as `/account/profile/image.css` cannot resolve to the same personalized handler as `/account/profile`.
- Verify that the URL extension and response `Content-Type` agree before caching a static asset.
- Ignore or remove query parameters from a cache key only after proving that they cannot change routing, authorization, or response content.

### 5. Coordinate Origin and Intermediary Policies

A secure origin policy can be weakened by a CDN rule, reverse proxy override, or framework default. [MDN's caching guide](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Caching) recommends explicitly controlling caching rather than relying on heuristic behavior.

- Define browser and shared-cache lifetimes independently with the appropriate directives.
- Review CDN rules that override origin `Cache-Control` headers or cache responses by status code, path pattern, or file extension.
- Give error pages, redirects, and authentication responses explicit cache policies.
- Use consistent URL normalization at every layer. When a CDN normalizes its cache key, send the normalized form to the origin as well.
- Maintain a tested purge mechanism for individual keys, tags, or narrowly scoped route groups.
- Fail closed when a sensitive route has a missing, malformed, or conflicting cache policy.

### 6. Protect Application-Level Caches

In-memory, database, and distributed caches can leak data even when HTTP caching is disabled. Authorization must still be enforced on every request before cached data is returned. See the [Authorization Cheat Sheet](Authorization_Cheat_Sheet.md) and [Multi-Tenant Security Cheat Sheet](Multi_Tenant_Security_Cheat_Sheet.md) for related controls.

- Namespace keys by environment and application to prevent collisions.
- Include tenant identity and every authorization-relevant resource dimension in the key.
- Do not let a cache hit bypass object-level or tenant-level authorization.
- Avoid caching final authorization decisions unless the key includes the complete subject, object, action, policy version, and a tightly bounded lifetime.
- Version key formats so schema or permission-model changes cannot reuse incompatible entries.
- Restrict administrative access to cache contents, configuration, statistics, and purge operations.

### 7. Test the Complete Cache Path

Test through the same CDN and proxy path used in production. The [Cloudflare cache-key documentation](https://developers.cloudflare.com/cache/how-to/cache-keys/) illustrates how scheme, host, path, query parameters, headers, and cookies can contribute to a cache key.

- Request the same URL as two different users and tenants; neither response may contain the other's data.
- Change one header, query parameter, cookie, or path component at a time and verify the expected cache behavior.
- Append static-looking suffixes and unexpected path segments to authenticated routes and verify that they are rejected and not cached.
- Test authorization changes, logout, content updates, and purge operations against already stored entries.
- Monitor for unexpected cache hits on authenticated routes, abrupt hit-ratio changes, unusual forwarded headers, and repeated purge activity.
- Log enough cache-status and routing metadata to investigate incidents, but never log secrets or full sensitive response bodies.

## Do's and Don'ts

Use these checks alongside the [HTTP caching requirements in RFC 9111](https://www.rfc-editor.org/rfc/rfc9111.html) and the application's normal authorization review.

**Do:**

- Set an explicit `Cache-Control` policy on every security-relevant response.
- Verify that every response-changing input is keyed, normalized, or rejected.
- Keep cache and origin routing rules consistent.
- Authorize the current request before returning cached application data.
- Test with multiple identities and tenants through the production caching path.
- Plan and test targeted cache invalidation before an incident occurs.

**Don't:**

- Assume that authentication, cookies, TLS, or `Set-Cookie` automatically prevents caching.
- Cache every URL with a static-looking extension.
- Allow unkeyed request metadata to influence shared responses.
- Treat `Vary: Cookie` as a substitute for an authorization design.
- Include credentials or session identifiers in keys, logs, or purge URLs.
- Assume that purging a poisoned entry fixes the underlying vulnerability.

## References

- [RFC 9111: HTTP Caching](https://www.rfc-editor.org/rfc/rfc9111.html)
- [MDN: HTTP Caching](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Caching)
- [MDN: Vary Header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Vary)
- [OWASP: Cache Poisoning](https://owasp.org/www-community/attacks/Cache_Poisoning)
- [Cloudflare: Avoid Web Cache Poisoning](https://developers.cloudflare.com/cache/cache-security/avoid-web-poisoning/)
- [Cloudflare: Cache Deception Armor](https://developers.cloudflare.com/cache/cache-security/cache-deception-armor/)
- [Cloudflare: Cache Keys](https://developers.cloudflare.com/cache/how-to/cache-keys/)
