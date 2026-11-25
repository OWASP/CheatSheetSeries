# CORS Security Cheat Sheet

## Introduction

Browsers stop a page from reading responses from another origin unless that origin agrees. Cross-Origin Resource Sharing (CORS) is how a server agrees: it sends headers such as `Access-Control-Allow-Origin` and `Access-Control-Allow-Credentials` that tell the browser which other origins may read its responses ([Fetch Standard: CORS protocol](https://fetch.spec.whatwg.org/#http-cors-protocol)).

CORS only relaxes the same-origin policy. Every origin a server allows can read what that server returns to the user's browser, so a CORS configuration is a list of origins you trust with your users' data. This cheat sheet covers how to configure it without exposing more than intended. For testing, see [WSTG-CLNT-07 Testing Cross Origin Resource Sharing](https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing/).

## What CORS Does and Doesn't Protect

- **CORS is not access control.** The browser enforces it, and only for scripts running in the browser. Scripts can't change the `Origin` header ([MDN: Forbidden request header](https://developer.mozilla.org/en-US/docs/Glossary/Forbidden_request_header)), but any other client can send whatever `Origin` it likes. Authenticate and authorize every request on the server as if CORS didn't exist.
- **CORS doesn't prevent CSRF.** Some cross-origin requests, such as a form `POST`, are sent without a preflight, so the server processes them even if the response can't be read ([MDN: Simple requests](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS#simple_requests), [PortSwigger: CORS](https://portswigger.net/web-security/cors)). Use the defenses in the [Cross-Site Request Forgery Prevention Cheat Sheet](Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md).
- **Not sending CORS headers is the safe default.** Only add them to endpoints that another origin actually needs to read.

## Allowing Origins

Compare the `Origin` request header against a fixed allowlist of full origins (scheme, host and port), and only echo it back in `Access-Control-Allow-Origin` if it matches exactly. Most CORS vulnerabilities come from getting this check wrong ([PortSwigger: Errors parsing Origin headers](https://portswigger.net/web-security/cors#errors-parsing-origin-headers)):

- **Don't reflect the `Origin` header without checking it.** Combined with `Access-Control-Allow-Credentials: true`, this lets any website read authenticated responses.
- **Don't match prefixes, suffixes or loose regular expressions.** A suffix check for `example.com` also allows `attackerexample.com`, and a prefix check allows `example.com.attacker.net`. In regular expressions, escape the dots and anchor both ends.
- **Don't allow `null`.** Sandboxed documents and `data:` or `file:` URLs send `Origin: null`, and any site can create such a document ([MDN: Access-Control-Allow-Origin](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Access-Control-Allow-Origin)).
- **Only allow HTTPS origins.** Allowing an `http://` origin lets a network attacker who can inject content into that origin read the response ([PortSwigger: Breaking TLS with poorly configured CORS](https://portswigger.net/web-security/cors#breaking-tls-with-poorly-configured-cors)).
- **Avoid trusting all subdomains.** An allowed origin is trusted completely, so a cross-site scripting (XSS) flaw on any allowed subdomain lets an attacker read your responses ([PortSwigger: Exploiting XSS via CORS trust relationships](https://portswigger.net/web-security/cors#exploiting-xss-via-cors-trust-relationships)). List the specific origins that need access.

A minimal check in Express, assuming the allowlist is maintained by the application and not built from input:

```javascript
const allowedOrigins = new Set(['https://app.example.com', 'https://admin.example.com']);

const origin = req.headers.origin;
if (origin && allowedOrigins.has(origin)) {
  res.setHeader('Access-Control-Allow-Origin', origin);
}
res.append('Vary', 'Origin');
```

Prefer your framework's CORS support over writing headers by hand, and check what its options do:

- Express `cors`: `origin: true` reflects any request origin. Pass an array of exact origins instead ([Express cors middleware](https://expressjs.com/en/resources/middleware/cors.html#configuration-options)).
- Spring: list exact origins with `allowedOrigins`. With credentials enabled, `allowedOriginPatterns` accepts patterns, so keep them as narrow as `allowedOrigins` would be ([Spring CORS: Credentialed Requests](https://docs.spring.io/spring-framework/reference/web/webmvc-cors.html#mvc-cors-credentialed-requests)).
- ASP.NET Core: use `WithOrigins`. Microsoft calls `AllowAnyOrigin` or `SetIsOriginAllowed(_ => true)` together with `AllowCredentials` an insecure configuration ([ASP.NET Core: Enable CORS](https://learn.microsoft.com/en-us/aspnet/core/security/cors#set-the-allowed-origins)).
- Django with `django-cors-headers`: prefer `CORS_ALLOWED_ORIGINS` over `CORS_ALLOWED_ORIGIN_REGEXES` and `CORS_ALLOW_ALL_ORIGINS` ([django-cors-headers](https://github.com/adamchainz/django-cors-headers#configuration)).

## Credentials

`Access-Control-Allow-Credentials: true` lets a cross-origin script read the response to a request that includes credentials: cookies, TLS client certificates, or HTTP authentication (not a token the script itself sets in the `Authorization` header). It doesn't decide whether cookies are sent: that depends on the request's credentials mode and the cookie's `SameSite` attribute, so the server still processes the request and the browser only withholds the response. The Fetch Standard calls sharing such responses "rather unsafe" and warns about the confused deputy problem ([Fetch Standard: CORS protocol and credentials](https://fetch.spec.whatwg.org/#cors-protocol-and-credentials)).

- Only enable credentials for endpoints and origins that need them, and keep public, unauthenticated endpoints separate.
- Browsers reject `Access-Control-Allow-Origin: *` on credentialed requests, so a server that wants credentials has to name the origin ([MDN: Credentialed requests and wildcards](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS#credentialed_requests_and_wildcards)). Don't work around this by reflecting the request origin.
- `Access-Control-Allow-Origin: *` without credentials is fine for truly public data, such as a public API or static assets. Don't use it on responses that depend on the user's network location or other ambient access, see [Internal Network Services](#internal-network-services).

## Preflight and Caching

- **Send `Vary: Origin`** whenever `Access-Control-Allow-Origin` depends on the request's `Origin`. Without it, a cache can serve a response with one origin's CORS headers to a different origin ([Fetch Standard: CORS protocol and HTTP caches](https://fetch.spec.whatwg.org/#cors-protocol-and-http-caches)).
- **Don't treat a preflight as authorization.** Answer it without requiring a session or a client certificate, never perform an action on it, and authorize the actual request. According to the Fetch Standard, a preflight `OPTIONS` request must not include credentials ([Fetch Standard: CORS protocol and credentials](https://fetch.spec.whatwg.org/#cors-protocol-and-credentials)), but some browsers deviate from this requirement for TLS client certificates:
    - Chromium-based browsers send TLS client certificates in CORS preflight requests ([Chromium issue 40089326](https://issues.chromium.org/issues/40089326)).
    - Firefox allows this behavior when the `network.cors_preflight.allow_client_cert` preference is enabled ([Firefox bug #1511151](https://bugzil.la/1511151)).
- **Keep `Access-Control-Allow-Methods` and `Access-Control-Allow-Headers` to what the client needs**, and keep `Access-Control-Max-Age` short enough that a change to the policy takes effect in reasonable time. Browsers cap it anyway, at 2 hours in Chromium and 24 hours in Firefox, and use 5 seconds when it's missing ([MDN: Preflighted requests](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS#preflighted_requests), [MDN: Access-Control-Max-Age](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Access-Control-Max-Age)).
- **List response headers the client needs in `Access-Control-Expose-Headers`.** Scripts can only read the CORS-safelisted response headers by default, so a header like `X-Total-Count` stays hidden even from an allowed origin. Only expose headers that are meant for the client ([MDN: Access-Control-Expose-Headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Access-Control-Expose-Headers)).

## Internal Network Services

A public website can make the user's browser send requests to services on `localhost` or the internal network that the attacker can't reach directly. If such a service answers with `Access-Control-Allow-Origin: *`, the attacking site can read its responses even without credentials ([PortSwigger: Intranets and CORS without credentials](https://portswigger.net/web-security/cors#intranets-and-cors-without-credentials)).

- Don't send permissive CORS headers from internal services or local development servers.
- Require authentication on internal and local services instead of relying on being unreachable.
- The proposed [Local Network Access](https://wicg.github.io/local-network-access/) specification adds a user permission for these requests, but don't rely on browsers enforcing it.

## References

- [Fetch Standard: CORS protocol](https://fetch.spec.whatwg.org/#http-cors-protocol)
- [MDN: Cross-Origin Resource Sharing (CORS)](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS)
- [MDN: Access-Control-Expose-Headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Access-Control-Expose-Headers)
- [MDN: Access-Control-Max-Age](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Access-Control-Max-Age)
- [OWASP WSTG-CLNT-07 Testing Cross Origin Resource Sharing](https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing/)
