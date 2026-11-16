# HTTP Request Smuggling Prevention Cheat Sheet

## Introduction

Most applications sit behind at least one front-end component, such as a CDN, load balancer, reverse proxy, or web application firewall (WAF), that forwards requests to a back-end server over shared, reused connections. Both sides have to agree where each request ends. When they disagree, an attacker can send one request that the front end sees as a single request and the back end sees as two. The leftover part is prepended to whatever comes next on that connection, which may be another user's request ([RFC 9112: Request Smuggling](https://www.rfc-editor.org/rfc/rfc9112.html#section-11.2), [CWE-444](https://cwe.mitre.org/data/definitions/444.html)).

This lets an attacker bypass access controls that only the front end enforces, capture other users' requests, and poison caches ([PortSwigger: Exploiting HTTP request smuggling](https://portswigger.net/web-security/request-smuggling/exploiting#using-http-request-smuggling-to-bypass-front-end-security-controls)). The root cause is in how components parse message framing, so the defenses below are about removing ambiguity rather than filtering payloads.

## How Desync Happens

- **Content-Length and Transfer-Encoding disagree.** An HTTP/1.1 request body is delimited either by `Content-Length` or by `Transfer-Encoding: chunked`. If a request carries both, or a `Transfer-Encoding` value that one component accepts and another ignores, each side can pick a different length. These are the CL.TE, TE.CL, and TE.TE variants ([RFC 9112: Message Body Length](https://www.rfc-editor.org/rfc/rfc9112.html#section-6.3)).
- **HTTP/2 is downgraded to HTTP/1.1.** HTTP/2 frames carry their own length, but a front end that rewrites requests into HTTP/1.1 for the back end can pass along a `content-length` or `transfer-encoding` header, or a header value with a CR or LF in it, that then decides the framing on the back end ([PortSwigger: HTTP/2 desync attacks](https://portswigger.net/research/http2)).
- **A server ignores a body it did not expect.** If the back end does not read the body of a request to an endpoint that normally has none, such as a static file or a redirect, the unread bytes are treated as the next request. Some of these cases can be triggered from a victim's browser, which poisons the browser's own connection to the site ([PortSwigger: Browser-powered desync attacks](https://portswigger.net/research/browser-powered-desync-attacks)).

## Prevention

### Use HTTP/2 End-to-End

Where the front end and the back end both support it, use HTTP/2 between them as well as towards clients, and turn off downgrading to HTTP/1.1. HTTP/2 determines the length of a request from its frames, so there is no second length to disagree about ([PortSwigger: How to prevent HTTP request smuggling](https://portswigger.net/web-security/request-smuggling#how-to-prevent-http-request-smuggling-vulnerabilities)).

### Reject Ambiguous HTTP/1.1 Framing

Apply the framing rules from [RFC 9112](https://www.rfc-editor.org/rfc/rfc9112.html#section-6.1) in every component, and prefer the strict option where the specification allows a choice:

- Reject a request that has both `Content-Length` and `Transfer-Encoding`. If a component processes it instead, it must use `Transfer-Encoding` alone. Either way, close the connection after responding.
- Respond with `400 (Bad Request)` and close the connection when `Transfer-Encoding` is present and `chunked` is not the final coding.
- Treat an invalid `Content-Length`, including several different values, as an unrecoverable error.

Have the front end normalize or reject ambiguous requests, and have the back end reject any that are still ambiguous and close the connection ([PortSwigger](https://portswigger.net/web-security/request-smuggling#how-to-prevent-http-request-smuggling-vulnerabilities)).

### Validate Requests That Are Downgraded

If HTTP/2 has to be translated to HTTP/1.1, validate the result as an HTTP/1.1 request before forwarding it ([RFC 9113: Field Validity](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.2.1)):

- Treat an HTTP/2 request as malformed if a header value contains CR, LF, or NUL, or a header name contains a colon (other than the leading one of a pseudo-header), whitespace, or uppercase characters.
- Treat an HTTP/2 request that contains `transfer-encoding` or other connection-specific headers as malformed ([RFC 9113: Connection-Specific Header Fields](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.2.2)).
- Treat a `content-length` that does not match the length of the DATA frames as malformed ([RFC 9113: Malformed Messages](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.1.1)).

### Handle Connections Defensively

- Read or discard the body of every request according to its declared length, even on endpoints that ignore the body. Never assume a request has no body ([PortSwigger](https://portswigger.net/web-security/request-smuggling#how-to-prevent-http-request-smuggling-vulnerabilities)).
- Close the connection instead of reusing it after a framing error or a server-level exception while handling a request.
- Disabling the reuse of back-end connections limits some attacks but does not stop request tunneling, so do not rely on it alone.
- Keep proxies, load balancers, and servers up to date, and check each product's own documentation for how it handles ambiguous requests and which settings make it strict.

## What These Controls Do Not Cover

- Request smuggling defeats controls that only the front end applies, because the smuggled request never passes through them. Enforce authorization in the application as well, not only in the proxy or WAF.
- A desync can poison a shared cache with another user's response. See the [Web Cache Security Cheat Sheet](Web_Cache_Security_Cheat_Sheet.md) for cache keys and what to cache.
- Header injection through CR and LF in values the application writes into responses is a related but separate problem. See the [HTTP Headers Cheat Sheet](HTTP_Headers_Cheat_Sheet.md).

## Testing

Test through the same chain of CDN, load balancer, and proxies that production uses, since the bug is in how those components disagree. The [OWASP Web Security Testing Guide](https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/07-Input_Validation_Testing/15-Testing_for_HTTP_Splitting_Smuggling/) and [PortSwigger](https://portswigger.net/web-security/request-smuggling/finding#finding-http-request-smuggling-vulnerabilities-using-timing-techniques) describe timing-based probes. Some probes can disrupt other users' requests on a vulnerable system, so test in a non-production environment where possible.

## References

- [RFC 9112: HTTP/1.1, Section 6.3 Message Body Length](https://www.rfc-editor.org/rfc/rfc9112.html#section-6.3)
- [RFC 9113: HTTP/2, Section 8.2 HTTP Fields](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.2)
- [CWE-444: Inconsistent Interpretation of HTTP Requests](https://cwe.mitre.org/data/definitions/444.html)
