# REST Assessment Cheat Sheet

## About RESTful Web Services

Web Services are an implementation of web technology used for machine to machine communication. As such they are used for Inter application communication, Web 2.0 and Mashups and by desktop and mobile applications to call a server.

RESTful web services (often called simply REST) are a light weight variant of Web Services based on the RESTful design pattern. In practice RESTful web services utilizes HTTP requests that are similar to regular HTTP calls in contrast with other Web Services technologies such as SOAP which utilizes a complex protocol.

## Key relevant properties of RESTful web services

- Use of HTTP methods (`GET`, `POST`, `PUT` and `DELETE`) as the primary verb for the requested operation.
- Non-standard parameters specifications:
    - As part of the URL.
    - In headers.
- Structured parameters and responses using JSON or XML in a parameter values, request body or response body. Those are required to communicate machine useful information.
- Custom authentication and session management, often utilizing custom security tokens: this is needed as machine to machine communication does not allow for login sequences.
- Lack of formal documentation. A [proposed standard for describing RESTful web services called WADL](http://www.w3.org/Submission/wadl/) was submitted by Sun Microsystems but was never officially adapted.

## The challenge of security testing RESTful web services

- Inspecting the application does not reveal the attack surface, I.e. the URLs and parameter structure used by the RESTful web service. The reasons are:
    - No application utilizes all the available functions and parameters exposed by the service
    - Those used are often activated dynamically by client side code and not as links in pages.
    - The client application is often not a web application and does not allow inspection of the activating link or even relevant code.
- The parameters are non-standard making it hard to determine what is just part of the URL or a constant header and what is a parameter worth [fuzzing](https://owasp.org/www-community/Fuzzing).
- As a machine interface the number of parameters used can be very large, for example a JSON structure may include dozens of parameters. [fuzzing](https://owasp.org/www-community/Fuzzing) each one significantly lengthen the time required for testing.
- Custom authentication mechanisms require reverse engineering and make popular tools not useful as they cannot track a login session.

## How to pentest a RESTful web service

Determine the attack surface through documentation - RESTful pen testing might be better off if some level of clear-box testing is allowed and you can get information about the service.

This information will ensure fuller coverage of the attack surface. Such information to look for:

- Formal service description - While for other types of web services such as SOAP a formal description, usually in WSDL is often available, this is seldom the case for REST. That said, either WSDL 2.0 or WADL can describe REST and are sometimes used.
- A developer guide for using the service may be less detailed but will commonly be found, and might even be considered *opaque-box* testing.
- Application source or configuration - in many frameworks, including dotNet ,the REST service definition might be easily obtained from configuration files rather than from code.

Collect full requests using a [proxy](https://www.zaproxy.org/) - while always an important pen testing step, this is more important for REST based applications as the application UI may not give clues on the actual attack surface.

Note that the proxy must be able to collect full requests and not just URLs as REST services utilize more than just GET parameters.

Analyze collected requests to determine the attack surface:

- Look for non-standard parameters:
    - Look for abnormal HTTP headers - those would many times be header based parameters.
    - Determine if a URL segment has a repeating pattern across URLs. Such patterns can include a date, a number or an ID like string and indicate that the URL segment is a URL embedded parameter.
        - For example: `http://server/srv/2013-10-21/use.php`
    - Look for structured parameter values - those may be JSON, XML or a non-standard structure.
    - If the last element of a URL does not have an extension, it may be a parameter. This is especially true if the application technology normally uses extensions or if a previous segment does have an extension.
        - For example: `http://server/svc/Grid.asmx/GetRelatedListItems`
    - Look for highly varying URL segments - a single URL segment that has many values may be parameter and not a physical directory.
        - For example if the URL `http://server/src/XXXX/page` repeats with hundreds of value for `XXXX`, chances `XXXX` is a parameter.

Verify non-standard parameters: in some cases (but not all), setting the value of a URL segment suspected of being a parameter to a value expected to be invalid can help determine if it is a path elements of a parameter. If a path element, the web server will return a *404* message, while for an invalid value to a parameter the answer would be an application level message as the value is legal at the web server level.

Analyzing collected requests to optimize [fuzzing](https://owasp.org/www-community/Fuzzing) - after identifying potential parameters to fuzz, analyze the collected values for each to determine:

- Valid vs. invalid values, so that [fuzzing](https://owasp.org/www-community/Fuzzing) can focus on marginal invalid values.
    - For example sending *0* for a value found to be always a positive integer.
- Sequences allowing to fuzz beyond the range presumably allocated to the current user.

Lastly, when [fuzzing](https://owasp.org/www-community/Fuzzing), don't forget to emulate the authentication mechanism used.

## Assessing OpenAPI/Swagger-based REST APIs

Modern REST APIs are commonly described using the [OpenAPI Specification (OAS)](https://www.openapis.org/), which replaces older formats such as WSDL and WADL. When an OpenAPI definition is available it significantly accelerates attack surface discovery.

**Locate the schema document.** Common default paths include:

- `/openapi.json`, `/openapi.yaml`
- `/swagger.json`, `/swagger.yaml`
- `/api-docs`, `/v2/api-docs`, `/v3/api-docs`
- `/docs`, `/redoc`

Even when these paths are not advertised, try them — many frameworks expose them by default in production.

**Enumerate endpoints and parameters from the schema.** The schema lists every path, HTTP method, query parameter, request body field, and response shape. Use this to:

- Build a complete list of endpoints that may not appear in the UI.
- Identify parameters that the client never sends but the server still accepts.
- Find endpoints marked `deprecated` that may receive less security scrutiny.

**Test undocumented fields.** Schemas can lag behind implementation. Submit additional JSON fields beyond those defined in the schema and observe whether they are accepted or reflected in responses — this is the basis for [Mass Assignment](#mass-assignment-in-json-apis) testing.

**Schema-driven fuzzing.** Tools such as [OWASP ZAP](https://www.zaproxy.org/) and [Schemathesis](https://schemathesis.readthedocs.io/) can import an OpenAPI definition and automatically generate test cases for each endpoint, including boundary values, type mismatches, and required-field omissions.

## JWT and OAuth2 Assessment

Many modern REST APIs use [JSON Web Tokens (JWTs)](https://jwt.io/) for stateless authentication and [OAuth 2.0](https://oauth.net/2/) for delegated authorization. Misconfigurations in either are a frequent source of critical vulnerabilities.

### JWT Assessment

**Verify signature validation.** Swap the algorithm header to `alg: none` and remove the signature. A vulnerable server will accept the token without validating it.

**Test algorithm confusion.** If the server uses RS256 (asymmetric), try signing the token with HS256 using the server's *public key* as the HMAC secret. Servers that do not pin the expected algorithm may accept the forged token.

**Tamper with claims.** Decode the payload (it is Base64Url-encoded, not encrypted), modify claims such as `sub`, `role`, or `email`, re-sign or strip the signature, and replay the token.

**Check expiry enforcement.** Send a token whose `exp` claim is in the past. The server should return `401`; if it returns `200`, expiry is not being validated.

**Inspect the payload for sensitive data.** JWT payloads are readable by anyone who holds the token. Look for PII, internal identifiers, or role information that should not be client-visible.

**Test `kid` header injection.** If the server resolves a signing key by a `kid` (key ID) header value, test for SQL injection, path traversal, and SSRF via that field.

For comprehensive JWT attack guidance see the [OWASP JSON Web Token Cheat Sheet](JSON_Web_Token_for_Java_Cheat_Sheet.md).

### OAuth2 Assessment

**Validate scope enforcement.** Obtain a token with a limited scope (e.g. `read:profile`) and attempt operations that require broader scope (e.g. `write:admin`). The server should reject out-of-scope requests with `403`.

**Test token reuse across tenants.** In multi-tenant APIs, use a valid token issued to Tenant A and attempt to access resources belonging to Tenant B.

**Check PKCE enforcement.** For authorization code flows, confirm that [PKCE](https://oauth.net/2/pkce/) (`code_challenge` / `code_verifier`) is required. Without it, a stolen authorization code can be exchanged for a token.

**Attempt refresh token misuse.** Test whether refresh tokens can be used more than once (they should be rotated and invalidated on use) and whether they expire.

## Broken Object Level Authorization (BOLA)

[BOLA](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/) (also known as IDOR — Insecure Direct Object Reference) is the most common API vulnerability in the [OWASP API Security Top 10](https://owasp.org/API-Security/).

**Identify object identifiers in requests.** Look for numeric IDs, UUIDs, slugs, or hashes in URL path segments and query parameters:

```
GET /api/v1/orders/4821
GET /api/v1/users/7/documents/99
```

**Horizontal privilege escalation.** Authenticate as User A, capture the identifier for one of User A's resources, then substitute the identifier for a resource belonging to User B. If the server returns User B's data, BOLA is present.

**Vertical privilege escalation.** Substitute identifiers for objects belonging to a higher-privilege user (e.g. an administrator record) using a low-privilege token.

**Test all HTTP methods.** An endpoint that correctly restricts `GET` on another user's resource may still permit `PUT`, `PATCH`, or `DELETE` on it.

**Test indirect references.** Some APIs replace direct database IDs with hashed or encoded identifiers. Attempt to decode or enumerate these — predictable schemes (sequential integers encoded in Base64, for example) can still be exploited.

## Mass Assignment in JSON APIs

Mass assignment occurs when an API automatically binds request body fields to internal object properties without filtering, allowing attackers to set fields the application never intended to expose — such as `role`, `isAdmin`, or `balance`.

**Identify bindable fields.** Compare the fields documented in the API schema against the fields present in the response body. Undocumented response fields are candidates for assignment testing.

**Inject extra fields in `POST` and `PUT` requests.** Add fields beyond those shown in the documentation:

```json
{
  "name": "Alice",
  "email": "alice@example.com",
  "role": "admin",
  "isVerified": true
}
```

Inspect the response and any subsequent `GET` requests for that resource to determine whether the injected fields were persisted.

**Target numeric privilege escalation fields.** Fields such as `credits`, `balance`, `quota`, or `subscriptionTier` are high-value targets. Attempt to set them to arbitrarily large values.

**Test `PATCH` separately.** Partial-update endpoints may apply mass assignment independently of full-update `PUT` endpoints.

## Rate Limiting and Throttling Assessment

APIs that do not enforce rate limits are vulnerable to credential stuffing, enumeration, denial-of-service, and scraping attacks.

**Establish a baseline.** Send a sequence of identical requests and note response time, headers, and status codes. Look for standard rate-limiting headers:

- `X-RateLimit-Limit` — the request ceiling
- `X-RateLimit-Remaining` — requests remaining in the current window
- `X-RateLimit-Reset` — Unix timestamp when the window resets
- `Retry-After` — seconds to wait after a `429` response

**Exceed the limit.** Send enough requests to exhaust the documented limit and confirm the API returns `429 Too Many Requests`. A `200` response after the limit is exceeded indicates rate limiting is not enforced.

**Test per-resource limits separately.** Authentication endpoints (login, password reset, OTP verification) should have stricter limits than general data endpoints. Test each independently.

**Attempt limit bypass.** Try the following bypass techniques and observe whether the limit resets or is circumvented:

- Rotating `X-Forwarded-For` or `X-Real-IP` header values.
- Distributing requests across multiple API keys or accounts.
- Using different HTTP methods (`GET` vs `POST`) for the same logical operation.

**Test for missing limits on sensitive operations.** Enumeration attacks against user IDs, coupon codes, OTPs, and similar finite spaces are often feasible even at low request rates if no limit is applied. Test these explicitly.

## Related Resources

- [REST Security Cheat Sheet](REST_Security_Cheat_Sheet.md) - the other side of this cheat sheet
- [OWASP API Security Top 10](https://owasp.org/API-Security/)
- [OWASP JSON Web Token Cheat Sheet](JSON_Web_Token_for_Java_Cheat_Sheet.md)
- [OWASP OAuth 2.0 Cheat Sheet](OAuth2_Cheat_Sheet.md)
- [Schemathesis — OpenAPI fuzzing tool](https://schemathesis.readthedocs.io/)
- [YouTube: RESTful services, web security blind spot](https://www.youtube.com/watch?v=pWq4qGLAZHI) - a video presentation elaborating on most of the topics on this cheat sheet.
