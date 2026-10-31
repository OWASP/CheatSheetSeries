# Browser-Initiated Request Abuse Cheat Sheet

## Introduction

Browsers can issue HTTP requests when loading embedded resources, without running injected JavaScript. If an authenticated application changes state in response to an unintended request, an attacker may be able to exploit that behavior as cross-site request forgery (CSRF). This cheat sheet explains two browser-initiated request patterns migrated from the XSS Filter Evasion Cheat Sheet and the conditions under which they matter. For comprehensive countermeasures, see the [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html).

These patterns do not, by themselves, demonstrate script execution, cross-site scripting (XSS), or web application firewall (WAF) bypass.

## Browser-Initiated Request Patterns

An HTML image element asks the browser to fetch the resource in its `src` attribute. It is a resource request, not a request to execute JavaScript. See the [MDN image element reference](https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/img).

### Direct Image Request (Formerly "IMG Embedded Commands")

Consider an application that incorrectly lets a GET request perform a privileged action. If an attacker can place the following markup in content a user views, the browser may request the action URL:

```html
<img src="https://app.example.test/admin/remove-user?id=42" alt="">
```

This is an **illustrative, nonfunctional URL**. The vulnerability would be in the server's handling of a state-changing GET request, not in the image element itself. Whether the operation succeeds depends on authentication, authorization, cookie delivery, and CSRF defenses. Image loading does not grant the attacker the ability to read the response.

### Redirected Image Request (Formerly "IMG Embedded Commands part II")

An image URL might first point to another host, which responds with an HTTP redirect:

```html
<img src="https://media.example.test/pixel" alt="">
```

```http
HTTP/1.1 302 Found
Location: https://app.example.test/admin/remove-user?id=42
```

A browser may follow the redirect and request the destination. If that destination performs a privileged operation using GET, the same class of problem can arise. A redirect does **not** automatically bypass browser cookie restrictions or the target application's security controls. Under [RFC 9110, Section 15.4.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4.3), `302 Found` is a redirect response. In contrast, [`304 Not Modified`](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4.5) is for conditional cache validation, **not** a redirect to an attacker-selected URI.

## Browser and Session Constraints

The presence of an image request alone does not establish a successful CSRF attack. In particular, [MDN's SameSite cookie documentation](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie#samesitesamesite-value) explains that `SameSite=Lax` generally excludes cookies from cross-site subresource requests such as images. Browser restrictions on third-party cookies may impose additional limits.

- Check whether the request is **same-site** or **cross-site**; these are not the same as same-origin and cross-origin.
- Check whether the browser sends the credentials required by the destination.
- Check whether the endpoint changes state on GET and whether the server enforces authorization and CSRF protections.
- Do not assume an HTTP redirect changes the request into an authorized action or makes session cookies available.

## Defensive Design and Review

The [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html) provides the full defense guidance. For this specific attack pattern:

- **Never use GET to perform a state-changing operation.** [RFC 9110, Section 9.2.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.2.1) requires resources to disallow unsafe actions when accessed by safe methods.
- Use an appropriate state-changing HTTP method and a framework-supported CSRF defense; verify authorization on every sensitive operation.
- Treat `SameSite` cookies and Fetch Metadata checks as useful controls within their documented limits, not substitutes for correct endpoint semantics.
- Test both direct resource requests and redirect chains. A GET endpoint must remain harmless even when a browser, crawler, or embedded resource follows its URL.

## References

- [OWASP: Cross-Site Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [IETF: RFC 9110, HTTP Semantics](https://www.rfc-editor.org/rfc/rfc9110.html)
- [MDN: Set-Cookie and SameSite](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie)
