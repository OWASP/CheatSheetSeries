# DotNet Security Cheat Sheet

## Introduction

This cheat sheet focuses on security decisions for modern .NET and ASP.NET Core. Guidance for existing .NET Framework applications is separated at the end.

Keep the runtime and packages supported and patched. Follow the [.NET security announcements](https://github.com/dotnet/announcements/issues?q=is%3Aopen+is%3Aissue+label%3ASecurity), which include ASP.NET Core advisories.

## Authentication and authorization

Use [ASP.NET Core Identity](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/identity?view=aspnetcore-10.0) or a supported identity provider integration. Do not implement password recovery or session management from scratch.

### Account protection

- Use a store that supports lockout and enable it for the affected users (`LockoutEnabled`). Configure `IdentityOptions.Lockout` and pass `lockoutOnFailure: true` to `PasswordSignInAsync` so failed password attempts count toward lockout. See [Identity lockout configuration](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/identity-configuration?view=aspnetcore-10.0#lockout).
- Apply [login throttling](Authentication_Cheat_Sheet.md#login-throttling) and [multifactor authentication](Multifactor_Authentication_Cheat_Sheet.md). Protect registration and password recovery too; login lockout does not cover those flows.
- Return consistent [authentication responses](Authentication_Cheat_Sheet.md#authentication-responses), including comparable timing, so login, registration, and recovery do not disclose whether an account exists.

### Passwords

- Use Identity's [`PasswordHasher<TUser>`](https://learn.microsoft.com/en-us/aspnet/core/security/data-protection/consumer-apis/password-hashing?view=aspnetcore-10.0); do not call `KeyDerivation.Pbkdf2` directly to store passwords.
- Configure [`PasswordHasherOptions.IterationCount`](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/identity-configuration?view=aspnetcore-10.0#password-hasher-options) for the hash algorithm used by your Identity version to meet the [Password Storage Cheat Sheet's PBKDF2 guidance](Password_Storage_Cheat_Sheet.md#pbkdf2). Benchmark the work factor on the deployment hardware; do not assume the framework default meets current guidance.
- Set `IdentityOptions.Password.RequiredLength` according to the [password strength guidance](Authentication_Cheat_Sheet.md#implement-proper-password-strength-controls). Disable the `RequireDigit`, `RequireLowercase`, `RequireUppercase`, and `RequireNonAlphanumeric` composition rules. Update scaffolded registration and password-reset validation to match; see [Identity password configuration](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/identity-configuration?view=aspnetcore-10.0#password). Also screen for common and breached passwords; length and composition settings do not provide that check.

### Authentication cookies

Configure Identity's application cookie through [`ConfigureApplicationCookie`](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/identity-configuration?view=aspnetcore-10.0):

- Set `Cookie.HttpOnly = true` and `Cookie.SecurePolicy = CookieSecurePolicy.Always`. Choose `Cookie.SameSite` to fit the authentication flow; test federated sign-in before tightening it. `HttpOnly` prevents script access to the cookie, but does not stop injected scripts from making authenticated requests.
- Set an appropriate `ExpireTimeSpan`. With `SlidingExpiration = true`, activity renews the authentication ticket; it is not an absolute session limit. See [cookie authentication options](https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.authentication.cookies.cookieauthenticationoptions) and [session expiration](Session_Management_Cheat_Sheet.md#automatic-session-expiration).
- Ensure security-sensitive changes update the user's security stamp, calling `UserManager.UpdateSecurityStampAsync(user)` when the operation does not already do so. Keep Identity's [security stamp validation](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/identity-configuration?view=aspnetcore-10.0#isecuritystampvalidator-and-signout-everywhere) enabled. Existing cookies are rejected at the next stamp validation, subject to `SecurityStampValidatorOptions.ValidationInterval`; revocation is not necessarily immediate.

### Authorization

Prefer a [fallback policy requiring authentication](https://learn.microsoft.com/en-us/aspnet/core/security/authorization/policies?view=aspnetcore-10.0#require-global-user-authentication), and mark intentionally public endpoints with `[AllowAnonymous]` or `AllowAnonymous()`. It covers only requests that reach the authorization middleware; static files served earlier are not protected by it.

Authentication alone does not grant permission. Apply role or named-policy requirements, such as `[Authorize(Policy = "...")]` or `RequireAuthorization("...")`, to privileged operations. Named policies do not inherit the fallback policy; include the authentication requirement.

For object-specific permissions, use [`IAuthorizationService.AuthorizeAsync`](https://learn.microsoft.com/en-us/aspnet/core/security/authorization/resource-based?view=aspnetcore-10.0) with the resource and requested operation before returning or changing it. Neither the fallback policy nor an `[Authorize]` attribute alone performs this resource check. See [Authorization](Authorization_Cheat_Sheet.md) and [Insecure Direct Object Reference Prevention](Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.md).

### Redirects

For local return URLs, use [`LocalRedirect` or check `Url.IsLocalUrl`](https://learn.microsoft.com/en-us/aspnet/core/security/preventing-open-redirects?view=aspnetcore-10.0) before redirecting. If external destinations are required, select them from a server-controlled allowlist; see [Unvalidated Redirects and Forwards](Unvalidated_Redirects_and_Forwards_Cheat_Sheet.md#preventing-unvalidated-redirects-and-forwards).

## Input handling

### SQL injection

- Prefer Entity Framework LINQ queries. For SQL text, use the [parameterized API supported by your EF Core version](https://learn.microsoft.com/en-us/ef/core/querying/sql-queries#passing-parameters), such as `FromSql` or `FromSqlInterpolated`. Never concatenate untrusted values into SQL text passed to `FromSqlRaw` or other command APIs.
- Parameters represent values, not table or column names. Map any dynamic identifier to a fixed allowlist. Parameterization does not replace authorization or a database account with minimal privileges.
- See [Query Parameterization](Query_Parameterization_Cheat_Sheet.md) and [Database Security](Database_Security_Cheat_Sheet.md) for examples and database access controls.

### OS command injection

See the [.NET guidance in the OS Command Injection Defense Cheat Sheet](OS_Command_Injection_Defense_Cheat_Sheet.md#net).

### Cross-site request forgery

When the browser sends credentials automatically, including cookies and Windows, Basic, or Digest authentication, protect state-changing operations with [ASP.NET Core antiforgery validation](https://learn.microsoft.com/en-us/aspnet/core/security/anti-request-forgery?view=aspnetcore-10.0). Do not change state in GET requests.

- In MVC applications, register `AutoValidateAntiforgeryTokenAttribute` globally for unsafe HTTP methods. Razor Pages provide antiforgery protection by default. These MVC filters are not a substitute for the antiforgery configuration required by other endpoint types.
- Pair token generation with server-side validation. For forms not covered by automatic token generation, use `@Html.AntiForgeryToken()` explicitly. JavaScript requests must send the request token in the configured header or form field, along with the antiforgery cookie.
- Do not add `IgnoreAntiforgeryToken` merely to make a failing request succeed. Verify how the endpoint authenticates requests and why CSRF protection is unnecessary before excluding it.

See [Cross-Site Request Forgery Prevention](Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md) for the threat model and controls beyond framework configuration.

### Cross-site scripting (XSS)

Razor [encodes ordinary variable output in HTML contexts](https://learn.microsoft.com/en-us/aspnet/core/security/cross-site-scripting?view=aspnetcore-10.0). Do not bypass it with `Html.Raw` or `HtmlString` for untrusted content. HTML encoding does not make a value safe inside JavaScript, CSS, or a URL; follow the context-specific guidance in [Cross-Site Scripting Prevention](Cross_Site_Scripting_Prevention_Cheat_Sheet.md).

Input validation is not a replacement for output encoding. If users must submit HTML, sanitize it with a maintained HTML sanitizer. Use [Content Security Policy](Content_Security_Policy_Cheat_Sheet.md) as an additional defense.

### Serialization and XML

- Do not use [`BinaryFormatter`](https://learn.microsoft.com/en-us/dotnet/standard/serialization/binaryformatter-security-guide); it cannot be made secure. Prefer a data-only format such as JSON with `System.Text.Json`, and deserialize into application-defined types. Validate the resulting values before use.
- Review serializer-specific risks in the [.NET deserialization guidance](Deserialization_Cheat_Sheet.md#net-csharp). A different serializer does not remove the need to validate data or constrain custom converters and type selection.
- For XML, disable unnecessary external resource resolution and follow the [settings for your .NET parser](XML_External_Entity_Prevention_Cheat_Sheet.md#net). Defaults differ by API and framework version.

## Data protection

### Encryption for storage

- For Windows-local secrets, [`ProtectedData` uses the Windows Data Protection API (DPAPI)](https://learn.microsoft.com/en-us/dotnet/standard/security/how-to-use-data-protection). Choose the scope deliberately: user scope binds decryption to that account, while machine scope permits other accounts on that computer to decrypt. This does not protect against code running with the decrypting account's privileges.
- Protect ASP.NET Core's Data Protection keys as well as the data they protect. When [overriding key persistence](https://learn.microsoft.com/en-us/aspnet/core/security/data-protection/implementation/key-storage-providers?view=aspnetcore-10.0), configure encryption at rest explicitly and restrict access to the key repository.
- For other stored data, follow [Cryptographic Storage](Cryptographic_Storage_Cheat_Sheet.md). If using `AesGcm` directly, use the [constructor with an explicit tag size](https://learn.microsoft.com/en-us/dotnet/fundamentals/syslib-diagnostics/syslib0053) and [never reuse a nonce with the same key](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.aesgcm.encrypt?view=net-10.0).

### Encryption for transmission

Use TLS, not a custom key-exchange protocol. For browser applications, configure [`UseHttpsRedirection` and `UseHsts`](https://learn.microsoft.com/en-us/aspnet/core/security/enforcing-ssl), or enforce them at the reverse proxy. APIs should reject insecure HTTP requests; a redirect cannot undo disclosure in the original request. See [Transport Layer Security](Transport_Layer_Security_Cheat_Sheet.md).

## Configuration and deployment

- Keep secrets out of source code and checked-in configuration. Use [User Secrets](https://learn.microsoft.com/en-us/aspnet/core/security/app-secrets) only for development; it is not encrypted storage. Obtain production credentials from a managed secret store. Follow [Secrets Management](Secrets_Management_Cheat_Sheet.md).
- Run production applications outside the `Development` environment. Use [exception handling middleware](https://learn.microsoft.com/en-us/aspnet/core/fundamentals/error-handling?view=aspnetcore-10.0) and return generic errors; keep stack traces, credentials, and request details out of responses.
- Apply [HTTP security headers](HTTP_Headers_Cheat_Sheet.md) in the application or reverse proxy, with one place responsible for each policy. Avoid copying a generic header configuration without testing the application's requirements.
- Use operating-system permissions and isolation for untrusted components. [Code Access Security and partial trust are not supported security boundaries](https://learn.microsoft.com/en-us/dotnet/standard/security/secure-coding-guidelines).

## Legacy .NET Framework

For secrets, .NET Framework 4.7.1 and later can use [Configuration Builders](https://learn.microsoft.com/en-us/aspnet/config-builder) to load values from external sources instead of embedding them in `web.config`.

### ASP.NET MVC and Web Forms

- In MVC, generate tokens with `@Html.AntiForgeryToken()` and validate them with `[ValidateAntiForgeryToken]` on state-changing actions. For AJAX, follow [Microsoft's Framework antiforgery guidance](https://learn.microsoft.com/en-us/aspnet/web-api/overview/security/preventing-cross-site-request-forgery-csrf-attacks#anti-csrf-and-ajax).
- In Web Forms, set [`ViewStateUserKey`](https://learn.microsoft.com/en-us/dotnet/fundamentals/code-analysis/quality-rules/ca5368) during `Page_Init` or `OnInit` to an unpredictable value unique to the session. This helps protect ViewState postbacks; endpoints that do not validate ViewState still need CSRF protection.
- Keep production debugging and tracing disabled and configure custom error responses. Use context-appropriate output encoding; request validation alone does not prevent XSS. See [ASP.NET request validation](https://learn.microsoft.com/en-us/aspnet/whitepapers/request-validation).

### Forms authentication

In [Forms Authentication settings](https://learn.microsoft.com/en-us/dotnet/api/system.web.configuration.formsauthenticationconfiguration?view=netframework-4.8.1), set `cookieless="UseCookies"`, `requireSSL="true"`, and an appropriate `timeout`. This keeps authentication tickets out of URLs and restricts their cookies to HTTPS.

### Windows Communication Foundation (WCF)

Choose a binding and security mode that provide the required confidentiality and authentication. [WCF bindings and security](https://learn.microsoft.com/en-us/dotnet/framework/wcf/feature-details/bindings-and-security) documents their differences: `BasicHttpBinding` is unsecured by default but supports HTTPS when configured; `TransportWithMessageCredential` combines transport protection with message credentials. Do not assume a binding name or HTTP method alone secures a service.

## References

- [Microsoft: Secure coding guidelines for .NET](https://learn.microsoft.com/en-us/dotnet/standard/security/secure-coding-guidelines)
- [Microsoft: Configure ASP.NET Core Identity](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/identity-configuration?view=aspnetcore-10.0)
- [Microsoft: Prevent cross-site request forgery in ASP.NET Core](https://learn.microsoft.com/en-us/aspnet/core/security/anti-request-forgery?view=aspnetcore-10.0)
