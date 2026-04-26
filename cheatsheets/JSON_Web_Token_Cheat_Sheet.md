# JSON Web Token Cheat Sheet

## Introduction

JSON Web Tokens (JWT, [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519)) are a compact, URL-safe means of representing claims to be transferred between two parties. They are widely used as bearer tokens in authentication and authorization flows — including as OIDC ID tokens and OAuth 2.0 access tokens.

A JWT consists of three Base64URL-encoded sections separated by dots:

`[Base64URL(HEADER)].[Base64URL(PAYLOAD)].[Base64URL(SIGNATURE)]`

**Header** — identifies the token type and signing algorithm:

```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

**Payload** — contains claims (statements about the subject and metadata):

```json
{
  "sub": "1234567890",
  "name": "John Doe",
  "role": "admin",
  "exp": 1716239022
}
```

**Signature** — ensures the token has not been tampered with (e.g., `HMACSHA256(base64url(header) + "." + base64url(payload), secret)`).

> **When not to use JWTs:** JWTs are stateless by design — once issued they are valid until expiry. Applications that require immediate session revocation on logout (e.g., banking, healthcare) may find traditional server-side sessions simpler. See the [Session Management Cheat Sheet](Session_Management_Cheat_Sheet.md).

## Security Vulnerabilities and Mitigations

### 1. Algorithm Confusion (`alg: none` and RS256 → HS256)

**Risk:** Attackers may manipulate the `alg` header to bypass signature verification.

- **`alg: none`** — Some libraries accepted tokens with algorithm set to `none`, treating them as already-verified. An attacker can strip the signature entirely and forge any claims.
- **RS256 → HS256 confusion** — If a server uses RS256 (asymmetric), an attacker can change `alg` to HS256 and re-sign the token using the **public key** as the HMAC secret, which the server may inadvertently accept.

**Mitigations:**

- Always explicitly specify and enforce the **expected algorithm** in your validation code — never derive it from the token header alone.
- Use an **allowlist** of accepted algorithms; reject anything not on it, especially `none`.
- Use an up-to-date, well-maintained JWT library and check it is not vulnerable to these issues (see [jwt.io/libraries](https://jwt.io/libraries)).

### 2. Weak Signing Secrets

**Risk:** HMAC-based tokens (HS256/384/512) are only as secure as their signing secret. An attacker who obtains a valid JWT can perform an offline brute-force attack using tools such as [Hashcat](https://hashcat.net/) or [John the Ripper](https://github.com/openwall/john) to recover the secret, then forge arbitrary tokens.

**Mitigations:**

- Use a **secret of at least 64 random characters** (256+ bits of entropy) — never use a human-memorable passphrase.
- Generate the secret with a [cryptographically secure random number generator](Cryptographic_Storage_Cheat_Sheet.md#secure-random-number-generation).
- Prefer **asymmetric algorithms** (RS256, ES256, PS256) so the signing key is never shared or exposed.
- Rotate secrets/keys periodically and after any suspected compromise.

### 3. Missing or Insufficient Claims Validation

**Risk:** Failing to validate standard claims allows attackers to replay expired tokens, use tokens issued for different audiences or issuers, or use tokens before they are valid.

**Mitigations:** Always validate the following claims on every request:

| Claim | Meaning | Validation |
| ------- | --------- | ---------- |
| `exp` | Expiration time | Reject tokens past this time |
| `nbf` | Not before | Reject tokens before this time |
| `iat` | Issued at | Optionally enforce a max token age |
| `iss` | Issuer | Must match the expected issuer |
| `aud` | Audience | Must match your service's identifier |
| `sub` | Subject | Must correspond to a valid, active user |

Use short **expiration times** — 15 minutes is common for access tokens. Issue a separate, longer-lived refresh token to obtain new access tokens.

### 4. Sensitive Data in Payload

**Risk:** JWT payloads are Base64URL-encoded, **not encrypted**. Anyone who intercepts or decodes a token can read the payload. Embedding PII, passwords, or internal implementation details exposes sensitive information.

**Mitigations:**

- Store only the **minimum necessary claims** (e.g., user ID, roles, expiry).
- Never store passwords, secrets, or sensitive PII in JWT payload.
- If payload confidentiality is required, use **JSON Web Encryption (JWE, [RFC 7516](https://datatracker.ietf.org/doc/html/rfc7516))** which encrypts the payload, or encrypt sensitive fields before embedding them. Use an authenticated encryption algorithm such as AES-GCM to prevent padding oracle and other cryptanalysis attacks.
- Always transmit tokens over **TLS/HTTPS**.

### 5. Insecure Token Storage (Client Side)

**Risk:** Where and how a JWT is stored in the browser determines the attack surface:

- **`localStorage`** — Persists across sessions and tabs; accessible to any JavaScript on the page, making it vulnerable to [XSS](Cross_Site_Scripting_Prevention_Cheat_Sheet.md) attacks.
- **`sessionStorage`** — Cleared when the tab is closed; still accessible to JavaScript on the page.
- **Accessible cookies** — If not hardened, vulnerable to [CSRF](Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md) and XSS.

**Mitigations:**

- Store access tokens in **memory (JavaScript variable/closure)** where possible; they disappear on page reload, limiting exposure.
- If persistence is needed, use `sessionStorage` with a **short-lived token** and refresh-token rotation.
- If storing in a cookie, use `HttpOnly; Secure; SameSite=Strict` flags and implement CSRF protection.
- Implement a strict [Content Security Policy](Content_Security_Policy_Cheat_Sheet.md) to reduce the XSS attack surface.
- Apply a **token fingerprint** (see [Token Sidejacking](#6-token-sidejacking)) to limit the usefulness of stolen tokens.

### 6. Token Sidejacking

**Risk:** If a token is stolen (via XSS, network interception, or log exposure), an attacker can use it from their own machine until it expires.

**Mitigation — Token Fingerprinting:**

1. At authentication time, generate a cryptographically random string (the "fingerprint").
2. Send the raw fingerprint to the client as a hardened cookie: `HttpOnly; Secure; SameSite=Strict` with `Max-Age` equal to or less than the token expiry.
3. Store a **SHA-256 hash** of the fingerprint (not the raw value) as a claim inside the JWT.
4. On every request, re-hash the cookie value and compare it to the claim in the token. Reject the token if they do not match.

This means an attacker who steals only the JWT (e.g., via XSS reading `sessionStorage`) cannot use it without also stealing the hardened cookie — which XSS cannot access. Avoid using IP addresses as context; they can change legitimately (mobile networks, VPNs) and raise GDPR concerns.

### 7. Lack of Token Revocation

**Risk:** JWTs are stateless — they remain valid until they expire even after logout or account compromise, because the server holds no session state to invalidate.

**Mitigations:**

- Use **short expiration times** for access tokens (e.g., 15 minutes) to limit the window of exposure.
- Implement a **token denylist** (blocklist): on logout or compromise, store a hash (e.g., SHA-256) of the token `jti` claim (JWT ID) in a fast data store (Redis, database) with a TTL equal to the token's remaining lifetime. Reject any token whose hash is in the denylist.
- Pair access tokens with **refresh tokens** — refresh tokens can be revoked server-side and used to issue new short-lived access tokens.
- Use the Token Fingerprinting approach described in [Token Sidejacking](#6-token-sidejacking) — clearing the fingerprint cookie on logout effectively invalidates the token without server-side state.

### 8. Header Injection (`kid`, `jku`, `x5u`)

**Risk:** Certain JWT header parameters can be abused to redirect signature verification to an attacker-controlled key or endpoint:

- **`kid` (Key ID) injection** — If the `kid` value is used unsanitized in a database query or filesystem path, an attacker can craft a `kid` to exploit SQL injection or path traversal, causing the server to verify the signature with an attacker-chosen key.
- **`jku` / `x5u` (JWK Set URL / X.509 URL) injection** — If the library fetches the verification key from a URL specified in the header, an attacker can point it to a server they control.

**Mitigations:**

- **Never trust header parameters** for key selection without strict validation.
- Use a **static allowlist** of valid key IDs and ignore any `kid` value not on it.
- **Disable or ignore** `jku` and `x5u` unless your use case explicitly requires them; if used, enforce a strict allowlist of trusted URLs.
- Sanitize all `kid` values before using them in queries or file lookups.

## Best Practices Summary

- **Use a reputable, actively-maintained JWT library** for your language/framework. Check [jwt.io/libraries](https://jwt.io/libraries) and the library's CVE history.
- **Prefer asymmetric algorithms** (RS256, ES256, PS256) over symmetric (HS256) when tokens are validated by services other than the one that issued them.
- **Set short expiration times** on access tokens and use refresh tokens for session continuity.
- **Validate all relevant claims** (`exp`, `nbf`, `iss`, `aud`, `sub`) on every request.
- **Never put sensitive data** (passwords, PII, internal secrets) in the payload.
- **Transmit tokens only over HTTPS/TLS**.
- **Rotate signing keys** regularly and provide a JWKS endpoint for public-key distribution.
- **Include a `jti` claim** (unique token ID) to support revocation and replay detection.

## References

- [RFC 7519 — JSON Web Token](https://datatracker.ietf.org/doc/html/rfc7519)
- [RFC 7515 — JSON Web Signature](https://datatracker.ietf.org/doc/html/rfc7515)
- [RFC 7516 — JSON Web Encryption](https://datatracker.ietf.org/doc/html/rfc7516)
- [RFC 8725 — JWT Best Current Practices](https://datatracker.ietf.org/doc/html/rfc8725)
- [OWASP Top 10 — Broken Authentication](https://owasp.org/www-project-top-ten/)
- [PortSwigger Web Academy — JWT Attacks](https://portswigger.net/web-security/jwt)
- [{JWT}.{Attack}.Playbook](https://github.com/ticarpi/jwt_tool/wiki) — Documents known JWT attacks and misconfigurations
- [Critical vulnerabilities in JSON Web Token libraries (Auth0 blog)](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/)
- [jwt.io — JWT Debugger and Library Directory](https://jwt.io/)
