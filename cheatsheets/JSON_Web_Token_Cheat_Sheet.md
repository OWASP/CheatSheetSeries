# JSON Web Token Cheat Sheet

## Introduction

This cheat sheet provides tips to prevent common security issues when using JSON Web Tokens (JWT).

[**JSON Web Tokens**](https://datatracker.ietf.org/doc/html/rfc7519) (JWT) are security tokens for carrying information (**claims**), often about a user, an application, etc. (**subject**). JWTs can provide authenticity of the claims (**signed JWT**) and/or confidentiality of the claims (**encrypted JWT**). In addition, JWT defines [standard claims](https://www.iana.org/assignments/jwt/jwt.xhtml).

JWTs are used in a wide range of applications such as:

- In [OpenID Connect](https://openid.net/specs/openid-connect-core-1_0.html), the [ID token](https://openid.net/specs/openid-connect-core-1_0.html#IDToken) is a JWT used to represent the identity and attributes of the connected user.
- In [OAuth 2](https://datatracker.ietf.org/doc/html/rfc6749), the access token used to obtain access to a protected resource [can be a JWT](https://datatracker.ietf.org/doc/html/rfc9068).
- A JWT is often suggested for “stateless” user sessions. However, this usage is [frowned upon](http://cryto.net/~joepie91/blog/2016/06/13/stop-using-jwt-for-sessions/).
- A [DPoP Proof JWT](https://datatracker.ietf.org/doc/html/rfc9449#name-dpop-proof-jwts) can be used to prove possession of a private key.
- In [SPIFFE](https://spiffe.io/), a [JWT-SVID](https://github.com/spiffe/spiffe/blob/main/standards/JWT-SVID.md) can be used to authenticate a workload.

In its most common form (signed JWT), this information is protected by the generating application (**issuer**) using a signature to ensure it has not been tampered with. This signature prevents attackers, such as a malicious client or user, from forging a token or modifying the claims in an existing token, for example changing the user role from a simple user to an admin or altering the client's login. The JWT can be seen as a protected identity card or certificate about a user, an application, etc. An application (**presenter**) presents the token to a consuming application (**audience**) which can verify the token's authenticity and validity and take decisions or actions based on these claims.

JWT can also provide confidentiality of the claims (encrypted JWT). Encryption is currently not treated in this cheat sheet but many aspects of this cheat sheet are applicable to encrypted JWTs.

## Token Structure

Signed JWTs have the following structure:

```
{base64url(json(header))}.{base64url(json(claims))}.{base64url(signature)}
```

The following elements are present in signed JWTs:

- **Protected Header:** the JWT header contains some information about the token such as the type of token (IANA media type) and the cryptographic algorithms used to protect the token.
- **Claims:** the content JWT is a list of claims (usually about the subject). See the [JWT IANA Registry](https://www.iana.org/assignments/jwt/jwt.xhtml) for a list of standard claims.
- **Signature:** a signature in JWT is either a public-key digital signature (using a public/private key pair) or a MAC (using a shared secret). The signature protects both the protected headers and the claims.

### Example

For example, the following example ([taken from JWT.IO](https://jwt.io/#token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30)):

```text
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30
```

The first part ([**protected header**](https://datatracker.ietf.org/doc/html/rfc7515#section-4)) can be decoded into:

```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

The second part ([**claims**](https://datatracker.ietf.org/doc/html/rfc7519#section-4)) can be decoded into:

```json
{
  "sub": "1234567890",
  "name": "John Doe",
  "admin": true,
  "iat": 1516239022
}
```

The last part (**signature**) guarantees the authenticity of both the header and the claims, either using a public/private key pair (digital signature) or a shared secret (MAC), depending on the `alg` header value. For our example, it is computed as:

```javascript
base64url(
    HMACSHA256(
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        + "."
        + "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
        key
    )
)
```

## Considerations about using JWTs

### Not using JWTs

Before using JWTs to solve your problems, you should consider if they are really necessary for your use case.

JWTs are often suggested for “stateless” user sessions. However, if you use JWTs for user sessions, you will need a solution for managing session invalidation. This can be achieved using a deny list of revoked sessions/tokens. If your application implements such a deny list, user sessions won't be completely stateless anymore which might defeat the benefits of stateless sessions. You might want to consider using a plain session system and follow the advices from the dedicated [session management cheat sheet](Session_Management_Cheat_Sheet.md).

### Public-key Signatures vs. MAC

A signed JWT can be authenticated using either a digital signature or a MAC:

- **When using a digital signature,** the issuer of the token uses its private key to generate a signature. The audience of the token can use the associated public key to verify the authenticity of the token. Whereas the private key must only be known by the issuer, the public key can be public.
- **When using a MAC,** a shared secret is shared between the issuer and the audience. The *same* shared secret is used by the issuer to generate the token and by the audience to verify the authenticity of the token.

The two approaches differ on how credentials are managed.

When using a digital signature:

- The issuer can reuse the same public key for many different audiences.
- The audience of the token only need public information to validate the token authenticity which removes the risk of secret leakage by the audience.
- Because the public key does not need to be secret, it can easily be distributed (eg. by publishing it at a public HTTPS URI).
- This makes key rotation simpler as well.
- Traditional digital signature schemes might be [broken by post quantum computers](https://datatracker.ietf.org/doc/html/rfc9958#name-asymmetric-cryptography) in the future. They would need to be replaced with post-quantum digital signature schemes which [heavier](https://datatracker.ietf.org/doc/html/rfc9958#name-impact-on-constrained-devic) are traditional signature schemes.

When using a MAC:

- A different secret must be used for each (issuer, audience) pair. If, for example, the same secret is reused for difference audiences, one audience can forge a token (impersonating the issuer).
- Secret keys must obviously not be published at a public HTTPS URI. Some solution for secret distribution and rotation must be found.
- MAC are much faster than digital signatures (but this is usually negligible in practice).

Using a MAC may be interesting in the following cases:

- The issuer of the token is the sole audience of the token. Even in this case, it might be easier to use digital signature for secret rotation/distribution.
- The issuer of the token is the audience. In this case, there is no problem of secret rotation/distribution.

### Public-key Signatures

| Signature scheme      | Identifier                      | Type         | Status
|-----------------------|---------------------------------|--------------|---------
| EdDSA                 | EdDSA, Ed448, Ed25519           | Traditional  | Recommended, limited support
| ECDSA                 | ES256, ES384, ES512             | Traditional  | Recommended
| RSASSA-PSS            | PS256, PS384, PS512             | Traditional  | Recommended
| RSASSA-PKCS1-v1_5     | RS256, RS384, RS512             | Traditional  | Not recommended
| Hybrid ML-DSA / EdDSA | ML-DSA-44-Ed25519, etc.         | PQ/T hybrid  | [Draft](https://ietf-wg-jose.github.io/draft-ietf-jose-pq-composite-sigs/draft-ietf-jose-pq-composite-sigs.html)
| Hybrid ML-DSA / ECDSA | ML-DSA-44-ES256, etc.           | PQ/T hybrid  | [Draft](https://ietf-wg-jose.github.io/draft-ietf-jose-pq-composite-sigs/draft-ietf-jose-pq-composite-sigs.html)
| ML-DSA                | ML-DSA-44, ML-DSA-65, ML-DSA-87 | Post-quantum | Very limited support at best

Explanations:

- Support for EdDSA in JWT implementations is currently limited.
- Generating ECDSA signatures may be dangerous on embedded systems where the quality of the randomness may be problematic. In this case, you the implementation must use deterministic ECDA as defined in [RFC 6979](https://datatracker.ietf.org/doc/html/rfc6979).
- Post-quantum signatures ([ML-DSA](https://datatracker.ietf.org/doc/html/rfc9964)) or [hybrid post quantum signatures](https://ietf-wg-jose.github.io/draft-ietf-jose-pq-composite-sigs/draft-ietf-jose-pq-composite-sigs.html) are designed to be resistant against quantum computers. However, they produce very large signatures, resulting in very large JWTs. Their usage is probably not justified at the moment unless you need signatures with a long validity.

Key management:

- Do not reuse the key pair for another purpose (eg. for encryption).
- Using the same key for authenticating different types of JWTs is fine as long as this does not introduce a risk of token type confusion.
- Do not publish your private key!

#### MAC

| Signature scheme      | Identifier                      | Status
|-----------------------|---------------------------------|---------------
| HMAC with SHA-2       | HS256, HS384, HS512             | Recommended

Secret management:

- Do not reuse the same secret for another purpose (eg. for encryption).
- Using the same key for authenticating different types of JWTs is fine as long as this does not introduce a risk of token type confusion.
- Do not reuse the same secret with another audience.
- Do not reuse the same secret with another issuer.
- Do not use a password as MAC secret.
- The secret must be generated using a local, cryptographically secure secret generator.
- The secret must have at least the same size as the output (eg. 256, 384 and 512 bits respectively for HS256, HS384 and HS512).
- Do not publish your secret key!
- The secret must have at least 160 bits of entropy.
- For HMAC, the secret [should be at least as long as the output size](https://datatracker.ietf.org/doc/html/rfc2104#section-3).

Valid HMAC secret generation example:

```python
import secrets
secret_for_hs256 = secrets.token_bytes(256//8)
secret_for_hs512 = secrets.token_bytes(512//8)
```

Invalid HMAC secret generation:

```python
import random
import secrets

# Using a password/passphrase is not OK:
bad_secret = b"MyProject2026"

# Using a hardcoded secret is not OK:
bad_secret = urlsafe_b64decode(b'KYkbbclxtjJMiHzoPvuahOfarej0VV-nQZPFxK0hyro=')

# Not a secure randomness source:
bad_secret = random.randbytes(256//8)

# Not enough entropy:
bad_secret = secrets.token_bytes(128//8)

# Not enough entropy for HS512
meh_secret_for_hs512 = secrets.token_bytes(256//8)
```

## Threats on JWTs

See [RFC 8725](https://datatracker.ietf.org/doc/html/rfc8725#name-threats-and-vulnerabilities) for a discussion on threats and vulnerabilities related to JWT.

### Unsecured JWTs

Some JWT libraries, [used to accept unsecured JWTs by default](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/) (`"alg":"none"`). In this case, an attacker would be able to forge their own JWTs: depending on the application, they might be able to impersonate arbitrary users, obtains arbitrary authorizations, etc.

This issue should now be fixed in JWT libraries.

Mitigation:

- Make sure that `"alg":"none"` is not accepted by your JWT parser. It should be disabled by default by recent implementations.

## JWT revocation

### Token Status List

If revocation of the JWTs by the issuer is needed, the [Token Status Lists](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list) (TSL) can be used:

- the JWT contains the URI of a TSL;
- the TSL aggregates the revocation status of several tokens in compressed form;
- the consumer of the token can fetch the TSL to obtain the revocation status of the JWT.

The issuer includes a `status` claim in the JWT. This claims contains the URI of the associated TSL and the index of the status of the JWT within this list:

```json
{
    "iss": "https://issuer.example/",
    "sub": "NsxuACbpJ9N7Ix96aWrYxHX-EZ4",
    "iat": 1783635268,
    "nbf": 1783635268,
    "exp": 1783653268,
    "status": {
        "status_list": {
            "idx": 6,
            "uri": "https://issuer.example/tsl/JAffke55FR5gtJQ_rtktWkSaTlI"
        }
    }
}
```

## Replay protection

### JWT denylist

In some cases, the consumer of the token might want to maintain a JWT denylist. This might be for example used a simple form of JWT replay protection or as a workaround for the “stateless session” invalidation problem.

A JWT deny list can typically be implemented based on the  `jti` and `iss` claims:

```python
def revoke_token(claims):
    jti = claims.get("jti")
    iss = claims.get("iss")
    exp = claims.get("exp")
    deny_list.insert((jti, iss), exp)

def is_token_revoked(claims) -> bool:
    jti = claims.get("jti")
    iss = claims.get("iss")
    return deny_list.contains((jti, iss))
```

Depending on the application and the type of JWT, other claims might be more suitable.

**Warning:** Using the raw JWT or a secure hash of the JWT (`SHA-256(token)`) as the denylist key is *not safe* and might expose the application to **denylist bypass through [JWT malleability](https://www.gabriel.urdhr.fr/2026/06/27/ecdsa-jwt-malleability/)**. An attacker in possession of a revoked JWT might be able to modify an alternative representation of the JWT that still passes signature verification:

- because of non-strict JWT parsing of the JWT implementation;
- for ECDSA JWTs, because of the malleability of ECDSA signatures.

```python
# Not secure. Might be vulnerable to JWT malleability:
def unsafe_revoke_token(claims):
    exp = claims.get("exp")
    token_hash = hashlib.sha256(token.encode("utf-8")).digest()
    deny_list.insert(token_hash, exp)
```

Before implementing such a JWT denylist, you should consider whether there is a better solution for your problem:

- Token Status List is a scalable solution for revocation of the JWT by the issuer.
- Freshness and replay protection can often by implementing by using a `nonce` bound to the session in the JWT claims. This approach is [used in OpenID Connect](https://openid.net/specs/openid-connect-core-1_0.html#NonceNotes).
- Token reuse can be mitigated by using short expiration time in the JWT.
- The risk of token exfiltration can be mitigated by using sender constrained JWT (such a [DPoP](https://datatracker.ietf.org/doc/html/rfc9449) or [TLS-bound JWT](https://www.rfc-editor.org/info/rfc8705/#section-3)).

## References

Main JWT and JOSE specifications:

- [RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515), JSON Web Signature (JWS)
- [RFC 7516](https://datatracker.ietf.org/doc/html/rfc7516), JSON Web Encryption (JWE)
- [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517), JSON Web Key (JWK)
- [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519), JSON Web Token (JWT)
- [RFC 8725](https://datatracker.ietf.org/doc/html/rfc8725), JWT Best Practices

Some applications of JWTs:

- [JWT Profile for OAuth 2.0 Access Tokens](https://datatracker.ietf.org/doc/html/rfc9068)

IANA registries:

- [JSON Object Signing and Encryption (JOSE) IANA Reguistry](https://www.iana.org/assignments/jose/jose.xhtml)
- [JSON Web Token IANA Reguistry (JWT)](https://www.iana.org/assignments/jwt/jwt.xhtml)

Attacks on JWT and JOSE:

- [{JWT}.{Attack}.Playbook](https://github.com/ticarpi/jwt_tool/wiki) - A project documents the known attacks and potential security vulnerabilities and misconfigurations of JSON Web Tokens.
- [JWT.io Discussion Forum](https://community.auth0.com/c/jwt/8) (Hosted by [Auth0](https://auth0.com/))

Other useful links:

- [JWT IANA Registry](https://www.iana.org/assignments/jwt/jwt.xhtml)
