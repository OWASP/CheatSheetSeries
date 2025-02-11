# JSON Web Encryption (JWE) Cheat Sheet

## 1. Introduction

JSON Web Encryption (JWE) is a standard for encrypting JSON-based tokens, ensuring the confidentiality of claims. It extends the JSON Web Token (JWT) specification by adding encryption capabilities, making it suitable for securely transmitting sensitive data.

---

## 2. Key Differences Between JWT and JWE

| **Feature**         | **JWT (JSON Web Token)**                             | **JWE (JSON Web Encryption)**                    |
|---------------------|------------------------------------------------------|--------------------------------------------------|
| **Purpose**         | Tokenized authentication and integrity verification  | Secure transmission of encrypted claims          |
| **Protection**      | Uses digital signatures for integrity (but payload is visible) | Encrypts payload to ensure confidentiality        |
| **Example Use Case**| Identity claims in OAuth                             | Protecting sensitive user data                   |

> **Note:** JWT ensures authenticity but does NOT encrypt data, while JWE provides full confidentiality.

### ***Using JWE-Only JWTs: Is It Secure?***

Some applications use JWTs only with JWE (encryption) without signing them using JWS. While this approach ensures confidentiality, it introduces potential risks:

**Problem:** Since there’s no digital signature (JWS), the recipient cannot verify the sender’s authenticity.

### Safe Usage Scenarios:-

- If the decryption key is tightly controlled and only trusted parties can encrypt messages.

- If the payload itself includes authentication mechanisms, such as an HMAC inside the encrypted content, to verify sender authenticity.

### When NOT to Use:-

- If integrity verification is required. Without a JWS, attackers might swap encrypted tokens without detection.

- If you rely on public-key encryption, ensure that only trusted issuers can create encrypted tokens.

### Best Practice:-

- Use JWE + JWS together if authenticity is critical.

- If using JWE-only, always validate key authenticity and encryption source.

---

## 3. JWE Structure

A JWE consists of five parts separated by dots (`.`)

```
 Header.EncryptedKey.IV.Ciphertext.AuthenticationTag 
```

| **Component**           | **Description**                                                                                   |
|-------------------------|---------------------------------------------------------------------------------------------------|
| **Header**              | Metadata including the encryption algorithm (`alg`) and the encryption method (`enc`).            |
| **Encrypted Key**       | The symmetric key (Content Encryption Key or CEK) encrypted using a public key (if key wrapping is used). |
| **IV (Initialization Vector)** | A cryptographically secure random value ensuring uniqueness for encryption.                      |
| **Ciphertext**          | The actual encrypted data (which includes the payload).                                           |
| **Authentication Tag**  | Provides integrity and authenticity (a result of AEAD encryption, e.g., AES-GCM).                  |

**Example JWE (abstract view):**

```eyJhbGciOiJSU0Et... . X4EJw... . 3K841... . Joaln... . 2AlJx...```
> **All parts are Base64URL-encoded.**

---

## 4. Choosing the Right Algorithm for JWE

### Symmetric vs. Asymmetric Encryption

- **Symmetric Encryption (e.g., AES-256-GCM):**

    - **Use Case:** Fast encryption for internal services where both sender and receiver share a secret.
    - **Advantages:** High performance; efficient for high-throughput systems
    - **Considerations:** Requires secure key distribution and rotation.

- **Asymmetric Encryption (e.g., RSA-OAEP, ECDH-ES):**

    - **Use Case:** Secure communication between different entities where a shared secret is not pre-established.
    - **Advantages:** Eliminates the key distribution problem; suitable for multi-party or external interactions.
    - **Considerations:** Computationally more expensive; ECDH-ES is generally faster and preferred for new implementations.  
        - **Note on ECDH-ES:** When using it with key wrapping (e.g., ECDH-ES+A128KW), this method is particularly useful for multi-recipient JWEs.
    - **Quantum Considerations:** ECDH-ES (like other ECC methods) might be vulnerable to quantum attacks in the future. Consider hybrid or post-quantum approaches if long-term security is a concern.
    - **RSA-OAEP:** May be used in legacy systems or where RSA keys are already in place.

- **PBES2 (Password-Based Encryption):**
    - **Use Case:** Only when a password-derived key is required.
    - **Recommendation:** Avoid for system-level encryption if strong keys are available.

**Final Recommendation:**

- Use **AES-256-GCM** for high-performance internal encryption when keys are securely managed.  
- Use **ECDH-ES (with key wrapping for multi-recipient scenarios)** or **RSA-OAEP** for external communications or when key distribution is challenging.

---

## 5. Secure Implementation Practices

### Best Practices for Secure JWE Usage

- **Algorithm & Header Validation:**
    - **Always validate** the `alg` and `enc` header values against expected values.  
    - **Reject tokens** where these values do not match the key you possess, preventing downgrade attacks or attacker-controlled header manipulation.

- **Input Validation:**
    - Validate and sanitize all inputs to prevent injection attacks.

- **Authenticated Encryption:**
    - Use **authenticated encryption** (e.g., AES-GCM or ChaCha20-Poly1305) which inherently provides integrity protection.
  
- **Key Management:**
    - **Rotate keys periodically** using a Key Management System (KMS).
    - **Do not reuse** AES nonces/IVs, Content Encryption Keys (CEKs), or ECDH ephemeral keys.
    - **Store keys** in secure hardware security modules (HSMs) or vaults.

- **Secure Storage:**
    - **Do NOT store JWEs in client-side storage** (localStorage, sessionStorage, IndexedDB).  
    - **Recommendation:** Use Secure, HttpOnly cookies to mitigate XSS risks and token theft.

- **Replay Attack Mitigation:**
    - **Implement nonce-based validation:** Ensure each token uses a unique nonce to prevent replay attacks.
    - **Set short expiration times** and enforce refresh policies to reduce the window of opportunity for replay.

- **Secure Transmission:**
    - Always transmit JWEs over **TLS 1.2+ or TLS 1.3** to protect against man-in-the-middle (MITM) attacks.

### Example: Secure JWE Key Management (JSON)

```json
{
  "kid": "key-1234",
  "alg": "RSA-OAEP",
  "enc": "A256GCM",
  "exp": 1700000000
}
```

---

## 6. Combining JWE with JWS (JWE + JWS)

While JWE provides encryption (confidentiality) and JWS provides signing (integrity and authenticity), there are cases where both should be used together.

- *When to Use:* If you need both confidentiality and verification of the sender’s identity.

- *How to Use:* First, sign the payload using JWS, then encrypt the signed JWS using JWE.

### Example:-

1. Create a JWS-signed JWT: jws = sign(payload, private_key)
2. Encrypt the JWS-signed JWT using JWE: jwe = encrypt(jws, recipient_public_key)
3. The recipient first decrypts the JWE and then verifies the JWS signature.

### Why?

Prevents message tampering since encryption alone does not guarantee authenticity.
Ensures confidentiality and integrity for sensitive data exchanges.

---

## 7. Hardening JWE Security

| **Threat**                  | **Mitigation Strategy**                                                    |
|-----------------------------|-----------------------------------------------------------------------------|
| **Key Leakage**             | Use Hardware Security Modules (HSMs) or KMS for key storage and management.  |
| **Replay Attacks**          | Implement nonce-based validation and use short-lived tokens.                |
| **Expired Tokens**          | Set short expiration times and enforce refresh policies.                    |
| **Man-in-the-Middle Attacks** | Always use TLS/SSL for transmission.                                        |
| **Algorithm Downgrade Attacks** | Validate `alg` and `enc` to ensure they match expected values.            |

---

## 8. Handling *apv* and *apu* Header Parameters in ECDH-based JWE

### Understanding apv and apu in ECDH-based JWE

When using ***ECDH-ES*** (Elliptic Curve Diffie-Hellman Ephemeral Static) key agreement for JWE, the following header parameters are important for secure key derivation:

### apv (Agreement Party Values)

- Ensures that only the intended recipient can derive the decryption key.

- It should be a Base64URL-encoded identifier that uniquely represents the recipient.

### apu (Agreement Party Keying Material)

- Strengthens key agreement security by adding recipient-related data.

- It helps mitigate key reuse attacks in multi-party encryption.

### Implementation Tip:-

- Always validate that apv and apu match expected values before decrypting.

- Example JWE Header with these parameters:

```json
{
  "alg": "ECDH-ES+A256KW",
  "enc": "A256GCM",
  "apu": "Base64URL-encoded-value",
  "apv": "Base64URL-encoded-identifier"
}
```

## 9. Implementation Examples

### JWE Implementation in Python (PyJWT & Cryptography)

**Encryption Examples:**

```python
import os, json, base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

def encrypt_jwe(payload, key):
    iv = os.urandom(12)  # Unique IV per encryption
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(iv, json.dumps(payload).encode(), None)
    # Return Base64URL-encoded values
    return {
        'iv': base64url_encode(iv),
        'ciphertext': base64url_encode(ciphertext)
    }

# Example usage
# key should be 32 bytes for AES-256-GCM
```

**Decryption Example:**

```python
import json, base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def base64url_decode(data: str) -> bytes:
    # Add required padding for decoding
    padding = '=' * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)

def decrypt_jwe(jwe, key):
    aesgcm = AESGCM(key)
    iv = base64url_decode(jwe['iv'])
    ciphertext = base64url_decode(jwe['ciphertext'])
    plaintext = aesgcm.decrypt(iv, ciphertext, None)
    return json.loads(plaintext.decode('utf-8'))
```

### JWE Implementation in Java (Nimbus JOSE+JWT)

**Encryption Example:**

```java
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.util.*;
import com.nimbusds.jwt.*;
import java.security.interfaces.*;

JWEHeader header = new JWEHeader(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM);
Payload payload = new Payload("Sensitive Data");
JWEObject jweObject = new JWEObject(header, payload);
RSAEncrypter encrypter = new RSAEncrypter((RSAPublicKey) publicKey);
jweObject.encrypt(encrypter);
String serializedJWE = jweObject.serialize();
System.out.println("Encrypted JWE: " + serializedJWE);
```

**Decryption Example:**

```java
try {
    JWEObject jweObject = JWEObject.parse(serializedJWE);
    RSADecrypter decrypter = new RSADecrypter((RSAPrivateKey) privateKey);
    jweObject.decrypt(decrypter);
    String decryptedPayload = jweObject.getPayload().toString();
    System.out.println("Decrypted Data: " + decryptedPayload);
} catch (Exception e) {
    System.err.println("Decryption failed: " + e.getMessage());
}
```

---

## 10. Common Use Cases of JWE

- Securing API communication (OAuth2, OpenID Connect)

- Protecting sensitive session data in web applications

- Inter-service encrypted communication in microservices

- Healthcare and financial data transmission

- End-to-end encryption for messaging apps

---

## 11. Common Pitfalls to Avoid

- **Using weak encryption algorithms:** Avoid AES-CBC and RSA1_5; use AES-GCM and RSA-OAEP-256 instead.

- **Storing sensitive data in unencrypted JWTs/JWEs:** Ensure encryption is applied.

- **Exposing private keys in client-side code:** Never embed private keys in frontend code.

- **Failing to validate JWE before decryption:** Always validate the alg and enc headers against expected values to prevent downgrade attacks.

- **Storing JWEs in client-side storage:** Even though JWEs are encrypted, storing them in localStorage or sessionStorage exposes them to theft and replay attacks. Use Secure, HttpOnly cookies instead.
- **Long-lived JWEs without Refresh Mechanisms:**  If a JWE remains valid for too long, an attacker can reuse a stolen token.
    - **Fix:** Always set short expiration times and implement refresh tokens to prevent session fixation attacks.

- **Compressing data before encryption:** Compression can leak information (CRIME/BREACH attacks).

### Example of a Bad Practice :-

```json
{
  "alg": "RSA-OAEP",
  "enc": "A128CBC-HS256"  // Weak encryption algorithm
}
```

**Fix :** AES-GCM for better Security.

## 12. JWE vs. PASETO

| **Feature**         | **JWE**                                            | **PASETO**                                         |
|---------------------|----------------------------------------------------|----------------------------------------------------|
| **Encryption**      | Yes                                                | Yes                                                |
| **Algorithm Flexibility** | High                                        | Limited                                            |
| **Simplicity**      | Moderate                                           | Higher                                             |
| **Security Focus**  | Configurable, depends on implementation            | Opinionated, secure by design                      |

**Final Recommendation:**

- Use **JWE** when you need flexibility and support for various algorithms.  
- Use **PASETO** for a simpler, opinionated approach that reduces algorithm confusion.  

---

## 13. Conclusion

JWE is a powerful extension of JWT that provides confidentiality, integrity, and security for sensitive data in JSON tokens. By using strong encryption algorithms, proper key management, and secure transmission practices, developers can ensure safe data exchanges in modern applications.

> **Final Note:**  
> Ensure that all header parameters (`alg`, `enc`) are validated by consumers to match the expected key. This prevents attackers from modifying these values and forcing weaker algorithms. Also, adopt best practices for key reuse, nonce generation, and secure storage to mitigate replay and MITM attacks.

**Use JWE when transmitting sensitive data, and use JWT when data confidentiality is not a requirement.**

---

## Additional References

- [RFC 7516 - JSON Web Encryption (JWE)](https://datatracker.ietf.org/doc/html/rfc7516)
