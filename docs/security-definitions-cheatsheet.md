# Security Definitions Cheat Sheet

# Encoding vs Escaping

- **Definition:**
    - **Encoding** transforms data into a specific format so it can be properly consumed.
    - **Escaping** adds special characters before certain characters to prevent interpretation as code.

- **Authoritative references:**
    - [OWASP: Input Validation][1]
    - [CNCF Security Glossary][2]
    - [NIST SP 800-53 Rev.5][3]

- **Why it matters in security:**
    - Proper encoding and escaping prevent injection attacks such as SQL, XSS, and command injection.

- **Common pitfalls & vulnerabilities:**
    - Confusing encoding with encryption.
    - Escaping input for one context but using it in another (HTML vs SQL).
    - Double encoding attacks.

- **Best practices:**
    - Encode output for the target context.
    - Use standard libraries for encoding/escaping.
    - Validate and sanitize input along with encoding/escaping.

- **Example snippet:**

```python
import html

user_input = "<script>alert('xss')</script>"
safe_output = html.escape(user_input)
print(safe_output)  # &lt;script&gt;alert('xss')&lt;/script&gt;
```

# Encryption vs Signature

- **Definition:**
    - **Encryption** keeps data confidential; only authorized parties can decrypt.
    - **Digital Signature** proves authenticity and integrity; verifies data was not altered.

- **Authoritative references:**
    - [OWASP Cryptography Cheat Sheet][4]
    - [NIST FIPS 186-5][5]
    - [CNCF Security Glossary][2]

- **Why it matters in security:**
    - Encryption protects sensitive data from unauthorized access.
    - Signatures ensure data authenticity and prevent tampering.

- **Common pitfalls & vulnerabilities:**
    - Using weak or outdated algorithms.
    - Confusing encryption and signatures.
    - Not verifying signatures correctly.
    - Hardcoding keys or sensitive data.

- **Best practices:**
    - Use strong, standard algorithms (AES, RSA, ECDSA).
    - Keep private keys secure.
    - Always verify signatures before trusting data.
    - Prefer libraries over custom implementations.

- **Example snippet:**

```python
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()

message = b"Important message"
signature = private_key.sign(
    message,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

public_key.verify(
    signature,
    message,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)
```

[1]: <https://owasp.org/www-project-top-ten/2017/A1_2017-Injection.html>
[2]: <https://github.com/cncf/glossary>
[3]: <https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final>
[4]: <https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html>
[5]: <https://csrc.nist.gov/publications/detail/fips/186/5/final>
