# Security Terminology Cheat Sheet

## Introduction

This cheat sheet provides clear definitions and distinctions for security terminology that is often confused, even by experienced developers. Understanding these terms is critical for correctly implementing security controls and following standards like the [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/).

## Table of Contents

- [Data Handling: Encoding, Escaping, Sanitization, and Serialization](#data-handling-encoding-escaping-sanitization-and-serialization)
- [Cryptography: Encryption, Hashing, and Signatures](#cryptography-encryption-hashing-and-signatures)
- [Identity: Authentication and Authorization](#identity-authentication-and-authorization)
- [Federated Identity Terms](#federated-identity-terms)
- [References](#references)

## Data Handling: Encoding, Escaping, Sanitization, and Serialization

These terms relate to how data is transformed for transport, storage, or display.

### Encoding

**Definition:** Transforming data into a different format using a publicly available scheme, so that it can be safely consumed by a different system.

- **Purpose:** Not for security, but for data usability and compatibility.
- **Reversibility:** Always reversible.
- **Examples:** Base64, URL Encoding, HTML Entity Encoding.
- **Security Context:** Using the wrong encoding can lead to vulnerabilities, but encoding itself is not a security control.

### Escaping

**Definition:** A sub-type of encoding where specific characters are prefixed with a "signal" character (like a backslash) to prevent them from being misinterpreted by a parser as control characters.

- **Purpose:** To ensure the interpreter treats the data as text rather than code/commands.
- **Examples:** `\'` in SQL, `\n` in strings, `&lt;` in HTML.
- **Security Context:** Essential for preventing Injection attacks (XSS, SQLi).

### Sanitization

**Definition:** The process of cleaning or filtering input by removing, replacing, or modifying potentially dangerous characters or content.

- **Purpose:** To make "dirty" input "clean" according to a security policy.
- **Examples:** Stripping `<script>` tags from HTML input, removing special characters from a filename.
- **Security Context:** Use as a secondary defense; prefer parameterized queries or output escaping where possible.

### Serialization

**Definition:** Converting an object or data structure into a format that can be stored or transmitted (e.g., a byte stream) and later reconstructed.

- **Purpose:** Data persistence and communication.
- **Security Context:** **Insecure Deserialization** occurs when untrusted data is used to reconstruct an object, potentially leading to Remote Code Execution (RCE).

---

## Cryptography: Encryption, Hashing, and Signatures

These terms relate to protecting the confidentiality, integrity, and authenticity of data.

### Encryption

**Definition:** Transforming data (plaintext) into an unreadable format (ciphertext) using a secret key.

- **Purpose:** **Confidentiality**. Only authorized parties with the key can read the data.
- **Reversibility:** Reversible (Decryption) with the correct key.
- **Types:** Symmetric (same key) and Asymmetric (public/private keys).

### Hashing

**Definition:** Transforming data into a fixed-size string (a "hash" or "digest") using a mathematical function.

- **Purpose:** **Integrity**. A small change in the input results in a completely different hash.
- **Reversibility:** One-way (non-reversible).
- **Security Context:** Used for password storage (with salt) and verifying file integrity.
- **Examples:** SHA-256, Argon2, bcrypt.

### Signatures (Digital Signatures)

**Definition:** Using asymmetric cryptography to provide proof of the origin and integrity of a message.

- **Purpose:** **Authenticity** and **Non-repudiation**. Proves who sent the message and that it wasn't altered.
- **Mechanism:** The sender signs a hash of the message with their *private key*; the receiver verifies it with the sender's *public key*.
- **Example:** JWT signatures, GPG signatures.

---

## Identity: Authentication and Authorization

### Authentication (AuthN)

**Definition:** The process of verifying who a user is.

- **Question:** "Who are you?"
- **Factors:** Something you know (password), something you have (token), something you are (biometrics).

### Authorization (AuthZ)

**Definition:** The process of verifying what a user has permission to do.

- **Question:** "Are you allowed to do this?"
- **Security Context:** Occurs *after* successful authentication.
- **Examples:** Role-Based Access Control (RBAC), Attribute-Based Access Control (ABAC).

---

## Federated Identity Terms

When working with OAuth2, SAML, or OIDC, these terms are frequently used:

| Term | Definition | Context |
| :--- | :--- | :--- |
| **Identity Provider (IdP)** | The system that creates, maintains, and manages identity information and provides authentication services. | Google, Okta, Azure AD |
| **Relying Party (RP)** | An application or service that relies on an IdP to authenticate users. | Your web app using "Login with Google" |
| **Service Provider (SP)** | In SAML, the equivalent of a Relying Party. | Your enterprise app using SAML |
| **Principal** | The entity (user, service, or device) being authenticated. | The user logging in |

---

## References

- [OWASP ASVS Standard](https://owasp.org/www-project-application-security-verification-standard/)
- [OWASP Key Management Cheat Sheet](Key_Management_Cheat_Sheet.md)
- [OWASP Password Storage Cheat Sheet](Password_Storage_Cheat_Sheet.md)
- [OWASP Input Validation Cheat Sheet](Input_Validation_Cheat_Sheet.md)
