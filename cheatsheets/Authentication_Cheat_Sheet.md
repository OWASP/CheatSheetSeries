
# Authentication Cheat Sheet (Full Version)

## Introduction

**Authentication (AuthN)** verifies that a user, entity, or system is who they claim to be.  
**Digital Identity** is a unique online representation of a subject.  
**Identity Proofing** ensures that the subject is actually who they claim to be (related to KYC).  
**Session Management** maintains state between the server and client via session IDs.

---

## Authentication General Guidelines

### User IDs
- Uniquely identify users.  
- Prefer randomly generated IDs to avoid predictability.

### Usernames
- Users can choose their username or use a verified email.  
- Validate emails properly ([Input Validation Cheat Sheet](Input_Validation_Cheat_Sheet.md#email-address-validation)).

### Authentication Solution and Sensitive Accounts
- **Do NOT allow internal sensitive accounts** (e.g., backend or database accounts) for front-end login.  
- Do **NOT** expose internal authentication systems (IDP / AD) to public users.

---

## Password Controls

### Strong Password Requirements
- **Length:**  
  - With MFA: ≥8 characters (weak if shorter)  
  - Without MFA: ≥15 characters (weak if shorter)  
  - Max: ≥64 characters  
- Allow all characters including Unicode and whitespace.  
- Avoid mandatory periodic password changes; encourage strong passwords and MFA.  
- Include a password strength meter (e.g., [zxcvbn-ts](https://github.com/zxcvbn-ts/zxcvbn)).  
- Block common or breached passwords ([Pwned Passwords](https://haveibeenpwned.com/Passwords)).

---

## Password Recovery & Storage
- Secure recovery: [Forgot Password Cheat Sheet](Forgot_Password_Cheat_Sheet.md)  
- Store passwords securely: [Password Storage Cheat Sheet](Password_Storage_Cheat_Sheet.md)  
- Compare hashes safely (e.g., `password_verify()` in PHP)

---

## Re-authentication & Sensitive Actions

- **Trigger re-authentication** for:
  - Password resets
  - Account recovery
  - High-risk actions
  - Suspicious behavior

**Mechanisms:**  
- Adaptive Authentication  
- Multi-Factor Authentication (MFA) – **highlighted below**  
- Challenge-based verification

**Developer Note:**  
- Minimize friction for low-risk actions.  
- Use context-aware decisions (device, location, IP).  
- Always maintain secure session management.

---

## Multi-Factor Authentication (MFA)

- **Optional for general users:**  
  ``` 
  // Encourage MFA but do not block login if user opts out
  ```
- **Mandatory for high-risk accounts/actions:**  
  ``` 
  // Enforce MFA during:
  // - Admin or sensitive account login
  // - Transactions with financial impact
  // - Access from unusual devices or locations
  ```
- Adaptive MFA: Step-up authentication based on risk level.

---

## Transaction & Strong Authentication

- Optional TLS Client Authentication for high-security operations.  
- Enforce step-up authentication for sensitive transactions.

---

## Authentication & Error Messages

- Always return **generic errors** to avoid user enumeration:

```
Login failed: Invalid user ID or password.
```

- Never reveal which part failed.

---

## Protection Against Automated Attacks

- Encourage optional MFA, login throttling, CAPTCHAs, and monitoring.  
- Enforce MFA for high-risk users/actions.  

**Developer Tip:**  
- Example: Optional MFA during normal login; mandatory MFA if unusual location or device detected.

---

## Logging & Monitoring

- Log authentication attempts, failures, password resets.  
- Review logs to detect attacks or anomalies.

---

## Passwordless Authentication

- Protocols like OAuth2.0, OpenID Connect, SAML, FIDO can reduce password exposure.  
- Allow integration with password managers safely (standard HTML fields, pasting enabled, sufficient length).

---

## Changing Registered Email Address

- **Multi-step verification required:**  
  - If MFA enabled → use MFA  
  - If MFA not enabled → verify current password  
- Notify both old and new email addresses with time-limited confirmation links.

---

## Adaptive or Risk-Based Authentication

- Evaluate risk by environment, device, location, behavior.  
- MFA optional for low-risk actions, step-up for high-risk.  

**Developer Note:**  
- Example: Login from usual device → MFA optional  
- Login from new country → enforce MFA

---

## References

- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)  
- [OWASP ASVS v5.0 – Authentication](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x15-V6-Authentication.md)  
- [NIST SP 800-63B – Digital Identity Guidelines](https://pages.nist.gov/800-63-4/sp800-63b.html#passwordver)  
- [Multifactor Authentication Cheat Sheet](Multifactor_Authentication_Cheat_Sheet.md)
