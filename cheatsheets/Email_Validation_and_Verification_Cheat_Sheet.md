# Email Validation and Verification in Identity Systems Cheat Sheet

## Introduction

Email addresses are widely used as primary identifiers in authentication and account recovery workflows. Improper handling of email validation, normalization, and verification can lead to account takeover, user enumeration, and identity confusion.

This cheat sheet provides guidance on securely handling email addresses within identity systems.

## Goals

- Safely treat email as an identifier
- Prevent account takeover via email-based flows
- Reduce user enumeration risk
- Define secure verification and change workflows

## Threat Model

Attackers may attempt to:

- Register equivalent or visually similar email addresses
- Exploit inconsistent normalization logic
- Abuse password reset functionality
- Enumerate valid accounts
- Take over accounts through email change workflows

## Email Canonicalization

Applications must define a consistent normalization strategy before storing or comparing email addresses.

### Recommendations

- Normalize the domain portion to lowercase
- Avoid provider-specific transformations (e.g., Gmail dot removal) unless fully controlled
- Store both:
    - Original input (for display and communication)
    - Canonical form (for comparison according to your policy)
- Document the comparison policy explicitly and apply it consistently across registration, login, password reset, account recovery, and account linking flows

## Email Format Validation

Strict regex-based validation often rejects valid addresses or introduces inconsistencies.

### Recommendations

- Use well-tested libraries instead of custom regex
- Accept a broad range of valid formats
- Reject clearly malformed input only

## Unicode and IDN Considerations

Unicode introduces spoofing risks via visually similar characters.

### Recommendations

- Normalize Unicode input
- Convert internationalized domains to punycode for comparison
- Be aware of homoglyph attacks (e.g., Latin vs Cyrillic characters)
- Be especially cautious with internationalized local-parts, because normalization and comparison behavior may differ across systems

## Case Sensitivity

- Domain part: always case-insensitive
- Local part: technically case-sensitive under SMTP, though many providers do not enforce this in practice

### Recommendation

- Preserve the original email address as entered by the user
- Define an explicit comparison policy for the local part based on your identity architecture and interoperability requirements
- Only fold or normalize the local part when the system fully owns that behavior and the decision will not create account-collision or mistaken-account risk

## Email Ownership Verification

Email ownership must be verified before enabling account use.

### Recommendations

- Use cryptographically secure, random tokens
- Ensure tokens are:
    - Single-use
    - Time-limited
- Do not activate accounts before verification is completed

## Password Reset Flows

Password reset is a high-risk operation.

### Recommendations

- Use single-use, time-limited tokens
- Do not disclose whether an email exists in the system
- Invalidate tokens after use or expiration
- Rate limit reset requests

## Email Change Workflows

Changing an email address is equivalent to changing identity.

### Recommendations

- Require re-authentication
- Notify the existing email address of the change
- Require confirmation of the new email address
- Consider requiring confirmation from both addresses for high-risk systems

## Anti-Enumeration Controls

Attackers should not be able to determine whether an email is registered.

### Recommendations

- Use consistent responses for login and reset flows
- Avoid timing discrepancies between valid and invalid cases
- Implement rate limiting and monitoring

## Temporary Email Abuse

Disposable email services can be used to bypass controls.

### Recommendations

- Maintain a list of known disposable domains if appropriate
- Prefer risk-based controls over strict blocking
- Monitor for suspicious patterns of account creation

## Email as an Authentication Factor

Email should not be treated as a strong authentication factor.

### Recommendations

- Treat email as a weak factor
- Require multi-factor authentication (MFA) for sensitive operations
- Do not rely on email alone for account security

## Logging and Monitoring

Monitoring email-related flows helps detect abuse.

### Recommendations

- Log verification attempts and failures
- Monitor password reset activity
- Detect abnormal patterns (e.g., high-frequency requests)
- Avoid logging full email addresses; mask or pseudonymize them where logging is necessary (e.g., `j***@example.com`)
- Never log verification, reset, or authentication tokens or full verification/reset URLs
- Treat email addresses and related identifiers in logs as personal or sensitive data and restrict access accordingly

## References

- [RFC 5322](https://datatracker.ietf.org/doc/html/rfc5322)
- [OWASP Authentication Cheat Sheet](Authentication_Cheat_Sheet.md)
- [OWASP Forgot Password Cheat Sheet](Forgot_Password_Cheat_Sheet.md)
