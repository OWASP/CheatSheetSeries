# Mobile Application Security Cheat Sheet

Mobile application development presents certain security challenges that are
unique compared to web applications and other forms of software. This cheat
sheet provides guidance on security considerations for mobile app development.
It is not a comprehensive guide by any means, but rather a starting point for
developers to consider security in their mobile app development.

## Architecture & Design

### 1. Secure by Design

- Opt for a secure design at the beginning of development, not as an
  afterthought.
- Keep in mind security principles like least privilege, defense in depth, and
  separation of concerns.
- Follow industry standards and best practices, such as:
    - National Institute of Standards and Technology (NIST)
    - Internet Engineering Task Force (IETF)

For more information, see the
[Secure Product Design Cheat Sheet](Secure_Product_Design_Cheat_Sheet.md).

### 2. Secure APIs

- Ensure that your mobile app communicates securely with backend services.
- Use OAuth2, JWT, or similar for secure authentication.
- Regularly update and rotate any used API keys or tokens.

### 3. Principle of Least Privilege

- Request only the permissions your app needs.
- This applies not only to device permissions granted by the user, but also to
  permissions granted to the app by backend services.
- Avoid storing application files with overly permissive permissions.
- Secure by default: applications should have the most secure settings by default.

### 4. Supply Chain

Developing with third-party libraries and components introduces the possibility
of security unknowns.

- Ensure app signing.
- Use only trusted and validated third-party libraries & components.
- Establish security controls for app updates, patches, and releases.
- Monitor and detect security incidents of used third-party products.

See the [Vulnerable Dependency Management Cheat Sheet](Vulnerable_Dependency_Management_Cheat_Sheet.md)
for recommendations on managing third-party dependencies when vulnerabilities are discovered.

## Authentication & Authorization

Authentication is a complex topic and there are many pitfalls. Authentication
logic must be written and tested with extreme care. The tips here are only a
starting point and barely scratch the surface. For more information, see the
[Authentication Cheat Sheet](Authentication_Cheat_Sheet.md) and
[M1: Insecure Authentication/Authorization](https://owasp.org/www-project-mobile-top-10/2023-risks/m1-insecure-authentication-authorization.html) from the OWASP Mobile Top 10.

### 1. Don't Trust the Client

- Perform authentication/authorization server-side and only load data on the device after successful authentication.
- If storing data locally, encrypt it using a key derived from the user’s login credentials.
- Do not store user passwords on the device; use device-specific tokens that can be revoked.
- Avoid using spoofable values like device identifiers for authentication.
- Assume all client-side controls can be bypassed and perform them server-side as well.
- Include client side code to detect code/binary tampering.

### 2. Credential Handling

- Do not hardcode credentials in the mobile app.
- Encrypt credentials in transmission.
- Do not store user credentials on the device. Consider using secure, revocable access tokens.

### 3. Passwords and PIN Policy

- Require password complexity.
- Do not allow short PINs such as 4 digits.
- Use platform specific secure storage mechanisms, such as Keychain (iOS) or Keystore (Android).

### 4. Biometric Authentication

- Use platform-supported methods for biometric authentication.
- Always provide a fallback, such as a PIN.

### 5. Session Management

- Sessions should timeout after inactivity.
- Offer a remote logout feature.
- Use randomly generated session tokens.
- Secure session data, both client and server side.

### 6. Token Storage

- Store authentication tokens securely.
- Handle token expiration gracefully.

### 7. Sensitive Operations

- Require users to re-authenticate for sensitive operations like changing
  passwords or updating payment information.
- Consider requring re-authentication before displaying highly sensitive
  information as well.
- Require authorization checks on any backend functionality.

## Data Storage & Privacy

### 1. Data Encryption

- Encrypt sensitive data both at rest and in transit.
- Store private data on the device's internal storage.
- Use platform APIs for encryption. Do not attempt to implement your own
  encryption algorithms.

### 2. Data Leakage

- Beware of caching, logging, and background snapshots. Ensure that sensitive
  data is not leaked through these mechanisms.

See the [Logging Cheat Sheet](Logging_Cheat_Sheet.md#data-to-exclude) for
examples of data that should not be logged.

### 3. Use HTTPS

- Always use HTTPS for network communications.

### 4. Third-Party Libraries

- Ensure all third-party libraries are secure and up to date.

### 5. Personally Identifiable Information (PII)

- Minimise any PII to neccessity.
- Attempt to replace PII with less critical information if possible.
- Reduce PII, e.g. less frequent location updates.
- Implement automatic expiration and deletion of PII to minimize retention.
- Ask for user consent before collecting or using PII.

## Network Communication

### 1. Don't Trust the Network

- Assume that all network communication is insecure and can be intercepted.

### 2. Use Secure Protocols

- Use HTTPS for all network communication.
- Do not override SSL certificate validation to allow self-signed or invalid
  certificates.
- Avoid mixed version SSL sessions.
- Encrypt data even if sent over SSL, in case of future SSL vulnerabilities.
- Use strong, industry standard cipher suites, with appropriate key lengths.
- Use certificates signed by a trusted CA provider
- Avoid sending sensitive data via SMS.

### 3. Certificate Pinning

- Consider certificate pinning. See the [Pinning Cheat Sheet](Pinning_Cheat_Sheet.md)
  for pros and cons of this approach.

## User Interface

### 1. UI Data Masking

- Mask sensitive information on UI fields to prevent shoulder surfing.

### 2. User Notifications

- Inform the user about security-related activities, such as logins from new
  devices.

### 3. Input Validation

- Validate and sanitize user input. See the
  [Input Validation Cheat Sheet](Input_Validation_Cheat_Sheet.md) for more
  information.

### 4. Output Validation

- Validate and sanitize output to prevent injection and execution attacks.

## Code Quality

### 1. Static Analysis

- Use static analysis tools to identify vulnerabilities.

### 2. Code Reviews

- Make security a focal point during code reviews.

### 3. Update Libraries

- Keep all your libraries up to date to patch known vulnerabilities.

## Application Integrity

- Disable debugging.
- Include code to validate integrity of application code.
- Obfuscate the app binary.

## Testing

### 1. Penetration Testing

- Perform ethical hacking to identify vulnerabilities.
- Example tests:
    - Cryptographic vulnerability assessment.
    - Attempt to execute backend server functionality anonymously by removing any session tokens from POST/GET requests.

### 2. Automated Tests

- Leverage automated tests to ensure that security features are working as
  expected and that access controls are enforced.

### 3. Usability Testing

- Ensure that security features do not harm usability, which could cause users
  to bypass security features.

## Post-Deployment

### 1. Incident Response

- Have a clear incident response plan in place.

### 2. Updates

- Plan for regular updates and patches. In the case of mobile apps, this is
  especially important due to the delay between when a patch is released and
  when users actually receive the updated version due to app store review
  processes and the time it takes for users to update their apps.

- Use a mechanism to force users to update their app version when necessary.

### 3. Monitoring and Analytics

- Use real-time monitoring to detect and respond to threats.

## Platform-Specific Guidance

### Android

- Use Android’s ProGuard for code obfuscation.
- Avoid storing sensitive data in SharedPreferences. See the
  [Android docs](https://developer.android.com/topic/security/data)
  on working with data securely for more details.
- Disable backup mode to prevent sensitive data being stored in backups.

### iOS

- Use ATS (App Transport Security) to enforce strong security policies for
  network communication.
- Do not store sensitive data in plist files.

For further reading, visit the
[OWASP Mobile Top 10 Project](https://owasp.org/www-project-mobile-top-10/).
For a more detailed framework for mobile security, see the
[OWASP Mobile Application Security Project](https://mas.owasp.org/).
