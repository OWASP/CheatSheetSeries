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
- Use only trusted and validated third-party libraries and components.
- Establish security controls for app updates, patches, and releases.
- Monitor and detect security incidents of used third-party products.

See the [Vulnerable Dependency Management Cheat Sheet](Vulnerable_Dependency_Management_Cheat_Sheet.md) for recommendations on managing third-party dependencies when vulnerabilities are discovered.

## Authentication & Authorization

Authentication is a complex topic and there are many pitfalls. Authentication
logic must be written and tested with extreme care. The tips here are only a
starting point and barely scratch the surface. For more information, see the
[Authentication Cheat Sheet](Authentication_Cheat_Sheet.md) and
[M1: Insecure Authentication/Authorization](
https://owasp.org/www-project-mobile-top-10/2023-risks/m1-insecure-authentication-authorization.html)
from the OWASP Mobile Top 10.

### 1. Don't Trust the Client

- Perform authentication/authorization server-side and only load data on
the device after successful authentication.
- If storing data locally, encrypt it using a key derived from the user's
login credentials.
- Do not store user passwords on the device; use device-specific tokens
that can be revoked.
- Avoid using spoofable values like device identifiers for authentication.
- Assume all client-side controls can be bypassed and perform them
server-side as well.
- Include client side code to detect code/binary tampering.

### 2. Credential Handling

- Do not hardcode credentials in the mobile app.
- Encrypt credentials in transmission.
- Do not store user credentials on the device. Consider using
secure, revocable access tokens.

### 3. Passwords and PIN Policy

- Require password complexity.
- Do not allow short PINs such as 4 digits.
- Use platform specific secure storage mechanisms, such as
Keychain (iOS) or Keystore (Android).

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
- Consider requiring re-authentication before displaying highly sensitive
  information as well.
- Require authorization checks on any backend functionality.

## Data Storage & Privacy

### 1. Data Encryption

- Encrypt sensitive data both at rest and in transit.
- Store private data on the device's internal storage.
- Use platform APIs for encryption. Do not attempt to implement your own
  encryption algorithms.
- Leverage hardware-based security features when available (e.g., Secure Enclave on iOS,
  Strongbox on Android) for key storage and cryptographic operations
  whenever available.

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

- Minimise any PII to necessity.
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
- Implement runtime anti-tampering controls:
    - Check for signs of debugging, hooking, or code injection.
    - Detect if the app is running in an emulator or rooted/jailbroken device.
    - Verify app signatures at runtime.
    - Apply appropriate responses to detected tampering (e.g., limiting functionality).

## Testing

### 1. Penetration Testing

- Perform ethical hacking to identify vulnerabilities.
- Example tests:
    - Cryptographic vulnerability assessment.
    - Attempt to execute backend server functionality anonymously by removing any
      session tokens from POST/GET requests.

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

- Use Android's ProGuard for code obfuscation.
- Avoid storing sensitive data in SharedPreferences. See the
  [Android docs](https://developer.android.com/topic/security/data)
  on working with data securely for more details.
- Disable backup mode to prevent sensitive data being stored in backups.

- Use Android Keystore with hardware backing (TEE or StrongBox) to securely store
  cryptographic keys.
    - **How**: Generate keys with hardware backing by specifying
      `.setIsStrongBoxBacked(true)` in `KeyGenParameterSpec.Builder` when available (Android 9+).
    - Verify hardware-backed storage via `KeyInfo.isInsideSecureHardware()`.
    - Fall back to regular hardware-backed keystore if Strongbox isn't available.
    - Configure key usage restrictions with `.setUserAuthenticationRequired(true)`
      for sensitive operations.
    - See [Hardware-backed Keystore documentation](https://developer.android.com/training/articles/keystore).

- Implement Google's [Play Integrity API](https://developer.android.com/google/play/integrity) for device and app integrity checks.
    - **How**: Obtain an integrity verdict from the device, validate server-side,
      and take action if integrity checks fail.
    - The SafetyNet Attestation API was fully turned down in January 2025. All
      developers must migrate to Play Integrity API.
    - See [Play Integrity API documentation](https://developer.android.com/google/play/integrity/overview).

### iOS and iPadOS

#### Shortcuts Permissions

- iOS/iPadOS Shortcuts allow for automation of app functions, which may
enable sensitive actions even when the device is locked.

- There are several scenarios in which a user can execute a Shortcut
while the device is locked:

  1. If a Shortcut is added as a widget to Today View, it can be accessed
and executed while the device is locked.
  2. If a Shortcut is assigned to the Action Button (on iPhone 15 Pro and
iPhone 16 Pro models), it can be executed by pressing the Action Button
while the device is locked.
  3. If a Shortcut is assigned to the Control Center (on iOS/iPadOS 18+),
it can be executed by pulling up the Control Center and pressing the
Shortcut button while the device is locked.
  4. A Shortcut can be invoked via Siri while the device is locked.
  5. If a Shortcut is added to the user's Home Screen (on iOS/iPadOS 18+),
it can be directly executed by tapping the Shortcut button on the user's
lock screen while the device is locked.
  6. If a Shortcut is set to run at a specific interval or a specific time,
it can execute even if the device is locked.

- Sensitive app functionalities triggered via Shortcuts should always
require device unlock before execution.

- **How**: Store secure tokens in Keychain that the app validates before
executing sensitive shortcuts. Implement checks with
`UIApplication.shared.isProtectedDataAvailable` to restrict execution
of sensitive actions when the device is locked.

#### Siri Permissions

- Siri can access app functionalities through voice or [Type to Siri](
  https://support.apple.com/guide/iphone/change-siri-accessibility-settings-iphaff1d606/ios.)
  commands, which is by default accessible even when the device is locked
  potentially enabling unauthorized actions.
- **How**: Configure `requiresUserAuthentication` to `true` on intents that expose
sensitive information or functionality. Additionally, set
`INIntent.userConfirmationRequired = true` for operations requiring explicit
user confirmation. These settings ensure proper authentication
(e.g., Face ID or PIN) and explicit approval before Siri can
execute sensitive commands. (For more information, see Apple Developer's
[SiriKit](https://developer.apple.com/documentation/sirikit) documentation.)

#### Deep Link Security

- Deep links offer direct access to specific app screens, which could
potentially bypass authentication if not secured, allowing unauthorized
users access to secure sections of the app.
- An example of this on Microsoft Authenticator for iOS (which was
remediated in July 2024) allowed users to bypass App Lock by simply
navigating to `msauth://microsoft.aad.brokerplugin/?`, which would
open Authenticator and dismiss the Face ID/Touch ID/passcode prompt.
- **How**: Implement authentication checks on any view controllers
or endpoints accessed via deep links. Configure and validate Universal
Links using apple-app-site-association files for secure deep linking.
Sanitize and validate all parameters received through deep links to
prevent injection attacks. Ensure unauthorized users are redirected
to the login screen, preventing direct access to sensitive parts of
the app without proper authentication. (See Apple Developer's
[Supporting universal links in your app](
https://developer.apple.com/documentation/xcode/supporting-universal-links-in-your-app)
documentation for more information.)

#### WidgetKit Security

- Widgets on the lock screen may display sensitive data, potentially
exposing it without the device being unlocked.
- **How**: For iOS/iPadOS versions 17 and higher, use `WidgetInfo.isLocked`
to detect lock screen state. For earlier iOS versions, implement custom
logic based on available widget states since `widgetFamily` alone doesn't
directly provide lock screen information. Apply conditional logic to mask
or restrict sensitive widget content when appropriate security conditions
aren't met. (See Apple's [WidgetKit security](
https://support.apple.com/guide/security/widgetkit-security-secbb0a1f9b4/web)
for more information.)

#### Additional Security Considerations

- Configure appropriate background refresh policies to prevent sensitive data
updates while the device is locked.
- Implement proper privacy-related configurations in `Info.plist` for
features requiring user permissions.
- Use App Groups with appropriate security configurations when sharing data
between app and widgets.
- Use ATS (App Transport Security) to enforce strong security policies for
network communication.
- Do not store sensitive data in `plist` files.

- Use Apple's Secure Enclave for secure cryptographic key storage and
  sensitive operations.
    - **How**: Create keys using `SecKeyCreateRandomKey` with `kSecAttrTokenID`
      set to `kSecAttrTokenIDSecureEnclave`.
    - Keys created in the Secure Enclave never leave the secure hardware -
      only the operations using those keys are performed there.
    - For biometric operations, use `LAContext` with `evaluatePolicy` to
      perform authentication directly through the Secure Enclave without
      exposing biometric data to your application.
    - Consider access control options like `kSecAccessControlBiometryAny` or
      `kSecAccessControlUserPresence` to require user authentication before
      key usage.
    - See [Secure Enclave documentation](https://support.apple.com/guide/security/secure-enclave-sec59b0b31ff/web).

- Use Apple's [App Attest API](https://developer.apple.com/documentation/devicecheck/establishing_your_app_s_integrity) (iOS 14+) to validate app integrity.
    - **How**: Generate attestation keys and assertions with `DCAppAttestService`
      and verify assertions server-side.
    - Complement with Apple's [DeviceCheck API](https://developer.apple.com/documentation/devicecheck) for persistent device state tracking.
    - See [App Attest documentation](https://developer.apple.com/documentation/devicecheck/dcappattestservice).

## Advanced Hardware Security & Monitoring

- Modern devices typically provide Trusted Execution Environments (TEE) or
  secure hardware modules. Leverage these through standard OS APIs.
- Consider additional runtime security measures (behavioral anomaly
  detection, runtime monitoring) to complement built-in OS protections
  in higher-risk scenarios.

For further reading, visit the
[OWASP Mobile Top 10 Project](https://owasp.org/www-project-mobile-top-10/).
For a more detailed framework for mobile security, see the
[OWASP Mobile Application Security Project](https://mas.owasp.org/).
