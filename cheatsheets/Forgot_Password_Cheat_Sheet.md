# Forgot Password Cheat Sheet

## Introduction

In order to implement a proper user management system, almost all systems integrate a **Forgot Password** service, which allows the user to request a reset to their password whenever they forget any of them, or if their account ever gets breached.

Even though this functionality looks straightforward and easy to implement, the details of its implementation makes it a sweet spot for security attacks, such as the renowned [user enumeration attack](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/03-Identity_Management_Testing/04-Testing_for_Account_Enumeration_and_Guessable_User_Account.html).

The following short guidelines can be used as a quick reference to protect the forgot password service:

- **Return a consistent message for both existent and nonexistent accounts.**
- **Ensure that the time taken for the user response message is uniform.**
- **Use a side-channel to communicate the method to reset their password.**
- **For critical services and applications, MFA should be used.**

## Forgot Password Service

The service providing the Forgot Password functionality should follow secure practices, as detailed below.

### Forgot Password Request

The user uses the forgot password service and inputs their username or email. To ensure the security on this stage, the below should be implemented:

- Return a consistent message for both existent and nonexistent accounts.
- Consistent user response time. That could be achieved by using asynchronous calls or by making sure that the same logic is followed, instead of using a quick exit method.
- Rate-limiting (*e.g.* Captchas, blocking IPs for a period of time, etc.) to protect the application against [brute-force attacks](https://en.wikipedia.org/wiki/Brute-force_attack).
- Employ normal security measures, such as [SQL Injection Prevention methods](SQL_Injection_Prevention_Cheat_Sheet.md) and [Input Validation](Input_Validation_Cheat_Sheet.md) where need be.

### User Resets Password

Once the user is validated through the provided token or code, they should reset their password to a new secure one. In order to secure this last step, the measures should be taken:

- Validate that a secure password policy is in place.
- The user should confirm the password they set by writing it twice.
- Update and store the password following [secure practices](Password_Storage_Cheat_Sheet.md).
- Send the user an email informing them that their password has been reset (do not send the password in the email!).
- Ask the user to re-login. Don't auto-login users on password reset!
- Ask the user if they want to invalidate all of the sessions, or invalidate the sessions by default without prompting the user.

## Methods

In order to allow a user to request a password reset, you will need to have some way to identify the user, or a means to reach out to them through a side-channel.

This can be done through any of the following methods:

- [URL tokens](#url-tokens-or-codes).
- [Offline methods](#offline-methods)
- [Security questions](#security-questions).

These methods can be used together and many times it is recommended to do so. No matter what you must ensure that a user always has a way to recover their account.

### General Security Practices

It is essential to employ security practices for the reset codes and tokens that will be used in the methods.

- [Secure random generation](Cryptographic_Storage_Cheat_Sheet.md#secure-random-number-generation).
- Short lifetime (*e.g.* 30 minutes).
- Linked to the user requesting the token in the database.
- One time use (should be removed from the database once used).
- Ensure that the tokens and codes are stored in a secure fashion by following the [Password Storage CS](Password_Storage_Cheat_Sheet.md).
- Tokens should be long enough to avoid brute-force attacks (16 characters should be the minimum used).
- Don't rely on the [Host](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Host) header while creating the reset URLs to avoid [Host Header Injection](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/17-Testing_for_Host_Header_Injection) attacks. When need be, implement a robust whitelist of the allowed Hosts.

### URL Tokens or Codes

URL tokens provide access control to the user by sending a URL with a token appended in the querystring, or by sending a code. They are both sent through a side-channel, *e.g.* email.

If a code is provided to the user, the user will have to provide that code manually to the application.

If a URL with a token is provided to the user, 2 flows present themselves:

First flow:

1. Access the URL with the attached token.
2. Create a restricted session from that token that permits the user to reset their password. If a JWT is used to replace the session creation, it is critical that security best practices are employed for the JWT (*e.g.* enforced algorithm, no sensitive data in the payload, etc.).
3. Let the user create a new password and confirm it. Ensure that the password policy is applied.

Second flow:

1. Access the URL with the attached token. Ensure that the reset password page adds the [Referrer Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy) tag with the `noreferrer` value in order to avoid [referrer leakage](https://portswigger.net/kb/issues/00500400_cross-domain-referer-leakage).
2. Let the user create a new password and confirm it. Ensure that the password policy is applied.

### Offline Methods

Offline methods provide the user at registration with methods that the user would store in an offline manner and then use at a later stage for the sole purpose of resetting their accounts.

#### Backup Codes

Backup codes should be provided to the user upon registering where the user should store them offline in a secure place (password managers). Some companies that implement this method are [Google](https://support.google.com/accounts/answer/1187538), [GitHub](https://help.github.com/en/github/authenticating-to-github/recovering-your-account-if-you-lose-your-2fa-credentials), and [Auth0](https://auth0.com/docs/mfa/guides/reset-user-mfa#recovery-codes).

While implementing this method, the following practices should be followed:

- Minimum length of 8 digits, 12 for improved security.
- A user should have multiple recovery codes at any given time to ensure that one of them works (most services provide the user with 10 backup codes).
- Code renewal or revocation service.

#### Multi-Factor Authentication

Multi-Factor Authentication (MFA) can be used as a reset password mechanism if the configured MFA service is specific to this mechanism, and a user is not using it as part of their login process.

This is configured on registration, or later on in the user's profile if they wish to enable it.

For more on MFA, refer to the [MFA CS](Multifactor_Authentication_Cheat_Sheet.md).

*Note:* Using the same MFA regitration for both the login process and the reset password process becomes a weakness. A user (or a malicious actor) is capable of resetting the password using the MFA for resetting the password, then using that password and MFA to login, which breaks the purpose of MFA.

### Security Questions

Security questions should not be used as the sole mechanism for resetting passwords due to weakness related to their implementations, where the questions could be either guessed or generic. However, if they are used as a factor, then ensure that secure questions are chosen as discussed in the [Security Questions CS](Choosing_and_Using_Security_Questions_Cheat_Sheet.md).
