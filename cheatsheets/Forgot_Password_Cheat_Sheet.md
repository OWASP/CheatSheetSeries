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

The service providing the Forgot Password functionality should follow secure practices on three stages, detailed below.

### Forgot Password Request

The user uses the forgot password service and inputs their username or email. To ensure the security on this stage, the below should implemented:

- Return a consistent message for both existent and nonexistent accounts.
- Consistent user response time. That could be achieved by using asynchronous calls or by making sure that the same logic is followed, instead of using a quick exit method.
- Rate-limiting (*e.g.* Captchas, blocking IPs for a period of time, etc.) to protect the application against [brute-force attacks](https://en.wikipedia.org/wiki/Brute-force_attack).
- Employ normal security measures, such as [SQL Injection Prevention methods](SQL_Injection_Prevention_Cheat_Sheet.md), and [Input Validation](Input_Validation_Cheat_Sheet.md) where need be.

### Code or Token Activation

After a user uses the service to reset their password, a code or token is provided to the user following one of the [methods](#methods) discussed later in this document. Adding on the [forgot password request](#forgot-password-request) security measure, if the token is sent in the querystring:

- The service should redirect the user after using that token and replacing it with a cookie in order to avoid [Cross-domain Referer leakage](https://portswigger.net/kb/issues/00500400_cross-domain-referer-leakage). This [attack](https://hackerone.com/reports/209352) occurs when private information is sent in the querystring and third party services are called, thus *leaking* the querystring in the `Referer` header.

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

- One Time Password (OTP).
- URL tokens.
- Security Questions.
- Offline backup codes.

These methods can be used together and many times it is recommended to do so. No matter what you must ensure that a user always has a way to recover their account.

### One Time Password

One Time Password (OTP) is the best method in order to implement a secure forgot password service that triggers as a 2FA functionality.

The two most famous methods are Time-OTP ([TOTP](https://tools.ietf.org/html/rfc6238)), or HMAC-OTP ([HOTP](https://tools.ietf.org/html/rfc4226)). The main difference is in the counter, where TOTP focuses on the Unix time, and HOTP has a counter that gets incremented on every user call to generate the OTP.

For a better description of OTP generation, refer to the [MFA CS](Multifactor_Authentication_Cheat_Sheet.md#something-you-have), where the pros and cons of every implementation are provided.

One implementation can be found over for [Authy](https://www.twilio.com/docs/authy/tutorials/two-factor-authentication-python-flask). If you don't want to rely on applications (such as Authy, Google/Microsoft Authenticator, etc.), there are libraries like pyotp, which helps the developer implement on their own any of the methods discussed in this section.

> OTPs can be sent through other channels as well, such as emails and SMSs. [Various attacks and weaknesses](https://en.wikipedia.org/wiki/SIM_swap_scam) have been identified in SMS that it is [preferrable not to use them for OTPs](https://auth0.com/blog/why-sms-multi-factor-still-matters/).

### URL Tokens or Codes

URL tokens provide access control to the user by sending a URL with a token appended in the querystring, or by sending a code. They are both sent through a side-channel, *e.g.* email.

If a code is provided to the user, the user will have to provide that code manually to the application.

If a URL with a token is provided to the user, the user will have to follow the below steps:

1. Access the URL with the attached token.
2. Set the token in a cookie (recommended), or the client-storage mechanism that your application uses.
3. Remove the token from the URL and redirect the user to the password reset service. This ensures that protection against [referer leakage](https://portswigger.net/kb/issues/00500400_cross-domain-referer-leakage).
4. Let the user create a new password and confirm it. Ensure that the password policy is applied.

### Security Questions

> This method should not be used as the sole method to reset a password, and should be used in conjunction with other methods.

Kindly refer to the [Security Questions Cheat Sheet](Choosing_and_Using_Security_Questions_Cheat_Sheet.md) for further guidance.

### Backup Codes

Backup codes should be provided to the user upon registering where the user should store them offline in a secure place (password managers). Some companies that implement this method are [Google](https://support.google.com/accounts/answer/1187538), [GitHub](https://help.github.com/en/github/authenticating-to-github/recovering-your-account-if-you-lose-your-2fa-credentials), and [Auth0](https://auth0.com/docs/mfa/guides/reset-user-mfa#recovery-codes).

### Methods Secure Practices

It is essential to employ security practices for the reset codes and tokens that will be used in the methods.

#### General Security Practices

- Randomly generated with a [CSPRNG](https://en.wikipedia.org/wiki/Cryptographically_secure_pseudorandom_number_generator) (*e.g.* [secrets](https://docs.python.org/3/library/secrets.html) library in Python).
- Short lifetime (*e.g.* 30 minutes).
- Linked to the user requesting the token in the database.
- One time use (should be removed from the database once used).
- Ensure that the tokens and codes are stored in a secure fashion by following the [Password Storage CS](Password_Storage_Cheat_Sheet.md) and the [Cryptographic Storage CS](Cryptographic_Storage_Cheat_Sheet.md).

#### Tokens Specific Security Practices

- Long enough to avoid brute-force attacks (16 characters should be the minimum used).

#### Codes Specific Security Practices

- Minimum length of 8 digits, 12 for improved security.
- If the service allows users to view the backup codes, the codes should be [securely stored](Cryptographic_Storage_Cheat_Sheet.md) and access should only happen in an authenticated session after asking for a user identifier (password, email token, etc.).
- A user should have multiple recovery codes at any given time to ensure that one of them works (most services provide the user with 10 backup codes).
