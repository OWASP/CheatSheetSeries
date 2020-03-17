# Forgot Password Cheat Sheet

## Introduction

In order to implement a proper user management system, almost all systems integrate a **Forgot Password?** service, which allows the user to request a reset to their password whenever they forget their password, or if their account ever gets breached.

As much as is this functionality looks straight-forward and easy to implement, the details of its implementations make it a sweet spot for security attacks, such as the renowned [user enumeration attack](https://www.owasp.org/index.php/Testing_for_User_Enumeration_and_Guessable_User_Account_%28OWASP-AT-002%29).

The following short guidelines can be used as a quick reference to protect the forgot password service:

- **Unified user message, whether the user exists or not.**
- **Ensure that the time taken for the user response message is uniform.**
- **Use a side-channel to communicate the method to reset their password.**
- **For critical services and applications, MFA should be used.**

## Content

<!--To be done-->

## Methods

In order to allow a user to request a password reset, you will need to have some way to identify the user, or a mean to reach out to them through a side-channel.

This can be done through any of the following methods:

- One Time Password (OTP).
- URL tokens.
- Security Questions.
- Offline pin codes.

## Methods Implementation

In order to implement the forgot password service, the developer needs to choose one of the proposed [methods](#methods).

### One Time Password

OTP is the best method in order to implement a secure forgot password service that triggers as a 2FA functionality.

The two most famous methods are Time-OTP ([TOTP](https://tools.ietf.org/html/rfc6238)), or HMAC-OTP ([HOTP](https://tools.ietf.org/html/rfc4226)). The main difference is in the counter, where TOTP focuses on the Unix time, and HOTP has a counter that gets incremented on every user call to generate the OTP.

TOTP is a favorite candidate over HOTP, since you don't have to worry about the counter, and it gets refreshed between 30 or 60 seconds in most implementations. One implementation can be found over for [Authy](https://www.twilio.com/docs/authy/tutorials/two-factor-authentication-python-flask). If you don't want to rely on applications (such as Authy, Google/Microsoft Authenticator, etc.), you can generate QR codes and send them from the server for the user to scan using their device. The following python library, [pyotp](https://github.com/pyauth/pyotp), helps the developer implement any of the methods discussed in this section.

> OTPs can be sent through other channels as well, such as emails and SMSs. Various attacks and weaknesses have been identified in such technologies that it is preferrable not to use them for OTPs.

### URL Tokens

URL tokens provide access control to the user by sending a URL with a short-lived token.

<!-- tokens best practices -->

After sending the URL token to the user through a side-channel, _e.g._ through email, the user will:

1. Access the URL with the attached token.
2. Set the token in a cookie (recommended), or the client-storage mechanism that your application uses.
3. Remove the token from the URL and redirect the user to the password reset service. This ensures that protection against [referer leakage](https://portswigger.net/kb/issues/00500400_cross-domain-referer-leakage).
4. Let the user create a new password and confirm it. Ensure that the password policy is applied.

### Security Questions

Kindly refer to the [Security Questions Cheat Sheet](Choosing_and_Using_Security_Questions_Cheat_Sheet.md) for further guidance.

### Pin Codes

<!--Under study to provide good practices that are being used-->

## Operational Tasks

- Ask the user if they want to invaldiate all of the sessions, or invalidate the sessions by default without prompting the user.
- Send the user an email that their password has been reset.
- Ask the user to re-login. Don't auto-login users on password reset!
