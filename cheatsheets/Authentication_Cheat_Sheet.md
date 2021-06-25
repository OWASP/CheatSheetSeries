# Authentication Cheat Sheet

## Introduction

**Authentication** is the process of verifying that an individual, entity or website is whom it claims to be. Authentication in the context of web applications is commonly performed by submitting a username or ID and one or more items of private information that only a given user should know.

**Session Management** is a process by which a server maintains the state of an entity interacting with it. This is required for a server to remember how to react to subsequent requests throughout a transaction. Sessions are maintained on the server by a session identifier which can be passed back and forward between the client and server when transmitting and receiving requests. Sessions should be unique per user and computationally very difficult to predict. The [Session Management Cheat Sheet](Session_Management_Cheat_Sheet.md) contains further guidance on the best practices in this area.

## Authentication General Guidelines

### User IDs

Make sure your usernames/user IDs are case-insensitive. User 'smith' and user 'Smith' should be the same user. Usernames should also be unique. For high-security applications, usernames could be assigned and secret instead of user-defined public data.

#### Email address as a User ID

For information on validating email addresses, please visit the [input validation cheatsheet email discussion](Input_Validation_Cheat_Sheet.md#Email_Address_Validation).

### Authentication Solution and Sensitive Accounts

- Do **NOT** allow login with sensitive accounts (i.e. accounts that can be used internally within the solution such as to a back-end / middle-ware / DB) to any front-end user-interface
- Do **NOT** use the same Authentication solution (e.g. IDP / AD) used internally for unsecured access (e.g. public access / DMZ)

### Implement Proper Password Strength Controls

A key concern when using passwords for Authentication is password strength. A "strong" password policy makes it difficult or even improbable for one to guess the password through either manual or automated means. The following characteristics define a strong password:

- Password Length
    - **Minimum** length of the passwords should be **enforced** by the application. Passwords **shorter than 8 characters** are considered to be weak ([NIST SP800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html)).
    - **Maximum** password length should not be set **too low**, as it will prevent users from creating passphrases. A common maximum length is 64 characters due to limitations in certain hashing algorithms, as discussed in the [Password Storage Cheat Sheet](Password_Storage_Cheat_Sheet.md#maximum-password-lengths). It is important to set a maximum password length to prevent [long password Denial of Service attacks](https://www.acunetix.com/vulnerabilities/web/long-password-denial-of-service/).
- Do not silently truncate passwords. The [Password Storage Cheat Sheet](Password_Storage_Cheat_Sheet.md#maximum-password-lengths) provides further guidance on how to handle passwords that are longer than the maximum length.
- Allow usage of **all** characters including unicode and whitespace. There should be no password composition rules limiting the type of characters permitted.
- Ensure credential rotation when a password leak, or at the time of compromise identification.
- Include password strength meter to help users create a more complex password and block common and previously breached passwords
    - [zxcvbn library](https://github.com/dropbox/zxcvbn) can be used for this purpose. (Note that this library is no longer maintained)
    - [Pwned Passwords](https://haveibeenpwned.com/Passwords) is a service where passwords can be checked against previously breached passwords. You can host it yourself or use [API](https://haveibeenpwned.com/API/v3#PwnedPasswords).

#### For more detailed information check

- [ASVS v4.0 Password Security Requirements](https://github.com/OWASP/ASVS/blob/master/4.0/en/0x11-V2-Authentication.md#v21-password-security-requirements)
- [Passwords Evolved: Authentication Guidance for the Modern Era](https://www.troyhunt.com/passwords-evolved-Authentication-guidance-for-the-modern-era/)

### Implement Secure Password Recovery Mechanism

It is common for an application to have a mechanism that provides a means for a user to gain access to their account in the event they forget their password. Please see [Forgot Password Cheat Sheet](Forgot_Password_Cheat_Sheet.md) for details on this feature.

### Store Passwords in a Secure Fashion

It is critical for an application to store a password using the right cryptographic technique. Please see [Password Storage Cheat Sheet](Password_Storage_Cheat_Sheet.md) for details on this feature.

### Compare Password Hashes Using Safe Functions

Where possible, the user-supplied password should be compared to the stored password hash using a secure password comparison function provided by the language or framework, such as the [password_verify()](https://www.php.net/manual/en/function.password-verify.php) function in PHP. Where this is not possible, ensure that the comparison function:

- Has a maximum input length, to protect against denial of service attacks with very long inputs.
- Explicitly sets the type of both variable, to protect against type confusion attacks such as [Magic Hashes](https://www.whitehatsec.com/blog/magic-hashes/) in PHP.
- Returns in constant time, to protect against timing attacks.

### Transmit Passwords Only Over TLS or Other Strong Transport

See: [Transport Layer Protection Cheat Sheet](Transport_Layer_Protection_Cheat_Sheet.md)

The login page and all subsequent authenticated pages must be exclusively accessed over TLS or other strong transport. The initial login page referred to as the "login landing page", must be served over TLS or other strong transport. Failure to utilize TLS or other strong transport for the login landing page allows an attacker to modify the login form action, causing the user's credentials to be posted to an arbitrary location. Failure to utilize TLS or other strong transport for authenticated pages after login enables an attacker to view the unencrypted session ID and compromise the user's authenticated session.

### Require Authorization for Sensitive Features

Perform Authorization when any sensitive transaction is requested and before updating sensitive account information such as the user's password, user's email, or before sensitive transactions, such as shipping a purchase to a new address.

See: [Transaction Authorization Cheat Sheet](Transaction_Authorization_Cheat_Sheet.md).

Without an Authorization mechanism at the time of any sensitive transaction an attacker may be able to execute sensitive transactions unchallenged through a CSRF or XSS attack, unchallenged because Authorization is how you verify requester identity and that they have their current credentials. Without Authorization there is no challenges for an attacker and no need for them to know the user's current credentials or prove they are who they claim to be.

### Consider additional Authentication factors

Some applications should use a second factor to check whether a user may perform sensitive operations. For more information, see the [Transaction Authorization Cheat Sheet](Transaction_Authorization_Cheat_Sheet.md) that explains the role a second factor plays for Authorization.

#### TLS Client Authentication

TLS Client Authentication is Mutual-TLS, also known as mTLS, which consists of both browser and server sending their respective TLS certificates to each other during the TLS handshake process.
Just as you can validate the authenticity of a server by using the certificate and asking a well known Certificate Authority (CA) if the certificate is valid, the server can authenticate the client device by receiving a certificate from the client and validating against it's corresponding public CA (or private CA if both client and server share a private network).
To do this, the server must provide the client with a certificate generated specifically for the client machine identity, assigning values to the _subject_ that are used to determine appropriate validation.
To enable Mutual-TLS the client machine must install the certificate to the client operating system certificate store, or install to a browser certificate store directly. Enterprise software known as Mobile Device Management (MDM) or Active Directory Group Policy are common tools to automate this certification distribution and installation, and there are visual interfaces for most browsers and operating systems if an end-user must install the client certificate manually themselves.

It is a good idea to do this when:

- It is acceptable (or even preferred) that the user only has access to the website from only a _single identity_ either on a single computer and browser or spanning multiple computers and browsers
- Lacking automation of certificate distribution nd installation, the user is not easily scared by the process of installing TLS certificates on their browser, or there will be someone, probably from IT support, that will do this for the user.
- The website or server requires assurance of the client machine identity to increase the security for the user when connecting to the website or server.
- Mutual-TLS is commonly needed to use internal websites, on an intranet, of a company or organization.

What concerns and issues to be aware of:

- It is generally considered not a good idea to use this method for widely or publicly available websites that will have an average user. For example, it wouldn't be a good idea to implement this for a website like Facebook unless it is expected that all users install a special Facebook certificate on every user device which might limit Facebook users to those who cannot or will not install aforementioned certificate
- While this technique can prevent the user from having to type a password (thus protecting against an average keylogger from stealing it), it is still considered a good idea to consider using some challenge-response mechanism like password as well as the Mutual-TLS client Authentication combined for Authorization purposes.

If the client is behind an forward proxy which performs network traffic inspection, this may interfere with Mutual-TLS Client Authentication depending on the server-side configuration of the website and configuration relationship with the forward proxy.

For more information, see: [Client-authenticated TLS handshake](https://en.wikipedia.org/wiki/Transport_Layer_Security#Client-authenticated_TLS_handshake)

### Authentication and Error Messages

Incorrectly implemented error messages in the case of Authentication functionality can be used for the purposes of user ID and password enumeration. An application should respond (both HTTP and HTML) in a generic manner.

#### Authentication Responses

Using any of the Authentication mechanisms (login, password reset or password recovery), an application must respond with a generic error message (and typically using HTTP Response code 403 and no significantly different response time) regardless of whether:

- The user ID or password was incorrect.
- The account does not exist.
- The account is locked or disabled.

The account registration feature should also be taken into consideration, and the same approach of generic error message can be applied regarding the case in which the new user data exists as a previously registered user. Leaking previously known user data can be used by attackers to derive correct information from a dataset which has both unknown and valid data.

The objective is to prevent the creation of a [discrepancy factor](https://cwe.mitre.org/data/definitions/204.html), allowing an attacker to mount a user enumeration action against the application.

It is interesting to note that the business logic itself can bring a discrepancy factor related to the processing time taken. Indeed, depending on the implementation, the processing time can be significantly different according to the case (success vs failure) allowing an attacker to mount a [time-based attack](https://en.wikipedia.org/wiki/Timing_attack) (delta of some seconds for example).

Example using pseudo-code for a login feature:

- First implementation using the "quick exit" approach

```text
IF USER_EXISTS(username) THEN
    password_hash=HASH(password)
    IS_VALID=LOOKUP_CREDENTIALS_IN_STORE(username, password_hash)
    IF NOT IS_VALID THEN
        RETURN Error("Invalid Username or Password!")
    ENDIF
ELSE
   RETURN Error("Invalid Username or Password!")
ENDIF
```

It can be clearly seen that if the user doesn't exist, the application will directly throw an error. Otherwise, when the user exists and the password doesn't, it is apparent that there will be more processing before the application errors out. In return, the response time will be different for the same error, allowing the attacker to differentiate between a wrong username and a wrong password.

- Second implementation without relying on the "quick exit" approach:

```text
password_hash=HASH(password)
IS_VALID=LOOKUP_CREDENTIALS_IN_STORE(username, password_hash)
IF NOT IS_VALID THEN
   RETURN Error("Invalid Username or Password!")
ENDIF
```

This code will go through the same process no matter what the user or the password is, allowing the application to return in approximately the same response time.

The problem with returning a generic error message for the user is a User Experience (UX) matter. A legitimate user might feel confused with the generic messages, thus making it hard for them to use the application, and might after several retries, leave the application because of its complexity. The decision to return a *generic error message* can be determined based on the criticality of the application and its data. For example, for critical applications, the team can decide that under the failure scenario, a user will always be redirected to the support page and a *generic error message* will be returned.

Regarding the user enumeration itself, protection against [brute-force attack](#protect-against-automated-attacks) are also effective because they prevent an attacker from applying the enumeration at scale. Usage of [CAPTCHA](https://en.wikipedia.org/wiki/CAPTCHA) can be applied on a feature for which a *generic error message* cannot be returned because the *user experience* must be preserved.

##### Incorrect and correct response examples

###### Login

Incorrect response examples:

- "Login for User foo: invalid password."
- "Login failed, invalid user ID."
- "Login failed; account disabled."
- "Login failed; this user is not active."

Correct response example:

- "Login failed; Invalid user ID or password."

###### Password recovery

Incorrect response examples:

- "We just sent you a password reset link."
- "This email address doesn't exist in our database."

Correct response example:

- "If that email address is in our database, we will send you an email to reset your password."

###### Account creation

Incorrect response examples:

- "This user ID is already in use."
- "Welcome! You have signed up successfully."

Correct response example:

- "A link to activate your account has been emailed to the address provided."

##### Error Codes and URLs

The application may return a different [HTTP Error code](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status) depending on the Authentication attempt response. It may respond with a 200 for a positive result and a 403 for a negative result. Even though a generic error page is shown to a user, the HTTP response code may differ which can leak information about whether the account is valid or not.

Error disclosure can also be used as a discrepancy factor, consult the [error handling cheat sheet](Error_Handling_Cheat_Sheet.md) regarding the global handling of different errors in an application.

### Protect Against Automated Attacks

There are a number of different types of automated attacks that attackers can use to try and compromise user accounts. The most common types are listed below:

| Attack Type | Description |
|-------------|-------------|
| Brute Force | Testing multiple passwords from a dictionary or other source against a single account. |
| Credential Stuffing | Testing username/password pairs obtained from the breach of another site. |
| Password Spraying | Testing a single weak password against a large number of different accounts.|

Different protection mechanisms can be implemented to protect against these attacks. In many cases, these defences do not provide complete protection, but when a number of them are implemented in a defence-in-depth approach, a reasonable level of protection can be achieved.

The following sections will focus primarily on preventing brute-force attacks, although these controls can also be effective against other types of attacks. For further guidance on defending against credential stuffing and password spraying, see the [Credential Stuffing Cheat Sheet](Credential_Stuffing_Prevention_Cheat_Sheet.md).

#### Multi-Factor Authentication

Multi-factor Authentication (MFA) is by far the best defence against the majority of password-related attacks, including brute-force attacks, with analysis by Microsoft suggesting that it would have stopped [99.9% of account compromises](https://techcommunity.microsoft.com/t5/Azure-Active-Directory-Identity/Your-Pa-word-doesn-t-matter/ba-p/731984). As such, it should be implemented wherever possible; however, depending on the audience of the application, it may not be practical or feasible to enforce the use of MFA.

The [Multifactor Authentication Cheat Sheet](Multifactor_Authentication_Cheat_Sheet.md) contains further guidance on implementing MFA.

#### Account Lockout

The most common protection against these attacks is to implement account lockout, which prevents any more login attempts for a period after a certain number of failed logins.

The counter of failed logins should be associated with the account itself, rather than the source IP address, in order to prevent an attacker from making login attempts from a large number of different IP addresses. There are a number of different factors that should be considered when implementing an account lockout policy in order to find a balance between security and usability:

- The number of failed attempts before the account is locked out (lockout threshold).
- The time period that these attempts must occur within (observation window).
- How long the account is locked out for (lockout duration).

Rather than implementing a fixed lockout duration (e.g., ten minutes), some applications use an exponential lockout, where the lockout duration starts as a very short period (e.g., one second), but doubles after each failed login attempt.

When designing an account lockout system, care must be taken to prevent it from being used to cause a denial of service by locking out other users' accounts. One way this could be performed is to allow the user of the forgotten password functionality to log in, even if the account is locked out.

#### CAPTCHA

The use of an effective CAPTCHA can help to prevent automated login attempts against accounts. However, many older CAPTCHA implementations have weaknesses that allow them to be solved using automated techniques or can be outsourced to services which can solve them. As such, the use of CAPTCHA should be viewed as a defence-in-depth control to make brute-force attacks more time consuming and expensive, rather than as a preventative. New CAPTCHA implementations require no user interaction and therefore avoid automation that leverages visual pattern matching entirely (and have no user friction at all).

It may be more user-friendly to only require a older CAPTCHA where solving visual patterns after a small number of failed login attempts, rather than requiring it from the very first login. Where possible you should always use the new CAPTCHA implementations that have no user interaction, for all sensitive transactions.

#### Security Questions and Memorable Words

The addition of a security question or memorable word can also help protect against automated attacks, especially when the user is asked to enter a number of randomly chosen characters from the word. It should be noted that this does **not** constitute multi-factor Authentication, as both factors are the same (something you know). Furthermore, security questions are often weak and have predictable answers, so they must be carefully chosen. The [Choosing and Using Security Questions cheat sheet](Choosing_and_Using_Security_Questions_Cheat_Sheet.md) contains further guidance on this.

## Logging and Monitoring

Enable logging and monitoring of Authentication functions to detect attacks/failures on a real-time basis

- Ensure that all failures are logged and reviewed
- Ensure that all password failures are logged and reviewed
- Ensure that all account lockouts are logged and reviewed

## Use of Authentication protocols that require no password

While Authentication through a user/password combination and using multi-factor Authentication is considered generally secure, there are use cases where it isn't considered the best option or even safe. Examples of this are third party applications that desire connecting to the web application, either from a mobile device, another website, desktop or other situations. When this happens, it is NOT considered safe to allow the third-party application to store the user/password combo, since then it extends the attack surface into their hands, where it isn't in your control. For this, and other use cases, there are several Authentication protocols that can protect you from exposing your users' data to attackers.

### OAuth

Open Authorization (OAuth) is a protocol that allows an application to trust Authentication of a user against a prior established Authentication mechanism for ongoing Authorization decisions, [OAuth is not an Authentication protocol](https://oauth.net/articles/Authentication/). In some cases the Authentication occurs without requiring passwords depending on the chosen prior established Authentication mechanism that OAuth has been configured to convey.

OAuth is providing Authorization and will generate a token representing a trust relationship so that a client, such as a mobile application, can assure a serverof their authority to perform delegated requests on behalf of a trusted identity.

The recommendation is to use and implement OAuth 2.0 due to flaws and vulnerabilities found in previous versions, such as session fixation and exposing secrets in plain text during communication. OAuth 2.0 mandates HTTPS for transport security.

### OpenID Connect (OIDC)

OpenID Connect is an HTTP-based protocol built on top of OAuth 2.0 that uses identity providers to validate that a user is whom they say they are.
It is a very simple protocol which allows a service provider to provide single sign-on (SSO). This allows the user to re-use a single identity given to a trusted OIDC identity provider and be the same user in multiple websites, without the need to provide any website with the password, except for the OIDC identity provider.

Due to its simplicity and that it provides protection of passwords, OIDC has been well adopted. Some of the well-known identity providers for OIDC are Stack Exchange, Google, Facebook and Yahoo!

For non-enterprise environments, OIDC is considered a secure and often better choice, as long as the OIDC identity provider is trusted.

### SAML

Security Assertion Markup Language (SAML) is often considered to compete with OIDC. The most recommended version is 2.0 since it is considered to be 'feature complete' and has no known systemic vulnerabilities, though many implementation flaws and weaknesses exist. Like OIDC, SAML uses identity providers, but unlike OIDC, it is XML-based and provides more flexibility. SAML is based on browser redirects which send XML data. Furthermore, SAML isn't only initiated by a service provider; it can also be initiated from the identity provider. This allows the user to navigate through different portals while still being authenticated without having to do anything, making the process transparent.

While OIDC has taken most of the consumer market, SAML is often the choice for enterprise applications. The reason for this is often that there are few OIDC identity providers which are considered of enterprise-class (meaning that the way they validate the user identity doesn't have high standards required for enterprise identity). It is more common to see SAML being used inside of intranet websites, sometimes even using a server from the intranet as the identity provider.

In the past few years, applications like SAP ERP and SharePoint (SharePoint by using Active Directory Federation Services 2.0) have decided to use SAML 2.0 Authentication as an often preferred method for single sign-on implementations whenever enterprise federation is required for web services and web applications.

**See also: [SAML Security Cheat Sheet](SAML_Security_Cheat_Sheet.md)**

### FIDO

The Fast Identity Online (FIDO) Alliance has created two protocols to facilitate online Authentication: the Universal Authentication Framework (UAF) protocol and the Universal Second Factor (U2F) protocol. While UAF focuses on password-less Authentication, U2F allows the addition of a second factor to existing password-based Authentication. Both protocols are based on a public key cryptography challenge-response model.

UAF takes advantage of existing security technologies present on devices for Authentication including fingerprint sensors, cameras(face biometrics), microphones(voice biometrics), Trusted Execution Environments(TEEs), Secure Elements(SEs) and others. The protocol is designed to plug-in these device capabilities into a common Authentication framework. UAF works with both native applications and web applications.

U2F augments password-based Authentication using a hardware token (typically USB) that stores cryptographic keys and uses them for signing. The user can use the same token as a second factor for Authorization of multiple applications. U2F works with web applications. It provides **protection against phishing** by using the URL of the website to look up the stored cryptographic key.

## Password Managers

Password managers are programs, browser plugins or web services that automate management of large number of different credentials. Most password managers have functionality to allow users to easily use them on websites, either by pasting the passwords into the login form, or by simulating the user typing them in.

Web applications should at least not make password managers job more difficult than necessary by observing the following recommendations:

- Use standard HTML forms for username and password input with appropriate `type` attributes.
    - Avoid plugin-based login pages (such as Flash or Silverlight).
- Implement a reasonable maximum password length, such as 64 characters, as discussed in the [Password Storage Cheat Sheet](Password_Storage_Cheat_Sheet.md#maximum-password-lengths).
- Allow any printable characters to be used in passwords.
- Allow users to paste into the username and password fields.
- Allow users to navigate between the username and password field with a single press of the `Tab` key.
