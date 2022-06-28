# Multi-Factor Authentication Cheat Sheet

## Introduction

Multi-Factor authentication (MFA), or Two-Factor Authentication (2FA) is when a user is required to present more than one type of evidence in order to authenticate on a system. There are four different types of evidence (or factors) that can be used, listed in the table below:

| Factor | Examples |
|--------|----------|
| Something You Know | Passwords, PINs and security questions. |
| Something You Have | Hardware or software tokens, certificates, email, SMS and phone calls. |
| Something You Are | Fingerprints, facial recognition, iris scans and handprint scans. |
| Location | Source IP ranges and geolocation |

It should be emphasised that while requiring multiple examples of a single factor (such as needing both a password and a PIN) **does not constitute MFA**, although it may provide some security benefits over a simple password.

Additionally, while the following sections discuss the disadvantage and weaknesses of various different types of MFA, in many cases these are only relevant against targeted attacks. **Any MFA is better than no MFA**.

## Advantages

The most common way that user accounts get compromised on applications is through weak, re-used or stolen passwords. Despite any technical security controls implemented on the application, users are liable to choose weak passwords, or to use the same password on different applications. As developers or system administrators, it should be assumed that users' passwords will be compromised at some point, and the system should be designed in order to defend against this.

Multi-factor authentication (MFA) is by far the best defense against the majority of password-related attacks, including brute-force, [credential stuffing](Credential_Stuffing_Prevention_Cheat_Sheet.md) and password spraying, with analysis by Microsoft suggesting that it would have stopped [99.9% of account compromises](https://techcommunity.microsoft.com/t5/Azure-Active-Directory-Identity/Your-Pa-word-doesn-t-matter/ba-p/731984).

## Disadvantages

The biggest disadvantage of MFA is the increase in management complexity for both administrators and end users. Many less technical users may find it difficult to configure and use MFA. Additionally, there are a number of other common issues encountered:

- Types of MFA that require users to have specific hardware can introduce significant costs and administrative overheads.
- Users may become locked out of their accounts if they lose or are unable to use their other factors.
- MFA introduces additional complexity into the application.
- Many MFA solutions add external dependencies to systems, which can introduce security vulnerabilities or single points of failure.
- Processes implemented to allow users to bypass or reset MFA may be exploitable by attackers.
- Requiring MFA may prevent some users from accessing the application.

## Quick Recommendations

Exactly when and how MFA is implemented in an application will vary on a number of different factors, including the threat model of the application, the technical level of the users, and the level of administrative control over the users. These need to be considered on a per-application basis.

However, the following recommendations are generally appropriate for most applications, and provide an initial starting point to consider.

- Provide the option for users to enable MFA on their accounts using [TOTP](#software-totp-tokens).
- Require MFA for administrative or other high privileged users.
- Consider allowing corporate IP ranges so that MFA is not required from them.
- Allow the user to remember the use of MFA in their browser, so they are not prompted every time they login.
- Implement a secure process to allow users to reset their MFA.

## Implementing MFA

### When to Require MFA

The most important place to require MFA on an application is when the user logs in. However, depending on the functionality available, it may also be appropriate to require MFA for performing sensitive actions, such as:

- Changing passwords or security questions.
- Changing the email address associated with the account.
- Disabling MFA.
- Elevating a user session to an administrative session.

If the application provides multiple ways for a user to authenticate these should all require MFA, or have other protections implemented. A common area that is missed is if the application provides a separate API that can be used to login, or has an associated mobile application.

### Improving Usability

Having to frequently login with MFA creates an additional burden for users, and may cause them to disable MFA on the application. A number of mechanisms can be used to try and reduce the level of annoyance that MFA causes. However, these types of measures do decrease the security provided by MFA, so need to be risk assessed to find a reasonable balance of security and usability for the application.

- Remembering the user's browser so they don't need to use MFA every time.
    - This can either be permanent, or for a period of a few days.
    - This needs to be done with more than just a cookie, which could be stolen by an attacker.
        - For example, a cookie matched to the previous IP address the cookie was issued for.
- Allow corporate IP ranges (or, more strictly, using location as a second factor).
    - This doesn't protect against malicious insiders, or a user's workstation being compromised.
- Only requiring MFA for sensitive actions, not for the initial login.
    - This will depend heavily on the functionality in the application.

### Failed Login Attempts

When a user enters their password, but fails to authenticate using a second factor, this could mean one of two things:

- The user has lost their second factor, or doesn't have it available (for example, they don't have their mobile phone, or have no signal).
- The user's password has been compromised.

There are a number of steps that should be taken when this occurs:

- Prompt the user to try another form of MFA
    - For example, an SMS code rather than using their hardware OTP token.
- Allow the user to attempt to [reset their MFA](#resetting-mfa).
- Notify the user of the failed login attempt, and encourage them to change their password if they don't recognize it.
    - The notification should include the time, browser and geographic location of the login attempt.
    - This should be displayed next time they login, and optionally emailed to them as well.

### Resetting MFA

One of the biggest challenges with implementing MFA is handling users who forget or lose their second factors. There are many ways this could happen, such as:

- Re-installing a workstation without backing up digital certificates.
- Wiping or losing a phone without backing up OTP codes.
- Changing mobile numbers.

In order to prevent users from being locked out of the application, there needs to be a mechanism for them to regain access to their account if they can't use their existing MFA; however it is also crucial that this doesn't provide an attacker with a way to bypass MFA and hijack their account.

There is no definitive "best way" to do this, and what is appropriate will vary hugely based on the security of the application, and also the level of control over the users. Solutions that work for a corporate application where all the staff know each other are unlikely to be feasible for a publicly available application with thousands of users all over the world. Every recovery method has its own advantages and disadvantages, and these need to be evaluated in the context of the application.

Some suggestions of possible methods include:

- Providing the user with a number of single-use recovery codes when they first setup MFA.
- Requiring the user to setup multiple types of MFA (such as a digital certificate, OTP core and phone number for SMS), so that they are unlikely to lose access to all of them at once.
- Posting a one-use recovery code (or new hardware token) to the user.
- Requiring the user contact the support team and having a rigorous process in place to verify their identity.
- Requiring another trusted user to vouch for them.

## Something You Know

The most common type of authentication is based on something the users knows - typically a password. The biggest advantage of this factor is that it has very low requirements for both the developers and the end user, as it does not require any special hardware, or integration with other services.

### Passwords and PINs

Passwords and PINs are the most common form of authentication due to the simplicity of implementing them. The [Authentication Cheat Sheet](Authentication_Cheat_Sheet.md#implement-proper-password-strength-controls) has guidance on how to implement a strong password policy, and the [Password Storage Cheat Sheet](Password_Storage_Cheat_Sheet.md) has guidance on how to securely store passwords.

Most multi-factor authentication systems make use of a password, as well as at least one other factor.

It should be noted that PINs, "secret words" and other similar type of information are all effectively the same as passwords. Using two different types of passwords **does not constitute MFA**.

#### Pros

- Simple and well understood.
- Native support in every authentication framework.
- Easy to implement.

#### Cons

- Users are prone to choosing weak passwords.
- Passwords are commonly re-used between systems.
- Susceptible to phishing.

### Security Questions

Security questions require the user to choose (or create) a number of questions that only they will know the answer to. These are effectively the same as passwords, although they are generally considered weaker. The [Choosing and Using Security Questions Cheat Sheet](Choosing_and_Using_Security_Questions_Cheat_Sheet.md) contains further guidance on how to implement these securely.

#### Pros

- Simple and well understood.

#### Cons

- Questions often have easily guessable answers.
- Answers to questions can often be obtained from social media or other sources.
- Questions must be carefully chosen so that users will remember answers years later.
- Susceptible to phishing.

## Something You Have

The second factor is something that the user possesses. This could be a physical item (such as a hardware token), a digital item (such as a certificate or private key), or based on the ownership of a mobile phone, phone number, or email address (such as SMS or a software token installed on the phone, or an email with a single-use verification code).

If properly implemented then this can be significantly more difficult for a remote attacker to compromise; however it also creates an additional administrative burden on the user, as they must keep the authentication factor with them whenever they wish to use it.

The requirement to have a second factor can also limit certain types of users' ability to access a service. For example, if a user does not have access to a mobile phone, many types of MFA will not be available for them.

### Hardware OTP Tokens

Physical hardware OTP tokens can be used which generate constantly changing numeric codes, which must be submitted when authentication on the application. Most well-known of these is the [RSA SecureID](https://en.wikipedia.org/wiki/RSA_SecurID), which generates a six digit number that changes every 60 seconds.

#### Pros

- As the tokens are separate physical devices, they are almost impossible for an attacker to compromise remotely.
- Tokens can be used without requiring the user to have a mobile phone or other device.

#### Cons

- Deploying physical tokens to users is expensive and complicated.
- If a user loses their token it could take a significant amount of time to purchase and ship them a new one.
- Some implementations require a backend server, which can introduce new vulnerabilities as well as a single point of failure.
- Stolen tokens can be used without a PIN or device unlock code.
- Susceptible to phishing (although short-lived).

### Software TOTP Tokens

A cheaper and easier alternative to hardware tokens is using software to generate Time-based One Time Password (TOTP) codes. This would typically involve the user installing a TOTP application on their mobile phone, and then scanning a QR code provided by the web application which provides the initial seed. The authenticator app then generates a six digit number every 60 seconds, in much the same way as a hardware token.

Most websites use standardized TOTP tokens, allowing the user to install any authenticator app that supports TOTP. However, a small number of applications use their own variants of this (such as Symantec), which requires the users to install a specific app in order to use the service. This should be avoided in favour of a standards-based approach.

#### Pros

- The absence of physical tokens greatly reduces the cost and administrative overhead of implementing the system.
- When users lose access to their TOTP app, a new one can be configured without needing to ship a physical token to them.
- TOTP is widely used, and many users will already have at least one TOTP app installed.
- As long as the user has a screen lock on their phone, an attacker will be unable to use the code if they steal the phone.

#### Cons

- TOTP apps are usually installed on mobile devices, which are vulnerable to compromise.
- The TOTP app may be installed on the same mobile device (or workstation) that is used to authenticate.
- Users may store the backup seeds insecurely.
- Not all users have mobile devices to use with TOTP.
- If the user's mobile device is lost, stolen or out of battery, they will be unable to authenticate.
- Susceptible to phishing (although short-lived).

### Hardware U2F Tokens

Hardware U2F tokens communicate with the users workstation over USB or NFC, and implement challenge-response based authentication, rather than requiring the user to manually enter the code. This would typically be done by the user pressing a button on the token, or tapping it against their NFC reader.

#### Pros

- Longer codes can be used, which may provide a higher level of security.
- Users can simply press a button rather than typing in a code.
- Resistant to phishing.

#### Cons

- As with hardware OTP tokens, the use of physical tokens introduces significant costs and administrative overheads.
- Stolen tokens can be used without a PIN or device unlock code.
- As the tokens are usually connected to the workstation via USB, users are more likely to forget them.

### Certificates

Digital certificates are files that are stored on the user's device which are automatically provided alongside the user's password when authenticating. The most common type is X.509 certificates (discussed in the [Transport Layer Protection Cheat Sheet](Transport_Layer_Protection_Cheat_Sheet.md#consider-the-use-of-client-side-certificates)), more commonly known as client certificates.

Certificates are supported by all major web browsers, and once installed require no further interaction from the user. The certificates should be linked to an individual's user account in order to prevent users from trying to authenticate against other accounts.

#### Pros

- There is no need to purchase and manage hardware tokens.
- Once installed, certificates are very simple for users.
- Certificates can be centrally managed and revoked.
- Resistant to phishing.

#### Cons

- Using digital certificates requires backend PKI system.
- Installing certificates can be difficult for users, particularly in a highly restricted environment.
- Enterprise proxy servers which perform SSL decryption will prevent the use of certificates.
- The certificates are stored on the user's workstation, and as such can be stolen if their system is compromised.

### Smartcards

Smartcards are credit-card size cards with a chip containing a digital certificate for the user, which is unlocked with a PIN. They are commonly used for operating system authentication, but are rarely used in web applications.

#### Pros

- Stolen smartcards cannot be used without the PIN.
- Smartcards can be used across multiple applications and systems.
- Resistant to phishing.

#### Cons

- Managing and distributing smartcards has the same costs and overheads as hardware tokens.
- Smartcards are not natively supported by modern browsers, so require third party software.
- Although most business-class laptops have smartcard readers built in, home systems often do not.
- The use of smartcards requires functioning backend PKI systems.

### SMS Messages and Phone Calls

SMS messages or phone calls can be used to provide users with a single-use code that they must submit as a second factor.

#### Pros

- Relatively simple to implement.
- Requires user to link their account to a mobile number.

#### Cons

- Requires the user to have a mobile device or landline.
- Require user to have signal to receive the call or message.
- Calls and SMS messages may cost money to send (need to protect against attackers requesting a large number of messages to exhaust funds.
- A number of attacks against SMS or mobile numbers have been demonstrated and exploited in the past.
- SMS messages may be received on the same device the user is authenticating from.
- Susceptible to phishing.

### Email

Email verification requires that the user enters a code or clicks a link sent to their email address. There is some debate as to whether email constitutes a form of MFA, because if the user does not have MFA configured on their email account, it simply requires knowledge of the user's email password (which is often the same as their application password). However, it is included here for completeness.

#### Pros

- Very easy to implement.
- No requirements for separate hardware or a mobile device.

#### Cons

- Relies entirely on the security of the email account, which often lacks MFA.
- Email passwords are commonly the same as application passwords.
- Provides no protection if the user's email is compromised first.
- Email may be received by the same device the user is authenticating from.
- Susceptible to phishing.

## Something You Are

The final factor in the traditional view of MFA is something you are - which is one of the physical attributes of the users (often called biometrics). Biometrics are rarely used in web applications due to the requirement for users to have specific hardware.

### Biometrics

The are a number of common types of biometrics that are used, including:

- Fingerprint scans
- Facial recognition
- Iris scans
- Handprint scans

#### Pros

- Well-implemented biometrics are hard to spoof, and require a targeted attack.

#### Cons

- Require manual enrolment of the user's physical attributes.
- Custom (sometimes expensive) hardware is often required to read biometrics.
- Modern browsers do not have native support, so custom client-side software is required.
- Privacy concerns: Sensitive physical information must be stored about users.
- If compromised, biometric data can be difficult to change.

## Location

The use of location as a fourth factor for MFA is not fully accepted;  however, it is increasingly be used for authentication. It is sometimes argued that location is used when deciding whether or not to require MFA (as discussed [above](#when-to-require-mfa)) however this is effectively the same as considering it to be a factor in its own right. Two prominent examples of this are the [Conditional Access Policies](https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/overview) available in Microsoft Azure, and the [Network Unlock](https://docs.microsoft.com/en-us/windows/security/information-protection/bitlocker/bitlocker-how-to-enable-network-unlock) functionality in BitLocker.

When talking about location, access to the application that the user is authenticating against is not usually considered (as this would always be the case, and as such is relatively meaningless).

### Source IP Ranges

The source IP address the user is connecting from can be used as a factor, typically in an allow-list based approach. This could either be based on a static list (such as corporate office ranges) or a dynamic list (such as previous IP addresses the user has authenticated from).

#### Pros

- Very easy for users.
- Requires minimal configuration and management from administrative staff.

#### Cons

- Doesn't provide any protection if the user's system is compromised.
- Doesn't provide any protection against rogue insiders.
- Trusted IP addresses must be carefully restricted (for example, if the open guest Wi-Fi uses the main corporate IP range).

### Geolocation

Rather than using the exact IP address of the user, the geographic location that the IP address is registered to can be used. This is less precise, but may be more feasible to implement in environments where IP addresses are not static. A common usage would be to require additional authentication factors when an authentication attempt is made from outside of the user's normal country.

#### Pros

- Very easy for users

#### Cons

- Doesn't provide any protection if the user's system is compromised.
- Doesn't provide any protection against rogue insiders.
- Easy for an attacker to bypass by obtaining IP addresses in the trusted country or location.
