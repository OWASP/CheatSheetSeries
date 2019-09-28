# Introduction

Multifactor authentication (MFA), or Two-Factor Authentication (2FA) is when a user is required to present more than one type of evidence in order to authenticate on a system. There are four different types of evidence (or factors) that can be used, listed in the table below:

| Factor | Examples |
|--------|----------|
| Something You Know | Passwords, PINs and security questions. |
| Something You Have | Hardware or software tokens, certificates, email, SMS and phone calls. |
| Something You Are | Fingerprints, facial recognition, iris scans and handprint scans. |
| Location | Source IP ranges and geolocation |

It should be emphasised that while requiring multiple examples of a single factor (such as needing both a password and a PIN) **does not constitute MFA**, although it may provide some security benefits over a simple password.

# Advantages

The most common way that user accounts get compromised on applications is through weak, re-used or stolen passwords. Despite any technical security controls implemented on the application, users are liable to choose weak passwords, or to use the same password on different applications. As developers or system administrators, it should be assumed that users' passwords will be compromised as some point, and the system should be designed in order to defend against this.

Multi-factor authentication (MFA) is by far the best defense against the majority of password-related attacks, including brute-force, [credential stuffing](Credential_Stuffing_Prevention_Cheat_Sheet.md) and password spraying, with analysis by Microsoft suggesting that it would have stopped [99.9% of account compromises](https://techcommunity.microsoft.com/t5/Azure-Active-Directory-Identity/Your-Pa-word-doesn-t-matter/ba-p/731984).

# Disadvantages

The biggest disadvantage of MFA is the increase in management complexity for both administrators and end users. Many less technical users may find it difficult to configure and use MFA. Additionally, there are a number of other common issues encountered:

- Types of MFA that require users to have specific hardware can introduce significant costs and administrative overheads.
- Users may become locked out of their accounts if they lose or are unable to use their other factors.
- MFA introduces additional complexity into the application.
- Many MFA solutions add external dependencies to systems, which can introduce security vulnerabilities or single points of failure.
- Processes implemented to allow users to bypass or reset MFA may be exploitable by attackers.
- Requiring MFA may prevent some users from accessing the application.

# Quick Recommendations

Exactly when and how MFA is implemented in an application will vary on a number of different factors, including the threat model of the application, the technical level of the users, and the level of administrative control over the users. These need to be considered on a per-application basis.

However, the following recommendations are generally appropriate for most applications, and provide an initial starting point to consider.

- Provide the option for users to enable MFA on their accounts using [TOTP](#software-otp-tokens).
- Require MFA for administrative or other high privileged users.
- Consider whitelisting corporate IP ranges so that MFA is not required from them.
- Allow the user to remember the use of MFA in their browser, so they are not prompted every time they login.
- Implement a secure process to allow users to reset their MFA.

# Implementing MFA

## When to Require MFA

The most important place to require MFA on an application is when the user logs in. However, depending on the functionality available, it may also be appropriate to require MFA for performing sensitive actions, such as:

- Changing passwords or security questions.
- Changing the email address associated with the account.
- Disabling MFA.
- Elevating a user session to an administrative session.

If the application provides multiple ways for a user to authenticate these should all require MFA, or have other protections implemented. A common area that is missed is if the application provides a separate API that can be used to login, or has an associated mobile application.

## Improving Usability

Having to frequently login with MFA creates an additional burden for users, and may cause them to disable MFA on the application. A number of mechanisms can be used to try and reduce the level of annoyance that MFA causes. However, these types of measures do decrease the security provided by MFA, so need to be risk assessed to find a reasonable balance of security and usability for the application.

- Remembering the user's browser so they don't need to use MFA every time.
  - This can either be permanent, or for a period of a few days.
  - This needs to be done with more than just a cookie, which could be stolen by an attacker.
- Whitelisting corporate IP ranges (or, more strictly, using location as a second factor).
  - This doesn't protect against malicious insiders, or a user's workstation being compromised.
- Only requiring MFA for sensitive actions, not for the initial login.
  - This will depend heavily on the functionality in the application.

## Resetting MFA

One of the biggest challenges with implementing MFA is handling users who forget or lose their second factors. There are many ways this could happen, such as:

- Re-installing a workstation without backing up digital certificates.
- Wiping or losing a phone without backing up OTP codes.
- Changing mobile numbers.

In order to prevent users from being locked out of the application, there needs to be a mechanism for them to regain access to their account if they can't use their existing MFA; however it is also crucial that this doesn't provide an attacker with a way to bypass MFA and hijack there account.

There is no definitive "best way" to do this, and what is appropriate will vary hugely based on the security of the application, and also the level of control over the users. Solutions that work for a corporate application where all the staff know each other are unlikely to be feasible for a publicly available application with thousands of users all over the world. Every recovery methods has its own advantages and disadvantages, and these need to be evaluated in the context of the application.

Some suggestions of possible methods include:

- Providing the user with a number of single-use recovery codes when they first setup MFA.
- Requiring the user to setup multiple types of MFA (such as a digital certificate, OTP core and phone number for SMS), so that they are unlikely to lose access to all of them at once.
- Posting a one-use recovery code (or new hardware token) to the user.
- Requiring the user contact the support team and having a rigorous process in place to verify their identity.
- Requiring another trusted user to vouch for them.

# Something You Know

The most common type of authentication is based on something the users knows - typically a password. The biggest advantage of this factor is that it has very low requirements for both the developers and the end user, as it does not require any special hardware, or integration with other services.

## Passwords and PINs

Passwords and PINs are the most common form of authentication due to the simplicity of implementing them. The [Authentication Cheat Sheet](Authentication_Cheat_Sheet.md#implement-proper-password-strength-controls) has guidance on how to implement a strong password policy, and the [Password Storage Cheat Sheet](Password_Storage_Cheat_Sheet.md) has guidance on how to securely store passwords.

Most multifactor authentication systems make use of a password, as well as at least one other factor.

It should be noted that PINs, "secret words" and other similar type of information are all effectively the same as passwords. Using two different types of passwords **does not constitute MFA**.

### Pros

- Simple and well understood.
- Native support in every authentication framework.
- Easy to implement.

### Cons

- Users are prone to choosing weak passwords.
- Passwords are commonly re-used between systems.

## Security Questions

Security questions require the user to choose (or create) a number of questions that only they will know the answer to. These are effectively the same as passwords, although they are generally considered weaker. The [Choosing and Using Security Questions Cheat Sheet](Choosing_and_Using_Security_Questions_Cheat_Sheet.md) contains further guidance on how to implement these securely.

### Pros

- Simple and well understood.

### Cons

- Questions often have easily guessable answers.
- Answers to questions can often be obtained from social media or other sources.
- Questions must be carefully chosen so that users will remember answers years later.

# Something You Have

## Hardware OTP Tokens

- Hardware tokens which generate changing random numbers

### Pros

- Hard to attack
- Time-limited codes

### Cons

- Expensive
- Administrative complexity
- Can be lost or stolen

## Software OTP Tokens

### Pros

- Free

### Cons

- Require a mobile device
- Insecure storage of backup keys

## Hardware U2F Tokens

### Pros

- Ease of use

### Cons

- Expensive
- Administrative complexity
- Can be lost or stolen

## Certificates

### Pros

- Free
- Ease of use once installed

### Cons

- Complex for users to install
- Don't work properly with SSL decrypting proxies
- Stored on computer, so easily stolen in compromise

## Email

### Pros

- Easiest to implement
- No additional requirements for user

### Cons

- Lack of security for email account
  - Passwords re-use
  - Email forwarding
  - No protection if email already compromised
- Email usually on same device as login attempt

## SMS Messages and Phone Calls

### Pros

- Can be used to verify user's identity

### Cons

- Require user to have mobile device
- Require user to have signal
- Cost of messages or calls
- Various attacks

# Something You Are

## Biometrics

- Fingerprints
- Face recognition
- Handprint and iris scans

### Pros

- Hard to spoof

### Cons

- Expensive to implement
- Often require custom hardware
- Usually impractical for web applications

# Location

## Source IP Ranges

### Pros

- Easy for users

### Cons

- Doesn't protect against rouge insiders
- Doesn't protect against a system compromise
- Wireless network may allow access to corporate ranges

## Geolocation

### Pros

- Easy for users
- Effective against untargeted attacks

### Cons

- Easy for an attacker to bypass
