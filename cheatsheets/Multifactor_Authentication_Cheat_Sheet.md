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

- Logins
- Password changes
- Sensitive actions

## Improving Usability

- Remembering MFA
- Whitelisting corporate IP ranges
  - Insider threat
- Using standard TOTP rather than custom apps

## Resetting MFA

- What to do when users reset/lose MFA
- Balance between usability and security

# Something You Know

## Passwords and PINs

### Pros

- Simple and well understood

### Cons

- Usually weak
- Hard to remember
- Frequently re-used

## Security Questions

### Pros

- Simple

### Cons

- Usually weak
- Link to Security Questions CS

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
