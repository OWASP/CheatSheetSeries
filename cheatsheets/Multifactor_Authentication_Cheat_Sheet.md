# Introduction

- What is MFA

| Factor | Examples | 
|--------|----------|
| Something You Know | Passwords, PINs and Security Questions. |
| Something You Have | Hardware or software tokens, certificates, SMS or phone calls. |
| Something You Are | Fingerprints, facial recognition, iris scans, handprint scans. |
| Location | Source IP ranges. |

- What is **not** MFA
  - Password + PIN/Security Question

# Quick Recommendations

- Passwords + TOTP
- MFA required for admins and high privileged users
- Optional but recommended for users
- Whitelist corporate IP ranges
- Security questions or manual process to reset MFA

# Advantages

- Protection against most types of authentication based attacks
- Link to Credential Stuffing CS

# Disadvantages

- Additional complexity
- Complicated for users
- Loss of availability of second factors lost
  - How to reset MFA?

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
