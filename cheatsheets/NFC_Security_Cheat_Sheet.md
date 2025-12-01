NFC Security Cheat Sheet
Introduction

Near Field Communication (NFC) enables short-range, wireless communication across a wide set of mobile use cases including tag reading, peer-to-peer transfer, device pairing, access control, and contactless payments.
This cheat sheet provides practical, high-impact security recommendations for developers implementing NFC features on iOS and Android, covering Reader/Writer, Tag, and Host Card Emulation (HCE/SE) use cases.

Threat Landscape

Common security issues encountered in NFC implementations include:

🎯 Replay and Relay Attacks

No nonce, counter, or TTL enables message duplication.

Relay/“ghost & leech” attacks allow attackers to extend NFC range.

🎯 Eavesdropping

Data sent in the clear can be captured beyond the expected “few cm” range.

Improper RF shielding increases attack distance.

🎯 Cloning & Legacy Cryptography

Use of weak tag types (e.g., MIFARE Classic) enables UID-based cloning.

Legacy crypto (Crypto-1) provides no real protection.

🎯 Malicious NDEF / Deep Link Hijacking

Malicious NDEF payloads can trigger unwanted app experiences.

Attackers can exploit deep links to hijack app intents.

🎯 Downgrade Attacks

Devices may be forced into unauthenticated or legacy modes that bypass protections.

🎯 Parser Bugs & Resource Abuse

Oversized or malformed NDEF/APDU messages can trigger DoS or parsing failures.

🎯 Supply-Chain Abuse

Misconfigured, counterfeit, or cloned tags can be placed in physical locations.

🎯 Payment-Specific Risks

HCE-based Tap-to-Pay requires strict timing, attestation, and PCI/EMV compliance.

General Principles

Always authenticate tags or payloads where integrity matters.

Never trust user-provided NFC data.

Sanitize NDEF payloads before processing.

Use platform APIs instead of custom low-level NFC logic.

Disable NFC features when not required.

Avoid legacy/weak tag types in production systems.

Implement user-visible confirmations when performing sensitive operations.

🔐 Do & Don’t Summary
Do	Why
Use strong tag types (Type 4, DESFire EV2/EV3)	Prevent cloning & UID-based attacks
Use per-transaction nonces/counters	Mitigates replay attacks
Validate NDEF record types & length	Prevent parser abuse
Enforce https:// deep links	Prevent malicious app redirection
Use platform-secure elements when available	Strongest protection for sensitive data
Use OS attestation (SafetyNet / Play Integrity) for HCE apps	Confirms device integrity
Don’t	Why Not
Trust UIDs or tag type alone	Easily cloned/spoofed
Parse NDEF data without bounds checking	Malicious/oversized records cause DoS
Assume NFC distance is always "a few cm"	Eavesdropping can exceed 1 meter
Rely on MIFARE Classic or legacy crypto	Known broken & clonable
Accept NFC data that triggers deep links directly	Enables hijacking attacks
Platform Guidance
🍏 iOS

iOS restricts NFC access through CoreNFC; no background scanning.

iOS only supports NDEF and ISO14443 (Type 4) interactions.

NDEF payloads should be validated using:

Expected record types (.wellKnown, .absoluteURI, .mimeType)

Expected RTD fields

Payload size limits

iOS HCE is not available — payment emulation is handled through Secure Element.

🤖 Android

Supports Reader/Writer, Peer-to-Peer, Tag emulation, and HCE.

Android security best practices:

Use IsoDep with APDU-level authentication.

Do not use NfcA/NfcV raw mode for secure operations.

Validate NDEF entries before processing.

Use FLAG_READER_NFC_A | FLAG_READER_SKIP_NDEF_CHECK carefully—avoid insecure defaults.

Enable foreground dispatch to ensure only your application handles intended intents.

Tag Security Guidelines

✔ Prefer NFC Forum Type 4 or DESFire EV2/EV3.
✔ Use cryptographic authentication for sensitive use cases.
✔ Implement application-level MACs for data validation.
✔ Store only non-sensitive or integrity-protected data on tags.
✔ Never store secrets or tokens on plain NFC tags.

Host Card Emulation (HCE) Guidance

HCE is powerful but has inherent limitations:

⚠ Risks:

App-based emulation is susceptible to root/jailbreak attacks.

Timing constraints make relay attacks more feasible.

Requires device integrity checks.

✔ Mitigations:

Use Play Integrity API or SafetyNet.

Enforce per-session ephemeral keys.

Validate APDU command size and structure.

Follow EMVCo time windows strictly.

Add server-side transaction validation (nonce, counters, attestation).

Secure Reader/Writer Best Practices

Use per-read session tokens.

Apply NDEF record length limits.

Reject records larger than expected.

Validate MIME types.

Enforce strict URI whitelisting.

Disable peer-to-peer mode unless required.

Explicitly close and reset reader sessions after use.

NDEF Record Validation

Before processing any NFC payload, enforce:

✔ MIME-type checking
✔ Size limits
✔ Expected RTD types
✔ Allowed URI schemes
✔ Safe parsing (no recursion, no nested excessive records)
✔ Rejecting unknown/unsupported TNF values

Testing & Hardening

Use the following tools and techniques:

🧪 Tools

ndef-tools

Android Studio NFCTools

proxmark3 (hardware)

Flipper Zero (range/relay test)

EMVCo Level 1 tools (payments)

🛡 Hardening Checklist

 Validate NDEF payloads

 Enforce max message size

 Use strong tag type

 Implement anti-replay (nonce/counters)

 Implement anti-relay if applicable

 Use attestation (HCE apps)

 Whitelist URI schemes

 Sanitize deep links

 Use platform APIs

 Disable unused NFC modes

References

NFC Forum Specifications (NDEF, RTD, LLCP)

EMVCo Contactless Specifications

PCI DSS for mobile/contactless systems

OWASP MASVS / MASTG

Google Android NFC Documentation

Apple CoreNFC Documentation