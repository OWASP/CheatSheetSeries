# Passkey Binding Integrity Cheat Sheet

## Introduction

Passkeys (WebAuthn/FIDO2) cryptographically prove that a client controls a registered credential. They do **not** prove which account that credential belongs to. The credential-to-account binding lives as a foreign-key column on the credentials table, and standard implementations leave it without integrity protection.

An attacker - a database administrator, a backup operator, an SQL injection vulnerability, a contractor with production database credentials - can tamper these foreign keys with a single `UPDATE` statement. WebAuthn signatures continue to validate without any cryptographic alarms. Authentication succeeds but account is wrong.

This cheat sheet describes the attack, identifies the affected library ecosystem, and prescribes a proportionate mitigation: cryptographically sign each credential row at registration and verify the signature on every authentication.

## The Attack

The vulnerable pattern is a credentials table with an unprotected `user_id` (or equivalent) foreign key:

```sql
-- Attacker has database write access
UPDATE credentials SET user_id = '<attacker_user_id>' WHERE id = '<victim_credential_id>';
```

Three variants share this single root cause and access requirement:

- **Takeover (primary concern)** - The attacker reassigns one of their own legitimately-registered credentials to point at a target account. Their authenticator signs the WebAuthn challenge correctly. The server resolves the foreign key to the target account and issues a session token for it.
- **Mass shuffle (high-impact insider variant)** - A bulk `UPDATE` redistributes bindings across a large fraction of the user base. Half the users complain that they are seeing someone else's account; the other half see nothing wrong. There is no cryptographic anchor to recover from, and backups taken after the attack inherit the corrupted state. Time-distributed shuffles defeat backup retention windows.
- **Misdirection** - A legitimate user authenticates and is silently redirected into an attacker-controlled account, useful for inducing privileged actions to execute under another identity.

All three require only database write access on the credentials table. The attack has been verified against a production passkey deployment via authorized internal security testing.

## Why This Pattern Is Widespread

The vulnerable pattern is the canonical implementation across the WebAuthn ecosystem. Major libraries and developer documentation prescribe it directly:

- [Google's official server-side passkey authentication guide](https://developers.google.com/identity/passkeys/developer-guides/server-authentication) instructs developers to look up the credential row and resolve the account via a `passkey_user_id` foreign key.
- [SimpleWebAuthn](https://web.archive.org/web/2024/https://simplewebauthn.dev/docs/packages/server) - the most widely used Node.js library - recommends a `Passkey` type containing a `user: UserModel` field, with the docs stating credentials should live in their own table "ideally with a foreign key somewhere connecting it to a specific UserModel."
- [Auth.js](https://authjs.dev/getting-started/authentication/webauthn) provides an official Postgres migration creating an `Authenticator` table whose only binding to the user is a plain `userId` foreign key (constraint `Authenticator_userId_fkey`). The Auth.js Passkeys provider is currently labelled experimental, but the migration is the canonical schema developers copy.
- [go-webauthn](https://pkg.go.dev/github.com/go-webauthn/webauthn/webauthn#hdr-Storage) is the only major library to recommend encryption at rest for credential records, but its documented schema annotates only the public key and attestation fields as "encrypt at rest" - the `user_id` lookup column is explicitly left in cleartext, leaving the shuffle attack viable on exactly the column targeted.

The pattern is universal because it matches standard ORM conventions ("users have credentials"). With go-webauthn's partial exception, none of these projects surface integrity protection of the user-lookup column as a security concern.

## Threat Scope

This cheat sheet addresses **persistence-layer attackers**: parties with database write capability but without runtime control of the application or access to the token-signing key. Specifically:

- Database administrators and contractors with production database credentials
- Backup operators with restore privileges
- SQL injection vulnerabilities reaching the credentials table
- Leaked database credentials with write privileges

The mitigation does not address full server compromise, registration-flow compromise, or authenticator compromise - see [Honest Limits](#honest-limits) below.

## Mitigation: Sign the Credential Row

At registration, sign each credential row with a private key managed by an HSM or KMS. The signature must cover every field the authentication path consults to attribute identity - nothing in the chain from credential lookup to account resolution should be left outside the signed payload. A field that is not signed is a field an attacker can shuffle.

The mandatory fields are the credential lookup key, the public key used to verify the WebAuthn assertion, the WebAuthn user handle (which discoverable-credential flows return in the assertion and the server compares against the stored value), and the account identifier the credential resolves to:

```
row_signature = Sign(signing_key, credential_id || credential_public_key || user_handle || account_id)
```

If the implementation consults additional columns to resolve identity - for example a tenant or realm identifier in multi-tenant deployments - include them in the signed payload as well. The integrity boundary must enclose the full set of values the authentication path relies on.

Store the signature alongside the row. At authentication, verify it on every assertion before issuing a token. If any signed field has been tampered with, the signature does not verify and authentication is rejected.

## Why Signing, Not Encryption

Signing matches what the threat actually requires - integrity of the binding. Encryption is the wrong tool:

- **Asymmetry of trust.** Signing places forgery capability behind the signing private key while verification requires only the public key. A compromised authentication runtime cannot forge bindings without independently obtaining the signing key. Encryption requires the verifier to hold key material capable of producing valid ciphertext, so a compromised runtime yields forgery capability.
- **Indexability.** Encrypting `account_id` breaks indexed lookups on that column. Signing leaves the column queryable.
- **The data is not secret.** `account_id` already appears in issued access tokens and downstream service calls. Confidentiality is not the goal; integrity is.

## Architectural Conditions

**Required - signing key isolation.** The signing key must reside in a different operational trust domain than the credentials database. Use an HSM or KMS with access controls, audit logging, and authentication paths independent of the database. If the same compromise that yields database write access also yields signing key access, the protection collapses. This condition is what defeats the persistence-layer attacker - they can write any row they want, but cannot invoke the signing operation from a SQL connection.

**Recommended - service separation.** Beyond signing key isolation, separating the registration service and the authentication service into distinct processes with distinct privileges is strongly recommended as defense-in-depth. The registration service holds the signing private key and database write access; the authentication service holds only the public verification key and database read access. This split does not strengthen protection against the persistence-layer threat - signing key isolation alone defeats that. What it provides is containment of partial service runtime compromise: a vulnerability scoped to the authentication service yields no forgery capability, and a vulnerability scoped to the registration service does not yield session-issuance capability.

## Honest Limits

The mitigation does not address:

- **Full server compromise.** An attacker with runtime control or KMS access to the token-signing key issues tokens directly, bypassing any binding mechanism. This is a structural limit of any application-layer integrity control.
- **Registration-flow compromise.** An attacker who can inject fraudulent registrations through the registration service inherits the row-signing capability for those registrations. Mitigation here is registration-flow hardening - rate limiting, multi-factor user confirmation at registration, and audit logging - and is complementary, not a substitute.
- **Authenticator compromise.** Within WebAuthn's standard threat model.

For threat models that include full server compromise, the answer is structural rather than cryptographic: external transparency logs, multi-party attestation, and distributed witness patterns (Certificate Transparency, Key Transparency, Sigstore). These require operational infrastructure beyond what individual passkey deployments typically maintain and are out of scope here.

## References

**Affected library documentation and code:**

- [Google - Server-side passkey authentication](https://developers.google.com/identity/passkeys/developer-guides/server-authentication)
- [SimpleWebAuthn - Server package documentation (Wayback snapshot)](https://web.archive.org/web/2024/https://simplewebauthn.dev/docs/packages/server)
- [Auth.js - WebAuthn / Passkeys provider](https://authjs.dev/getting-started/authentication/webauthn)
- [go-webauthn - Storage section](https://pkg.go.dev/github.com/go-webauthn/webauthn/webauthn#hdr-Storage)

**Related OWASP cheat sheets:**

- [Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [Multifactor Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html)
- [Zero Trust Architecture Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Zero_Trust_Architecture_Cheat_Sheet.html)
