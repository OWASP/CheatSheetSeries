# Post-Quantum Cryptography Cheat Sheet

## Introduction

Post-quantum cryptography (PQC) uses algorithms designed to resist attacks from both classical and quantum computers. This cheat sheet turns [PQC migration planning](https://www.ncsc.gov.uk/guidance/pqc-migration-timelines) into stages for application developers: inventory dependencies, prioritize work, adopt supported implementations, test, and roll out. Start the preparation stages even when a dependency cannot yet migrate.

## Stage 1: Inventory cryptographic dependencies

Create a [cryptographic inventory](https://pages.nist.gov/nccoe-migration-post-quantum-cryptography/FAQ/index.html#what-is-a-cryptographic-inventory) with one entry per use of cryptography. Include dependencies managed by your platform or service provider, not just direct calls in application code.

| Record | Include |
| --- | --- |
| Purpose and lifetime | Transport, stored data, key protection, or signatures; how long confidentiality or trust must last. |
| Implementation | Protocol, algorithms and parameters, library or service version, key and certificate identifiers. Store metadata, never secret key material. |
| Dependencies | Clients, servers, proxies, signing and verification services, key management services, hardware security modules, and backups. |
| Ownership | Responsible team or supplier, supported upgrade path, and components that cannot be updated. |

Map each transport connection separately, including connections from a gateway to the application. Trace how stored data's encryption keys are protected and recovered. Inventory signature verifiers as well as signers.

**Complete when:** each dependency has an owner and an identified migration path or a recorded blocker.

## Stage 2: Prioritize migration work

Prioritize data that must stay confidential for years and systems that will be difficult to update later, following the [NCSC migration planning guidance](https://www.ncsc.gov.uk/guidance/pqc-migration-timelines). Assign an owner and target date to each migration item.

- **Long-lived confidentiality:** prioritize exposed connections and stored data whose keys depend on RSA or elliptic curve cryptography. Updating encryption later cannot protect copies an adversary has already collected.
- **Long-lived trust:** plan early for software and firmware verification, trust anchors, and signed records that must remain trustworthy for years. Include the time needed to update every verifier.
- **Blocked dependencies:** request a supported release and migration plan from the supplier. Record the remaining exposure, a review date, and whether replacement is necessary.

Prefer AES-256 for additional quantum security margin, consistent with the [Cryptographic Storage Cheat Sheet](Cryptographic_Storage_Cheat_Sheet.md#algorithms). Use a secure encryption mode. AES-128 remains permitted: [NIST's PQC FAQ](https://csrc.nist.gov/Projects/post-quantum-cryptography/faqs) allows continued use of AES-128, AES-192, and AES-256. Check the public-key protection of encryption keys even when the data itself uses AES.

**Complete when:** the backlog separates confidentiality and signature work, with explicit decisions for dependencies that cannot yet migrate.

## Stage 3: Adopt supported implementations

Upgrade maintained libraries and platform services to implementations of standardized algorithms. Select parameters through the supported protocol and your security requirements. Algorithm support alone does not establish protocol interoperability.

| Use case | Developer action |
| --- | --- |
| Key establishment | Use a supported integration of the Module-Lattice-Based Key-Encapsulation Mechanism, [ML-KEM (FIPS 203)](https://csrc.nist.gov/pubs/fips/203/final). It establishes a shared secret for symmetric cryptography; it does not directly encrypt application data or authenticate the peer. |
| Transport | Pilot a supported classical + PQC hybrid exchange, such as [X25519MLKEM768](https://www.rfc-editor.org/rfc/rfc10024.html), following the [Transport Layer Security (TLS) Cheat Sheet](Transport_Layer_Security_Cheat_Sheet.md#set-the-appropriate-diffie-hellman-groups). Keep certificate and hostname validation enabled. |
| Signatures | Plan a separate migration using a supported signature format and verifier, such as an integration of the Module-Lattice-Based Digital Signature Algorithm, [ML-DSA (FIPS 204)](https://csrc.nist.gov/pubs/fips/204/final). Coordinate signer and verifier upgrades; follow the [JSON Web Token (JWT) guidance](JSON_Web_Token_Cheat_Sheet.md#public-key-signatures) for tokens. |
| Stored data | Use your provider's supported migration process for public-key protection of data keys, including existing wrapped keys. Follow the [key rotation and existing-data guidance](Key_Management_Cheat_Sheet.md#cryptoperiods-and-rotation) and retain recovery access during migration. |

A hybrid construction combines classical and post-quantum algorithms. Use the protocol's implementation rather than constructing your own combination. [RFC 9794, Section 5](https://www.rfc-editor.org/rfc/rfc9794.html#section-5) distinguishes hybrid confidentiality from authentication: a hybrid TLS key exchange does not make classical certificate signatures quantum-resistant.

Where a supported dual-signature scheme requires both signatures, enforce both verifications. Accepting either one permits classical-only acceptance; [NIST describes dual-signature verification](https://csrc.nist.gov/Projects/post-quantum-cryptography/faqs) as requiring all component signatures to succeed. Do not append a custom signature field to an existing token or certificate format.

For signed records needing long-term proof, validate them and preserve evidence through a supported [archive timestamp and renewal process](https://www.rfc-editor.org/rfc/rfc4998.html#section-1.1) before the protecting algorithms become weak. Retaining an old verifier alone does not preserve that proof.

**Complete when:** a supported migration works in a test environment, and the team has documented which security properties it provides.

## Stage 4: Test the full application path

Test with the actual algorithms and parameter sets you will deploy. [NIST's crypto agility guidance, Sections 3.2 and 6.2](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.39-upd1.pdf) calls out larger cryptographic objects and protecting algorithm negotiation.

- Exercise real clients, proxies, gateways, and backend connections. Verify the negotiated key exchange for new connections. For [resumed TLS sessions](https://datatracker.ietf.org/doc/html/rfc9846#section-4.3.9), check the resumption mode and how the original connection and resumption secrets were protected.
- Measure handshake and verification costs under expected load. Check certificate, signature, message, and database field limits. Keep size limits explicit when increasing them.
- Test rejection of invalid signatures, untrusted certificates, and disallowed algorithms. If both signatures are required, either missing or invalid signature must cause rejection.
- Decide where classical fallback is temporarily allowed. For paths requiring PQC, verify that failures cannot silently trigger a classical-only retry.
- Test existing data, older signed artifacts, backup restoration, and key recovery before retiring old keys or formats.

**Complete when:** compatibility, rejection behavior, recovery, and rollback tests pass for the intended deployment policy.

## Stage 5: Roll out and retire temporary exceptions

Deploy to a small group of services or clients, then expand using the tests and monitoring results. Keep an approved rollback plan and explicit criteria for ending classical-only support, as recommended by the [NCSC migration guidance](https://www.ncsc.gov.uk/guidance/pqc-migration-timelines).

- Record negotiated algorithms and verification outcomes without logging secrets. Alert on unexpected classical-only use and verification failures.
- Treat a rollback to classical-only protection as a security exception with an owner and expiry date. Where PQC is required, pause the affected operation instead of silently weakening the policy.
- Track library security updates and applicable standards. Remove temporary fallback only after required peers and recovery workflows have migrated. Preserve required access to older data and signed records under an explicit legacy policy. Once PQC verification is required, restrict classical-only exceptions to identified legacy artifacts; do not use them to accept new artifacts.

**Complete when:** required paths demonstrably use the intended protection, and remaining exceptions have owners and retirement dates. Keep the inventory current as dependencies change.

## References

- [NCSC: Timelines for migration to post-quantum cryptography](https://www.ncsc.gov.uk/guidance/pqc-migration-timelines)
- [NIST CSWP 39-upd1: Considerations for Achieving Crypto Agility](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.39-upd1.pdf)
- [RFC 9794: Terminology for Post-Quantum Traditional Hybrid Schemes](https://www.rfc-editor.org/rfc/rfc9794.html)
