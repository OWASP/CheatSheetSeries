# Cryptographic Storage Cheat Sheet

## Introduction

This article provides a simple model to follow when implementing solutions to protect data at rest.

For guidance on securely storing passwords, see the [Password Storage Cheat Sheet](Password_Storage_Cheat_Sheet.md).

## Contents

**FIXME**

## Architectural Design

An architectural decision must be made to determine the appropriate method to protect data at rest. There are such wide varieties of products, methods and mechanisms for cryptographic storage. This cheat sheet will only focus on low-level guidelines for developers and architects who are implementing cryptographic solutions. We will not address specific vendor solutions, nor will we address the design of cryptographic algorithms.

### Minimise the Storage of Sensitive Information

The best way to protect sensitive information is to not store it in the first place. Although this applies to all kinds of information, it is most often applicable to credit card details, as they are highly desirable for attackers, and PCI DSS has such stringent requirements for how they must be stored, discussed in the [section below](#pci-dss)

## Algorithms

For symmetric encryption **AES** with a **256 bit** key should be used as the preferred algorithm.

For asymmetric encryption, **RSA** with at least a **2048 bit** key should be used as the preferred algorithm.

Many other symmetric and asymmetric algorithms are available which have their own pros and cons, and specific use cases they may be better or worse than AES or RSA. When considering these, a number of factors should be taken into account, including:

- Key size.
- Known attacks and weaknesses of the algorithm.
- Maturity of the algorithm.
- Approval by third parties such as [NIST's algorithmic validation program](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program).
- Performance (both for encryption and decryption).
- Quality of the libraries available.
- Portability of the algorithm (i.e, how widely supported is it).

In some cases there may be regulatory requirements that limit the algorithms that can be used, such as [FIPS 140-2](https://csrc.nist.gov/csrc/media/publications/fips/140/2/final/documents/fips1402annexa.pdf) or [PCI DSS](#34-render-pan-primary-account-number-at-minimum-unreadable-anywhere-it-is-stored).

### Custom Algorithms

Don't do this.

### Cipher Modes

There are various [modes](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation) that can be used to allow block ciphers (such as AES) to decrypt arbitrary amounts of data, in the same way that a stream cipher would. These modes have different security and performance characteristics, and a full discussion of them it outside the scope of this cheat sheet. Some of the modes have requirements to generate secure initialisation vectors (IVs) and other attributes, but these should be handled automatically by the library.

Where available, authenticated modes should always be used. These provide guarantees of the integrity and authenticity of the data, as well as confidentiality. The most commonly used authenticated modes are **[GCM](https://en.wikipedia.org/wiki/Galois/Counter_Mode)** and **[CCM](https://en.wikipedia.org/wiki/CCM_mode)**, which should be used as a first preference.

If GCM or CCM are not available, then [CTR](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)) mode or [CBC](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_(CBC)) mode should be used. As these do not provide any guarantees about the authenticity of the data, separate authentication should be implemented, such as using the [Encrypt-then-MAC](https://en.wikipedia.org/wiki/Authenticated_encryption#Encrypt-then-MAC_(EtM)) technique. Care needs to be taken when using this method with [variable length messages](https://en.wikipedia.org/wiki/CBC-MAC#Security_with_fixed_and_variable-length_messages)

If random access to the encrypted data is required then [XTS](https://en.wikipedia.org/wiki/Disk_encryption_theory#XTS) mode should be used. This is typically used for disk encryption, so it unlikely to be used by a web application.

[EBC](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#ECB) should not be used outside of very specific circumstances.

### Secure Random Number Generation

Random numbers (or strings) are needed for various security critical functionality, such as generating session IDs, CSRF tokens or password reset tokens. As such, it is important that these are generated securely, and that it is not possible for an attacker to guess and predict them.

It is generally not possible for computers to generate truly random numbers (without special hardware), so most systems and languages provide two different types of randomness:

Pseudo-Random Number Generators (PRNG) provide low-quality randomness that are much faster, and can be used for non-security related functionality (such as ordering results on a page, or randomising UI elements). However, they **must not** be used for anything security critical, as it is often possible for attackers to guess or predict the output.

Cryptographically Secure Pseudo-Random Number Generators (CSPRNG) are designed to produce a much higher quality of randomness (more strictly, a greater amount of entropy), making them safe to use for security-sensitive functionality. However, they are slower and more CPU intensive, can end up blocking in some circumstances when large amounts of random data are requested. As such, if large amounts of non-security related randomness are needed, they may not be appropriate.

The table below shows the recommended algorithms for each language, as well as insecure functions that should not be used.

| Language | Unsafe Functions | Cryptographically Secure Functions |
|----------|------------------|------------------------------------|
| C        | `random()`, `rand()` | [getrandom(2)](http://man7.org/linux/man-pages/man2/getrandom.2.html) |
| Java     | `java.util.Random()` | [java.security.SecureRandom](https://docs.oracle.com/javase/8/docs/api/java/security/SecureRandom.html) |
| PHP      | `rand()`, `mt_rand()`, `array_rand()`, `uniqid()` | [random_bytes()](https://www.php.net/manual/en/function.random-bytes.php), [random_int()](https://www.php.net/manual/en/function.random-int.php) in PHP 7 or [openssl_random_pseudo_bytes()](https://www.php.net/manual/en/function.openssl-random-pseudo-bytes.php) in PHP 5 |
| .NET/C#  | `Random()`, | [RNGCryptoServiceProvider](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.rngcryptoserviceprovider?view=netframework-4.8) |
| Objective-C | `arc4random()` (Uses RC4 Cipher), | [SecRandomCopyBytes](https://developer.apple.com/documentation/security/1399291-secrandomcopybytes?language=objc) |
| Python   | `random()`, | [secrets()](https://docs.python.org/3/library/secrets.html#module-secrets) |
| Ruby     | `Random`, | [SecureRandom](https://ruby-doc.org/stdlib-2.5.1/libdoc/securerandom/rdoc/SecureRandom.html) |
| Go       | `rand` using `math/rand` package, | [crypto.rand](https://golang.org/pkg/crypto/rand/) package |
| Rust     | `rand::prng::XorShiftRng`, | [rand::prng::chacha::ChaChaRng](https://docs.rs/rand/0.5.0/rand/prng/chacha/struct.ChaChaRng.html) and the rest of the Rust library [CSPRNGs.](https://docs.rs/rand/0.5.0/rand/prng/index.html#cryptographically-secure-pseudo-random-number-generators-csprngs) |

#### UUIDs and GUIDs

Universally unique identifiers (UUIDs or GUIDs) are sometimes used as a quick way to generate random strings. Although they can provide a reasonable source of randomness, this will depend on the [type or version](https://en.wikipedia.org/wiki/Universally_unique_identifier#Versions) of the UUID that is created.

Specifically, version 1 UUIDs are comprised of a high precision timestamp and the MAC address of the system that generated them, so are **not random** (although they may be hard to guess, given the timestamp is to the nearest 100ns). Type 4 UUIDs are randomly generated, although whether this is done using a CSPRNG will depend on the implementation. Unless this is known to be secure in the specific language or framework, the randomness of UUIDs should not be relied upon.

### Ensure that the cryptographic protection remains secure even if access controls fail

This rule supports the principle of defense in depth. Access controls (usernames, passwords, privileges, etc.) are one layer of protection. Storage encryption should add an additional layer of protection that will continue protecting the data even if an attacker subverts the database access control layer.

## Key Management

### Processes

Formal processes should be implemented (and tested) to cover all aspects of key management, including:

- Generating and storing new keys.
- Distributing keys to the required parties.
- Deploying keys to application servers.
- Rotating and decommissioning old keys

### Key Generation

Keys should be randomly generated using a cryptographically secure function, such as those discussed in the [Secure Random Number Generation](#secure-random-number-generation) section. Keys **should not** be based on common words or phrases, or on "random" characters generated by mashing the keyboard.

### Key Lifetimes and Rotation

Encryption keys should be changed (or rotated) based on a number of different criteria:

- If the previous key is known (or suspected) to have been compromised.
  * This could also be caused by a someone who had access to the key leaving the organisation.
- After a specified period of time has elapsed (known as the cryptoperiod).
  * There are many factors that could affect what an appropriate cryptoperiod is, including the size of the key, the sensitivity of the data, and the threat model of the system. See section 5.3 of [NIST SP 800-57](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r4.pdf) for further guidance.
- After the key has been used to encrypt a specific amount of data.
  * This would typically be `2^35` bytes (~34GB) for 64-bit keys (DES, 3DES, Blowfish, RC5, etc.) and `2^68` bytes (~295 exabytes) for 128 bit keys (AES, Twofish, Serpent, etc.).
- If there is a significant change to the security provided by the algorithm (such as a new attack being announced).

Once one of these criteria have been met, a new key should be generated and used for encrypting any new data. There are two main approaches for how existing data that was encrypted with the old key(s) should be handled:

- Decrypting it and re-encrypting it with the new key.
- Marking each item with the ID of the key that was used to encrypt it, and storing multiple keys to allow the old data to be decrypted.

The first option should generally be preferred, as it greatly simplifies both the application code and key management processes; however, it may not always be feasible. Note that old keys should generally be stored for a certain period after they have been retired, in case old backups of copies of the data need to be decrypted.

It is important that the code and processes required to rotate a key are in place **before** they are required, so that keys can be quickly rotated in the event of a compromise. Additionally, processes should also be implemented to allow the encryption algorithm or library to be changed, in case a new vulnerability is found in the algorithm or implementation.

### Store unencrypted keys away from the encrypted data

If the keys are stored with the data then any compromise of the data will easily compromise the keys as well. Unencrypted keys should never reside on the same machine or cluster as the data.

### Use independent keys when multiple keys are required

Ensure that key material is independent. That is, do not choose a second key which is easily related to the first (or any preceding) keys.

### Protect keys in a key vault

Keys should remain in a protected key vault at all times. In particular, ensure that there is a gap between the threat vectors that have direct access to the data and the threat vectors that have direct access to the keys. 

This implies that keys should not be stored on the application or web server (assuming that application attackers are part of the relevant threat model).

### Document concrete procedures for managing keys through the lifecycle

These procedures must be written down and the key custodians must be adequately trained.

### Document concrete procedures to handle a key compromise

Ensure operations staff have the information they need, readily available, when rotation of encryption keys must be performed. Rotating keys should not require changes to source code or other risky deployment measures, since doing this in the middle of an incident will already place a great deal of stress on these staff.

## Regulatory Requirements

### PCI DSS

The [Payment Card Industry (PCI) Data Security Standard (DSS)](https://www.pcisecuritystandards.org/document_library?category=pcidss&document=pci_dss) was developed to encourage and enhance cardholder data security and facilitate the broad adoption of consistent data security measures globally. The standard was introduced in 2005 and replaced individual compliance standards from Visa, Mastercard, Amex, JCB and Diners.

PCI DSS requirement 3 covers secure storage of credit card data. This requirement covers several aspects of secure storage including the data you must never store but we are covering Cryptographic Storage which is covered in requirements 3.4, 3.5 and 3.6 as you can see below:

#### 3.4 Render PAN (Primary Account Number), at minimum, unreadable anywhere it is stored

Compliance with requirement 3.4 can be met by implementing any of the four types of secure storage described in the standard which includes encrypting and hashing data. These two approaches will often be the most popular choices from the list of options. The standard doesn't refer to any specific algorithms but it mandates the use of **Strong Cryptography**. The glossary document from the PCI council defines **Strong Cryptography** as:

> Cryptography based on industry-tested and accepted algorithms, along with strong key lengths and proper key-management practices. Cryptography is a method to protect data and includes both encryption (which is reversible) and hashing (which is not reversible, or "one way"). SHA-1 is an example of an industry-tested and accepted hashing algorithm. Examples of industry-tested and accepted standards and algorithms for encryption include AES (128 bits and higher), TDES (minimum double-length keys), RSA (1024 bits and higher), ECC (160 bits and higher), and ElGamal (1024 bits and higher).

If you have implemented the second rule in this cheat sheet you will have implemented a strong cryptographic algorithm which is compliant with or stronger than the requirements of PCI DSS requirement 3.4. You need to ensure that you identify all locations that card data could be stored including logs and apply the appropriate level of protection. This could range from encrypting the data to replacing the card number in logs.

This requirement can also be met by implementing disk encryption rather than file or column level encryption. The requirements for **Strong Cryptography** are the same for disk encryption and backup media. The card data should never be stored in the clear and by following the guidance in this cheat sheet you will be able to securely store your data in a manner which is compliant with PCI DSS requirement 3.4

#### 3.5 Protect any keys used to secure cardholder data against disclosure and misuse

As the requirement name above indicates, we are required to securely store the encryption keys themselves. This will mean implementing strong access control, auditing and logging for your keys. The keys must be stored in a location which is both secure and "away" from the encrypted data. This means key data shouldn't be stored on web servers, database servers etc

Access to the keys must be restricted to the smallest amount of users possible. This group of users will ideally be users who are highly trusted and trained to perform Key Custodian duties. There will obviously be a requirement for system/service accounts to access the key data to perform encryption/decryption of data.

The keys themselves shouldn't be stored in the clear but encrypted with a KEK (Key Encrypting Key). The KEK must not be stored in the same location as the encryption keys it is encrypting.

#### 3.6 Fully document and implement all key-management processes and procedures for cryptographic keys used for encryption of cardholder data

Requirement 3.6 mandates that key management processes within a PCI compliant company cover 8 specific key lifecycle steps:

##### 3.6.1 Generation of strong cryptographic keys

As we have previously described in this cheat sheet we need to use algorithms which offer high levels of data security. We must also generate strong keys so that the security of the data isn't undermined by weak cryptographic keys. A strong key is generated by using a key length which is sufficient for your data security requirements and compliant with the PCI DSS. The key size alone isn't a measure of the strength of a key. The data used to generate the key must be sufficiently random ("sufficient" often being determined by your data security requirements) and the entropy of the key data itself must be high.

##### 3.6.2 Secure cryptographic key distribution

The method used to distribute keys must be secure to prevent the theft of keys in transit. The use of a protocol such as Diffie-Hellman can help secure the distribution of keys, the use of secure transport such as TLS and SSHv2 can also secure the keys in transit. Older protocols like SSLv3 should not be used.

##### 3.6.3 Secure cryptographic key storage

The secure storage of encryption keys including KEK's has been touched on in our description of requirement 3.5 (see above).

##### 3.6.4 Periodic cryptographic key changes

The PCI DSS standard mandates that keys used for encryption must be rotated at least annually. The key rotation process must remove an old key from the encryption/decryption process and replace it with a new key. All new data entering the system must encrypted with the new key. While it is recommended that existing data be rekeyed with the new key, as per the Rekey data at least every one to three years rule above, it is not clear that the PCI DSS requires this.

##### 3.6.5 Retirement or replacement of keys as deemed necessary when the integrity of the key has been weakened or keys are suspected of being compromised

The key management processes must cater for archived, retired or compromised keys. The process of securely storing and replacing these keys will more than likely be covered by your processes for requirements 3.6.2, 3.6.3 and 3.6.4

##### 3.6.6 Split knowledge and establishment of dual control of cryptographic keys

The requirement for split knowledge and/or dual control for key management prevents an individual user performing key management tasks such as key rotation or deletion. The system should require two individual users to perform an action (i.e. entering a value from their own OTP) which creates to separate values which are concatenated to create the final key data.

##### 3.6.7 Prevention of unauthorized substitution of cryptographic keys

The system put in place to comply with requirement 3.6.6 can go a long way to preventing unauthorised substitution of key data. In addition to the dual control process you should implement strong access control, auditing and logging for key data so that unauthorised access attempts are prevented and logged.

##### 3.6.8 Requirement for cryptographic key custodians to sign a form stating that they understand and accept their key-custodian responsibilities

To perform the strong key management functions we have seen in requirement 3.6 we must have highly trusted and trained key custodians who understand how to perform key management duties. The key custodians must also sign a form stating they understand the responsibilities that come with this role.

## Related documentation & tools

### Documentation

- [Guide to Cryptography](https://www.owasp.org/index.php/Guide_to_Cryptography)
- [Application Security Verification Standard (ASVS) – Communication Security Verification Requirements (V10)](http://www.owasp.org/index.php/ASVS)
- [BetterCrypto - Config Snippets](https://bettercrypto.org/)

### Tools

- [Cryptosense](https://cryptosense.com/discovery/)
