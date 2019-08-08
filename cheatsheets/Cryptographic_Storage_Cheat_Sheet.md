# Introduction

This article provides a simple model to follow when implementing solutions to protect data at rest.

# Architectural Decision

An architectural decision must be made to determine the appropriate method to protect data at rest. There are such wide varieties of products, methods and mechanisms for cryptographic storage. This cheat sheet will only focus on low-level guidelines for developers and architects who are implementing cryptographic solutions. We will not address specific vendor solutions, nor will we address the design of cryptographic algorithms.

The general practices and required minimum key length depending on the scenario listed below.

- Key exchange: `Diffie–Hellman key exchange with minimum 2048 bits`
- Message Integrity: `HMAC-SHA2`
- Message Hash: `SHA2 256 bits`
- Asymmetric encryption: `RSA 2048 bits`
- Symmetric encryption: `AES 128 bits`
- Password Hashing: `Argon2, PBKDF2, Scrypt, Bcrypt`

# Providing Cryptographic Functionality

## Secure Cryptographic Storage Design

- All protocols and algorithms for authentication and secure communication should be well vetted by the cryptographic community.
- Ensure certificates are properly validated against the hostnames/users ie whom they are meant for.
- Avoid using wildcard certificates unless there is a business need for it
- Maintain a cryptographic standard to ensure that the developer community knows about the approved ciphersuits for network security protocols, algorithms, permitted use, cryptoperiods and Key Management

### Rule - Only store sensitive data that you need

Many eCommerce businesses utilize third party payment providers to store credit card information for recurring billing. This offloads the burden of keeping credit card numbers safe.

### Rule - Use strong approved Authenticated Encryption

E.g. [CCM](http://en.wikipedia.org/wiki/CCM_mode) or [GCM](http://en.wikipedia.org/wiki/GCM_mode) are approved [Authenticated Encryption](http://en.wikipedia.org/wiki/Authenticated_encryption) modes based on [AES](http://en.wikipedia.org/wiki/Advanced_Encryption_Standard) algorithm.

#### Rule - Use strong approved cryptographic algorithms

Do not implement an existing cryptographic algorithm on your own, no matter how easy it appears. Instead, use widely accepted algorithms and widely accepted implementations.

Only use approved public algorithms such as AES, RSA public key cryptography, and SHA-256 or better for hashing. Do not use weak algorithms, such as MD5 or SHA1. Avoid hashing for password storage, instead use Argon2, PBKDF2, bcrypt or scrypt. Note that the classification of a "strong" cryptographic algorithm can change over time. See [NIST approved algorithms](http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r4.pdf) or ISO TR 14742 “Recommendations on Cryptographic Algorithms and their use” or [Algorithms, key size and parameters report – 2014](http://www.enisa.europa.eu/activities/identity-and-trust/library/deliverables/algorithms-key-size-and-parameters-report-2014/at_download/fullReport) from European Union Agency for Network and Information Security. E.g. [AES](http://en.wikipedia.org/wiki/Advanced_Encryption_Standard) 128, [RSA](http://en.wikipedia.org/wiki/RSA_%28cryptosystem%29) 3072, [SHA](http://en.wikipedia.org/wiki/Secure_Hash_Algorithm) 256.

Ensure that the implementation has (at minimum) had some cryptography experts involved in its creation. If possible, use an implementation that is FIPS 140-2 certified.

See [NIST approved algorithms](http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r4.pdf) Table 2 “Comparable strengths” for the strength (“security bits”) of different algorithms and key lengths, and how they compare to each other.

- In general, where different algorithms are used, they should have comparable strengths e.g. if an AES-128 key is to be encrypted, an AES-128 key or greater, or RSA-3072 or greater could be used to encrypt it.
- In general, hash lengths are twice as long as the security bits offered by the symmetric/asymmetric algorithm  e.g. SHA-224 for 3TDEA (112 security bits) (due to the [Birthday Attack](http://en.wikipedia.org/wiki/Birthday_attack))

If a password is being used to protect keys then the [password strength](http://en.wikipedia.org/wiki/Password_strength) should be sufficient for the strength of the keys it is protecting.

When 3DES is used, ensure `K1 != K2 != K3`, and the minimum key length must be `192 bits` .

#### Rule - Use approved cryptographic modes

In general, you should not use AES, DES or other symmetric cipher primitives directly. [NIST approved modes](http://csrc.nist.gov/groups/ST/toolkit/BCM/current_modes.html) should be used instead.

**Note:** Do not use [ECB mode](http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Electronic_codebook_.28ECB.29) for encrypting lots of data (the other modes are better because they chain the blocks of data together to improve the data security).

#### Rule - Use strong random numbers

Ensure that all random numbers, especially those used for cryptographic parameters (keys, IV’s, MAC tags), random file names, random GUIDs, and random strings are generated in a cryptographically strong fashion.

Ensure that random algorithms are seeded with sufficient entropy.

Tools like [NIST RNG Test tool](http://csrc.nist.gov/groups/ST/toolkit/rng/documentation_software.html) (as used in PCI PTS Derived Test Requirements) can be used to comprehensively assess the quality of a Random Number Generator by reading e.g. 128MB of data from the RNG source and then assessing its randomness properties with the tool.

The following functions are considered **weak** random number generators and should not be used.

- C : `random()`, `rand()` instead use [getrandom(2)](http://man7.org/linux/man-pages/man2/getrandom.2.html)
- Java : `java.util.Random()` instead use `java.security.SecureRandom`
- PHP : `rand()`, `mt_rand()`, `array_rand()`, `uniqid()` instead use [random_bytes()](https://www.php.net/manual/en/function.random-bytes.php), [random_int()](https://www.php.net/manual/en/function.random-int.php) in PHP 7 or [openssl_random_pseudo_bytes()](https://www.php.net/manual/en/function.openssl-random-pseudo-bytes.php) in PHP 5 (which is **deprecated** and **should not be used**)

For secure random number generation, refer to NIST SP 800-90A. CTR-DRBG, HASH-DRBG or HMAC-DRBG are recommended. Refer to NIST SP800-22 A Statistical Test Suite for Random and Pseudorandom Number Generators for Cryptographic Applications, and the testing toolkit.

References:
- http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-22r1a.pdf

#### Rule - Use Authenticated Encryption of data

Use ([AE](http://en.wikipedia.org/wiki/Authenticated_encryption)) modes under a uniform API. Recommended modes include [CCM](http://en.wikipedia.org/wiki/CCM_mode), and [GCM](http://en.wikipedia.org/wiki/Galois/Counter_Mode) as these, and only these as of November 2014, are specified in [NIST approved modes](http://csrc.nist.gov/groups/ST/toolkit/BCM/current_modes.html), ISO IEC 19772 (2009) "Information technology — Security techniques — Authenticated encryption", and [IEEE P1619 Standard for Cryptographic Protection of Data on Block-Oriented Storage Devices](http://en.wikipedia.org/wiki/IEEE_P1619):

- [Authenticated Encryption](http://en.wikipedia.org/wiki/Authenticated_encryption) gives [confidentiality](http://en.wikipedia.org/wiki/Confidentiality), [integrity](http://en.wikipedia.org/wiki/Data_integrity), and [authenticity](http://en.wikipedia.org/wiki/Authentication) (CIA); encryption alone just gives confidentiality. Encryption must always be combined with message integrity and authenticity protection. Otherwise the ciphertext may be vulnerable to manipulation causing changes to the underlying plaintext data, especially if it's being passed over untrusted channels (e.g. in an URL or cookie).
- These modes require only one key. In general, the tag sizes and the IV sizes should be set to maximum values.

If these recommended [AE](http://en.wikipedia.org/wiki/Authenticated_encryption) modes are not available:

- Combine encryption in [cipher-block chaining (CBC) mode](http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Cipher-block_chaining_.28CBC.29) with post-encryption message authentication code, such as [HMAC](http://en.wikipedia.org/wiki/HMAC) or [CMAC](http://en.wikipedia.org/wiki/CMAC) i.e. Encrypt-then-MAC.
    - Note that Integrity and Authenticity are preferable to Integrity alone i.e. a MAC such as HMAC-SHA256 or HMAC-SHA512 is a better choice than SHA-256 or SHA-512.
- Use 2 independent keys for these 2 independent operations.
- Do not use ECB mode. CDC is preferred.
- Do not use [CBC MAC for variable length data](http://en.wikipedia.org/wiki/CBC-MAC#Security_with_fixed_and_variable-length_messages)
- The [CAVP program](http://csrc.nist.gov/groups/STM/cavp/index.html) is a good default place to go for validation of cryptographic algorithms when one does not have AES or one of the authenticated encryption modes that provide confidentiality and authenticity (i.e., data origin authentication) such as CCM, EAX, CMAC, etc. For Java, if you are using SunJCE that will be the case. The cipher modes supported in JDK 1.5 and later are CBC, CFB, CFBx, CTR, CTS, ECB, OFB, OFBx, PCBC. None of these cipher modes are authenticated encryption modes. (That's why it is added explicitly.) If you are using an alternate JCE provider such as Bouncy Castle, RSA JSafe, IAIK, etc., then these authenticated encryption modes should be used.

**Note:** 
- [Disk encryption](http://en.wikipedia.org/wiki/Disk_encryption_theory) is a special case of [data at rest](http://en.wikipedia.org/wiki/Data_at_Rest) e.g. Encrypted File System on a Hard Disk Drive. 
- [XTS-AES mode](http://csrc.nist.gov/publications/nistpubs/800-38E/nist-sp-800-38E.pdf) is optimized for Disk encryption and is one of the [NIST approved modes](http://csrc.nist.gov/groups/ST/toolkit/BCM/current_modes.html); it provides confidentiality and some protection against data manipulation (but not as strong as the [AE](http://en.wikipedia.org/wiki/Authenticated_encryption) [NIST approved modes](http://csrc.nist.gov/groups/ST/toolkit/BCM/current_modes.html)). It is also specified in [IEEE P1619 Standard for Cryptographic Protection of Data on Block-Oriented Storage Devices](http://en.wikipedia.org/wiki/IEEE_P1619)

### Rule - Store a one-way and salted value of passwords

Use Argon2, PBKDF2, bcrypt or scrypt for password storage. For more information on password storage, please see the [Password Storage Cheat Sheet](Password_Storage_Cheat_Sheet.md).

### Rule - Ensure that the cryptographic protection remains secure even if access controls fail

This rule supports the principle of defense in depth. Access controls (usernames, passwords, privileges, etc.) are one layer of protection. Storage encryption should add an additional layer of protection that will continue protecting the data even if an attacker subverts the database access control layer.

### Rule - Ensure that any secret key is protected from unauthorized access

#### Rule - Define a key lifecycle

The key lifecycle details the various states that a key will move through during its life. The lifecycle will specify when a key should no longer be used for encryption, when a key should no longer be used for decryption (these are not necessarily coincident), whether data must be rekeyed when a new key is introduced, and when a key should be removed from use all together.

#### Rule - Store unencrypted keys away from the encrypted data

If the keys are stored with the data then any compromise of the data will easily compromise the keys as well. Unencrypted keys should never reside on the same machine or cluster as the data.

#### Rule - Use independent keys when multiple keys are required

Ensure that key material is independent. That is, do not choose a second key which is easily related to the first (or any preceeding) keys.

#### Rule - Protect keys in a key vault

Keys should remain in a protected key vault at all times. In particular, ensure that there is a gap between the threat vectors that have direct access to the data and the threat vectors that have direct access to the keys. 

This implies that keys should not be stored on the application or web server (assuming that application attackers are part of the relevant threat model).

#### Rule - Document concrete procedures for managing keys through the lifecycle

These procedures must be written down and the key custodians must be adequately trained.

#### Rule - Build support for changing algorithms and keys when needed

If keys are compromised or an external authority expires them, key changes will be needed. Application polices or emergency needs will force application administrators to rotate keys and potentially rekey data at some point. 

It's best to be prepared to rapidly handle this need when necessary. Including a key version and encryption algorithm version with the encrypted data is a useful, proactive feature. 

For instance, including a simple prefix string, such as "`{1,1}...`", prior to the encrypted data could indicate algorithm version 1, key version 1. This allows for an "online" change to the encryption algorithm and key without re-encrypting all existing data all at once.

#### Rule - Document concrete procedures to handle a key compromise

Ensure operations staff have the information they need, readily available, when rotation of encryption keys must be performed. Rotating keys should not require changes to source code or other risky deployment measures, since doing this in the middle of an incident will already place a great deal of stress on these staff.

#### Rule - Limit quantity of data encrypted with one key

If the amount of data encrypted grows beyond a **certain threshold**, a new key should be used. This **certain threshold** varies depending on the encryption algorithm used, but is typically 2³⁵ bytes (around 34 gigabytes) for 64 bit block ciphers (DES, 3DES, Blowfish, RC5, ...) and 2⁶⁸ bytes (around 295,147,905 terabytes) for 128 bit block ciphers (AES, TwoFish, Serpent). If encrypting with a modern cipher, this threshold is unlikely to be reached, but it should be considered when evaluating algorithms and rotation procedures.

### Rule - Follow applicable regulations on use of cryptography

#### Rule - Under PCI DSS requirement 3, you must protect cardholder data

The [Payment Card Industry (PCI) Data Security Standard (DSS)](https://www.pcisecuritystandards.org/document_library?category=pcidss&document=pci_dss) was developed to encourage and enhance cardholder data security and facilitate the broad adoption of consistent data security measures globally. The standard was introduced in 2005 and replaced individual compliance standards from Visa, Mastercard, Amex, JCB and Diners.

PCI DSS requirement 3 covers secure storage of credit card data. This requirement covers several aspects of secure storage including the data you must never store but we are covering Cryptographic Storage which is covered in requirements 3.4, 3.5 and 3.6 as you can see below:

##### 3.4 Render PAN (Primary Account Number), at minimum, unreadable anywhere it is stored

Compliance with requirement 3.4 can be met by implementing any of the four types of secure storage described in the standard which includes encrypting and hashing data. These two approaches will often be the most popular choices from the list of options. The standard doesn't refer to any specific algorithms but it mandates the use of **Strong Cryptography**. The glossary document from the PCI council defines **Strong Cryptography** as:

*Cryptography based on industry-tested and accepted algorithms, along with strong key lengths and proper key-management practices. Cryptography is a method to protect data and includes both encryption (which is reversible) and hashing (which is not reversible, or “one way”). SHA-1 is an example of an industry-tested and accepted hashing algorithm. Examples of industry-tested and accepted standards and algorithms for encryption include AES (128 bits and higher), TDES (minimum double-length keys), RSA (1024 bits and higher), ECC (160 bits and higher), and ElGamal (1024 bits and higher).*

If you have implemented the second rule in this cheat sheet you will have implemented a strong cryptographic algorithm which is compliant with or stronger than the requirements of PCI DSS requirement 3.4. You need to ensure that you identify all locations that card data could be stored including logs and apply the appropriate level of protection. This could range from encrypting the data to replacing the card number in logs.

This requirement can also be met by implementing disk encryption rather than file or column level encryption. The requirements for **Strong Cryptography** are the same for disk encryption and backup media. The card data should never be stored in the clear and by following the guidance in this cheat sheet you will be able to securely store your data in a manner which is compliant with PCI DSS requirement 3.4

##### 3.5 Protect any keys used to secure cardholder data against disclosure and misuse

As the requirement name above indicates, we are required to securely store the encryption keys themselves. This will mean implementing strong access control, auditing and logging for your keys. The keys must be stored in a location which is both secure and "away" from the encrypted data. This means key data shouldn't be stored on web servers, database servers etc

Access to the keys must be restricted to the smallest amount of users possible. This group of users will ideally be users who are highly trusted and trained to perform Key Custodian duties. There will obviously be a requirement for system/service accounts to access the key data to perform encryption/decryption of data.

The keys themselves shouldn't be stored in the clear but encrypted with a KEK (Key Encrypting Key). The KEK must not be stored in the same location as the encryption keys it is encrypting.

##### 3.6 Fully document and implement all key-management processes and procedures for cryptographic keys used for encryption of cardholder data

Requirement 3.6 mandates that key management processes within a PCI compliant company cover 8 specific key lifecycle steps:

###### 3.6.1 Generation of strong cryptographic keys

As we have previously described in this cheat sheet we need to use algorithms which offer high levels of data security. We must also generate strong keys so that the security of the data isn't undermined by weak cryptographic keys. A strong key is generated by using a key length which is sufficient for your data security requirements and compliant with the PCI DSS. The key size alone isn't a measure of the strength of a key. The data used to generate the key must be sufficiently random ("sufficient" often being determined by your data security requirements) and the entropy of the key data itself must be high.

###### 3.6.2 Secure cryptographic key distribution

The method used to distribute keys must be secure to prevent the theft of keys in transit. The use of a protocol such as Diffie Hellman can help secure the distribution of keys, the use of secure transport such as TLS and SSHv2 can also secure the keys in transit. Older protocols like SSLv3 should not be used.

###### 3.6.3 Secure cryptographic key storage

The secure storage of encryption keys including KEK's has been touched on in our description of requirement 3.5 (see above).

###### 3.6.4 Periodic cryptographic key changes

The PCI DSS standard mandates that keys used for encryption must be rotated at least annually. The key rotation process must remove an old key from the encryption/decryption process and replace it with a new key. All new data entering the system must encrypted with the new key. While it is recommended that existing data be rekeyed with the new key, as per the Rekey data at least every one to three years rule above, it is not clear that the PCI DSS requires this.

###### 3.6.5 Retirement or replacement of keys as deemed necessary when the integrity of the key has been weakened or keys are suspected of being compromised

The key management processes must cater for archived, retired or compromised keys. The process of securely storing and replacing these keys will more than likely be covered by your processes for requirements 3.6.2, 3.6.3 and 3.6.4

###### 3.6.6 Split knowledge and establishment of dual control of cryptographic keys

The requirement for split knowledge and/or dual control for key management prevents an individual user performing key management tasks such as key rotation or deletion. The system should require two individual users to perform an action (i.e. entering a value from their own OTP) which creates to separate values which are concatenated to create the final key data.

###### 3.6.7 Prevention of unauthorized substitution of cryptographic keys

The system put in place to comply with requirement 3.6.6 can go a long way to preventing unauthorised substitution of key data. In addition to the dual control process you should implement strong access control, auditing and logging for key data so that unauthorised access attempts are prevented and logged.

###### 3.6.8 Requirement for cryptographic key custodians to sign a form stating that they understand and accept their key-custodian responsibilities

To perform the strong key management functions we have seen in requirement 3.6 we must have highly trusted and trained key custodians who understand how to perform key management duties. The key custodians must also sign a form stating they understand the responsibilities that come with this role.

# Related documentation & tools

## Documentation

- [Testing for SSL-TLS](https://www.owasp.org/index.php/Testing_for_SSL-TLS_%28OWASP-CM-001%29)
- [Guide to Cryptography](https://www.owasp.org/index.php/Guide_to_Cryptography)
- [Application Security Verification Standard (ASVS) – Communication Security Verification Requirements (V10)](http://www.owasp.org/index.php/ASVS)
- [SSLLabs wiki](https://github.com/ssllabs/research/wiki)
- [Mozilla TLS wiki](https://wiki.mozilla.org/Security/Server_Side_TLS)
- [Transport Layer Protection Cheat Sheet](Transport_Layer_Protection_Cheat_Sheet.md)
- [BetterCrypto - Config Snippets](https://bettercrypto.org/)

## Tools

- [TestSSL](https://testssl.sh/)
- [Cryptosense](https://cryptosense.com/discovery/)