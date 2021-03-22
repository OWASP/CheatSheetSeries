# Password Storage Cheat Sheet

## Introduction

It is essential to store passwords in a way that prevents them from being obtained by an attacker even if the application or database is compromised. The majority of modern languages and frameworks provide built-in functionality to help store passwords safely.

This cheat sheet provides guidance on the various areas that need to be considered related to storing passwords. In short:

- **Use [Argon2id](#argon2id) with a minimum configuration of 15 MiB of memory, an iteration count of 2, and 1 degree of parallelism.**
- **If [Argon2id](#argon2id) is not available, use [bcrypt](#bcrypt) with a work factor of 10 or more and with a password limit of 64 characters.**
- **If FIPS-140 compliance is required, use [PBKDF2](#pbkdf2) with a work factor of 310,000 or more and set with an internal hash function of HMAC-SHA-256.**
- **Consider using a [pepper](#peppering) to provide additional defense in depth (though alone, it provides no additional secure characteristics).**

## Background

### Hashing vs Encryption

Hashing and encryption both provide ways to keep sensitive data safe. However, in almost all circumstances, **passwords should be hashed, NOT encrypted.**

**Hashing is a one-way function** (i.e., it is impossible to "decrypt" a hash and obtain the original plaintext value). Hashing is appropriate for password storage. Even if an attacker obtains the hashed password, they cannot enter it into an application's password field and log in as the victim.

**Encryption is a two-way function**, meaning that the original plaintext can be retrieved. Encryption is appropriate for storing data such as a user's address since this data is displayed in plaintext on the user's profile. Hashing their address would result in a garbled mess.

In the context of password storage, encryption should only be used in edge cases where it is necessary to obtain the original plaintext password. This might be necessary if the application needs to use the password to authenticate with another system that does not support a modern way to programmatically grant access, such as OpenID Connect (OIDC). Where possible, an alternative architecture should be used to avoid the need to store passwords in an encrypted form.

For further guidance on encryption, see the [Cryptographic Storage Cheat Sheet](Cryptographic_Storage_Cheat_Sheet.md).

### How Attackers Crack Password Hashes

Although it is not possible to "decrypt" password hashes to obtain the original passwords, it is possible to "crack" the hashes in some circumstances.

The basic steps are:

- Select a password you think the victim has chosen (e.g.`password1!`)
- Calculate the hash
- Compare the hash you calculated to the hash of the victim. If they match, you have correctly "cracked" the hash and now know the plaintext value of their password.

This process is repeated for a large number of potential candidate passwords. Different methods can be used to select candidate passwords, including:

- Lists of passwords obtained from other compromised sites
- Brute force (trying every possible candidate)
- Dictionaries or wordlists of common passwords

**Strong passwords stored with modern hashing algorithms should be effectively impossible for an attacker to crack.**  It is your responsibility as an application owner to select a modern hashing algorithm.

## Password Storage Concepts

### Salting

A salt is a unique, randomly generated string that is added to each password as part of the hashing process. As the salt is unique for every user, an attacker has to crack hashes one at a time using the respective salt rather than calculating a hash once and comparing it against every stored hash. This makes cracking large numbers of hashes significantly harder, as the time required grows in direct proportion to the number of hashes.

Salting also protects against an attacker pre-computing hashes using rainbow tables or database-based lookups. Finally, salting means that it is impossible to determine whether two users have the same password without cracking the hashes, as the different salts will result in different hashes even if the passwords are the same.

[Modern hashing algorithms](#password-hashing-algorithms) such as Argon2id, bcrypt, and PBKDF2 automatically salt the passwords, so no additional steps are required when using them.

### Peppering

A [pepper](https://www.ietf.org/archive/id/draft-ietf-kitten-password-storage-04.html#section-4.2) can be used in addition to salting to provide an additional layer of protection.

- The pepper is **shared between stored passwords**, rather than being *unique* like a salt. A pepper rotation strategy should be considered
- Unlike many implementations of a password salt, the pepper **should not be stored in the database**. Pepper should be managed as a secret itself, keeping its access as much segregated as possible from the legitimate access to the database or the different attack chains (backups, SQLi, OS access, OS privileged access, ...). Use vaults or HSMs for storage where possible and threat-model runtime use of the pepper
- The purpose of the pepper is to prevent an attacker from being able to crack any of the hashes if they only have access to the database, for example, if they have exploited a SQL injection vulnerability or obtained a backup of the database.

One of several peppering strategies is to hash the passwords as usual (specifically using a password hashing algorithm) and then HMAC or encrypt the hashes with a symmetrical encryption key before storing them in the database, with the key acting as the pepper. These peppering strategies do not affect the password hashing function in any way.

### Work Factors

The work factor is essentially the number of iterations of the hashing algorithm that are performed for each password (usually, it's actually `2^work` iterations). The purpose of the work factor is to make calculating the hash more computationally expensive, which in turn reduces the speed at which an attacker can attempt to crack the password hash. The work factor is typically stored in the hash output.

When choosing a work factor, a balance needs to be struck between security and performance. Higher work factors will make the hashes more difficult for an attacker to crack but will also make the process of verifying a login attempt slower. If the work factor is too high, this may degrade the performance of the application and could also be used by an attacker to carry out a denial of service attack by making a large number of login attempts to exhaust the server's CPU.

There is no golden rule for the ideal work factor - it will depend on the performance of the server and the number of users on the application. Determining the optimal work factor will require experimentation on the specific server(s) used by the application. As a general rule, calculating a hash should take less than one second.

#### Upgrading the Work Factor

One key advantage of having a work factor is that it can be increased over time as hardware becomes more powerful and cheaper.

The most common approach to upgrading the work factor is to wait until the user next authenticates and then to re-hash their password with the new work factor. This means that different hashes will have different work factors and may result in hashes never being upgraded if the user doesn't log back into the application. Depending on the application, it may be appropriate to remove the older password hashes and require users to reset their passwords next time they need to login in order to avoid storing older and less secure hashes.

## Password Hashing Algorithms

There are a number of modern hashing algorithms that have been specifically designed for securely storing passwords. This means that they should be slow (unlike algorithms such as MD5 and SHA-1, which were designed to be fast), and how slow they are can be configured by changing the [work factor](#work-factors).

Websites should not hide which password hashing algorithm they use. If you utilize a modern password hashing algorithm with proper configuration parameters, it should be safe to state in public which password hashing algorithms are in use and be listed [here](https://pulse.michalspacek.cz/passwords/storages).

The main three algorithms that should be considered are listed below:

### Argon2id

[Argon2](https://en.wikipedia.org/wiki/Argon2) is the winner of the 2015 [Password Hashing Competition](https://password-hashing.net). There are three different versions of the algorithm, and the Argon2id variant should be used, as it provides a balanced approach to resisting both side-channel and GPU-based attacks.

Rather than a simple work factor like other algorithms, Argon2id has three different parameters that can be configured. Argon2id should use one of the following configuration settings as a base minimum which includes the minimum memory size (m), the minimum number of iterations (t) and the degree of parallelism (p).

- m=37 MiB, t=1, p=1
- m=15 MiB, t=2, p=1

Consider raising these settings to the following (or more) if performance considerations do not have a negative impact your system.

- m=37 MiB, t=11, p=1
- m=15 MiB, t=26, p=1

### bcrypt

The [bcrypt](https://en.wikipedia.org/wiki/bcrypt) password hashing function should be the second choice for password storage if Argon2id is not available or PBKDF2 is required to achieve FIPS-140 compliance.

The minimum work factor for bcrypt should be 10. Consider raising the work factor to 12 (or more) if performance considerations do not have a negative impact on your system.

#### Input Limits

bcrypt has a maximum length input length of 72 characters [for most implementations](https://security.stackexchange.com/questions/39849/does-bcrypt-have-a-maximum-password-length). To protect against this issue, a maximum password length of 64 characters should be enforced when using bcrypt.

#### Pre-Hashing Passwords

An alternative approach is to pre-hash the user-supplied password with a fast algorithm such as SHA-256, and then to hash the resulting hash with bcrypt (i.e., `bcrypt(base64(hmac-sha256(data:$password, key:$pepper)), $salt, $cost)`). This is a dangerous (but common) practice that **should be avoided** due to [password shucking](https://www.youtube.com/watch?v=OQD3qDYMyYQ) and other issues when [combining bcrypt with other hash functions](https://blog.ircmaxell.com/2015/03/security-issue-combining-bcrypt-with.html).

### PBKDF2

[PBKDF2](https://en.wikipedia.org/wiki/PBKDF2) is recommended by [NIST](https://pages.nist.gov/800-63-3/sp800-63b.html#memsecretver) and has FIPS-140 validated implementations. So, it should be the preferred algorithm when these are required.

PBKDF2 requires that you select an internal hashing algorithm such as an HMAC or a variety of other hashing algorithms. HMAC-SHA-256 is widely supported and is recommended by NIST.

The work factor for PBKDF2 is implemented through an iteration count, which should set differently based on the internal hashing algorithm used.

- PBKDF2-HMAC-SHA1: 720,000 iterations
- PBKDF2-HMAC-SHA256: 310,000 iterations
- PBKDF2-HMAC-SHA512: 120,000 iterations

Consider raising these settings to the following (or more) if performance considerations do not have a negative impact your system.

- PBKDF2-HMAC-SHA1: 110,000,000 iterations
- PBKDF2-HMAC-SHA256: 48,000,000 iterations
- PBKDF2-HMAC-SHA512: 19,000,000 iterations

When PBKDF2 is used with an HMAC, and the password is longer than the hash function's block size (64 bytes for SHA-256), the password will be automatically pre-hashed. For example, the password "This is a password longer than 512 bits which is the block size of SHA-256" is converted to the hash value (in hex) fa91498c139805af73f7ba275cca071e78d78675027000c99a9925e2ec92eedd. A good implementation of PBKDF2 will perform this step before the expensive iterated hashing phase, but some implementations perform the conversion on each iteration. This can make hashing long passwords significantly more expensive than hashing short passwords. If a user can supply very long passwords, there is a potential denial of service vulnerability, such as the one published in [Django](https://www.djangoproject.com/weblog/2013/sep/15/security/) in 2013. Manual [pre-hashing](#pre-hashing-passwords) can reduce this risk but requires adding a [salt](#salting) to the pre-hash step.

## Upgrading Legacy Hashes

For older applications built using less secure hashing algorithms such as MD5 or SHA-1, these hashes should be upgraded to modern password hashing algorithms as described above. When the user next enters their password (usually by authenticating on the application), it should be re-hashed using the new algorithm. It would also be good practice to expire the users' current password and require them to enter a new one so that any older (less secure) hashes of their password are no longer useful to an attacker.

However, this approach means that old (less secure) password hashes will be stored in the database until the user logs in. Two main approaches can be taken to avoid this dilemma.

One method is to expire and delete the password hashes of users who have been inactive for an extended period and require them to reset their passwords to login again. Although secure, this approach is not particularly user-friendly. Expiring the passwords of many users may cause issues for support staff or may be interpreted by users as an indication of a breach.

An alternative approach is to use the existing password hashes as inputs for a more secure algorithm. For example, if the application originally stored passwords as `md5($password)`, this could be easily upgraded to `bcrypt(md5($password))`. Layering the hashes avoids the need to know the original password; however, it can make the hashes easier to crack. These hashes should be replaced with direct hashes of the users' passwords next time the user logs in.
