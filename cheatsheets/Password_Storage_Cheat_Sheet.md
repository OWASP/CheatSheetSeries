# Password Storage Cheat Sheet

## Introduction

It is important to store passwords in a way that prevents them from being obtained by an attacker even if the application or database is compromised. The majority of modern languages and frameworks provide built-in functionality to help store passwords safely.

This Cheat Sheet provides guidance on the various areas that need to be considered related to storing passwords. In short:

- **Use [bcrypt](#bcrypt) with work factor 12 or more and with a password limit of 64 characters.**
- **Consider the use of [Argon2id](#argon2id) with configuration settings inline with [IETF specifications](https://tools.ietf.org/html/draft-ietf-kitten-password-storage-03#section-5.1).**
- **Use [PBKDF2](#pbkdf2) with a work factor of 310,000 or more and set with an internal hash function of HMAC-SHA-256 for systems requiring FIPS-140 compliance.**
- **Consider using a [pepper](#peppering) to provide an additional defence in depth (though alone it provides no additional secure characteristics).**

## Background

### Hashing vs Encryption

Hashing and encryption both provide ways to keep sensitive data safe. However, in almost all circumstances, **passwords should be hashed NOT encrypted.**

**Hashing is a one-way function** (i.e, it is not possible to "decrypt" a hash and obtain the original plaintext value). Hashing is appropriate for password storage because even if an attacker obtains the hashed password, they can't enter it into the password field of your application and log in as the victim.

**Encryption is a two-way function**, meaning that the original plaintext can be retrieved. Encryption is appropriate for storing data such as a user's address since this data is displayed in plaintext on the user's profile. Hashing their address would result in a garbled mess.

In the context of password storage, encryption should only be used in edge cases where it is necessary to obtain the original plaintext password. This might be necessary if the application needs to use the password to authenticate with another system that doesn't support a modern way to programmatically grant access, such as OpenID Connect (OIDC). Where possible, an alternative architecture should be used to avoid the need to store passwords in an encrypted form.

For further guidance on encryption see the [Cryptographic Storage Cheat Sheet](Cryptographic_Storage_Cheat_Sheet.md).

### How Attackers Crack Password Hashes

Although it is not possible to "decrypt" password hashes to obtain the original passwords, in some circumstances it is possible to "crack" the hashes.

The basic steps are:

- Select a password you think the victim has chosen (e.g.`password1!`)
- Calculate the hash
- Compare the hash you calculated to the hash of the victim. If they match, you have correctly "cracked" the hash and now know the plaintext value of their password.

This process is repeated for a large number of potential candidate passwords. There are different methods that can be used to select candidate passwords, including:

- Lists of passwords obtained from other compromised sites
- Brute force (trying every possible candidate)
- Dictionaries or wordlists of common passwords

**Strong passwords stored with modern hashing algorithms should be effectively impossible for an attacker to crack.**  It is your responsibility as an application owner to select a modern hashing algorithm.

## Password Storage Concepts

### Salting

A salt is a unique, randomly generated string that is added to each password as part of the hashing process. As the salt is unique for every user, an attacker has to crack hashes one at a time using the respective salt, rather than being able to calculate a hash once and compare it against every stored hash. This makes cracking large numbers of hashes significantly harder, as the time required grows in direct proportion to the number of hashes.

Salting also provides protection against an attacker pre-computing hashes using rainbow tables or database-based lookups. Finally, salting means that it is not possible to determine whether two users have the same password without cracking the hashes, as the different salts will result in different hashes even if the passwords are the same.

[Modern hashing algorithms](#password-hashing-algorithms) such as Argon2, bcrypt and PBKDF2 automatically salt the passwords, so no additional steps are required when using them.

### Peppering

A [pepper](https://tools.ietf.org/html/draft-ietf-kitten-password-storage-03#section-4.2) can be used in addition to salting to provide an additional layer of protection. It is similar to a salt but has four key differences:

- The pepper is **shared between all stored passwords**, rather than being *unique* like a salt. This makes a pepper predicable, and attempts to crack a password hash *probabilistic*. The static nature of a pepper also *weakens" hash collision resistance whereas the salt improves hash collision resistance by extending the length with unique characters that increase the entropy of input to the hashing function.
- The pepper is **not stored in the database**, unlike many implementations of a password salt (but not always true for a salt).
- The pepper is not a mechanism to make password cracking **too hard to be feasible** for an attacker, like many password storage protections (salting among these) aim to do.

The purpose of the pepper is to prevent an attacker from being able to crack any of the hashes if they only have access to the database, for example if they have exploited a SQL injection vulnerability or obtained a backup of the database.

The pepper should be *at-least* 32 characters long and should be randomly generated using a secure pseudo-random generator (CSPRNG). It should be stored securely in "secrets management" solution.

Never place a pepper as a suffix as this may lead to vulnerabilities such as issues related to truncation and length-extension attacks. Practically these threats allow the input password component to validate successfully because the unique password is never truncated, only the probabilistic pepper would be truncated.

#### Alternatives

An alternative pepper approach is to hash the passwords as usual (specifically one-way hashing) and then encrypt the hashes with a symmetrical encryption key before storing them in the database, with the key acting as the pepper without effecting the password directly or the hash function in any way. This avoids known issues with the concatenation/prefix approach and it allows for password to remain valid when you apply key rotation (using established encryption key rotation procedures) if the key that acts as a pepper is believed to be compromised.

Another solution may be storing the secret pepper with an ID to easily retrieve it, and past known peppers. When you store a password hash, store only the ID of the pepper in the database alongside the associated password hashes. This allows rotation of the pepper without disclosing the secret pepper itself. When the pepper needs to be updated, this ID can be updated for hashes using the new pepper. The requires the application logic to additionally associate an ID to an external store with all the pepper secret values that are valid and currently in use, which may or may not be possible for all secret stores (HSM and secret vaults typically support a lookup ID).

### Work Factors

The work factor is essentially the number of iterations of the hashing algorithm that are performed for each password (usually it's actually `2^work` iterations). The purpose of the work factor is to make calculating the hash more computationally expensive, which in turn reduces the speed at which an attacker can attempt to crack the password hash. The work factor is typically stored in the hash output.

When choosing a work factor, a balance needs to be struck between security and performance. Higher work factors will make the hashes more difficult for an attacker to crack, but will also make the process of verifying a login attempt slower. If the work factor is too high, this may degrade the performance of the application, and could also be used by an attacker to carry out a denial of service attack by making a large number of login attempts to exhaust the server's CPU.

There is no golden rule for the ideal work factor - it will depend on the performance of the server and the number of users on the application. Determining the optimal work factor will require experimentation on the specific server(s) used by the application. As a general rule, calculating a hash should take less than one second.

#### Upgrading the Work Factor

One key advantage of having a work factor is that it can be increased over time as hardware becomes more powerful and cheaper.

The most common approach to upgrading the work factor is to wait until the user next authenticates, and then to re-hash their password with the new work factor. This means that different hashes will have different work factors, and may result in hashes never being upgraded if the user doesn't log back in to the application. Depending on the application, it may be appropriate to remove the older password hashes and require users to reset their passwords next time they need to login, in order to avoid storing older and less secure hashes.

## Password Hashing Algorithms

There are a number of modern hashing algorithms that have been specifically designed for securely storing passwords. This means that they should be slow (unlike algorithms such as MD5 and SHA-1 which were designed to be fast), and how slow they are can be configured by changing the [work factor](#work-factors).

The main three algorithms that should be considered are listed below:

### Argon2id

[Argon2](https://en.wikipedia.org/wiki/Argon2) is the winner of the 2015 [Password Hashing Competition](https://password-hashing.net). There are three different versions of the algorithm, and the Argon2**id** variant should be used where available, as it provides a balanced approach to resisting both side channel and GPU-based attacks.

Rather than a simple work factor like other algorithms, Argon2 has three different parameters that can be configured, meaning that it's more complicated to correctly tune for the environment. The specification from 2015 contains [guidance on choosing appropriate parameters](https://password-hashing.net/argon2-specs.pdf). There is also a 2021 [IETF draft](https://tools.ietf.org/html/draft-ietf-kitten-password-storage-03#section-5.1) on tuning Argon2 and other password storage algorithms.

However, if you're not in a position to properly tune Argon2, then a simpler algorithm such as [bcrypt](#bcrypt) may be a better choice.

### bcrypt

[bcrypt](https://en.wikipedia.org/wiki/bcrypt) is the most widely supported of the algorithms and should be the default choice unless there are specific requirements for PBKDF2, or appropriate knowledge to tune Argon2.

The minimum work factor for bcrypt should be 12.

#### Input Limits

bcrypt has a maximum length for the input, which is 72 characters for most implementations (there are some [reports](https://security.stackexchange.com/questions/39849/does-bcrypt-have-a-maximum-password-length) that other implementations have lower maximum lengths, but none have been identified at the time of writing). Where bcrypt is used, a maximum length of 64 characters should be enforced on the input, as this provides a sufficiently high limit, while still allowing for string termination issues and not revealing that the application uses bcrypt.

In order to protect against this issue, a maximum password length of 64 characters should be enforced when using bcrypt.

#### Pre-Hashing Passwords

An alternative approach is to pre-hash the user-supplied password with a fast algorithm such as SHA-384, and then to hash the resultant hash with bcrypt (i.e, `bcrypt(sha384($password))`).

When using pre-hashing, ensure that the output for the pre-hashing algorithm is safely encoded as hexadecimal or base64, as bcrypt can behave in undesirable ways if the [input contains null bytes](https://blog.ircmaxell.com/2015/03/security-issue-combining-bcrypt-with.html).

Also, it is critical to not store the sha384 hash in any way and to only store the bcrypt output value.

### PBKDF2

[PBKDF2](https://en.wikipedia.org/wiki/PBKDF2) is recommended by [NIST](https://pages.nist.gov/800-63-3/sp800-63b.html#memsecretver) and has FIPS-140 validated implementations. So, it should be the preferred algorithm when these are required. Additionally, it is supported out of the box in the .NET framework, so is commonly used in ASP.NET applications.

PBKDF2 requires that you select an internal hashing algorithm. You can choose HMACs or a variety of other hashing algorithms. HMAC-SHA-256 is widely supported and is recommended by NIST.

The work factor for PBKDF2 is implemented through an iteration count, which should set differently based on the internal hashing algorithm used.

- PBKDF2-HMAC-SHA1: 720,000 iterations
- PBKDF2-HMAC-SHA256: 310,000 iterations
- PBKDF2-HMAC-SHA512: 120,000 iterations

When PBKDF2 is used with HMAC, and the password is longer than the block size of the hash function (64 bytes for SHA-256), then the password will be automatically pre-hashed. For example, the password "This is a password longer than 512 bits which is the block size of SHA-256" is converted to the hash value (in hex) fa91498c139805af73f7ba275cca071e78d78675027000c99a9925e2ec92eedd. A good implementation of PBKDF2 will perform this step once before the expensive iterated hashing phase, but some implementations perform the conversion on each iteration. This can make hashing long passwords significantly more expensive than hashing short passwords. If a user can supply very long passwords then there is a potential denial of service vulnerability, such as the one published in [Django](https://www.djangoproject.com/weblog/2013/sep/15/security/) in 2013. Manual [pre-hashing](#pre-hashing-passwords) can reduce this risk.

## Upgrading Legacy Hashes

For older applications that were built using less secure hashing algorithms such as MD5 or SHA-1, these hashes should be upgraded to more modern and secure ones. When the user next enters their password (usually by authenticating on the application), it should be re-hashed using the new algorithm. It would also be good practice to expire the users' current password and require them to enter a new one, so that any older (less secure) hashes of their password are no longer useful to an attacker.

However, this approach means that old (less secure) password hashes will be stored in the database until the user next logs in and may be stored indefinitely. There are two main approaches that can be taken to solve this.

One method is to expire and delete the password hashes of users who have been inactive for a long period, and require them to reset their passwords to login again. Although secure, this approach is not particularly user friendly, and expiring the passwords of a large number of users may cause issues for the support staff, or may be interpreted by users as an indication of a breach. However, if there is a reasonable delay between implementing the password hash upgrade code on login and removing old password hashes, most active users should have changed their passwords already.

An alternative approach is to use the existing password hashes as inputs for a more secure algorithm. For example if the application originally stored passwords as `md5($password)`, this could be easily upgraded to `bcrypt(md5($password))`. Layering the hashes in this manner avoids the need to known the original password, however it can make the hashes easier to crack. As such, these hashes should be replaced with direct hashes of the users' passwords next time the users login.
