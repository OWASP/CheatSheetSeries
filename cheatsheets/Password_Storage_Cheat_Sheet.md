# Introduction

As the majority of users will re-use passwords between different applications, it is important to store passwords in a way that that prevents them from being obtained by an attacker, even if the application or database is compromised. As with most areas of cryptography, there are a many different areas that need to be considered, but happily, the majority of modern languages and frameworks provide built-in functionality to help store passwords, which handles much of the complexity for you.

This Cheat Sheet provides guidance on the various areas that need to be considered related to storing passwords. In short:

- **Use Argon2 if your library supports it.**
  - **If it doesn't, use Scrypt, PBKDF2 or Bcrypt.**
- **Set a reasonable [work factor](#work-factors) for you system.**
- **Consider using a pepper to provide an additional layer of security.**

## Hashing vs Encryption

Hashing and encrypted are two terms that are often confused or used incorrectly. The key difference between them is that hashing is a **one way** function (i.e, it is not possible to "decrypt" a hash and obtain the original value), whereas encryption is a two-way function.

In almost all circumstances passwords should be hashed, rather than encrypted, as this makes it difficult or impossible for an attacker to obtain the original passwords from the hashes.

Encryption should only be used in edge cases where it is necessary to be able to obtain the original password. Some examples of where this might be necessary are:

- If the application needs to use the password to authenticate against an external legacy system that doesn't support SSO.
- If it is necessary to retrieve individual characters from the password.

The ability to decrypt passwords represents a serious security risk, so should be fully risk assessed. Where possible an alternative architecture should be used to avoid the need to store passwords in an encrypted form.

This Cheat Sheet is focused on password hashing - for further guidance on encrypting passwords see the [Cryptographic Storage Cheat Sheet](Cryptographic_Storage_Cheat_Sheet.md).

## How Attackers Crack Password Hashes

Although it is not possible to "decrypt" password hashes to obtain the original passwords, in some circumstances it is possible to "crack" the hashes. The basic steps are:

- Select a likely candidate (such as "password").
- Calculate the hash of the input.
- Compare it to the target hash.

This process is then repeated for a large number of potential candidate passwords until a match is found. There are a large number of different methods that can be used to select candidate passwords, including:

- Brute force (trying every possible candidate).
- Dictionaries or wordlists of common passwords
- Lists of passwords obtained from other compromised sites.
- More sophisticated algorithms such as [Markov chains](https://github.com/magnumripper/JohnTheRipper/blob/bleeding-jumbo/doc/MARKOV) or [PRINCE](https://github.com/hashcat/princeprocessor)
- Patterns or masks (such as "1 capital letter, 6 lowercase letters, 1 number").

The cracking process is not guaranteed to be successful, and will depend on a number of factors:

- The strength of the password.
- The speed of the algorithm (or work factor for modern algorithms).
- The number of passwords being targeted (assuming they have unique salts).

Strong passwords stored with modern hashing algorithms should be effectively impossible for an attacker to crack.

# Hashing Concepts

## Salting

A salt is a unique, randomly generated string that is added to each password as part of the hashing process. As the salt is unique for every user, an attacker has to crack hashes one at a time using the respective salt, rather than being able to calculate a hash once and compare it against every stored hash. This makes cracking large numbers of hashes significantly harder, as the time required grows in direct proportion to the number of hashes.

Salting also provides protection against an attacker pre-computing hashes using rainbow tables or database-based lookups. Finally, salting means that it is not possible to determine whether two users have the same password without cracking the hashes, as the different salts will result in different hashes even if the passwords are the same.

Modern hashing algorithms such as Bcrypt or Argon2 automatically salt  the passwords, so no additional steps are required when using them. However, if you are using a [legacy password hashing algorithm](#legacy-algorithms) then salting needs to be implemented manually. The basic steps to perform this are:

* Generate a salt using a [cryptographically secure function](Cryptographic_Storage_Cheat_Sheet.md#rule---use-cryptographically-secure-pseudo-random-number-generators-csprng).
  * The salt should be at least 16 characters long.
  * Encode the salt into a safe character set such as hexadecimal or Base64.
* Combine the salt with the password.
  * This can be done using simple concatenation, or a construct such as a HMAC.
* Hash the combined password and salt.
* Store the salt and the password hash.

## Peppering

A [pepper](https://en.wikipedia.org/wiki/Pepper_(cryptography)) can be used in additional to salting to provide an additional layer of protection. It is similar to a salt, but has two key differences:

* The pepper is shared between all stored passwords, rather than being unique like a salt.
* The pepper is stored separately from the hashes (i.e, not in the database).

The purpose of the pepper is to prevent an attacker from being able to crack any of the hashes if they only have access to the database, for example if they have exploited a SQL injection vulnerability or obtained a backup of the database.

The pepper should be at least 32 characters long, and should be randomly generated. It should be stored in an application configuration file (protected with appropriate permissions), using the secure storage APIs provided by the operating system, or in a HSM.

The pepper is traditionally used in a similar way to a salt, but concatenating it with the password prior to hashing, using a construct such as `hash(pepper . password)`.

An alternative approach is to hash the passwords as usual, and then encrypt the stored hashes with a symmetrical encryption key before storing them in the database, with the key acting as the pepper. This avoids some of the issues with the traditional approach to peppering, and allows for much easier rotation of the pepper if it is believed to be compromised.

### Disadvantages

The main issues with peppers is their long term maintenance. Changing the pepper in use will invalidate all of the existing passwords stored in the database, which means that it can't easily be changed in the event of the pepper being compromised.

One solution to this is to store the ID of the pepper in the database alongside the associated password hashes. When the pepper needs to be updated, this ID can updated for hashes using the new pepper. Although the application will need to store all of the peppers that are currently in use, this does provide a way to replace a compromised pepper.

## Work Factors

The work factor is essentially the number of iterations of the hashing algorithm that are performed for each passwords (usually it's actually `2^work` iterations). The purpose of the work factor is to make calculating the hash more computationally expensive, which in turn reduces the speed at which an attacker can attempt to crack the password hash.

When choosing a work factor, a balance needs to be struck between security and performance. Higher work factors will make the hashes more difficult for an attacker to crack, but will also make the process of verifying a login attempt slower. If the work factor is too high, this may degrade the performance of the application, and could also be used by an attacker to carry out a denial of service attack by making a large number of login attempts to exhaust server's CPU.

There is no golden rule for the ideal work factor - it will depend on the performance of the server and the number of users on the application. Determining the optimal work factor will require experimentation on the specific server(s) used by the application. As a general rule, the calculating a hash should take less than one second, although on higher traffic sites it should be significantly less than this.

### Upgrading the Work Factor

One key advantage of having a work factor is that it can be increased over time as hardware becomes more powerful and cheaper. Taking Moore's Law (i.e, that computational power at a given price point doubles every eighteen months) as a rough approximation, this means that the work factor should be increased by 1 every eighteen months.

The most common approach to upgrading the work factor is to wait until the user next authenticates, and then to re-hash their password with the new work factor. This means that different hashes will have different work factors, and may result in hashes never being upgraded if the user doesn't log back in to the application. In some cases, it may be appropriate to remove the older password hashes and require users to reset their passwords next time they need to login, in order to avoid storing older and less secure hashes.

In some cases, it may be possible to increase the work factor of the hashes without the original password, although this is not supported by common hashing algorithms such as Bcrypt and PBKDF2.

## Maximum Password Lengths

Some hashing algorithms such as Bcrypt have a maximum length for the input, which can [vary between different implementations](https://security.stackexchange.com/questions/39849/does-bcrypt-have-a-maximum-password-length) of the algorithm. Where Bcrypt is used, a maximum length of 50 characters should be enforced on the input to cover all known implementations.

Additionally, due to how computationally expensive modern hashing functions are, if a user can supply very long passwords then there is a potential denial of service vulnerability, such as the one published in [Django](https://www.djangoproject.com/weblog/2013/sep/15/security/) in 2013.

In order to protect against both of these issues, a maximum password length should be enforced. This should be 50 characters for Bcrypt, and at least 64 characters for other algorithms. There are two main ways that this can be done:

- Restrict the maximum length in a password policy.
- Hash the password with another algorithm such as SHA-1 (which produces a 40 character output) or SHA-256 (64 characters) before hashing it with the modern algorithm.

# Hashing Algorithms

## Modern Algorithms

There are four main algorithms that should be considered for hashing passwords in modern applications. All of these algorithms support an iteration count of [work factor](#work-factors), which should be adjusted based on the system they are being used with.

- [Argon2](https://github.com/P-H-C/phc-winner-argon2) is the winner of the 2015 [Password Hashing Competition](https://password-hashing.net), and should be used as the first choice when it is available. It has strong resistance to both GPU and ASIC based attacks.
- [Scrypt](https://en.wikipedia.org/wiki/Scrypt) is designed to resist GPU based attacks, but is less widely supported.
- [PBKDF2](https://en.wikipedia.org/wiki/PBKDF2) is recommended by [NIST](https://pages.nist.gov/800-63-3/sp800-63b.html#memsecretver), and should be used when FIPS compliance is required. It requires that 
- [Bcrypt](https://en.wikipedia.org/wiki/Bcrypt) is the oldest of the algorithms, and is more susceptible to GPU based attacks. However, due to its age it is widely supported across most languages.

It should be stressed that even though Bcrypt is considered comparatively weak compared to newer algorithms such as Scrypt or Argon2, it is still substantially stronger than legacy algorithms such as MD5 and SHA-1. Although exact cracking speeds will vary based on the hardware, to give an idea of context, a benchmark using [8 Nvidia GTX 1080 GPUs](https://gist.github.com/epixoip/a83d38f412b4737e99bbef804a270c40) showed Bcrypt hashes to be approximately 2 million times harder to crack than MD5.

## Legacy Algorithms

In some circumstances it is not possible to use [modern hashing algorithms](#modern-algorithms), usually due tot he use of legacy language or environments. Where possible, third party libraries should be used to provide these algorithms. However, if the only algorithms available are legacy ones such as MD5 and SHA-1, then there are a number of steps that can be taken to improve the security of stored passwords.

- Use the strongest algorithm available (SHA-512 > SHA-256 > SHA-1 > MD5).
- Use a [pepper](#peppering).
- Use a unique [salt](#salting) for each password, generated using a [cryptographically secure random number generator](Cryptographic_Storage_Cheat_Sheet.md#rule---use-cryptographically-secure-pseudo-random-number-generators-csprng).
- Use a very large number of iterations of the algorithm (at least 10,000, and possibly significantly more depending on the speed of the hardware).

It should be emphasised that these steps **are not as good as using a  modern hashing algorithm**, and that this approach should only be taken where no other options are available.

## Upgrading Legacy Hashes

For older applications that were built using less secure password hashing algorithms such as MD5 or SHA-1, there are a number of different methods that can be undertaken to upgrade the password hashes into a more secure algorithm.

The simplest way to do this is to use the existing password hashes as inputs for a more secure algorithm. For example if the application originally stored passwords as `md5(password)`, this could be easily upgraded to `argon2(md5(password))`. Stacking the hashes in this manner avoids the need to known the original password, and can also solve potential issues related to [password length](#maximum-password-lengths).

An alternative approach is to wait until the user enters their password (by authenticating on the application), and then replacing their old password hash with a new one using a modern algorithm. The downside of this is that old, weak hashes will remain in the database until the users next login, which could mean that they are never replaced if users are inactive. One way to solve this is to expire and delete the password hashes of users who have been inactive for a long period, and require them to reset their passwords to login again. This approach also requires more complicated authentication code, which needs to determine the type of hash stored, compare securely against it, and then overwrite it. There are a number of [articles](https://veggiespam.com/painless-password-hash-upgrades/) that discuss these issues and other potential approaches.

## Custom Algorithms

Writing custom cryptographic code such as a hashing algorithm is **really hard** and should **never be done** outside of an academic exercise. Any potential benefit that you might have from using an unknown or bespoke algorithm will be vastly overshadowed by the weaknesses that exist in it.

**Do not do this.**
