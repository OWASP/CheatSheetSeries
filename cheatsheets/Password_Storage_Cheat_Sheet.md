# Password Storage Cheat Sheet

## Introduction

As the majority of users will re-use passwords between different applications, it is important to store passwords in a way that prevents them from being obtained by an attacker, even if the application or database is compromised. As with most areas of cryptography, there are many different factors that need to be considered, but fortunately, the majority of modern languages and frameworks provide built-in functionality to help store passwords, which handles much of the complexity.

This Cheat Sheet provides guidance on the various areas that need to be considered related to storing passwords. In short:

- **Use [Bcrypt](#modern-algorithms) unless you have a good reason not to.**
- **Set a reasonable [work factor](#work-factors) for you system.**
- **Use a [salt](#salting) (modern algorithms do this for you automatically).**
- **Consider using a [pepper](#peppering) to provide an additional layer of security.**

## Background

### Hashing vs Encryption

Hashing and encryption are two terms that are often confused or used incorrectly. The key difference between them is that hashing is a **one way** function (i.e, it is not possible to "decrypt" a hash and obtain the original value), whereas encryption is a two-way function.

In almost all circumstances, passwords should be hashed rather than encrypted, as this makes it difficult or impossible for an attacker to obtain the original passwords from the hashes.

Encryption should only be used in edge cases where it is necessary to be able to obtain the original password. Some examples of where this might be necessary are:

- If the application needs to use the password to authenticate against an external legacy system that doesn't support SSO.
- If it is necessary to retrieve individual characters from the password.

The ability to decrypt passwords represents a serious security risk, so it should be fully risk assessed. Where possible, an alternative architecture should be used to avoid the need to store passwords in an encrypted form.

This Cheat Sheet is focused on password hashing - for further guidance on encrypting passwords see the [Cryptographic Storage Cheat Sheet](Cryptographic_Storage_Cheat_Sheet.md).

### How Attackers Crack Password Hashes

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

The cracking process is not guaranteed to be successful, and the success rate will depend on a number of factors:

- The strength of the password.
- The speed of the algorithm (or work factor for modern algorithms).
- The number of passwords being targeted (assuming they have unique salts).

Strong passwords stored with modern hashing algorithms should be effectively impossible for an attacker to crack.

## Hashing Concepts

### Salting

A salt is a unique, randomly generated string that is added to each password as part of the hashing process. As the salt is unique for every user, an attacker has to crack hashes one at a time using the respective salt, rather than being able to calculate a hash once and compare it against every stored hash. This makes cracking large numbers of hashes significantly harder, as the time required grows in direct proportion to the number of hashes.

Salting also provides protection against an attacker pre-computing hashes using rainbow tables or database-based lookups. Finally, salting means that it is not possible to determine whether two users have the same password without cracking the hashes, as the different salts will result in different hashes even if the passwords are the same.

[Modern hashing algorithms](#modern-algorithms) such as Argon2 or Bcrypt automatically salt the passwords, so no additional steps are required when using them. However, if you are using a [legacy password hashing algorithm](#legacy-algorithms) then salting needs to be implemented manually. The basic steps to perform this are:

- Generate a salt using a [cryptographically secure function](Cryptographic_Storage_Cheat_Sheet.md#secure-random-number-generation).
    - The salt should be at least 16 characters long.
    - Encode the salt into a safe character set such as hexadecimal or Base64.
- Combine the salt with the password.
    - This can be done using simple concatenation, or a construct such as a HMAC.
- Hash the combined password and salt.
- Store the salt and the password hash.

### Peppering

A [pepper](https://en.wikipedia.org/wiki/Pepper_%28cryptography%29) can be used in addition to salting to provide an additional layer of protection. It is similar to a salt but has two key differences:

- The pepper is shared between all stored passwords, rather than being unique like a salt.
- The pepper is **not stored in the database**, unlike the salts.

The purpose of the pepper is to prevent an attacker from being able to crack any of the hashes if they only have access to the database, for example if they have exploited a SQL injection vulnerability or obtained a backup of the database.

The pepper should be at least 32 characters long and should be randomly generated. It should be stored in an application configuration file (protected with appropriate permissions) using the secure storage APIs provided by the operating system, or in a Hardware Security Module (HSM).

The pepper is traditionally used in a similar way to a salt by concatenating it with the password prior to hashing, using a construct such as `hash($pepper . $password)`.

An alternative approach is to hash the passwords as usual and then encrypt the hashes with a symmetrical encryption key before storing them in the database, with the key acting as the pepper. This avoids some of the issues with the traditional approach to peppering, and it allows for much easier rotation of the pepper if it is believed to be compromised.

#### Disadvantages

The main issues with peppers is their long term maintenance. Changing the pepper in use will invalidate all of the existing passwords stored in the database, which means that it can't easily be changed in the event of the pepper being compromised.

One solution to this is to store the ID of the pepper in the database alongside the associated password hashes. When the pepper needs to be updated, this ID can updated for hashes using the new pepper. Although the application will need to store all of the peppers that are currently in use, this does provide a way to replace a compromised pepper.

### Work Factors

The work factor is essentially the number of iterations of the hashing algorithm that are performed for each password (usually it's actually `2^work` iterations). The purpose of the work factor is to make calculating the hash more computationally expensive, which in turn reduces the speed at which an attacker can attempt to crack the password hash. The work factor is typically stored in the hash output.

When choosing a work factor, a balance needs to be struck between security and performance. Higher work factors will make the hashes more difficult for an attacker to crack, but will also make the process of verifying a login attempt slower. If the work factor is too high, this may degrade the performance of the application, and could also be used by an attacker to carry out a denial of service attack by making a large number of login attempts to exhaust the server's CPU.

There is no golden rule for the ideal work factor - it will depend on the performance of the server and the number of users on the application. Determining the optimal work factor will require experimentation on the specific server(s) used by the application. As a general rule, calculating a hash should take less than one second, although on higher traffic sites it should be significantly less than this.

#### Upgrading the Work Factor

One key advantage of having a work factor is that it can be increased over time as hardware becomes more powerful and cheaper. Taking Moore's Law (i.e, that computational power at a given price point doubles every eighteen months) as a rough approximation, this means that the work factor should be increased by 1 every eighteen months.

The most common approach to upgrading the work factor is to wait until the user next authenticates, and then to re-hash their password with the new work factor. This means that different hashes will have different work factors, and may result in hashes never being upgraded if the user doesn't log back in to the application. Depending on the application, it may be appropriate to remove the older password hashes and require users to reset their passwords next time they need to login, in order to avoid storing older and less secure hashes.

In some cases, it may be possible to increase the work factor of the hashes without the original password, although this is not supported by common hashing algorithms such as Bcrypt and PBKDF2.

### Maximum Password Lengths

Some hashing algorithms such as Bcrypt have a maximum length for the input, which is 72 characters for most implementations (there are some [reports](https://security.stackexchange.com/questions/39849/does-bcrypt-have-a-maximum-password-length) that other implementations have lower maximum lengths, but none have been identified at the time of writing). Where Bcrypt is used, a maximum length of 64 characters should be enforced on the input, as this provides a sufficiently high limit, while still allowing for string termination issues and not revealing that the application uses Bcrypt.

Additionally, due to how computationally expensive modern hashing functions are, if a user can supply very long passwords then there is a potential denial of service vulnerability, such as the one published in [Django](https://www.djangoproject.com/weblog/2013/sep/15/security/) in 2013.

In order to protect against both of these issues, a maximum password length should be enforced. This should be 64 characters for Bcrypt (due to limitations in the algorithm and implementations), and between 64 and 128 characters for other algorithms.

#### Pre-Hashing Passwords

An alternative approach is to pre-hash the user-supplied password with a fast algorithm such as SHA-256, and then to hash the resultant hash with a more secure algorithm such as Bcrypt (i.e, `bcrypt(sha256($password))`). While this approach solves the problem of arbitrary length user inputs to slower hashing algorithms, it also introduces some vulnerabilities that could allow attackers to crack hashes more easily.

If an attacker is able to obtain password hashes from two different sources, one of which is storing passwords with `bcrypt(sha256($password))` and the other of which is storing them as plain `sha256($password)`, and attacker can use uncracked SHA-256 hashes from the second site as candidate passwords to try and crack the hashes from the first (more secure) site. If passwords are re-used between the two sites, this can effectively allow the attacker to strip off the Bcrypt layer, and to crack the much easier SHA-256 passwords.

Pre-hashing with SHA-256 also means that the keyspace for an attacker to brute-force the hashes is `2^256`, rather than `2^420` for passwords capped at 64 characters (although both of these are big enough to make no practical difference).

Finally, when using pre-hashing ensure that the output for the first hashing algorithm is safely encoded as hexadecimal or base64, as some hashing algorithms such as Bcrypt can behave in undesirable ways if the [input contains null bytes](https://blog.ircmaxell.com/2015/03/security-issue-combining-bcrypt-with.html).

As such, the preferred option should generally be to limit the maximum password length. Pre-hashing of passwords should only be performed where there is a specific requirement to do so, and appropriate steps have been taking to mitigate the issues discussed above.

## Password Hashing Algorithms

### Modern Algorithms

There are a number of modern hashing algorithms that have been specifically designed for securely storing passwords. This means that they should be slow (unlike algorithms such as MD5 and SHA-1 which were designed to be fast), and how slow they are can be configured by changing the [work factor](#work-factors).

The main three algorithms that should be considered as listed below.

#### Argon2id

[Argon2](https://en.wikipedia.org/wiki/Argon2) is the winner of the 2015 [Password Hashing Competition](https://password-hashing.net). There are three different versions of the algorithm, and the Argon2**id** variant should be used where available, as it provides a balanced approach to resisting both side channel and GPU-based attacks.

Rather than a simple work factor like other algorithms, Argon2 has three different parameters that can be configured, meaning that it's more complicated to correctly tune for the environment. The specification contains [guidance on choosing appropriate parameters](https://password-hashing.net/argon2-specs.pdf), however, if you're not in a position to properly tune it, then a simpler algorithm such as [Bcrypt](#bcrypt) may be a better choice.

#### PBKDF2

[PBKDF2](https://en.wikipedia.org/wiki/PBKDF2) is recommended by [NIST](https://pages.nist.gov/800-63-3/sp800-63b.html#memsecretver) and has FIPS-140 validated implementations. So, it should be the preferred algorithm when these are required. Additionally, it is supported out of the box in the .NET framework, so is commonly used in ASP.NET applications.

PBKDF2 can be used with HMACs based on a number of different hashing algorithms. HMAC-SHA-256 is widely supported and is recommended by NIST.

The work factor for PBKDF2 is implemented through the iteration count, which should be at least 10,000 (although values of up to 100,000 may be appropriate in higher security environments).

#### Bcrypt

[Bcrypt](https://en.wikipedia.org/wiki/Bcrypt) is the most widely supported of the algorithms and should be the default choice unless there are specific requirements for PBKDF2, or appropriate knowledge to tune Argon2.

The default work factor for Bcrypt is 10, and this should generally be raised to 12 unless operating on older or lower-powered systems.

### Legacy Algorithms

In some circumstances it is not possible to use [modern hashing algorithms](#modern-algorithms), usually due to the use of legacy language or environments. Where possible, third party libraries should be used to provide these algorithms. However, if the only algorithms available are legacy ones such as MD5 and SHA-1, then there are a number of steps that can be taken to improve the security of stored passwords.

- Use the strongest algorithm available (SHA-512 > SHA-256 > SHA-1 > MD5).
- Use a [pepper](#peppering).
- Use a unique [salt](#salting) for each password, generated using a [cryptographically secure random number generator](Cryptographic_Storage_Cheat_Sheet.md#secure-random-number-generation).
- Use a very large number of iterations of the algorithm (at least 10,000, and possibly significantly more depending on the speed of the hardware).

It should be emphasised that these steps **are not as good as using a modern hashing algorithm**, and that this approach should only be taken where no other options are available.

### Upgrading Legacy Hashes

For older applications that were built using less secure hashing algorithms such as MD5 or SHA-1, these hashes should be upgraded to more modern and secure ones. When the user next enters their password (usually by authenticating on the application), it should be re-hashed using the new algorithm. It would also be good practice to expire the users' current password and require them to enter a new one, so that any older (less secure) hashes of their password are no longer useful to an attacker.

However, this approach means that old (less secure) password hashes will be stored in the database until the user next logs in and may be stored indefinitely. There are two main approaches that can be taken to solve this.

One method is to expire and delete the password hashes of users who have been inactive for a long period, and require them to reset their passwords to login again. Although secure, this approach is not particularly user friendly, and expiring the passwords of a large number of users may cause issues for the support staff, or may be interpreted by users as an indication of a breach. However, if there is a reasonable delay between implementing the password hash upgrade code on login and removing old password hashes, most active users should have changed their passwords already.

An alternative approach is to use the existing password hashes as inputs for a more secure algorithm. For example if the application originally stored passwords as `md5($password)`, this could be easily upgraded to `bcrypt(md5($password))`. Layering the hashes in this manner avoids the need to known the original password, however it can make the hashes easier to crack, as discussed in the [Pre-Hashing](#pre-hashing) section. As such, these hashes should be replaced with direct hashes of the users' passwords next time the users login.

### Custom Algorithms

Writing custom cryptographic code such as a hashing algorithm is **really hard** and should **never be done** outside of an academic exercise. Any potential benefit that you might have from using an unknown or bespoke algorithm will be vastly overshadowed by the weaknesses that exist in it.

**Do not do this.**
