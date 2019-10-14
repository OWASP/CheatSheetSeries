# Introduction

Media covers the theft of large collections of passwords on an almost daily basis. Media coverage of password theft discloses the password storage scheme, the weakness of that scheme, and often discloses a large population of compromised credentials that can affect multiple web sites or other applications. This article provides guidance on properly storing passwords, secret question responses, and similar credential information. Proper storage helps prevent theft, compromise, and malicious use of credentials. Information systems store passwords and other credentials in a variety of protected forms. Common vulnerabilities allow the theft of protected passwords through attack vectors such as SQL Injection. Protected passwords can also be stolen from artefacts such as logs, dumps, and backups.

Specific guidance herein protects against stored credential theft but the bulk of guidance aims to prevent credential compromise. That is, this guidance helps designs resist revealing users' credentials or allowing system access in the event threats steal protected credential information. For more information and a thorough treatment of this topic, refer to the Secure Password Storage Threat Model [here](https://docs.google.com/document/d/1R6c9NW6wtoEoT3CS4UVmthw1a6Ex6TGSBaEqDay5U7g).

## Hashing vs Encryption

* Difference
* When to hash
* When to encrypt

# Hashing

## Salting

* Purpose
* Recommended implementations
  * Good algorithms do this for you
  * Generating salts for legacy algorithms

A salt is fixed-length cryptographically-strong random value. Append credential data to the salt and use this as input to a protective function.

Store the protected form appended to the salt as follows:

```
[protected form] = [salt] + protect([protection func], [salt] + [credential]);
```

Follow these practices to properly implement credential-specific salts:

- Generate a unique salt upon creation of each stored credential (not just per user or system wide);
- Use [cryptographically-strong random](Password_Storage_Cheat_Sheet.md#ref3) data;
- As storage permits, use a `32 byte` or `64 byte` salt (actual size dependent on protection function);
- Scheme security does not depend on hiding, splitting, or otherwise obscuring the salt.

Salts serve two purposes:
1. prevent the protected form from revealing two identical credentials and
2. augment entropy fed to protecting function without relying on credential complexity. The second aims to make [pre-computed lookup attacks](Password_Storage_Cheat_Sheet.md#ref2) on an individual credential and time-based attacks on a population intractable.

## Peppering

A [pepper](https://en.wikipedia.org/wiki/Pepper_(cryptography)) can be used in additional to salting to provide an additional layer of protection. It is similar to a salt, but has two key differences:

* The pepper is shared between all stored passwords, rather than being unique like a salt.
* The pepper is stored separately from the hashes (i.e, not in the database).

The purpose of the pepper is to prevent an attacker from being able to crack any of the hashes if they only have access to the database, for example if they have exploited a SQL injection vulnerability or obtained a backup of the database.

The pepper should be at least 32 characters long, and should be randomly generated. It should be stored in an application configuration file (protected with appropriate permissions), using the secure storage APIs provided by the operating system, or in a HSM.

The pepper is used in a similar way to a salt, but concatenating it with the password prior to hashing, using a construct such as:

```
hash(pepper . password)
```

### Disadvantages

The main issues with peppers is their long term maintenance. Changing the pepper in use will invalidate all of the existing passwords stored in the database, which means that it can't easily be changed in the event of the pepper being compromised.

One solution to this is to store the ID of the pepper in the database alongside the associated password hashes. When the pepper needs to be updated, this ID can updated for hashes using the new pepper. Although the application will need to store all of the peppers that are currently in use, this does provide a way to replace a compromised pepper.

## Work Factors

The work factor is essentially the number of iterations of the hashing algorithm that are performed for each passwords (usually it's actually `2^work` iterations). The purpose of the work factor is to make calculating the hash more computationally expensive, which in turn reduces the speed at which an attacker can attempt to crack the password hash.

When choosing a work factor, a balance needs to be struck between security and performance. Higher work factors will make the hashes more difficult for an attacker to crack, but will also make the process of verifying a login attempt slower. If the work factor is too high, this may degrade the performance of the application, and could also be used by an attacker to carry out a denial of service attack by making a large number of login attempts to exhaust server's CPU.

There is no golden rule for the ideal work factor - it will depend on the performance of the server and the number of users on the application. Determining the optimal work factor will require experimentation on the specific server(s) used by the application. As a general rule, the calculating a hash should take less than one second, although on higher traffic sites it should be significantly less than this.

## Upgrading the Work Factor

One key advantage of having a work factor is that it can be increased over time as hardware becomes more powerful and cheaper. Taking Moore's Law (i.e, that computational power at a given price point doubles every eighteen months) as a rough approximation, this means that the work factor should be increased by 1 every eighteen months.

The most common approach to upgrading the work factor is to wait until the user next authenticates, and then to re-hash their password with the new work factor. This means that different hashes will have different work factors, and may result in hashes never being upgraded if the user doesn't log back in to the application. In some cases, it may be appropriate to remove the older password hashes and require users to reset their passwords next time they need to login, in order to avoid storing older and less secure hashes.

In some cases, it may be possible to increase the work factor of the hashes without the original password, although this is not supported by common hashing algorithms such as Bcrypt and PBKDF2

## Modern Algorithms

* PBKDF2
* Bcrypt and Scrypt
* Argon2

Adaptive one-way functions compute a one-way (irreversible) transform. Each function allows configuration of 'work factor'. Underlying mechanisms used to achieve irreversibility and govern work factors (such as time, space, and parallelism) vary between functions and remain unimportant to this discussion.

Select:

- **[Argon2](Password_Storage_Cheat_Sheet.md#ref7)** is the winner of the [password hashing competition](https://password-hashing.net/) and should **be considered as your first choice** for new applications;
- **[PBKDF2](Password_Storage_Cheat_Sheet.md#ref4)** when FIPS certification or enterprise support on many platforms is required;
- **[Scrypt](Password_Storage_Cheat_Sheet.md#ref5)** where resisting any/all hardware accelerated attacks is necessary but support isn't.
- **[Bcrypt](https://auth0.com/blog/hashing-in-action-understanding-bcrypt/)** where PBKDF2 or Scrypt support is not available.

Example `protect()` pseudo-code follows:

```text
return [salt] + pbkdf2([salt], [credential], c=[iteration_count]);
```

In the example above, as PBKDF2 computation time depend on the target system, **iteration_count** must have a number implying that the computation time on the target system must take at least 1 second.
500.000 is a good example, but please note that, as PBKDF2 is **not** time constant, this configuration is highly dependant on the target machine and you should probably [test the appropriate number for your specific situation](../assets/Password_Storage_Cheat_Sheet_Test_PBKDF2_Iterations.java).

Designers select one-way adaptive functions to implement `protect()` because these functions can be configured to cost (linearly or exponentially) more than a hash function to execute. Defenders adjust work factor to keep pace with threats' increasing hardware capabilities. Those implementing adaptive one-way functions must tune work factors so as to impede attackers while providing acceptable user experience and scale.

Additionally, adaptive one-way functions do not effectively prevent reversal of common dictionary-based credentials (users with password 'password') regardless of user population size or salt usage.

## Legacy Algorithms

* MD5
* SHA-1 and SHA-256 and

## Custom Algorithms

* Don't do this

## Upgrading Legacy Hashes

* Update on password change
* Stacked algorithms
* Resetting user passwords

The above guidance describes how to do password hashing correctly/safely. However, it is very likely you'll be in a situation where you have an existing solution you want to upgrade. This [article](https://veggiespam.com/painless-password-hash-upgrades/) provides some good guidance on how to accomplish an upgrade in place without adversely affecting existing user accounts and future proofing your upgrade so you can seamlessly upgrade again (which you eventually will need to do).

2. Load and use new protection scheme
    1. Load a new, stronger credential protection scheme (See next section on: Upgrading your existing password hashing solution)
    2. Include version information stored with form
    3. Set 'tainted'/'compromised' bit until user resets credentials
    4. Rotate any keys and/or adjust protection function parameters such as work factor or salt
    5. Increment scheme version number

3. When user logs in:
    1. Validate credentials based on stored version (old or new); if older compromised version is still active for user, demand 2nd factor or secret answers until the new method is implemented or activated for that user
    2. Prompt user for credential change, apologize, & conduct out-of-band confirmation
    3. Convert stored credentials to new scheme as user successfully log in

# Encryption

## When to Encrypt Passwords

* When the clear text passwords are needed for other systems
* To allow individual characters to be checked

## How to Encrypt Passwords

* See [Cryptographic Storage Cheat Sheet](Cryptographic_Storage_Cheat_Sheet.md)

# Other Guidance

## Maximum Password Lengths

### Do not limit the character set and set long max lengths for credentials

Some organizations restrict the 1) types of special characters and 2) length of credentials accepted by systems because of their inability to prevent SQL Injection, Cross-site scripting, command-injection and other forms of injection attacks. These restrictions, while well-intentioned, facilitate certain simple attacks such as brute force.

Do not allow short or no-length passwords and do not apply character set, or encoding restrictions on the entry or storage of credentials. Continue applying encoding, escaping, masking, outright omission, and other best practices to eliminate injection risks.

A reasonable long password length is 160. Very long password policies can [lead to DoS in certain circumstances](http://arstechnica.com/security/2013/09/long-passwords-are-good-but-too-much-length-can-be-bad-for-security/).

### Hash the password as one of several steps

Very large passwords can be a performance bottleneck or a DoS situation when users utilize very long passwords. Also, some implementations of some of the adaptive algorithms suggested below, such as bcrypt, truncate long passwords making them less effective. By first hashing the passwords with a fast hash such as SHA-512, and then hashing the output with a slower and more secure hash such as bcrypt, even giant passwords are reduced to 512 bits, solving both problems.

## Use Built-in Libraries and Functions

From PHP version 7.2, [Argon2 is supported](https://wiki.php.net/rfc/argon2_password_hash) in built-in password hashing related functions:

- **password_hash()**
- **password_verify()**
- **password_get_info()**
