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

## Use a cryptographically strong credential-specific salt

A salt is fixed-length cryptographically-strong random value. Append credential data to the salt and use this as input to a protective function. 

Store the protected form appended to the salt as follows:

```text
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

## Peppers

* Purpose
* Recommended implementations

## Work Factors

* Purpose
* Choosing a work factor
* Upgrading a work factor

Since resources are normally considered limited, a common rule of thumb for tuning the work factor (or cost) is to make `protect()` run as slow as possible without affecting the users' experience and without increasing the need for extra hardware over budget. So, if the registration and authentication's cases accept `protect()` taking up to 1 second, you can tune the cost so that it takes 1 second to run on your hardware. This way, it shouldn't be so slow that your users become affected, but it should also affect the attackers' attempt as much as possible.

While there is a minimum number of iterations recommended to ensure data safety, this value changes every year as technology improves and then require to be reviewed on a regular basis or after an hardware upgrade. 

However, it is critical to understand that a single work factor does not fit all designs, [experimentation is important](Password_Storage_Cheat_Sheet.md#ref6).

Upholding security improvement over (solely) salted schemes relies on proper key management.

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

# General Guidance

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
