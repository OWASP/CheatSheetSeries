# Introduction

Media covers the theft of large collections of passwords on an almost daily basis. Media coverage of password theft discloses the password storage scheme, the weakness of that scheme, and often discloses a large population of compromised credentials that can affect multiple web sites or other applications. This article provides guidance on properly storing passwords, secret question responses, and similar credential information. Proper storage helps prevent theft, compromise, and malicious use of credentials. Information systems store passwords and other credentials in a variety of protected forms. Common vulnerabilities allow the theft of protected passwords through attack vectors such as SQL Injection. Protected passwords can also be stolen from artifacts such as logs, dumps, and backups.

Specific guidance herein protects against stored credential theft but the bulk of guidance aims to prevent credential compromise. That is, this guidance helps designs resist revealing users’ credentials or allowing system access in the event threats steal protected credential information. For more information and a thorough treatment of this topic, refer to the Secure Password Storage Threat Model [here](https://docs.google.com/document/d/1R6c9NW6wtoEoT3CS4UVmthw1a6Ex6TGSBaEqDay5U7g).

# Guidance

## Do not limit the character set and set long max lengths for credentials

Some organizations restrict the 1) types of special characters and 2) length of credentials accepted by systems because of their inability to prevent SQL Injection, Cross-site scripting, command-injection and other forms of injection attacks. These restrictions, while well-intentioned, facilitate certain simple attacks such as brute force.

Do not allow short or no-length passwords and do not apply character set, or encoding restrictions on the entry or storage of credentials. Continue applying encoding, escaping, masking, outright omission, and other best practices to eliminate injection risks.

A reasonable long password length is 160. Very long password policies can [lead to DOS in certain circumstances](http://arstechnica.com/security/2013/09/long-passwords-are-good-but-too-much-length-can-be-bad-for-security/).

## Hash the password as one of several steps

Very large passwords can be a performance bottleneck or a DOS situation when users utilize very long passwords. Also, some implementations of some of the adaptive algorithms suggested below, such as bcrypt, truncate long passwords making them less effective. By hashing the passwords with a hash such as SHA-512, even giant passwords are reduced to 512 bits, solving both problems.

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

## Impose infeasible verification on attacker

The function used to protect stored credentials should balance attacker and defender verification. The defender needs an acceptable response time for verification of users’ credentials during peak use. However, the time required to map `<credential> → <protected form>` must remain beyond threats’ hardware (GPU, FPGA) and technique (dictionary-based, brute force, etc) capabilities.

Two approaches facilitate this, each imperfectly.

### Leverage an adaptive one-way function

Adaptive one-way functions compute a one-way (irreversible) transform. Each function allows configuration of ‘work factor’. Underlying mechanisms used to achieve irreversibility and govern work factors (such as time, space, and parallelism) vary between functions and remain unimportant to this discussion.

Select:

- **[Argon2](Password_Storage_Cheat_Sheet.md#ref7)** is the winner of the [password hashing competition](https://password-hashing.net/) and should **be considered as your first choice** for new applications;
- **[PBKDF2](Password_Storage_Cheat_Sheet.md#ref4)** when FIPS certification or enterprise support on many platforms is required;
- **[Scrypt](Password_Storage_Cheat_Sheet.md#ref5)** where resisting any/all hardware accelerated attacks is necessary but support isn’t.
- **[Bcrypt](https://auth0.com/blog/hashing-in-action-understanding-bcrypt/)** where PBKDF2 or Scrypt support is not available.

Example `protect()` pseudo-code follows:

```text
return [salt] + pbkdf2([salt], [credential], c=[iteration_count]);
```

In the example above, as PBKDF2 computation time depend on the target system, **iteration_count** must have a number implying that the computation time on the target system must take at least 1 second.  
500.000 is a good example, but please note that, as PBKDF2 is **not** time constant, this configuration is highly dependant on the target machine and you should probably [test the appropriate number for your specific situation](../assets/Password_Storage_Cheat_Sheet_Test_PBKDF2_Iterations.java). 

Designers select one-way adaptive functions to implement `protect()` because these functions can be configured to cost (linearly or exponentially) more than a hash function to execute. Defenders adjust work factor to keep pace with threats’ increasing hardware capabilities. Those implementing adaptive one-way functions must tune work factors so as to impede attackers while providing acceptable user experience and scale.

Additionally, adaptive one-way functions do not effectively prevent reversal of common dictionary-based credentials (users with password ‘password’) regardless of user population size or salt usage.

#### Work Factor

Since resources are normally considered limited, a common rule of thumb for tuning the work factor (or cost) is to make `protect()` run as slow as possible without affecting the users' experience and without increasing the need for extra hardware over budget. So, if the registration and authentication's cases accept `protect()` taking up to 1 second, you can tune the cost so that it takes 1 second to run on your hardware. This way, it shouldn't be so slow that your users become affected, but it should also affect the attackers' attempt as much as possible.

While there is a minimum number of iterations recommended to ensure data safety, this value changes every year as technology improves and then require to be reviewed on a regular basis or after an hardware upgrade. 

However, it is critical to understand that a single work factor does not fit all designs, [experimentation is important](Password_Storage_Cheat_Sheet.md#ref6).

### Leverage Keyed functions

Keyed functions, such as HMACs, compute a one-way (irreversible) transform using a private key and given input. For example, HMACs inherit properties of hash functions including their speed, allowing for near instant verification. Key size imposes infeasible size- and/or space- requirements on compromise--even for common credentials (aka password = ‘password’). Designers protecting stored credentials with keyed functions:

- Use a single “site-wide” key;
- Protect this key as any private key using best practices;
- Store the key outside the credential store (aka: not in the database);
- Generate the key using cryptographically-strong pseudo-random data;
- Do not worry about output block size (i.e. SHA-256 vs. SHA-512).

Example `protect()` pseudo-code follows:

```text
return [salt] + HMAC-SHA-256([key], [salt] + [credential]);
```

Upholding security improvement over (solely) salted schemes relies on proper key management.

## Design password storage assuming eventual compromise

The frequency and ease with which threats steal protected credentials demands “design for failure”. Having detected theft, a credential storage scheme must support continued operation by marking credential data as compromised. It's also critical to engage alternative credential validation workflows as follows:

1. Protect the user’s account
    1. Invalidate authentication ‘shortcuts’ by disallowing login without 2nd factors, secret questions or some other form of strong authentication.
    2. Disallow changes to user accounts such as editing secret questions and changing account multi-factor configuration settings.

2. Load and use new protection scheme
    1. Load a new, stronger credential protection scheme (See next section on: Upgrading your existing password hashing solution)
    2. Include version information stored with form
    3. Set ‘tainted’/‘compromised’ bit until user resets credentials
    4. Rotate any keys and/or adjust protection function parameters such as work factor or salt
    5. Increment scheme version number

3. When user logs in:
    1. Validate credentials based on stored version (old or new); if older compromised version is still active for user, demand 2nd factor or secret answers until the new method is implemented or activated for that user
    2. Prompt user for credential change, apologize, & conduct out-of-band confirmation
    3. Convert stored credentials to new scheme as user successfully log in

## Upgrading your existing password hashing solution

The above guidance describes how to do password hashing correctly/safely. However, it is very likely you'll be in a situation where you have an existing solution you want to upgrade. This [article](https://veggiespam.com/painless-password-hash-upgrades/) provides some good guidance on how to accomplish an upgrade in place without adversely affecting existing user accounts and future proofing your upgrade so you can seamlessly upgrade again (which you eventually will need to do).

# Argon2 usage proposal in Java

The objective is to propose a example of secure usage/integration of the Argon2 algorithm in Java application to protect password when stored.

## Argon2 library used

The Argon2 implementation provided by [phc-winner-argon2](https://github.com/P-H-C/phc-winner-argon2) project has been used because:

- It's the reference implementation of this algorithm.
- It's dedicated to this new algorithm so all work by the maintainer is focused on the implementation.
- Project is active, [last release](https://github.com/P-H-C/phc-winner-argon2/blob/master/CHANGELOG.md) date from december 2017.
- There bindings for many technologies.

Java bindings by [phxql](https://github.com/phxql/argon2-jvm) has been used because it's currently the only binding proposed for Java in the [bindings list](https://github.com/P-H-C/phc-winner-argon2#bindings) and is simple to use.

[libsodium](https://github.com/jedisct1/libsodium) propose an implementation but it have been decided to use a dedicated project because libsodium provide several crypto features and thus work from maintainer will not focus on Argon2 implementation (however project is active and propose also bindings for many technologies).

## Remark about Argon2 native library embedding

Due to the kind of data processed (password), the implementation without the embedded pre-compiled native library has been used in order to don't embed native untrusted compiled code (*there absolutely no issue with the project owner of argon2-jvm, it is just a secure approach*) that will be difficult to validate. For java part, sources are provided in Maven repositories along jar files.

Technical details about how to build the Argon2 library on different platforms are available on [PHC](https://github.com/P-H-C/phc-winner-argon2#usage) repository and on [argon2-jvm](https://github.com/phxql/argon2-jvm/blob/master/docs/compile-argon2.md) repository.

**Note:**

Always name the compiled library with this format to simplify integration with the *argon2-jvm* binding project:

- For Windows: *argon2*.dll
- For Linux: *libargon2*.so
- For OSX: *libargon2*.dylib

## Integration in company projects

Integration in company projects can use the following approach:

1. Create a internal shared java utility library that embeed your compiled version of the Argon2 library.
2. Use this shared java library in the different projects in order to:
    1. Prevent to embed a version of the Argon2 library in all your project.
    2. Centralize and unify the version of the Argon2 library used (important for upgrade process).

## Implementation proposal

The following class propose utility methods to compute and verify a hash of a password along creating a abstraction layer on the algorithm used behind the scene.

``` java
import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;
import org.checkerframework.checker.nullness.qual.NonNull;
import java.nio.charset.Charset;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.ResourceBundle;

/**
* This class provided utility methods to create and verify a hash of a password.
*
* This implementation can be used to create a company internal 
*  shared java utility library that embed your compiled version of the Argon2 library
* to ensure that no external untrusted binary as used in your information system.
*
* As hash will be used for password type of information then the variant 
* named "Argon2i" of Argon2 will be used.
*
* The hash creation method return a hash with all information in order to 
* allow the application that need to verify the hash to be in a full stateless mode.
*/
public final class PasswordUtil {

    /**
    * Compute a hash of a password.
    * Password provided is wiped from the memory at the end of this method
    *
    * @param password Password to hash
    * @param charset  Charset of the password
    * @return the hash in format "$argon2i$v=19$m=128000,t=3,
    *       p=4$sfSe5MewORVlg8cDtxOTbg$uqWx4mZvLI092oJ8ZwAjAWU0rrBSDQkOezxAuvrE5dM"
    */
    public static String hash(@NonNull char[] password, @NonNull Charset charset) {
        String hash;
        Argon2 argon2Hasher = null;
        try {
            // Create instance
            argon2Hasher = createInstance();
            //Create options
            Map<String, String> options = loadParameters();
            int iterationsCount = Integer.parseInt(options.get("ITERATIONS"));
            int memoryAmountToUse = Integer.parseInt(options.get("MEMORY"));
            int threadToUse = Integer.parseInt(options.get("PARALLELISM"));
            //Compute and return the hash
            hash = argon2Hasher.hash(iterationsCount, memoryAmountToUse, threadToUse, 
                                     password, charset);
        } finally {
            //Clean the password from the memory
            if (argon2Hasher != null) {
                argon2Hasher.wipeArray(password);
            }
        }
        return hash;
    }

    /**
    * Verifies a password against a hash
    * Password provided is wiped from the memory at the end of this method
    *
    * @param hash     Hash to verify
    * @param password Password to which hash must be verified against
    * @param charset  Charset of the password
    * @return True if the password matches the hash, false otherwise.
    */
    public static boolean verify(@NonNull String hash, @NonNull char[] password,
                                 @NonNull Charset charset) {
        Argon2 argon2Hasher = null;
        boolean isMatching;
        try {
            // Create instance
            argon2Hasher = createInstance();
            //Apply the verification (hash computation options are included
            //in the hash itself)
            isMatching = argon2Hasher.verify(hash, password, charset);
        } finally {
            //Clean the password from the memory
            if (argon2Hasher != null) {
                argon2Hasher.wipeArray(password);
            }
        }
        return isMatching;
    }

    /**
    * Create and configure an Argon2 instance
    *
    * @return The Argon2 instance
    */
    private static Argon2 createInstance() {
        // Create and return the instance
        return Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2i);
    }


    /**
    * Load Argon2 options to use for hashing.
    *
    * @return A map with the options
    */
    private static Map<String, String> loadParameters() {
        Map<String, String> options = new HashMap<>();
        ResourceBundle optionsBundle = ResourceBundle.getBundle("config");
        String k;
        Enumeration<String> keys = optionsBundle.getKeys();
        while (keys.hasMoreElements()) {
            k = keys.nextElement();
            options.putIfAbsent(k, optionsBundle.getString(k).trim());
        }
        return options;
    }
}
```

Proposed configuration options for Argon2 are based on the following source of recommendation:

- [PHC project](https://github.com/P-H-C/phc-winner-argon2/issues/59).
- Section 9 of the Argon2 [specifications document](https://github.com/P-H-C/phc-winner-argon2/blob/master/argon2-specs.pdf).

Documented configuration is the following, increase the number of the **ITERATIONS** parameter if the computing of a hash take less than 2 seconds on your environement:

``` bash
# Configuration to define Argon2 options
# See https://github.com/P-H-C/phc-winner-argon2#command-line-utility
# See https://github.com/phxql/argon2-jvm/blob/master/src/main/java/de/mkammerer/
#     argon2/Argon2.java
# See https://github.com/P-H-C/phc-winner-argon2/issues/59
#
# Number of iterations, here adapted to take at least 2 seconds
# Tested on the following environments:
#   ENV NUMBER 1: LAPTOP - 15 Iterations is enough to reach 2 seconds processing time
#       CPU: Intel Core i7-2670QM 2.20 GHz with 8 logical processors and 4 cores
#       RAM: 24GB but no customization on JVM (Java8 32 bits)
#       OS: Windows 10 Pro 64 bits
#   ENV NUMBER 2: TRAVIS CI LINUX VM - 15 Iterations is NOT enough to reach 2 seconds 
#                 processing time (processing time take 1 second)
#       See details on https://docs.travis-ci.com/user/reference/overview/
#                      #Virtualisation-Environment-vs-Operating-System
#       "Ubuntu Precise" and "Ubuntu Trusty" using infrastructure 
#                      "Virtual machine on GCE" were used (GCE = Google Compute Engine)
ITERATIONS=40
# The memory usage of 2^N KiB, here set to recommended value from Issue n°9 of PHC project (128 MB)
MEMORY=128000
# Parallelism to N threads here set to recommended value from Issue n°9 of PHC project
PARALLELISM=4
```

## Input password size

In order to prevent any DOS attack using a very big password, it's recommended to define a higher size limit for the password choosen by the user.

A limit of **1000 characters** is sufficient to let the user choose a very big password without impacting the system.

A test with a password with an alphanumeric content of **10 000 000 characters** has been performed on the used Argon2 library and binding using the proposed configuration:

``` java
import org.apache.commons.lang3.RandomStringUtils;
import java.nio.charset.Charset;
import java.time.Duration;
import java.time.Instant;

/**
 * Test in order to verify if the hash generation method supports 
 * very big password, here 10 000 000 alphanumeric characters.
 */
public class TryVeryBigPassword {
    public static void main(String[] args){
        int passSize = 10000000;
        String pass = RandomStringUtils.randomAlphanumeric(passSize);
        Instant start = Instant.now();
        String hash = PasswordUtil.hash(pass.toCharArray(), Charset.forName("UTF-8"));
        Instant end = Instant.now();
        Duration timeElapsed = Duration.between(start, end);
        System.out.printf("DELAY => %s seconds\n",timeElapsed.getSeconds());
        System.out.printf("HASH  => %s\n",hash);
    }
}
```

There no problem meet, library and binding supports it:

``` text
DELAY => 2 seconds
HASH  => $argon2i$v=19$m=128000,t=40,
         p=4$RAQHs/CUlVGVgi92Mofgdg$xSovVoh7U4iiPUTvrk6wFanOn1w5kOwUes+nTa+tZiQ
```

## Sources of the prototype

The entire source code of the POC is available [here](https://github.com/righettod/poc-argon2).

# Argon2 usage proposal in PHP

The objective is to propose a example of secure usage/integration of the Argon2 algorithm in PHP application to protect password when stored.

From PHP version 7.2, [Argon2 is supported](https://wiki.php.net/rfc/argon2_password_hash) in built-in password hashing related functions:

- **password_hash()**
- **password_verify()**
- **password_get_info()**

Like for the Java proposal, the Argon2 implementation provided by [phc-winner-argon2](https://github.com/P-H-C/phc-winner-argon2) project has been used and for the same reasons.

## Remark about self compilation of binaries for PHP and Argon2

Like for Java proposal, focus is made here on non-installing binaries from untrusted sources (non official linux repositories - PHC Github repository for Argon2 is considered as trusted because sources are provided and a security code review can be applied).

The third-party linux repository **[ondrej/php](https://launchpad.net/~ondrej/+archive/ubuntu/php)** provide pre-compiled packages for Argon2 and PHP 7.2 but it have been decided to not trust it because is not an official repository.

## Implementation proposal

### Setup PHP for Argon2 usage

The following shell script show a proposal for the setup of a PHP 7.2 installation to enable the usage of Argon2 for password hashing:

``` bash
#!/bin/sh
export CDIR=`pwd`
ARGON2_RELEASE_NAME=20171227
PHP_RELEASE_NAME=7.2.3
echo "#### Install Argon2 from PHC release on Github repository ####"
cd $CDIR
wget https://github.com/P-H-C/phc-winner-argon2/archive/$ARGON2_RELEASE_NAME.zip
unzip $ARGON2_RELEASE_NAME.zip
cd phc-winner-argon2-$ARGON2_RELEASE_NAME
make
make test > tests-argon2-library.txt
TESTS_CONTAINS_ERROR=`grep -c FAIL tests-argon2-library.txt`
if [ "$TESTS_CONTAINS_ERROR" != "0" ]
then
    exit 1
fi
sudo make install
echo "#### Install PHP 7.2 from sources with Argon2 option enabled ####"
cd $CDIR
wget http://de2.php.net/get/php-$PHP_RELEASE_NAME.tar.gz/from/this/mirror
mv mirror mirror.tgz
tar xf mirror.tgz
cd php-$PHP_RELEASE_NAME
./configure --with-password-argon2=/usr/lib
make
make test
sudo make install
echo "#### Cleanup temporary stuff ####"
cd $CDIR
rm $ARGON2_RELEASE_NAME.zip
rm -rf phc-winner-argon2-$ARGON2_RELEASE_NAME
rm mirror.tgz
rm -rf php-$PHP_RELEASE_NAME
```

### Password hashing usage

The following class propose utility methods to compute and verify a hash of a password along creating a abstraction layer on the algorithm used behind the scene.

Like for Java proposal, this class can be included in a internal shared utility library that will be used by others projects.

Remark made for Java proposal about input password size is also applicable for PHP.

``` php
/**
* This class provided utility methods to create and verify a hash of a password.
*
* This implementation can be used to create a company internal shared php utility 
* library that abstract application to know algorithm used and how to use it.
*
* As hash will be used for password type of information then the variant 
* named "Argon2i" of Argon2 will be used.
*
* The hash creation method return a hash with all information in order 
* to allow the application that need to verify the hash to be in a 
* full stateless mode.
*/
class PasswordUtil
{
    /**
        * Compute a hash of a password.
        *
        * @param string $password Password to hash.
        * @return string The hash in format "$argon2i$v=19$m=1024,t=2,
        *        p=2$amRwcjA5ZUlUZDdDNEJHRg$B6K1JOhuh2IyEsDrGFZHrmD+118gtj1tKt1V1n2ftus"
        */
    public static function hash($password)
    {
        //Create options
        $options = self::loadParameters();
        //Compute the hash and return it
        return password_hash($password, PASSWORD_ARGON2I, $options);
    }


    /**
        * Verifies a password against a hash
        * Password provided is wiped at the end of this method
        *
        * @param string $password Password to which hash must be verified against.
        * @param string $hash Hash to verify.
        * @return bool True if the password matches the hash, False otherwise.
        */
    public static function verify($password, $hash)
    {
        //Apply the verification (hash computation options are included in 
        //the hash itself) and return the result
        return password_verify($password, $hash);
    }


    /**
    * Load Argon2 options to use for hashing.
    *
    * @return array A associative array with the options.
    */
    private static function loadParameters()
    {
        //Parse configuration file
        $options_array = parse_ini_file("config.ini");
        $memory = intval($options_array["MEMORY"]);
        $timeCost = intval($options_array["ITERATIONS"]);
        $parallelism = intval($options_array["PARALLELISM"]);
        if ($memory <= 0 || $timeCost <= 0 || $parallelism <= 0) {
            throw new Exception("One or more of the hashing configuration" . 
            " parameters are not valid values !");
        }
        //Create the options final arrays and return it
        return ["memory_cost" => $memory, "time_cost" => $timeCost, 
                "threads" => $parallelism];
    }
}
```

Proposed configuration options for Argon2 are based on the same sources than for the Java proposal.

Documented configuration is the following:

```ini
; Configuration to define Argon2 options: DO NOT STORE THIS FILE IN THE WEB FOLDER !!!
; See https://github.com/P-H-C/phc-winner-argon2#command-line-utility
; See https://github.com/P-H-C/phc-winner-argon2/issues/59
;
; Number of iterations, here adapted to take at least 2 seconds
; Tested on the following environments:
;   ENV NUMBER 1: VMWARE VIRTUAL MACHINE - 30 Iterations is enough to reach 
;                                          2 seconds processing time
;       CPU: Intel Core i7-2670QM 2.20 GHz with 2 CPU
;       RAM: 2GB
;       OS: Ubuntu 14 64 bits
;   ENV NUMBER 2: TRAVIS CI LINUX VM - 30 Iterations is also enough to reach 
;                                      2 seconds processing time
;       See details on https://docs.travis-ci.com/user/reference/overview/
;                      #Virtualisation-Environment-vs-Operating-System
;       "Ubuntu Trusty" using infrastructure "Virtual machine on GCE" 
;       were used (GCE = Google Compute Engine)
[main]
ITERATIONS=30
; The memory usage of 2^N KiB, here set to recommended value from Issue n°9 of PHC project (128 MB)
MEMORY=128000
; Parallelism to N threads here set to recommended value from Issue n°9 of PHC project
PARALLELISM=4
```      

## Sources of the prototype

The entire source code of the POC is available [here](https://github.com/righettod/poc-argon2-php).

# References

## Ref1

- [Morris, R. Thompson, K., Password Security: A Case History, 04/03/1978, p4](https://spqr.eecs.umich.edu/courses/cs660sp11/papers/10.1.1.128.1635.pdf)

## Ref2 

- [Space-based (Lookup) attacks: Space-time Tradeoff: Hellman, M., Crypanalytic Time-Memory Trade-Off, Transactions of Information Theory, Vol. IT-26, No. 4, July, 1980](http://www-ee.stanford.edu/~hellman/publications/36.pdf)
- [Rainbow Tables](http://ophcrack.sourceforge.net/tables.php).

## Ref3

- For example: [Java SecureRandom class](http://docs.oracle.com/javase/6/docs/api/java/security/SecureRandom.html).

## Ref4

- [Kalski, B., PKCS \#5: Password-Based Cryptography Specification Version 2.0, IETF RFC 2898, September, 2000, p9](http://www.ietf.org/rfc/rfc2898.txt).

## Ref5

- [Percival, C., Stronger Key Derivation Via Sequential Memory-Hard Functions, BSDCan ‘09, May, 2009](http://www.tarsnap.com/scrypt/scrypt.pdf).

## Ref6

For instance, one might set work factors targeting the following run times: 
1. Password-generated session key - fraction of a second; 
2. User credential - ~0.5 seconds; 
3. Password-generated site (or other long-lived) key - potentially a second or more.

## Ref7

- [Argon2 detailed specifications can be found here](https://password-hashing.net/argon2-specs.pdf).

## Ref8

- [Painless Password Hash Upgrades](https://veggiespam.com/painless-password-hash-upgrades/).