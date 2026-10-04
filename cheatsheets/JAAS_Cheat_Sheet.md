# JAAS Cheat Sheet

## Introduction - What is JAAS authentication

The process of verifying the identity of a user or another system is authentication.

[JAAS](https://docs.oracle.com/javase/8/docs/technotes/guides/security/jaas/JAASRefGuide.html), as an authentication framework manages the authenticated user's identity and credentials from login to logout.

The [JAAS authentication lifecycle](https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/security/auth/spi/LoginModule.html):

1. The application creates a `LoginContext` using the configured login name and a callback handler.
2. The `LoginContext` reads the configuration and instantiates the configured `LoginModule`s.
3. The `LoginContext` calls each module's `initialize()` with the shared `Subject` and other context.
4. The application calls `LoginContext.login()`, which invokes the configured modules' `login()` methods according to their control flags.
5. If overall authentication succeeds, the `LoginContext` invokes the modules' `commit()` methods; otherwise, it invokes their `abort()` methods.

## Configuration file

The JAAS configuration file contains a `LoginModule` stanza for each `LoginModule` available for logging on to the application.

A stanza from a JAAS configuration file:

```text
Branches
{
    USNavy.AppLoginModule required
    debug=true
    succeeded=true;
}
```

Note the placement of the semicolons, terminating both `LoginModule` entries and stanzas.

The word required indicates the `LoginContext`'s `login()` method must be successful when logging in the user. The `LoginModule`-specific values `debug` and `succeeded` are passed to the `LoginModule`.

They are defined by the `LoginModule` and their usage is managed inside the `LoginModule`. Note, Options are Configured using key-value pairing such as `debug="true"` and the key and value should be separated by a `=` sign.

## Main.java (The client)

- Execution syntax:

```text
Java –Djava.security.auth.login.config==packageName/packageName.config
        packageName.Main Stanza1

Where:
    packageName is the directory containing the config file.
    packageName.config specifies the config file in the Java package, packageName.
    packageName.Main specifies Main.java in the Java package, packageName.
    Stanza1 is the name of the stanza Main() should read from the config file.
```

- When executed, the 1st command-line argument is the stanza from the config file. The Stanza names the `LoginModule` to be used. The 2nd argument is the `CallbackHandler`.
- Create a new `LoginContext` with the arguments passed to `Main.java`.
    - `loginContext = new LoginContext (args[0], new AppCallbackHandler());`
- Call the LoginContext.Login Module:
    - `loginContext.login();`
- `LoginContext.login()` returns without a value when authentication succeeds and throws a `LoginException` when it fails.
- Retrieve the authenticated `Subject` using `loginContext.getSubject()` after successful login.

## LoginModule.java

A `LoginModule` must have the following authentication methods:

- `initialize()`
- `login()`
- `commit()`
- `abort()`
- `logout()`

### initialize()

In `Main()`, after the `LoginContext` reads the correct stanza from the config file, the `LoginContext` instantiates the `LoginModule` specified in the stanza.

- `initialize()` methods signature:
    - `public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState, Map<String, ?> options)`
- The arguments above should be saved as follows:
    - `this.subject = subject;`
    - `this.callbackHandler = callbackHandler;`
    - `this.sharedState = sharedState;`
    - `this.options = options;`
- What the `initialize()` method does:
    - Stores the supplied shared `Subject`; successful `commit()` associates authenticated principals and credentials with that object.
    - Sets the `CallbackHandler` which interacts with the user to gather login information.
    - If a `LoginContext` specifies 2 or more LoginModules, which is legal, they can share information via a `sharedState` map.
    - Saves state information such as debug and succeeded in an options Map.

### login()

Captures user supplied login information. The code snippet below declares an array of two callback objects which, when passed to the `callbackHandler.handle` method in the `callbackHandler.java` program, will be loaded with a username and password provided interactively by the user:

```java
NameCallback nameCB = new NameCallback("Username");
PasswordCallback passwordCB = new PasswordCallback ("Password", false);
Callback[] callbacks = new Callback[] { nameCB, passwordCB };
callbackHandler.handle (callbacks);
```

- Authenticates the user
- Retrieves the user supplied information from the callback objects:
    - `String ID = nameCallback.getName ();`
    - `char[] tempPW = passwordCallback.getPassword ();`
- Compare `name` and `tempPW` to values stored in a repository such as LDAP.
- Set the value of the variable succeeded and return to `Main()`.

### commit()

Once the users credentials are successfully verified during `login()`, the JAAS authentication framework associates the credentials, as needed, with the subject.

A [`Subject` separates credentials by their protection and sharing requirements](https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/security/auth/Subject.html):

- Public credentials are intended to be shared, such as public key certificates.
- Private credentials require special protection, such as passwords and private cryptographic keys.

Principals (i.e. Identities the subject has other than their login name) such as employee number or membership ID in a user group are added to the subject.

Implement [`commit()`](https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/security/auth/spi/LoginModule.html#commit()) using the authentication state saved by `login()`. Associate principals and credentials with the shared `Subject` only when this module's authentication succeeded; otherwise, clean up its saved state. Return `true` on success, `false` when the module is ignored, or throw `LoginException` on failure.

### abort()

The `abort()` method is called when authentication doesn't succeed. Before the `abort()` method exits the `LoginModule`, care should be taken to reset state including the username and password input fields.

### logout()

The release of the users principals and credentials when `LoginContext.logout` is called:

```java
public boolean logout() {
    if (!subject.isReadOnly()) {
        Set principals = subject.getPrincipals(UserGroupPrincipal.class);
        subject.getPrincipals().removeAll(principals);
        Set creds = subject.getPublicCredentials(UsernameCredential.class);
        subject.getPublicCredentials().removeAll(creds);
        return true;
    } else {
        return false;
    }
}
```

## CallbackHandler.java

The `callbackHandler` is in a source (`.java`) file separate from any single `LoginModule` so that it can service a multitude of LoginModules with differing callback objects:

- Creates instance of the `CallbackHandler` class and has only one method, `handle()`.
- A `CallbackHandler` servicing a LoginModule requiring username & password to login:

```java
public void handle(Callback[] callbacks) {
    for (int i = 0; i < callbacks.length; i++) {
        Callback callback = callbacks[i];
        if (callback instanceof NameCallback) {
            NameCallback nameCallBack = (NameCallback) callback;
            nameCallBack.setName(username);
    }  else if (callback instanceof PasswordCallback) {
            PasswordCallback passwordCallBack = (PasswordCallback) callback;
            passwordCallBack.setPassword(password.toCharArray());
        }
    }
}
```

## Related Articles

- [JAAS in Action](https://jaasbook.wordpress.com/2009/09/27/intro/), Michael Coté, posted on September 27, 2009, URL as 5/14/2012.
- Pistoia Marco, Nagaratnam Nataraj, Koved Larry, Nadalin Anthony from book ["Enterprise Java Security" - Addison-Wesley, 2004](https://www.oreilly.com/library/view/enterprise-javatm-security/0321118898/).

## Disclosure

All of the code in the attached JAAS cheat sheet has been copied verbatim from this [free source](https://jaasbook.wordpress.com/2009/09/27/intro/).

## References

- [Oracle JAAS Reference Guide](https://docs.oracle.com/javase/8/docs/technotes/guides/security/jaas/JAASRefGuide.html)
- [Oracle JAAS: LoginModule Developer's Guide](https://docs.oracle.com/en/java/javase/13/security/java-authentication-and-authorization-service-jaas-loginmodule-developers-guide1.html)
