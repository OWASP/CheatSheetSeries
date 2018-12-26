---
title: JAAS Cheat Sheet
permalink: /JAAS_Cheat_Sheet/
---

`__NOTOC__`

<div style="width:100%;height:160px;border:0,margin:0;overflow: hidden;">
[link=](/File:Cheatsheets-header.jpg\ "wikilink")

</div>
{\\| style="padding: 0;margin:0;margin-top:10px;text-align:left;" \\|- \\| valign="top" style="border-right: 1px dotted gray;padding-right:25px;" \\| Last revision (mm/dd/yy): **//**

Introduction
============

`__TOC__`

What is JAAS authentication
---------------------------

The process of verifying the identity of a user or another system is authentication. JAAS, as an authentication framework manages the authenticated user’s identity and credentials from login to logout.
The JAAS authentication lifecycle:

1.  Create LoginContext
2.  Read the configuration file for one or more LoginModules to initialize
3.  Call LoginContext.initialize () for each LoginModule to initialize.
4.  Call LoginContext.login () for each LoginModule
5.  If login successful then call LoginContext.commit () else call LoginContext.abort ()

Configuration file
------------------

The JAAS configuration file contains a LoginModule stanza for each LoginModule available for logging on to the application.

A stanza from a JAAS configuration file:

    Branches
    {
         USNavy.AppLoginModule required
         debug=true
         succeeded=true;
    }

Note the placement of the semicolons, terminating both LoginModule entries and stanzas. The word required indicates the LoginContext’s login () method must be successful when logging in the user. The LoginModule-specific values debug and succeeded are passed to the LoginModule. They are defined by the LoginModule and their usage is managed inside the LoginModule. Note, Options are Configured using key-value pairing such as debug="true" and the key and value should be separated by a 'equals' sign.

Main.java (The client)
----------------------

-   Execution syntax

<!-- -->

    Java –Djava.security.auth.login.config==packageName/packageName.config
         packageName.Main Stanza1
    Where:
    packageName is the directory containing the config file.
    packageName.config specifies the config file in the Java package, packageName
    packageName.Main specifies Main.java in the Java package, packageName
    Stanza1 is the name of the stanza Main () should read from the config file.

-   When executed, the 1st command line argument is the stanza from the config file. The Stanza names the LoginModule to be used. The 2nd argument is the CallbackHandler.
-   Create a new LoginContext with the arguments passed to Main.java.
    -   loginContext = new LoginContext (args\[0\], new AppCallbackHandler ());
-   Call the LoginContext.Login Module
    -   loginContext.login ();
-   The value in succeeded Option is returned from loginContext.login ()
-   If the login was successful, a subject was created.

LoginModule.java
----------------

A LoginModule must have the following authentication methods:

-   initialize ()
-   login ()
-   commit ()
-   abort ()
-   logout ()

### initialize ()

In Main (), after the LoginContext reads the correct stanza from the config file, the LoginContext instantiates the LoginModule specified in the stanza.

-   initialize () methods signature:
    -   Public void initialize (Subject subject, CallbackHandler callbackHandler, Map sharedState, Map options)
-   The arguments above should be saved as follows:
    -   this.subject = subject;
    -   this.callbackHandler = callbackHandler;
    -   this.sharedState = sharedState;
    -   this.options = options;
-   What the initialize () method does:
    -   Builds a subject object of the Subject class contingent on a successful login ()
    -   Sets the CallbackHandler which interacts with the user to gather login information
    -   If a LoginContext specifies 2 or more LoginModules, which is legal, they can share information via a sharedState map
    -   Saves state information such as debug and succeeded in an options Map

### login ()

Captures user supplied login information. The code snippet below declares an array of two callback objects which, when passed to the callbackHandler.handle method in the callbackHandler.java program, will be loaded with a user name and password provided interactively by the user.

    NameCallback nameCB = new NameCallback("Username");
    PasswordCallback passwordCB = new PasswordCallback ("Password", false);
    Callback[] callbacks = new Callback[] { nameCB, passwordCB };
    callbackHandler.handle (callbacks);

-   Authenticates the user
-   Retrieves the user supplied information from the callback objects:
    -   String ID = nameCallback.getName ();
    -   char\[\] tempPW = passwordCallback.getPassword ();
-   Compare name and tempPW to values stored in a repository such as LDAP
-   Set the value of the variable succeeded and return to Main ()

### commit ()

Once the users credentials are successfully verified during login (), the JAAS authentication framework associates the credentials, as needed, with the subject. There are two types of credentials, public and private. Public credentials include public keys. Private credentials include passwords and public keys. Principals (i.e. Identities the subject has other than their login name) such as employee number or membership ID in a user group are added to the subject. Below, is an example commit () method where first, for each group the authenticated user has membership in, the group name is added as a principal to the subject. The subject’s username is then added to their public credentials.

Code snippet setting then adding any principals and a public credentials to a subject: :

    public boolean commit() {
      If (userAuthenticated) {
         Set groups = UserService.findGroups (username);
         for (Iterator itr = groups.iterator (); itr.hasNext (); {
            String groupName = (String) itr.next ();
            UserGroupPrincipal group = new UserGroupPrincipal (GroupName);
            subject.getPrincipals ().add (group);
         }
         UsernameCredential cred = new UsernameCredential (username);
         subject.getPublicCredentials().add (cred);
      }
    }

### abort ()

The abort () method is called when authentication doesn’t succeed. Before the abort () method exits the LoginModule, care should be taken to reset state including the user name and password input fields.

### logout ()

-   The release of the users principals and credentials when LoginContext.logout is called.

public boolean logout() { if (!subject.isReadOnly()) {

`  Set principals = subject.getPrincipals(UserGroupPrincipal.class);`
`  subject.getPrincipals().removeAll(principals);`
`  Set creds = subject.getPublicCredentials(UsernameCredential.class);`
`  subject.getPublicCredentials().removeAll(creds);`
`  return true;`

} else {

`          return false;`
`  }`

}

CallbackHandler.java
--------------------

The callbackHandler is in a source (.java) file separate from any single LoginModule so that it can service a multitude of LoginModules with differing callback objects.

-   Creates instance of the CallbackHandler class and has only one method, handle ().
-   A CallbackHandler servicing a LoginModule requiring username & password to login:

<!-- -->

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

Related Articles
================

-   JAAS in Action, Michael Coté, posted on September 27, 2009, URL as 5/14/2012 <http://jaasbook.com/>
-   Pistoia, Marco, Nagaratnam, Nataraj, Koved, Larry, Nadalin, Anthony, "Enterprise Java Security", Addison-Wesley, 2004.

Disclosure
==========

All of the code in the attached JAAS cheat sheet has been copied verbatim from the free source at <http://jaasbook.com/>

Authors and Primary Editors
===========================

Dr. A.L. Gottlieb - AnthonyG \[at\] owasp.org

Other Cheatsheets
=================

\\|}

[Category:Cheatsheets](/Category:Cheatsheets "wikilink")