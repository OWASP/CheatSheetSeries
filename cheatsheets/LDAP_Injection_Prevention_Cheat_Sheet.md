# LDAP Injection Prevention Cheat Sheet

## Introduction

The Lightweight Directory Access Protocol (LDAP) allows an application to remotely perform operations such as searching and modifying records in
directories. LDAP injection results from inadequate input sanitization and validation and allows malicious users to glean restricted information using the
directory service. For general information about LDAP please visit [lightweight directory access protocol (LDAP)](https://www.redhat.com/en/topics/security/what-is-ldap-authentication).

LDAP Injection is an attack used to exploit web based applications that construct LDAP statements based on user input. When an application fails to properly sanitize user input, it's possible to modify LDAP statements through techniques similar to [SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection).

This cheatsheet is focused on providing clear, simple, actionable guidance for preventing LDAP Injection flaws in your applications. [LDAP injection](https://owasp.org/www-community/attacks/LDAP_Injection) attacks are common due to two factors:

1. The lack of safer, parameterized LDAP query interfaces
2. The widespread use of LDAP to authenticate users to systems.

LDAP injection attacks could result in the granting of permissions to unauthorized queries, and content modification inside the LDAP tree.

Primary Defenses:

- Escape all variables using the right LDAP encoding function
- Use a framework that escapes automatically.

Additional Defenses:

- Least Privilege
- Allow-List Input Validation

## Primary Defenses

### Defense Option 1: Escape all variables using the right LDAP encoding function

#### Distinguished Name Escaping

The main way LDAP stores names is based on DN (distinguished name). You can think of this like a unique identifier. These are sometimes used to access resources, like a username.

A DN might look like this

`cn=Richard Feynman, ou=Physics Department, dc=Caltech, dc=edu`

or

`uid=inewton, ou=Mathematics Department, dc=Cambridge, dc=com`

A whitelist can be used to restrict input to a list of valid characters. Characters and character sequences that must be excluded from whitelists — including
Java Naming and Directory Interface (JNDI) metacharacters and LDAP special characters — are listed in the following list.

The [exhaustive list](https://ldapwiki.com/wiki/Wiki.jsp?page=DN%20Escape%20Values) is the following: `\ # + < > , ; " =` and leading or trailing spaces.

Some "special" characters that are allowed in Distinguished Names and do not need to be escaped include:

```text
* ( ) . & - _ [ ] ` ~ | @ $ % ^ ? : { } ! '
```

#### Search Filter Escaping

Each DN points to exactly 1 entry, which can be thought of sort of like a row in a RDBMS. For each entry, there will be 1 or more attributes which are analogous to RDBMS columns. If you are interested in searching through LDAP for users with certain attributes, you may do so with search filters.

In a search filter, you can use standard boolean logic to get a list of users matching an arbitrary constraint. Search filters are written in Polish notation AKA prefix notation.

Example:

```text
(&(ou=Physics)(|
(manager=cn=Freeman Dyson,ou=Physics,dc=Caltech,dc=edu)
(manager=cn=Albert Einstein,ou=Physics,dc=Princeton,dc=edu)
))
```

When building LDAP queries in application code, you MUST escape any untrusted data that is added to any LDAP query. There are two forms of LDAP escaping. Encoding for LDAP Search and Encoding for LDAP DN (distinguished name). The proper escaping depends on whether you are sanitizing input for a search filter, or you are using a DN as a username-like credential for accessing some resource.

Some "special" characters that are allowed in search filters and must be escaped include:

```text
* ( ) \ NUL
```

For more information on search filter escaping visit [RFC4515](https://datatracker.ietf.org/doc/html/rfc4515#section-3).

#### Safe Java Escaping Example

The following solution uses a whitelist to sanitize user input so that the filter string contains only valid characters. In this code, userSN may contain
only letters and spaces, whereas a password may contain only alphanumeric characters:

```java
// String userSN = "Sherlock Holmes"; // Valid
// String userPassword = "secret2"; // Valid
// ... beginning of LDAPInjection.searchRecord()...
sc.setSearchScope(SearchControls.SUBTREE_SCOPE);
String base = "dc=example,dc=com";

if (!userSN.matches("[\\w\\s]*") || !userPassword.matches("[\\w]*")) {
 throw new IllegalArgumentException("Invalid input");
}

String filter = "(&(sn = " + userSN + ")(userPassword=" + userPassword + "))";
// ... remainder of LDAPInjection.searchRecord()... 
```

When a database field such as a password must include special characters, it is critical to ensure that the authentic data is stored in sanitized form in the
database and also that any user input is normalized before the validation or comparison takes place. Using characters that have special meanings in JNDI
and LDAP in the absence of a comprehensive normalization and whitelisting-based routine is discouraged. Special characters must be transformed to
sanitized, safe values before they are added to the whitelist expression against which input will be validated. Likewise, normalization of user input should
occur before the validation step (source: [Prevent LDAP injection](https://wiki.sei.cmu.edu/confluence/spaces/flyingpdf/pdfpageexport.action?pageId=88487534)).

For further information visit [OWASP ESAPI Java Encoder Project which includes encodeForLDAP(String) and encodeForDN(String)](https://owasp.org/www-project-java-encoder/).

#### Safe C Sharp .NET TBA Example

[.NET AntiXSS](https://blogs.msdn.microsoft.com/securitytools/2010/09/30/antixss-4-0-released/) (now the Encoder class) has LDAP encoding functions including `Encoder.LdapFilterEncode(string)`, `Encoder.LdapDistinguishedNameEncode(string)` and `Encoder.LdapDistinguishedNameEncode(string, bool, bool)`.

`Encoder.LdapFilterEncode` encodes input according to [RFC4515](https://tools.ietf.org/search/rfc4515) where unsafe values are converted to `\XX` where `XX` is the representation of the unsafe character.

`Encoder.LdapDistinguishedNameEncode` encodes input according to [RFC2253](https://tools.ietf.org/html/rfc2253) where unsafe characters are converted to `#XX` where `XX` is the representation of the unsafe character and the comma, plus, quote, slash, less than and great than signs are escaped using slash notation (`\X`). In addition to this a space or octothorpe (`#`) at the beginning of the input string is `\` escaped as is a space at the end of a string.

`LdapDistinguishedNameEncode(string, bool, bool)` is also provided so you may turn off the initial or final character escaping rules, for example if you are concatenating the escaped distinguished name fragment into the midst of a complete distinguished name.

### Defense Option 2: Use Frameworks that Automatically Protect from LDAP Injection

#### Safe .NET Example

We recommend using [LINQ to LDAP](https://www.nuget.org/packages/LinqToLdap/) (for .NET Framework 4.5 or lower [until it has been updated](https://github.com/madhatter22/LinqToLdap/issues/31)) in DotNet. It provides automatic LDAP encoding when building LDAP queries.
Contact the [Readme file](https://github.com/madhatter22/LinqToLdap/blob/master/README.md) in the project repository.

## Additional Defenses

Beyond adopting one of the two primary defenses, we also recommend adopting all of these additional defenses in order to provide defense in depth. These additional defenses are:

- **Least Privilege**
- **Allow-List Input Validation**

### Least Privilege

To minimize the potential damage of a successful LDAP injection attack, you should minimize the privileges assigned to the LDAP binding account in your environment.

### Enabling Bind Authentication

If LDAP protocol is configured with bind Authentication, attackers would not be able to perform LDAP injection attacks because of verification
and authorization checks that are performed against valid credentials passed by the user.
An attacker can still bypass bind authentication through an anonymous connection or by exploiting the use of unauthenticated bind: Anonymous Bind (LDAP) and Unauthenticated Bind (LDAP).

### Allow-List Input Validation

Input validation can be used to detect unauthorized input before it is passed to the LDAP query. For more information please see the [Input Validation Cheat Sheet](Input_Validation_Cheat_Sheet.md).

## Related Articles

- OWASP article on [LDAP Injection](https://owasp.org/www-community/attacks/LDAP_Injection) Vulnerabilities.
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/) article on how to [Test for LDAP Injection](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/06-Testing_for_LDAP_Injection.html) Vulnerabilities.
