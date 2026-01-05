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

An allowlist can be used to restrict input to a list of valid characters. Characters and character sequences that must be excluded from allowlists — including
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

The following solution uses an allowlist to sanitize user input so that the filter string contains only valid characters. In this code, userSN may contain
only letters and spaces.

```java
// String userSN = "Sherlock Holmes"; // Valid
// ... beginning of LDAPInjection.searchRecord()...
sc.setSearchScope(SearchControls.SUBTREE_SCOPE);
String base = "dc=example,dc=com";

if (!userSN.matches("[\\w\\s]*")) {
 throw new IllegalArgumentException("Invalid input");
}

String filter = "(sn = " + userSN + ")";
// ... remainder of LDAPInjection.searchRecord()... 
```

When a database field must include special characters, it is critical to ensure that the authentic data is stored in sanitized form in the
database and also that any user input is normalized before the validation or comparison takes place. Using characters that have special meanings in JNDI
and LDAP in the absence of a comprehensive normalization and allowlisting-based routine is discouraged. Special characters must be transformed to
sanitized, safe values before they are added to the allowlist expression against which input will be validated. Likewise, normalization of user input should
occur before the validation step (source: [Prevent LDAP injection](https://wiki.sei.cmu.edu/confluence/spaces/flyingpdf/pdfpageexport.action?pageId=88487534)).

For further information visit [OWASP ESAPI Java Encoder Project which includes encodeForLDAP(String) and encodeForDN(String)](https://owasp.org/www-project-java-encoder/).

#### Insecure vs Secure Java LDAP Query Construction

❌ **Insecure Example (vulnerable to LDAP Injection)**

```java
// User input directly concatenated into the filter
String filter = "(&(uid=" + userInput + ")(objectClass=person))";
NamingEnumeration<SearchResult> results =
    ctx.search("ou=users,dc=example,dc=com", filter, controls);


✅ Secure Example (using parameterized filter)

// User input safely passed as a parameter
String filter = "(&(uid={0})(objectClass=person))";
NamingEnumeration<SearchResult> results =
    ctx.search("ou=users,dc=example,dc=com", filter, new Object[]{ userInput }, controls);
```

#### Safe C# .NET Libraries

| Library | .NET Support | NuGet | Notes |
|---------|--------------|-------|-------|
| [System.DirectoryServices.Protocols](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.protocols) | .NET 6+ / Core | [Official](https://www.nuget.org/packages/System.DirectoryServices.Protocols/) | Microsoft LDAP v3 |
| [System.DirectoryServices](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices) | .NET 6+ | [NuGet](https://www.nuget.org/packages/system.directoryservices/) | Active Directory access |
| [Novell.Directory.Ldap.NETStandard](https://www.nuget.org/packages/Novell.Directory.Ldap.NETStandard) | .NET Std 2.0+ | [NuGet](https://www.nuget.org/packages/Novell.Directory.Ldap.NETStandard) | Cross-platform LDAP |

**Security Note:** None of these .NET LDAP libraries provide automatic input escaping. You MUST manually escape user input using RFC 4515 encoding before constructing LDAP filter strings.

**Example (Secure - RFC 4515 Escaping):**

```csharp
// Manual LDAP filter escaping per RFC 4515
public static string EscapeLdapFilterValue(string value)
{
    if (string.IsNullOrEmpty(value))
        return string.Empty;
    
    return value
        .Replace("\\", "\\5c")
        .Replace("*", "\\2a")
        .Replace("(", "\\28")
        .Replace(")", "\\29")
        .Replace("\0", "\\00");
}

// Usage with System.DirectoryServices.Protocols
var escapedUid = EscapeLdapFilterValue(userInput);
var request = new SearchRequest(
    "dc=example,dc=com",
    $"(&(objectClass=person)(uid={escapedUid}))",
    SearchScope.Subtree
);
```

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
