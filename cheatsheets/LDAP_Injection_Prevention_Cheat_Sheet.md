# LDAP Injection Prevention Cheat Sheet

## Introduction

The Lightweight Directory Access Protocol (LDAP) allows an application to remotely perform operations—such as searching and modifying records—in directory services. LDAP injection results from inadequate input handling and allows malicious users to manipulate LDAP queries to glean restricted information or change directory content. For general background on LDAP, see [What is LDAP?](https://www.redhat.com/en/topics/security/what-is-ldap-authentication).

LDAP injection is similar in spirit to [SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection): when an application constructs LDAP statements from untrusted input without proper handling, attackers can alter query logic.

This cheat sheet provides clear, actionable guidance to prevent [LDAP Injection](https://owasp.org/www-community/attacks/LDAP_Injection). LDAP injection attacks are common due to:

1. The lack of widely adopted, parameterized LDAP query interfaces.
2. The widespread use of LDAP for authentication and authorization.

LDAP injection can lead to granting permissions to unauthorized principals, data disclosure, and modification within the LDAP tree.

**Primary defenses:**

- Escape all variables with the correct LDAP encoding function.
- Use frameworks that automatically and correctly escape/encode.

**Additional defenses:**

- Least privilege.
- Allow-list input validation.

---

## Primary Defenses

### Defense option 1: Escape all variables using the correct LDAP encoding function

#### Distinguished name (DN) escaping

LDAP identifies entries using a distinguished name (DN). You can think of a DN as a unique path to an entry, similar to a fully qualified username.

Examples:

`cn=Richard Feynman,ou=Physics Department,dc=Caltech,dc=edu`

or

`uid=inewton,ou=Mathematics Department,dc=Cambridge,dc=com`

When building DNs from untrusted input, apply **DN escaping**. Characters and conditions that require escaping in DNs include:

- The characters: `\`, `#`, `+`, `<`, `>`, `,`, `;`, `"`, `=`
- Leading or trailing spaces

An allow-list can further restrict input to known-good characters.

Some characters that are commonly permitted in DNs (and may not require escaping when not in special positions) include:

```text
* ( ) . & - _ [ ] ` ~ | @ $ % ^ ? : { } ! '
```

For normative DN string rules, see [RFC 4514](https://datatracker.ietf.org/doc/html/rfc4514).

---

See:  
- [Anonymous Bind (LDAP)](https://ldapwiki.com/wiki/Anonymous%20Bind)  

---

### Allow-list input validation

Input validation can be used to detect unauthorized input before it is passed to an LDAP query.  

For more details, see the [Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html).
- [Unauthenticated Bind (LDAP)](https://ldapwiki.com/wiki/Unauthenticated%20Bind)  

#### Search filter escaping
If LDAP is configured with bind authentication, attackers cannot trivially perform LDAP injection because valid credentials are required. However, injection may still be possible through anonymous connections or when applications allow unauthenticated binds.  

Search filters identify entries by attribute constraints and use boolean logic in prefix (Polish) notation.  


Example filter:
#### Enabling bind authentication

```text

To minimize the potential damage of a successful LDAP injection attack, minimize the privileges assigned to the LDAP binding account in your environment.

(&(ou=Physics)(|
  (manager=cn=Freeman Dyson,ou=Physics,dc=Caltech,dc=edu)
  (manager=cn=Albert Einstein,ou=Physics,dc=Princeton,dc=edu)
))
```
### Least privilege

When putting untrusted data into **search filters**, apply **filter escaping**. At a minimum, escape:

- `*` `(` `)` `\` and the NUL character

See [RFC 4515](https://datatracker.ietf.org/doc/html/rfc4515#section-3) for the precise rules.


> **Important:** There are two different encodings:
>
> - **Filter encoding** (for search filters)  
## Additional Defenses

Beyond adopting one of the two primary defenses, we also recommend adopting these additional defenses for defense-in-depth:
> - **DN encoding** (for distinguished names)  
>
> Use the correct one for the context.

---

---

#### Safe Java example (allow-list + ESAPI encoding)

Use both allow-listing (to keep inputs predictable) and correct encoding before interpolation. In Java, **OWASP ESAPI** provides the right methods: `encodeForLDAP(String)` (filter) and `encodeForDN(String)` (DN).

```java

import javax.naming.directory.SearchControls;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Encoder;

public List<?> searchRecord(String userSN, String userPassword) {
    SearchControls sc = new SearchControls();
We recommend using **LINQ to LDAP** (for .NET Framework 4.5 or lower until it has been updated) in .NET. It provides automatic LDAP encoding when building LDAP queries. See the README for usage examples.
    sc.setSearchScope(SearchControls.SUBTREE_SCOPE);
    String base = "dc=example,dc=com";

    // Keep inputs simple/predictable (optional but recommended)
    if (!userSN.matches("[\w\s]*")) {
        throw new IllegalArgumentException("Invalid surname");
#### Safe .NET example

    }
    if (!userPassword.matches("[A-Za-z0-9]*")) {
        throw new IllegalArgumentException("Invalid password");
    }

    Encoder enc = ESAPI.encoder();


    // Use filter encoding for attributes/values used in search filters
    String safeSN = enc.encodeForLDAP(userSN);         // filter context
    String safePwd = enc.encodeForLDAP(userPassword);  // filter context

    String filter = "(&(sn=" + safeSN + ")(userPassword=" + safePwd + "))";

    // ... perform LDAP search with base + filter + controls ...
    return List.of(); // placeholder
### Defense option 2: Use frameworks that automatically protect from LDAP injection
}
```

Example of **DN encoding**:

```java

Encoder enc = ESAPI.encoder();
String uid = "inewton";
String safeUid = enc.encodeForDN("uid=" + uid); // DN context
String userDn = safeUid + ",ou=People,dc=example,dc=com";
```

---
---

#### Safe C# / .NET example

The .NET `Encoder` class has LDAP encoding functions including:
```

allows you to disable escaping of leading/trailing characters when concatenating fragments into a complete DN.


- `Encoder.LdapFilterEncode(string)`
- `Encoder.LdapDistinguishedNameEncode(string)`
- `Encoder.LdapDistinguishedNameEncode(string, bool, bool)`

`LdapFilterEncode` encodes input according to [RFC 4515](https://datatracker.ietf.org/doc/html/rfc4515), where unsafe values are converted to `\XX` where `XX` is the representation of the unsafe character.

`LdapDistinguishedNameEncode` encodes input according to [RFC 2253](https://datatracker.ietf.org/doc/html/rfc2253), where unsafe characters are converted to `#XX` where `XX` is the representation of the unsafe character and the comma, plus, quote, slash, less than and greater-than signs are escaped using slash notation (`\X`). In addition, a space or `#` at the beginning of the string and a space at the end of a string are escaped.

