---
title: LDAP Injection Prevention Cheat Sheet
permalink: /LDAP_Injection_Prevention_Cheat_Sheet/
---

`__NOTOC__`

<div style="width:100%;height:160px;border:0,margin:0;overflow: hidden;">
[link=](/File:Cheatsheets-header.jpg\ "wikilink")

</div>
<b>WORK IN PROGRESS</b>

Last revision (mm/dd/yy): **//**

Introduction
============

`__TOC__`

This cheatsheet is focused on providing clear, simple, actionable guidance for preventing LDAP Injection flaws in your applications.

LDAP Injection is an attack used to exploit web based applications that construct LDAP statements based on user input. When an application fails to properly sanitize user input, it’s possible to modify LDAP statements through techniques similar to [SQL Injection](/SQL_Injection "wikilink"). LDAP injection attacks could result in the granting of permissions to unauthorized queries, and content modification inside the LDAP tree. For more information on LDAP Injection attacks, visit [LDAP injection](/LDAP_injection "wikilink").

[LDAP injection](/LDAP_injection "wikilink") attacks are common due to two factors:

1.  The lack of safer, parameterized LDAP query interfaces
2.  The widespread use of LDAP to authenticate users to systems.

Primary Defenses:

-   Escape all variables using the right LDAP encoding function

Additional Defenses:

-   Use a framework (like LINQtoAD) that escapes automatically

Primary Defenses
================

Defense Option 1: Escape all variables using the right LDAP encoding function
-----------------------------------------------------------------------------

The main way LDAP stores names is based on DN (distinguished name). You can think of this like a unique identifier. These are sometimes used to access resources, like a username.

A DN might look like this

`cn=Richard Feynman, ou=Physics Department, dc=Caltech, dc=edu`

or

`uid=inewton, ou=Mathematics Department, dc=Cambridge, dc=com`

There are certain characters that are considered special characters in a DN. The exhaustive list is the following: ',','\\','\#','+','&lt;','&gt;',';','"','=', and leading or trailing spaces

Each DN points to exactly 1 entry, which can be thought of sort of like a row in a RDBMS. For each entry, there will be 1 or more attributes which are analogous to RDBMS columns. If you are interested in searching through LDAP for users will certain attributes, you may do so with search filters. In a search filter, you can use standard boolean logic to get a list of users matching an arbitrary constraint. Search filters are written in Polish notation AKA prefix notation.

Example:

`(&(ou=Physics)(\|`
`(manager=cn=Freeman Dyson,ou=Physics,dc=Caltech,dc=edu)`
`(manager=cn=Albert Einstein,ou=Physics,dc=Princeton,dc=edu)`
`))`

When building LDAP queries in application code, you MUST escape any untrusted data that is added to any LDAP query. There are two forms of LDAP escaping. Encoding for LDAP Search and Encoding for LDAP DN (distinguished name). The proper escaping depends on whether you are sanitizing input for a search filter, or you are using a DN as a username-like credential for accessing some resource.

Safe Java Escaping Example

2008 Java article on LDAP injection defense: <https://blogs.oracle.com/shankar/entry/what_is_ldap_injection>

Legacy OWASP ESAPI for Java DefaultEncoder which includes encodeForLDAP(String) and encodeForDN(String): <https://github.com/ESAPI/esapi-java-legacy/blob/develop/src/main/java/org/owasp/esapi/reference/DefaultEncoder.java>

Safe C\# .NET TBA Example

.NET AntiXSS (now the Encoder class) has LDAP encoding functions including Encoder.LdapFilterEncode(string), Encoder.LdapDistinguishedNameEncode(string) and Encoder.LdapDistinguishedNameEncode(string, bool, bool). <http://blogs.msdn.com/b/securitytools/archive/2010/09/30/antixss_2d00_4_2d00_0_2d00_release_2d00_notes.aspx>

Encoder.LdapFilterEncode encodes input according to RFC4515 where unsafe values are converted to \\XX where XX is the representation of the unsafe character.

Encoder.LdapDistinguishedNameEncode encodes input according to RFC 2253 where unsafe characters are converted to \#XX where XX is the representation of the unsafe character and the comma, plus, quote, slash, less than and great than signs are escaped using slash notation (\\X). In addition to this a space or octothorpe (\#) at the beginning of the input string is \\ escaped as is a space at the end of a string.

LdapDistinguishedNameEncode(string, bool, bool) is also provided so you may turn off the initial or final character escaping rules, for example if you are concatenating the escaped distinguished name fragment into the midst of a complete distinguished name.

Defense Option 2: Use Frameworks that Automatically Protect from LDAP Injection
-------------------------------------------------------------------------------

Safe NET Example

<i>LINQ to Active Directory</i> provides automatic LDAP encoding when building LDAP queries: <https://linqtoad.codeplex.com/>

Defense Option 3: Additional Defenses
-------------------------------------

Beyond adopting one of the two primary defenses, we also recommend adopting all of these additional defenses in order to provide defense in depth. These additional defenses are:

-   **Least Privilege**
-   **White List Input Validation**

Least Privilege
---------------

To minimize the potential damage of a successful LDAP injection attack, you should minimize the privileges assigned to the LDAP binding account in your environment.

White List Input Validation
---------------------------

Input validation can be used to detect unauthorized input before it is passed to the LDAP query. For more information please see the [Input Validation Cheat Sheet](/Input_Validation_Cheat_Sheet "wikilink").

Related Articles
================

-   OWASP article on [LDAP Injection](/LDAP_injection\ "wikilink") Vulnerabilities
-   OWASP article on [Preventing LDAP Injection in Java](/Preventing_LDAP_Injection_in_Java "wikilink")
-   [OWASP Testing Guide](/:Category:OWASP_Testing_Project\ "wikilink") article on how to [Test for LDAP Injection](/Testing_for_LDAP_Injection_(OTG-INPVAL-006)\ "wikilink") Vulnerabilities

Authors and Primary Editors
===========================

Ben Weintraub - Ben\[at\]bluetalon.com
Jim Manico - jim\[at\]owasp.org

Other Cheatsheets
=================

[Category:Cheatsheets](/Category:Cheatsheets "wikilink") [Category:Popular](/Category:Popular "wikilink")