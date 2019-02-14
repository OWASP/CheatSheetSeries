---
title: PL SQL Security Cheat Sheet
permalink: /PL/SQL_Security_Cheat_Sheet/
---

PL/SQL is a powerful procedural language built on top of Oracle SQL syntax. Extensive library of business-related and data-processing functions it incorporates makes it an attractive environment for building business-critical applications operating fully within the Oracle database. Introduction of PL/SQL Web Toolkit enabled Oracle developers to generate HTML straight from the PL/SQL code and build web applications fully residing from within the Oracle database.

Just as any other web stack, PL/SQL web applications require careful input validation and other standard safeguards to prevent exploitable [OWASP Top 10](/OWASP_Top_10 "wikilink") vulnerabilities. Oracle `htp` (hypertext procedures) and `htf` (hypertext functions) packages contain the primary functions for generating output in PL/SQL web applications as well as output escaping functions. See [Oracle: The htp and htf Packages](https://docs.oracle.com/cd/B14099_19/web.1012/b15896/pshtp.htm)

Escaping output data to prevent Cross-Site Scripting
----------------------------------------------------

Applications running on newer Oracle versions where APEX packages are available should use `apex_escape` for contextual escaping of output data in a manner similar to [ESAPI](/ESAPI "wikilink") validators. See [Oracle: apex_escape](https://docs.oracle.com/database/121/AEAPI/apex_escape.htm)

-   APEX_ESCAPE.HTML
-   APEX_ESCAPE.HTML_ATTRIBUTE
-   APEX_ESCAPE.HTML_TRUNC
-   APEX_ESCAPE.HTML_WHITELIST
-   APEX_ESCAPE.JS_LITERAL
-   APEX_ESCAPE.LDAP_DN
-   APEX_ESCAPE.LDAP_SEARCH_FILTER
-   APEX_ESCAPE.NOOP

Applications should use `htp.prints` to output text blocks rather than `htp.print` as the former escapes potentially dangerous characters (&lt;code&gt;&lt;&gt;"'</code>). Note that the `htp.prints` cannot be used as a simple drop-in replacement for `htp.print` because it will also escape legitimate HTML but by `htp` usage model raw HTML shouldn't be generally entered in strings but rather generated with appropriate HTML functions (e.g. `htp.header(1,` `'Hello');` will output <code>

<H1>
Hello

</H1>
</code>).

Sample usage in typical PL/SQL code:

`   htp.header(1, 'Details for user ' \|\| apex_escape.html(username)); -- outputs `

<H1>
...

</H1>
`   htp.print('Username: '); -- just a string literal, no need to escape`
`   htp.italic(apex_escape.html(username), 'class=' \|\| apex_escape.html_attribute(userclass) );`
`   htp.para();`
`   htp.prints(address); -- escapes dangerous chars in address string`
`   htp.script ('var username="' \|\| apex_escape.js_literal(username) \|\| '";');`

On older Oracle platforms `htf.escape_sc` for output in HTML context can be used and the `utl_url.escape` function is available to escape URL characters (&lt;code&gt;&"&lt;&gt;%</code>). URL escaping functionality is also provided by legacy `htf.escape_url` function. These functions are generally less robust than their `apex_escape` equivalents and not context-aware.

Input validation and sanitization
---------------------------------

### Regular expression functions

`   IF REGEXP_LIKE('untrusted input', '^[0-9a-zA-z]{2,6}$') THEN /* Match */ ELSE /* No match */ END IF;`
`   select REGEXP_REPLACE('subject<<>>', '[<>]') from dual; -- returns: "subject"`

### DBMS_ASSERT

-   ENQUOTE_LITERAL — Enquotes a string literal
-   ENQUOTE_NAME — Encloses a name in double quotes
-   NOOP — Returns the unmodified value
-   QUALIFIED_SQL_NAME — Verifies that the input string is a qualified SQL name
-   SCHEMA_NAME — Verifies that the input string is an existing schema name
-   SIMPLE_SQL_NAME — Verifies that the input string is a simple SQL name
-   SQL_OBJECT_NAME — Verifies that the input parameter string is a qualified SQL identifier of an existing SQL object

Example:

`   SELECT SYS.DBMS_ASSERT.SIMPLE_SQL_NAME  ('Data with `<invalid>` characters') FROM dual;`
`   ORA-44003: invalid SQL name`

See [Oracle: DBMS_ASSERT](https://docs.oracle.com/database/121/ARPLS/d_assert.htm#ARPLS231)

References
----------

-   [Oracle "How to write SQL injection proof PL/SQL"](http://www.oracle.com/technetwork/database/features/plsql/overview/how-to-write-injection-proof-plsql-1-129572.pdf)
-   [Security in Oracle ADF: Addressing the OWASP Top 10 Security Vulnerabilities](http://www.oracle.com/technetwork/developer-tools/adf/adfowasptop10-final-2348304.pdf)

Authors
-------

-   Pawel Krawczyk

Other Cheatsheets
-----------------

[Category:Cheatsheets](/Category:Cheatsheets "wikilink")
