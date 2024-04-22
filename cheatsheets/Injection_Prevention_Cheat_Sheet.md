# Injection Prevention Cheat Sheet

## Introduction

This article is focused on providing clear, simple, actionable guidance for preventing the entire category of Injection flaws in your applications. Injection attacks, especially [SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection), are unfortunately very common.

Application accessibility is a very important factor in protection and prevention of injection flaws. Only the minority of all applications within a company/enterprise are developed in house, where as most applications are from external sources. Open source applications give at least the opportunity to fix problems, but closed source applications need a different approach to injection flaws.

Injection flaws occur when an application sends untrusted data to an interpreter. Injection flaws are very prevalent, particularly in legacy code, often found in SQL queries, LDAP queries, XPath queries, OS commands, program arguments, etc. Injection flaws are easy to discover when examining code, but more difficult via testing. Scanners and fuzzers can help attackers find them.

Depending on the accessibility different actions must be taken in order to fix them. It is always the best way to fix the problem in source code itself, or even redesign some parts of the applications. But if the source code is not available or it is simply uneconomical to fix legacy software only virtual patching makes sense.

## Application Types

Three classes of applications can usually be seen within a company. Those 3 types are needed to identify the actions which need to take place in order to prevent/fix injection flaws.

### A1: New Application

A new web application in the design phase, or in early stage development.

### A2: Productive Open Source Application

An already productive application, which can be easily adapted. A Model-View-Controller (MVC) type application is just one example of having a easily accessible application architecture.

### A3: Productive Closed Source Application

A productive application which cannot or only with difficulty be modified.

## Forms of Injection

There are several forms of injection targeting different technologies including SQL queries, LDAP queries, XPath queries and OS commands.

### Query languages

The most famous form of injection is SQL Injection where an attacker can modify existing database queries. For more information see the [SQL Injection Prevention Cheat Sheet](SQL_Injection_Prevention_Cheat_Sheet.md).

But also LDAP, SOAP, XPath and REST based queries can be susceptible to injection attacks allowing for data retrieval or control bypass.

#### SQL Injection

An SQL injection attack consists of insertion or "injection" of either a partial or complete SQL query via the data input or transmitted from the client (browser) to the web application.

A successful SQL injection attack can read sensitive data from the database, modify database data (insert/update/delete), execute administration operations on the database (such as shutdown the DBMS), recover the content of a given file existing on the DBMS file system or write files into the file system, and, in some cases, issue commands to the operating system. SQL injection attacks are a type of injection attack, in which SQL commands are injected into data-plane input in order to affect the execution of predefined SQL commands.

SQL Injection attacks can be divided into the following three classes:

- **Inband:** data is extracted using the same channel that is used to inject the SQL code. This is the most straightforward kind of attack, in which the retrieved data is presented directly in the application web page.
- **Out-of-band:** data is retrieved using a different channel (e.g., an email with the results of the query is generated and sent to the tester).
- **Inferential or Blind:** there is no actual transfer of data, but the tester is able to reconstruct the information by sending particular requests and observing the resulting behavior of the DB Server.

##### How to test for the issue

###### During code review

please check for any queries to the database are not done via prepared statements.

If dynamic statements are being made please check if the data is sanitized before used as part of the statement.

Auditors should always look for uses of sp_execute, execute or exec within SQL Server stored procedures. Similar audit guidelines are necessary for similar functions for other vendors.

###### Automated Exploitation

Most of the situation and techniques below here can be performed in a automated way using some tools. In this article the tester can find information how to perform an automated auditing using [SQLMap](https://wiki.owasp.org/index.php/Automated_Audit_using_SQLMap)

Equally Static Code Analysis Data flow rules can detect of unsanitized user controlled input can change the SQL query.

###### Stored Procedure Injection

When using dynamic SQL within a stored procedure, the application must properly sanitize the user input to eliminate the risk of code injection. If not sanitized, the user could enter malicious SQL that will be executed within the stored procedure.

###### Time delay Exploitation technique

The time delay exploitation technique is very useful when the tester find a Blind SQL Injection situation, in which nothing is known on the outcome of an operation. This technique consists in sending an injected query and in case the conditional is true, the tester can monitor the time taken to for the server to respond. If there is a delay, the tester can assume the result of the conditional query is true. This exploitation technique can be different from DBMS to DBMS (check DBMS specific section).

```text
http://www.example.com/product.php?id=10 AND IF(version() like '5%', sleep(10), 'false'))--
```

In this example the tester is checking whether the MySql version is 5.x or not, making the server delay the answer by 10 seconds. The tester can increase the delay time and monitor the responses. The tester also doesn't need to wait for the response. Sometimes they can set a very high value (e.g. 100) and cancel the request after some seconds.

###### Out of band Exploitation technique

This technique is very useful when the tester find a Blind SQL Injection situation, in which nothing is known on the outcome of an operation. The technique consists of the use of DBMS functions to perform an out of band connection and deliver the results of the injected query as part of the request to the tester's server. Like the error based techniques, each DBMS has its own functions. Check for specific DBMS section.

##### Remediation

###### Defense Option 1: Prepared Statements (with Parameterized Queries)

Prepared statements ensure that an attacker is not able to change the intent of a query, even if SQL commands are inserted by an attacker. In the safe example below, if an attacker were to enter the userID of `tom' or '1'='1`, the parameterized query would not be vulnerable and would instead look for a username which literally matched the entire string `tom' or '1'='1`.

###### Defense Option 2: Stored Procedures

The difference between prepared statements and stored procedures is that the SQL code for a stored procedure is defined and stored in the database itself, and then called from the application.

Both of these techniques have the same effectiveness in preventing SQL injection so your organization should choose which approach makes the most sense for you. Stored procedures are not always safe from SQL injection. However, certain standard stored procedure programming constructs have the same effect as the use of parameterized queries when implemented safely* which is the norm for most stored procedure languages.

*Note:* 'Implemented safely' means the stored procedure does not include any unsafe dynamic SQL generation.

###### Defense Option 3: Allow-List Input Validation

Various parts of SQL queries aren't legal locations for the use of bind variables, such as the names of tables or columns, and the sort order indicator (ASC or DESC). In such situations, input validation or query redesign is the most appropriate defense. For the names of tables or columns, ideally those values come from the code, and not from user parameters.

But if user parameter values are used to make different for table names and column names, then the parameter values should be mapped to the legal/expected table or column names to make sure unvalidated user input doesn't end up in the query. Please note, this is a symptom of poor design and a full rewrite should be considered if time allows.

###### Defense Option 4: Escaping All User-Supplied Input

This technique should only be used as a last resort, when none of the above are feasible. Input validation is probably a better choice as this methodology is frail compared to other defenses and we cannot guarantee it will prevent all SQL Injection in all situations.

This technique is to escape user input before putting it in a query. It's usually only recommended to retrofit legacy code when implementing input validation isn't cost effective.

##### Example code - Java

###### Safe Java Prepared Statement Example

The following code example uses a `PreparedStatement`, Java's implementation of a parameterized query, to execute the same database query.

```java
// This should REALLY be validated too
String custname = request.getParameter("customerName");
// Perform input validation to detect attacks
String query = "SELECT account_balance FROM user_data WHERE user_name = ?";
PreparedStatement pstmt = connection.prepareStatement(query);
pstmt.setString(1, custname);
ResultSet results = pstmt.executeQuery();
```

We have shown examples in Java, but practically all other languages, including Cold Fusion, and Classic ASP, support parameterized query interfaces.

###### Safe Java Stored Procedure Example

The following code example uses a `CallableStatement`, Java's implementation of the stored procedure interface, to execute the same database query. The `sp_getAccountBalance` stored procedure would have to be predefined in the database and implement the same functionality as the query defined above.

```java
// This should REALLY be validated
String custname = request.getParameter("customerName");
try {
 CallableStatement cs = connection.prepareCall("{call sp_getAccountBalance(?)}");
 cs.setString(1, custname);
 ResultSet results = cs.executeQuery();
 // Result set handling...
} catch (SQLException se) {
 // Logging and error handling...
}
```

#### LDAP Injection

LDAP Injection is an attack used to exploit web based applications that construct LDAP statements based on user input. When an application fails to properly sanitize user input, it's possible to modify LDAP statements through techniques similar to [SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection). LDAP injection attacks could result in the granting of permissions to unauthorized queries, and content modification inside the LDAP tree. For more information on LDAP Injection attacks, visit [LDAP injection](https://owasp.org/www-community/attacks/LDAP_Injection).

[LDAP injection](https://owasp.org/www-community/attacks/LDAP_Injection) attacks are common due to two factors:

1. The lack of safer, parameterized LDAP query interfaces
2. The widespread use of LDAP to authenticate users to systems.

##### How to test for the issue

###### During code review

Please check for any queries to the LDAP escape special characters, see [here](LDAP_Injection_Prevention_Cheat_Sheet.md#defense-option-1-escape-all-variables-using-the-right-ldap-encoding-function).

###### Automated Exploitation

Scanner module of tool like OWASP [ZAP](https://www.zaproxy.org/) have module to detect LDAP injection issue.

##### Remediation

###### Escape all variables using the right LDAP encoding function

The main way LDAP stores names is based on DN ([distinguished name](https://ldapwiki.com/wiki/Distinguished%20Names)). You can think of this like a unique identifier. These are sometimes used to access resources, like a username.

A DN might look like this

```text
cn=Richard Feynman, ou=Physics Department, dc=Caltech, dc=edu
```

or

```text
uid=inewton, ou=Mathematics Department, dc=Cambridge, dc=com
```

There are certain characters that are considered special characters in a DN. The exhaustive list is the following: `\ # + < > , ; " =` and leading or trailing spaces

Each DN points to exactly 1 entry, which can be thought of sort of like a row in a RDBMS. For each entry, there will be 1 or more attributes which are analogous to RDBMS columns. If you are interested in searching through LDAP for users will certain attributes, you may do so with search filters. In a search filter, you can use standard boolean logic to get a list of users matching an arbitrary constraint. Search filters are written in Polish notation AKA prefix notation.

Example:

```text
(&(ou=Physics)(| (manager=cn=Freeman Dyson,ou=Physics,dc=Caltech,dc=edu)
(manager=cn=Albert Einstein,ou=Physics,dc=Princeton,dc=edu) ))
```

When building LDAP queries in application code, you MUST escape any untrusted data that is added to any LDAP query. There are two forms of LDAP escaping. Encoding for LDAP Search and Encoding for LDAP DN (distinguished name). The proper escaping depends on whether you are sanitizing input for a search filter, or you are using a DN as a username-like credential for accessing some resource.

##### Example code - Java

###### Safe Java for LDAP escaping Example

```java
public String escapeDN (String name) {
 //From RFC 2253 and the / character for JNDI
 final char[] META_CHARS = {'+', '"', '<', '>', ';', '/'};
 String escapedStr = new String(name);
 //Backslash is both a Java and an LDAP escape character,
 //so escape it first
 escapedStr = escapedStr.replaceAll("\\\\\\\\","\\\\\\\\");
 //Positional characters - see RFC 2253
 escapedStr = escapedStr.replaceAll("\^#","\\\\\\\\#");
 escapedStr = escapedStr.replaceAll("\^ | $","\\\\\\\\ ");
 for (int i=0 ; i < META_CHARS.length ; i++) {
        escapedStr = escapedStr.replaceAll("\\\\" +
                     META_CHARS[i],"\\\\\\\\" + META_CHARS[i]);
 }
 return escapedStr;
}
```

Note, that the backslash character is a Java String literal and a regular expression escape character.

```java
public String escapeSearchFilter (String filter) {
 //From RFC 2254
 String escapedStr = new String(filter);
 escapedStr = escapedStr.replaceAll("\\\\\\\\","\\\\\\\\5c");
 escapedStr = escapedStr.replaceAll("\\\\\*","\\\\\\\\2a");
 escapedStr = escapedStr.replaceAll("\\\\(","\\\\\\\\28");
 escapedStr = escapedStr.replaceAll("\\\\)","\\\\\\\\29");
 escapedStr = escapedStr.replaceAll("\\\\" +
               Character.toString('\\u0000'), "\\\\\\\\00");
 return escapedStr;
}
```

#### XPath Injection

TODO

### Scripting languages

All scripting languages used in web applications have a form of an `eval` call which receives code at runtime and executes it. If code is crafted using unvalidated and unescaped user input code injection can occur which allows an attacker to subvert application logic and eventually to gain local access.

Every time a scripting language is used, the actual implementation of the 'higher' scripting language is done using a 'lower' language like C. If the scripting language has a flaw in the data handling code '[Null Byte Injection](http://projects.webappsec.org/w/page/13246949/Null%20Byte%20Injection)' attack vectors can be deployed to gain access to other areas in memory, which results in a successful attack.

### Operating System Commands

OS command injection is a technique used via a web interface in order to execute OS commands on a web server. The user supplies operating system commands through a web interface in order to execute OS commands.

Any web interface that is not properly sanitized is subject to this exploit. With the ability to execute OS commands, the user can upload malicious programs or even obtain passwords. OS command injection is preventable when security is emphasized during the design and development of applications.

#### How to test for the issue

##### During code review

Check if any command execute methods are called and in unvalidated user input are taken as data for that command.

Out side of that, appending a semicolon to the end of a URL query parameter followed by an operating system command, will execute the command. `%3B` is URL encoded and decodes to semicolon. This is because the `;` is interpreted as a command separator.

Example: `http://sensitive/something.php?dir=%3Bcat%20/etc/passwd`

If the application responds with the output of the `/etc/passwd` file then you know the attack has been successful. Many web application scanners can be used to test for this attack as they inject variations of command injections and test the response.

Equally Static Code Analysis tools check the data flow of untrusted user input into a web application and check if the data is then entered into a dangerous method which executes the user input as a command.

#### Remediation

If it is considered unavoidable the call to a system command incorporated with user-supplied, the following two layers of defense should be used within software in order to prevent attacks

1. **Parameterization** - If available, use structured mechanisms that automatically enforce the separation between data and command. These mechanisms can help to provide the relevant quoting, encoding.
2. **Input validation** - the values for commands and the relevant arguments should be both validated. There are different degrees of validation for the actual command and its arguments:
    - When it comes to the **commands** used, these must be validated against a list of allowed commands.
    - In regards to the **arguments** used for these commands, they should be validated using the following options:
        - Positive or allowlist input validation - where are the arguments allowed explicitly defined
        - Allow-list Regular Expression - where is explicitly defined a list of good characters allowed and the maximum length of the string. Ensure that metacharacters like `& | ; $ > < \` \ !` and whitespaces are not part of the Regular Expression. For example, the following regular expression only allows lowercase letters and numbers, and does not contain metacharacters. The length is also being limited to 3-10 characters:

`^[a-z0-9]{3,10}$`

#### Example code - Java

##### Incorrect Usage

```java
ProcessBuilder b = new ProcessBuilder("C:\DoStuff.exe -arg1 -arg2");
```

In this example, the command together with the arguments are passed as a one string, making easy to manipulate that expression and inject malicious strings.

##### Correct Usage

Here is an example that starts a process with a modified working directory. The command and each of the arguments are passed separately. This make it easy to validated each term and reduces the risk to insert malicious strings.

```java
ProcessBuilder pb = new ProcessBuilder("TrustedCmd", "TrustedArg1", "TrustedArg2");
Map<String, String> env = pb.environment();
pb.directory(new File("TrustedDir"));
Process p = pb.start();
```

### Network Protocols

Web applications often communicate with network daemons (like SMTP, IMAP, FTP) where user input becomes part of the communication stream. Here it is possible to inject command sequences to abuse an established session.

## Injection Prevention Rules

### Rule \#1 (Perform proper input validation)

Perform proper input validation. Positive or allowlist input validation with appropriate canonicalization is also recommended, but **is not a complete defense** as many applications require special characters in their input.

### Rule \#2 (Use a safe API)

The preferred option is to use a safe API which avoids the use of the interpreter entirely or provides a parameterized interface. Be careful of APIs, such as stored procedures, that are parameterized, but can still introduce injection under the hood.

### Rule \#3 (Contextually escape user data)

If a parameterized API is not available, you should carefully escape special characters using the specific escape syntax for that interpreter.

## Other Injection Cheatsheets

[SQL Injection Prevention Cheat Sheet](SQL_Injection_Prevention_Cheat_Sheet.md)

[OS Command Injection Defense Cheat Sheet](OS_Command_Injection_Defense_Cheat_Sheet.md)

[LDAP Injection Prevention Cheat Sheet](LDAP_Injection_Prevention_Cheat_Sheet.md)

[Injection Prevention Cheat Sheet in Java](Injection_Prevention_in_Java_Cheat_Sheet.md)
