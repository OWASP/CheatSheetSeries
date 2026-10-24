# Injection Prevention Cheat Sheet

## Introduction

This article is focused on providing clear, simple, actionable guidance for preventing injection flaws in your applications. Injection attacks, for example [SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection), are unfortunately very common.

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

Use the guidance for the query language or interpreter your application uses:

| Type | When | Reference |
|------|------|-----------|
| SQL injection | Builds SQL queries | [SQL Injection Prevention](SQL_Injection_Prevention_Cheat_Sheet.md) and [Query Parameterization](Query_Parameterization_Cheat_Sheet.md) |
| Object-relational mapper query injection | Builds query strings with tools such as Hibernate | [SQL Injection Prevention](SQL_Injection_Prevention_Cheat_Sheet.md) and [Query Parameterization](Query_Parameterization_Cheat_Sheet.md) |
| NoSQL injection | Builds queries for a NoSQL database | [NoSQL Security](NoSQL_Security_Cheat_Sheet.md) |
| Cross-site scripting (XSS) | Places untrusted data into browser content | [Cross Site Scripting Prevention](Cross_Site_Scripting_Prevention_Cheat_Sheet.md) and [DOM based XSS Prevention](DOM_based_XSS_Prevention_Cheat_Sheet.md) |
| LDAP injection | Builds LDAP queries | [LDAP Injection Prevention](LDAP_Injection_Prevention_Cheat_Sheet.md) |
| XPath injection | Builds XPath queries | [XPath Injection Prevention](XPath_Injection_Prevention_Cheat_Sheet.md) |
| OS command injection | Invokes operating system commands | [OS Command Injection Defense](OS_Command_Injection_Defense_Cheat_Sheet.md) |
| Argument injection | Passes untrusted input as command arguments | [Argument Injection](OS_Command_Injection_Defense_Cheat_Sheet.md#argument-injection) |

For Java-specific guidance, see [Injection Prevention in Java](Injection_Prevention_in_Java_Cheat_Sheet.md).

### Query languages

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

###### Use the right LDAP encoding function

LDAP distinguished names and LDAP search filters require different escaping rules, defined by [RFC 4514](https://datatracker.ietf.org/doc/html/rfc4514) and [RFC 4515](https://datatracker.ietf.org/doc/html/rfc4515), respectively. Avoid custom escaping code and use a library encoder for the correct context. See the [LDAP Injection Prevention Cheat Sheet](LDAP_Injection_Prevention_Cheat_Sheet.md) for current defenses and examples.

#### XPath Injection

See the [XPath Injection Prevention Cheat Sheet](XPath_Injection_Prevention_Cheat_Sheet.md) for defenses and a parameterized query example.

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
ProcessBuilder b = new ProcessBuilder("C:\\DoStuff.exe -arg1 -arg2");
```

This creates a builder with one command-list element, not a program followed by two arguments. [`ProcessBuilder`](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/lang/ProcessBuilder.html) represents the executable and its arguments as a list. The snippet does not start a process or demonstrate shell-command injection.

##### Correct Usage

This illustrative example starts a process with a modified working directory and passes the executable and each argument separately. Keep the executable and working directory trusted, and validate any untrusted arguments for the invoked program. Argument separation does not replace [argument validation](OS_Command_Injection_Defense_Cheat_Sheet.md#layer-2).

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

## References

- [RFC 4514: LDAP Distinguished Names](https://datatracker.ietf.org/doc/html/rfc4514)
- [RFC 4515: LDAP Search Filters](https://datatracker.ietf.org/doc/html/rfc4515)
- [Oracle JDBC: Using Prepared Statements](https://docs.oracle.com/javase/tutorial/jdbc/basics/prepared.html)
