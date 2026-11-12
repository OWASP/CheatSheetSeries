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
| Cross-site scripting (XSS) | Places untrusted data into browser content | [Cross Site Scripting Prevention](Cross_Site_Scripting_Prevention_Cheat_Sheet.md), [DOM based XSS Prevention](DOM_based_XSS_Prevention_Cheat_Sheet.md) and [XSS Filter Evasion](XSS_Filter_Evasion_Cheat_Sheet.md) |
| LDAP injection | Builds LDAP queries | [LDAP Injection Prevention](LDAP_Injection_Prevention_Cheat_Sheet.md) |
| XPath injection | Builds XPath queries | [XPath Injection Prevention](XPath_Injection_Prevention_Cheat_Sheet.md) |
| OS command injection | Invokes operating system commands | [OS Command Injection Defense](OS_Command_Injection_Defense_Cheat_Sheet.md) |
| Argument injection | Passes untrusted input as command arguments | [Argument Injection](OS_Command_Injection_Defense_Cheat_Sheet.md#argument-injection) |

For Java-specific guidance, see [Injection Prevention in Java](Injection_Prevention_in_Java_Cheat_Sheet.md).

### Query languages

#### XPath Injection

See the [XPath Injection Prevention Cheat Sheet](XPath_Injection_Prevention_Cheat_Sheet.md) for defenses and a parameterized query example.

### Scripting languages

All scripting languages used in web applications have a form of an `eval` call which receives code at runtime and executes it. If code is crafted using unvalidated and unescaped user input code injection can occur which allows an attacker to subvert application logic and eventually to gain local access.

Every time a scripting language is used, the actual implementation of the 'higher' scripting language is done using a 'lower' language like C. If the scripting language has a flaw in the data handling code '[Null Byte Injection](http://projects.webappsec.org/w/page/13246949/Null%20Byte%20Injection)' attack vectors can be deployed to gain access to other areas in memory, which results in a successful attack.

### Operating System Commands

See the [OS Command Injection Defense Cheat Sheet](OS_Command_Injection_Defense_Cheat_Sheet.md) for testing guidance, layered remediation, and language-specific examples.

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

- [Oracle JDBC: Using Prepared Statements](https://docs.oracle.com/javase/tutorial/jdbc/basics/prepared.html)
- [DOM based XSS Prevention Cheat Sheet](DOM_based_XSS_Prevention_Cheat_Sheet.md)
- [XSS Filter Evasion Cheat Sheet](XSS_Filter_Evasion_Cheat_Sheet.md)
