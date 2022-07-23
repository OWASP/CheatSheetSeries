# AJAX Security Cheat Sheet

## Introduction

This document will provide a starting point for AJAX security and will hopefully be updated and expanded reasonably often to provide more detailed information about specific frameworks and technologies.

### Client Side (JavaScript)

#### Use `.innerText` instead of `.innerHTML`

The use of `.innerText` will prevent most XSS problems as it will automatically encode the text.

#### Don't use `eval()`, `new Function()` or other code evaluation tools

`eval()` function is evil, never use it. Needing to use eval usually indicates a problem in your design.

#### Canonicalize data to consumer (read: encode before use)

When using data to build HTML, script, CSS, XML, JSON, etc. make sure you take into account how that data must be presented in a literal sense to keep its logical meaning.

Data should be properly encoded before used in this manner to prevent injection style issues, and to make sure the logical meaning is preserved.

[Check out the OWASP Java Encoder Project.](https://owasp.org/www-project-java-encoder/)

#### Don't rely on client logic for security

Don't forget that the user controls the client-side logic. A number of browser plugins are available to set breakpoints, skip code, change values, etc. Never rely on client logic for security.

#### Don't rely on client business logic

Just like the security one, make sure any interesting business rules/logic is duplicated on the server side lest a user bypasses needed logic and does something silly, or worse, costly.

#### Avoid writing serialization code

This is hard and even a small mistake can cause large security issues. There are already a lot of frameworks to provide this functionality.

Take a look at the [JSON page](http://www.json.org/) for links.

#### Avoid building XML or JSON dynamically

Just like building HTML or SQL you will cause XML injection bugs, so stay away from this or at least use an encoding library or safe JSON or XML library to make attributes and element data safe.

- [XSS (Cross Site Scripting) Prevention](Cross_Site_Scripting_Prevention_Cheat_Sheet.md)
- [SQL Injection Prevention](SQL_Injection_Prevention_Cheat_Sheet.md)

#### Never transmit secrets to the client

Anything the client knows the user will also know, so keep all that secret stuff on the server please.

#### Don't perform encryption in client side code

Use TLS/SSL and encrypt on the server!

#### Don't perform security impacting logic on client side

This is the overall one that gets me out of trouble in case I missed something :)

### Server Side

#### Use CSRF Protection

Take a look at the [Cross-Site Request Forgery (CSRF) Prevention](Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md) cheat sheet.

#### Protect against JSON Hijacking for Older Browsers

##### Review AngularJS JSON Hijacking Defense Mechanism

See the [JSON Vulnerability Protection](https://docs.angularjs.org/api/ng/service/$http#json-vulnerability-protection) section of the AngularJS documentation.

##### Always return JSON with an Object on the outside

Always have the outside primitive be an object for JSON strings:

**Exploitable:**

```json
[{"object": "inside an array"}]
```

**Not exploitable:**

```json
{"object": "not inside an array"}
```

**Also not exploitable:**

```json
{"result": [{"object": "inside an array"}]}
```

#### Avoid writing serialization code Server Side

Remember ref vs. value types! Look for an existing library that has been reviewed.

#### Services can be called by users directly

Even though you only expect your AJAX client side code to call those services the users can too.

Make sure you validate inputs and treat them like they are under user control (because they are!).

#### Avoid building XML or JSON by hand, use the framework

Use the framework and be safe, do it by hand and have security issues.

#### Use JSON And XML Schema for Webservices

You need to use a third-party library to validate web services.
