# AJAX Security Cheat Sheet

## Introduction

This document will provide a starting point for AJAX security and will hopefully be updated and expanded reasonably often to provide more detailed information about specific frameworks and technologies.

### Client-Side (JavaScript)

#### Use of `innerHTML` with extreme caution

Manipulating the Document Object Model (DOM) is common in web applications, especially in monolithic server-side rendering (e.g., PHP, ASP.NET) and Ajax-driven applications. While `innerHTML` seems like a convenient way to inject HTML content, but it poses significant security risks on untrusted-data, particularly cross-site scripting (XSS).

##### What is `innerHTML`?
The `innerHTML` property sets or gets the HTML content of an element, including tags, which the browser parses and renders as part of the DOM. For example, setting `innerHTML = "<p>Hello</p>"` creates a paragraph element.

##### Why `innerHTML` requires extreme cautions?
Using `innerHTML` with untrusted data (e.g., from API responses in Ajax ) allows malicious JavaScript to execute in the user’s browser, leading to XSS vulnerabilities. Potential risks include:
- Stealing user session cookies.
- Defacing the website.
- Redirecting users to malicious sites.
- Performing unauthorized actions (e.g., API calls on behalf of the user).

###### Vulnerable Example 
```javascript
    document.getElementById('content').innerHTML = data; 
    // DANGER! The server returned a payload that executes scripts, for example: <img src=abc onerror=alert('xss!')>.
```

##### When `innerHTML` is acceptable?
The fundamental security rule is to never use innerHTML with untrusted data. However, in limited cases, such as legacy monolithic applications with no viable alternatives, innerHTML may be used cautiously:
* **Static, Hardcoded HTML**: For small, fixed HTML snippets that are part of your application’s source code and contain no user input:
```javascript
document.getElementById('footer').innerHTML = '<p>© 2025 My Company. All rights reserved.</p>';
```
* **Sanitized HTML**: For user-generated HTML (e.g., in rich text editors), sanitize with a library like [DOMPurify ](https://cheatsheetseries.owasp.org/cheatsheets/DOM_Clobbering_Prevention_Cheat_Sheet.html#1-html-sanitization)before using innerHTML:
```javascript
import DOMPurify from 'dompurify';
const userInput = '<img src=abc onerror=alert("xss")>';
document.getElementById('content').innerHTML = DOMPurify.sanitize(userInput); // Safe, removes malicious code
```
##### Alternatives:
* Use Templating Engines (with auto-escaping) for reusable, structured HTML snippets.
* Use Modern Frameworks (React, Vue, Angular, Svelte) for complex applications. They standardize DOM manipulation, provide reactivity, and inherently handle sanitization for dynamic data. However, developers must avoid unsafe APIs (e.g., dangerouslySetInnerHTML in React,[innerHTML] in Angular) to prevent XSS vulnerabilities.



#### Don't use `eval()`, `new Function()` or other code evaluation tools

`eval()` function is evil, never use it. Needing to use eval() usually indicates a problem in your design.

#### Encode Data Before Use in an Output Context

When using data to build HTML, script, CSS, XML, JSON, etc., make sure you take into account how that data must be presented in a literal sense to keep its logical meaning.

Data should be properly encoded before used in this manner to prevent injection style issues, and to make sure the logical meaning is preserved.

[Check out the OWASP Java Encoder Project.](https://owasp.org/www-project-java-encoder/)

#### Don't rely on client logic for security

Don't forget that the user controls the client-side logic. A number of browser plugins are available to set breakpoints, skip code, change values, etc. Never rely on client logic for security.

#### Don't rely on client business logic

Just like the security one, make sure any interesting business rules/logic is duplicated on the server-side lest a user bypass this logic, leading to unexpected or costly behavior.

#### Avoid writing serialization code

This is hard and even a small mistake can cause large security issues. There are already a lot of frameworks to provide this functionality.

Take a look at the [JSON page](http://www.json.org/) for links.

#### Avoid building XML or JSON dynamically

Just like building HTML or SQL you will cause XML injection bugs, so stay away from this or at least use an encoding library or safe JSON or XML library to make attributes and element data safe.

- [XSS (Cross Site Scripting) Prevention](Cross_Site_Scripting_Prevention_Cheat_Sheet.md)
- [SQL Injection Prevention](SQL_Injection_Prevention_Cheat_Sheet.md)

#### Never transmit secrets to the client

Anything the client knows the user will also know, so keep all that secret stuff on the server please.

#### Don't perform encryption in client-side code

Use TLS/SSL and encrypt on the server!

#### Don't perform security impacting logic on client-side

This principle serves as a fail-safe—if a security decision is ambiguous, default to performing it on the server.

### Server-Side

#### Use CSRF Protection

Take a look at the [Cross-Site Request Forgery (CSRF) Prevention](Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md) cheat sheet.

#### Protect against JSON hijacking for older browsers

##### Review AngularJS JSON hijacking defense mechanism

See the [JSON Vulnerability Protection](https://docs.angularjs.org/api/ng/service/$http#json-vulnerability-protection) section of the AngularJS documentation.

##### Always return JSON with an object on the outside

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

#### Avoid writing serialization code server-side

Remember ref vs. value types! Look for an existing library that has been reviewed.

#### Services can be called by users directly

Even though you only expect your AJAX client-side code to call those services, a malicious user can also call them directly.

Make sure you validate inputs and treat them like they are under user control (because they are!).

#### Avoid building XML or JSON by hand, use the framework

Use the framework and be safe, do it by hand and have security issues.

#### Use JSON and XML schema for web services

You need to use a third-party library to validate web services.
