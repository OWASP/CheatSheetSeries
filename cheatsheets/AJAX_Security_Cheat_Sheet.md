# AJAX Security Cheat Sheet

## Introduction

This document will provide a starting point for AJAX security and will hopefully be updated and expanded reasonably often to provide more detailed information about specific frameworks and technologies.

### Client-Side (JavaScript)

#### Use `innerHTML` with extreme caution

Manipulating the Document Object Model (DOM) is common in web applications, especially in monolithic server-side rendering (e.g., PHP, ASP.NET) and AJAX-driven applications. While `innerHTML` seems like a convenient way to inject HTML content, it poses significant security risks on untrusted-data, particularly cross-site scripting (XSS).

##### What is `innerHTML`?

The `innerHTML` property sets or gets the HTML content of an element, including tags, which the browser parses and renders as part of the DOM. For example, setting `innerHTML = "<p>Hello</p>"` creates a paragraph element.

##### Why does `innerHTML` requires extreme cautions?

Using `innerHTML` with untrusted data (e.g., from API responses in AJAX) can allow malicious JavaScript to execute in the user’s browser, leading to XSS vulnerabilities. Potential risks include:

- Stealing user session cookies.
- Defacing the website.
- Redirecting users to malicious sites.
- Performing unauthorized actions (e.g., API calls on behalf of the user).

###### Vulnerable Example

```javascript
    document.getElementById('content').innerHTML = data; 
    // DANGER! The server may have returned a payload that executes scripts, for example: <img src=abc onerror=alert('xss!')>.
```

##### When is `innerHTML` acceptable?

The fundamental security rule is to never use innerHTML with untrusted data. However, in limited cases, such as legacy monolithic applications with no viable alternatives, innerHTML may be used cautiously:

- **Static, Hardcoded HTML**: For small, fixed HTML snippets that are part of your application’s source code and contain no user input:

```javascript
document.getElementById('footer').innerHTML = '<p>© 2025 My Company. All rights reserved.</p>';
```

- **Sanitized HTML**: For user-generated HTML (e.g., in rich text editors), sanitize with a library like [DOMPurify](DOM_Clobbering_Prevention_Cheat_Sheet.md#1-html-sanitization) before using innerHTML:

```javascript
import DOMPurify from 'dompurify';
const userInput = '<img src=abc onerror=alert("xss")>';
document.getElementById('content').innerHTML = DOMPurify.sanitize(userInput); // Safe, removes malicious code
```

##### Alternatives

- Use Templating Engines (with auto-escaping) for reusable, structured HTML snippets.
- Use Modern Frameworks (React, Vue, Angular, Svelte) for complex applications. They standardize DOM manipulation, provide reactivity, and inherently handle sanitization for dynamic data. However, developers must avoid unsafe APIs (e.g., `dangerouslySetInnerHTML` in React, `[innerHTML]` in Angular) to prevent XSS vulnerabilities.

#### Use of `textContent` or `innerText` for DOM updates (for text-only content)

In AJAX and monolithic server-side rendering applications (e.g., PHP, ASP.NET), dynamic Document Object Model (DOM) updates are common for rendering text-only content from APIs or user inputs.

##### What is `textContent`?

The `textContent` property sets or gets the plain text content of an element. It treats inserted HTML tags as literal text and does not parse them. It is ideal for most text-only updates, such as displaying user comments, etc.

```javascript
const userInput = '<script>alert("OWASP")</script>';
document.getElementById('content').textContent = userInput; // Displays plain text
```

##### What is `innerText`?

The `innerText` property sets or gets the visible text content of an element, respecting CSS styling (e.g., ignoring text in `display: none` elements). It also reflects rendered text formatting, such as line breaks or spacing.

```javascript
const userInput = 'OWASP'; 
document.getElementById('content').innerText = userInput;
```

##### When to Use `textContent` vs. `innerText`

- **Use `textContent`**: Use textContent in monolithic applications to safely insert plain text content returned from APIs.
- **Use `innerText`**: Only when CSS visibility or rendered text formatting (e.g. ignoring text in `display: none` elements) is required.

##### Note

- While `textContent` and `innerText` are safe for inserting plain text into the DOM, they do not protect against XSS in other contexts such as HTML attributes, JavaScript event handlers, or URLs. Always validate and sanitize untrusted input.
- Modern Frameworks like React, Vue, Angular, or Svelte automatically update text-only content so there is no need to manually use `textContent` or `innerText`.

#### Don't use `eval()`, `new Function()` or other code evaluation tools

`eval()` function is dangerous, never use it. Needing to use eval() usually indicates a problem in your design.

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

Refer to the [JSON page](https://www.json.org/) for more info.

#### Avoid building XML or JSON dynamically

Just like building HTML or SQL you may cause XML injection bugs, so stay away from this or at least use an encoding library or safe JSON or XML library to make attributes and element data safe.

- [XSS (Cross Site Scripting) Prevention](Cross_Site_Scripting_Prevention_Cheat_Sheet.md)
- [SQL Injection Prevention](SQL_Injection_Prevention_Cheat_Sheet.md)

#### Never transmit secrets to the client

Anything sent to the client can be read or modified by the user, so keep all that secret stuff on the server please.

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
