# DOM Clobbering Prevention Cheat Sheet

## Introduction

[DOM Clobbering](https://domclob.xyz/domc_wiki/#overview) is a type of code-reuse, HTML-only injection attack, where attackers confuse a web application by injecting HTML elements whose `id` or `name` attribute matches the name of security-sensitive variables or browser APIs, such as variables used for fetching remote content (e.g., script src), and overshadow their value.

It is particularly relevant when script injection is not possible, e.g., when filtered by HTML sanitizers, or mitigated by disallowing or controlling script execution. In these scenarios, attackers may still inject non-script HTML markups into webpages and transform the initially secure markup into executable code, achieving [Cross-Site Scripting (XSS)](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html).

**This cheat sheet is a list of guidelines, secure coding patterns, and practices to prevent or restrict the impact of DOM Clobbering in your web application.**

## Background

Before we dive into DOM Clobbering, let's refresh our knowledge with some basic Web background.

When a webpage is loaded, the browser creates a [DOM tree](https://developer.mozilla.org/en-US/docs/Web/API/Document_Object_Model/Introduction) that represents the structure and content of the page, and JavaScript code has read and write access to this tree.

When creating the DOM tree, browsers also create an attribute for (some) named HTML elements on `window` and `document` objects. Named HTML elements are those having an `id` or `name` attribute. For example, the markup:

```html
<form id=x></a>
```

will lead to browsers creating references to that form element with the attribute `x` of `window` and `document`:

```js
var obj1 = document.getElementById('x');
var obj2 = document.x;
var obj3 = document.x;
var obj4 = window.x;
var obj5 = x; // by default, objects belong to the global Window, so x is same as window.x
console.log(
 obj1 === obj2 && obj2 === obj3 &&
 obj3 === obj4 && obj4 === obj5
); // true
```

When accessing an attribute of `window` and `document` objects, named HTML element references come before lookups of built-in APIs and other attributes on `window` and `document` that developers have defined, also known as [named property accesses](https://html.spec.whatwg.org/multipage/nav-history-apis.html#named-access-on-the-window-object). Developers unaware of such behavior may use the content of window/document attributes for sensitive operations, such as URLs for fetching remote content, and attackers can exploit it by injecting markups with colliding names. Similarly to custom attributes/variables, built-in browser APIs may be overshadowed by DOM Clobbering.

If attackers are able to inject (non-script) HTML markup in the DOM tree,
it can change the value of a variable that the web application relies on due to named property accesses, causing it to malfunction, expose sensitive data, or execute attacker-controlled scripts. DOM Clobbering works by taking advantage of this (legacy) behaviour, causing a namespace collision between the execution environment (i.e., `window` and `document` objects), and JavaScript code.

### Example Attack 1

```javascript
let redirectTo = window.redirectTo || '/profile/';
location.assign(redirectTo);
```

The attacker can:

- inject the markup `<a id=redirectTo href='javascript:alert(1)'` and obtain XSS.
- inject the markup `<a id=redirectTo href='phishing.com'` and obtain open redirect.

### Example Attack 2

```javascript
var script = document.createElement('script');
let src = window.config.url || 'script.js';
s.src = src;
document.body.appendChild(s);
```

The attacker can inject the markup `<a id=config><a id=config name=url href='malicious.js'>` to load additional JavaScript code, and obtain arbitrary client-side code execution.

## Summary of Guidelines

For quick reference, below is the summary of guidelines discussed next.

|    | **Guidelines**                                                | Description                                                               |
|----|---------------------------------------------------------------|---------------------------------------------------------------------------|
| \# 1  | Use HTML Sanitizers                                           | [link](#1-html-sanitization)                                              |
| \# 2  | Use Content-Security Policy                                   | [link](#2-content-security-policy)                                        |
| \# 3  | Freeze Sensitive DOM Objects                                  | [link](#3-freezing-sensitive-dom-objects)                                 |
| \# 4  | Validate All Inputs to DOM Tree                               | [link](#4-validate-all-inputs-to-dom-tree)                                |
| \# 5  | Use Explicit Variable Declarations                            | [link](#5-use-explicit-variable-declarations)                             |
| \# 6  | Do Not Use Document and Window for Global Variables           | [link](#6-do-not-use-document-and-window-for-global-variables)            |
| \# 7  | Do Not Trust Document Built-in APIs Before Validation         | [link](#7-do-not-trust-document-built-in-apis-before-validation)          |
| \# 8  | Enforce Type Checking                                         | [link](#8-enforce-type-checking)                                          |
| \# 9  | Use Strict Mode                                               | [link](#9-use-strict-mode)                                                |
| \# 10 | Apply Browser Feature Detection                               | [link](#10-apply-browser-feature-detection)                               |
| \# 11 | Limit Variables to Local Scope                                | [link](#11-limit-variables-to-local-scope)                                |
| \# 12 | Use Unique Variable Names In Production                       | [link](#12-use-unique-variable-names-in-production)                       |
| \# 13 | Use Object-oriented Programming Techniques like Encapsulation | [link](#13-use-object-oriented-programming-techniques-like-encapsulation) |

## Mitigation Techniques

### \#1: HTML Sanitization

Robust HTML sanitizers can prevent or restrict the risk of DOM Clobbering. They can do so in multiple ways. For example:

- completely remove named properties like `id` and `name`. While effective, this may hinder the usability when named properties are needed for legitimate functionalties.
- namespace isolation, which can be, for example, prefixing the value of named properties by a constant string to limit the risk of naming collisions.
- dynamically checking if named properties of the input mark has collisions with the existing DOM tree, and if that is the case, then remove named properties of the input markup.

OWASP recommends [DOMPurify](https://github.com/cure53/DOMPurify) or the [Sanitizer API](https://developer.mozilla.org/en-US/docs/Web/API/HTML_Sanitizer_API) for HTML sanitization.

#### DOMPurify Sanitizer

By default, DOMPurify removes all clobbering collisions with **built-in** APIs and properties (using the enabled-by-default `SANITIZE_DOM` configuration option). ]

To be protected against clobbering of custom variables and properties as well, you need to enable the `SANITIZE_NAMED_PROPS` config:

```js
var clean = DOMPurify.sanitize(dirty, {SANITIZE_NAMED_PROPS: true});
```

This would isolate the namespace of named properties and JavaScript variables by prefixing them with `user-content-` string.

#### Sanitizer API

The new browser-built-in [Sanitizer API](https://developer.mozilla.org/en-US/docs/Web/API/HTML_Sanitizer_API) does not prevent DOM Clobbering it its [default setting](https://wicg.github.io/sanitizer-api/#dom-clobbering), but can be configured to remove named properties:

```js
const sanitizerInstance = new Sanitizer({
  blockAttributes: [
    {'name': 'id', elements: '*'},
    {'name': 'name', elements: '*'}
  ]
});
containerDOMElement.setHTML(input, {sanitizer: sanitizerInstance});
```

### \#2: Content-Security Policy

[Content-Security Policy (CSP)](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy) is a set of rules that tell the browser which resources are allowed to be loaded on a web page. By restricting the sources of JavaScript files (e.g., with the [script-src](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src) directive), CSP can prevent malicious code from being injected into the page.

**Note:** CSP can only mitigate **some varints** of DOM clobbering attacks, such as when attackers attempt to load new scripts by clobbering script sources, but not when already-present code can be abused for code execution, e.g., clobbering the parameters of code evaluation constructs like `eval()`.

### \#3: Freezing Sensitive DOM Objects

A simple way to mitigate DOM Clobbering against individual objects could be to freeze sensitive DOM objects and their properties, e.g., via [Object.freeze()](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/freeze) method.

**Note:** Freezing object properties prevents them from being overwritten by named DOM elements. But, determining all objects and object properties that need to be frozen may be not be easy, limiting the usefulness of this approach.

## Secure Coding Guidelines

DOM Clobbering can be avoided by defensive programming and adhering to a few coding patterns and guidelines.

### \#4: Validate All Inputs to DOM Tree

Before inserting any markup into the webpage's DOM tree, sanitize `id` and `name` attributes (see [HTML sanitization](#html-sanitization)).

### \#5: Use Explicit Variable Declarations

When initializing varibles, always use a variable declarator like `var`, `let` or `const`, which prevents clobbering of the variable.

**Note:** Declaring a variable with `let` does not create a property on `window`, unlike `var`. Therefore, `window.VARNAME` can still be clobbered (assuming `VARNAME` is the name of the variable).

### \#6: Do Not Use Document and Window for Global Variables

Avoid using objects like `document` and `window` for storing global variables, because they can be easily manipulated. (see, e.g., [here](https://domclob.xyz/domc_wiki/indicators/patterns.html#do-not-use-document-for-global-variables)).

### \#7: Do Not Trust Document Built-in APIs Before Validation

Document properties, including built-in ones, are always overshadowed by DOM Clobbering, even right after they are assigned a value.

**Hint:** This is due to the so-called [named property visibility algorithm](https://webidl.spec.whatwg.org/#legacy-platform-object-abstract-ops), where named HTML element references come before lookups of built-in APIs and other attributes on `document`.

### \#8: Enforce Type Checking

Always check the type of Document and Window properties before using them in sensitive operations, e.g., using the [instance of](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/instanceof) operator.

**Hint:** When an object is clobbered, it would refer to an [HTMLElement](https://developer.mozilla.org/en-US/docs/Web/API/HTMLElement) instance, which may not be the expected type.

### \#9: Use Strict Mode

Use `strict` mode to prevent unintended global variable creation, and to [raise an error](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Errors/Read-only) when read-only properties are attempted to be over-written.

### \#10: Apply Browser Feature Detection

Instead of relying on browser-specific features or properties, use feature detection to determine whether a feature is supported before using it. This can help prevent errors and DOM Clobbering that might arise when using those features in unsupported browsers.

**Hint:** Unsupported feature APIs can act as an undefined variable/property in unsupported browsers, making them clobberable.

### \#11: Limit Variables to Local Scope

Global variables are more prone to being overwritten by DOM Clobbering. Whenever possible, use local variables and object properties.

### \#12: Use Unique Variable Names In Production

Using unique variable names may help prevent naming collisions that could lead to accidental overwrites.

### \#13: Use Object-oriented Programming Techniques like Encapsulation

Encapsulating variables and functions within objects or classes can help prevent them from being overwritten. By making them private, they cannot be accessed from outside the object, making them less prone to DOM Clobbering.

## References

- [domclob.xyz](https://domclob.xyz)
- [PortSwigger: DOM Clobbering Strikes Back](https://portswigger.net/research/dom-clobbering-strikes-back)
- [Blogpost: XSS in GMail’s AMP4Email](https://research.securitum.com/xss-in-amp4email-dom-clobbering/)
- [HackTricks: DOM Clobbering](https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting/dom-clobbering)
- [HTMLHell: DOM Clobbering](https://www.htmhell.dev/adventcalendar/2022/12/)
