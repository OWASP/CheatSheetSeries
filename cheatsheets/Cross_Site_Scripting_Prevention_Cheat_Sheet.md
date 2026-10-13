# Cross Site Scripting Prevention Cheat Sheet

## Introduction

This cheat sheet helps developers prevent XSS vulnerabilities.

Cross-Site Scripting (XSS) is a misnomer. Originally this term was derived from early versions of the attack that were primarily focused on stealing data cross-site. Since then, the term has widened to include injection of basically any content. XSS attacks are serious and can lead to account impersonation, observing user behavior, loading external content, stealing sensitive data, and more.

**This cheatsheet contains techniques to prevent or limit the impact of XSS. Since no single technique will solve XSS, using the right combination of defensive techniques will be necessary to prevent XSS.**

## Framework Security

Fortunately, applications built with modern web frameworks have fewer XSS bugs, because these frameworks steer developers towards good security practices and help mitigate XSS by using templating, auto-escaping, and more. However, developers need to know that problems can occur if frameworks are used insecurely, such as:

- _escape hatches_ that frameworks use to directly manipulate the DOM
- React’s `dangerouslySetInnerHTML` without sanitizing the HTML
- Unvalidated URL values: [React 19 blocks `javascript:` URLs in `src` and `href`](https://react.dev/blog/2024/04/25/react-19-upgrade-guide#other-breaking-changes), but this does not replace application-specific [URL validation](#xss-prevention-rules-summary)
- Angular’s `bypassSecurityTrustAs*` functions
- Lit's `unsafeHTML` function
- Polymer's `inner-h-t-m-l` attribute and `htmlLiteral` function
- Template injection
- Out of date framework plugins or components
- and more

When you use a modern web framework, you need to know how your framework prevents XSS and where it has gaps. There will be times where you need to do something outside the protection provided by your framework, which means that Output Encoding and HTML Sanitization can be critical. OWASP will be producing framework specific cheatsheets for React, Vue, and Angular.

## XSS Defense Philosophy

For an XSS attack to succeed, an attacker must insert and execute malicious content in a webpage. XSS defense follows a source-to-sink principle: untrusted dynamic data originating from any source must not be interpreted as executable content when reaching a browser sink.

Input validation alone is insufficient to prevent XSS. While input validation ensures data conforms to expected business formats, it cannot anticipate every downstream rendering context, nor can it safely permit legitimate characters (such as `<` or `&`) required by application data. Instead, context-appropriate protection—such as output encoding, URL validation, or HTML sanitization—belongs at the point of use, applied immediately before data is passed to a sink.

Modern web frameworks automate many of these protections by default, but gaps remain when using framework bypasses or raw DOM APIs. Output encoding and HTML sanitization address those gaps.

## Output Encoding

When you need to safely display data exactly as a user types it in, output encoding is recommended. Variables should not be interpreted as code instead of text. This section covers each form of output encoding, where to use it, and when you should not use dynamic variables at all.

First, when you wish to display data as the user typed it in, start with your framework’s default output encoding protection. Automatic encoding and escaping functions are built into most frameworks.

If you’re not using a framework or need to cover gaps in the framework then you should use an output encoding library. Each variable used in the user interface should be passed through an output encoding function. A list of output encoding libraries is included in the appendix.

There are many different output encoding methods because browsers parse HTML, JS, URLs, and CSS differently. Using the wrong encoding method may introduce weaknesses or harm the functionality of your application.

### Output Encoding for “HTML Contexts”

“HTML Context” refers to inserting a variable between two basic HTML tags like a `<div>` or `<b>`. For example:

```HTML
<div> $varUnsafe </div>
```

An attacker could modify data that is rendered as `$varUnsafe`. This could lead to an attack being added to a webpage. For example:

```HTML
<div> <script>alert`1`</script> </div> // Example Attack
```

In order to add a variable to a HTML context safely to a web template, use HTML entity encoding for that variable.

Here are some examples of encoded values for specific characters:

When displaying text with JavaScript, assign it to the [`textContent` property](https://developer.mozilla.org/en-US/docs/Web/API/Node/textContent) of an ordinary element such as a `<div>`. This creates a text node without parsing HTML; it does not HTML-encode the value. Pass the original text without pre-encoding it. Do not use it for untrusted script or style content; [`HTMLScriptElement.textContent`](https://developer.mozilla.org/en-US/docs/Web/API/HTMLScriptElement/textContent) sets executable code.

```HTML
&    &amp;
<    &lt;
>    &gt;
"    &quot;
'    &#x27;
```

### Output Encoding for “HTML Attribute Contexts”

Use HTML attribute encoding for data inserted into ordinary text attributes, such as `title` or `value`. Keep element and attribute names fixed. Attributes containing URLs, CSS, HTML, or JavaScript need controls for those additional contexts.

The placeholder below represents data already encoded for a quoted HTML attribute:

```html
<input value="ENCODED DATA">
```

**Always surround attribute values with double (`"`) or single (`'`) quotation marks.** Use your framework's or library's attribute encoder to protect the surrounding quotes and other HTML syntax. Spaces do not end a quoted value, so encoding every space or every non-alphanumeric character is unnecessary. The [HTML parsing rules](https://html.spec.whatwg.org/multipage/parsing.html#attribute-value-(double-quoted)-state) distinguish quoted values from unquoted ones, where whitespace ends the value.

HTML attribute encoding alone does not protect JavaScript in an event-handler attribute: the HTML parser decodes character references before the JavaScript is interpreted. Encoding more characters as HTML entities does not remove that second context. Prefer `addEventListener()` with trusted handler functions and pass user values as data. For unavoidable legacy templates, follow the library's [documented JavaScript-in-HTML context](https://github.com/OWASP/owasp-java-encoder/blob/main/docs/contexts.md#encode-for-the-parser-that-receives-the-value) for data inside a quoted JavaScript string within a quoted HTML attribute; an encoder cannot make untrusted handler code safe.

When updating an existing element from JavaScript, `element.setAttribute("title", value)` assigns the value directly; it does not HTML-encode it. Do not pre-encode a runtime value for this ordinary text attribute. Keep the attribute name fixed and safe: [event-handler attributes and `srcdoc` can interpret their values as code or HTML](https://developer.mozilla.org/en-US/docs/Web/API/Element/setAttribute#security_considerations).

### Output Encoding for “JavaScript Contexts”

When a server template inserts string data into an inline script, use an encoder documented for both the JavaScript string and the enclosing HTML script. The placeholder below represents data already encoded for that location; the template supplies the quotes:

```html
<script>const message = "ENCODED DATA";</script>
```

Do not insert untrusted code, identifiers, or expressions. Use a maintained encoder and follow its context contract instead of escaping quotes manually or applying a generic `\xHH` rule. The [OWASP Java Encoder context guide](https://github.com/OWASP/owasp-java-encoder/blob/main/docs/contexts.md#encode-for-the-parser-that-receives-the-value) distinguishes script blocks, quoted event-handler strings, and standalone JavaScript. Support for ordinary template literals depends on the library and version; it does not imply support for tagged templates or `${...}` expression bodies.

These encoders protect string placement, not subsequent use: passing the resulting value to `eval()` or another code-interpreting sink remains unsafe.

For JSON, verify that the `Content-Type` header is `application/json` and not `text/html` to prevent XSS.

### Output Encoding for “CSS Contexts”

“CSS Contexts” refer to variables placed into inline CSS, which is common when developers want their users to customize the look and feel of their webpages. Since CSS is surprisingly powerful, it has been used for many types of attacks, including [CSS injection](https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/11-Client-side_Testing/05-Testing_for_CSS_Injection/) and [data exfiltration](https://portswigger.net/research/blind-css-exfiltration).

Placing variables only in a CSS property value is **not** sufficient on its own: without strict constraints, an attacker can break out of a property value (for example, with `; }` under [CSS syntax rules](https://www.w3.org/TR/css-syntax-3/#syntax-description)) to inject arbitrary rules or declaration blocks. To safely handle dynamic CSS:

- **Keep property names fixed.** Never allow untrusted data to define CSS property names or selectors.
- **Reject arbitrary CSS input and declaration blocks.** Do not allow users to supply entire CSS rule sets, declaration blocks, or arbitrary style strings.
- **Use strict, property-specific validation or allowlisting.** Restrict values to safe, expected formats (such as numeric values with fixed units or allowlisted color names and hex codes).
- **Validate URLs strictly.** Properties that accept a URL (such as `background-image`) load external resources rather than executing script. To prevent unauthorized external resource requests, strictly validate URLs and constrain allowed schemes (such as `https:`) and origins using an application allowlist.

```HTML
<style> selector { property : $varValidated; } </style>
<span style="property : $varValidated">Safe text</span>
```

When changing styles with JavaScript, use a fixed property such as `element.style.color` with a value from an application-defined allowlist. [CSS property assignment](https://developer.mozilla.org/en-US/docs/Web/API/CSSStyleDeclaration/setProperty) sets a CSS value; it does not automatically CSS-encode it. Do not let untrusted input choose the property or supply an entire declaration block. Properties that accept URLs require URL validation as well.

### Output Encoding for “URL Contexts”

“URL Contexts” refer to variables placed into a URL. Most commonly, a developer will add a parameter or URL fragment to a URL base that is then displayed or used in some operation. Use URL Encoding for these scenarios.

```HTML
<a href="http://www.owasp.org?test=$varUnsafe">link</a >
```

Encode all characters with the `%HH` encoding format. Make sure any attributes are fully quoted, same as JS and CSS.

#### Common Mistake

There will be situations where you use a URL in different contexts. The most common one would be adding it to an `href` or `src` attribute of an `<a>` tag. In these scenarios, you should do URL encoding, followed by HTML attribute encoding.

```HTML
url = "https://site.com?data=" + urlencode(parameter)
<a href='attributeEncode(url)'>link</a>
```

When using JavaScript to construct a URL, use [`encodeURIComponent()`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/encodeURIComponent) to encode each untrusted query parameter value. It encodes a URL component; it does not validate a complete URL.

[Base64url](https://www.rfc-editor.org/rfc/rfc4648.html#section-5) represents bytes using a URL-safe alphabet. Protocols such as [JSON Web Tokens (JWTs)](JSON_Web_Token_Cheat_Sheet.md) use an [unpadded form](https://www.rfc-editor.org/rfc/rfc7515.html#section-2) that `encodeURIComponent()` leaves unchanged. Use base64url only when the receiver expects it. After decoding, apply the output encoding or sanitization required by the destination context.

### Dangerous Contexts

Output encoding is not perfect. It will not always prevent XSS. These locations are known as **dangerous contexts**. Dangerous contexts include:

```HTML
<script>Directly in a script</script>
<!-- Inside an HTML comment -->
<style>Directly in CSS</style>
<div ToDefineAnAttribute=test />
<ToDefineATag href="/test" />
```

Other areas to be careful with include:

- Callback functions
- Where URLs are handled in code such as this CSS { background-url : “javascript:alert(xss)”; }
- Untrusted JavaScript event-handler code (for example, an entire `onclick` value). Prefer trusted functions registered with `addEventListener()`; see the HTML Attribute Contexts section for legacy string interpolation.
- Unsafe JS functions like `eval()`, `setInterval()`, `setTimeout()`

Don't place variables into dangerous contexts as even with output encoding, it will not prevent an XSS attack fully.

## HTML Sanitization

When users need to author HTML, developers may let users change the styling or structure of content inside a WYSIWYG editor. Output encoding in this case will prevent XSS, but it will break the intended functionality of the application. The styling will not be rendered. In these cases, HTML Sanitization should be used.

HTML Sanitization will strip dangerous HTML from a variable and return a safe string of HTML. OWASP recommends [DOMPurify](https://github.com/cure53/DOMPurify) for HTML Sanitization.

```js
let clean = DOMPurify.sanitize(dirty);
```

There are some further things to consider:

- If you sanitize content and then modify it afterwards, you can easily void your security efforts.
- If you sanitize content and then send it to a library for use, check that it doesn’t mutate that string somehow. Otherwise, again, your security efforts are void.
- You must regularly patch DOMPurify or other HTML Sanitization libraries that you use. Browsers change functionality and bypasses are being discovered regularly.

## Safe Sinks

Security professionals often talk in terms of sources and sinks. If you pollute a river, it'll flow downstream somewhere. It’s the same with computer security. XSS sinks are places where variables are placed into your webpage.

Thankfully, many sinks where variables can be placed are safe. This is because these sinks treat the variable as text and will never execute it. Try to refactor your code to remove references to unsafe sinks like innerHTML, and instead use textContent or value.

```js
elem.textContent = dangerVariable;
elem.insertAdjacentText("beforeend", dangerVariable);
elem.className = dangerVariable;
elem.setAttribute(safeName, dangerVariable);
formfield.value = dangerVariable;
document.createTextNode(dangerVariable);
document.createElement(dangerVariable);
elem.innerHTML = DOMPurify.sanitize(dangerVar);
```

[`insertAdjacentText()`](https://developer.mozilla.org/en-US/docs/Web/API/Element/insertAdjacentText) requires a position and a text value. In the example, `"beforeend"` appends a text node inside the element. Use text sinks on ordinary elements, not script or style elements.

### HTML Attribute Safety

Ordinary text attributes (such as `title`, `alt`, `placeholder`, or `value` on form inputs) are safe to populate with untrusted data when properly quoted and HTML-attribute-encoded in markup, or when assigned directly via DOM properties (such as `element.setAttribute("title", value)` or `formfield.value = value`).

However, attribute contexts vary significantly, and ordinary attribute encoding is insufficient for attributes with executable or scriptable semantics:

- **URLs (`href`, `src`):** Can execute code via `javascript:` pseudoprotocols. Validate and allowlist safe protocols (such as `http:` or `https:`) before rendering.
- **Event Handlers (`onclick`, `onload`, `onerror`, etc.):** Interpret values directly as JavaScript code. Never insert untrusted dynamic data into event handler attributes; attach trusted event listener functions using `addEventListener()` instead.
- **Style Attributes (`style`):** Interpret values as CSS. Untrusted input can allow CSS injection or data exfiltration; use fixed property names and strictly allowlist or validate values rather than accepting arbitrary CSS.
- **`srcdoc` Attributes:** Interpret values as complete HTML documents within an `<iframe>`. Untrusted data must be sanitized with an HTML sanitizer before insertion.
- **Dynamic Attribute Names:** Attribute names must always be fixed and hardcoded. Allowing dynamic attribute names lets attackers inject arbitrary event handlers or dangerous attributes regardless of how the attribute value is encoded.

## Other Controls

Framework Security Protections, Output Encoding, and HTML Sanitization will provide the best protection for your application. OWASP recommends these in all circumstances.

Consider adopting the following controls in addition to the above:

- Cookie Attributes - These change how JavaScript and browsers can interact with cookies. Cookie attributes try to limit the impact of an XSS attack but don’t prevent the execution of malicious content or address the root cause of the vulnerability.
- Content Security Policy - An allowlist that prevents content being loaded. It’s easy to make mistakes with the implementation so it should not be your primary defense mechanism. Use a CSP as an additional layer of defense and have a look at the [cheatsheet here](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html).
- Trusted Types - Supported across current major browsers (Chromium-based browsers such as Chrome and Edge from version 83, Firefox from version 148, and Safari from version 26, according to [MDN compatibility data](https://developer.mozilla.org/en-US/docs/Web/API/Trusted_Types_API#browser_compatibility)). Enable Trusted Types by adding `Content-Security-Policy: require-trusted-types-for 'script'`. This causes DOM XSS sinks (`innerHTML`, `outerHTML`, `document.write`, `script.src`, etc.) to reject plain strings, forcing all assignments to go through a vetted policy. If using a polyfill during rollout on unsupported browsers, distinguish API-only builds (which define types without enforcement) from enforcement-capable implementations; even enforcement polyfills monkey-patch only common DOM sinks and cannot provide equivalent coverage to native browser enforcement. Combine with a default policy that delegates to a sanitizer (such as DOMPurify) for legacy code paths.

### Controls Not Recommended as Primary XSS Mitigation

- **Web Application Firewalls (WAFs):** WAFs are **not recommended as a primary XSS mitigation**. While they can detect known attack signatures at the network perimeter, they do not fix the root cause of vulnerabilities, are regularly bypassed, and cannot reliably prevent DOM-based XSS that operates entirely within the browser.

### XSS Prevention Rules Summary

These snippets of HTML demonstrate how to render untrusted data safely in a variety of different contexts.

Data Type: String
Context: HTML Body
Code: `<span>UNTRUSTED DATA </span>`
Sample Defense: HTML Entity Encoding (rule \#1)

Data Type: String
Context: Ordinary HTML Attributes
Code: `<input type="text" name="fname" value="UNTRUSTED DATA ">`
Sample Defense: Quote the value and use HTML attribute encoding. Keep attribute names fixed and use ordinary text attributes; apply additional controls for URL, CSS, HTML, or JavaScript values.

Data Type: String
Context: GET Parameter
Code: `<a href="/site/search?value=UNTRUSTED DATA ">clickme</a>`
Sample Defense: URL Encoding (rule \#5).

Data Type: String
Context: Untrusted URL in a SRC or HREF attribute
Code: `<a href="UNTRUSTED URL ">clickme</a> <iframe src="UNTRUSTED URL " />`
Sample Defense: Canonicalize input, URL Validation, Safe URL verification, Allow-list http and HTTPS URLs only (Avoid the JavaScript Protocol to Open a new Window), Attribute encoder.

Data Type: String
Context: CSS Value
Code: `HTML <div style="width: UNTRUSTED DATA ;">Selection</div>`
Sample Defense: Strict property-specific validation or allowlisting, fixed property names, CSS hex encoding.

Data Type: String
Context: JavaScript Variable
Code: `<script>var currentValue='UNTRUSTED DATA ';</script> <script>someFunction('UNTRUSTED DATA ');</script>`
Sample Defense: Insert string data only inside a quoted string, using an encoder that also protects the enclosing HTML script context. Do not rely on quote escaping alone.

Data Type: HTML
Context: HTML Body
Code: `<div>UNTRUSTED HTML</div>`
Sample Defense: HTML validation (JSoup, AntiSamy, HTML Sanitizer...).

Data Type: String
Context: DOM XSS
Code: `<script>document.write("UNTRUSTED INPUT: " + document.location.hash );<script/>`
Sample Defense: [DOM based XSS Prevention Cheat Sheet](DOM_based_XSS_Prevention_Cheat_Sheet.md) |

### Output Encoding Rules Summary

The purpose of output encoding (as it relates to Cross Site Scripting) is to convert untrusted input into a safe form where the input is displayed as **data** to the user without executing as **code** in the browser. The following charts provides a list of critical output encoding methods needed to stop Cross Site Scripting.

Encoding Type: HTML Entity
Encoding Mechanism: Convert `&` to `&amp;`, Convert `<` to `&lt;`, Convert `>` to `&gt;`, Convert `"` to `&quot;`, Convert `'` to `&#x27`

Encoding Type: HTML Attribute Encoding
Encoding Mechanism: Use a framework or library encoder for quoted HTML text attributes and surround the value with `"` or `'`. Encoding every space or non-alphanumeric character is unnecessary. This does not validate URLs or encode JavaScript, CSS, or HTML contained in an attribute.

Encoding Type: URL Encoding
Encoding Mechanism: Use standard percent encoding, as specified in the [W3C specification](http://www.w3.org/TR/html401/interact/forms.html#h-17.13.4.1), to encode parameter values. Be cautious and only encode parameter values, not the entire URL or path fragments of a URL.

Encoding Type: JavaScript Encoding
Encoding Mechanism: Use a library encoder for JavaScript string data in the actual surrounding context. It must protect the string delimiters and, when embedded in HTML, the enclosing script or attribute. Follow the library's supported contexts; hex or Unicode escapes alone are not a substitute for that contract.

Encoding Type: CSS Hex Encoding
Encoding Mechanism: CSS encoding supports both `\XX` and `\XXXXXX` formats. To ensure proper encoding, consider these options: (a) Add a space after the CSS encode (which will be ignored by the CSS parser), or (b) use the full six-character CSS encoding format by zero-padding the value. For example, `A` becomes `\41` (short format) or `\000041` (full format). Alphanumeric characters (letters A to Z, a to z, and digits 0 to 9) remain unencoded.

## Common Anti-patterns: Ineffective Approaches to Avoid

Defending against XSS is actually quite easy in most cases: modern web frameworks encode dynamic content by default, safe DOM APIs (such as `textContent` on ordinary HTML elements, excluding `script` and `style` elements) treat untrusted input as data rather than executable code, and vetted sanitizers handle rich text. Vulnerabilities typically arise when developers bypass these defaults or seek shortcuts instead of addressing data sinks directly.

Common [anti-patterns](https://en.wikipedia.org/wiki/Anti-pattern) to avoid include:

### Sole Reliance on Content-Security-Policy (CSP)

[Content Security Policy (CSP)](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html) is an essential defense-in-depth control, but it is not a substitute for proper output encoding and sanitization:

- **Not a primary defense:** CSP restricts the execution and loading of unauthorized resources, but relying solely on CSP leaves unencoded sinks in your application code.
- **Coverage and bypass gaps:** CSP policies are complex and frequently weakened by misconfigurations, permissive directives (`unsafe-inline`, overly broad domain allowlists), or operational exceptions granted to accommodate legacy components. Additionally, older browser clients or non-browser environments may lack complete support for modern CSP directives.

### Reliance on HTTP Interceptors or Global Filters

Attempting to handle output encoding or input sanitization globally using generic HTTP request interceptors or servlet filters (such as a Spring `HandlerInterceptor` or Java EE `Filter`) fails for several fundamental reasons:

- **Context blindness:** Protection must be contextual. A generic filter inspecting HTTP parameters cannot know where or how a variable will eventually be rendered (for example, within an HTML element, an attribute, a JavaScript block, or a URL). HTML-encoding data in a global filter will not protect against injection into JavaScript contexts and can cause double-encoding bugs that break application functionality.
- **Ineffective against DOM-based XSS:** Global server-side interceptors only see HTTP requests and responses; they cannot inspect or protect against client-side data flows where JavaScript reads from a DOM source and writes to a DOM sink.
- **Misses secondary sources:** Untrusted data often originates outside incoming HTTP request parameters, such as from backend databases, third-party APIs, or internal microservices. An interceptor that only inspects incoming HTTP parameters will leave downstream renders of stored data unprotected.

## Related Articles

See the [XSS Filter Evasion Cheat Sheet](XSS_Filter_Evasion_Cheat_Sheet.md) for examples that illustrate why filtering alone is insufficient.

## References

- [OWASP Java Encoder: Output Contexts and Boundaries](https://github.com/OWASP/owasp-java-encoder/blob/main/docs/contexts.md#encode-for-the-parser-that-receives-the-value)
- [DOMPurify Documentation](https://github.com/cure53/DOMPurify)
