---
title: Content Security Policy Cheat Sheet
permalink: /Content_Security_Policy_Cheat_Sheet/
---

Content Security Policy (CSP) is an important standard by the W3C that is aimed to prevent a broad range of content injection attacks such as cross-site scripting (XSS).

Introduction
============

Content Security Policy (CSP) is an effective "defense in depth" technique to be used against content injection attacks. It is a declarative policy that informs the user agent what are valid sources to load from.

Since, it was introduced in Firefox version 4 by Mozilla, it has been adopted as a standard, and grown in adoption and capabilities.

This document is meant to provide guidance on how to utilize CSP under a variety of situations to address a variety of concerns.

References
==========

Specifications of the CSP standard can be found the following locations:

-   Latest Revision - <https://w3c.github.io/webappsec/specs/content-security-policy/>
-   Latest Version (CSP2) - <http://www.w3.org/TR/CSP2/>
-   CSP 1.0 - <http://www.w3.org/TR/2012/CR-CSP-20121115/>

CSP Basics
==========

CSP consists of a series of directives. CSP has also evolved over two major revisions. Most browsers support 1.0, and adoption of CSP2 has been incremental.

HTTP Headers
------------

The following are headers for CSP.

-   **Content-Security-Policy** : W3C Spec standard header. Supported by Firefox 23+, Chrome 25+ and Opera 19+
-   **Content-Security-Policy-Report-Only** : W3C Spec standard header. Supported by Firefox 23+, Chrome 25+ and Opera 19+, whereby the policy is non-blocking ("fail open") and a report is sent to the URL designated by the **report-uri** directive. This is often used as a precursor to utilizing CSP in blocking mode ("fail closed")
-   **DO NOT** use X-Content-Security-Policy or X-WebKit-CSP. Their implementations are obsolete (since Firefox 23, Chrome 25), limited, inconsistent, and incredibly buggy.

Directives
----------

The following is a listing of directives, and a brief description.

### CSP 1.0 Spec

-   **connect-src** (d) - restricts which URLs the protected resource can load using script interfaces. (e.g. send() method of an XMLHttpRequest object)
-   **font-src** (d) - restricts from where the protected resource can load fonts
-   **img-src** (d) - restricts from where the protected resource can load images
-   **media-src** (d) - restricts from where the protected resource can load video, audio, and associated text tracks
-   **object-src** (d) - restricts from where the protected resource can load plugins
-   **script-src** (d) - restricts which scripts the protected resource can execute. Additional restrictions against, inline scripts, and eval. Additional directives in CSP2 for hash and nonce support
-   **style-src** (d) - restricts which styles the user may applies to the protected resource. Additional restrictions against inline and eval.
-   **default-src** - Covers any directive with *(d)*
-   **frame-src** - restricts from where the protected resource can embed frames. Note, deprecated in CSP2
-   **report-uri** - specifies a URL to which the user agent sends reports about policy violation
-   **sandbox** - specifies an HTML sandbox policy that the user agent applies to the protected resource. Optional in 1.0

### New in CSP2

-   **form-action** - retricts which URLs can be used as the action of HTML form elements
-   **frame-ancestors** - indicates whether the user agent should allow embedding the resource using a frame, iframe, object, embed or applet element, or equivalent functionality in non-HTML resources
-   **plugin-types** - restricts the set of plugins that can be invoked by the protected resource by limiting the types of resources that can be embedded
-   **base-uri** - restricts the URLs that can be used to specify the document base URL
-   **child-src** (d) - governs the creation of nested browsing contexts as well as Worker execution contexts

CSP Sample Policies
===================

Basic CSP Policy
----------------

This policy will only allow resources from the originating domain for all the default level directives, and will not allow inline scripts/styles to execute. If your application and function with these restrictions, it drastically reduces your attack surface having this policy in place, and will work with most modern browsers.

The most basic policy assumes:

-   all resources are hosted by the same domain of the document
-   there are no inlines or evals for scripts and style resources

` Content-Security-Policy: default-src 'self' `

To tighten further, one can do the following:

`Content-Security-Policy: default-src 'none'; script-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self';`

This policy allows images, scripts, AJAX, and CSS from the same origin, and does not allow any other resources to load (eg. object, frame, media, etc). (see <http://content-security-policy.com/>)

Mixed Content Policy
--------------------

In order to prevent mixed content (resources being loaded over http, from a document loaded over https), one can use the value "https:" as a directive value.

For instance:

`Content-Security-Policy: default-src https:; connect-src https:; font-src https: data:; frame-src https:; `
`img-src https: data:; media-src https:;  object-src https:; script-src 'unsafe-inline' 'unsafe-eval' https:; `
`style-src 'unsafe-inline' https:;`

This is what was used at Twitter, Oct 2014. The policy prevents mixed content, allows for scheme "data:" in font-src and img-src, allows for unsafe-inline and unsafe-eval for script-src, and unsafe-inline for style-src. (see: <https://twittercommunity.com/t/blocking-mixed-content-with-content-security-policy/26375>)

Mixed Content has two categories: Active and Passive. Passive content consists of "resources which cannot directly interact with or modify other resources on a page: images, fonts, audio, and video for example", whereas active content is "content which can in some way directly manipulate the resource with which a user is interacting." (http://www.w3.org/TR/2014/WD-mixed-content-20140722)

`Content-Security-Policy: img-src https: data:; font-src https: data:; media-src https:;`

This is an example to block only passive mixed content.

`Content-Security-Policy: script-src https:; style-src https:; object-src https:; connect-src https:; frame-src https:; `

This is an example to block only active mixed content.

Preventing Clickjacking
-----------------------

The established way of preventing clickjacking involves the use of the header `X-Frame-Options` (see: [Clickjacking_Defense_Cheat_Sheet](/Clickjacking_Defense_Cheat_Sheet "wikilink")). However, CSP 2.0 has a new directive `frame-ancestors`.

To prevent all framing of your content use:

`Content-Security-Policy: frame-ancestors 'none'`

To allow for your site only, use:

`Content-Security-Policy: frame-ancestors 'self'`

To allow for trusted domain (my-trusty-site.com), do the following:

`Content-Security-Policy: frame-ancestors my-trusty-site.com `

A word about support. Not supported in all browsers yet, Chrome 40+ and FF 35+ support, but will also default to X-Frame-Options if it exists. Spec says, CSP should take precedence. <https://w3c.github.io/webappsec/specs/content-security-policy/#frame-ancestors-and-frame-options>

Also, keep in mind the following (from the [CSP Spec](https://w3c.github.io/webappsec/specs/content-security-policy/#frame-ancestors-and-frame-options)):

`The frame-ancestors directive MUST be ignored when monitoring a policy, and when a contained in a policy defined via a meta element.`

In otherwords, this will not work when CSP is in a <meta> tag, and will not work when using Content-Security-Policy-Report-Only.

When a report is generated, the blocked-uri will only have a value if it is the same origin as the page.

Refactoring inline code
=======================

By default CSP disables any unsigned JavaScript code placed inline in the HTML source, such as this:

<script>
var foo = "314"

<script>
The inline code can be enabled by **specifying its SHA256 hash** in the CSP header:

`    Content-Security-Policy: script-src 'sha256-gPMJwWBMWDx0Cm7ZygJKZIU2vZpiYvzUQjl5Rh37hKs='`

This particular script's hash can be calculated using the following command:

`   echo -n 'var foo = "314"' \| openssl sha256 -binary \| openssl base64`

Some browsers (e.g. Chrome) will also display the hash of the script in JavaScript console warning when blocking an unsigned script.

The inline code can be also simply moved to a separate JavaScript file:

<script>
var foo = "314"

<script>
becomes:

<script src="app.js">
</script>
with \`app.js\` containing the \`var foo = "314"\` code.

The inline code restriction also applies to **inline event handlers**, so that the following construct will be blocked under CSP:

`   `<button id="button1" onclick="doSomething()">

This should be replaced by \`addEventListener' calls:

`   document.getElementById("button1").addEventListener('click', doSomething);`

Variable assignment in inline scripts. Rather than do this:

<script>
var foo = "314";

<script>
Leverage HTML5's custom data attributes by setting the value as follows:

`<body data-foo="314”>`
`   ...`

</body>
And access the value by doing:

`  var itemID = document.body.getAttribute("data-foo”);`

Authors and Primary Editors
===========================

-   Neil Mattatall - neil\[at\]owasp.org
-   Denis Mello - ddtaxe
-   Boris Chen

Other Cheatsheets
=================

[Category:Cheatsheets](/Category:Cheatsheets "wikilink")