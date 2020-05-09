# Introduction

This article brings forth a way to integrate the `defense in depth` concept to the client-side of web applications. By injecting the Content-Security-Policy (CSP) headers from the server, the browser is aware and capable of protecting the user from dynamic calls that will load content into the page currently being visited.

# Context

The increase in XSS and clickjacking vulnerabilities demands a more `defense in depth` security approach. CSP comes in place to enforce the loading of resources (scripts, images, etc.) from restricted locations that are trusted by the server, as well as enforcing HTTPS usage transparently. Moreover, the developer will get more visibility on the attacks occurring on the application by using the CSP reporting directive.

# Defense in Depth

A strong CSP provides an effective second layer of protection against various types of vulnerabilities, including XSS. Although it may not be possible to fully mitigate these issues, a CSP can make it significantly harder for an attacker to actually exploit them.

Even on a fully static website, which does not accept any user input, a CSP can be used to enforce the use of [Subresource Integrity (SRI)](https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity). This can help prevent malicious code being loaded on the website if one of the third party sites hosting JavaScript files (such as analytics scripts) is compromised.

However, CSP **should not** be relied upon as the only defensive mechanism on a website. It is still vital that other protective controls are implemented, such as those discussed in the [Cross-Site Scripting Prevention Cheat Sheet](Cross_Site_Scripting_Prevention_Cheat_Sheet.md).

# Policy Delivery

CSP can be delivered to the user agent in different techniques.
1. `Content-Security-Policy` HTTP response header field. This is the most preferred technique.
1. `<meta>` HTML element with `http-equiv` attribute set to `Content-Security-Policy`. These elements need to be placed as early as possible in the documents.
1. `Content-Security-Policy-Report-Only` HTTP response header field. This header is used when the developer is unsure of the CSP behavior and wants to monitor it, instead of enforcing it.

## HTTP Headers

The following are headers for CSP.

- `Content-Security-Policy` : W3C Spec standard header. Supported by Firefox 23+, Chrome 25+ and Opera 19+
- `Content-Security-Policy-Report-Only` : W3C Spec standard header. Supported by Firefox 23+, Chrome 25+ and Opera 19+, whereby the policy is non-blocking ("fail open") and a report is sent to the URL designated by the `report-uri` directive. This is often used as a precursor to utilizing CSP in blocking mode ("fail closed")
- `DO NOT` use X-Content-Security-Policy or X-WebKit-CSP. Their implementations are obsolete (since Firefox 23, Chrome 25), limited, inconsistent, and incredibly buggy.

# CSP Directives

Multiple types of directives exist that allow the developer to granularly control the flow of the policies.

## Fetch Directives

Fetch directives tell the browser the locations to trust and load resources from.

Most fetch directives have a certain [fallback list specified in w3](https://www.w3.org/TR/CSP3/#directive-fallback-list). This list allows for granular control of the source of scripts, images, files, etc. 

- `child-src` allows the developer to control nested browsing contexts and worker execution contexts.
  - According to [MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy#Fetch_directives), the below 2 directives should be used to regulate nested browsing context and workers as `child-src` will be deprecated in the coming versions.
  - `frame-src` specifies the URLs which can be loaded into nested browsing contexts (*e.g.* `<iframe>`).
  - `worker-src` specifies the URLs which can be loaded as worker, sharedworker, or serviceworker. Fallback's on `script-src` too.
- `connect-src` provides control over fetch requests, XHR, eventsource, beacon and websockets connections.
- `font-src` specifies which URLs to load fonts from.
- `img-src` specifies the URLs that images can be loaded from.
- `manifest-src` specifies the URLs that application manifests may be loaded from.
- `media-src` specifies the URLs from which video, audio and text track resources can be loaded from.
- `prefetch-src` specifies the URLs from which resources can be prefetched from.
- `object-src` specifies the URLs from which plugins can be loaded from.
- `script-src` specifies the locations from which a script can be executed from. It is a fallback directive for other script-like directives.
  - `script-src-elem` controls the location from which execution of script requests and blocks can occur.
  - `script-src-attr` controls the execution of event handlers.
- `style-src` controls from where styles get applied to a document. This includes `<link>` elements, `@import` rules, and requests originating from a `Link` HTTP response header field.
  - `style-src-elem` controls styles except for inline attributes.
  - `style-src-attr` controls styles attributes.
- `default-src` is a fallback directive for the other fetch directives. Directives that are specified have no inheritance, yet directives that are not specified will fall back to the value of `default-src`.

## Document Directives

Document directives instruct the browser about the properties of the document to which the policies will apply to. 

- `base-uri` specifies the possible URLs that the `<base>` element can use.
- `plugin-types` limits the types of resources that can be loaded into the document (*e.g.* application/pdf). 3 rules apply to the affected elements, `<embed>` and `<object>`:
  - The element needs to explicitly declare its type.
  - The element's type needs to match the declared type.
  - The element's resource need to match the declared type.
- `sandbox` restricts a page's actions such as submitting forms.
  - Only applies when used with the request header `Content-Security-Policy`.
  - Not specifying a value for the directive activates all of the sandbox restrictions. `Content-Security-Policy: sandbox;`
  - [Sandbox syntax](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/sandbox#Syntax)

## Navigation Directives

Navigation directives instruct the browser about the locations that the document can navigate to.

- `navigate-to` restricts the URLs which a document can navigate to by any mean.
- `form-action` restricts the URLs which the forms can submit to.
- `frame-ancestors` restricts the URLs that can embed the requested resource inside of  `<frame>`, `<iframe>`, `<object>`, `<embed>`, or `<applet>` elements.
  - If this directive is specified in a `<meta>` tag, the directive is ignored.
  - This directive doesn't fallback to `default-src` directive.
  - `X-Frame-Options` is rendered obsolete by this directive and is ignored by the user agents.

## Reporting Directives

Reporting directives deliver violations of prevented behaviors to specified locations. These directives serve no purpose on their own and are dependent on other directives.

- `report-to` which is a groupname defined in the header in a json formatted header value.
  - [MDN report-to documentation](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/report-to)
- `report-uri` directive is deprecated by `report-to`, which is a URI that the reports are sent to.
  - Goes by the format of: `Content-Security-Policy: report-uri https://example.com/csp-reports`

In order to ensure backward compatibility, use the 2 directives in conjunction. Whenever a browser supports `report-to`, it will ignore `report-uri`. Otherwise, `report-uri` will be used.

## Special Directive Sources

| Value            | Description                                                                 |
|------------------|-----------------------------------------------------------------------------|
| 'none'           | No URLs match.                                                              |
| 'self'           | Refers to the origin site with the same scheme and port number.             |
| 'unsafe-inline'  | Allows the usage of inline scripts or styles.                               |
| 'unsafe-eval'    | Allows the usage of eval in scripts.                                        |
| 'strict-dynamic' | Informs the browser to trust scripts originating from a root trusted script.|

*Note:* `strict-dynamic` is not a standalone directive and should be used in combination with other directive values, such as `nonce`, `hashes`, etc.

In case where the developer needs to use inline scripts, it's recommended to use `hashes` for static scripts or a `nonce` on every page request.

To create hashes, check out this [hash generator](https://report-uri.com/home/hash). This is a great [example](https://csp.withgoogle.com/docs/faq.html#static-content) of using hashes.

To better understand how the directive sources work, check out the [source lists from w3c](https://w3c.github.io/webappsec-csp/#framework-directive-source-list).

## Nonces

[Nonces](https://en.wikipedia.org/wiki/Cryptographic_nonce) attributes are added to script tags. Nonce attributes are composed of base64 values. This nonce is verified against the nonce sent in the CSP header, and only matching nonces are allowed to execute.

They can be used in dynamic script blocks in combination with `strict-dynamic`. If the script block is creating additional DOM elements and executing JS inside of them, `strict-dynamic` tells the browser to trust those elements.

For more details on strict-dynamic, check out [strict-dynamic usage](https://w3c.github.io/webappsec-csp/#strict-dynamic-usage).

# CSP Sample Policies

## Basic CSP Policy

This policy will only allow resources from the originating domain for all the default level directives and will not allow inline scripts/styles to execute. If your application functions with these restrictions, it drastically reduces your attack surface, and works with most modern browsers.

The most basic policy assumes:

- All resources are hosted by the same domain of the document.
- There are no inlines or evals for scripts and style resources.

> `Content-Security-Policy: default-src 'self';`

To tighten further, one can apply the following:

> `Content-Security-Policy: default-src 'none'; script-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self';`

This policy allows images, scripts, AJAX, and CSS from the same origin, and does not allow any other resources to load (eg. object, frame, media, etc).

## Mixed Content Policy

- In order to prevent mixed content (resources being loaded over http, from a document loaded over https), one can use the [block-all-mixed-content](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/block-all-mixed-content) directive to block mixed content.

  - `Content-Security-Policy: block-all-mixed-content;`

- On the other hand, if the developer is migrating from HTTP to HTTPS, the following directive will ensure that all requests will be sent over HTTPS with no fallback to HTTP:

  - `Content-Security-Policy: upgrade-insecure-requests;`

If the [upgrade-insecure-requests](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/upgrade-insecure-requests) is set, the `block-all-mixed-content` is rendered meaningless and should be removed.

## Preventing ClickJacking

- To prevent all framing of your content use:
  - `Content-Security-Policy: frame-ancestors 'none';`
- To allow for the site itself, use:
  - `Content-Security-Policy: frame-ancestors 'self';`
- To allow for trusted domain, do the following:
  - `Content-Security-Policy: frame-ancestors trusted.com;`

## Strict Policy

A strict policy's role is to protect against classical stored, reflected, and some of the DOM XSS attacks and should be the optimal goal of any team trying to implement CSP.

Google went ahead and set up a [guide](https://csp.withgoogle.com/docs/strict-csp.html) to adopt a strict CSP based on nonces.

Based on a [presentation](https://speakerdeck.com/lweichselbaum/csp-a-successful-mess-between-hardening-and-mitigation?slide=55) at LocoMocoSec, the following two policies can be used to apply a strict policy:

- Moderate Strict Policy:

```
script-src 'nonce-r4nd0m' 'strict-dynamic';
object-src 'none'; base-uri 'none';
```

- Locked down Strict Policy:

```
script-src 'nonce-r4nd0m';
object-src 'none'; base-uri 'none';
```

## Refactoring inline code

By default CSP disables any unsigned JavaScript code placed inline in the HTML source, such as this:

```javascript
<script>
var foo = "314"
<script>
```

The inline code can be enabled by **specifying its SHA256 hash** in the CSP header:

> `Content-Security-Policy: script-src 'sha256-gPMJwWBMWDx0Cm7ZygJKZIU2vZpiYvzUQjl5Rh37hKs=';`

This particular script's hash can be calculated using the following command:

> `echo -n 'var foo = "314"' | openssl sha256 -binary | openssl base64`

Some browsers (e.g. Chrome) will also display the hash of the script in JavaScript console warning when blocking an unsigned script.

The inline code can be also simply moved to a separate JavaScript file and the code in the page becomes:

```javascript
<script src="app.js">
</script>
```

with `app.js` containing the `var foo = "314"` code.

The inline code restriction also applies to `inline event handlers`, so that the following construct will be blocked under CSP:

> `<button id="button1" onclick="doSomething()">`

This should be replaced by `addEventListener` calls:

> `document.getElementById("button1").addEventListener('click', doSomething);`

# References

- [CSP with Google](https://csp.withgoogle.com/docs/index.html)
- [CSP Level 3 W3C](https://www.w3.org/TR/CSP3/)
- [Content-Security-Policy](https://content-security-policy.com/)
- [MDN CSP](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy)
- [CSP CheatSheet by Scott Helme](https://scotthelme.co.uk/csp-cheat-sheet/)
- [Breaking Bad CSP](https://www.slideshare.net/LukasWeichselbaum/breaking-bad-csp)
- [CSP A Successful Mess Between Hardening And Mitigation](https://speakerdeck.com/lweichselbaum/csp-a-successful-mess-between-hardening-and-mitigation)
