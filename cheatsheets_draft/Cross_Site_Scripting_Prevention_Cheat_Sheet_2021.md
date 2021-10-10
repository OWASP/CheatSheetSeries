# Cross Site Scripting Prevention Cheat Sheet

## Introduction

This cheat sheet provides guidance to prevent XSS vulnerabilities.

Cross-site scripting is where a hacker manipulates a website into sending malicious javascript to a victim. This allows the hacker to impersonate, take actions, and steal data. Our users need to trust that the websites they use are safe, and XSS is the most common way to break that trust.

This is a list of actions you can take to prevent XSS, or to limit the impact. No control is perfect at preventing XSS alone. Use a mix, and choose options that make sense for your business and your application. 

## Framework Security Measures

The previous version of this cheatsheet focussed on finding where user input is sent to a browser and performing contextualised output encoding.

We have come a long way since 2010. Web frameworks now do this for you. Applications built with modern frameworks tend to have significantly fewer XSS bugs introduced. Developers do not need to:

- identify application flows to secure all pathways
- consider which output encoding format is appropriate
- know about web security to write secure code

Templates like `{ { hello } }` and Framework-provided abstraction methods like `[InnerHtml]` make it difficult to introduce XSS flaws. Following these patterns is called *The Paved Road*.

When you deviate from the paved road though, that's where XSS comes up again. Unsafe methods like `DangersoulySetInnerHTML()`, writing direct HTML, or interacting with native DOM elements are ways framework protections can be bypassed. 

There will be situations where you need to deviate though. Adopting additional controls will help prevent XSS in this case. 

## Security Headers

HTTP Response Headers provide browsers with metadata about a HTTP response. There are many security headers. We will focus on ones that prevent XSS. Read the Security Header CheatSheet and the Content Security policy CheatSheet for guidance around other security headers.

### Content-Security-Policy

A Content-Security-Policy states what content is allowed and what is not. Restricting execution of inline content and javascript from domains you do not control prevents most forms of XSS. It is not easy to build a strong content-security policy. There are subtle nuances and mistakes that can be made. 

This CheatSheet outlines steps to build quickly introduce a policy and improve it. Explicit and detailed guidance is available in the OWASP CSP CheatSheet. 

**Starting with CSP**
- Start with a strict CSP policy and use report-only mode to identify violations.
- Add domains until your website functions correctly.
- Explore the different directives available.
- Create a Report URI Endpoint.

Start simple.

```js
Content-Security-Policy-Report-Only: default-src 'self'
```

Content loaded from other domains will be reported as a CSP Violation. View violations with browser developer tools. Add domains that violate the policy to your CSP. This will quickly create a CSP that won't break website functionality (hopefully) and will provide some protection. As an example, the below policy will prevent content outside of owasp.org and their subdomains from being loaded.

```js
Content-Security-Policy: default-src 'self' owasp.org *.owasp.org
```

After a basic policy has been created, review the other directives that exist. `img-src: *` may be appropriate for a meme-sharing website.

**Improving your Base CSP**
- Host content on your domain
- Restrict CSP to script, object, and base
- Refactor Inline / Eval code

Consider the following CSP...

- It has a large number of domains listed under each directive
- It contains a lot of directives
- It uses unsafe-inline and unsafe-eval

```js
content-security-policy: default-src 'self' https://api.github.com https://*.githubusercontent.com https://*.google-analytics.com https://owaspadmin.azurewebsites.net https://*.twimg.com https://platform.twitter.com https://www.youtube.com https://*.doubleclick.net; frame-ancestors 'self'; frame-src https://*.vuejs.org https://*.stripe.com https://*.wufoo.com https://*.sched.com https://*.google.com https://*.twitter.com https://www.youtube.com https://w.soundcloud.com; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://fonts.googleapis.com https://app.diagrams.net https://cdnjs.cloudflare.com https://cse.google.com https://*.vuejs.org https://*.stripe.com https://*.wufoo.com https://*.youtube.com https://*.meetup.com https://*.sched.com https://*.google-analytics.com https://unpkg.com https://buttons.github.io https://www.google.com https://*.gstatic.com https://*.twitter.com https://*.twimg.com; style-src 'self' 'unsafe-inline' https://*.gstatic.com https://cdnjs.cloudflare.com https://www.google.com https://fonts.googleapis.com https://platform.twitter.com https://*.twimg.com data:; font-src 'self' fonts.gstatic.com; manifest-src 'self' https://pay.google.com; img-src 'self' data: www.w3.org https://licensebuttons.net https://img.shields.io https://*.twitter.com https://github.githubassets.com https://*.twimg.com https://platform.twitter.com https://*.githubusercontent.com https://*.vercel.app https://*.cloudfront.net https://*.coreinfrastructure.org https://*.securityknowledgeframework.org https://badges.gitter.im https://travis-ci.org https://api.travis-ci.org https://s3.amazonaws.com https://snyk.io https://coveralls.io https://requires.io https://github.com https://*.googleapis.com https://*.google.com https://*.gstatic.com
```

Each domain listed in your CSP is a potential risk, especially Content Distribution Networks (CDN's). CDN's are problematic as anybody can host malicious content on one. In addition, having a large CSP is difficult to maintain and inflexible for development teams. If possible, look to host javascript files from your own domain, or check out strict-dynamic further down.

`script-src`, `object-src`, and `base-uri` are the most important directives for preventing XSS. Other directives have mild security benefits, but mostly bloat your policy. A bloated policy is a performance and maintenance bottleneck and makes it easier for hackers to learn about your domain.

Refactor inline code. Moving inline code into hosted files will prevent allow you to remove the unsafe-inline directive, preventing inline scripts from executing.

**Fully Mature CSP**
- Strict-Dynamic
- Nonces
- Trusted Types

A fully mature CSP uses a combination of nonces, strict-dynamic, and trusted types over domain and path allowlisting of content. The [w3 explanation](https://www.w3.org/TR/CSP3/#strict-dynamic-usage) of Strict-Dynamic and nonce based validation is clear about the benefits and implementation.

Using a trusted type requires you to process string data before passing it to one of the below dangerous DOM functions.

- `<script>` element text content and `<script src>`
- HTML generation from a string, like `document.write`, `innerHTML`, and `DOMParser.parseFromString` 
- Plugins like `<object>` 
- JavaScript code compilation like `eval` or `setTimeout`

```js
anElement.innerHTML = location.href; // Browser will not execute this as it is a string

anElement.innerHTML = aTrustedHTML; // TrustedHTML will execute as it is a safe object 
```

Trusted Types reduce the DOM XSS attack surface of your application. For detailed guidance, refer to this guide at [web dev](https://web.dev/trusted-types/).

### X-XSS-Protection

X-XSS-Protection will instruct a browser to invoke the XSS-Auditor. The XSS-Auditor would review the response for potential XSS attacks. It can be configured to block or alert on malicious content.

Hackers found methods to bypass or abuse this control. Splitting content across multiple input fields, invoking the auditor on purpose to deny website access, and preventing specific JS files from loading are all examples of why it is now deprecated across all major browsers.

If you need to support older browsers, this feature may still have value. Otherwise, sending this header does not achieve much except indicate that you may not know it has been deprecated. 

## Browser Storage

Cookies, LocalStorage, SessionStorage, the IndexedDB, and the Cache are current browser storage methods. Cookies are the only one with a feature to prevent JavaScript access. The other methods are designed for ease of use, increased storage capacity, and performance. Not necessarily security.

If you need to store an authentication token, then a cookie with the Secure, HTTPOnly, and SameSite attributes set is the best method. The HTTPOnly attribute prevents cookie data being read by JavaScript. This makes it difficult for an XSS attack to steal Authentication details. Secure means that the data can only be transmitted over a HTTPS connection, preventing someone from intercepting that request and reading the cookie data. SameSite means that data can only be submitted to the Same Origin. This prevents the sensitive information from being shared cross-origin.

In general, do not store sensitive information outside of Cookies if you are looking to reduce the impact of an XSS vulnerability. The WebCrypto API and WebWorkers are further points of research but out of scope for this CheatSheet.

## Third-Party Integrity Mechanisms

We use third-party libraries every day in our web applications. Attackers may modify the code of a library we use to compromise our systems. To verify the integrity of a library, we use the Subresource Integriy attribute. You can use the [SRI Generator](https://www.srihash.org/) to generate a hash of a javascript file.

When the browser encounters a script or link tag with an integrity attribute, it will check to see if the hash matches before executing the javascript. If it does not match, then it will return a network error and not execute the script. This protects against library tampering to malicious javascript.

```html
<script src="https://owasp.org/SRI.js"
        integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC"
        crossorigin="anonymous"></script>
```    

## Other Control Options

If the above controls are not suitable then some alernative controls include:

- Implement [DOMPurify](https://github.com/cure53/DOMPurify/tree/1.0.8) to sanitise content
- Use the Unsafe-Hashes part of a CSP to as an interim security measure
- Perform contextualised output encoding as per the old guide below
- Perform Input Validation based on exact matches, regular expressions, blocklisting characters in order of effectiveness
- Use out of band controls like Web Application Firewalls and packet inspection
- Accepting the risk!

## Related Articles

<!-- This needs to be completely refreshed down here. -->

**XSS Attack Cheat Sheet:**

The following article describes how to exploit different kinds of XSS Vulnerabilities that this article was created to help you avoid:

- OWASP: [XSS Filter Evasion Cheat Sheet](https://owasp.org/www-community/xss-filter-evasion-cheatsheet).

**Description of XSS Vulnerabilities:**

- OWASP article on [XSS](https://owasp.org/www-community/attacks/xss/) Vulnerabilities.

**Discussion on the Types of XSS Vulnerabilities:**

- [Types of Cross-Site Scripting](https://owasp.org/www-community/Types_of_Cross-Site_Scripting).

**How to Review Code for Cross-site scripting Vulnerabilities:**

- [OWASP Code Review Guide](https://owasp.org/www-project-code-review-guide/) article on [Reviewing Code for Cross-site scripting](https://wiki.owasp.org/index.php/Reviewing_Code_for_Cross-site_scripting) Vulnerabilities.

**How to Test for Cross-site scripting Vulnerabilities:**

- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/) article on [Testing for Cross site scripting](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/11-Client_Side_Testing/README.html) Vulnerabilities.
- [XSS Experimental Minimal Encoding Rules](https://wiki.owasp.org/index.php/XSS_Experimental_Minimal_Encoding_Rules)
