---
title: HTTP Strict Transport Security Cheat Sheet
permalink: /HTTP_Strict_Transport_Security_Cheat_Sheet/
---

`__NOTOC__`

<div style="width:100%;height:160px;border:0,margin:0;overflow: hidden;">
[link=](/File:Cheatsheets-header.jpg\ "wikilink")

</div>
{\\| style="padding: 0;margin:0;margin-top:10px;text-align:left;" \\|- \\| valign="top" style="border-right: 1px dotted gray;padding-right:25px;" \\| Last revision (mm/dd/yy): **//**

`__TOC__`

Introduction
============

HTTP Strict Transport Security (HSTS) is an opt-in security enhancement that is specified by a web application through the use of a special response header. Once a supported browser receives this header that browser will prevent any communications from being sent over HTTP to the specified domain and will instead send all communications over HTTPS. It also prevents HTTPS click through prompts on browsers.

The specification has been released and published end of 2012 as RFC 6797 (HTTP Strict Transport Security (HSTS)) by the IETF. (Reference see in the links at the bottom.)

Threats
-------

HSTS addresses the following threats:

-   User bookmarks or manually types <http://example.com> and is subject to a man-in-the-middle attacker
    -   HSTS automatically redirects HTTP requests to HTTPS for the target domain
-   Web application that is intended to be purely HTTPS inadvertently contains HTTP links or serves content over HTTP
    -   HSTS automatically redirects HTTP requests to HTTPS for the target domain
-   A man-in-the-middle attacker attempts to intercept traffic from a victim user using an invalid certificate and hopes the user will accept the bad certificate
    -   HSTS does not allow a user to override the invalid certificate message

Examples
--------

Simple example, using a long (1 year) max-age. This example is dangerous since it lacks <i>includeSubDomains</i>.

` Strict-Transport-Security: max-age=31536000`

This example is useful if all present and future subdomains will be HTTPS. This is a more secure option but will block access to certain pages that can only be served over HTTP.

` Strict-Transport-Security: max-age=31536000; includeSubDomains`

This example is useful if all present and future subdomains will be HTTPS. In this example we set a very short max-age in case of mistakes during initial rollout.

` Strict-Transport-Security: max-age=86400; includeSubDomains`

**Recommended:** If the site owner would like their domain to be included in the [HSTS preload list](https://hstspreload.appspot.com/) maintained by Chrome (and used by Firefox and Safari), then use the header below. <b>Sending the preload directive from your site can have PERMANENT CONSEQUENCES and prevent users from accessing your site and any of its subdomains if you find you need to switch back to HTTP. Please read the details at hstspreload.appspot.com/\#removal before sending the header with "preload".</b>

` Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`

The \`preload\` flag indicates the site owner's consent to have their domain preloaded. The site owner still needs to then go and submit the domain to the list.

Problems
--------

Site owners can use HSTS to identify users without cookies. This can lead to a significant privacy leak[1](http://www.leviathansecurity.com/blog/the-double-edged-sword-of-hsts-persistence-and-privacy).

Cookies can be manipulated from sub-domains, so omitting the "includeSubDomains" option permits a broad range of cookie-related attacks that HSTS would otherwise prevent by requiring a valid certificate for a subdomain. Ensuring the "Secure Flag" is set on all cookies will also prevent, some, but not all, of the same attacks.

Browser Support
---------------

{\\| width="400" cellspacing="1" cellpadding="1" border="1" \\|- \\| **Browser**
\\| **Support Introduced**
\\|- \\| Internet Explorer
\\| Internet Explorer 11 on Windows 8.1 and Windows 7[2](http://blogs.windows.com/msedgedev/2015/06/09/http-strict-transport-security-comes-to-internet-explorer-11-on-windows-8-1-and-windows-7/)
\\|- \\| Firefox
\\| 4
\\|- \\| Opera
\\| 12
\\|- \\| Safari
\\| Mavericks (Mac OS X 10.9)
\\|- \\| Chrome
\\| 4.0.211.0
\\|}

A detailed overview of supporting browsers can be found at [caniuse.com](http://caniuse.com/#feat=stricttransportsecurity). There is also a [TLS Browser Test Page](https://badssl.com/) to check whether your current browser supports HSTS.

Links
-----

-   [HSTS Preload Submission](https://hstspreload.appspot.com/)
-   [Chromium Projects/HSTS](http://dev.chromium.org/sts)
-   [HSTS Spec](http://tools.ietf.org/html/rfc6797)
-   [Wikipedia](http://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security)
-   [Mozilla Developer Network](https://developer.mozilla.org/en/Security/HTTP_Strict_Transport_Security)
-   [OWASP TLS Protection Cheat Sheet](https://www.owasp.org/index.php/Transport_Layer_Protection_Cheat_Sheet)
-   [Firefox STS Support](https://developer.mozilla.org/en/Security/HTTP_Strict_Transport_Security)
-   [Google Chrome STS Support](http://lists.w3.org/Archives/Public/public-webapps/2009JulSep/1148.html)
-   [Moxie Marlinspike's Black Hat 2009 talk on sslstrip, that demonstrates why you need HSTS](http://www.thoughtcrime.org/software/sslstrip/)
-   [AppSecTutorial Series - Episode 4](http://www.youtube.com/watch?v=zEV3HOuM_Vw&feature=youtube_gdata)
-   [Nmap NSE script to detect HSTS configuration](https://nmap.org/nsedoc/scripts/http-hsts-verify.html)

Authors and Primary Editors
===========================

Til Maas
Jim Manico
Pawel Krawczyk
Daniel Black
Michael Coates
and others...

Other Cheatsheets
=================

\\|}

[Category:Cheatsheets](/Category:Cheatsheets "wikilink") [Category:OWASP Best Practices](/Category:OWASP_Best_Practices "wikilink") [Control](/Category:Control\ "wikilink")